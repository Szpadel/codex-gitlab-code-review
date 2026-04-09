use super::{
    AppServerCommandOptions, AuthAccount, AuthFallbackAction, Context, DockerCodexRunner, Duration,
    Instant, MentionCommandContext, MentionCommandResult, MentionCommandStatus, Result,
    RunHistorySessionUpdate, RunnerSessionConfig, anyhow, bail, json, repo_checkout_root,
    restore_push_remote_url_exec_command,
};
use crate::composer_install::composer_install_timeout_seconds;
use std::collections::BTreeSet;

fn git_status_paths(status_output: &str) -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for line in status_output.lines() {
        if line.len() < 4 {
            continue;
        }
        let path = &line[3..];
        let normalized = path
            .rsplit_once(" -> ")
            .map_or(path, |(_, target)| target)
            .trim();
        if !normalized.is_empty() {
            paths.insert(normalized.to_string());
        }
    }
    paths
}

impl DockerCodexRunner {
    pub(crate) fn mention_developer_instructions(ctx: &MentionCommandContext) -> String {
        let mut instructions = format!(
            "You are handling a GitLab mention command request.\n\
             \n\
             Git identity for commits is configured as:\n\
             - Name: {name}\n\
             - Email: {email}\n\
             \n\
             Requirements:\n\
             - If code changes are required, create at least one commit before you finish.\n\
             - In your final response, include the commit SHA(s) you created.\n\
             - If no code changes are required, explicitly say that no commit was created.\n\
             - Do not push to remote.\n\
             - Keep the response focused on what you changed or answered.",
            name = ctx.requester_name,
            email = ctx.requester_email
        );
        if let Some(extra) = ctx
            .additional_developer_instructions
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            instructions.push_str("\n\nAdditional instructions:\n");
            instructions.push_str(extra);
        }
        instructions
    }

    pub(crate) async fn run_mention_container_with_sandbox(
        &self,
        ctx: &MentionCommandContext,
        sandbox_mode: &str,
        account: &AuthAccount,
    ) -> Result<MentionCommandResult> {
        debug_assert_eq!(sandbox_mode, self.sandbox_mode_value());
        let clone_url = self.clone_url(&ctx.repo)?;
        let repo_dir = repo_checkout_root(&ctx.project_path);
        let prepared = self
            .prepare_runner_session_components(
                ctx.run_history_id,
                &ctx.feature_flags,
                &ctx.project_path,
                &self.codex.mcp_server_overrides.mention,
                true,
            )
            .await;
        let script = Self::build_mention_command_script(
            ctx,
            &clone_url,
            &self.gitlab_token,
            &self.codex.auth_mount_path,
            AppServerCommandOptions {
                browser_mcp: prepared.browser_mcp.as_ref(),
                gitlab_discovery_mcp: prepared
                    .gitlab_discovery_mcp
                    .as_ref()
                    .map(|prepared| &prepared.runtime_config),
                mcp_server_overrides: &prepared.effective_mcp_server_overrides,
                session_override: self.mention_session_override(),
            },
        );
        let mut session = self
            .start_runner_session(RunnerSessionConfig {
                script,
                auth_account: account.clone(),
                run_history_id: ctx.run_history_id,
                browser_mcp: prepared.browser_mcp.clone(),
                gitlab_discovery_mcp: prepared.gitlab_discovery_mcp.clone(),
                gitlab_discovery_extra_hosts: prepared.gitlab_discovery_extra_hosts.clone(),
            })
            .await?;

        let run_timeout = Duration::from_secs(self.codex.timeout_seconds);
        let run_started_at = Instant::now();
        let browser_container_id = session.browser_container_id.clone();
        let browser_mcp = prepared.browser_mcp.clone();
        let mention_result = self
            .run_session_with_timeout(
                browser_container_id.as_deref(),
                browser_mcp.as_ref(),
                run_timeout.saturating_sub(run_started_at.elapsed()),
                "codex mention command timed out",
                async {
                self.update_run_history_session(
                    ctx.run_history_id,
                    RunHistorySessionUpdate {
                        auth_account_name: Some(session.auth_account_name.clone()),
                        ..RunHistorySessionUpdate::default()
                    },
                )
                .await;
                    session.client.initialize().await?;
                    session.client.initialized().await?;
                    let Some(composer_timeout_seconds) = composer_install_timeout_seconds(
                        run_timeout.saturating_sub(run_started_at.elapsed()),
                    ) else {
                        bail!("codex mention command timed out");
                    };
                    let _composer_install = self
                        .run_composer_install_step(
                            &session.container_id,
                            repo_dir.as_str(),
                            &ctx.project_path,
                            &ctx.feature_flags,
                            composer_timeout_seconds,
                            ctx.run_history_id,
                        )
                        .await;
                    let baseline_worktree_state = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["status".to_string(), "--porcelain".to_string()],
                            Some(repo_dir.as_str()),
                        )
                        .await?
                        .stdout;
                    let baseline_worktree_paths = git_status_paths(&baseline_worktree_state);
                    let extra_writable_roots = prepared.extra_writable_roots();
                    let prepared_inputs = self
                        .prepare_mention_inputs(&session.container_id, repo_dir.as_str(), ctx)
                        .await;
                    let thread_id = self
                        .session_start_thread(
                            &mut session,
                            self.thread_start_params(
                                repo_dir.as_str(),
                                Some(Self::mention_developer_instructions(ctx)),
                                &extra_writable_roots,
                            ),
                            "thread/start missing thread id",
                        )
                        .await?;
                    self.update_run_history_session(
                        ctx.run_history_id,
                        RunHistorySessionUpdate {
                            thread_id: Some(thread_id.clone()),
                            auth_account_name: Some(session.auth_account_name.clone()),
                            ..RunHistorySessionUpdate::default()
                        },
                    )
                    .await;

                    self.exec_container_git_command(
                        &session.container_id,
                        &[
                            "config".to_string(),
                            "user.name".to_string(),
                            ctx.requester_name.clone(),
                        ],
                        Some(repo_dir.as_str()),
                    )
                    .await?;
                    self.exec_container_git_command(
                        &session.container_id,
                        &[
                            "config".to_string(),
                            "user.email".to_string(),
                            ctx.requester_email.clone(),
                        ],
                        Some(repo_dir.as_str()),
                    )
                    .await?;
                    self.exec_container_git_command(
                        &session.container_id,
                        &[
                            "remote".to_string(),
                            "set-url".to_string(),
                            "--push".to_string(),
                            "origin".to_string(),
                            "no_push://disabled".to_string(),
                        ],
                        Some(repo_dir.as_str()),
                    )
                    .await?;
                    let before_sha = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["rev-parse".to_string(), "HEAD".to_string()],
                            Some(repo_dir.as_str()),
                        )
                        .await?
                        .stdout
                        .trim()
                        .to_string();

                    let turn_id = self
                        .session_start_turn(
                            &mut session,
                            json!({
                                "threadId": thread_id.as_str(),
                                "cwd": repo_dir.as_str(),
                                "input": prepared_inputs.turn_input,
                            }),
                            "turn/start missing turn id",
                        )
                        .await?;
                    self.update_run_history_session(
                        ctx.run_history_id,
                        RunHistorySessionUpdate {
                            thread_id: Some(thread_id.clone()),
                            turn_id: Some(turn_id.clone()),
                            auth_account_name: Some(session.auth_account_name.clone()),
                            ..RunHistorySessionUpdate::default()
                        },
                    )
                    .await;
                    let mut reply_message = self
                        .session_stream_turn_message(&mut session, &thread_id, &turn_id)
                        .await?;
                    if reply_message.trim().is_empty() {
                        reply_message = "Mention command completed.".to_string();
                    }

                    let after_sha = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["rev-parse".to_string(), "HEAD".to_string()],
                            Some(repo_dir.as_str()),
                        )
                        .await?
                        .stdout
                        .trim()
                        .to_string();
                    let (status, commit_sha) = if after_sha == before_sha {
                        let worktree_state = self
                            .exec_container_git_command(
                                &session.container_id,
                                &["status".to_string(), "--porcelain".to_string()],
                                Some(repo_dir.as_str()),
                            )
                            .await?;
                        if worktree_state.stdout != baseline_worktree_state {
                            bail!(
                                "mention command left uncommitted changes without creating a commit"
                            );
                        }
                        (MentionCommandStatus::NoChanges, None)
                    } else {
                        let source_branch = ctx
                            .mr
                            .source_branch
                            .as_deref()
                            .filter(|value| !value.is_empty())
                            .ok_or_else(|| anyhow!("merge request source branch is missing"))?;
                        if let Err(err) = self
                            .exec_container_git_command(
                                &session.container_id,
                                &[
                                    "merge-base".to_string(),
                                    "--is-ancestor".to_string(),
                                    before_sha.clone(),
                                    after_sha.clone(),
                                ],
                                Some(repo_dir.as_str()),
                            )
                            .await
                        {
                            bail!("mention command moved HEAD outside MR ancestry: {err}");
                        }
                        let commit_count_output = self
                            .exec_container_git_command(
                                &session.container_id,
                                &[
                                    "rev-list".to_string(),
                                    "--count".to_string(),
                                    format!("{before_sha}..{after_sha}"),
                                ],
                                Some(repo_dir.as_str()),
                            )
                            .await?;
                        let commit_count = commit_count_output
                            .stdout
                            .trim()
                            .parse::<u64>()
                            .with_context(|| {
                                format!(
                                    "parse commit count for mention command range {before_sha}..{after_sha}"
                                )
                            })?;
                        if commit_count == 0 {
                            bail!("mention command moved HEAD without producing new commits");
                        }
                        if !baseline_worktree_paths.is_empty() {
                            let committed_paths_output = self
                                .exec_container_git_command(
                                    &session.container_id,
                                    &[
                                        "diff".to_string(),
                                        "--name-only".to_string(),
                                        format!("{before_sha}..{after_sha}"),
                                    ],
                                    Some(repo_dir.as_str()),
                                )
                                .await?;
                            let committed_paths = committed_paths_output
                                .stdout
                                .lines()
                                .map(str::trim)
                                .filter(|line| !line.is_empty())
                                .collect::<BTreeSet<_>>();
                            let overlapping_baseline_paths = baseline_worktree_paths
                                .iter()
                                .filter(|path| committed_paths.contains(path.as_str()))
                                .cloned()
                                .collect::<Vec<_>>();
                            if !overlapping_baseline_paths.is_empty() {
                                bail!(
                                    "mention command commit included baseline composer-install changes: {}",
                                    overlapping_baseline_paths.join(", ")
                                );
                            }
                        }
                        self.exec_container_command_with_env(
                            &session.container_id,
                            restore_push_remote_url_exec_command(&clone_url),
                            Some(repo_dir.as_str()),
                            Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
                        )
                        .await?;
                        self.exec_container_git_command(
                            &session.container_id,
                            &[
                                "push".to_string(),
                                "origin".to_string(),
                                format!("HEAD:{source_branch}"),
                            ],
                            Some(repo_dir.as_str()),
                        )
                        .await?;
                        (MentionCommandStatus::Committed, Some(after_sha))
                    };

                    Ok::<MentionCommandResult, anyhow::Error>(MentionCommandResult {
                        status,
                        commit_sha,
                        reply_message,
                    })
                }
            )
            .await;

        self.close_runner_session(session).await;

        mention_result
    }

    pub(crate) async fn run_mention_container(
        &self,
        ctx: &MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        self.run_with_auth_fallback(AuthFallbackAction::MentionCommand, |account| async move {
            self.run_mention_container_with_sandbox(ctx, self.sandbox_mode_value(), &account)
                .await
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::git_status_paths;
    use std::collections::BTreeSet;

    #[test]
    fn git_status_paths_normalizes_plain_and_renamed_entries() {
        let paths =
            git_status_paths(" M composer.lock\n?? vendor/bin/tool\nR  old.php -> new.php\n");

        assert_eq!(
            paths,
            BTreeSet::from([
                "composer.lock".to_string(),
                "new.php".to_string(),
                "vendor/bin/tool".to_string(),
            ])
        );
    }
}

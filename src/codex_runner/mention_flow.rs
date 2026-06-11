use super::session_runner::{
    PreparedRunnerSessionComponents, RunSessionConfig, SessionInitializeRequest,
    standard_session_launch_request,
};
use super::{
    AppServerCommandOptions, AuthAccount, AuthFallbackAction, Context, DockerCodexRunner,
    MentionCommandContext, MentionCommandResult, MentionCommandStatus, Result,
    RunHistorySessionUpdate, anyhow, bail, debug, info, json, repo_checkout_root,
    restore_push_remote_url_exec_command, warn,
};
use futures::FutureExt;
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

fn log_mention_git_error(ctx: &MentionCommandContext, command: &str) {
    warn!(
        repo = ctx.repo.as_str(),
        iid = ctx.mr.iid,
        run_history_id = ctx.run_history_id,
        command,
        "mention git command failed"
    );
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
        info!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            run_history_id = ctx.run_history_id,
            auth_account = account.name.as_str(),
            "starting mention command session"
        );
        let clone_url = self.clone_url(&ctx.repo)?;
        let repo_dir = repo_checkout_root(&ctx.project_path);
        let launch = self
            .launch_runner_session(standard_session_launch_request(
                ctx.run_history_id,
                &ctx.feature_flags,
                &ctx.project_path,
                &self.codex.mcp_server_overrides.mention,
                true,
                account,
                |prepared: &PreparedRunnerSessionComponents| {
                    Ok(Self::build_mention_command_script(
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
                    ))
                },
            ))
            .await?;
        let prepared = launch.prepared;
        let mut session = launch.session;
        let run_timeout = launch.run_timeout;
        let run_started_at = launch.run_started_at;
        debug!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            run_history_id = ctx.run_history_id,
            container_id = session.container_id.as_str(),
            browser_container_id = session.browser_container_id.as_deref().unwrap_or("none"),
            "launched mention command runner session"
        );
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(session.auth_account_name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;
        debug!(
            repo = ctx.repo.as_str(),
            iid = ctx.mr.iid,
            run_history_id = ctx.run_history_id,
            "initializing mention command session and dependency step"
        );

        let app_server_container_id = session.container_id.clone();
        let browser_container_id = session.browser_container_id.clone();
        let browser_mcp = prepared.browser_mcp.clone();
        let prepared_for_run = &prepared;
        let repo_dir_for_run = repo_dir.as_str();
        let mention_result = self
            .run_initialized_session(
                &mut session,
                RunSessionConfig {
                    app_server_container_id,
                    browser_container_id,
                    browser_mcp,
                    timeout_duration: run_timeout.saturating_sub(run_started_at.elapsed()),
                    timeout_error: "codex mention command timed out",
                },
                SessionInitializeRequest {
                    repo_dir: repo_dir_for_run,
                    project_path: &ctx.project_path,
                    feature_flags: &ctx.feature_flags,
                    run_timeout,
                    run_started_at,
                    timeout_error: "codex mention command timed out",
                },
                |session| {
                    async move {
                    debug!(
                        repo = ctx.repo.as_str(),
                        iid = ctx.mr.iid,
                        run_history_id = ctx.run_history_id,
                        "mention command dependency step completed"
                    );
                    let baseline_worktree_state = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["status".to_string(), "--porcelain".to_string()],
                            Some(repo_dir_for_run),
                        )
                        .await
                        .inspect_err(|_| {
                            log_mention_git_error(ctx, "git status --porcelain");
                        })?
                        .stdout;
                    let baseline_worktree_paths = git_status_paths(&baseline_worktree_state);
                    let extra_writable_roots = prepared_for_run.extra_writable_roots();
                    let prepared_inputs = self
                        .prepare_mention_inputs(&session.container_id, repo_dir_for_run, ctx)
                        .await;
                    let thread_id = self
                        .session_start_thread(
                            session,
                            self.thread_start_params(
                                repo_dir_for_run,
                                Some(Self::mention_developer_instructions(ctx)),
                                &extra_writable_roots,
                            ),
                            "thread/start missing thread id",
                        )
                        .await?;
                    info!(
                        repo = ctx.repo.as_str(),
                        iid = ctx.mr.iid,
                        run_history_id = ctx.run_history_id,
                        thread_id = thread_id.as_str(),
                        "started mention command thread"
                    );
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
                        Some(repo_dir_for_run),
                    )
                    .await
                    .inspect_err(|_| {
                        log_mention_git_error(ctx, "git config user.name");
                    })?;
                    self.exec_container_git_command(
                        &session.container_id,
                        &[
                            "config".to_string(),
                            "user.email".to_string(),
                            ctx.requester_email.clone(),
                        ],
                        Some(repo_dir_for_run),
                    )
                    .await
                    .inspect_err(|_| {
                        log_mention_git_error(ctx, "git config user.email");
                    })?;
                    self.exec_container_git_command(
                        &session.container_id,
                        &[
                            "remote".to_string(),
                            "set-url".to_string(),
                            "--push".to_string(),
                            "origin".to_string(),
                            "no_push://disabled".to_string(),
                        ],
                        Some(repo_dir_for_run),
                    )
                    .await
                    .inspect_err(|_| {
                        log_mention_git_error(
                            ctx,
                            "git remote set-url --push origin no_push://disabled",
                        );
                    })?;
                    let before_sha = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["rev-parse".to_string(), "HEAD".to_string()],
                            Some(repo_dir_for_run),
                        )
                        .await
                        .inspect_err(|_| {
                            log_mention_git_error(ctx, "git rev-parse HEAD");
                        })?
                        .stdout
                        .trim()
                        .to_string();

                    let turn_id = self
                        .session_start_turn(
                            session,
                            json!({
                                "threadId": thread_id.as_str(),
                                "cwd": repo_dir_for_run,
                                "input": prepared_inputs.turn_input,
                            }),
                            "turn/start missing turn id",
                        )
                        .await?;
                    info!(
                        repo = ctx.repo.as_str(),
                        iid = ctx.mr.iid,
                        run_history_id = ctx.run_history_id,
                        thread_id = thread_id.as_str(),
                        turn_id = turn_id.as_str(),
                        "started mention command turn"
                    );
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
                        .session_stream_turn_message(session, &thread_id, &turn_id)
                        .await?;
                    if reply_message.trim().is_empty() {
                        reply_message = "Mention command completed.".to_string();
                    }

                    let after_sha = self
                        .exec_container_git_command(
                            &session.container_id,
                            &["rev-parse".to_string(), "HEAD".to_string()],
                            Some(repo_dir_for_run),
                        )
                        .await
                        .inspect_err(|_| {
                            log_mention_git_error(ctx, "git rev-parse HEAD");
                        })?
                        .stdout
                        .trim()
                        .to_string();
                    let (status, commit_sha) = if after_sha == before_sha {
                        let worktree_state = self
                            .exec_container_git_command(
                                &session.container_id,
                                &["status".to_string(), "--porcelain".to_string()],
                                Some(repo_dir_for_run),
                            )
                            .await
                            .inspect_err(|_| {
                                log_mention_git_error(ctx, "git status --porcelain");
                            })?;
                        if worktree_state.stdout != baseline_worktree_state {
                            warn!(
                                repo = ctx.repo.as_str(),
                                iid = ctx.mr.iid,
                                run_history_id = ctx.run_history_id,
                                "mention command left uncommitted changes without creating a commit"
                            );
                            bail!(
                                "mention command left uncommitted changes without creating a commit"
                            );
                        }
                        info!(
                            repo = ctx.repo.as_str(),
                            iid = ctx.mr.iid,
                            run_history_id = ctx.run_history_id,
                            "mention command completed without commits"
                        );
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
                                Some(repo_dir_for_run),
                            )
                            .await
                        {
                            warn!(
                                repo = ctx.repo.as_str(),
                                iid = ctx.mr.iid,
                                run_history_id = ctx.run_history_id,
                                "mention command moved HEAD outside MR ancestry"
                            );
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
                                Some(repo_dir_for_run),
                            )
                            .await
                            .inspect_err(|_| {
                                log_mention_git_error(ctx, "git rev-list --count");
                            })?;
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
                            warn!(
                                repo = ctx.repo.as_str(),
                                iid = ctx.mr.iid,
                                run_history_id = ctx.run_history_id,
                                "mention command moved HEAD without producing new commits"
                            );
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
                                    Some(repo_dir_for_run),
                                )
                                .await
                                .inspect_err(|_| {
                                    log_mention_git_error(ctx, "git diff --name-only");
                                })?;
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
                                warn!(
                                    repo = ctx.repo.as_str(),
                                    iid = ctx.mr.iid,
                                    run_history_id = ctx.run_history_id,
                                    "mention command commit included baseline composer-install changes"
                                );
                                bail!(
                                    "mention command commit included baseline composer-install changes: {}",
                                    overlapping_baseline_paths.join(", ")
                                );
                            }
                        }
                        self.exec_container_command_with_env(
                            &session.container_id,
                            restore_push_remote_url_exec_command(&clone_url),
                            Some(repo_dir_for_run),
                            Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
                        )
                        .await
                        .inspect_err(|_| {
                            log_mention_git_error(ctx, "restore git push remote");
                        })?;
                        self.exec_container_git_command(
                            &session.container_id,
                            &[
                                "push".to_string(),
                                "origin".to_string(),
                                format!("HEAD:{source_branch}"),
                            ],
                            Some(repo_dir_for_run),
                        )
                        .await
                        .inspect_err(|_| {
                            log_mention_git_error(ctx, "git push origin HEAD");
                        })?;
                        info!(
                            repo = ctx.repo.as_str(),
                            iid = ctx.mr.iid,
                            run_history_id = ctx.run_history_id,
                            "mention command pushed commits to source branch"
                        );
                        (MentionCommandStatus::Committed, Some(after_sha))
                    };

                    Ok::<MentionCommandResult, anyhow::Error>(MentionCommandResult {
                        status,
                        commit_sha,
                        reply_message,
                    })
                    }
                    .boxed()
                },
            )
            .await;

        if mention_result.is_err() {
            warn!(
                repo = ctx.repo.as_str(),
                iid = ctx.mr.iid,
                run_history_id = ctx.run_history_id,
                "mention command session failed"
            );
        }
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

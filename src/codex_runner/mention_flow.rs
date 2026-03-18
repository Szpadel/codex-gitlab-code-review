use super::*;

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
        let repo_dir = "/work/repo";
        let browser_mcp = self.effective_browser_mcp(&self.codex.mcp_server_overrides.mention);
        let gitlab_discovery_mcp = self.prepare_gitlab_discovery_mcp(
            &ctx.project_path,
            &ctx.feature_flags,
            &self.codex.mcp_server_overrides.mention,
        );
        self.sync_effective_feature_flags(
            ctx.run_history_id,
            &ctx.feature_flags,
            gitlab_discovery_mcp.is_some(),
        )
        .await;
        let reasoning_summary =
            configured_reasoning_summary(self.codex.reasoning_summary.mention.as_deref());
        let reasoning_effort =
            configured_reasoning_effort(self.codex.reasoning_effort.mention.as_deref());
        let effective_mcp_server_overrides = self.effective_mcp_server_overrides_for_run(
            &self.codex.mcp_server_overrides.mention,
            gitlab_discovery_mcp.is_some(),
        );
        let script = Self::build_mention_command_script(
            ctx,
            &clone_url,
            &self.gitlab_token,
            &self.codex.auth_mount_path,
            AppServerCommandOptions {
                browser_mcp,
                gitlab_discovery_mcp: gitlab_discovery_mcp
                    .as_ref()
                    .map(|prepared| &prepared.runtime_config),
                mcp_server_overrides: &effective_mcp_server_overrides,
                reasoning_summary,
                reasoning_effort,
            },
        );
        let gitlab_discovery_extra_hosts = gitlab_discovery_mcp
            .as_ref()
            .map(|prepared| self.gitlab_discovery_extra_hosts(&prepared.runtime_config))
            .unwrap_or_default();
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(
                script,
                &account.auth_host_path,
                Vec::new(),
                Vec::new(),
                browser_mcp,
                gitlab_discovery_extra_hosts,
            )
            .await?;
        let gitlab_discovery_session = match self
            .register_gitlab_discovery_session(
                gitlab_discovery_mcp.as_ref(),
                &container_id,
                browser_container_id.as_deref().unwrap_or(&container_id),
                ctx.run_history_id,
            )
            .await
        {
            Ok(session) => session,
            Err(err) => {
                warn!(
                    container_id,
                    error = %err,
                    "failed to register gitlab discovery MCP session"
                );
                self.append_gitlab_discovery_mcp_startup_failure(
                    ctx.run_history_id,
                    gitlab_discovery_mcp
                        .as_ref()
                        .map(|prepared| prepared.runtime_config.advertise_url.as_str())
                        .unwrap_or("<unknown>"),
                    "failed to register MCP session binding",
                )
                .await;
                None
            }
        };
        self.probe_gitlab_discovery_mcp_endpoint(
            gitlab_discovery_mcp.as_ref(),
            &container_id,
            gitlab_discovery_session.as_ref(),
            ctx.run_history_id,
        )
        .await;
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(account.name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;

        let mention_result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            client.initialize().await?;
            client.initialized().await?;
            let extra_writable_roots = gitlab_discovery_mcp
                .as_ref()
                .map(|prepared| vec![prepared.runtime_config.clone_root.clone()])
                .unwrap_or_default();
            let thread_response = client
                .request(
                    "thread/start",
                    self.thread_start_params(
                        repo_dir,
                        Some(Self::mention_developer_instructions(ctx)),
                        &extra_writable_roots,
                    ),
                )
                .await?;
            let thread_id = thread_response
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("thread/start missing thread id"))?
                .to_string();
            self.update_run_history_session(
                ctx.run_history_id,
                RunHistorySessionUpdate {
                    thread_id: Some(thread_id.clone()),
                    auth_account_name: Some(account.name.clone()),
                    ..RunHistorySessionUpdate::default()
                },
            )
            .await;

            self.exec_container_git_command(
                &container_id,
                &[
                    "config".to_string(),
                    "user.name".to_string(),
                    ctx.requester_name.clone(),
                ],
                Some(repo_dir),
            )
            .await?;
            self.exec_container_git_command(
                &container_id,
                &[
                    "config".to_string(),
                    "user.email".to_string(),
                    ctx.requester_email.clone(),
                ],
                Some(repo_dir),
            )
            .await?;
            self.exec_container_git_command(
                &container_id,
                &[
                    "remote".to_string(),
                    "set-url".to_string(),
                    "--push".to_string(),
                    "origin".to_string(),
                    "no_push://disabled".to_string(),
                ],
                Some(repo_dir),
            )
            .await?;
            let before_sha = self
                .exec_container_git_command(
                    &container_id,
                    &["rev-parse".to_string(), "HEAD".to_string()],
                    Some(repo_dir),
                )
                .await?
                .stdout
                .trim()
                .to_string();

            let turn_response = client
                .request(
                    "turn/start",
                    json!({
                        "threadId": thread_id.as_str(),
                        "cwd": repo_dir,
                        "input": [{ "type": "text", "text": ctx.prompt.as_str() }],
                    }),
                )
                .await?;
            let turn_id = turn_response
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("turn/start missing turn id"))?
                .to_string();
            self.update_run_history_session(
                ctx.run_history_id,
                RunHistorySessionUpdate {
                    thread_id: Some(thread_id.clone()),
                    turn_id: Some(turn_id.clone()),
                    auth_account_name: Some(account.name.clone()),
                    ..RunHistorySessionUpdate::default()
                },
            )
            .await;
            let mut reply_message = client
                .stream_turn_message(
                    &thread_id,
                    &turn_id,
                    gitlab_discovery_mcp
                        .as_ref()
                        .map(|prepared| prepared.runtime_config.server_name.as_str()),
                    |events| async move {
                        self.append_run_history_events(ctx.run_history_id, &events)
                            .await;
                    },
                    || async move {
                        self.clear_gitlab_discovery_mcp_startup_failure(ctx.run_history_id)
                            .await;
                    },
                )
                .await?;
            if reply_message.trim().is_empty() {
                reply_message = "Mention command completed.".to_string();
            }

            let after_sha = self
                .exec_container_git_command(
                    &container_id,
                    &["rev-parse".to_string(), "HEAD".to_string()],
                    Some(repo_dir),
                )
                .await?
                .stdout
                .trim()
                .to_string();
            let (status, commit_sha) = if after_sha != before_sha {
                let source_branch = ctx
                    .mr
                    .source_branch
                    .as_deref()
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow!("merge request source branch is missing"))?;
                if let Err(err) = self
                    .exec_container_git_command(
                        &container_id,
                        &[
                            "merge-base".to_string(),
                            "--is-ancestor".to_string(),
                            before_sha.clone(),
                            after_sha.clone(),
                        ],
                        Some(repo_dir),
                    )
                    .await
                {
                    bail!("mention command moved HEAD outside MR ancestry: {err}");
                }
                let commit_count_output = self
                    .exec_container_git_command(
                        &container_id,
                        &[
                            "rev-list".to_string(),
                            "--count".to_string(),
                            format!("{before_sha}..{after_sha}"),
                        ],
                        Some(repo_dir),
                    )
                    .await?;
                let commit_count = commit_count_output
                    .stdout
                    .trim()
                    .parse::<u64>()
                    .with_context(|| {
                        format!(
                            "parse commit count for mention command range {}..{}",
                            before_sha, after_sha
                        )
                    })?;
                if commit_count == 0 {
                    bail!("mention command moved HEAD without producing new commits");
                }
                self.exec_container_command_with_env(
                    &container_id,
                    restore_push_remote_url_exec_command(&clone_url),
                    Some(repo_dir),
                    Some(vec![format!("GITLAB_TOKEN={}", self.gitlab_token)]),
                )
                .await?;
                self.exec_container_git_command(
                    &container_id,
                    &[
                        "push".to_string(),
                        "origin".to_string(),
                        format!("HEAD:{source_branch}"),
                    ],
                    Some(repo_dir),
                )
                .await?;
                (MentionCommandStatus::Committed, Some(after_sha))
            } else {
                let worktree_state = self
                    .exec_container_git_command(
                        &container_id,
                        &["status".to_string(), "--porcelain".to_string()],
                        Some(repo_dir),
                    )
                    .await?;
                if !worktree_state.stdout.trim().is_empty() {
                    bail!("mention command left uncommitted changes without creating a commit");
                }
                (MentionCommandStatus::NoChanges, None)
            };

            Ok::<MentionCommandResult, anyhow::Error>(MentionCommandResult {
                status,
                commit_sha,
                reply_message,
            })
        })
        .await;

        let mention_result = match mention_result {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(err)) => Err(self
                .enrich_error_with_browser_diagnostics(
                    err,
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
            Err(_) => Err(self
                .enrich_error_with_browser_diagnostics(
                    anyhow!("codex mention command timed out"),
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
        };

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;
        self.unregister_gitlab_discovery_session(gitlab_discovery_session.as_ref())
            .await;

        mention_result
    }

    pub(crate) async fn run_mention_container(
        &self,
        ctx: &MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        let now = Utc::now();
        let available_accounts = self.available_auth_accounts(now).await?;
        if available_accounts.is_empty() {
            bail!(
                "no available codex auth accounts (all accounts are waiting for usage-limit reset)"
            );
        }

        let mut auth_fallback_errors = Vec::new();
        for account in &available_accounts {
            let attempt_started_at = Utc::now();
            info!(
                account = account.name.as_str(),
                is_primary = account.is_primary,
                repo = ctx.repo.as_str(),
                iid = ctx.mr.iid,
                discussion_id = ctx.discussion_id.as_str(),
                trigger_note_id = ctx.trigger_note_id,
                "running codex mention command with auth account"
            );
            match self
                .run_mention_container_with_sandbox(ctx, self.sandbox_mode_value(), account)
                .await
            {
                Ok(result) => {
                    self.clear_limit_reset_if_stale(account, attempt_started_at)
                        .await?;
                    return Ok(result);
                }
                Err(err) => {
                    let kind = classify_auth_failure(
                        &err,
                        Utc::now(),
                        self.codex.usage_limit_fallback_cooldown_seconds,
                    );
                    let kind = classify_auth_failure_for_account(kind, &err, account);
                    match kind {
                        AuthFailureKind::UsageLimited { reset_at } => {
                            self.mark_limit_reset_at(account, reset_at).await?;
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                reset_at = %reset_at,
                                error = %err,
                                "codex auth account usage-limited for mention command; trying next account"
                            );
                            auth_fallback_errors.push(format!(
                                "account '{}' usage-limited until {}: {}",
                                account.name, reset_at, err
                            ));
                        }
                        AuthFailureKind::AuthUnavailable => {
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                error = %err,
                                "codex auth account unavailable for mention command; trying next account"
                            );
                            auth_fallback_errors
                                .push(format!("account '{}' unavailable: {}", account.name, err));
                        }
                        AuthFailureKind::Other => {
                            return Err(err).with_context(|| {
                                format!(
                                    "mention command failed for account '{}' without fallback classification",
                                    account.name
                                )
                            });
                        }
                    }
                }
            }
        }

        bail!(
            "all codex auth accounts failed with usage-limit/auth errors for mention command: {}",
            auth_fallback_errors.join(" | ")
        );
    }
}

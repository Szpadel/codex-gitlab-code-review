use super::*;

#[derive(Debug, Deserialize)]
pub(crate) struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewTargetRequest {
    NativeBaseBranch { branch: String },
    Custom { instructions: String },
}

impl DockerCodexRunner {
    pub(crate) fn review_additional_developer_instructions(&self) -> Option<String> {
        self.review_additional_developer_instructions
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    }

    pub(crate) fn fallback_review_target_instructions(
        ctx: &ReviewContext,
        additional_developer_instructions: Option<&str>,
    ) -> String {
        let mut prompt = format!(
            "{} GitLab did not provide target branch metadata for this merge request, so this fallback reviews the checked-out head commit instead of a merge diff.",
            build_commit_review_prompt(ctx.head_sha.as_str(), ctx.mr.title.as_deref())
        );
        if let Some(additional_developer_instructions) = additional_developer_instructions {
            prompt =
                append_additional_review_instructions(&prompt, additional_developer_instructions);
        }
        prompt
    }

    // Drift note:
    // This mirrors only Codex upstream review target prompt construction from
    // `codex-rs/core/src/review_prompts.rs` via the synced generated templates.
    // Upstream source metadata is recorded in `generated_review_prompt_templates.rs`.
    //
    // Local alteration:
    // - default path keeps native `review/start { type: "baseBranch" }`
    // - when `review.additional_developer_instructions` is configured, we switch
    //   to `review/start { type: "custom" }` and append those instructions to the
    //   synced upstream target prompt so the Codex-owned review rubric remains in
    //   the runtime image instead of being copied into this service.
    pub(crate) fn review_target_request(
        ctx: &ReviewContext,
        merge_base_sha: Option<&str>,
        additional_developer_instructions: Option<&str>,
    ) -> ReviewTargetRequest {
        let base_branch = ctx
            .mr
            .target_branch
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        match (base_branch, additional_developer_instructions) {
            (Some(branch), None) => ReviewTargetRequest::NativeBaseBranch {
                branch: branch.to_string(),
            },
            (Some(branch), Some(additional_developer_instructions)) => {
                let prompt = build_base_branch_review_prompt(branch, merge_base_sha);
                ReviewTargetRequest::Custom {
                    instructions: append_additional_review_instructions(
                        &prompt,
                        additional_developer_instructions,
                    ),
                }
            }
            (None, additional_developer_instructions) => ReviewTargetRequest::Custom {
                instructions: Self::fallback_review_target_instructions(
                    ctx,
                    additional_developer_instructions,
                ),
            },
        }
    }

    pub(crate) async fn resolve_review_target_request(
        &self,
        ctx: &ReviewContext,
        container_id: &str,
        repo_path: &str,
    ) -> ReviewTargetRequest {
        let additional_developer_instructions = self.review_additional_developer_instructions();
        let merge_base_sha = if let Some(branch) = ctx
            .mr
            .target_branch
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if additional_developer_instructions.is_some() {
                self.try_resolve_review_merge_base(container_id, repo_path, branch)
                    .await
            } else {
                None
            }
        } else {
            None
        };
        Self::review_target_request(
            ctx,
            merge_base_sha.as_deref(),
            additional_developer_instructions.as_deref(),
        )
    }

    pub(crate) async fn try_resolve_review_merge_base(
        &self,
        container_id: &str,
        repo_path: &str,
        branch: &str,
    ) -> Option<String> {
        let output = match self
            .exec_container_git_command(
                container_id,
                &[
                    "merge-base".to_string(),
                    "HEAD".to_string(),
                    branch.to_string(),
                ],
                Some(repo_path),
            )
            .await
        {
            Ok(output) => output,
            Err(err) => {
                warn!(
                    branch,
                    upstream_prompt_path = upstream_review_prompt_source_path(),
                    upstream_prompt_commit = upstream_review_prompt_source_commit(),
                    error = %err,
                    "failed to resolve review merge-base locally; falling back to synced upstream backup prompt"
                );
                return None;
            }
        };
        let merge_base_sha = output.stdout.trim();
        if merge_base_sha.is_empty() {
            warn!(
                branch,
                upstream_prompt_path = upstream_review_prompt_source_path(),
                upstream_prompt_commit = upstream_review_prompt_source_commit(),
                "review merge-base command returned empty output; falling back to synced upstream backup prompt"
            );
            None
        } else {
            Some(merge_base_sha.to_string())
        }
    }

    pub(crate) fn review_target_value(review_target: ReviewTargetRequest) -> Value {
        match review_target {
            ReviewTargetRequest::NativeBaseBranch { branch } => {
                json!({ "type": "baseBranch", "branch": branch })
            }
            ReviewTargetRequest::Custom { instructions } => {
                json!({ "type": "custom", "instructions": instructions })
            }
        }
    }

    pub(crate) async fn run_app_server_review_with_account(
        &self,
        ctx: &ReviewContext,
        account: &AuthAccount,
    ) -> Result<String> {
        let browser_mcp = self.effective_browser_mcp(&self.codex.mcp_server_overrides.review);
        let gitlab_discovery_mcp = self.prepare_gitlab_discovery_mcp(
            &ctx.project_path,
            &ctx.feature_flags,
            &self.codex.mcp_server_overrides.review,
        );
        self.sync_effective_feature_flags(
            ctx.run_history_id,
            &ctx.feature_flags,
            gitlab_discovery_mcp.is_some(),
        )
        .await;
        let script = self.command(
            ctx,
            AppServerCommandOptions {
                browser_mcp,
                gitlab_discovery_mcp: gitlab_discovery_mcp
                    .as_ref()
                    .map(|prepared| &prepared.runtime_config),
                mcp_server_overrides: &self.codex.mcp_server_overrides.review,
                reasoning_summary: None,
                reasoning_effort: None,
            },
        )?;
        let extra_env = gitlab_discovery_mcp
            .as_ref()
            .map(|prepared| {
                vec![format!(
                    "{}={}",
                    prepared.runtime_config.bearer_token_env_var, prepared.bearer_token
                )]
            })
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
                extra_env,
                browser_mcp,
            )
            .await?;
        self.register_gitlab_discovery_session(
            gitlab_discovery_mcp.as_ref(),
            &container_id,
            ctx.run_history_id,
        )
        .await;
        self.probe_gitlab_discovery_mcp_endpoint(
            gitlab_discovery_mcp.as_ref(),
            &container_id,
            ctx.run_history_id,
        )
        .await;
        let repo_path = "/work/repo";
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(account.name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;

        let review_result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            let review_target = Self::review_target_value(
                self.resolve_review_target_request(ctx, &container_id, repo_path)
                    .await,
            );
            client.initialize().await?;
            client.initialized().await?;
            let extra_writable_roots = gitlab_discovery_mcp
                .as_ref()
                .map(|prepared| vec![prepared.runtime_config.clone_root.clone()])
                .unwrap_or_default();
            let thread_response = client
                .request(
                    "thread/start",
                    self.thread_start_params(repo_path, None, &extra_writable_roots),
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
            let review_response = client
                .request(
                    "review/start",
                    json!({
                        "threadId": thread_id,
                        "delivery": "inline",
                        "target": review_target,
                    }),
                )
                .await?;
            let turn_id = review_response
                .get("turn")
                .and_then(|turn| turn.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("review/start missing turn id"))?
                .to_string();
            let review_thread_id = review_response
                .get("reviewThreadId")
                .and_then(|id| id.as_str())
                .unwrap_or(thread_id.as_str())
                .to_string();
            self.update_run_history_session(
                ctx.run_history_id,
                RunHistorySessionUpdate {
                    thread_id: Some(thread_id.clone()),
                    turn_id: Some(turn_id.clone()),
                    review_thread_id: Some(review_thread_id.clone()),
                    auth_account_name: Some(account.name.clone()),
                },
            )
            .await;
            client
                .stream_review(
                    &review_thread_id,
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
                .await
        })
        .await;

        let review_result = match review_result {
            Ok(Ok(review)) => Ok(review),
            Ok(Err(err)) => Err(self
                .enrich_error_with_browser_diagnostics(
                    err,
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
            Err(_) => Err(self
                .enrich_error_with_browser_diagnostics(
                    anyhow!("codex review timed out"),
                    browser_container_id.as_deref(),
                    browser_mcp,
                )
                .await),
        };

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;
        self.unregister_gitlab_discovery_session(gitlab_discovery_mcp.as_ref())
            .await;

        review_result
    }

    pub(crate) async fn run_app_server_review(&self, ctx: &ReviewContext) -> Result<String> {
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
                "running codex review with auth account"
            );
            match self.run_app_server_review_with_account(ctx, account).await {
                Ok(output) => {
                    self.clear_limit_reset_if_stale(account, attempt_started_at)
                        .await?;
                    return Ok(output);
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
                                "codex auth account usage-limited; trying next account"
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
                                "codex auth account unavailable; trying next account"
                            );
                            auth_fallback_errors
                                .push(format!("account '{}' unavailable: {}", account.name, err));
                        }
                        AuthFailureKind::Other => {
                            return Err(err).with_context(|| {
                                format!(
                                    "codex review failed for account '{}' without fallback classification",
                                    account.name
                                )
                            });
                        }
                    }
                }
            }
        }

        bail!(
            "all codex auth accounts failed with usage-limit/auth errors: {}",
            auth_fallback_errors.join(" | ")
        );
    }
}

pub(crate) fn parse_review_output(text: &str) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<CodexOutput>(&json_text)
    {
        return match parsed.verdict.as_str() {
            "pass" => Ok(CodexResult::Pass {
                summary: parsed.summary,
            }),
            "comment" => Ok(CodexResult::Comment {
                summary: parsed.summary,
                body: parsed.comment_markdown,
            }),
            other => Err(anyhow!("unknown verdict: {}", other)),
        };
    }

    let summary = trimmed
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Codex review")
        .trim()
        .to_string();
    Ok(CodexResult::Comment {
        summary,
        body: trimmed.to_string(),
    })
}

pub(crate) fn extract_json_block(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

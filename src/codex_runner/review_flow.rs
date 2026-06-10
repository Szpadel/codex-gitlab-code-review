use super::review_output::validated_security_min_confidence_score;
use super::security_context::{
    SECURITY_CONTEXT_PROMPT_VERSION, SecurityContextPayloadResolution,
    SeparateSecurityContextSessionRequest,
};
use super::{
    AppServerCommandOptions, Arc, AuthAccount, AuthFallbackAction, DockerCodexRunner, Duration,
    Instant, Mutex, PreparedGitLabDiscoveryMcp, Result, ReviewContext, RunHistorySessionUpdate,
    RunnerSessionConfig, Utc, Value, append_additional_review_instructions, bail,
    build_base_branch_review_prompt, build_commit_review_prompt, json, repo_checkout_root,
    upstream_review_prompt_source_commit, upstream_review_prompt_source_path, warn,
};
use crate::composer_install::composer_install_timeout_seconds;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewTargetRequest {
    NativeBaseBranch { branch: String },
    Custom { instructions: String },
}

impl DockerCodexRunner {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn prepare_review_gitlab_discovery_mcp(
        &self,
        ctx: &ReviewContext,
    ) -> Option<PreparedGitLabDiscoveryMcp> {
        if ctx.lane.is_security() {
            return None;
        }
        self.prepare_gitlab_discovery_mcp(
            &ctx.project_path,
            &ctx.feature_flags,
            &self.codex.mcp_server_overrides.review,
        )
    }

    pub(crate) fn review_additional_developer_instructions(
        &self,
        ctx: &ReviewContext,
    ) -> Option<String> {
        ctx.additional_developer_instructions
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .or_else(|| {
                self.review_additional_developer_instructions
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToOwned::to_owned)
            })
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
        let additional_developer_instructions = self.review_additional_developer_instructions(ctx);
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
        let prepared = self
            .prepare_runner_session_components(
                ctx.run_history_id,
                &ctx.feature_flags,
                &ctx.project_path,
                &self.codex.mcp_server_overrides.review,
                !ctx.lane.is_security(),
            )
            .await;
        let script = self.command(
            ctx,
            AppServerCommandOptions {
                browser_mcp: prepared.browser_mcp.as_ref(),
                gitlab_discovery_mcp: prepared
                    .gitlab_discovery_mcp
                    .as_ref()
                    .map(|prepared| &prepared.runtime_config),
                mcp_server_overrides: &prepared.effective_mcp_server_overrides,
                session_override: if ctx.lane.is_security() {
                    self.security_review_session_override()
                } else {
                    self.review_session_override()
                },
            },
        )?;
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

        let repo_path = repo_checkout_root(&ctx.project_path);
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(session.auth_account_name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;

        let run_timeout = Duration::from_secs(self.codex.timeout_seconds);
        let run_started_at = Instant::now();
        let extra_security_context_session = Arc::new(Mutex::new(None::<(String, Option<String>)>));
        let browser_container_id = session.browser_container_id.clone();
        let browser_mcp = prepared.browser_mcp.clone();
        let review_result = self
            .run_session_with_timeout(
                browser_container_id.as_deref(),
                browser_mcp.as_ref(),
                run_timeout.saturating_sub(run_started_at.elapsed()),
                "codex review timed out",
                async {
                    session.client.initialize().await?;
                    session.client.initialized().await?;
                let Some(composer_timeout_seconds) = composer_install_timeout_seconds(
                    run_timeout.saturating_sub(run_started_at.elapsed()),
                ) else {
                    bail!("codex review timed out");
                };
                let _composer_install = self
                    .run_composer_install_step(
                        &session.container_id,
                        repo_path.as_str(),
                        &ctx.project_path,
                        &ctx.feature_flags,
                        composer_timeout_seconds,
                        ctx.run_history_id,
                    )
                    .await;
                let extra_writable_roots = prepared.extra_writable_roots();
                let mut security_base_prompt = None;
                let mut security_min_confidence_score = None;
                let mut security_review_instructions = None;
                let mut security_context_resolution = SecurityContextPayloadResolution::default();
                let mut security_context_base_branch = None;
                if ctx.lane.is_security() {
                    let min_confidence_score = validated_security_min_confidence_score(
                        ctx.min_confidence_score,
                        "security review min_confidence_score",
                    )?;
                    let base_branch = ctx
                        .mr
                        .target_branch
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned);
                    let merge_base_sha = if let Some(branch) = base_branch.as_deref() {
                        self.try_resolve_review_merge_base(
                            &session.container_id,
                            repo_path.as_str(),
                            branch,
                        )
                        .await
                    } else {
                        None
                    };
                    let base_prompt = if let Some(branch) = base_branch.as_deref() {
                        build_base_branch_review_prompt(branch, merge_base_sha.as_deref())
                    } else {
                        Self::fallback_review_target_instructions(ctx, None)
                    };
                    security_base_prompt = Some(base_prompt.clone());
                    if let Some(branch) = base_branch.as_deref() {
                        match self
                            .resolve_security_context_payload(
                                ctx,
                                &session.container_id,
                                repo_path.as_str(),
                                branch,
                            )
                            .await
                        {
                            Ok(resolution) => {
                                security_context_resolution = resolution;
                                security_context_base_branch = Some(branch.to_string());
                            }
                            Err(err) => {
                                warn!(
                                    repo = ctx.repo.as_str(),
                                    iid = ctx.mr.iid,
                                    branch,
                                    error = %err,
                                    "failed to build cached security context; continuing without it"
                                );
                            }
                        }
                    }
                    security_min_confidence_score = Some(min_confidence_score);
                    security_review_instructions = Some(self.build_security_review_instructions(
                        base_prompt.as_str(),
                        security_context_resolution.payload_json.as_deref(),
                        min_confidence_score,
                        ctx.additional_developer_instructions.as_deref(),
                    ));
                }
                let thread_id = self
                    .session_start_thread(
                        &mut session,
                        self.thread_start_params(repo_path.as_str(), None, &extra_writable_roots),
                        "thread/start missing thread id",
                    )
                    .await?;
                let mut session_update = Self::security_context_session_update(
                    security_context_base_branch.as_deref(),
                    &security_context_resolution,
                );
                session_update.thread_id = Some(thread_id.clone());
                session_update.auth_account_name = Some(session.auth_account_name.clone());
                self.update_run_history_session(ctx.run_history_id, session_update)
                    .await;
                if ctx.lane.is_security() {
                    if security_context_resolution.build_guard.is_some() {
                        let base_branch = security_context_base_branch
                            .as_deref()
                            .expect("security context base branch set when build is pending");
                        let base_head_sha = security_context_resolution
                            .build_base_head_sha
                            .as_deref()
                            .expect("security context base head SHA set when build is pending");
                        let build_result = self
                            .build_security_context_with_separate_session(
                                ctx,
                                SeparateSecurityContextSessionRequest {
                                    account,
                                    browser_mcp: prepared.browser_mcp.as_ref(),
                                    repo_path: repo_path.as_str(),
                                    base_branch,
                                    base_head_sha,
                                    extra_session_container: Arc::clone(
                                        &extra_security_context_session,
                                    ),
                                },
                            )
                            .await;
                        let mut build_guard = security_context_resolution.build_guard.take();
                        match build_result {
                            Ok(payload_json) => {
                                let generated_at = Utc::now().timestamp();
                                let expires_at = generated_at
                                    + ctx.security_context_ttl_seconds.unwrap_or(1_209_600) as i64;
                                if let Err(err) = self
                                    .state
                                    .security_context_cache.upsert_security_review_context_cache(
                                        &crate::state::SecurityReviewContextCacheEntry {
                                            repo: self.security_context_cache_repo_key(ctx)
                                                .to_string(),
                                            base_branch: base_branch.to_string(),
                                            base_head_sha: base_head_sha.to_string(),
                                            prompt_version:
                                                SECURITY_CONTEXT_PROMPT_VERSION.to_string(),
                                            payload_json: payload_json.clone(),
                                            source_run_history_id: ctx
                                                .run_history_id
                                                .unwrap_or_default(),
                                            generated_at,
                                            expires_at,
                                        },
                                    )
                                    .await
                                {
                                    warn!(
                                        repo = ctx.repo.as_str(),
                                        iid = ctx.mr.iid,
                                        branch = base_branch,
                                        error = %err,
                                        "failed to persist cached security context; continuing without cache reuse"
                                    );
                                }
                                security_context_resolution.payload_json =
                                    Some(payload_json.clone());
                                security_context_resolution.source_run_history_id =
                                    ctx.run_history_id;
                                security_context_resolution.generated_at = Some(generated_at);
                                security_context_resolution.expires_at = Some(expires_at);
                                self.update_run_history_session(
                                    ctx.run_history_id,
                                    Self::security_context_session_update(
                                        security_context_base_branch.as_deref(),
                                        &security_context_resolution,
                                    ),
                                )
                                .await;
                                security_review_instructions = Some(
                                    self.build_security_review_instructions(
                                        security_base_prompt
                                            .as_deref()
                                            .expect("security base prompt set for security lane"),
                                        Some(payload_json.as_str()),
                                        security_min_confidence_score.expect(
                                            "security min confidence score set for security lane",
                                        ),
                                        ctx.additional_developer_instructions.as_deref(),
                                    ),
                                );
                                if let Some(build_guard) = build_guard.take() {
                                    build_guard.complete();
                                }
                            }
                            Err(err) => {
                                if let Some(build_guard) = build_guard.take() {
                                    build_guard.complete();
                                }
                                warn!(
                                    repo = ctx.repo.as_str(),
                                    iid = ctx.mr.iid,
                                    branch = base_branch,
                                    error = %err,
                                    "failed to build cached security context; continuing without it"
                                );
                            }
                        }
                    }
                    let turn_id = self
                        .session_start_turn(
                            &mut session,
                            json!({
                                "threadId": thread_id,
                                "cwd": repo_path.as_str(),
                                "input": [
                                    {
                                        "type": "text",
                                        "text": security_review_instructions
                                            .as_deref()
                                            .expect("security review instructions built"),
                                    }
                                ],
                                "outputSchema": Self::security_review_output_schema(),
                            }),
                            "turn/start missing turn id for security review",
                        )
                        .await?;
                    let mut session_update = Self::security_context_session_update(
                        security_context_base_branch.as_deref(),
                        &security_context_resolution,
                    );
                    session_update.thread_id = Some(thread_id.clone());
                    session_update.turn_id = Some(turn_id.clone());
                    session_update.auth_account_name = Some(session.auth_account_name.clone());
                    self.update_run_history_session(ctx.run_history_id, session_update)
                        .await;
                    self.session_stream_turn_message(&mut session, &thread_id, &turn_id)
                        .await
                } else {
                    let review_target = Self::review_target_value(
                        self.resolve_review_target_request(
                            ctx,
                            &session.container_id,
                            repo_path.as_str(),
                        )
                            .await,
                    );
                    let review_turn = self
                        .session_start_review(&mut session, &thread_id, review_target)
                        .await?;
                    self.update_run_history_session(
                        ctx.run_history_id,
                        RunHistorySessionUpdate {
                            thread_id: Some(thread_id.clone()),
                            turn_id: Some(review_turn.turn_id.clone()),
                            review_thread_id: Some(review_turn.review_thread_id.clone()),
                            auth_account_name: Some(session.auth_account_name.clone()),
                            ..RunHistorySessionUpdate::default()
                        },
                    )
                    .await;
                    self.session_stream_review(
                        &mut session,
                        &review_turn.review_thread_id,
                        &review_turn.turn_id,
                    )
                        .await
                }
            },
        )
            .await;

        let extra_security_context_session = {
            let mut slot = extra_security_context_session
                .lock()
                .expect("security context extra session lock poisoned");
            slot.take()
        };
        if let Some((extra_container_id, extra_browser_container_id)) =
            extra_security_context_session
        {
            self.cleanup_app_server_containers(
                &extra_container_id,
                extra_browser_container_id.as_deref(),
            )
            .await;
        }

        self.close_runner_session(session).await;

        review_result
    }

    pub(crate) async fn run_app_server_review(&self, ctx: &ReviewContext) -> Result<String> {
        self.run_with_auth_fallback(AuthFallbackAction::Review, |account| async move {
            self.run_app_server_review_with_account(ctx, &account).await
        })
        .await
    }
}

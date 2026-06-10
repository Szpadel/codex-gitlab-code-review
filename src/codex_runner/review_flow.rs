use super::review_output::validated_security_min_confidence_score;
use super::security_context::{
    ExtraSecurityContextSessionContainer, SECURITY_CONTEXT_PROMPT_VERSION,
    SecurityContextPayloadResolution, SeparateSecurityContextSessionRequest,
};
use super::session_runner::{
    PreparedRunnerSessionComponents, RunnerSession, SessionInitializeRequest, SessionLaunchRequest,
};
use super::{
    AppServerCommandOptions, Arc, AuthAccount, AuthFallbackAction, DockerCodexRunner, Instant,
    PreparedGitLabDiscoveryMcp, Result, ReviewContext, RunHistorySessionUpdate, Utc, Value,
    append_additional_review_instructions, build_base_branch_review_prompt,
    build_commit_review_prompt, json, repo_checkout_root, upstream_review_prompt_source_commit,
    upstream_review_prompt_source_path, warn,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewTargetRequest {
    NativeBaseBranch { branch: String },
    Custom { instructions: String },
}

struct SecurityReviewPlan {
    base_prompt: String,
    min_confidence_score: f32,
    instructions: String,
    context_resolution: SecurityContextPayloadResolution,
    base_branch: Option<String>,
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

    async fn prepare_security_review_plan(
        &self,
        ctx: &ReviewContext,
        container_id: &str,
        repo_path: &str,
    ) -> Result<SecurityReviewPlan> {
        let min_confidence_score = validated_security_min_confidence_score(
            ctx.min_confidence_score,
            "security review min_confidence_score",
        )?;
        let target_base_branch = ctx
            .mr
            .target_branch
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let merge_base_sha = if let Some(branch) = target_base_branch.as_deref() {
            self.try_resolve_review_merge_base(container_id, repo_path, branch)
                .await
        } else {
            None
        };
        let base_prompt = if let Some(branch) = target_base_branch.as_deref() {
            build_base_branch_review_prompt(branch, merge_base_sha.as_deref())
        } else {
            Self::fallback_review_target_instructions(ctx, None)
        };
        let mut context_resolution = SecurityContextPayloadResolution::default();
        let mut context_base_branch = None;
        if let Some(branch) = target_base_branch.as_deref() {
            match self
                .resolve_security_context_payload(ctx, container_id, repo_path, branch)
                .await
            {
                Ok(resolution) => {
                    context_resolution = resolution;
                    context_base_branch = Some(branch.to_string());
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
        let instructions = self.build_security_review_instructions(
            base_prompt.as_str(),
            context_resolution.payload_json.as_deref(),
            min_confidence_score,
            ctx.additional_developer_instructions.as_deref(),
        );
        Ok(SecurityReviewPlan {
            base_prompt,
            min_confidence_score,
            instructions,
            context_resolution,
            base_branch: context_base_branch,
        })
    }

    async fn refresh_security_context_if_pending(
        &self,
        ctx: &ReviewContext,
        account: &AuthAccount,
        prepared: &PreparedRunnerSessionComponents,
        repo_path: &str,
        plan: &mut SecurityReviewPlan,
        extra_session: &ExtraSecurityContextSessionContainer,
    ) {
        if plan.context_resolution.build_guard.is_none() {
            return;
        }
        let base_branch = plan
            .base_branch
            .as_deref()
            .expect("security context base branch set when build is pending")
            .to_string();
        let base_head_sha = plan
            .context_resolution
            .build_base_head_sha
            .as_deref()
            .expect("security context base head SHA set when build is pending")
            .to_string();
        let build_result = self
            .build_security_context_with_separate_session(
                ctx,
                SeparateSecurityContextSessionRequest {
                    account,
                    browser_mcp: prepared.browser_mcp.as_ref(),
                    repo_path,
                    base_branch: base_branch.as_str(),
                    base_head_sha: base_head_sha.as_str(),
                    extra_session_container: Arc::clone(extra_session),
                },
            )
            .await;
        let mut build_guard = plan.context_resolution.build_guard.take();
        match build_result {
            Ok(payload_json) => {
                self.record_built_security_context(
                    ctx,
                    plan,
                    base_branch.as_str(),
                    base_head_sha.as_str(),
                    payload_json,
                )
                .await;
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
                    branch = base_branch.as_str(),
                    error = %err,
                    "failed to build cached security context; continuing without it"
                );
            }
        }
    }

    async fn record_built_security_context(
        &self,
        ctx: &ReviewContext,
        plan: &mut SecurityReviewPlan,
        base_branch: &str,
        base_head_sha: &str,
        payload_json: String,
    ) {
        let generated_at = Utc::now().timestamp();
        let expires_at =
            generated_at + ctx.security_context_ttl_seconds.unwrap_or(1_209_600) as i64;
        if let Err(err) = self
            .state
            .security_context_cache
            .upsert_security_review_context_cache(&crate::state::SecurityReviewContextCacheEntry {
                repo: self.security_context_cache_repo_key(ctx).to_string(),
                base_branch: base_branch.to_string(),
                base_head_sha: base_head_sha.to_string(),
                prompt_version: SECURITY_CONTEXT_PROMPT_VERSION.to_string(),
                payload_json: payload_json.clone(),
                source_run_history_id: ctx.run_history_id.unwrap_or_default(),
                generated_at,
                expires_at,
            })
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
        plan.context_resolution.payload_json = Some(payload_json.clone());
        plan.context_resolution.source_run_history_id = ctx.run_history_id;
        plan.context_resolution.generated_at = Some(generated_at);
        plan.context_resolution.expires_at = Some(expires_at);
        self.update_run_history_session(
            ctx.run_history_id,
            Self::security_context_session_update(
                plan.base_branch.as_deref(),
                &plan.context_resolution,
            ),
        )
        .await;
        plan.instructions = self.build_security_review_instructions(
            plan.base_prompt.as_str(),
            Some(payload_json.as_str()),
            plan.min_confidence_score,
            ctx.additional_developer_instructions.as_deref(),
        );
    }

    async fn run_security_review_turn(
        &self,
        ctx: &ReviewContext,
        session: &mut RunnerSession,
        thread_id: &str,
        repo_path: &str,
        plan: &SecurityReviewPlan,
    ) -> Result<String> {
        let turn_id = self
            .session_start_turn(
                session,
                json!({
                    "threadId": thread_id,
                    "cwd": repo_path,
                    "input": [
                        {
                            "type": "text",
                            "text": plan.instructions.as_str(),
                        }
                    ],
                    "outputSchema": Self::security_review_output_schema(),
                }),
                "turn/start missing turn id for security review",
            )
            .await?;
        let mut session_update = Self::security_context_session_update(
            plan.base_branch.as_deref(),
            &plan.context_resolution,
        );
        session_update.thread_id = Some(thread_id.to_string());
        session_update.turn_id = Some(turn_id.clone());
        session_update.auth_account_name = Some(session.auth_account_name.clone());
        self.update_run_history_session(ctx.run_history_id, session_update)
            .await;
        self.session_stream_turn_message(session, thread_id, &turn_id)
            .await
    }

    async fn run_general_review_turn(
        &self,
        ctx: &ReviewContext,
        session: &mut RunnerSession,
        thread_id: &str,
        repo_path: &str,
    ) -> Result<String> {
        let review_target = Self::review_target_value(
            self.resolve_review_target_request(ctx, &session.container_id, repo_path)
                .await,
        );
        let review_turn = self
            .session_start_review(session, thread_id, review_target)
            .await?;
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                thread_id: Some(thread_id.to_string()),
                turn_id: Some(review_turn.turn_id.clone()),
                review_thread_id: Some(review_turn.review_thread_id.clone()),
                auth_account_name: Some(session.auth_account_name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;
        self.session_stream_review(session, &review_turn.review_thread_id, &review_turn.turn_id)
            .await
    }

    async fn cleanup_extra_security_context_session(
        &self,
        extra_session: &ExtraSecurityContextSessionContainer,
    ) {
        let extra_session = {
            let mut slot = extra_session
                .lock()
                .expect("security context extra session lock poisoned");
            slot.take()
        };
        if let Some((extra_container_id, extra_browser_container_id)) = extra_session {
            self.cleanup_app_server_containers(
                &extra_container_id,
                extra_browser_container_id.as_deref(),
            )
            .await;
        }
    }

    pub(crate) async fn run_app_server_review_with_account(
        &self,
        ctx: &ReviewContext,
        account: &AuthAccount,
    ) -> Result<String> {
        let launch = self
            .launch_runner_session(SessionLaunchRequest {
                run_history_id: ctx.run_history_id,
                feature_flags: &ctx.feature_flags,
                project_path: &ctx.project_path,
                mcp_server_overrides: &self.codex.mcp_server_overrides.review,
                allow_gitlab_discovery: !ctx.lane.is_security(),
                auth_account: account,
                build_script: |prepared: &PreparedRunnerSessionComponents| {
                    self.command(
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
                    )
                },
            })
            .await?;
        let prepared = launch.prepared;
        let mut session = launch.session;
        let run_timeout = launch.run_timeout;
        let repo_path = repo_checkout_root(&ctx.project_path);
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(session.auth_account_name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;

        let run_started_at = Instant::now();
        let extra_security_context_session = ExtraSecurityContextSessionContainer::default();
        let browser_container_id = session.browser_container_id.clone();
        let browser_mcp = prepared.browser_mcp.clone();
        let review_result = self
            .run_session_with_timeout(
                browser_container_id.as_deref(),
                browser_mcp.as_ref(),
                run_timeout.saturating_sub(run_started_at.elapsed()),
                "codex review timed out",
                async {
                    self.initialize_session_and_install_deps(
                        &mut session,
                        SessionInitializeRequest {
                            repo_dir: repo_path.as_str(),
                            project_path: &ctx.project_path,
                            feature_flags: &ctx.feature_flags,
                            run_timeout,
                            run_started_at,
                            timeout_error: "codex review timed out",
                        },
                    )
                    .await?;

                    let extra_writable_roots = prepared.extra_writable_roots();
                    let mut security_plan = if ctx.lane.is_security() {
                        Some(
                            self.prepare_security_review_plan(
                                ctx,
                                &session.container_id,
                                repo_path.as_str(),
                            )
                            .await?,
                        )
                    } else {
                        None
                    };
                    let thread_id = self
                        .session_start_thread(
                            &mut session,
                            self.thread_start_params(
                                repo_path.as_str(),
                                None,
                                &extra_writable_roots,
                            ),
                            "thread/start missing thread id",
                        )
                        .await?;
                    let default_security_context_resolution =
                        SecurityContextPayloadResolution::default();
                    let security_context_resolution = security_plan
                        .as_ref()
                        .map(|plan| &plan.context_resolution)
                        .unwrap_or(&default_security_context_resolution);
                    let security_context_base_branch = security_plan
                        .as_ref()
                        .and_then(|plan| plan.base_branch.as_deref());
                    let mut session_update = Self::security_context_session_update(
                        security_context_base_branch,
                        security_context_resolution,
                    );
                    session_update.thread_id = Some(thread_id.clone());
                    session_update.auth_account_name = Some(session.auth_account_name.clone());
                    self.update_run_history_session(ctx.run_history_id, session_update)
                        .await;

                    if ctx.lane.is_security() {
                        let plan = security_plan
                            .as_mut()
                            .expect("security review plan built for security lane");
                        self.refresh_security_context_if_pending(
                            ctx,
                            account,
                            &prepared,
                            repo_path.as_str(),
                            plan,
                            &extra_security_context_session,
                        )
                        .await;
                        self.run_security_review_turn(
                            ctx,
                            &mut session,
                            &thread_id,
                            repo_path.as_str(),
                            plan,
                        )
                        .await
                    } else {
                        self.run_general_review_turn(
                            ctx,
                            &mut session,
                            &thread_id,
                            repo_path.as_str(),
                        )
                        .await
                    }
                },
            )
            .await;

        self.cleanup_extra_security_context_session(&extra_security_context_session)
            .await;
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

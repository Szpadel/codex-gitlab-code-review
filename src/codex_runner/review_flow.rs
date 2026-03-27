use super::{
    AppServerClient, AppServerCommandOptions, Arc, AuthAccount, AuthFailureKind, BrowserMcpConfig,
    CodexResult, Context, Deserialize, DockerCodexRunner, Duration, Instant, Mutex,
    PreparedGitLabDiscoveryMcp, Result, ReviewCodeLocation, ReviewComment, ReviewContext,
    ReviewFinding, ReviewLineRange, RunHistorySessionUpdate, SecurityContextBuildCompletionGuard,
    SecurityContextBuildKey, SecurityContextBuildRegistration, StartedAppServer, Utc, Value,
    anyhow, append_additional_review_instructions, bail, build_base_branch_review_prompt,
    build_commit_review_prompt, classify_auth_failure, classify_auth_failure_for_account, debug,
    info, json, repo_checkout_root, timeout, upstream_review_prompt_source_commit,
    upstream_review_prompt_source_path, warn,
};
use crate::composer_install::composer_install_timeout_seconds;
use crate::review_lane::ReviewLane;

#[derive(Debug, Deserialize)]
pub(crate) struct CodexOutput {
    verdict: String,
    summary: String,
    comment_markdown: String,
}

#[derive(Debug, Deserialize)]
struct ReviewOutputPayload {
    #[serde(default)]
    findings: Vec<ReviewFindingPayload>,
    #[serde(default)]
    overall_explanation: Option<String>,
    #[serde(default)]
    overall_correctness: Option<String>,
    #[serde(default)]
    overall_confidence_score: Option<f32>,
}

#[derive(Debug, Deserialize)]
struct ReviewFindingPayload {
    title: String,
    body: String,
    #[serde(default)]
    confidence_score: Option<f32>,
    #[serde(default)]
    priority: Option<u8>,
    code_location: ReviewCodeLocationPayload,
}

#[derive(Debug, Deserialize)]
struct ReviewCodeLocationPayload {
    absolute_file_path: String,
    line_range: ReviewLineRangePayload,
}

#[derive(Debug, Deserialize)]
struct ReviewLineRangePayload {
    start: usize,
    end: usize,
}

#[derive(Default)]
struct SecurityContextPayloadResolution {
    payload_json: Option<String>,
    source_run_history_id: Option<i64>,
    base_head_sha: Option<String>,
    build_base_head_sha: Option<String>,
    generated_at: Option<i64>,
    expires_at: Option<i64>,
    build_guard: Option<SecurityContextBuildCompletionGuard>,
}

struct SecurityContextPayloadRequest<'a> {
    client: &'a mut AppServerClient,
    gitlab_discovery_server_name: Option<&'a str>,
    thread_id: &'a str,
    turn_cwd: &'a str,
    base_branch: &'a str,
    base_head_sha: &'a str,
}

type ExtraSecurityContextSessionContainer = Arc<Mutex<Option<(String, Option<String>)>>>;

struct SeparateSecurityContextSessionRequest<'a> {
    account: &'a AuthAccount,
    browser_mcp: Option<&'a BrowserMcpConfig>,
    repo_path: &'a str,
    base_branch: &'a str,
    base_head_sha: &'a str,
    extra_session_container: ExtraSecurityContextSessionContainer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewTargetRequest {
    NativeBaseBranch { branch: String },
    Custom { instructions: String },
}

const SINGLE_REVIEW_HEADER: &str = "Review comment:";
const MULTI_REVIEW_HEADER: &str = "Full review comments:";
const SECURITY_CONTEXT_PROMPT_VERSION: &str = "security-review-context-v1";
const SECURITY_REVIEW_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("assets/security_review_instructions.md");

impl DockerCodexRunner {
    pub(crate) fn security_context_cache_repo_key<'a>(&self, ctx: &'a ReviewContext) -> &'a str {
        ctx.repo.as_str()
    }

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

    fn security_review_instructions(
        &self,
        min_confidence_score: f32,
        additional_developer_instructions: Option<&str>,
    ) -> String {
        let base = SECURITY_REVIEW_INSTRUCTIONS_TEMPLATE.replace(
            "@@MIN_CONFIDENCE_SCORE@@",
            &format!("{min_confidence_score:.2}"),
        );
        if let Some(extra) = additional_developer_instructions
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            format!("{base}\n\nSecurity review additions:\n{extra}")
        } else {
            base
        }
    }

    pub(crate) fn security_context_output_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "components",
                "entry_points",
                "trust_boundaries",
                "attacker_controlled_inputs",
                "privileged_operations",
                "sensitive_assets",
                "security_critical_paths",
                "runtime_notes",
                "focus_paths"
            ],
            "properties": {
                "components": { "type": "array", "items": { "type": "string" } },
                "entry_points": { "type": "array", "items": { "type": "string" } },
                "trust_boundaries": { "type": "array", "items": { "type": "string" } },
                "attacker_controlled_inputs": { "type": "array", "items": { "type": "string" } },
                "privileged_operations": { "type": "array", "items": { "type": "string" } },
                "sensitive_assets": { "type": "array", "items": { "type": "string" } },
                "security_critical_paths": { "type": "array", "items": { "type": "string" } },
                "runtime_notes": { "type": "array", "items": { "type": "string" } },
                "focus_paths": { "type": "array", "items": { "type": "string" } }
            },
            "additionalProperties": false
        })
    }

    fn security_review_output_schema() -> Value {
        json!({
            "type": "object",
            "required": [
                "findings",
                "overall_explanation",
                "overall_correctness",
                "overall_confidence_score"
            ],
            "properties": {
                "findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "required": [
                            "title",
                            "body",
                            "confidence_score",
                            "priority",
                            "code_location"
                        ],
                        "properties": {
                            "title": { "type": "string" },
                            "body": { "type": "string" },
                            "confidence_score": { "type": "number" },
                            "priority": { "type": ["integer", "null"] },
                            "code_location": {
                                "type": "object",
                                "required": ["absolute_file_path", "line_range"],
                                "properties": {
                                    "absolute_file_path": { "type": "string" },
                                    "line_range": {
                                        "type": "object",
                                        "required": ["start", "end"],
                                        "properties": {
                                            "start": { "type": "integer" },
                                            "end": { "type": "integer" }
                                        },
                                        "additionalProperties": false
                                    }
                                },
                                "additionalProperties": false
                            }
                        },
                        "additionalProperties": false
                    }
                },
                "overall_explanation": { "type": ["string", "null"] },
                "overall_correctness": {
                    "type": "string",
                    "enum": ["patch is correct", "patch is incorrect"]
                },
                "overall_confidence_score": { "type": ["number", "null"] }
            },
            "additionalProperties": false
        })
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

    async fn try_resolve_base_branch_head_sha(
        &self,
        ctx: &ReviewContext,
        container_id: &str,
        repo_path: &str,
        branch: &str,
    ) -> Option<String> {
        let remote_branch_ref = format!("refs/remotes/origin/{branch}");
        let output = match self
            .exec_container_git_command(
                container_id,
                &["rev-parse".to_string(), remote_branch_ref.clone()],
                Some(repo_path),
            )
            .await
        {
            Ok(output) => output,
            Err(err) => {
                warn!(
                    repo = ctx.repo.as_str(),
                    iid = ctx.mr.iid,
                    branch,
                    remote_branch_ref,
                    error = %err,
                    "failed to resolve target branch head SHA locally for security context"
                );
                return ctx
                    .mr
                    .diff_refs
                    .as_ref()
                    .and_then(|diff| diff.base_sha.clone())
                    .filter(|value| !value.trim().is_empty());
            }
        };
        let resolved = output.stdout.trim();
        if resolved.is_empty() {
            ctx.mr
                .diff_refs
                .as_ref()
                .and_then(|diff| diff.base_sha.clone())
                .filter(|value| !value.trim().is_empty())
        } else {
            Some(resolved.to_string())
        }
    }

    async fn create_security_context_worktree(
        &self,
        container_id: &str,
        repo_path: &str,
        base_head_sha: &str,
    ) -> Result<String> {
        let tmpdir = self
            .exec_container_command(
                container_id,
                vec![
                    "mktemp".to_string(),
                    "-d".to_string(),
                    "/tmp/codex-security-context-XXXXXX".to_string(),
                ],
                Some(repo_path),
            )
            .await?
            .stdout
            .trim()
            .to_string();
        if tmpdir.is_empty() {
            bail!("failed to allocate temporary worktree path for security context");
        }
        if let Err(err) = self
            .exec_container_git_command(
                container_id,
                &[
                    "worktree".to_string(),
                    "add".to_string(),
                    "--detach".to_string(),
                    tmpdir.clone(),
                    base_head_sha.to_string(),
                ],
                Some(repo_path),
            )
            .await
        {
            self.remove_security_context_tempdir(container_id, repo_path, &tmpdir)
                .await;
            return Err(err);
        }
        Ok(tmpdir)
    }

    async fn remove_security_context_tempdir(
        &self,
        container_id: &str,
        repo_path: &str,
        worktree_path: &str,
    ) {
        if let Err(err) = self
            .exec_container_command(
                container_id,
                vec![
                    "rm".to_string(),
                    "-rf".to_string(),
                    worktree_path.to_string(),
                ],
                Some(repo_path),
            )
            .await
        {
            warn!(
                container_id,
                worktree_path,
                error = %err,
                "failed to remove temporary security context directory"
            );
        }
    }

    async fn remove_security_context_worktree(
        &self,
        container_id: &str,
        repo_path: &str,
        worktree_path: &str,
    ) {
        if let Err(err) = self
            .exec_container_git_command(
                container_id,
                &[
                    "worktree".to_string(),
                    "remove".to_string(),
                    "--force".to_string(),
                    worktree_path.to_string(),
                ],
                Some(repo_path),
            )
            .await
        {
            warn!(
                container_id,
                worktree_path,
                error = %err,
                "failed to remove security context worktree"
            );
        }
    }

    async fn build_security_context_payload(
        &self,
        ctx: &ReviewContext,
        request: SecurityContextPayloadRequest<'_>,
    ) -> Result<String> {
        let turn_response = request
            .client
            .request(
                "turn/start",
                json!({
                    "threadId": request.thread_id,
                    "cwd": request.turn_cwd,
                    "input": [
                        {
                            "type": "text",
                            "text": format!(
                                "$security-threat-model Build a concise repository-grounded threat model for the base branch.\nReturn only JSON matching the provided output schema.\nFocus on runtime behavior on branch {} at commit {}.\nKeep the result compact and evidence-based.",
                                request.base_branch, request.base_head_sha
                            ),
                        },
                        {
                            "type": "skill",
                            "name": "security-threat-model",
                            "path": format!(
                                "{}/skills/security-threat-model/SKILL.md",
                                self.codex.auth_mount_path.trim_end_matches('/')
                            ),
                        }
                    ],
                    "outputSchema": Self::security_context_output_schema(),
                }),
            )
            .await?;
        let turn_id = turn_response
            .get("turn")
            .and_then(|turn| turn.get("id"))
            .and_then(|id| id.as_str())
            .ok_or_else(|| anyhow!("turn/start missing turn id for security context"))?
            .to_string();
        let output = request
            .client
            .stream_turn_message(
                request.thread_id,
                &turn_id,
                request.gitlab_discovery_server_name,
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
        let payload: Value =
            serde_json::from_str(output.trim()).context("parse security context JSON payload")?;
        if !payload.is_object() {
            bail!("security context output must be a JSON object");
        }
        serde_json::to_string(&payload).context("serialize security context cache payload")
    }

    async fn resolve_security_context_payload(
        &self,
        ctx: &ReviewContext,
        container_id: &str,
        repo_path: &str,
        base_branch: &str,
    ) -> Result<SecurityContextPayloadResolution> {
        let Some(base_head_sha) = self
            .try_resolve_base_branch_head_sha(ctx, container_id, repo_path, base_branch)
            .await
        else {
            return Ok(SecurityContextPayloadResolution::default());
        };
        let cache_repo_key = self.security_context_cache_repo_key(ctx);
        let now = Utc::now().timestamp();
        if let Some(entry) = self
            .state
            .get_security_review_context_cache(
                cache_repo_key,
                base_branch,
                base_head_sha.as_str(),
                SECURITY_CONTEXT_PROMPT_VERSION,
                now,
            )
            .await?
        {
            return Ok(SecurityContextPayloadResolution {
                payload_json: Some(entry.payload_json),
                source_run_history_id: (entry.source_run_history_id > 0)
                    .then_some(entry.source_run_history_id),
                base_head_sha: Some(base_head_sha.clone()),
                build_base_head_sha: Some(base_head_sha.clone()),
                generated_at: Some(entry.generated_at),
                expires_at: Some(entry.expires_at),
                build_guard: None,
            });
        }
        if ctx.feature_flags.security_context_ignore_base_head
            && let Some(entry) = self
                .state
                .get_latest_security_review_context_cache_for_branch(
                    cache_repo_key,
                    base_branch,
                    SECURITY_CONTEXT_PROMPT_VERSION,
                    now,
                )
                .await?
        {
            return Ok(SecurityContextPayloadResolution {
                payload_json: Some(entry.payload_json),
                source_run_history_id: (entry.source_run_history_id > 0)
                    .then_some(entry.source_run_history_id),
                base_head_sha: Some(entry.base_head_sha),
                build_base_head_sha: Some(base_head_sha),
                generated_at: Some(entry.generated_at),
                expires_at: Some(entry.expires_at),
                build_guard: None,
            });
        }
        let build_key = SecurityContextBuildKey {
            repo: cache_repo_key.to_string(),
            base_branch: base_branch.to_string(),
            base_head_sha: base_head_sha.clone(),
            prompt_version: SECURITY_CONTEXT_PROMPT_VERSION.to_string(),
        };
        match self.register_security_context_build(build_key) {
            SecurityContextBuildRegistration::Leader(build_guard) => {
                let now = Utc::now().timestamp();
                if let Some(entry) = self
                    .state
                    .get_security_review_context_cache(
                        cache_repo_key,
                        base_branch,
                        base_head_sha.as_str(),
                        SECURITY_CONTEXT_PROMPT_VERSION,
                        now,
                    )
                    .await?
                {
                    build_guard.complete();
                    return Ok(SecurityContextPayloadResolution {
                        payload_json: Some(entry.payload_json),
                        source_run_history_id: (entry.source_run_history_id > 0)
                            .then_some(entry.source_run_history_id),
                        base_head_sha: Some(base_head_sha.clone()),
                        build_base_head_sha: Some(base_head_sha.clone()),
                        generated_at: Some(entry.generated_at),
                        expires_at: Some(entry.expires_at),
                        build_guard: None,
                    });
                }
                if ctx.feature_flags.security_context_ignore_base_head
                    && let Some(entry) = self
                        .state
                        .get_latest_security_review_context_cache_for_branch(
                            cache_repo_key,
                            base_branch,
                            SECURITY_CONTEXT_PROMPT_VERSION,
                            now,
                        )
                        .await?
                {
                    build_guard.complete();
                    return Ok(SecurityContextPayloadResolution {
                        payload_json: Some(entry.payload_json),
                        source_run_history_id: (entry.source_run_history_id > 0)
                            .then_some(entry.source_run_history_id),
                        base_head_sha: Some(entry.base_head_sha),
                        build_base_head_sha: Some(base_head_sha.clone()),
                        generated_at: Some(entry.generated_at),
                        expires_at: Some(entry.expires_at),
                        build_guard: None,
                    });
                }
                Ok(SecurityContextPayloadResolution {
                    payload_json: None,
                    source_run_history_id: None,
                    base_head_sha: Some(base_head_sha.clone()),
                    build_base_head_sha: Some(base_head_sha.clone()),
                    generated_at: None,
                    expires_at: None,
                    build_guard: Some(build_guard),
                })
            }
            SecurityContextBuildRegistration::Follower(slot) => {
                debug!(
                    repo = ctx.repo.as_str(),
                    iid = ctx.mr.iid,
                    branch = base_branch,
                    base_head_sha,
                    "waiting for in-flight security context build"
                );
                slot.wait().await;
                let now = Utc::now().timestamp();
                if let Some(entry) = self
                    .state
                    .get_security_review_context_cache(
                        cache_repo_key,
                        base_branch,
                        base_head_sha.as_str(),
                        SECURITY_CONTEXT_PROMPT_VERSION,
                        now,
                    )
                    .await?
                {
                    return Ok(SecurityContextPayloadResolution {
                        payload_json: Some(entry.payload_json),
                        source_run_history_id: (entry.source_run_history_id > 0)
                            .then_some(entry.source_run_history_id),
                        base_head_sha: Some(base_head_sha.clone()),
                        build_base_head_sha: Some(base_head_sha.clone()),
                        generated_at: Some(entry.generated_at),
                        expires_at: Some(entry.expires_at),
                        build_guard: None,
                    });
                }
                if ctx.feature_flags.security_context_ignore_base_head
                    && let Some(entry) = self
                        .state
                        .get_latest_security_review_context_cache_for_branch(
                            cache_repo_key,
                            base_branch,
                            SECURITY_CONTEXT_PROMPT_VERSION,
                            now,
                        )
                        .await?
                {
                    return Ok(SecurityContextPayloadResolution {
                        payload_json: Some(entry.payload_json),
                        source_run_history_id: (entry.source_run_history_id > 0)
                            .then_some(entry.source_run_history_id),
                        base_head_sha: Some(entry.base_head_sha),
                        build_base_head_sha: Some(base_head_sha.clone()),
                        generated_at: Some(entry.generated_at),
                        expires_at: Some(entry.expires_at),
                        build_guard: None,
                    });
                }
                debug!(
                    repo = ctx.repo.as_str(),
                    iid = ctx.mr.iid,
                    branch = base_branch,
                    base_head_sha,
                    "in-flight security context build finished without a cached result"
                );
                Ok(SecurityContextPayloadResolution {
                    payload_json: None,
                    source_run_history_id: None,
                    base_head_sha: Some(base_head_sha.clone()),
                    build_base_head_sha: Some(base_head_sha.clone()),
                    generated_at: None,
                    expires_at: None,
                    build_guard: None,
                })
            }
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

    fn build_security_review_instructions(
        &self,
        base_prompt: &str,
        security_context_payload_json: Option<&str>,
        min_confidence_score: f32,
        additional_developer_instructions: Option<&str>,
    ) -> String {
        let mut prompt = base_prompt.to_string();
        if let Some(payload_json) = security_context_payload_json
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            prompt.push_str("\n\nCached repository security context (base branch):\n");
            prompt.push_str(payload_json);
        }
        prompt.push_str("\n\n");
        prompt.push_str(
            self.security_review_instructions(
                min_confidence_score,
                additional_developer_instructions,
            )
            .trim(),
        );
        prompt
    }

    fn security_context_session_update(
        base_branch: Option<&str>,
        resolution: &SecurityContextPayloadResolution,
    ) -> RunHistorySessionUpdate {
        if resolution.base_head_sha.is_none() {
            return RunHistorySessionUpdate::default();
        }
        RunHistorySessionUpdate {
            security_context_source_run_id: resolution.source_run_history_id,
            security_context_base_branch: base_branch.map(ToOwned::to_owned),
            security_context_base_head_sha: resolution.base_head_sha.clone(),
            security_context_prompt_version: Some(SECURITY_CONTEXT_PROMPT_VERSION.to_string()),
            security_context_payload_json: resolution.payload_json.clone(),
            security_context_generated_at: resolution.generated_at,
            security_context_expires_at: resolution.expires_at,
            ..RunHistorySessionUpdate::default()
        }
    }

    async fn build_security_context_with_separate_session(
        &self,
        ctx: &ReviewContext,
        request: SeparateSecurityContextSessionRequest<'_>,
    ) -> Result<String> {
        let script = self.command(
            ctx,
            AppServerCommandOptions {
                browser_mcp: request.browser_mcp,
                gitlab_discovery_mcp: None,
                mcp_server_overrides: &self.codex.mcp_server_overrides.review,
                reasoning_summary: None,
                reasoning_effort: None,
            },
            self.security_context_reasoning_effort(),
        )?;
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(
                script,
                &request.account.auth_host_path,
                Vec::new(),
                Vec::new(),
                request.browser_mcp,
                Vec::new(),
            )
            .await?;
        {
            let mut slot = request
                .extra_session_container
                .lock()
                .expect("security context extra session lock poisoned");
            *slot = Some((container_id.clone(), browser_container_id.clone()));
        }

        let build_result = async {
            client.initialize().await?;
            client.initialized().await?;
            let worktree_path = self
                .create_security_context_worktree(
                    &container_id,
                    request.repo_path,
                    request.base_head_sha,
                )
                .await?;
            let thread_response = client
                .request(
                    "thread/start",
                    self.thread_start_params(request.repo_path, None, &[worktree_path.clone()]),
                )
                .await?;
            let thread_id = thread_response
                .get("thread")
                .and_then(|thread| thread.get("id"))
                .and_then(|id| id.as_str())
                .ok_or_else(|| anyhow!("thread/start missing thread id for security context"))?
                .to_string();
            let build_result = self
                .build_security_context_payload(
                    ctx,
                    SecurityContextPayloadRequest {
                        client: &mut client,
                        gitlab_discovery_server_name: None,
                        thread_id: &thread_id,
                        turn_cwd: &worktree_path,
                        base_branch: request.base_branch,
                        base_head_sha: request.base_head_sha,
                    },
                )
                .await;
            self.remove_security_context_worktree(&container_id, request.repo_path, &worktree_path)
                .await;
            build_result
        }
        .await;

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;
        {
            let mut slot = request
                .extra_session_container
                .lock()
                .expect("security context extra session lock poisoned");
            *slot = None;
        }

        build_result
    }

    pub(crate) async fn run_app_server_review_with_account(
        &self,
        ctx: &ReviewContext,
        account: &AuthAccount,
    ) -> Result<String> {
        let browser_mcp = self.effective_browser_mcp(&self.codex.mcp_server_overrides.review);
        let gitlab_discovery_mcp = self.prepare_review_gitlab_discovery_mcp(ctx);
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
            if ctx.lane.is_security() {
                self.security_review_reasoning_effort()
            } else {
                self.review_reasoning_effort()
            },
        )?;
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
                        .map_or("<unknown>", |prepared| {
                            prepared.runtime_config.advertise_url.as_str()
                        }),
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
        let repo_path = repo_checkout_root(&ctx.project_path);
        self.update_run_history_session(
            ctx.run_history_id,
            RunHistorySessionUpdate {
                auth_account_name: Some(account.name.clone()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await;
        let run_timeout = Duration::from_secs(self.codex.timeout_seconds);
        let run_started_at = Instant::now();
        let extra_security_context_session = Arc::new(Mutex::new(None::<(String, Option<String>)>));
        let review_result = timeout(
            run_timeout.saturating_sub(run_started_at.elapsed()),
            async {
                client.initialize().await?;
                client.initialized().await?;
                let Some(composer_timeout_seconds) = composer_install_timeout_seconds(
                    run_timeout.saturating_sub(run_started_at.elapsed()),
                ) else {
                    bail!("codex review timed out");
                };
                let _composer_install = self
                    .run_composer_install_step(
                        &container_id,
                        repo_path.as_str(),
                        &ctx.project_path,
                        &ctx.feature_flags,
                        composer_timeout_seconds,
                        ctx.run_history_id,
                    )
                    .await;
                let extra_writable_roots = gitlab_discovery_mcp
                    .as_ref()
                    .map(|prepared| vec![prepared.runtime_config.clone_root.clone()])
                    .unwrap_or_default();
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
                        self.try_resolve_review_merge_base(&container_id, repo_path.as_str(), branch)
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
                                &container_id,
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
                let thread_response = client
                    .request(
                        "thread/start",
                        self.thread_start_params(repo_path.as_str(), None, &extra_writable_roots),
                    )
                    .await?;
                let thread_id = match thread_response
                    .get("thread")
                    .and_then(|thread| thread.get("id"))
                    .and_then(|id| id.as_str())
                {
                    Some(thread_id) => thread_id.to_string(),
                    None => bail!("thread/start missing thread id"),
                };
                let mut session_update = Self::security_context_session_update(
                    security_context_base_branch.as_deref(),
                    &security_context_resolution,
                );
                session_update.thread_id = Some(thread_id.clone());
                session_update.auth_account_name = Some(account.name.clone());
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
                                    browser_mcp,
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
                                    .upsert_security_review_context_cache(
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
                    let turn_response = client
                        .request(
                            "turn/start",
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
                        )
                        .await?;
                    let turn_id = turn_response
                        .get("turn")
                        .and_then(|turn| turn.get("id"))
                        .and_then(|id| id.as_str())
                        .ok_or_else(|| anyhow!("turn/start missing turn id for security review"))?
                        .to_string();
                    let mut session_update = Self::security_context_session_update(
                        security_context_base_branch.as_deref(),
                        &security_context_resolution,
                    );
                    session_update.thread_id = Some(thread_id.clone());
                    session_update.turn_id = Some(turn_id.clone());
                    session_update.auth_account_name = Some(account.name.clone());
                    self.update_run_history_session(ctx.run_history_id, session_update)
                        .await;
                    client
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
                        .await
                } else {
                    let review_target = Self::review_target_value(
                        self.resolve_review_target_request(ctx, &container_id, repo_path.as_str())
                            .await,
                    );
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
                            ..RunHistorySessionUpdate::default()
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
                }
            },
        )
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

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;
        self.unregister_gitlab_discovery_session(gitlab_discovery_session.as_ref())
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

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn parse_review_output(text: &str) -> Result<CodexResult> {
    parse_review_output_for_lane(text, ReviewLane::General, None)
}

pub(crate) fn parse_review_output_for_lane(
    text: &str,
    lane: ReviewLane,
    min_confidence_score: Option<f32>,
) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        if lane.is_security() {
            bail!("security review output must be a structured JSON object");
        }
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if lane.is_security() {
        let parsed = serde_json::from_str::<ReviewOutputPayload>(trimmed)
            .map_err(|_| anyhow!("security review output must be a structured JSON object"))?;
        if !review_output_payload_looks_structured(&parsed) {
            bail!("security review output must be a structured JSON object");
        }
        return parse_structured_review_output(parsed, lane, min_confidence_score);
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<ReviewOutputPayload>(&json_text)
        && review_output_payload_looks_structured(&parsed)
    {
        return parse_structured_review_output(parsed, lane, min_confidence_score);
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<CodexOutput>(&json_text)
    {
        return match parsed.verdict.as_str() {
            "pass" => Ok(CodexResult::Pass {
                summary: parsed.summary,
            }),
            "comment" => Ok(CodexResult::Comment(ReviewComment {
                summary: parsed.summary,
                overall_explanation: None,
                overall_confidence_score: None,
                findings: Vec::new(),
                body: parsed.comment_markdown,
            })),
            other => Err(anyhow!("unknown verdict: {other}")),
        };
    }

    Ok(CodexResult::Comment(parse_rendered_review_comment(trimmed)))
}

pub(crate) fn extract_json_block(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end < start {
        return None;
    }
    Some(text[start..=end].to_string())
}

fn parse_structured_review_output(
    parsed: ReviewOutputPayload,
    lane: ReviewLane,
    min_confidence_score: Option<f32>,
) -> Result<CodexResult> {
    let original_findings_count = parsed.findings.len();
    if lane.is_security()
        && parsed
            .findings
            .iter()
            .any(|finding| finding.confidence_score.is_none())
    {
        bail!("security review findings must include confidence_score");
    }
    if lane.is_security()
        && parsed.findings.iter().any(|finding| {
            !matches!(
                finding.confidence_score,
                Some(score) if score.is_finite() && (0.0..=1.0).contains(&score)
            )
        })
    {
        bail!("security review findings must use confidence_score values between 0.0 and 1.0");
    }

    let findings = parsed
        .findings
        .into_iter()
        .map(|finding| ReviewFinding {
            title: finding.title,
            body: finding.body,
            confidence_score: finding.confidence_score,
            priority: finding.priority,
            code_location: ReviewCodeLocation {
                absolute_file_path: finding.code_location.absolute_file_path,
                line_range: ReviewLineRange {
                    start: finding.code_location.line_range.start,
                    end: finding.code_location.line_range.end,
                },
            },
        })
        .collect::<Vec<_>>();
    let overall_explanation = parsed.overall_explanation.and_then(trim_to_option);
    let overall_confidence_score = parsed.overall_confidence_score;
    let findings = if lane.is_security() {
        let threshold = validated_security_min_confidence_score(
            min_confidence_score,
            "security review min_confidence_score",
        )?;
        findings
            .into_iter()
            .filter(|finding| finding.confidence_score.unwrap_or(0.0) >= threshold)
            .collect::<Vec<_>>()
    } else {
        findings
    };
    if findings.is_empty() && lane.is_security() {
        if parsed.overall_correctness.is_none() {
            bail!("security review output must include overall_correctness");
        }
        if parsed.overall_correctness.as_deref() == Some("patch is incorrect")
            && original_findings_count == 0
        {
            bail!("security review marked patch incorrect without confirmed findings");
        }
        return Ok(CodexResult::Pass {
            summary: overall_explanation
                .unwrap_or_else(|| "no confirmed security issues found".to_string()),
        });
    }
    if findings.is_empty()
        && parsed
            .overall_correctness
            .as_deref()
            .is_some_and(|value| value == "patch is correct")
    {
        return Ok(CodexResult::Pass {
            summary: overall_explanation.unwrap_or_else(|| "no issues found".to_string()),
        });
    }
    let body = render_review_comment_body(overall_explanation.as_deref(), &findings);
    Ok(CodexResult::Comment(ReviewComment {
        summary: summary_from_text(body.as_str()),
        overall_explanation,
        overall_confidence_score,
        findings,
        body,
    }))
}

fn validated_security_min_confidence_score(
    min_confidence_score: Option<f32>,
    field_name: &str,
) -> Result<f32> {
    let threshold = min_confidence_score.unwrap_or(0.85);
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(threshold)
    } else {
        bail!("{field_name} must be a finite number between 0.0 and 1.0");
    }
}

fn review_output_payload_looks_structured(payload: &ReviewOutputPayload) -> bool {
    !payload.findings.is_empty()
        || payload
            .overall_explanation
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
        || payload.overall_correctness.is_some()
}

fn parse_rendered_review_comment(text: &str) -> ReviewComment {
    let lines = text.lines().collect::<Vec<_>>();
    let header_idx = lines.iter().position(|line| {
        let trimmed = line.trim();
        trimmed == SINGLE_REVIEW_HEADER || trimmed == MULTI_REVIEW_HEADER
    });

    let (overall_explanation, findings) = if let Some(header_idx) = header_idx {
        let explanation = lines[..header_idx].join("\n");
        let findings = parse_rendered_review_findings(&lines[(header_idx + 1)..]);
        (trim_to_option(explanation), findings)
    } else {
        (trim_to_option(text.to_string()), Vec::new())
    };

    ReviewComment {
        summary: summary_from_text(text),
        overall_explanation,
        overall_confidence_score: None,
        findings,
        body: text.to_string(),
    }
}

fn parse_rendered_review_findings(lines: &[&str]) -> Vec<ReviewFinding> {
    let mut findings = Vec::new();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx];
        if !line.starts_with("- ") {
            idx += 1;
            continue;
        }

        let Some((title, location)) = line[2..].rsplit_once(" — ") else {
            idx += 1;
            continue;
        };
        let Some(code_location) = parse_rendered_location(location) else {
            idx += 1;
            continue;
        };

        idx += 1;
        let mut body_lines = Vec::new();
        while idx < lines.len() {
            let current = lines[idx];
            if current.starts_with("- ") {
                break;
            }
            if let Some(stripped) = current.strip_prefix("  ") {
                body_lines.push(stripped);
            } else if current.trim().is_empty() {
                body_lines.push("");
            }
            idx += 1;
        }

        findings.push(ReviewFinding {
            title: title.trim().to_string(),
            body: body_lines.join("\n").trim().to_string(),
            confidence_score: None,
            priority: None,
            code_location,
        });
    }
    findings
}

fn parse_rendered_location(text: &str) -> Option<ReviewCodeLocation> {
    let (path, range) = text.rsplit_once(':')?;
    let (start, end) = range.split_once('-')?;
    Some(ReviewCodeLocation {
        absolute_file_path: path.to_string(),
        line_range: ReviewLineRange {
            start: start.parse().ok()?,
            end: end.parse().ok()?,
        },
    })
}

fn render_review_comment_body(
    overall_explanation: Option<&str>,
    findings: &[ReviewFinding],
) -> String {
    let mut sections = Vec::new();
    if let Some(overall_explanation) = overall_explanation
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        sections.push(overall_explanation.to_string());
    }
    if !findings.is_empty() {
        sections.push(render_review_findings_block(findings));
    }
    if sections.is_empty() {
        "Reviewer failed to output a response.".to_string()
    } else {
        sections.join("\n\n")
    }
}

fn render_review_findings_block(findings: &[ReviewFinding]) -> String {
    let mut lines = Vec::new();
    lines.push(if findings.len() > 1 {
        MULTI_REVIEW_HEADER.to_string()
    } else {
        SINGLE_REVIEW_HEADER.to_string()
    });
    for finding in findings {
        lines.push(String::new());
        lines.push(format!(
            "- {} — {}:{}-{}",
            finding.title,
            finding.code_location.absolute_file_path,
            finding.code_location.line_range.start,
            finding.code_location.line_range.end
        ));
        if !finding.body.is_empty() {
            for body_line in finding.body.lines() {
                lines.push(format!("  {body_line}"));
            }
        }
    }
    lines.join("\n")
}

fn summary_from_text(text: &str) -> String {
    text.lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Codex review")
        .trim()
        .to_string()
}

fn trim_to_option(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_review_instructions_require_sectioned_findings_and_plain_references() {
        let base =
            SECURITY_REVIEW_INSTRUCTIONS_TEMPLATE.replace("@@MIN_CONFIDENCE_SCORE@@", "0.85");
        let instructions = format!(
            "{base}\n\nSecurity review additions:\n{}",
            "Prefer proving tenant-boundary impact."
        );
        let (core, additions) = instructions
            .split_once("\n\nSecurity review additions:\n")
            .expect("extra instructions section");
        assert_eq!(additions, "Prefer proving tenant-boundary impact.");

        let validation_rules = core
            .split_once("Validation rules:\n")
            .and_then(|(_, rest)| {
                rest.split_once("\n\nPrompt-injection and exfiltration resistance:")
            })
            .map(|(section, _)| section)
            .expect("validation rules block");
        let lines = validation_rules.lines().collect::<Vec<_>>();
        let section_heading_idx = lines
            .iter()
            .position(|line| {
                *line
                    == "- Each finding body must use these exact Markdown section labels, in this exact order:"
            })
            .expect("section heading marker");
        let required_section_labels = lines[(section_heading_idx + 1)..]
            .iter()
            .copied()
            .take_while(|line| line.starts_with("  - "))
            .collect::<Vec<_>>();
        assert_eq!(
            required_section_labels,
            [
                "  - `**Summary**`",
                "  - `**Severity**`",
                "  - `**Reproduction**`",
                "  - `**Evidence**`",
                "  - `**Attack-path analysis**`",
                "  - `**Likelihood**`",
                "  - `**Impact**`",
                "  - `**Assumptions**`",
                "  - `**Blindspots**`",
            ]
        );
        for required_rule in [
            "- Put each label on its own line, then the section content on the following line(s).",
            "- Fill every section. If a section has no extra detail, say `None.` rather than omitting it.",
            "- The `**Severity**` section must include the severity level and why it fits.",
            "- The `**Reproduction**` section must give the fastest realistic developer repro path.",
            "- The `**Evidence**` section must cite the exact proof from the repo, runtime behavior, or validation artifact.",
            "- The `**Attack-path analysis**` section must explain the attacker-controlled input, boundary crossing, failed guard, and sink.",
            "- When citing repository locations in the narrative sections, use checked-out file references like `/work/repo/<project-path>/src/auth.rs:42` or `/work/repo/<project-path>/src/auth.rs:42-47`.",
            "- Do not wrap repository-location references in backticks or code fences.",
        ] {
            assert!(
                validation_rules.contains(required_rule),
                "missing validation rule: {required_rule}"
            );
        }
    }
}

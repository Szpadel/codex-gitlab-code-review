//! Security-review context cache lifecycle and separate-session context building.

use super::session_runner::{PreparedRunnerSessionComponents, standard_session_launch_request};
use super::{
    AppServerClient, AppServerCommandOptions, Arc, AuthAccount, BrowserMcpConfig, Context,
    DockerCodexRunner, Mutex, Result, ReviewContext, RunHistorySessionUpdate,
    SecurityContextBuildCompletionGuard, SecurityContextBuildKey, SecurityContextBuildRegistration,
    Utc, Value, anyhow, bail, debug, json, warn,
};
use crate::codex_runner::placeholders::render_placeholders;

#[derive(Default)]
pub(super) struct SecurityContextPayloadResolution {
    pub(super) payload_json: Option<String>,
    pub(super) source_run_history_id: Option<i64>,
    pub(super) base_head_sha: Option<String>,
    pub(super) build_base_head_sha: Option<String>,
    pub(super) generated_at: Option<i64>,
    pub(super) expires_at: Option<i64>,
    pub(super) build_guard: Option<SecurityContextBuildCompletionGuard>,
}

struct SecurityContextPayloadRequest<'a> {
    client: &'a mut AppServerClient,
    gitlab_discovery_server_name: Option<&'a str>,
    thread_id: &'a str,
    turn_cwd: &'a str,
    base_branch: &'a str,
    base_head_sha: &'a str,
}

pub(super) type ExtraSecurityContextSessionContainer = Arc<Mutex<Option<(String, Option<String>)>>>;

pub(super) struct SeparateSecurityContextSessionRequest<'a> {
    pub(super) account: &'a AuthAccount,
    pub(super) browser_mcp: Option<&'a BrowserMcpConfig>,
    pub(super) repo_path: &'a str,
    pub(super) base_branch: &'a str,
    pub(super) base_head_sha: &'a str,
    pub(super) extra_session_container: ExtraSecurityContextSessionContainer,
}

pub(super) const SECURITY_CONTEXT_PROMPT_VERSION: &str = "security-review-context-v1";
const SECURITY_REVIEW_INSTRUCTIONS_TEMPLATE: &str =
    include_str!("assets/security_review_instructions.md");

fn security_review_instructions_template(min_confidence_score: f32) -> String {
    let min_confidence_score = format!("{min_confidence_score:.2}");
    render_placeholders(
        SECURITY_REVIEW_INSTRUCTIONS_TEMPLATE,
        &[("MIN_CONFIDENCE_SCORE", &min_confidence_score)],
    )
    .expect("security review instructions placeholders are valid")
}

impl DockerCodexRunner {
    pub(crate) fn security_context_cache_repo_key<'a>(&self, ctx: &'a ReviewContext) -> &'a str {
        ctx.repo.as_str()
    }

    fn security_review_instructions(
        &self,
        min_confidence_score: f32,
        additional_developer_instructions: Option<&str>,
    ) -> String {
        let base = security_review_instructions_template(min_confidence_score);
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

    pub(super) fn security_review_output_schema() -> Value {
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

    pub(super) async fn resolve_security_context_payload(
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
            .security_context_cache
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
                .security_context_cache
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
                    .security_context_cache
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
                        .security_context_cache
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
                    .security_context_cache
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
                        .security_context_cache
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

    pub(super) fn build_security_review_instructions(
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

    pub(super) fn security_context_session_update(
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

    pub(super) async fn build_security_context_with_separate_session(
        &self,
        ctx: &ReviewContext,
        request: SeparateSecurityContextSessionRequest<'_>,
    ) -> Result<String> {
        let launch = self
            .launch_runner_session(standard_session_launch_request(
                ctx.run_history_id,
                &ctx.feature_flags,
                &ctx.project_path,
                &self.codex.mcp_server_overrides.review,
                false,
                request.account,
                |_prepared: &PreparedRunnerSessionComponents| {
                    self.command(
                        ctx,
                        AppServerCommandOptions {
                            browser_mcp: request.browser_mcp,
                            gitlab_discovery_mcp: None,
                            mcp_server_overrides: &self.codex.mcp_server_overrides.review,
                            session_override: self.security_context_session_override(),
                        },
                    )
                },
            ))
            .await?;
        let mut session = launch.session;
        {
            let mut slot = request
                .extra_session_container
                .lock()
                .expect("security context extra session lock poisoned");
            *slot = Some((
                session.container_id.clone(),
                session.browser_container_id.clone(),
            ));
        }

        let build_result = async {
            session.client.initialize().await?;
            session.client.initialized().await?;
            let worktree_path = self
                .create_security_context_worktree(
                    &session.container_id,
                    request.repo_path,
                    request.base_head_sha,
                )
                .await?;
            let thread_id = self
                .session_start_thread(
                    &mut session,
                    self.thread_start_params(
                        request.repo_path,
                        None,
                        std::slice::from_ref(&worktree_path),
                    ),
                    "thread/start missing thread id for security context",
                )
                .await?;
            let build_result = self
                .build_security_context_payload(
                    ctx,
                    SecurityContextPayloadRequest {
                        client: &mut session.client,
                        gitlab_discovery_server_name: None,
                        thread_id: &thread_id,
                        turn_cwd: &worktree_path,
                        base_branch: request.base_branch,
                        base_head_sha: request.base_head_sha,
                    },
                )
                .await;
            self.remove_security_context_worktree(
                &session.container_id,
                request.repo_path,
                &worktree_path,
            )
            .await;
            build_result
        }
        .await;

        let build_result = match build_result {
            Ok(payload) => Ok(payload),
            Err(err) => Err(self
                .enrich_app_server_io_error_if_needed(err, &session.container_id)
                .await),
        };

        self.close_runner_session(session).await;
        {
            let mut slot = request
                .extra_session_container
                .lock()
                .expect("security context extra session lock poisoned");
            *slot = None;
        }

        build_result
    }
}

#[cfg(test)]
mod tests {
    use super::security_review_instructions_template;
    use insta::assert_snapshot;

    #[test]
    fn security_review_instructions_render_snapshot_without_placeholders() {
        let instructions = security_review_instructions_template(0.75);

        assert!(!instructions.contains("@@"), "{instructions}");
        assert_snapshot!("security_review_instructions", instructions);
    }
}

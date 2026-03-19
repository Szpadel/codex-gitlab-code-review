use super::*;
use crate::composer_install::composer_install_timeout_seconds;

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
    overall_explanation: String,
    #[serde(default)]
    overall_correctness: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReviewFindingPayload {
    title: String,
    body: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReviewTargetRequest {
    NativeBaseBranch { branch: String },
    Custom { instructions: String },
}

const SINGLE_REVIEW_HEADER: &str = "Review comment:";
const MULTI_REVIEW_HEADER: &str = "Full review comments:";

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
        let repo_path = "/work/repo";
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
                        repo_path,
                        &ctx.project_path,
                        &ctx.feature_flags,
                        composer_timeout_seconds,
                        ctx.run_history_id,
                    )
                    .await;
                let review_target = Self::review_target_value(
                    self.resolve_review_target_request(ctx, &container_id, repo_path)
                        .await,
                );
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

pub(crate) fn parse_review_output(text: &str) -> Result<CodexResult> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(CodexResult::Pass {
            summary: "no issues found".to_string(),
        });
    }

    if let Some(json_text) = extract_json_block(trimmed)
        && let Ok(parsed) = serde_json::from_str::<ReviewOutputPayload>(&json_text)
        && review_output_payload_looks_structured(&parsed)
    {
        return parse_structured_review_output(parsed);
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
                findings: Vec::new(),
                body: parsed.comment_markdown,
            })),
            other => Err(anyhow!("unknown verdict: {}", other)),
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

fn parse_structured_review_output(parsed: ReviewOutputPayload) -> Result<CodexResult> {
    let findings = parsed
        .findings
        .into_iter()
        .map(|finding| ReviewFinding {
            title: finding.title,
            body: finding.body,
            code_location: ReviewCodeLocation {
                absolute_file_path: finding.code_location.absolute_file_path,
                line_range: ReviewLineRange {
                    start: finding.code_location.line_range.start,
                    end: finding.code_location.line_range.end,
                },
            },
        })
        .collect::<Vec<_>>();
    let overall_explanation = trim_to_option(parsed.overall_explanation);
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
        findings,
        body,
    }))
}

fn review_output_payload_looks_structured(payload: &ReviewOutputPayload) -> bool {
    !payload.findings.is_empty()
        || !payload.overall_explanation.trim().is_empty()
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

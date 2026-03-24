use super::browser_mcp::{
    BrowserContainerDiagnostics, BrowserContainerStateSnapshot, BrowserLaunchConfig,
    BrowserLogTail, browser_container_cmd, browser_container_has_exited, browser_logs_report_ready,
};
use super::test_support::{
    ExecContainerCommandRequest, FakeGitLabDiscoveryHandle, FakeRunnerHarness,
    ManagedContainerSummary, ScriptedAppChunk, ScriptedAppRequest, ScriptedAppServer,
};
use super::*;
use crate::composer_install::{
    COMPOSER_SKIP_MARKER, ComposerInstallMode, DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS,
    composer_install_exec_command,
};
use crate::config::{
    DepsConfig, FallbackAuthAccountConfig, GitLabTargets, McpServerOverridesConfig,
};
use crate::state::{NewRunHistory, RunHistoryKind};
use anyhow::Context;
use chrono::TimeZone;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;
use std::time::Duration;

fn empty_app_server_client() -> AppServerClient {
    AppServerClient {
        input: Box::pin(tokio::io::sink()),
        output: Box::pin(futures::stream::empty()),
        buffer: Vec::new(),
        pending_notifications: VecDeque::new(),
        reasoning_buffers: HashMap::new(),
        agent_message_buffers: HashMap::new(),
        command_output_buffers: HashMap::new(),
        recent_runner_errors: VecDeque::new(),
        log_all_json: false,
    }
}

fn run_bash_script(script: &str) -> Result<Output> {
    Ok(Command::new("bash").arg("-lc").arg(script).output()?)
}

fn test_browser_mcp_config(command: &str) -> BrowserMcpConfig {
    BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "chromedp/headless-shell:latest".to_string(),
        remote_debugging_port: BROWSER_MCP_REMOTE_DEBUGGING_PORT,
        mcp_command: command.to_string(),
        browser_args: vec![],
        ..BrowserMcpConfig::default()
    }
}

fn render_browser_wait_script_for_port(port: u16) -> String {
    browser_wait_script(Some(&test_browser_mcp_config("npx")))
        .replace(
            &format!("/{}", BROWSER_MCP_REMOTE_DEBUGGING_PORT),
            &format!("/{port}"),
        )
        .replace(
            &format!(":{}", BROWSER_MCP_REMOTE_DEBUGGING_PORT),
            &format!(":{port}"),
        )
}

#[test]
fn parse_review_output_json_pass() -> Result<()> {
    let text = r#"{"verdict":"pass","summary":"ok","comment_markdown":""}"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "ok");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn security_context_output_schema_is_strict_root_object() {
    let schema = DockerCodexRunner::security_context_output_schema();
    assert_eq!(
        schema.get("additionalProperties"),
        Some(&serde_json::Value::Bool(false))
    );
}

#[test]
fn parse_review_output_json_comment() -> Result<()> {
    let text = r#"{"verdict":"comment","summary":"needs changes","comment_markdown":"- fix"}"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "needs changes");
            assert_eq!(comment.body, "- fix");
            assert!(comment.findings.is_empty());
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_fallback_comment() -> Result<()> {
    let text = "Looks good overall\n\n- minor nit";
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "Looks good overall");
            assert_eq!(comment.body, text);
            assert!(comment.findings.is_empty());
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_structured_findings_json() -> Result<()> {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Use safer cache invalidation",
          "body": "This can leave stale entries in the process cache.",
          "confidence_score": 0.91,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/cache.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "The patch has one correctness issue.",
      "overall_confidence_score": 0.88
    }"#;
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "The patch has one correctness issue.");
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch has one correctness issue.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(
                comment.findings[0].title,
                "[P1] Use safer cache invalidation"
            );
            assert_eq!(
                comment.findings[0].code_location.absolute_file_path,
                "/work/repo/src/cache.rs"
            );
            assert_eq!(comment.findings[0].code_location.line_range.start, 14);
            assert_eq!(comment.findings[0].code_location.line_range.end, 16);
            assert!(comment.body.contains("Review comment:"));
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_review_output_upstream_rendered_review_text() -> Result<()> {
    let text = "The patch has one correctness issue.\n\nReview comment:\n\n- [P1] Use safer cache invalidation — /work/repo/src/cache.rs:14-16\n  This can leave stale entries in the process cache.";
    let result = parse_review_output(text)?;
    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "The patch has one correctness issue.");
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch has one correctness issue.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(
                comment.findings[0].title,
                "[P1] Use safer cache invalidation"
            );
            assert_eq!(
                comment.findings[0].body,
                "This can leave stale entries in the process cache."
            );
            assert_eq!(
                comment.findings[0].code_location.absolute_file_path,
                "/work/repo/src/cache.rs"
            );
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_security_review_output_filters_low_confidence_findings() -> Result<()> {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Reject missing auth check",
          "body": "The endpoint can be reached without the intended guard.",
          "confidence_score": 0.84,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "No confirmed security issues after validation.",
      "overall_confidence_score": 0.84
    }"#;
    let result =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "No confirmed security issues after validation.");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn parse_security_review_output_rejects_unstructured_text() {
    let err = parse_review_output_for_lane(
        "This patch looks safe.",
        crate::review_lane::ReviewLane::Security,
        Some(0.85),
    )
    .expect_err("security review should reject prose output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_wrapped_json() {
    let text = r#"Security review result:
{
  "findings": [],
  "overall_correctness": "patch is correct",
  "overall_explanation": "No confirmed issues."
}"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject prose-wrapped JSON output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_empty_text() {
    let err =
        parse_review_output_for_lane("", crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject empty output");
    assert!(
        err.to_string()
            .contains("security review output must be a structured JSON object")
    );
}

#[test]
fn parse_security_review_output_rejects_findings_without_confidence() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject findings without confidence");
    assert!(
        err.to_string()
            .contains("security review findings must include confidence_score")
    );
}

#[test]
fn parse_security_review_output_rejects_invalid_confidence_threshold() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "confidence_score": 0.91,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(1.5))
            .expect_err("security review should reject invalid thresholds");
    assert!(err.to_string().contains(
        "security review min_confidence_score must be a finite number between 0.0 and 1.0"
    ));
}

#[test]
fn parse_security_review_output_rejects_invalid_finding_confidence_scores() {
    let text = r#"{
      "findings": [
        {
          "title": "[P1] Missing auth guard",
          "body": "An attacker can reach the endpoint without the intended check.",
          "confidence_score": 7,
          "priority": 1,
          "code_location": {
            "absolute_file_path": "/work/repo/src/auth.rs",
            "line_range": { "start": 14, "end": 16 }
          }
        }
      ],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "A security issue was found."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject invalid finding confidence");
    assert!(
        err.to_string().contains(
            "security review findings must use confidence_score values between 0.0 and 1.0"
        )
    );
}

#[test]
fn parse_security_review_output_accepts_nullable_optional_fields() -> Result<()> {
    let text = r#"{
      "findings": [],
      "overall_correctness": "patch is correct",
      "overall_explanation": null,
      "overall_confidence_score": null
    }"#;
    let result =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "no confirmed security issues found");
            Ok(())
        }
        _ => bail!("expected pass"),
    }
}

#[test]
fn parse_security_review_output_preserves_sectioned_body() -> Result<()> {
    let finding_body = "Summary:\nUntrusted callers can reach src/auth.rs:14.\n\nSeverity:\nP1 because the missing guard exposes tenant data.\n\nReproduction:\nSend the authenticated request sequence described near src/http.rs:22.\n\nEvidence:\nsrc/auth.rs:14 skips the role check and src/http.rs:22 still reaches the handler.\n\nAttack-path analysis:\nAn attacker-controlled request crosses the HTTP boundary, bypasses the auth check, and reaches the privileged handler.\n\nLikelihood:\nHigh because the endpoint is externally reachable.\n\nImpact:\nCross-tenant data exposure.\n\nAssumptions:\nThe route remains available to normal API clients.\n\nBlindspots:\nDid not validate WAF-specific mitigations.";
    let text = json!({
        "findings": [
            {
                "title": "[P1] Missing auth guard",
                "body": finding_body,
                "confidence_score": 0.91,
                "priority": 1,
                "code_location": {
                    "absolute_file_path": "/work/repo/src/auth.rs",
                    "line_range": { "start": 14, "end": 16 }
                }
            }
        ],
        "overall_correctness": "patch is incorrect",
        "overall_explanation": "The patch introduces a confirmed auth bypass.",
        "overall_confidence_score": 0.91
    })
    .to_string();
    let result =
        parse_review_output_for_lane(&text, crate::review_lane::ReviewLane::Security, Some(0.85))?;

    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(
                comment.overall_explanation.as_deref(),
                Some("The patch introduces a confirmed auth bypass.")
            );
            assert_eq!(comment.findings.len(), 1);
            assert_eq!(comment.findings[0].body, finding_body);
            let expected_body = format!(
                "The patch introduces a confirmed auth bypass.\n\nReview comment:\n\n- [P1] Missing auth guard — /work/repo/src/auth.rs:14-16\n  {}",
                finding_body.replace('\n', "\n  ")
            );
            assert_eq!(comment.body, expected_body);
            Ok(())
        }
        _ => bail!("expected comment"),
    }
}

#[test]
fn parse_security_review_output_rejects_incorrect_verdict_without_confirmed_findings() {
    let text = r#"{
      "findings": [],
      "overall_correctness": "patch is incorrect",
      "overall_explanation": "The patch is unsafe."
    }"#;
    let err =
        parse_review_output_for_lane(text, crate::review_lane::ReviewLane::Security, Some(0.85))
            .expect_err("security review should reject incorrect verdict without findings");
    assert!(
        err.to_string()
            .contains("security review marked patch incorrect without confirmed findings")
    );
}

#[test]
fn handle_turn_notification_enriches_agent_message_from_deltas() -> Result<()> {
    let mut client = empty_app_server_client();
    let mut capture = TurnHistoryCapture::default();
    client.handle_turn_notification(
        "item/agentMessage/delta",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "itemId": "item-1",
            "delta": "Reply from deltas"
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |_| {},
    )?;

    let mut completed = None;
    client.handle_turn_notification(
        "item/completed",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {
                "id": "item-1",
                "type": "AgentMessage",
                "phase": "final"
            }
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |item| completed = Some(item.clone()),
    )?;

    let completed = completed.context("completed agent message")?;
    assert_eq!(completed["text"], "Reply from deltas");
    let events = capture.take_pending();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload["createdAt"].is_string());
    assert_eq!(events[0].payload["text"], "Reply from deltas");
    Ok(())
}

#[test]
fn handle_turn_notification_enriches_command_output_from_deltas() -> Result<()> {
    let mut client = empty_app_server_client();
    let mut capture = TurnHistoryCapture::default();
    client.handle_turn_notification(
        "item/commandExecution/outputDelta",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "itemId": "cmd-1",
            "delta": "line one\nline two"
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |_| {},
    )?;

    let mut completed = None;
    client.handle_turn_notification(
        "item/completed",
        Some(&json!({
            "threadId": "thread-1",
            "turnId": "turn-1",
            "item": {
                "id": "cmd-1",
                "type": "commandExecution",
                "command": "cargo test",
                "status": "completed"
            }
        })),
        TurnNotificationContext {
            thread_id: "thread-1",
            turn_id: "turn-1",
            history_capture: &mut capture,
        },
        |_, _| {},
        |item| completed = Some(item.clone()),
    )?;

    let completed = completed.context("completed command")?;
    assert_eq!(completed["aggregatedOutput"], "line one\nline two");
    let events = capture.take_pending();
    assert_eq!(events.len(), 1);
    assert!(events[0].payload["createdAt"].is_string());
    assert_eq!(events[0].payload["aggregatedOutput"], "line one\nline two");
    Ok(())
}

fn review_context_with_target_branch(target_branch: Option<&str>) -> ReviewContext {
    ReviewContext {
        lane: crate::review_lane::ReviewLane::General,
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: Some("feature".to_string()),
            target_branch: target_branch.map(ToOwned::to_owned),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        feature_flags: FeatureFlagSnapshot::default(),
        additional_developer_instructions: None,
        min_confidence_score: None,
        security_context_ttl_seconds: None,
        run_history_id: None,
    }
}

fn scripted_security_review_server(
    thread_id: &str,
    threat_turn_id: Option<&str>,
    threat_output: Option<&str>,
    threat_delay_ms: u64,
    review_turn_id: &str,
    review_output: &str,
) -> ScriptedAppServer {
    let mut requests = vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": thread_id } })),
    ];
    if let (Some(threat_turn_id), Some(threat_output)) = (threat_turn_id, threat_output) {
        let mut after_response = vec![ScriptedAppChunk::Json(json!({
            "method": "turn/started",
            "params": { "threadId": thread_id, "turnId": threat_turn_id }
        }))];
        if threat_delay_ms > 0 {
            after_response.push(ScriptedAppChunk::SleepMillis(threat_delay_ms));
        }
        after_response.extend([
            ScriptedAppChunk::Json(json!({
                "method": "item/agentMessage/delta",
                "params": {
                    "threadId": thread_id,
                    "turnId": threat_turn_id,
                    "itemId": "agent-threat",
                    "delta": threat_output
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "item/completed",
                "params": {
                    "threadId": thread_id,
                    "turnId": threat_turn_id,
                    "item": {
                        "id": "agent-threat",
                        "type": "AgentMessage",
                        "phase": "final"
                    }
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "turn/completed",
                "params": {
                    "threadId": thread_id,
                    "turnId": threat_turn_id,
                    "turn": { "status": "completed" }
                }
            })),
        ]);
        requests.push(
            ScriptedAppRequest::result("turn/start", json!({ "turn": { "id": threat_turn_id } }))
                .with_after_response(after_response),
        );
    }
    requests.push(
        ScriptedAppRequest::result("turn/start", json!({ "turn": { "id": review_turn_id } }))
            .with_after_response(vec![
                ScriptedAppChunk::Json(json!({
                    "method": "turn/started",
                    "params": { "threadId": thread_id, "turnId": review_turn_id }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": thread_id,
                        "turnId": review_turn_id,
                        "itemId": "agent-review",
                        "delta": review_output
                    }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/completed",
                    "params": {
                        "threadId": thread_id,
                        "turnId": review_turn_id,
                        "item": {
                            "id": "agent-review",
                            "type": "AgentMessage",
                            "phase": "final"
                        }
                    }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "turn/completed",
                    "params": {
                        "threadId": thread_id,
                        "turnId": review_turn_id,
                        "turn": { "status": "completed" }
                    }
                })),
            ]),
    );
    ScriptedAppServer::from_requests(requests)
}

fn scripted_security_context_server(
    thread_id: &str,
    threat_turn_id: &str,
    threat_output: &str,
    threat_delay_ms: u64,
) -> ScriptedAppServer {
    let mut after_response = vec![ScriptedAppChunk::Json(json!({
        "method": "turn/started",
        "params": { "threadId": thread_id, "turnId": threat_turn_id }
    }))];
    if threat_delay_ms > 0 {
        after_response.push(ScriptedAppChunk::SleepMillis(threat_delay_ms));
    }
    after_response.extend([
        ScriptedAppChunk::Json(json!({
            "method": "item/agentMessage/delta",
            "params": {
                "threadId": thread_id,
                "turnId": threat_turn_id,
                "itemId": "agent-threat",
                "delta": threat_output
            }
        })),
        ScriptedAppChunk::Json(json!({
            "method": "item/completed",
            "params": {
                "threadId": thread_id,
                "turnId": threat_turn_id,
                "item": {
                    "id": "agent-threat",
                    "type": "AgentMessage",
                    "phase": "final"
                }
            }
        })),
        ScriptedAppChunk::Json(json!({
            "method": "turn/completed",
            "params": {
                "threadId": thread_id,
                "turnId": threat_turn_id,
                "turn": { "status": "completed" }
            }
        })),
    ]);
    ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": thread_id } })),
        ScriptedAppRequest::result("turn/start", json!({ "turn": { "id": threat_turn_id } }))
            .with_after_response(after_response),
    ])
}

#[test]
fn security_context_cache_repo_key_uses_canonical_repo_identity() {
    let runner = test_runner_with_codex(test_codex_config());
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.project_path = "fork/source".to_string();
    assert_eq!(runner.security_context_cache_repo_key(&ctx), "group/repo");
}

#[test]
fn security_review_disables_gitlab_discovery_mcp() {
    let mut codex = test_codex_config();
    codex.gitlab_discovery_mcp = crate::config::GitLabDiscoveryMcpConfig {
        enabled: true,
        bind_addr: "127.0.0.1:8091".to_string(),
        advertise_url: "http://mcp.internal:8091/mcp".to_string(),
        allow: vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["fork/source".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }],
        ..crate::config::GitLabDiscoveryMcpConfig::default()
    };
    let service = Arc::new(
        crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            },
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets::default(),
            },
            codex.gitlab_discovery_mcp.clone(),
        )
        .expect("gitlab discovery service"),
    );
    let mut runner = test_runner_with_codex(codex);
    runner.gitlab_discovery_mcp = Some(service as Arc<dyn GitLabDiscoveryHandle>);
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review_lane::ReviewLane::Security;
    ctx.project_path = "fork/source".to_string();
    ctx.feature_flags.gitlab_discovery_mcp = true;

    assert!(runner.prepare_review_gitlab_discovery_mcp(&ctx).is_none());
}

#[test]
fn review_target_request_uses_native_base_branch_without_extra_instructions() {
    let ctx = review_context_with_target_branch(Some("main"));
    let request = DockerCodexRunner::review_target_request(&ctx, Some("mergebase"), None);
    assert_eq!(
        request,
        ReviewTargetRequest::NativeBaseBranch {
            branch: "main".to_string()
        }
    );
}

#[test]
fn review_target_request_uses_synced_custom_prompt_with_extra_instructions() {
    let ctx = review_context_with_target_branch(Some("main"));
    let request = DockerCodexRunner::review_target_request(
        &ctx,
        Some("mergebase"),
        Some("Check performance-sensitive paths."),
    );
    match request {
        ReviewTargetRequest::NativeBaseBranch { .. } => {
            panic!("expected custom review target request")
        }
        ReviewTargetRequest::Custom { instructions } => {
            assert!(instructions.contains("merge base commit for this comparison is mergebase"));
            assert!(instructions.contains("Additional review instructions:"));
            assert!(instructions.contains("Check performance-sensitive paths."));
        }
    }
}

#[test]
fn review_target_request_falls_back_when_target_branch_missing() {
    let ctx = review_context_with_target_branch(None);
    let request =
        DockerCodexRunner::review_target_request(&ctx, None, Some("Check browser regressions."));
    match request {
        ReviewTargetRequest::NativeBaseBranch { .. } => {
            panic!("expected custom review target request")
        }
        ReviewTargetRequest::Custom { instructions } => {
            assert!(instructions.contains("introduced by commit abc123 (\"Title\")"));
            assert!(instructions.contains("did not provide target branch metadata"));
            assert!(instructions.contains("Additional review instructions:"));
            assert!(instructions.contains("Check browser regressions."));
        }
    }
}

#[test]
fn parse_usage_limit_reset_at_supports_rfc3339() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "rate limit reached; resets at 2026-03-02T12:30:00Z";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 12, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_compact_relative_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded, try again in 1h 20m";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 20, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_spaced_relative_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "quota reached; try again in 1 hour 30 minutes";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_conjunction_in_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded; try again in 1 hour and 30 minutes";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_fractional_seconds() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded; try again in 2.3s";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 10, 0, 3)
            .single()
            .expect("valid")
    );
}

#[test]
fn classify_auth_failure_usage_limit_falls_back_to_default_cooldown_when_unparseable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(
        kind,
        AuthFailureKind::UsageLimited {
            reset_at: Utc
                .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
                .single()
                .expect("valid"),
        }
    );
}

#[test]
fn classify_auth_failure_handles_huge_cooldown_without_panicking() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded");
    let kind = classify_auth_failure(&err, now, u64::MAX);
    match kind {
        AuthFailureKind::UsageLimited { reset_at } => {
            assert!(reset_at > now);
        }
        _ => panic!("expected usage-limited classification"),
    }
}

#[test]
fn classify_auth_failure_detects_rate_limit_reached_phrase() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: Rate limit reached, try again in 45m");
    let kind = classify_auth_failure(&err, now, 3600);
    assert!(matches!(kind, AuthFailureKind::UsageLimited { .. }));
}

#[test]
fn classify_auth_failure_handles_huge_relative_retry_hint_without_panicking() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded, try again in 9223372036854775807s");
    let kind = classify_auth_failure(&err, now, 3600);
    match kind {
        AuthFailureKind::UsageLimited { reset_at } => {
            assert!(reset_at > now);
        }
        _ => panic!("expected usage-limited classification"),
    }
}

#[test]
fn classify_auth_failure_detects_auth_unavailable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex app-server error: not authenticated, run codex auth login");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::AuthUnavailable);
}

#[test]
fn classify_auth_failure_preserves_non_auth_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex app-server closed stdout");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_non_codex_rate_limit_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("git clone failed: received HTTP 429 from gitlab");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_generic_app_server_429_without_codex_limit_context() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err =
        anyhow!("codex app-server closed stdout: recent runner errors: git clone failed with 429");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_openai_package_install_429() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex-runner-error: npm install -g @openai/codex failed with 429");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_disk_quota_exceeded_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("write failed: disk quota exceeded");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_for_account_marks_mount_path_errors_as_unavailable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let account = AuthAccount {
        name: "backup".to_string(),
        auth_host_path: "/missing/codex-auth".to_string(),
        state_key: auth_account_state_key("backup", "/missing/codex-auth"),
        is_primary: false,
    };
    let err = anyhow!(
        "create docker container failed: invalid mount config for type \"bind\": bind source path does not exist: /missing/codex-auth"
    );
    let base = classify_auth_failure(&err, now, 3600);
    let kind = classify_auth_failure_for_account(base, &err, &account);
    assert_eq!(kind, AuthFailureKind::AuthUnavailable);
}

#[test]
fn should_clear_limit_reset_only_when_marker_is_not_newer_than_attempt() {
    let attempt_started_at = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let older_reset = Utc
        .with_ymd_and_hms(2026, 3, 2, 9, 0, 0)
        .single()
        .expect("valid");
    let newer_reset = Utc
        .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
        .single()
        .expect("valid");

    assert!(should_clear_limit_reset(older_reset, attempt_started_at));
    assert!(should_clear_limit_reset(
        attempt_started_at,
        attempt_started_at
    ));
    assert!(!should_clear_limit_reset(newer_reset, attempt_started_at));
}

#[test]
fn build_auth_accounts_keeps_primary_first_then_fallback_order() {
    let codex = CodexConfig {
        image: "ghcr.io/openai/codex-universal:latest".to_string(),
        timeout_seconds: 300,
        auth_host_path: "/root/.codex-primary".to_string(),
        auth_mount_path: "/root/.codex".to_string(),
        session_history_path: None,
        exec_sandbox: "danger-full-access".to_string(),
        fallback_auth_accounts: vec![
            FallbackAuthAccountConfig {
                name: "backup-high".to_string(),
                auth_host_path: "/root/.codex-backup-high".to_string(),
            },
            FallbackAuthAccountConfig {
                name: "backup-low".to_string(),
                auth_host_path: "/root/.codex-backup-low".to_string(),
            },
        ],
        usage_limit_fallback_cooldown_seconds: 3600,
        deps: DepsConfig { enabled: false },
        browser_mcp: BrowserMcpConfig::default(),
        gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
        mcp_server_overrides: McpServerOverridesConfig::default(),
        reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
        reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
    };

    let accounts = DockerCodexRunner::build_auth_accounts(&codex);
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[0].name, PRIMARY_AUTH_ACCOUNT_NAME);
    assert_eq!(accounts[0].auth_host_path, "/root/.codex-primary");
    assert_eq!(
        accounts[0].state_key,
        auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, "/root/.codex-primary")
    );
    assert!(accounts[0].is_primary);
    assert_eq!(accounts[1].name, "backup-high");
    assert_eq!(accounts[2].name, "backup-low");
    assert_eq!(
        accounts[1].state_key,
        auth_account_state_key("backup-high", "/root/.codex-backup-high")
    );
    assert_eq!(
        accounts[2].state_key,
        auth_account_state_key("backup-low", "/root/.codex-backup-low")
    );
    assert!(!accounts[1].is_primary);
    assert!(!accounts[2].is_primary);
}

#[test]
fn runner_env_vars_do_not_include_proxy_settings() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let runner = DockerCodexRunner {
        runtime: RunnerRuntime::Docker {
            docker: connect_docker(&DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            })
            .expect("docker client"),
            image_pulls: Mutex::new(HashMap::new()),
            next_image_pull_id: AtomicU64::new(1),
        },
        security_context_builds: Arc::new(Mutex::new(HashMap::new())),
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 300,
            auth_host_path: "/root/.codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: Vec::new(),
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: DepsConfig { enabled: false },
            browser_mcp: BrowserMcpConfig::default(),
            gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
            reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
        },
        gitlab_discovery_mcp: None,
        mention_commands_active: false,
        review_additional_developer_instructions: None,
        git_base: Url::parse("https://gitlab.example.com").expect("url"),
        gitlab_token: "token".to_string(),
        log_all_json: false,
        owner_id: "owner-id".to_string(),
        state: Arc::new(
            runtime
                .block_on(ReviewStateStore::new(":memory:"))
                .expect("state"),
        ),
        auth_accounts: Vec::new(),
    };

    let env = runner.env_vars(&[]);

    assert_eq!(env, vec!["HOME=/root".to_string(),]);
}

#[test]
fn with_recent_runner_errors_adds_context() {
    let err = anyhow!("codex app-server closed stdout");
    let recent = VecDeque::from(vec![
        "codex-runner-error: codex install failed".to_string(),
        "codex-runner-error: npm ERR! network".to_string(),
    ]);
    let wrapped = with_recent_runner_errors(err, &recent);
    let chain = format!("{wrapped:#}");
    assert!(chain.contains("codex app-server closed stdout"));
    assert!(chain.contains("recent runner errors:"));
    assert!(chain.contains("codex-runner-error: codex install failed"));
    assert!(chain.contains("codex-runner-error: npm ERR! network"));
}

#[test]
fn with_recent_runner_errors_is_noop_when_empty() {
    let err = anyhow!("codex app-server closed stdout");
    let recent = VecDeque::new();
    let wrapped = with_recent_runner_errors(err, &recent);
    assert_eq!(
        wrapped.to_string(),
        "codex app-server closed stdout".to_string()
    );
}

#[test]
fn validate_container_exec_result_accepts_zero_exit_code() -> Result<()> {
    let command = vec!["git".to_string(), "status".to_string()];
    let output = ContainerExecOutput {
        exit_code: 0,
        stdout: "clean\n".to_string(),
        stderr: String::new(),
    };
    let validated = validate_container_exec_result(&command, Some("/work/repo"), output)?;
    assert_eq!(validated.stdout, "clean\n");
    Ok(())
}

#[test]
fn validate_container_exec_result_rejects_nonzero_exit_with_stderr() {
    let command = vec!["git".to_string(), "status".to_string()];
    let output = ContainerExecOutput {
        exit_code: 128,
        stdout: String::new(),
        stderr: "fatal: not a git repository\n".to_string(),
    };
    let err = validate_container_exec_result(&command, Some("/work/repo"), output)
        .expect_err("expected command failure");
    let text = err.to_string();
    assert!(text.contains("docker exec command failed with exit code 128"));
    assert!(text.contains("'git' 'status'"));
    assert!(text.contains("/work/repo"));
    assert!(text.contains("fatal: not a git repository"));
}

#[test]
fn validate_container_exec_result_rejects_nonzero_exit_without_stderr() {
    let command = vec!["git".to_string(), "status".to_string()];
    let output = ContainerExecOutput {
        exit_code: 1,
        stdout: String::new(),
        stderr: " \n ".to_string(),
    };
    let err = validate_container_exec_result(&command, Some("/work/repo"), output)
        .expect_err("expected command failure");
    let text = err.to_string();
    assert!(text.contains("docker exec command failed with exit code 1"));
    assert!(text.contains("'git' 'status'"));
    assert!(text.contains("/work/repo"));
}

#[test]
fn auxiliary_git_exec_command_wraps_git_in_login_shell() {
    let command = auxiliary_git_exec_command(&["status".to_string()]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'status'".to_string()
        ]
    );
}

#[test]
fn auxiliary_git_exec_command_quotes_arguments() {
    let command = auxiliary_git_exec_command(&[
        "config".to_string(),
        "user.name".to_string(),
        "O'Brian Example".to_string(),
    ]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'config' 'user.name' 'O'\"'\"'Brian Example'".to_string()
        ]
    );
}

#[test]
fn auxiliary_git_exec_command_wraps_merge_base_flags_and_shas() {
    let command = auxiliary_git_exec_command(&[
        "merge-base".to_string(),
        "--is-ancestor".to_string(),
        "before123".to_string(),
        "after456".to_string(),
    ]);
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "'git' 'merge-base' '--is-ancestor' 'before123' 'after456'".to_string()
        ]
    );
}

#[test]
fn restore_push_remote_url_exec_command_preserves_gitlab_token_expansion() {
    let command = restore_push_remote_url_exec_command(
        "https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git",
    );
    assert_eq!(
        command,
        vec![
            "bash".to_string(),
            "-lc".to_string(),
            "git remote set-url --push origin \"https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git\"".to_string(),
        ]
    );
}

#[test]
fn app_server_cmd_uses_bash_login_args() {
    let cmd = DockerCodexRunner::app_server_cmd("echo hi".to_string());
    assert_eq!(cmd, vec!["-lc".to_string(), "echo hi".to_string()]);
}

#[test]
fn codex_app_server_exec_command_without_mcp_overrides_is_plain() {
    let overrides = BTreeMap::new();
    let cmd = codex_app_server_exec_command(None, None, &overrides, None, None);
    assert_eq!(cmd, "exec codex app-server");
}

#[test]
fn codex_app_server_exec_command_renders_sorted_mcp_overrides() {
    let overrides = BTreeMap::from([("serena".to_string(), false), ("github".to_string(), true)]);
    let cmd = codex_app_server_exec_command(None, None, &overrides, None, None);
    assert_eq!(
        cmd,
        "exec codex -c 'mcp_servers.github.enabled=true' -c 'mcp_servers.serena.enabled=false' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_reasoning_effort_override() {
    let cmd = codex_app_server_exec_command(None, None, &BTreeMap::new(), None, Some("high"));
    assert_eq!(
        cmd,
        "exec codex -c 'model_reasoning_effort=\"high\"' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_reasoning_summary_override() {
    let cmd = codex_app_server_exec_command(None, None, &BTreeMap::new(), Some("detailed"), None);
    assert_eq!(
        cmd,
        "exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"
    );
}

#[test]
fn codex_app_server_exec_command_includes_browser_mcp_config() {
    let cmd = codex_app_server_exec_command(
        Some(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            browser_args: vec![],
            remote_debugging_port: 9222,
            ..BrowserMcpConfig::default()
        }),
        None,
        &BTreeMap::new(),
        None,
        None,
    );
    assert!(cmd.contains("mcp_servers.chrome-devtools.command=\"npx\""));
    assert!(cmd.contains("chrome-devtools-mcp@latest"));
    assert!(cmd.contains("--browserUrl=http://127.0.0.1:9222"));
    assert!(cmd.contains("mcp_servers.chrome-devtools.enabled=true"));
}

#[test]
fn codex_app_server_exec_command_includes_gitlab_discovery_mcp_config() {
    let cmd = codex_app_server_exec_command(
        None,
        Some(&GitLabDiscoveryMcpRuntimeConfig {
            server_name: "gitlab-discovery".to_string(),
            advertise_url: "http://gitlab-discovery.internal/mcp".to_string(),
            clone_root: "/work/mcp".to_string(),
        }),
        &BTreeMap::new(),
        None,
        None,
    );
    assert!(
        cmd.contains("mcp_servers.gitlab-discovery.url=\"http://gitlab-discovery.internal/mcp\"")
    );
    assert!(cmd.contains("mcp_servers.gitlab-discovery.enabled=true"));
}

#[test]
fn codex_app_server_exec_command_allows_mode_overrides_to_disable_browser_mcp() {
    let cmd = codex_app_server_exec_command(
        Some(&BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            browser_entrypoint: Vec::new(),
            remote_debugging_port: 9222,
            browser_args: vec![],
            mcp_command: "npx".to_string(),
            mcp_args: vec!["-y".to_string(), "chrome-devtools-mcp@latest".to_string()],
        }),
        None,
        &BTreeMap::from([("chrome-devtools".to_string(), false)]),
        None,
        None,
    );
    let expected_enable = "-c 'mcp_servers.chrome-devtools.enabled=true'";
    let expected_disable = "-c 'mcp_servers.chrome-devtools.enabled=false'";
    assert!(cmd.contains(expected_enable));
    assert!(cmd.contains(expected_disable));
    assert!(cmd.find(expected_enable) < cmd.find(expected_disable));
}

#[test]
fn codex_app_server_exec_command_places_reasoning_effort_before_mcp_overrides() {
    let overrides = BTreeMap::from([("github".to_string(), false)]);
    let cmd = codex_app_server_exec_command(None, None, &overrides, None, Some("medium"));
    let reasoning = "-c 'model_reasoning_effort=\"medium\"'";
    let mcp = "-c 'mcp_servers.github.enabled=false'";
    assert!(cmd.contains(reasoning));
    assert!(cmd.contains(mcp));
    assert!(cmd.find(reasoning) < cmd.find(mcp));
}

#[test]
fn codex_app_server_exec_command_places_reasoning_summary_before_effort() {
    let cmd = codex_app_server_exec_command(
        None,
        None,
        &BTreeMap::new(),
        Some("detailed"),
        Some("medium"),
    );
    let summary = "-c 'model_reasoning_summary=\"detailed\"'";
    let effort = "-c 'model_reasoning_effort=\"medium\"'";
    assert!(cmd.contains(summary));
    assert!(cmd.contains(effort));
    assert!(cmd.find(summary) < cmd.find(effort));
}

#[test]
fn effective_browser_mcp_disables_sidecar_when_mode_override_is_false() {
    let browser_mcp = BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "chromedp/headless-shell:latest".to_string(),
        ..BrowserMcpConfig::default()
    };
    let effective = effective_browser_mcp(
        Some(&browser_mcp),
        &BTreeMap::from([("chrome-devtools".to_string(), false)]),
    );
    assert!(effective.is_none());
}

#[test]
fn effective_browser_mcp_keeps_sidecar_when_mode_override_is_true() {
    let browser_mcp = BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "chromedp/headless-shell:latest".to_string(),
        ..BrowserMcpConfig::default()
    };
    let effective = effective_browser_mcp(
        Some(&browser_mcp),
        &BTreeMap::from([("chrome-devtools".to_string(), true)]),
    );
    assert_eq!(effective, Some(&browser_mcp));
}

#[test]
fn browser_container_cmd_includes_no_sandbox_by_default() {
    let cmd = browser_container_cmd(
        "ghcr.io/acme/browser:latest",
        &[],
        &BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "ghcr.io/acme/browser:latest".to_string(),
            ..BrowserMcpConfig::default()
        },
    );
    assert!(cmd.iter().any(|arg| arg == "--no-sandbox"));
}

#[test]
fn browser_container_cmd_skips_injected_debug_flags_for_headless_shell_wrapper() {
    let cmd = browser_container_cmd(
        "chromedp/headless-shell:latest",
        &[],
        &BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell:latest".to_string(),
            browser_args: vec!["--window-size=1280,720".to_string()],
            ..BrowserMcpConfig::default()
        },
    );
    assert_eq!(cmd, vec!["--window-size=1280,720".to_string()]);
}

#[test]
fn browser_launch_config_keeps_image_default_entrypoint_for_default_headless_shell_image() {
    let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "chromedp/headless-shell:latest".to_string(),
        browser_entrypoint: Vec::new(),
        ..BrowserMcpConfig::default()
    });
    assert!(launch.entrypoint.is_empty());
    assert!(launch.cmd.is_empty());
}

#[test]
fn browser_launch_config_preserves_explicit_entrypoint_override() {
    let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "chromedp/headless-shell:latest".to_string(),
        browser_entrypoint: vec!["/custom/entrypoint".to_string()],
        ..BrowserMcpConfig::default()
    });
    assert_eq!(launch.entrypoint, vec!["/custom/entrypoint".to_string()]);
    assert!(
        launch
            .cmd
            .iter()
            .any(|arg| arg == "--remote-debugging-address=0.0.0.0")
    );
}

#[test]
fn browser_launch_config_keeps_other_images_on_image_default_entrypoint() {
    let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig {
        enabled: true,
        server_name: "chrome-devtools".to_string(),
        browser_image: "ghcr.io/acme/browser:latest".to_string(),
        browser_entrypoint: Vec::new(),
        ..BrowserMcpConfig::default()
    });
    assert!(launch.entrypoint.is_empty());
}

#[test]
fn browser_logs_report_ready_requires_expected_port() {
    let ready = browser_logs_report_ready(
        &BrowserLogTail {
            stdout: vec![],
            stderr: vec![
                "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
            ],
        },
        9222,
    );
    let wrong_port = browser_logs_report_ready(
        &BrowserLogTail {
            stdout: vec![],
            stderr: vec![
                "DevTools listening on ws://127.0.0.1:9223/devtools/browser/abc".to_string(),
            ],
        },
        9222,
    );
    let prefix_port = browser_logs_report_ready(
        &BrowserLogTail {
            stdout: vec![],
            stderr: vec![
                "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
            ],
        },
        922,
    );
    assert!(ready);
    assert!(!wrong_port);
    assert!(!prefix_port);
}

#[test]
fn browser_container_has_exited_only_for_terminal_states() {
    assert!(!browser_container_has_exited(Some(
        &BrowserContainerStateSnapshot {
            status: Some("created".to_string()),
            running: Some(false),
            exit_code: None,
            oom_killed: None,
            error: None,
            started_at: None,
            finished_at: None,
        },
    )));
    assert!(browser_container_has_exited(Some(
        &BrowserContainerStateSnapshot {
            status: Some("exited".to_string()),
            running: Some(false),
            exit_code: Some(1),
            oom_killed: Some(false),
            error: Some("boom".to_string()),
            started_at: None,
            finished_at: Some("2026-03-06T07:22:00Z".to_string()),
        },
    )));
}

#[test]
fn browser_container_running_grace_period_is_ten_seconds() {
    assert_eq!(BROWSER_CONTAINER_RUNNING_GRACE_PERIOD.as_secs(), 10);
}

#[test]
fn browser_container_diagnostics_context_includes_state_and_logs() {
    let diagnostics = BrowserContainerDiagnostics {
        container_id: "browser-123".to_string(),
        launch: BrowserLaunchConfig {
            image: "chromedp/headless-shell:latest".to_string(),
            entrypoint: vec!["/headless-shell/headless-shell".to_string()],
            cmd: vec!["--remote-debugging-port=9222".to_string()],
        },
        state: Some(BrowserContainerStateSnapshot {
            status: Some("running".to_string()),
            running: Some(true),
            exit_code: Some(0),
            oom_killed: Some(false),
            error: None,
            started_at: Some("2026-03-06T07:20:00Z".to_string()),
            finished_at: None,
        }),
        state_collection_error: None,
        log_tail: BrowserLogTail {
            stdout: vec!["browser stdout line".to_string()],
            stderr: vec![
                "DevTools listening on ws://127.0.0.1:9222/devtools/browser/abc".to_string(),
            ],
        },
        log_collection_error: None,
    };

    let formatted = diagnostics.format_context();

    assert!(formatted.contains("browser container diagnostics"));
    assert!(formatted.contains("browser-123"));
    assert!(formatted.contains("chromedp/headless-shell:latest"));
    assert!(formatted.contains("/headless-shell/headless-shell"));
    assert!(formatted.contains("status=running"));
    assert!(formatted.contains("browser stdout line"));
    assert!(formatted.contains("DevTools listening on ws://127.0.0.1:9222"));
}

#[test]
fn browser_container_diagnostics_context_includes_collection_errors() {
    let diagnostics = BrowserContainerDiagnostics {
        container_id: "browser-123".to_string(),
        launch: BrowserLaunchConfig {
            image: "chromedp/headless-shell:latest".to_string(),
            entrypoint: vec![],
            cmd: vec!["--remote-debugging-port=9222".to_string()],
        },
        state: None,
        state_collection_error: Some("inspect failed".to_string()),
        log_tail: BrowserLogTail::default(),
        log_collection_error: Some("log fetch failed".to_string()),
    };

    let formatted = diagnostics.format_context();

    assert!(formatted.contains("state unavailable: inspect failed"));
    assert!(formatted.contains("log tail unavailable: log fetch failed"));
    assert!(formatted.contains("entrypoint=<image-default>"));
}

#[test]
fn build_command_script_sets_writable_codex_home() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("export CODEX_HOME=\"/root/.codex\""));
    assert!(script.contains("mkdir -p \"/root/.codex\""));
    assert!(script.contains("repo_dir='/work/repo/repo'"));
}

#[test]
fn build_command_script_fetches_target_branch() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: Some("main"),
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("git fetch --depth 1 origin \"main\""));
    assert!(script.contains("git branch --force \"main\" FETCH_HEAD"));
    assert!(script.contains("git fetch --unshallow"));
}

#[test]
fn build_command_script_updates_submodules() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("run_git clone git clone --depth 1 --recurse-submodules"));
    assert!(script.contains("run_git submodule_update git submodule update --init --recursive"));
    assert!(script.contains("export GIT_CONFIG_COUNT="));
    assert!(script.contains("export GIT_CONFIG_KEY_0="));
    assert!(script.contains("export GIT_CONFIG_VALUE_0="));
}

#[test]
fn git_bootstrap_auth_setup_script_prefers_relative_url_root_when_present() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com/gitlab/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='5'"));
    assert!(script.contains(
        "export GIT_CONFIG_KEY_0='url.https://oauth2:token@example.com/gitlab/.insteadOf'"
    ));
    assert!(script.contains("export GIT_CONFIG_VALUE_0='git@example.com:'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_2='git@example.com:gitlab/'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_3='ssh://git@example.com/gitlab/'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_4='https://example.com/gitlab/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_preserves_explicit_host_port_for_ssh_urls() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com:8443/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_VALUE_1='ssh://git@example.com:8443/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_rewrites_same_host_https_submodule_urls() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='3'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_2='https://example.com/'"));
}

#[test]
fn git_bootstrap_auth_setup_script_rewrites_https_submodule_urls_under_relative_root() {
    let script = git_bootstrap_auth_setup_script(
        "https://oauth2:${GITLAB_TOKEN}@example.com:8443/gitlab/group/repo.git",
        "group/repo",
        "token",
    );

    assert!(script.contains("export GIT_CONFIG_COUNT='5'"));
    assert!(script.contains("export GIT_CONFIG_VALUE_4='https://example.com:8443/gitlab/'"));
}

#[test]
fn build_command_script_clears_bootstrap_git_auth_before_app_server() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: Some("main"),
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );

    let unset_pos = script
        .find("unset GIT_CONFIG_COUNT")
        .expect("bootstrap git auth cleanup");
    let unset_token_pos = script
        .find("unset GITLAB_TOKEN")
        .expect("gitlab token cleanup");
    let sanitize_remote_pos = script
        .find("git remote set-url origin \"$sanitized_origin\"")
        .expect("origin sanitization");
    let target_fetch_pos = script
        .find("git fetch --depth 1 origin \"main\"")
        .expect("target branch fetch");
    let exec_pos = script
        .find("exec codex app-server")
        .expect("app server exec");
    assert!(target_fetch_pos < unset_pos);
    assert!(unset_pos < exec_pos);
    assert!(unset_token_pos < exec_pos);
    assert!(sanitize_remote_pos < exec_pos);
}

#[test]
fn build_command_script_includes_prefetch_when_enabled_without_composer_install() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: true,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("prefetch_deps()"));
    assert!(!script.contains("composer install"));
    assert!(script.contains("npm install"));
}

#[test]
fn build_command_script_includes_mcp_server_overrides() {
    let overrides = BTreeMap::from([("github".to_string(), false)]);
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &overrides,
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("exec codex -c 'mcp_servers.github.enabled=false' app-server"));
}

#[test]
fn gitlab_discovery_mcp_probe_exec_command_uses_runtime_url_and_health_check() {
    let command = gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
        server_name: "gitlab-discovery".to_string(),
        advertise_url: "http://10.42.0.15:8081/mcp".to_string(),
        clone_root: "/work/mcp".to_string(),
    })
    .expect("probe command");

    assert_eq!(command[0], "/bin/bash");
    assert_eq!(command[1], "-lc");
    assert!(command[2].contains("http://10.42.0.15:8081/mcp"));
    assert!(command[2].contains("http://10.42.0.15:8081/healthz"));
    assert!(command[2].contains("command -v curl"));
    assert!(command[2].contains("python3 - <<'PY'"));
    assert!(command[2].contains("healthz unavailable"));
    assert!(!command[2].contains("ERROR healthz failed"));
    assert!(command[2].contains("\"method\":\"initialize\""));
    assert!(command[2].contains("\"method\":\"tools/list\""));
    assert!(command[2].contains("gitlab discovery MCP tools reachable"));
    assert!(command[2].contains("inspect_gitlab_repo"));
}

#[test]
fn gitlab_discovery_mcp_probe_exec_command_rejects_invalid_url() {
    assert!(
        gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
            server_name: "gitlab-discovery".to_string(),
            advertise_url: "not-a-url".to_string(),
            clone_root: "/work/mcp".to_string(),
        })
        .is_none()
    );
}

#[test]
fn gitlab_discovery_mcp_startup_failure_events_create_completed_system_turn() {
    let events = gitlab_discovery_mcp_startup_failure_events(
        "GitLab discovery MCP startup warning: endpoint http://10.0.0.5:8081/mcp was unreachable.",
    );

    assert_eq!(events.len(), 3);
    assert_eq!(
        events[0].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[0].event_type, "turn_started");
    assert_eq!(
        events[1].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[1].event_type, "item_completed");
    assert_eq!(events[1].payload["type"], json!("agentMessage"));
    assert_eq!(events[1].payload["phase"], json!("system"));
    assert!(
        events[1].payload["text"]
            .as_str()
            .expect("message text")
            .contains("GitLab discovery MCP startup warning")
    );
    assert_eq!(
        events[2].turn_id.as_deref(),
        Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID)
    );
    assert_eq!(events[2].event_type, "turn_completed");
    assert_eq!(events[2].payload["status"], json!("completed"));
}

#[test]
fn successful_gitlab_discovery_mcp_tool_call_is_detected() {
    let item = json!({
        "type": "mcpToolCall",
        "server": "gitlab-discovery",
        "tool": "list_gitlab_paths",
        "status": "completed",
        "result": {"paths": []}
    });

    assert!(item_is_successful_gitlab_discovery_call(
        &item,
        Some("gitlab-discovery")
    ));
}

#[test]
fn failed_or_unrelated_mcp_tool_calls_do_not_clear_startup_warning() {
    let failed = json!({
        "type": "mcpToolCall",
        "server": "gitlab-discovery",
        "tool": "list_gitlab_paths",
        "status": "failed",
        "error": {"message": "boom"}
    });
    let other_server = json!({
        "type": "mcpToolCall",
        "server": "chrome-devtools",
        "tool": "list_pages",
        "status": "completed"
    });

    assert!(!item_is_successful_gitlab_discovery_call(
        &failed,
        Some("gitlab-discovery")
    ));
    assert!(!item_is_successful_gitlab_discovery_call(
        &other_server,
        Some("gitlab-discovery")
    ));
}

#[test]
fn build_command_script_includes_reasoning_effort_override() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: Some("high"),
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_effort=\"high\"' app-server"));
}

#[test]
fn build_command_script_includes_reasoning_summary_override() {
    let script = DockerCodexRunner::build_command_script(
        BuildCommandScriptInput {
            clone_url: "https://example.com/repo.git",
            gitlab_token: "token",
            repo: "repo",
            project_path: "repo",
            head_sha: "abc",
            auth_mount_path: "/root/.codex",
            target_branch: None,
            deps_enabled: false,
        },
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: Some("detailed"),
            reasoning_effort: None,
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"));
}

#[test]
fn thread_start_params_include_extra_workspace_write_roots() {
    let mut codex = test_codex_config();
    codex.exec_sandbox = "workspace-write".to_string();
    let runner = test_runner_with_codex(codex);

    let params =
        runner.thread_start_params("/work/repo/group/repo", None, &["/work/mcp".to_string()]);

    assert_eq!(params["sandbox"], "workspace-write");
    assert_eq!(
        params["config"]["sandbox_workspace_write"]["writable_roots"],
        serde_json::json!(["/work/mcp", "/work/repo/group/repo"])
    );
    assert_eq!(
        params["config"]["sandbox_workspace_write"]["network_access"],
        serde_json::json!(true)
    );
}

#[test]
fn thread_start_params_preserve_workspace_write_defaults_without_extra_roots() {
    let mut codex = test_codex_config();
    codex.exec_sandbox = "workspace-write".to_string();
    let runner = test_runner_with_codex(codex);

    let params = runner.thread_start_params("/work/repo/group/repo", None, &[]);

    assert_eq!(params["sandbox"], "workspace-write");
    assert!(params.get("config").is_none());
}

#[test]
fn effective_feature_flags_require_injected_gitlab_discovery_mcp() {
    let requested = FeatureFlagSnapshot {
        gitlab_discovery_mcp: true,
        gitlab_inline_review_comments: false,
        composer_install: false,
        composer_auto_repositories: false,
        composer_safe_install: false,
        security_review: false,
    };

    assert!(DockerCodexRunner::effective_feature_flags(&requested, true).gitlab_discovery_mcp);
    assert!(!DockerCodexRunner::effective_feature_flags(&requested, false).gitlab_discovery_mcp);
}

#[test]
fn command_skips_static_gitlab_discovery_enable_override_without_injection() {
    let mut codex = test_codex_config();
    codex.mcp_server_overrides.review =
        BTreeMap::from([(codex.gitlab_discovery_mcp.server_name.clone(), true)]);
    let runner = test_runner_with_codex(codex);
    let ctx = review_context_with_target_branch(Some("main"));

    let script = runner
        .command(
            &ctx,
            AppServerCommandOptions {
                browser_mcp: None,
                gitlab_discovery_mcp: None,
                mcp_server_overrides: &runner.codex.mcp_server_overrides.review,
                reasoning_summary: None,
                reasoning_effort: None,
            },
            runner.review_reasoning_effort(),
        )
        .expect("command script");

    assert!(!script.contains("mcp_servers.gitlab-discovery.enabled=true"));
}

#[test]
fn prepare_gitlab_discovery_mcp_rejects_empty_source_repo() {
    let mut codex = test_codex_config();
    codex.gitlab_discovery_mcp = crate::config::GitLabDiscoveryMcpConfig {
        enabled: true,
        bind_addr: "127.0.0.1:8091".to_string(),
        advertise_url: "http://mcp.internal:8091/mcp".to_string(),
        allow: vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["group/repo".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }],
        ..crate::config::GitLabDiscoveryMcpConfig::default()
    };
    let service = Arc::new(
        crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            },
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets::default(),
            },
            codex.gitlab_discovery_mcp.clone(),
        )
        .expect("gitlab discovery service"),
    );
    let mut runner = test_runner_with_codex(codex);
    runner.gitlab_discovery_mcp = Some(service as Arc<dyn GitLabDiscoveryHandle>);

    let prepared = runner.prepare_gitlab_discovery_mcp(
        "",
        &FeatureFlagSnapshot {
            gitlab_discovery_mcp: true,
            gitlab_inline_review_comments: false,
            composer_install: false,
            composer_auto_repositories: false,
            composer_safe_install: false,
            security_review: false,
        },
        &BTreeMap::new(),
    );

    assert!(prepared.is_none());
}

#[test]
fn browser_mcp_prereq_script_fails_when_command_is_missing() -> Result<()> {
    let script = browser_mcp_prereq_script(Some(&test_browser_mcp_config(
        "definitely-not-installed-browser-mcp",
    )));
    let output = run_bash_script(&script)?;
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("browser MCP requires"));
    Ok(())
}

#[test]
fn browser_mcp_prereq_script_succeeds_when_command_exists() -> Result<()> {
    let script = browser_mcp_prereq_script(Some(&test_browser_mcp_config("sh")));
    let output = run_bash_script(&script)?;
    assert!(output.status.success());
    Ok(())
}

#[test]
fn browser_mcp_prereq_script_is_empty_when_disabled() {
    let script = browser_mcp_prereq_script(None);
    assert!(script.is_empty());
}

#[test]
fn browser_wait_script_probes_endpoint_until_ready() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let server = thread::spawn(move || -> Result<Vec<u8>> {
        let (mut stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;

        let mut request = Vec::new();
        let mut buf = [0_u8; 256];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    request.extend_from_slice(&buf[..n]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => return Err(err.into()),
            }
        }

        if request == b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
        {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")?;
        }

        Ok(request)
    });

    let output = run_bash_script(&render_browser_wait_script_for_port(port))?;
    let request = server.join().expect("server thread panicked")?;

    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        request,
        b"GET /json/version HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    Ok(())
}

#[test]
fn mention_command_script_clones_repo_and_starts_app_server() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(
        script.contains("run_git clone git clone --depth 1 --recurse-submodules \"https://oauth2:${GITLAB_TOKEN}@example.com/repo.git\"")
    );
    assert!(script.contains("repo_dir='/work/repo/group/repo'"));
    assert!(script.contains("export GITLAB_TOKEN='token'"));
    assert!(
        script
            .contains("export GIT_CONFIG_KEY_0='url.https://oauth2:token@example.com/.insteadOf'")
    );
    assert!(script.contains("unset GIT_CONFIG_COUNT"));
    assert!(script.contains("unset GITLAB_TOKEN"));
    assert!(!script.contains("rm -rf"));
    assert!(script.contains("git remote set-url --push origin \"no_push://disabled\""));
    assert!(script.contains("exec codex app-server"));
    assert!(!script.contains("codex exec --sandbox workspace-write"));
    assert!(!script.contains("GIT_AUTHOR_NAME="));
}

#[test]
fn mention_command_script_includes_mcp_server_overrides() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let overrides = BTreeMap::from([("playwright".to_string(), true)]);
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &overrides,
            reasoning_summary: None,
            reasoning_effort: None,
        },
    );
    assert!(script.contains("exec codex -c 'mcp_servers.playwright.enabled=true' app-server"));
}

#[test]
fn mention_command_script_includes_reasoning_effort_override() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: None,
            reasoning_effort: Some("low"),
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_effort=\"low\"' app-server"));
}

#[test]
fn mention_command_script_includes_reasoning_summary_override() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            reasoning_summary: Some("detailed"),
            reasoning_effort: None,
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"));
}

#[test]
fn mention_developer_instructions_require_commit_and_sha_reporting() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
    assert!(instructions.contains("create at least one commit before you finish"));
    assert!(instructions.contains("include the commit SHA"));
    assert!(instructions.contains("no commit was created"));
    assert!(instructions.contains("Name: Alice Example"));
    assert!(instructions.contains("Email: alice@example.com"));
    assert!(!instructions.contains("Additional instructions:"));
}

#[test]
fn mention_developer_instructions_include_additional_section_when_configured() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: Some(
            "  Prefer minimal diffs and include tests.  ".to_string(),
        ),
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
    assert!(instructions.contains("Additional instructions:"));
    assert!(instructions.contains("Prefer minimal diffs and include tests."));
}

#[test]
fn normalize_image_reference_appends_latest_when_missing_tag() {
    let image = "ghcr.io/openai/codex-universal";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal:latest"
    );
}

#[test]
fn normalize_image_reference_preserves_tag() {
    let image = "ghcr.io/openai/codex-universal:v1.2.3";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal:v1.2.3"
    );
}

#[test]
fn normalize_image_reference_preserves_digest() {
    let image = "ghcr.io/openai/codex-universal@sha256:deadbeef";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal@sha256:deadbeef"
    );
}

#[test]
fn normalize_image_reference_handles_registry_port() {
    let image = "localhost:5000/codex-universal";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "localhost:5000/codex-universal:latest"
    );
}

#[test]
fn normalize_image_reference_keeps_tag_with_registry_port() {
    let image = "localhost:5000/codex-universal:canary";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "localhost:5000/codex-universal:canary"
    );
}

#[test]
fn warm_up_image_refs_only_include_codex_image_when_browser_mcp_disabled() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: false,
            ..BrowserMcpConfig::default()
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_include_browser_image_when_any_mode_keeps_browser_enabled() {
    let runner = test_runner_with_codex_and_mentions(
        CodexConfig {
            image: "ghcr.io/openai/codex-universal".to_string(),
            browser_mcp: BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "chromedp/headless-shell".to_string(),
                ..BrowserMcpConfig::default()
            },
            mcp_server_overrides: McpServerOverridesConfig {
                review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
                mention: BTreeMap::new(),
            },
            ..test_codex_config()
        },
        true,
    );

    assert_eq!(
        runner.warm_up_image_refs(),
        vec![
            "ghcr.io/openai/codex-universal:latest".to_string(),
            "chromedp/headless-shell:latest".to_string()
        ]
    );
}

#[test]
fn warm_up_image_refs_skip_browser_image_when_mentions_are_disabled() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell".to_string(),
            ..BrowserMcpConfig::default()
        },
        mcp_server_overrides: McpServerOverridesConfig {
            review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
            mention: BTreeMap::new(),
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_skip_browser_image_when_all_modes_disable_browser() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell".to_string(),
            ..BrowserMcpConfig::default()
        },
        mcp_server_overrides: McpServerOverridesConfig {
            review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
            mention: BTreeMap::from([("chrome-devtools".to_string(), false)]),
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_deduplicate_identical_codex_and_browser_images() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "ghcr.io/openai/codex-universal:latest".to_string(),
            ..BrowserMcpConfig::default()
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

fn test_codex_config() -> CodexConfig {
    CodexConfig {
        image: "ghcr.io/openai/codex-universal:latest".to_string(),
        timeout_seconds: 300,
        auth_host_path: "/root/.codex".to_string(),
        auth_mount_path: "/root/.codex".to_string(),
        session_history_path: None,
        exec_sandbox: "danger-full-access".to_string(),
        fallback_auth_accounts: Vec::new(),
        usage_limit_fallback_cooldown_seconds: 3600,
        deps: DepsConfig { enabled: false },
        browser_mcp: BrowserMcpConfig::default(),
        gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
        mcp_server_overrides: McpServerOverridesConfig::default(),
        reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
        reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
    }
}

fn test_runner_with_codex(codex: CodexConfig) -> DockerCodexRunner {
    test_runner_with_codex_and_mentions(codex, false)
}

async fn test_runner_with_fake_runtime(
    codex: CodexConfig,
    mention_commands_active: bool,
    harness: Arc<FakeRunnerHarness>,
    gitlab_discovery_mcp: Option<Arc<dyn GitLabDiscoveryHandle>>,
) -> DockerCodexRunner {
    DockerCodexRunner::new_with_test_runtime(
        codex,
        Url::parse("https://gitlab.example.com").expect("url"),
        Arc::new(ReviewStateStore::new(":memory:").await.expect("state")),
        gitlab_discovery_mcp,
        RunnerRuntimeOptions {
            gitlab_token: "token".to_string(),
            log_all_json: false,
            owner_id: "owner-id".to_string(),
            mention_commands_active,
            review_additional_developer_instructions: None,
        },
        harness,
    )
}

fn test_runner_with_codex_and_mentions(
    codex: CodexConfig,
    mention_commands_active: bool,
) -> DockerCodexRunner {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    DockerCodexRunner {
        runtime: RunnerRuntime::Docker {
            docker: connect_docker(&DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            })
            .expect("docker client"),
            image_pulls: Mutex::new(HashMap::new()),
            next_image_pull_id: AtomicU64::new(1),
        },
        security_context_builds: Arc::new(Mutex::new(HashMap::new())),
        codex,
        gitlab_discovery_mcp: None,
        mention_commands_active,
        review_additional_developer_instructions: None,
        git_base: Url::parse("https://gitlab.example.com").expect("url"),
        gitlab_token: "token".to_string(),
        log_all_json: false,
        owner_id: "owner-id".to_string(),
        state: Arc::new(
            runtime
                .block_on(ReviewStateStore::new(":memory:"))
                .expect("state"),
        ),
        auth_accounts: Vec::new(),
    }
}

#[tokio::test]
async fn run_review_with_fake_runtime_starts_browser_and_returns_comment() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result(
            "review/start",
            json!({
                "turn": { "id": "turn-1" },
                "reviewThreadId": "thread-1",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "review-item-1",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"comment\",\"summary\":\"needs changes\",\"comment_markdown\":\"- fix it\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));

    let mut codex = test_codex_config();
    codex.browser_mcp.enabled = true;
    codex.mcp_server_overrides.review = BTreeMap::from([("serena".to_string(), false)]);
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;

    let result = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await?;

    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "needs changes");
            assert_eq!(comment.body, "- fix it");
        }
        _ => bail!("expected comment result"),
    }

    let app_starts = harness.app_server_starts();
    assert_eq!(app_starts.len(), 1);
    assert_eq!(
        app_starts[0].browser_container_id.as_deref(),
        Some("browser-1")
    );
    assert_eq!(
        app_starts[0].network_mode.as_deref(),
        Some("container:browser-1")
    );
    assert!(app_starts[0].request.cmd[1].contains("--browserUrl=http://127.0.0.1:9222"));
    assert!(app_starts[0].request.cmd[1].contains("mcp_servers.serena.enabled=false"));

    let browser_starts = harness.browser_starts();
    assert_eq!(browser_starts.len(), 1);
    assert_eq!(browser_starts[0].container_id, "browser-1");
    assert_eq!(
        harness.ensured_images(),
        vec![
            "ghcr.io/openai/codex-universal:latest".to_string(),
            "chromedp/headless-shell:latest".to_string(),
        ]
    );
    let request_methods = harness
        .app_protocol_requests()
        .into_iter()
        .filter_map(|message| {
            message
                .get("method")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        request_methods,
        vec![
            "initialize".to_string(),
            "initialized".to_string(),
            "thread/start".to_string(),
            "review/start".to_string(),
        ]
    );
    assert_eq!(harness.removed_containers(), vec!["app-1", "browser-1"]);
    Ok(())
}

#[tokio::test]
async fn run_review_with_fake_runtime_initializes_before_composer_install() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result(
            "review/start",
            json!({
                "turn": { "id": "turn-1" },
                "reviewThreadId": "thread-1",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "review-item-1",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"pass\",\"summary\":\"ok\",\"comment_markdown\":\"\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));
    let composer_command = composer_install_exec_command(
        ComposerInstallMode::Full,
        DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS,
        None,
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: composer_command.clone(),
            cwd: Some("/work/repo".to_string()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 86,
            stdout: format!("{COMPOSER_SKIP_MARKER}:missing-composer-json\n"),
            stderr: String::new(),
        },
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.feature_flags = FeatureFlagSnapshot {
        composer_install: true,
        ..FeatureFlagSnapshot::default()
    };

    let result = runner.run_review(ctx).await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let operations = harness.operation_log();
    let initialize_index = operations
        .iter()
        .position(|entry| entry == "app:initialize")
        .expect("initialize request");
    let initialized_index = operations
        .iter()
        .position(|entry| entry == "app:initialized")
        .expect("initialized notification");
    let composer_index = operations
        .iter()
        .position(|entry| {
            entry.starts_with("exec:")
                && entry.contains(
                    "composer install --no-interaction --no-progress --ignore-platform-reqs",
                )
        })
        .expect("composer exec");
    assert!(initialize_index < composer_index);
    assert!(initialized_index < composer_index);

    Ok(())
}

#[tokio::test]
async fn wait_for_browser_container_ready_with_fake_runtime_reports_exit() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_browser_diagnostics(
        "browser-1",
        vec![BrowserContainerDiagnostics {
            container_id: "browser-1".to_string(),
            launch: BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default()),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(137),
                oom_killed: Some(false),
                error: Some("process exited".to_string()),
                started_at: Some("2026-03-18T10:00:00Z".to_string()),
                finished_at: Some("2026-03-18T10:00:02Z".to_string()),
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: Vec::new(),
                stderr: vec!["browser failed to boot".to_string()],
            },
            log_collection_error: None,
        }],
    );
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .wait_for_browser_container_ready(
            "browser-1",
            &BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default()),
        )
        .await
        .expect_err("browser readiness should fail");

    let text = format!("{err:#}");
    assert!(text.contains("browser container exited before reporting readiness on port 9222"));
    assert!(text.contains("browser failed to boot"));
}

#[tokio::test]
async fn run_mention_command_with_fake_runtime_executes_git_helpers_and_returns_commit()
-> Result<()> {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result("turn/start", json!({ "turn": { "id": "turn-1" } }))
            .with_after_response(vec![
                ScriptedAppChunk::Json(json!({
                    "method": "turn/started",
                    "params": { "threadId": "thread-1", "turnId": "turn-1" }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "itemId": "agent-1",
                        "delta": "Implemented and committed deadbeef"
                    }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "item": {
                            "id": "agent-1",
                            "type": "AgentMessage",
                            "phase": "final"
                        }
                    }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "turn/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "turn": { "status": "completed" }
                    }
                })),
            ]),
    ]));

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    for command in [
        vec![
            "config".to_string(),
            "user.name".to_string(),
            "Requester".to_string(),
        ],
        vec![
            "config".to_string(),
            "user.email".to_string(),
            "requester@example.com".to_string(),
        ],
        vec![
            "remote".to_string(),
            "set-url".to_string(),
            "--push".to_string(),
            "origin".to_string(),
            "no_push://disabled".to_string(),
        ],
    ] {
        harness.push_exec_output(
            ExecContainerCommandRequest {
                container_id: "app-1".to_string(),
                command: auxiliary_git_exec_command(&command),
                cwd: Some(repo_dir.clone()),
                env: None,
            },
            ContainerExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
    }
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["rev-parse".to_string(), "HEAD".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "before-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["rev-parse".to_string(), "HEAD".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "after-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "--is-ancestor".to_string(),
                "before-sha".to_string(),
                "after-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-list".to_string(),
                "--count".to_string(),
                "before-sha..after-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "1\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: restore_push_remote_url_exec_command(
                "https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git",
            ),
            cwd: Some(repo_dir.clone()),
            env: Some(vec!["GITLAB_TOKEN=token".to_string()]),
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "push".to_string(),
                "origin".to_string(),
                "HEAD:feature".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let result = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot::default(),
            run_history_id: None,
        })
        .await?;

    assert_eq!(result.status, MentionCommandStatus::Committed);
    assert_eq!(result.commit_sha.as_deref(), Some("after-sha"));
    assert_eq!(result.reply_message, "Implemented and committed deadbeef");

    let exec_requests = harness.exec_requests();
    assert_eq!(exec_requests.len(), 10);
    assert_eq!(
        exec_requests.last().unwrap().command,
        auxiliary_git_exec_command(&[
            "push".to_string(),
            "origin".to_string(),
            "HEAD:feature".to_string(),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn prepare_mention_inputs_downloads_images_inside_container() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-mention-images-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-mention-images-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: super::mention_inputs::mention_image_download_exec_command(
                "/tmp/codex-mention-images-123456/01-screenshot.png",
                "https://gitlab.example.com/api/v4/projects/group%2Frepo/uploads/hash/screenshot.png",
            ),
            cwd: Some(repo_dir.clone()),
            env: Some(vec!["GITLAB_TOKEN=token".to_string()]),
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;

    let prepared = runner
        .prepare_mention_inputs(
            "app-1",
            repo_dir.as_str(),
            &MentionCommandContext {
                repo: "group/repo".to_string(),
                project_path: "group/repo".to_string(),
                discussion_project_path: "group/repo".to_string(),
                mr: MergeRequest {
                    iid: 11,
                    title: Some("Title".to_string()),
                    web_url: None,
                    created_at: None,
                    updated_at: None,
                    sha: Some("before-sha".to_string()),
                    source_branch: Some("feature".to_string()),
                    target_branch: Some("main".to_string()),
                    author: None,
                    source_project_id: Some(1),
                    target_project_id: Some(1),
                    diff_refs: None,
                },
                head_sha: "before-sha".to_string(),
                discussion_id: "discussion-1".to_string(),
                trigger_note_id: 77,
                requester_name: "Requester".to_string(),
                requester_email: "requester@example.com".to_string(),
                additional_developer_instructions: None,
                prompt: "Please fix it".to_string(),
                image_uploads: vec![crate::gitlab_links::GitLabMarkdownImageUpload {
                    markdown_path: "/uploads/hash/screenshot.png".to_string(),
                    absolute_url: "https://gitlab.example.com/uploads/hash/screenshot.png"
                        .to_string(),
                    secret: "hash".to_string(),
                    filename: "screenshot.png".to_string(),
                }],
                feature_flags: FeatureFlagSnapshot::default(),
                run_history_id: None,
            },
        )
        .await;

    assert_eq!(
        prepared.turn_input,
        vec![
            json!({
                "type": "text",
                "text": "Please fix it",
            }),
            json!({
                "type": "localImage",
                "path": "/tmp/codex-mention-images-123456/01-screenshot.png",
            }),
        ]
    );
}

#[tokio::test]
async fn run_mention_command_with_fake_runtime_initializes_before_composer_install() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
    ]));
    let composer_command = composer_install_exec_command(
        ComposerInstallMode::Full,
        DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS,
        None,
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: composer_command.clone(),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 86,
            stdout: format!("{COMPOSER_SKIP_MARKER}:missing-composer-json\n"),
            stderr: String::new(),
        },
    );
    harness.push_exec_error(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        "git status failed",
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let err = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot {
                composer_install: true,
                ..FeatureFlagSnapshot::default()
            },
            run_history_id: None,
        })
        .await
        .expect_err("mention command should fail after baseline git status");

    assert!(format!("{err:#}").contains("git status failed"));

    let operations = harness.operation_log();
    let initialize_index = operations
        .iter()
        .position(|entry| entry == "app:initialize")
        .expect("initialize request");
    let initialized_index = operations
        .iter()
        .position(|entry| entry == "app:initialized")
        .expect("initialized notification");
    let composer_index = operations
        .iter()
        .position(|entry| {
            entry.starts_with("exec:")
                && entry.contains(
                    "composer install --no-interaction --no-progress --ignore-platform-reqs",
                )
        })
        .expect("composer exec");
    assert!(initialize_index < composer_index);
    assert!(initialized_index < composer_index);
}

#[tokio::test]
async fn run_mention_command_with_fake_runtime_surfaces_exec_failures() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
    ]));
    harness.push_exec_error(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        "git status failed",
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let err = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot::default(),
            run_history_id: None,
        })
        .await
        .expect_err("mention command should fail");

    assert!(format!("{err:#}").contains("git status failed"));
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn run_review_with_fake_runtime_surfaces_closed_stdout_with_recent_runner_errors() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result(
            "review/start",
            json!({
                "turn": { "id": "turn-1" },
                "reviewThreadId": "thread-1",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Line("codex-runner-error: git clone failed with 429".to_string()),
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
        ])
        .close_output_after(),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await
        .expect_err("review should fail when app-server closes stdout");

    let text = format!("{err:#}");
    assert!(text.contains("codex app-server closed stdout"));
    assert!(text.contains("recent runner errors: codex-runner-error: git clone failed with 429"));
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn run_review_with_fake_runtime_security_lane_uses_split_sessions_on_cache_miss() -> Result<()>
{
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_app_server(scripted_security_review_server(
        "thread-review",
        None,
        None,
        0,
        "turn-review",
        "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}",
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context",
        "turn-threat",
        "{\"components\":[],\"entry_points\":[],\"trust_boundaries\":[],\"attacker_controlled_inputs\":[],\"privileged_operations\":[],\"sensitive_assets\":[],\"security_critical_paths\":[],\"runtime_notes\":[],\"focus_paths\":[]}",
        0,
    ));

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
    let run_history_id = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review_lane::ReviewLane::Security;
    ctx.min_confidence_score = Some(0.85);
    ctx.run_history_id = Some(run_history_id);

    let result = runner.run_review(ctx).await?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "No confirmed security issues.");
        }
        other => bail!("expected pass result, got {other:?}"),
    }

    let request_methods = harness
        .app_protocol_requests()
        .into_iter()
        .filter_map(|message| {
            message
                .get("method")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        request_methods,
        vec![
            "initialize".to_string(),
            "initialized".to_string(),
            "thread/start".to_string(),
            "initialize".to_string(),
            "initialized".to_string(),
            "thread/start".to_string(),
            "turn/start".to_string(),
            "turn/start".to_string(),
        ]
    );
    let app_server_starts = harness.app_server_starts();
    assert_eq!(app_server_starts.len(), 2);
    assert!(
        app_server_starts[0]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    assert!(
        app_server_starts[1]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"xhigh\""))
    );

    let run = runner
        .state
        .get_run_history(run_history_id)
        .await?
        .expect("run history");
    assert_eq!(run.thread_id.as_deref(), Some("thread-review"));
    assert_eq!(run.turn_id.as_deref(), Some("turn-review"));
    assert_eq!(run.review_thread_id, None);
    assert_eq!(run.security_context_source_run_id, Some(run_history_id));
    assert_eq!(run.security_context_base_branch.as_deref(), Some("main"));
    assert_eq!(
        run.security_context_base_head_sha.as_deref(),
        Some("base-head-sha")
    );
    assert_eq!(
        run.security_context_prompt_version.as_deref(),
        Some("security-review-context-v1")
    );
    assert!(run.security_context_payload_json.is_some());
    assert!(run.security_context_generated_at.is_some());
    assert!(run.security_context_expires_at.is_some());

    let events = runner.state.list_run_history_events(run_history_id).await?;
    let turn_ids = events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(turn_ids, BTreeSet::from(["turn-review", "turn-threat"]));

    let cache_entry = runner
        .state
        .get_security_review_context_cache(
            "group/repo",
            "main",
            "base-head-sha",
            "security-review-context-v1",
            1_000_000_000,
        )
        .await?
        .expect("cache entry");
    assert_eq!(cache_entry.source_run_history_id, run_history_id);
    Ok(())
}

#[tokio::test]
async fn concurrent_security_reviews_reuse_single_inflight_context_build() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let security_context_json = "{\"components\":[],\"entry_points\":[],\"trust_boundaries\":[],\"attacker_controlled_inputs\":[],\"privileged_operations\":[],\"sensitive_assets\":[],\"security_critical_paths\":[],\"runtime_notes\":[],\"focus_paths\":[]}";
    let security_review_json = "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}";

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );

    harness.push_app_server(scripted_security_review_server(
        "thread-review-1",
        None,
        None,
        0,
        "turn-review-1",
        security_review_json,
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context-1",
        "turn-threat-1",
        security_context_json,
        200,
    ));
    harness.push_app_server(scripted_security_review_server(
        "thread-review-2",
        None,
        None,
        0,
        "turn-review-2",
        security_review_json,
    ));

    let runner = Arc::new(
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await,
    );
    let run_history_id_1 = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let run_history_id_2 = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "def456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let mut ctx1 = review_context_with_target_branch(Some("main"));
    ctx1.lane = crate::review_lane::ReviewLane::Security;
    ctx1.min_confidence_score = Some(0.85);
    ctx1.run_history_id = Some(run_history_id_1);

    let mut ctx2 = review_context_with_target_branch(Some("main"));
    ctx2.lane = crate::review_lane::ReviewLane::Security;
    ctx2.min_confidence_score = Some(0.85);
    ctx2.run_history_id = Some(run_history_id_2);
    ctx2.head_sha = "def456".to_string();
    ctx2.mr.iid = 12;
    ctx2.mr.sha = Some("def456".to_string());
    ctx2.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/12".to_string());
    ctx2.mr.source_branch = Some("feature-2".to_string());

    let leader_runner = Arc::clone(&runner);
    let leader = tokio::spawn(async move { leader_runner.run_review(ctx1).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let follower_runner = Arc::clone(&runner);
    let follower = tokio::spawn(async move { follower_runner.run_review(ctx2).await });

    let leader_result = leader.await??;
    let follower_result = follower.await??;
    assert!(matches!(leader_result, CodexResult::Pass { .. }));
    assert!(matches!(follower_result, CodexResult::Pass { .. }));

    let exec_requests = harness.exec_requests();
    let mktemp_requests = exec_requests
        .iter()
        .filter(|request| {
            request
                .command
                .first()
                .is_some_and(|command| command == "mktemp")
        })
        .count();
    assert_eq!(mktemp_requests, 1);

    let cache_entry = runner
        .state
        .get_security_review_context_cache(
            "group/repo",
            "main",
            "base-head-sha",
            "security-review-context-v1",
            1_000_000_000,
        )
        .await?
        .expect("cache entry");
    assert_eq!(cache_entry.source_run_history_id, run_history_id_1);

    let follower_run = runner
        .state
        .get_run_history(run_history_id_2)
        .await?
        .expect("follower run history");
    assert_eq!(follower_run.thread_id.as_deref(), Some("thread-review-2"));
    let follower_events = runner
        .state
        .list_run_history_events(run_history_id_2)
        .await?;
    let follower_turn_ids = follower_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(follower_turn_ids, BTreeSet::from(["turn-review-2"]));
    let app_server_starts = harness.app_server_starts();
    assert_eq!(app_server_starts.len(), 3);
    assert!(
        app_server_starts[0]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    assert!(
        app_server_starts[1]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"xhigh\""))
    );
    assert!(
        app_server_starts[2]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_security_reviews_wake_followers_when_context_build_fails() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let security_review_json = "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}";

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-654321\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-654321".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-654321".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );

    harness.push_app_server(scripted_security_review_server(
        "thread-review-1",
        None,
        None,
        0,
        "turn-review-1",
        security_review_json,
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context-1",
        "turn-threat-fail",
        "not-json",
        200,
    ));
    harness.push_app_server(scripted_security_review_server(
        "thread-review-2",
        None,
        None,
        0,
        "turn-review-2",
        security_review_json,
    ));

    let runner = Arc::new(
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await,
    );
    let run_history_id_1 = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let run_history_id_2 = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "def456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let mut ctx1 = review_context_with_target_branch(Some("main"));
    ctx1.lane = crate::review_lane::ReviewLane::Security;
    ctx1.min_confidence_score = Some(0.85);
    ctx1.run_history_id = Some(run_history_id_1);
    ctx1.mr.iid = 21;
    ctx1.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/21".to_string());

    let mut ctx2 = review_context_with_target_branch(Some("main"));
    ctx2.lane = crate::review_lane::ReviewLane::Security;
    ctx2.min_confidence_score = Some(0.85);
    ctx2.run_history_id = Some(run_history_id_2);
    ctx2.head_sha = "def456".to_string();
    ctx2.mr.iid = 22;
    ctx2.mr.sha = Some("def456".to_string());
    ctx2.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/22".to_string());
    ctx2.mr.source_branch = Some("feature-2".to_string());

    let leader_runner = Arc::clone(&runner);
    let leader = tokio::spawn(async move { leader_runner.run_review(ctx1).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let follower_runner = Arc::clone(&runner);
    let follower = tokio::spawn(async move { follower_runner.run_review(ctx2).await });

    let leader_result = leader.await??;
    let follower_result = follower.await??;
    assert!(matches!(leader_result, CodexResult::Pass { .. }));
    assert!(matches!(follower_result, CodexResult::Pass { .. }));

    let exec_requests = harness.exec_requests();
    let mktemp_requests = exec_requests
        .iter()
        .filter(|request| {
            request
                .command
                .first()
                .is_some_and(|command| command == "mktemp")
        })
        .count();
    assert_eq!(mktemp_requests, 1);

    assert!(
        runner
            .state
            .get_security_review_context_cache(
                "group/repo",
                "main",
                "base-head-sha",
                "security-review-context-v1",
                1_000_000_000,
            )
            .await?
            .is_none()
    );
    let follower_run = runner
        .state
        .get_run_history(run_history_id_2)
        .await?
        .expect("follower run history");
    assert!(follower_run.security_context_payload_json.is_none());
    assert_eq!(follower_run.thread_id.as_deref(), Some("thread-review-2"));
    Ok(())
}

#[tokio::test]
async fn run_review_with_fake_runtime_persists_gitlab_discovery_startup_warning() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_peer_ips("app-1", BTreeSet::from(["10.42.0.15".to_string()]));
    let discovery = Arc::new(FakeGitLabDiscoveryHandle::new(
        "gitlab-discovery",
        "http://gitlab-discovery.internal:8091/mcp",
        "/work/mcp",
    ));
    discovery.set_allow_list(
        "group/repo",
        ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from(["group/shared".to_string()]),
            target_groups: BTreeSet::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
                server_name: "gitlab-discovery".to_string(),
                advertise_url: "http://gitlab-discovery.internal:8091/mcp".to_string(),
                clone_root: "/work/mcp".to_string(),
            })
            .expect("probe command"),
            cwd: None,
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "ERROR healthz failed\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result(
            "review/start",
            json!({
                "turn": { "id": "turn-1" },
                "reviewThreadId": "thread-1",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "review-item-1",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"pass\",\"summary\":\"ok\",\"comment_markdown\":\"\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));

    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        false,
        Arc::clone(&harness),
        Some(discovery.clone() as Arc<dyn GitLabDiscoveryHandle>),
    )
    .await;
    let run_history_id = runner
        .state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let result = runner
        .run_review(ReviewContext {
            run_history_id: Some(run_history_id),
            feature_flags: FeatureFlagSnapshot {
                gitlab_discovery_mcp: true,
                gitlab_inline_review_comments: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
                security_review: false,
            },
            ..review_context_with_target_branch(Some("main"))
        })
        .await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let app_start = harness.app_server_starts();
    assert_eq!(app_start.len(), 1);
    assert!(app_start[0].request.cmd[1].contains(
        "mcp_servers.gitlab-discovery.url=\"http://gitlab-discovery.internal:8091/mcp\""
    ));

    let events = runner.state.list_run_history_events(run_history_id).await?;
    assert!(
        events
            .iter()
            .any(|event| event.turn_id.as_deref() == Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID))
    );
    assert_eq!(discovery.registered_bindings().len(), 1);
    assert_eq!(discovery.removed_bindings(), vec!["app-1"]);
    Ok(())
}

#[tokio::test]
async fn stop_active_review_containers_with_fake_runtime_filters_to_owned_managed_names() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_managed_containers(vec![
        ManagedContainerSummary {
            id: Some("remove-review".to_string()),
            names: vec!["/codex-review-123".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("remove-browser".to_string()),
            names: vec!["/codex-browser-456".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("skip-other-owner".to_string()),
            names: vec!["/codex-review-789".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "someone-else".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("skip-unmanaged".to_string()),
            names: vec!["/not-codex".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
    ]);
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    runner.stop_active_review_containers_best_effort().await;

    assert_eq!(
        harness.removed_containers(),
        vec!["remove-review".to_string(), "remove-browser".to_string()]
    );
}

#[test]
fn review_container_prefix_matcher_handles_docker_name_format() {
    assert!(DockerCodexRunner::is_managed_container_name(
        "codex-review-abc"
    ));
    assert!(DockerCodexRunner::is_managed_container_name(
        "/codex-review-def"
    ));
    assert!(DockerCodexRunner::is_managed_container_name(
        "/codex-browser-jkl"
    ));
    assert!(!DockerCodexRunner::is_managed_container_name(
        "/codex-auth-ghi"
    ));
}

#[test]
fn review_container_labels_include_owner_label() {
    let labels = DockerCodexRunner::review_container_labels("worker-a");
    assert_eq!(
        labels.get(REVIEW_OWNER_LABEL_KEY),
        Some(&"worker-a".to_string())
    );
    assert_eq!(labels.len(), 1);
}

#[test]
fn review_container_filters_include_name_prefix_and_owner_label() {
    let filters = DockerCodexRunner::review_container_filters("worker-a");
    assert_eq!(
        filters.get("name"),
        Some(&vec![
            REVIEW_CONTAINER_NAME_PREFIX.to_string(),
            BROWSER_CONTAINER_NAME_PREFIX.to_string()
        ])
    );
    assert_eq!(
        filters.get("label"),
        Some(&vec![format!("{REVIEW_OWNER_LABEL_KEY}=worker-a")])
    );
}

#[test]
fn has_review_owner_label_requires_exact_owner_match() {
    let labels = HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), "worker-a".to_string())]);
    assert!(DockerCodexRunner::has_review_owner_label(
        Some(&labels),
        "worker-a"
    ));
    assert!(!DockerCodexRunner::has_review_owner_label(
        Some(&labels),
        "worker-b"
    ));
    assert!(!DockerCodexRunner::has_review_owner_label(None, "worker-a"));
}

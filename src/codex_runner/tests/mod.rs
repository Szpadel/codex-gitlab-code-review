use super::app_server::{
    TurnHistoryCapture, TurnNotificationContext, item_is_successful_gitlab_discovery_call,
    with_recent_runner_errors,
};
use super::auth::{auth_account_state_key, parse_usage_limit_reset_at, should_clear_limit_reset};
use super::browser_mcp::{
    BrowserContainerDiagnostics, BrowserContainerStateSnapshot, BrowserLaunchConfig,
    BrowserLogTail, browser_container_cmd, browser_container_has_exited, browser_logs_report_ready,
};
use super::container::{
    ContainerExecOutput, auxiliary_git_exec_command, validate_container_exec_result,
};
use super::gitlab_discovery::{
    gitlab_discovery_mcp_probe_exec_command, gitlab_discovery_mcp_startup_failure_events,
};
use super::review_flow::{ReviewTargetRequest, parse_review_output};
use super::scripts::{
    BuildCommandScriptInput, ConfiguredSessionOverride, browser_mcp_prereq_script,
    browser_wait_script, codex_app_server_exec_command, git_bootstrap_auth_setup_script,
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
    SessionOverridesConfig, WorkTmpfsConfig,
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

mod commands_and_scripts;
mod container_management;
mod context_and_auth;
mod image_refs;
mod mention_templates;
mod parsing;
mod runtime_discovery;
mod runtime_mention;
mod runtime_review;
mod runtime_security;

fn review_context_with_target_branch(target_branch: Option<&str>) -> ReviewContext {
    ReviewContext {
        lane: crate::review_lane::ReviewLane::General,
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
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
        work_tmpfs: WorkTmpfsConfig::default(),
        gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
        mcp_server_overrides: McpServerOverridesConfig::default(),
        session_overrides: SessionOverridesConfig::default(),
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

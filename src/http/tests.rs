use super::*;
use crate::codex_runner::{CodexResult, CodexRunner, ReviewContext};
use crate::config::{
    BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, FallbackAuthAccountConfig,
    GitLabConfig, GitLabTargets, McpServerOverridesConfig, ReasoningEffortOverridesConfig,
    ReasoningSummaryOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ScheduleConfig,
    ServerConfig, TargetSelector,
};
use crate::dev_mode::DevToolsService;
use crate::review_lane::ReviewLane;
use crate::state::{
    NewRunHistory, NewRunHistoryEvent, PersistedScanStatus, ReviewRateLimitBucketMode,
    ReviewRateLimitRuleUpsert, ReviewRateLimitScope, ReviewRateLimitTarget,
    ReviewRateLimitTargetKind, ReviewStateStore, RunHistoryFinish, RunHistoryKind,
    RunHistorySessionUpdate, ScanMode, ScanOutcome, ScanState, TranscriptBackfillState,
};
use crate::transcript_backfill::{
    TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR, TranscriptBackfillSource,
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{StatusCode, multipart};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::time::{Duration, sleep};
use zip::write::SimpleFileOptions;

fn test_client_builder() -> reqwest::ClientBuilder {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::Client::builder()
}

fn test_client() -> reqwest::Client {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::Client::new()
}

async fn test_get(url: impl reqwest::IntoUrl) -> reqwest::Result<reqwest::Response> {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::get(url).await
}

#[tokio::test]
async fn api_status_returns_scan_and_in_progress_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/repo", 7, "abcdef").await?;
    state
        .begin_mention_command("group/repo", 7, "discussion-1", 99, "abcdef")
        .await?;
    state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Idle,
            mode: Some(ScanMode::Incremental),
            started_at: Some("2026-03-10T11:00:00Z".to_string()),
            finished_at: Some("2026-03-10T11:00:05Z".to_string()),
            outcome: Some(ScanOutcome::Success),
            error: None,
            next_scan_at: Some("2026-03-10T11:10:00Z".to_string()),
        })
        .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/api/status")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("\"scan_state\":\"idle\""));
    assert!(body.contains("\"mode\":\"incremental\""));
    assert!(body.contains("\"repo\":\"group/repo\""));
    assert!(body.contains("\"trigger_note_id\":99"));
    Ok(())
}

#[tokio::test]
async fn status_page_renders_sections_and_escapes_dynamic_content() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state.begin_review("group/<repo>", 42, "abcdef").await?;
    state
        .set_auth_limit_reset_at("primary<script>", "2026-03-10T12:00:00Z")
        .await?;
    state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Scanning,
            mode: Some(ScanMode::Full),
            started_at: Some("2026-03-10T11:59:00Z".to_string()),
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: None,
        })
        .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/status")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Service status"));
    assert!(body.contains("In-progress reviews"));
    assert!(body.contains("Auth fallback cooldowns"));
    assert!(body.contains("group/&lt;repo&gt;"));
    assert!(body.contains("primary&lt;script&gt;"));
    assert!(body.contains("class=\"localized-timestamp\""));
    assert!(body.contains("datetime=\"2026-03-10T11:59:00Z\""));
    assert!(body.contains("datetime=\"2026-03-10T12:00:00Z\""));
    assert!(body.contains("Mar 10, 2026, 11:59 AM UTC"));
    assert!(body.contains("Mar 10, 2026, 12:00 PM UTC"));
    assert!(body.contains("name=\"codex-status-csrf\""));
    assert!(body.contains("function resolveAppBasePath(pathname)"));
    assert!(!body.contains("primary<script>"));
    Ok(())
}

#[tokio::test]
async fn development_page_renders_when_dev_tools_are_enabled() -> Result<()> {
    let mut config = test_config();
    config.database.path = "/tmp/codex-gitlab-code-review-dev-test.sqlite".to_string();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(config.clone(), state, false, None));
    let dev_tools = Arc::new(DevToolsService::new(&config.database.path));
    let address = spawn_test_server(app_router_with_dev_tools(
        Arc::clone(&status_service),
        Some(dev_tools),
    ))
    .await?;

    let response = test_get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Development tools"));
    assert!(body.contains("demo/group/service-a"));
    assert!(body.contains("demo/group/service-b"));
    assert!(body.contains("demo/group/service-c"));
    assert!(body.contains("/tmp/codex-gitlab-code-review-dev-test.sqlite"));
    assert!(body.contains("<a class=\"nav-link active\" href=\"/development\""));
    assert!(body.contains("No active synthetic MR."));
    Ok(())
}

#[tokio::test]
async fn development_page_is_not_mounted_without_dev_tools() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(test_config(), state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let status_response = reqwest::get(format!("http://{address}/status")).await?;
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_body = status_response.text().await?;
    assert!(!status_body.contains("href=\"/development\""));

    let response = reqwest::get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn development_repo_actions_require_csrf_and_update_snapshot() -> Result<()> {
    let mut config = test_config();
    config.database.path = "/tmp/codex-gitlab-code-review-dev-test.sqlite".to_string();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(config.clone(), state, false, None));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let dev_tools = Arc::new(DevToolsService::new(&config.database.path));
    let address = spawn_test_server(app_router_with_dev_tools(
        Arc::clone(&status_service),
        Some(dev_tools),
    ))
    .await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/development/repos/create"))
        .form(&[
            ("csrf_token", "wrong"),
            ("repo_path", "demo/group/service-z"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let created = client
        .post(format!("http://{address}/development/repos/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("repo_path", "demo/group/service-z"),
        ])
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);

    let repo_key = super::view::encode_repo_key("demo/group/service-z");
    let simulated_mr = client
        .post(format!(
            "http://{address}/development/repos/{repo_key}/simulate-mr"
        ))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(simulated_mr.status(), StatusCode::SEE_OTHER);

    let simulated_commit = client
        .post(format!(
            "http://{address}/development/repos/{repo_key}/simulate-commit"
        ))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(simulated_commit.status(), StatusCode::SEE_OTHER);

    let response = test_get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("demo/group/service-z"));
    assert!(body.contains("Active MR !1"));
    assert!(body.contains("Revision 2"));
    Ok(())
}

#[tokio::test]
async fn rate_limits_page_renders_create_form_and_empty_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Merge request backlog limit".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 2,
            window_seconds: 600,
        })
        .await?;

    let status_service = Arc::new(StatusService::new(test_config(), state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/rate-limits")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Review rate limits"));
    assert!(body.contains("Create rule"));
    assert!(body.contains("Open create rule modal"));
    assert!(body.contains("Existing rules"));
    assert!(body.contains("Merge request backlog limit"));
    assert!(body.contains("group/repo"));
    assert!(body.contains("data-role=\"rate-limit-modal\""));
    assert!(body.contains("2h 15m"));
    assert!(body.contains("\"bucket_mode\":\"shared\""));
    assert!(body.contains("Per repository"));
    assert!(body.contains("one bucket per matched repository"));
    assert!(body.contains("/rate-limits"));
    assert!(body.contains("No active buckets."));
    assert!(body.contains("No pending review items."));
    assert!(body.contains("<a class=\"nav-link active\" href=\"/rate-limits\""));
    Ok(())
}

#[tokio::test]
async fn create_rate_limit_rule_endpoint_requires_csrf_and_persists_rule() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", "wrong"),
            ("label", "Create denied"),
            ("scope", "project"),
            ("targets_json", r#"[{"kind":"repo","path":"group/repo"}]"#),
            ("bucket_mode", "shared"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "2m"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let created = client
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Create allowed"),
            ("scope", "project"),
            (
                "targets_json",
                r#"[{"kind":"repo","path":"group/repo"},{"kind":"group","path":"group/platform"}]"#,
            ),
            ("bucket_mode", "independent"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "2m"),
        ])
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);
    assert_eq!(state.list_review_rate_limit_rules().await?.len(), 1);
    assert_eq!(
        state.list_review_rate_limit_rules().await?[0].label,
        "Create allowed"
    );
    assert_eq!(
        state.list_review_rate_limit_rules().await?[0].targets,
        vec![
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string()
            },
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Group,
                path: "group/platform".to_string()
            }
        ]
    );
    assert_eq!(
        state.list_review_rate_limit_rules().await?[0].bucket_mode,
        ReviewRateLimitBucketMode::Shared
    );
    Ok(())
}

#[tokio::test]
async fn update_rate_limit_rule_endpoint_requires_csrf_and_applies_form_changes() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Original".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 3,
            window_seconds: 300,
        })
        .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/{rule_id}/update"))
        .form(&[
            ("csrf_token", "bad"),
            ("label", "Updated"),
            ("scope", "project"),
            ("targets_json", r#"[{"kind":"repo","path":"group/repo"}]"#),
            ("bucket_mode", "shared"),
            ("capacity", "5"),
            ("window_text", "5m"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let updated = client
        .post(format!("http://{address}/rate-limits/{rule_id}/update"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Updated"),
            ("scope", "project"),
            (
                "targets_json",
                r#"[{"kind":"group","path":"group/platform"}]"#,
            ),
            ("bucket_mode", "independent"),
            ("capacity", "5"),
            ("window_text", "5m"),
            ("applies_to_review", "true"),
        ])
        .send()
        .await?;
    assert_eq!(updated.status(), StatusCode::SEE_OTHER);

    let rule = state.list_review_rate_limit_rules().await?;
    assert_eq!(rule.len(), 1);
    assert_eq!(rule[0].label, "Updated");
    assert_eq!(rule[0].capacity, 5);
    assert_eq!(rule[0].bucket_mode, ReviewRateLimitBucketMode::Shared);
    assert_eq!(
        rule[0].targets,
        vec![ReviewRateLimitTarget {
            kind: ReviewRateLimitTargetKind::Group,
            path: "group/platform".to_string(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn delete_rate_limit_rule_endpoint_requires_csrf_and_removes_rule() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Delete me".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 1,
            window_seconds: 60,
        })
        .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/{rule_id}/delete"))
        .form(&[("csrf_token", "bad")])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(state.list_review_rate_limit_rules().await?.len(), 1);

    let deleted = client
        .post(format!("http://{address}/rate-limits/{rule_id}/delete"))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert!(state.list_review_rate_limit_rules().await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn regen_rate_limit_bucket_slot_endpoint_refunds_slot() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Regenerate".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 2,
            window_seconds: 300,
        })
        .await?;

    let now = Utc::now().timestamp();
    state
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 11, now)
        .await?;
    state
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 11, now)
        .await?;
    let before = state.list_active_review_rate_limit_buckets(now).await?;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].available_slots, 0.0);
    let bucket_id = before[0].bucket_id.clone();

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{address}/rate-limits/buckets/regen"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("bucket_id", bucket_id.as_str()),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let after = state
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?;
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].available_slots, 1.0);
    assert_eq!(after[0].rule_id, rule_id);
    Ok(())
}

#[tokio::test]
async fn create_rate_limit_rule_endpoint_allows_global_rules_without_targets() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Global cap"),
            ("scope", "project"),
            ("targets_json", "[]"),
            ("bucket_mode", "shared"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "30m"),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let rules = state.list_review_rate_limit_rules().await?;
    assert_eq!(rules.len(), 1);
    assert!(rules[0].targets.is_empty());
    assert_eq!(rules[0].scope_subject, "Global".to_string());
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_accepts_friendly_duration_and_targets() -> Result<()> {
    let upsert = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Friendly".to_string(),
        scope: "project".to_string(),
        targets_json:
            r#"[{"kind":"repo","path":"group/repo"},{"kind":"group","path":"group/platform"}]"#
                .to_string(),
        bucket_mode: "independent".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 2,
        window_text: "2h 15m".to_string(),
    })?;

    assert_eq!(upsert.window_seconds, 8_100);
    assert_eq!(upsert.bucket_mode, ReviewRateLimitBucketMode::Independent);
    assert_eq!(
        upsert.targets,
        vec![
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            },
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Group,
                path: "group/platform".to_string(),
            }
        ]
    );
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_accepts_empty_targets_for_global_rules() -> Result<()> {
    let upsert = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Global".to_string(),
        scope: "project".to_string(),
        targets_json: "[]".to_string(),
        bucket_mode: "shared".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 1,
        window_text: "45m".to_string(),
    })?;

    assert!(upsert.targets.is_empty());
    assert_eq!(upsert.window_seconds, 2_700);
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_rejects_invalid_duration_text() {
    let err = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Bad".to_string(),
        scope: "project".to_string(),
        targets_json: r#"[{"kind":"repo","path":"group/repo"}]"#.to_string(),
        bucket_mode: "shared".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 1,
        window_text: "later".to_string(),
    })
    .expect_err("expected invalid duration");

    assert!(err.to_string().contains("window_text"));
}

#[tokio::test]
async fn feature_flag_update_endpoint_persists_runtime_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/source".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/target".to_string()],
        target_groups: Vec::new(),
    }];
    let status_service = Arc::new(StatusService::new(config, Arc::clone(&state), false, None));
    let csrf_token = status_service.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client();

    let response = client
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("\"runtime_override\":true"));
    assert!(body.contains("\"effective_enabled\":true"));

    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_requires_csrf_header() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.gitlab_discovery_mcp.enabled = true;
    let status_service = Arc::new(StatusService::new(config, Arc::clone(&state), false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_rejects_unavailable_flags() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_clears_unavailable_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": null }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_persists_composer_install_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/composer_install"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .composer_install,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_persists_composer_auto_repositories_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/composer_auto_repositories"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .get_runtime_feature_flag_overrides()
            .await?
            .composer_auto_repositories,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn status_service_snapshot_exposes_project_catalog_summary() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .save_project_catalog("all", &["group/a".to_string(), "group/b".to_string()])
        .await?;
    state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Idle,
            mode: Some(ScanMode::Full),
            started_at: Some("2026-03-10T09:00:00Z".to_string()),
            finished_at: Some("2026-03-10T09:00:02Z".to_string()),
            outcome: Some(ScanOutcome::Failure),
            error: Some("boom".to_string()),
            next_scan_at: Some("2026-03-10T09:10:00Z".to_string()),
        })
        .await?;

    let status_service = StatusService::new(test_config(), state, false, None);
    let snapshot = status_service.snapshot().await?;
    assert_eq!(snapshot.project_catalogs.len(), 1);
    assert_eq!(snapshot.project_catalogs[0].cache_key, "all".to_string());
    assert_eq!(snapshot.project_catalogs[0].project_count, 2);
    assert_eq!(snapshot.scan.scan_state, "idle".to_string());
    assert_eq!(snapshot.scan.outcome, Some("failure".to_string()));
    assert_eq!(snapshot.scan.error, Some("boom".to_string()));
    Ok(())
}

#[tokio::test]
async fn status_service_snapshot_tolerates_malformed_scan_status() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("INSERT INTO service_state (key, value) VALUES ('scan_status', 'not-json')")
        .execute(state.pool())
        .await?;

    let status_service = StatusService::new(test_config(), state, false, None);
    let snapshot = status_service.snapshot().await?;

    assert_eq!(snapshot.scan.scan_state, "idle".to_string());
    assert_eq!(snapshot.scan.mode, None);
    Ok(())
}

#[tokio::test]
async fn status_service_scan_updates_roundtrip() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = StatusService::new(test_config(), Arc::clone(&state), false, None);

    status_service
        .set_next_scan_at(Some(
            DateTime::parse_from_rfc3339("2026-03-10T12:10:00Z")?.with_timezone(&Utc),
        ))
        .await?;
    status_service.mark_scan_started(ScanMode::Full).await?;
    status_service
        .mark_scan_finished(ScanMode::Full, ScanOutcome::Success, None)
        .await?;

    let persisted = state.get_scan_status().await?;
    assert_eq!(persisted.state, ScanState::Idle);
    assert_eq!(persisted.mode, Some(ScanMode::Full));
    assert!(persisted.started_at.is_some());
    assert!(persisted.finished_at.is_some());
    assert_eq!(persisted.outcome, Some(ScanOutcome::Success));
    assert_eq!(persisted.error, None);
    assert_eq!(persisted.next_scan_at, None);
    Ok(())
}

#[tokio::test]
async fn status_routes_are_not_registered_when_ui_disabled() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.server.status_ui_enabled = false;
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let status_response = reqwest::get(format!("http://{address}/status")).await?;
    assert_eq!(status_response.status(), StatusCode::NOT_FOUND);

    let health_response = reqwest::get(format!("http://{address}/healthz")).await?;
    assert_eq!(health_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn startup_recovery_clears_stale_scanning_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish::default(),
    )
    .await?;
    sqlx::query("UPDATE run_history SET status = 'in_progress', result = NULL, finished_at = NULL WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Scanning,
            mode: Some(ScanMode::Incremental),
            started_at: Some("2026-03-10T10:00:00Z".to_string()),
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: Some("2026-03-10T10:10:00Z".to_string()),
        })
        .await?;
    let status_service = StatusService::new(test_config(), Arc::clone(&state), false, None);

    status_service.recover_startup_status().await?;

    let persisted = state.get_scan_status().await?;
    assert_eq!(persisted.state, ScanState::Idle);
    assert_eq!(persisted.mode, Some(ScanMode::Incremental));
    assert_eq!(persisted.outcome, Some(ScanOutcome::Failure));
    assert_eq!(
        persisted.error,
        Some("scan interrupted by service restart".to_string())
    );
    assert!(persisted.finished_at.is_some());
    assert_eq!(persisted.next_scan_at, None);
    let recovered_run = state
        .get_run_history(run_id)
        .await?
        .expect("recovered run should exist");
    assert_eq!(recovered_run.status, "done".to_string());
    assert_eq!(recovered_run.result.as_deref(), Some("cancelled"));
    assert_eq!(
        recovered_run.error.as_deref(),
        Some("run interrupted by service restart")
    );
    Ok(())
}

#[tokio::test]
async fn history_snapshot_filters_runs_and_returns_summary_rows() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let matching_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abcdef1".to_string(),
            discussion_id: Some("discussion-1".to_string()),
            trigger_note_id: Some(99),
            trigger_note_author_name: Some("reviewer".to_string()),
            trigger_note_body: Some("please inspect failing pipeline".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7".to_string()),
            summary: Some("Committed a fix".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/other".to_string(),
            iid: 8,
            head_sha: "abcdef2".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "pass".to_string(),
            preview: Some("Review group/other !8".to_string()),
            summary: Some("Looks good".to_string()),
            ..Default::default()
        },
    )
    .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let snapshot = status_service
        .history_snapshot(
            HistoryQueryParams {
                repo: Some("group/repo".to_string()),
                iid: None,
                kind: Some("mention".to_string()),
                result: None,
                q: Some("failing pipeline".to_string()),
                limit: None,
                page: None,
                after: None,
                before: None,
            }
            .into_query()?,
        )
        .await?;
    let body: Value = serde_json::to_value(snapshot)?;
    let runs = body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].get("id").and_then(Value::as_i64), Some(matching_id));
    assert_eq!(
        runs[0].get("preview").and_then(Value::as_str),
        Some("Mention group/repo !7")
    );
    assert_eq!(
        runs[0].get("summary").and_then(Value::as_str),
        Some("Committed a fix")
    );
    assert_eq!(runs[0].get("trigger_note_body"), None);
    Ok(())
}

#[tokio::test]
async fn history_page_renders_field_based_filters_layout() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !7".to_string()),
            summary: Some("Posted findings".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-10T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
        .bind(started_at)
        .bind(started_at)
        .bind(run_id)
        .execute(state.pool())
        .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/history?repo=group%2Frepo&iid=7&kind=review&q=findings"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("class=\"filter-field\""));
    assert!(body.contains("class=\"filter-field filter-field-wide\""));
    assert!(body.contains("class=\"filter-actions\""));
    assert!(body.contains("name=\"limit\" value=\"100\""));
    assert!(body.contains("name=\"repo\" value=\"group/repo\""));
    assert!(body.contains("name=\"iid\" value=\"7\""));
    assert!(body.contains("class=\"localized-timestamp\""));
    assert!(body.contains("data-timestamp=\"2026-03-10T12:00:00Z\""));
    assert!(body.contains("Mar 10, 2026, 12:00 PM UTC"));
    Ok(())
}

#[tokio::test]
async fn history_snapshot_searches_review_comment_body() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 10,
            head_sha: "abc1010".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "comment".to_string(),
            preview: Some("Review group/repo !10".to_string()),
            summary: Some("Posted findings".to_string()),
            error: Some("Please rename this helper before merge.".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let status_service = StatusService::new(test_config(), Arc::clone(&state), false, None);

    let snapshot = status_service
        .history_snapshot(
            HistoryQueryParams {
                repo: None,
                iid: None,
                kind: None,
                result: None,
                q: Some("rename this helper".to_string()),
                limit: None,
                page: None,
                after: None,
                before: None,
            }
            .into_query()?,
        )
        .await?;

    assert_eq!(snapshot.runs.len(), 1);
    assert_eq!(snapshot.runs[0].id, run_id);
    Ok(())
}

#[test]
fn history_query_accepts_all_kind_as_unfiltered() -> Result<()> {
    let query = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: Some("all".to_string()),
        result: None,
        q: None,
        limit: None,
        page: None,
        after: None,
        before: None,
    }
    .into_query()?;

    assert_eq!(query.kind, None);
    Ok(())
}

#[test]
fn history_query_accepts_security_kind() -> Result<()> {
    let query = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: Some("security".to_string()),
        result: None,
        q: None,
        limit: None,
        page: None,
        after: None,
        before: None,
    }
    .into_query()?;

    assert_eq!(query.kind, Some(RunHistoryKind::Security));
    Ok(())
}

#[test]
fn history_query_rejects_page_based_pagination() {
    let error = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: None,
        result: None,
        q: None,
        limit: Some(25),
        page: Some(1),
        after: None,
        before: None,
    }
    .into_query()
    .expect_err("page-based history query should be rejected");

    assert!(error.to_string().contains("invalid"));
}

#[test]
fn history_query_rejects_simultaneous_after_and_before() {
    let error = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: None,
        result: None,
        q: None,
        limit: None,
        page: None,
        after: Some("abc".to_string()),
        before: Some("def".to_string()),
    }
    .into_query()
    .expect_err("cursor query should reject simultaneous after and before");

    assert!(error.to_string().contains("invalid"));
}

#[tokio::test]
async fn history_api_returns_cursor_metadata() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut run_ids = Vec::new();
    for (iid, started_at) in [(41u64, 1_000i64), (42, 2_000), (43, 3_000)] {
        let run_id = insert_run_history(
            &state,
            NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            RunHistorySessionUpdate::default(),
            RunHistoryFinish {
                result: "commented".to_string(),
                preview: Some(format!("Review group/repo !{iid}")),
                summary: Some("pagination fixture".to_string()),
                ..Default::default()
            },
        )
        .await?;
        sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
            .bind(started_at)
            .bind(started_at)
            .bind(run_id)
            .execute(state.pool())
            .await?;
        run_ids.push(run_id);
    }
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/api/history?repo=group%2Frepo&limit=1"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let first_body: Value = response.json().await?;
    assert_eq!(first_body.get("limit").and_then(Value::as_u64), Some(1));
    assert_eq!(
        first_body.get("has_previous").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        first_body.get("has_next").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(first_body.get("previous_cursor"), Some(&Value::Null));
    assert_eq!(
        first_body
            .get("filters")
            .and_then(|filters| filters.get("after")),
        Some(&Value::Null)
    );
    let runs = first_body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].get("id").and_then(Value::as_i64), Some(run_ids[2]));
    assert_eq!(runs[0].get("head_sha"), None);

    let next_cursor = first_body
        .get("next_cursor")
        .and_then(Value::as_str)
        .expect("next cursor")
        .to_string();
    let response = reqwest::get(format!(
        "http://{address}/api/history?repo=group%2Frepo&limit=1&after={next_cursor}"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let second_body: Value = response.json().await?;
    assert_eq!(
        second_body.get("has_previous").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        second_body.get("has_next").and_then(Value::as_bool),
        Some(true)
    );
    let second_runs = second_body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(second_runs.len(), 1);
    assert_eq!(
        second_runs[0].get("id").and_then(Value::as_i64),
        Some(run_ids[1])
    );
    Ok(())
}

#[tokio::test]
async fn history_page_renders_pagination_links_with_active_filters() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    for (iid, started_at) in [(51u64, 1_000i64), (52, 2_000)] {
        let run_id = insert_run_history(
            &state,
            NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            RunHistorySessionUpdate::default(),
            RunHistoryFinish {
                result: "commented".to_string(),
                preview: Some(format!("Review group/repo !{iid}")),
                summary: Some("findings".to_string()),
                ..Default::default()
            },
        )
        .await?;
        sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
            .bind(started_at)
            .bind(started_at)
            .bind(run_id)
            .execute(state.pool())
            .await?;
    }
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/history?repo=group%2Frepo&kind=review&q=findings&limit=1"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Showing up to 1 matching runs"));
    assert!(body.contains("pagination-link pagination-link-disabled\">Previous</span>"));
    assert!(body.contains(
        "/history?limit=1&amp;repo=group%2Frepo&amp;kind=review&amp;q=findings&amp;after="
    ));
    Ok(())
}

#[tokio::test]
async fn mr_history_page_lists_all_sessions_for_single_mr() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let first_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc111".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !7".to_string()),
            summary: Some("Posted findings".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let second_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc222".to_string(),
            discussion_id: Some("discussion-9".to_string()),
            trigger_note_id: Some(123),
            trigger_note_author_name: Some("maintainer".to_string()),
            trigger_note_body: Some("run codex fix".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "no_changes".to_string(),
            preview: Some("Mention group/repo !7 note 123".to_string()),
            summary: Some("No code changes required.".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 8,
            head_sha: "abc333".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "pass".to_string(),
            preview: Some("Review group/repo !8".to_string()),
            summary: Some("LGTM".to_string()),
            ..Default::default()
        },
    )
    .await?;

    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;
    let repo_key = super::view::encode_repo_key("group/repo");

    let response = reqwest::get(format!("http://{address}/mr/{repo_key}/7/history")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("group/repo !7 has 2 recorded session(s)."));
    assert!(body.contains(&format!("/history/{first_id}")));
    assert!(body.contains(&format!("/history/{second_id}")));
    assert!(!body.contains("Review group/repo !8"));
    Ok(())
}

#[tokio::test]
async fn run_detail_page_renders_trigger_note_and_thread_preview() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: Some("discussion-7".to_string()),
            trigger_note_id: Some(321),
            trigger_note_author_name: Some("qa<script>".to_string()),
            trigger_note_body: Some("please fix <broken> command".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7 note 321".to_string()),
            summary: Some("Implemented requested fix".to_string()),
            commit_sha: Some("deadbeef".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-11T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    let finished_at = DateTime::parse_from_rfc3339("2026-03-11T12:05:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query(
        "UPDATE run_history SET started_at = ?, finished_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(started_at)
    .bind(finished_at)
    .bind(finished_at)
    .bind(run_id)
    .execute(state.pool())
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:00Z",
                    "type": "userMessage",
                    "content": [{ "type": "text", "text": "Please inspect the failing job." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:05Z",
                    "type": "reasoning",
                    "summary": ["Need to inspect CI output"],
                    "content": ["The failure looks deterministic."]
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:06Z",
                    "type": "reasoning",
                    "summary": [
                        { "type": "summary_text", "text": "Typed reasoning summary" }
                    ],
                    "content": [
                        { "type": "reasoning_text", "text": "Typed reasoning detail." }
                    ]
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:07Z",
                    "type": "reasoning",
                    "summary": [],
                    "content": null,
                    "encrypted_content": "opaque-reasoning-blob"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "cwd": "/workdir",
                    "status": "completed",
                    "exitCode": 0,
                    "durationMs": 1200,
                    "aggregatedOutput": "all tests passed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "mcpToolCall",
                    "server": "gitlab",
                    "tool": "get_merge_request",
                    "arguments": { "iid": 7, "include": "changes" },
                    "status": "completed",
                    "durationMs": 50,
                    "result": { "iid": 7 }
                }),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "dynamicToolCall",
                    "tool": "resolve_release_note_template",
                    "status": "completed",
                    "durationMs": 18,
                    "contentItems": [{"type": "inputText", "text": "Use the customer-facing changelog template."}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "webSearch",
                    "query": "ci retry strategy",
                    "action": { "type": "search", "query": "ci retry strategy" }
                }),
            },
            NewRunHistoryEvent {
                sequence: 10,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "src/main.rs": {
                            "type": "update",
                            "unified_diff": "@@ -1,7 +1,8 @@\n---- banner\n--- docs/readme\n-old line\n+new line\n+--- frontmatter\n+++ heading\n+++ /tmp/cache\n unchanged\n"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 11,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "AgentMessage",
                    "phase": "final",
                    "content": [{ "type": "Text", "text": "Implemented the requested fix." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 12,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Trigger note"));
    assert!(body.contains("qa&lt;script&gt;"));
    assert!(body.contains("please fix &lt;broken&gt; command"));
    assert!(body.contains("Session transcript"));
    assert!(body.contains("transcript-panel"));
    assert!(body.contains("transcript-stream"));
    assert!(body.contains("message-entry"));
    assert!(body.contains("message-timestamp"));
    assert!(body.contains("class=\"localized-timestamp message-timestamp\""));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:54:00Z\""));
    assert!(body.contains("Mar 11, 2026, 12:54 PM UTC"));
    assert!(body.contains("reasoning-entry"));
    assert!(body.contains("terminal-entry"));
    assert!(body.contains("mcp-entry"));
    assert!(body.contains("dynamic-tool-entry"));
    assert!(body.contains("<summary class=\"entry-summary reasoning-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary tool-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary web-search-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary file-change-summary\">"));
    assert!(!body.contains("<summary class=\"entry-summary reasoning-summary\"><div"));
    assert!(body.contains("tool-preview-box"));
    assert!(body.contains("web-search-entry"));
    assert!(body.contains("diff-view"));
    assert!(body.contains("1.2 s"));
    assert!(body.contains("50 ms"));
    assert!(!body.contains("turn-label\">Turn</p>"));
    assert!(body.contains(">src/main.rs</span>"));
    assert!(body.contains("diff-stats-add\">+4</span>"));
    assert!(body.contains("diff-stats-remove\">-3</span>"));
    assert!(body.contains("Reasoning"));
    assert!(body.contains("Need to inspect CI output"));
    assert!(body.contains("The failure looks deterministic."));
    assert!(body.contains("Typed reasoning summary"));
    assert!(body.contains("Typed reasoning detail."));
    assert!(body.contains(
        "Reasoning is unavailable because Codex returned only encrypted history for this step."
    ));
    assert!(body.contains("cargo test"));
    assert!(body.contains("gitlab:get_merge_request"));
    assert!(body.contains("Arguments"));
    assert!(body.contains("&quot;include&quot;: &quot;changes&quot;"));
    assert!(body.contains("Result"));
    assert!(body.contains("resolve_release_note_template"));
    assert!(body.contains("Use the customer-facing changelog template."));
    assert!(body.contains("ci retry strategy"));
    assert!(body.contains("diff-line-add"));
    assert!(body.contains("diff-line-remove"));
    assert!(body.contains("diff-line-add\">+--- frontmatter</div>"));
    assert!(body.contains("diff-line-add\">+++ heading</div>"));
    assert!(body.contains("diff-line-add\">+++ /tmp/cache</div>"));
    assert!(body.contains("diff-line-remove\">---- banner</div>"));
    assert!(body.contains("diff-line-remove\">--- docs/readme</div>"));
    assert!(body.contains("Implemented the requested fix."));
    assert!(body.contains("Please inspect the failing job."));
    Ok(())
}

#[tokio::test]
async fn run_detail_uses_review_thread_id_in_metadata_when_events_exist() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 9,
            head_sha: "abc777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-base".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: Some("thread-review".to_string()),
            auth_account_name: Some("primary".to_string()),
            security_context_source_run_id: None,
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !9".to_string()),
            summary: Some("Posted findings".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-11T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    let finished_at = DateTime::parse_from_rfc3339("2026-03-11T12:05:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query(
        "UPDATE run_history SET started_at = ?, finished_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(started_at)
    .bind(finished_at)
    .bind(finished_at)
    .bind(run_id)
    .execute(state.pool())
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("meta-chip-label\">Thread</span><code>thread-review</code>"));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:00:00Z\""));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:05:00Z\""));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_dynamic_tool_results_and_failed_command_status() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "deadbeef".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-21".to_string()),
            turn_id: Some("turn-21".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !21".to_string()),
            summary: Some("Check dynamic tool result and failed command styling".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-21".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-21".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "dynamicToolCall",
                    "tool": "resolve_release_note_template",
                    "status": "completed",
                    "durationMs": 18,
                    "result": { "template": "customer-facing" }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-21".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "status": "completed",
                    "exitCode": 1,
                    "durationMs": 250,
                    "aggregatedOutput": "1 test failed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-21".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("resolve_release_note_template"));
    assert!(body.contains("customer-facing"));
    assert!(body.contains("Result"));
    assert!(body.contains("status-pill status-danger\">failed</span>"));
    assert!(body.contains("1 test failed"));
    assert!(!body.contains("<span class=\"message-timestamp\">"));
    Ok(())
}

#[tokio::test]
async fn run_detail_formats_numeric_millisecond_timestamps_as_utc() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 24,
            head_sha: "cafebabe".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-24".to_string()),
            turn_id: Some("turn-24".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !24".to_string()),
            summary: Some("Format millisecond timestamps".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-24".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-24".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "userMessage",
                    "createdAt": 1773233640000i64,
                    "content": [{ "type": "text", "text": "Check timestamp formatting." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-24".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("data-timestamp=\"2026-03-11T12:54:00Z\""));
    assert!(body.contains("Mar 11, 2026, 12:54 PM UTC"));
    assert!(!body.contains("1773233640000"));
    Ok(())
}

#[tokio::test]
async fn run_detail_page_falls_back_when_event_history_is_missing() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: Some("discussion-7".to_string()),
            trigger_note_id: Some(321),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("please fix command".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7 note 321".to_string()),
            summary: Some("Implemented requested fix".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Run metadata"));
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_non_diff_file_change_payload_as_plain_body() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "beadfeed".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-22".to_string()),
            turn_id: Some("turn-22".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !22".to_string()),
            summary: Some("Show file change payload without unified diff".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-22".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-22".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "README.md": {
                            "type": "rename",
                            "previous_path": "README-old.md"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-22".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("README.md"));
    assert!(body.contains("&quot;type&quot;: &quot;rename&quot;"));
    assert!(!body.contains("meta-pill preview-pill\">diff</span>"));
    assert!(!body.contains("<div class=\"diff-view\">"));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_mixed_file_change_payloads_with_diff_sections() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feedbead".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-23".to_string()),
            turn_id: Some("turn-23".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Show mixed file changes".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-23".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-23".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "src/lib.rs": {
                            "type": "update",
                            "unified_diff": "@@ -1 +1 @@\n-old\n+new\n"
                        },
                        "README.md": {
                            "type": "rename",
                            "previous_path": "README-old.md"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-23".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains(">2 files changed</span>"));
    assert!(body.contains("diff-stats-add\">+1</span>"));
    assert!(body.contains("diff-stats-remove\">-1</span>"));
    assert!(body.contains("meta-pill preview-pill\">diff</span>"));
    assert!(body.contains("file-change-section-path\"><code>src/lib.rs</code>"));
    assert!(body.contains("file-change-section-path\"><code>README.md</code>"));
    assert!(body.contains("diff-line-add\">+new</div>"));
    assert!(body.contains("&quot;previous_path&quot;: &quot;README-old.md&quot;"));
    Ok(())
}

#[derive(Clone)]
struct ThreadReaderRunner {
    response: Value,
}

#[async_trait]
impl CodexRunner for ThreadReaderRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        unreachable!("run_review is not used in status tests")
    }

    async fn read_thread(&self, _account_name: &str, _thread_id: &str) -> Result<Value> {
        Ok(self.response.clone())
    }
}

#[tokio::test]
async fn run_detail_page_shows_unavailable_transcript_for_legacy_runs() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "feed123".to_string(),
            discussion_id: Some("discussion-11".to_string()),
            trigger_note_id: Some(777),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("please inspect the legacy thread".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-legacy".to_string()),
            turn_id: Some("turn-legacy".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !11 legacy thread".to_string()),
            summary: Some("Used legacy thread replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-legacy",
                "preview": "Legacy thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-legacy",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Legacy history still renders."
                    }]
                }]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    assert!(!body.contains("Legacy history still renders."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_partial_persisted_history_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "feed456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-live".to_string()),
            turn_id: Some("turn-live".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !12".to_string()),
            summary: Some("Used complete live thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-live".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        }],
    )
    .await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-live",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [
                    {
                        "id": "turn-live",
                        "status": "completed",
                        "items": [{
                            "type": "agentMessage",
                            "text": "Complete live thread history."
                        }]
                    },
                    {
                        "id": "turn-follow-up",
                        "status": "completed",
                        "items": [{
                            "type": "agentMessage",
                            "text": "Follow-up turn from live replay."
                        }]
                    }
                ]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Complete live thread history."));
    assert!(!body.contains("Follow-up turn from live replay."));
    Ok(())
}

#[tokio::test]
async fn run_detail_prefers_complete_persisted_event_history() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 13,
            head_sha: "feed789".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-persisted".to_string()),
            turn_id: Some("turn-persisted".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !13".to_string()),
            summary: Some("Prefer persisted event history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Persisted transcript wins."
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-persisted",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-persisted",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Live replay should not replace persisted transcript."
                    }]
                }]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript wins."));
    assert!(!body.contains("Live replay should not replace persisted transcript."));
    Ok(())
}

#[tokio::test]
async fn run_detail_skips_live_thread_when_complete_persisted_history_exists() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 14,
            head_sha: "feedabc".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-richer".to_string()),
            turn_id: Some("turn-richer".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !14".to_string()),
            summary: Some("Prefer richer live transcript".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-richer".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-richer".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Persisted transcript item."
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-richer".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript item."));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_incomplete_persisted_history_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 15,
            head_sha: "feeddef".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-incomplete".to_string()),
            turn_id: Some("turn-incomplete".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !15".to_string()),
            summary: Some("Use live replay after persistence failure".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-incomplete".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-incomplete".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-incomplete",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-incomplete",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Recovered from live replay."
                    }]
                }]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered from live replay."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_completed_turn_without_items_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 16,
            head_sha: "feed000".to_string(),
            discussion_id: Some("discussion-16".to_string()),
            trigger_note_id: Some(16),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("show delta-only completion".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-delta-only".to_string()),
            turn_id: Some("turn-delta-only".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !16".to_string()),
            summary: Some("Recover delta-only turn via live replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-delta-only".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-delta-only".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-delta-only",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-delta-only",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Recovered delta-only reply."
                    }]
                }]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered delta-only reply."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_command_without_body_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 17,
            head_sha: "feed111".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-command-body".to_string()),
            turn_id: Some("turn-command-body".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !17".to_string()),
            summary: Some("Recover command output from live replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "status": "completed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-command-body",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-command-body",
                    "status": "completed",
                    "items": [{
                        "type": "commandExecution",
                        "command": "cargo test",
                        "aggregatedOutput": "Recovered command output"
                    }]
                }]
            }
        }),
    });
    let status_service = Arc::new(StatusService::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("cargo test"));
    assert!(!body.contains("Recovered command output"));
    Ok(())
}

#[derive(Clone)]
struct CountingThreadReaderRunner {
    read_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CodexRunner for CountingThreadReaderRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        unreachable!("run_review is not used in status tests")
    }

    async fn read_thread(&self, _account_name: &str, _thread_id: &str) -> Result<Value> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({
            "thread": {
                "id": "unused",
                "preview": "unused",
                "status": "completed",
                "turns": []
            }
        }))
    }
}

#[derive(Clone)]
struct StaticTranscriptBackfillSource {
    events: Vec<NewRunHistoryEvent>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for StaticTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.events.clone()))
    }
}

#[derive(Clone)]
struct SequencedTranscriptBackfillSource {
    responses: Arc<Mutex<Vec<Option<Vec<NewRunHistoryEvent>>>>>,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for SequencedTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut responses = self
            .responses
            .lock()
            .expect("sequenced transcript responses mutex");
        if responses.len() > 1 {
            Ok(responses.remove(0))
        } else {
            Ok(responses.first().cloned().unwrap_or(None))
        }
    }
}

#[derive(Clone)]
struct CapturingTranscriptBackfillSource {
    events: Vec<NewRunHistoryEvent>,
    calls: Arc<AtomicUsize>,
    seen_thread_id: Arc<Mutex<Option<String>>>,
    seen_turn_id: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl TranscriptBackfillSource for CapturingTranscriptBackfillSource {
    async fn load_events(
        &self,
        thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .seen_thread_id
            .lock()
            .expect("capturing transcript thread id mutex") = Some(thread_id.to_string());
        *self
            .seen_turn_id
            .lock()
            .expect("capturing transcript turn id mutex") = turn_id.map(ToOwned::to_owned);
        Ok(Some(self.events.clone()))
    }
}

#[derive(Clone)]
struct TurnScopedFallbackTranscriptBackfillSource {
    turn_events: Option<Vec<NewRunHistoryEvent>>,
    full_thread_events: Vec<NewRunHistoryEvent>,
    seen_turn_ids: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl TranscriptBackfillSource for TurnScopedFallbackTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex")
            .push(turn_id.map(ToOwned::to_owned));
        Ok(match turn_id {
            Some(_) => self.turn_events.clone(),
            None => Some(self.full_thread_events.clone()),
        })
    }
}

#[derive(Clone)]
struct ErroringTranscriptBackfillSource {
    error: &'static str,
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for ErroringTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!(self.error);
    }
}

#[tokio::test]
async fn run_detail_queues_async_backfill_and_serves_rewritten_persisted_history() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 18,
            head_sha: "feed222".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-backfill".to_string()),
            turn_id: Some("turn-backfill".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !18".to_string()),
            summary: Some("Queue background transcript backfill".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(StaticTranscriptBackfillSource {
        events: vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "Recovered summary"}],
                    "content": [{"type": "reasoning_text", "text": "Recovered detail"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, Some(runner))
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);

    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after async backfill")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered summary"));
    assert!(body.contains("Recovered detail"));
    assert!(!body.contains("Transcript backfill is in progress"));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_transcript_backfill_preserves_all_turns_for_security_shared_thread() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 19,
            head_sha: "feed333".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-security".to_string()),
            turn_id: Some("turn-review".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "pass".to_string(),
            preview: Some("Security review group/repo !19".to_string()),
            summary: Some("Rebuild shared-thread security transcript".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let run = state
        .get_run_history(run_id)
        .await?
        .expect("run history should exist");
    let source = TurnScopedFallbackTranscriptBackfillSource {
        turn_events: Some(vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ]),
        full_thread_events: vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-threat".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-threat".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"focus_paths\":[]}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-threat".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
        seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
    };

    crate::http::status::run_transcript_backfill(&state, &source, &run, false).await?;

    let persisted_events = state.list_run_history_events(run_id).await?;
    let persisted_turn_ids = persisted_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        persisted_turn_ids,
        std::collections::HashSet::from(["turn-threat", "turn-review"])
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_replaces_child_only_persisted_review_turns() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 27,
            head_sha: "feedchild".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-wrapper".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !27".to_string()),
            summary: Some("Replace child-only persisted review turn".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after child-only backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_recovers_missing_parent_turn_from_full_thread_after_sanitize_empties_persisted_events()
-> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 127,
            head_sha: "feedsanitize".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-missing-parent-only-child".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !127".to_string()),
            summary: Some("Recover missing parent turn from full thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after sanitize-empty recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("sanitize-empty recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_drops_partial_stale_review_child_items_before_rewrite() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 28,
            head_sha: "feeddup".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-duplicate".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !28".to_string()),
            summary: Some("Drop partial stale child review items".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await?
            .contains("Transcript backfill is in progress")
    );

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after duplicate child backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_preserves_later_turns_while_removing_stale_review_child_turns()
-> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 29,
            head_sha: "feedlater".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-later".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !29".to_string()),
            summary: Some(
                "Preserve later turns while removing stale child review turns".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after later-turn preserving backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(body.contains("later legitimate turn"));
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.list_run_history_events(run_id).await?;
    assert!(persisted_events.iter().all(|event| {
        matches!(
            event.turn_id.as_deref(),
            Some("turn-parent") | Some("turn-later")
        )
    }));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_preserves_later_turns_when_parent_turn_was_missing() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 30,
            head_sha: "feedmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-missing-parent".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !30".to_string()),
            summary: Some("Preserve later turns when parent turn is missing".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.161Z"}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript",
                    "createdAt": "2026-03-11T21:32:37.162Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:37.163Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after missing-parent backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(body.contains("later legitimate turn"));
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("missing-parent fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_target_only_fallback_preserves_known_good_later_turns() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 31,
            head_sha: "feedtargetonly".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-target-only".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !31".to_string()),
            summary: Some("Preserve later turns during target-only fallback".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.161Z"}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript",
                    "createdAt": "2026-03-11T21:32:37.162Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:37.163Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after target-only fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(body.contains("later legitimate turn"));
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("target-only fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_recovers_missing_plain_target_turn_before_later_persisted_turns() -> Result<()>
{
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 34,
            head_sha: "feedplainmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-plain-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !34".to_string()),
            summary: Some("Recover plain missing target turn before later turns".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after plain missing-target recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let persisted_events = state.list_run_history_events(run_id).await?;
    let target_first_sequence = persisted_events
        .iter()
        .find(|event| event.turn_id.as_deref() == Some("turn-target"))
        .expect("target turn persisted")
        .sequence;
    let later_first_sequence = persisted_events
        .iter()
        .find(|event| event.turn_id.as_deref() == Some("turn-later"))
        .expect("later turn persisted")
        .sequence;
    assert!(target_first_sequence < later_first_sequence);
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("plain missing-target recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_empty_history_recovery_keeps_target_turn_scoped() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 32,
            head_sha: "feedempty".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !32".to_string()),
            summary: Some(
                "Recover only the target turn when persisted history is empty".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after empty-history recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("later legitimate turn"));
    let persisted_events = state.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("empty-history recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_empty_history_recovery_ignores_unrelated_pending_review_markers() -> Result<()>
{
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 33,
            head_sha: "feedemptyother".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty-other".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !33".to_string()),
            summary: Some(
                "Recover target turn even when another turn is still waiting for review child history"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"],
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after empty-history unrelated marker recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("Transcript backfill failed"));
    let persisted_events = state.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("empty-history unrelated marker recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_target_only_recovery_ignores_unrelated_missing_child_history() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 36,
            head_sha: "feedtargetothermissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-target-other-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !36".to_string()),
            summary: Some(
                "Recover missing target turn even when another persisted turn still waits on review child history"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "persisted unrelated turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Waiting on unrelated child",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after target-only unrelated-marker recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("persisted unrelated turn"));
    assert!(body.contains("recovered target turn"));
    assert!(!body.contains("Transcript backfill failed"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("target-only unrelated-marker recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_full_thread_recovery_replaces_recoverable_stale_turns_when_target_missing()
-> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 137,
            head_sha: "feedstaleoldertargetmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-older-target-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !137".to_string()),
            summary: Some(
                "Recover stale older review-wrapper turns from full-thread backfill when the current target turn is missing"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-old-child"]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-old-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Recovered older turn",
                                "reviewMissingChildTurnIds": ["turn-old-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Recovered current turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after stale full-thread recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Transcript backfill failed"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("stale full-thread recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_empty_history_target_only_recovery_waits_for_missing_review_sibling()
-> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 35,
            head_sha: "feedemptytargetreview".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty-target".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !35".to_string()),
            summary: Some(
                "Do not finalize target-only recovery while review sibling is missing".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "wrapper summary"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after empty target-only missing-child recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .get_run_history(run_id)
        .await?
        .context("run history row after empty target-only missing-child recovery")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("local session history is still being written")
    );
    assert!(state.list_run_history_events(run_id).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn run_detail_stale_missing_review_sibling_without_wrapper_fallback_stays_failed()
-> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 37,
            head_sha: "feedstalemissingsibling".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-missing-sibling".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !37".to_string()),
            summary: Some(
                "Do not accept stale missing review siblings when the wrapper has no renderable fallback"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after stale missing-sibling retry window")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .get_run_history(run_id)
        .await?
        .context("run history row after stale missing-sibling retry window")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("local session history remained incomplete after retry window")
    );
    assert!(state.list_run_history_events(run_id).await?.is_empty());
    Ok(())
}

#[tokio::test]
async fn run_detail_stale_missing_review_sibling_with_wrapper_fallback_recovers() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 38,
            head_sha: "feedstalewrapperfallback".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-wrapper-fallback".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !38".to_string()),
            summary: Some(
                "Recover stale missing review siblings when wrapper output is renderable"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Wrapper fallback summary",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Wrapper fallback summary",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after stale wrapper fallback recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let run = state
        .get_run_history(run_id)
        .await?
        .context("run history row after stale wrapper fallback recovery final state")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Complete
    );

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Wrapper fallback summary"));
    assert!(!body.contains("Transcript backfill failed"));
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_drops_multi_child_stale_turns_without_timestamps() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 31,
            head_sha: "feedmultichild".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-multi-child-missing-parent".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !31".to_string()),
            summary: Some("Drop multiple stale child turns without timestamps".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child one"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child two"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state.mark_run_history_events_incomplete(run_id).await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": [
                                    "turn-stale-child-one",
                                    "turn-stale-child-two"
                                ]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": [
                                    "turn-stale-child-one",
                                    "turn-stale-child-two"
                                ]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after multi-child missing-parent backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(body.contains("later legitimate turn"));
    assert!(!body.contains("stale child one"));
    assert!(!body.contains("stale child two"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("multi-child missing-parent fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_does_not_queue_backfill_for_active_runs() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 19,
            head_sha: "feed333".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .update_run_history_session(
            run_id,
            RunHistorySessionUpdate {
                thread_id: Some("thread-active".to_string()),
                turn_id: Some("turn-active".to_string()),
                review_thread_id: None,
                security_context_source_run_id: None,
                auth_account_name: Some("primary".to_string()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-active".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-active".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: Vec::new(),
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(!body.contains("Transcript backfill is in progress"));
    sleep(Duration::from_millis(20)).await;
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_stale_in_progress_backfill_after_restart() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 20,
            head_sha: "feed444".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-stale-backfill".to_string()),
            turn_id: Some("turn-stale-backfill".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !20".to_string()),
            summary: Some("Retry stale transcript backfill".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered after restart"}],
                            "content": [{"type": "reasoning_text", "text": "Backfill retried successfully"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after retry")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after restart"));
    assert!(body.contains("Backfill retried successfully"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_after_transient_missing_session_history() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "feed555".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-transient".to_string()),
            turn_id: Some("turn-transient".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !21".to_string()),
            summary: Some("Retry after transient session-history miss".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-transient".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-transient".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-transient".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            None,
            None,
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "Recovered after missing file"}],
                        "content": [{"type": "reasoning_text", "text": "Second attempt found session history"}]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                },
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if backfill_calls.load(Ordering::SeqCst) >= 1 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after transient miss")?
            .transcript_backfill_state
            == TranscriptBackfillState::Failed
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let run = state
        .get_run_history(run_id)
        .await?
        .context("run history row after transient miss")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("matching Codex session history was not found")
    );

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill failed"));

    sleep(Duration::from_millis(1100)).await;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after retry success")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after missing file"));
    assert!(body.contains("Second attempt found session history"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_after_partial_session_history_file() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 24,
            head_sha: "feed888".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-partial-file".to_string()),
            turn_id: Some("turn-partial-file".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !24".to_string()),
            summary: Some("Retry partial session-history file after cooldown".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": []
                    }),
                },
            ]),
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "Recovered after partial write"}],
                        "content": [{"type": "reasoning_text", "text": "Second parse saw the finished turn"}]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                },
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after partial file fallback")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after partial write"));
    assert!(body.contains("Second parse saw the finished turn"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn run_detail_marks_backfill_failed_when_other_turns_remain_incomplete() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "feed666".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-partial".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !22".to_string()),
            summary: Some("Do not mark partial multi-turn transcript complete".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                            "content": [{"type": "reasoning_text", "text": "Older turn still missing"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after partial multi-turn backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .get_run_history(run_id)
        .await?
        .context("run history row after failed partial backfill")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert!(!run.events_persisted_cleanly);

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(!body.contains("Recovered current turn"));
    assert!(body.contains("Transcript backfill failed"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_falls_back_to_full_thread_when_older_turn_missing() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feed777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-full-fallback".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Recover older turns from the full local thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 8,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Later turn should be ignored"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after full-thread fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Older turn detail"));
    assert!(body.contains("Recovered current turn"));
    assert!(body.contains("Current turn detail"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_full_thread_fallback_ignores_unrelated_pending_review_markers() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 123,
            head_sha: "feedignore".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-ignore-unrelated-pending".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !123".to_string()),
            summary: Some(
                "Ignore unrelated pending review markers during full-thread fallback".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 8,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Waiting on unrelated child",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 9,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after unrelated marker fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Waiting on unrelated child"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("ignore unrelated pending seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_uses_full_thread_fallback_when_turn_scoped_backfill_is_incomplete() -> Result<()>
{
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 124,
            head_sha: "feedfullthread".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-turn-incomplete-full-ready".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !124".to_string()),
            summary: Some(
                "Use full-thread fallback when turn-scoped backfill is incomplete".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Partial current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Missing turn completion"}]
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after incomplete-turn full-thread fallback")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Partial current turn"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("incomplete-turn full-thread fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_falls_back_to_full_thread_when_turn_lookup_is_missing() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 26,
            head_sha: "feedabc".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-missing-turn".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !26".to_string()),
            summary: Some(
                "Fallback to whole-thread session history when turn lookup is missing".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await?
            .contains("Transcript backfill is in progress")
    );

    for _ in 0..20 {
        let run = state
            .get_run_history(run_id)
            .await?
            .context("run history row after missing turn fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Later turn should be ignored"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_uses_base_thread_id_when_review_thread_differs() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 25,
            head_sha: "feed999".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-base".to_string()),
            turn_id: Some("turn-review".to_string()),
            review_thread_id: Some("thread-review".to_string()),
            auth_account_name: Some("primary".to_string()),
            security_context_source_run_id: None,
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !25".to_string()),
            summary: Some("Backfill should read base thread history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let seen_thread_id = Arc::new(Mutex::new(None));
    let seen_turn_id = Arc::new(Mutex::new(None));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(CapturingTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered"}],
                            "content": [{"type": "reasoning_text", "text": "Base thread history used"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
                seen_thread_id: Arc::clone(&seen_thread_id),
                seen_turn_id: Arc::clone(&seen_turn_id),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if backfill_calls.load(Ordering::SeqCst) >= 1 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    assert_eq!(
        seen_thread_id
            .lock()
            .expect("captured thread id mutex")
            .as_deref(),
        Some("thread-base")
    );
    assert_eq!(
        seen_turn_id
            .lock()
            .expect("captured turn id mutex")
            .as_deref(),
        Some("turn-review")
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_when_session_history_directory_appears_later() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feed777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-unavailable".to_string()),
            turn_id: Some("turn-unavailable".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Do not retry unavailable local session history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-unavailable".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-unavailable".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        StatusService::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(ErroringTranscriptBackfillSource {
                error: TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR,
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .get_run_history(run_id)
            .await?
            .context("run history row after unavailable backfill source")?
            .transcript_backfill_state
            == TranscriptBackfillState::Failed
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    sleep(Duration::from_millis(1100)).await;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));
    for _ in 0..20 {
        if backfill_calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn skills_page_renders_upload_form_and_installed_skill_list() -> Result<()> {
    let auth_home = TestAuthDir::new("http-skills-page");
    write_skill(
        auth_home.path(),
        "web-skill",
        "---\nname: web-skill\ndescription: Web skill\n---\n",
        &[("scripts/run.sh", b"echo web")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/skills")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Upload skill archive"));
    assert!(body.contains("name=\"archive\""));
    assert!(body.contains("web-skill"));
    assert!(body.contains("/skills/web-skill"));
    Ok(())
}

#[tokio::test]
async fn skill_preview_page_renders_account_status_and_delete_form() -> Result<()> {
    let primary = TestAuthDir::new("http-skill-preview-primary");
    let backup = TestAuthDir::new("http-skill-preview-backup");
    write_skill(
        primary.path(),
        "preview-skill",
        "---\nname: preview-skill\ndescription: Preview me\n---\n",
        &[("scripts/run.sh", b"echo primary")],
    )?;
    write_skill(
        backup.path(),
        "preview-skill",
        "---\nname: preview-skill\ndescription: Preview me\n---\n",
        &[("scripts/run.sh", b"echo primary")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = primary.path().display().to_string();
    config.codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: backup.path().display().to_string(),
    }];
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/skills/preview-skill")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Skill preview"));
    assert!(body.contains("preview-skill"));
    assert!(body.contains("primary"));
    assert!(body.contains("backup"));
    assert!(body.contains("/skills/preview-skill/delete"));
    Ok(())
}

#[tokio::test]
async fn upload_skill_endpoint_installs_into_primary_and_fallback_auth_homes() -> Result<()> {
    let primary = TestAuthDir::new("http-upload-primary");
    let backup = TestAuthDir::new("http-upload-backup");
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = primary.path().display().to_string();
    config.codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: backup.path().display().to_string(),
    }];
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(Arc::clone(&status_service))).await?;
    let archive = build_skill_zip(&[
        (
            "wrapped/web-skill/SKILL.md",
            b"---\nname: web-skill\ndescription: Upload me\n---\n",
        ),
        ("wrapped/web-skill/scripts/run.sh", b"echo upload\n"),
    ]);

    let client = test_client();
    let response = client
        .post(format!("http://{address}/skills/upload"))
        .multipart(multipart::Form::new().text("csrf_token", csrf_token).part(
            "archive",
            multipart::Part::bytes(archive).file_name("web-skill.zip"),
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(primary.path().join("skills/web-skill/SKILL.md").is_file());
    assert!(
        backup
            .path()
            .join("skills/web-skill/scripts/run.sh")
            .is_file()
    );
    Ok(())
}

#[tokio::test]
async fn upload_skill_endpoint_rejects_unsupported_archive_type() -> Result<()> {
    let auth_home = TestAuthDir::new("http-upload-invalid");
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client();

    let response = client
        .post(format!("http://{address}/skills/upload"))
        .multipart(multipart::Form::new().text("csrf_token", csrf_token).part(
            "archive",
            multipart::Part::bytes(b"not-an-archive".to_vec()).file_name("bad.rar"),
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn delete_skill_endpoint_requires_csrf_and_removes_skill() -> Result<()> {
    let auth_home = TestAuthDir::new("http-delete-primary");
    write_skill(
        auth_home.path(),
        "delete-skill",
        "---\nname: delete-skill\n---\n",
        &[("scripts/run.sh", b"echo delete")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(StatusService::new(config, state, false, None));
    let csrf_token = status_service.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(Arc::clone(&status_service))).await?;
    let client = test_client();

    let forbidden = client
        .post(format!("http://{address}/skills/delete-skill/delete"))
        .form(&[("csrf_token", "wrong")])
        .send()
        .await?;
    assert_eq!(forbidden.status(), StatusCode::BAD_REQUEST);
    assert!(auth_home.path().join("skills/delete-skill").exists());

    let deleted = client
        .post(format!("http://{address}/skills/delete-skill/delete"))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(!auth_home.path().join("skills/delete-skill").exists());
    Ok(())
}

struct TestAuthDir {
    path: PathBuf,
}

impl TestAuthDir {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "codex-gitlab-review-{prefix}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&path).expect("create auth dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestAuthDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn write_skill(
    auth_home: &Path,
    name: &str,
    markdown: &str,
    extra_files: &[(&str, &[u8])],
) -> Result<()> {
    let skill_root = auth_home.join("skills").join(name);
    fs::create_dir_all(&skill_root)?;
    fs::write(skill_root.join("SKILL.md"), markdown)?;
    for (path, contents) in extra_files {
        let full_path = skill_root.join(path);
        if let Some(parent) = full_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full_path, contents)?;
    }
    Ok(())
}

fn build_skill_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, bytes) in entries {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start skill zip entry");
        writer.write_all(bytes).expect("write skill zip entry");
    }
    writer.finish().expect("finish skill zip").into_inner()
}

fn test_config() -> Config {
    Config {
        feature_flags: crate::feature_flags::FeatureFlagDefaults::default(),
        gitlab: GitLabConfig {
            base_url: "https://gitlab.example.com".to_string(),
            token: String::new(),
            bot_user_id: Some(123),
            created_after: None,
            targets: GitLabTargets {
                repos: TargetSelector::List(vec!["group/repo".to_string()]),
                groups: TargetSelector::List(vec![]),
                exclude_repos: vec![],
                exclude_groups: vec![],
                refresh_seconds: 3600,
            },
        },
        schedule: ScheduleConfig {
            cron: "0 */10 * * * *".to_string(),
            timezone: Some("UTC".to_string()),
        },
        review: ReviewConfig {
            max_concurrent: 2,
            eyes_emoji: "eyes".to_string(),
            thumbs_emoji: "thumbsup".to_string(),
            rate_limit_emoji: "hourglass_flowing_sand".to_string(),
            comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
            stale_in_progress_minutes: 120,
            dry_run: true,
            additional_developer_instructions: None,
            security: crate::config::ReviewSecurityConfig::default(),
            mention_commands: ReviewMentionCommandsConfig {
                enabled: true,
                bot_username: Some("codex".to_string()),
                eyes_emoji: None,
                additional_developer_instructions: None,
            },
        },
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 1800,
            auth_host_path: "/tmp/codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: vec![],
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: Default::default(),
            browser_mcp: BrowserMcpConfig::default(),
            gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            reasoning_effort: ReasoningEffortOverridesConfig::default(),
            reasoning_summary: ReasoningSummaryOverridesConfig::default(),
        },
        docker: DockerConfig {
            host: "unix:///var/run/docker.sock".to_string(),
        },
        database: DatabaseConfig {
            path: ":memory:".to_string(),
        },
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            status_ui_enabled: true,
        },
    }
}

async fn spawn_test_server(app: Router) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(10)).await;
    Ok(addr)
}

async fn insert_run_history(
    state: &ReviewStateStore,
    new_run: NewRunHistory,
    session: RunHistorySessionUpdate,
    finish: RunHistoryFinish,
) -> Result<i64> {
    let run_id = state.start_run_history(new_run).await?;
    if session != RunHistorySessionUpdate::default() {
        state.update_run_history_session(run_id, session).await?;
    }
    state.finish_run_history(run_id, finish).await?;
    Ok(run_id)
}

async fn insert_run_history_events(
    state: &ReviewStateStore,
    run_id: i64,
    events: Vec<NewRunHistoryEvent>,
) -> Result<()> {
    state.append_run_history_events(run_id, &events).await
}

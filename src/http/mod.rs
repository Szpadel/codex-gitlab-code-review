mod status;
mod view;

use axum::{
    Json, Router,
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

pub use status::StatusService;
use view::render_status_page;

pub fn app_router(status_service: Arc<StatusService>) -> Router {
    let mut router = Router::new().route("/healthz", get(healthcheck));
    if status_service.status_ui_enabled() {
        router = router
            .route("/", get(status_page))
            .route("/status", get(status_page))
            .route("/api/status", get(status_json));
    }
    router.with_state(status_service)
}

pub async fn run_http_server(bind_addr: String, status_service: Arc<StatusService>) {
    match TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            if let Err(err) = axum::serve(listener, app_router(status_service)).await {
                error!(error = %err, "http server failed");
            }
        }
        Err(err) => {
            error!(error = %err, "failed to bind http server");
        }
    }
}

async fn healthcheck() -> &'static str {
    "OK"
}

async fn status_json(
    State(status_service): State<Arc<StatusService>>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    Ok(Json(status_service.snapshot().await?))
}

async fn status_page(
    State(status_service): State<Arc<StatusService>>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = status_service.snapshot().await?;
    Ok(Html(render_status_page(&snapshot)))
}

#[derive(Debug)]
struct StatusHandlerError(anyhow::Error);

impl From<anyhow::Error> for StatusHandlerError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

impl IntoResponse for StatusHandlerError {
    fn into_response(self) -> axum::response::Response {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("status endpoint error: {}", self.0),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabTargets, McpServerOverridesConfig, ReasoningEffortOverridesConfig, ReviewConfig,
        ReviewMentionCommandsConfig, ScheduleConfig, ServerConfig, TargetSelector,
    };
    use crate::state::{PersistedScanStatus, ReviewStateStore, ScanMode, ScanOutcome, ScanState};
    use anyhow::Result;
    use chrono::{DateTime, Utc};
    use reqwest::StatusCode;
    use std::sync::Arc;
    use tokio::time::{Duration, sleep};

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

        let status_service = Arc::new(StatusService::new(test_config(), Arc::clone(&state), false));
        let address = spawn_test_server(app_router(status_service)).await?;

        let response = reqwest::get(format!("http://{address}/api/status")).await?;
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

        let status_service = Arc::new(StatusService::new(test_config(), Arc::clone(&state), false));
        let address = spawn_test_server(app_router(status_service)).await?;

        let response = reqwest::get(format!("http://{address}/status")).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await?;
        assert!(body.contains("Service status"));
        assert!(body.contains("In-progress reviews"));
        assert!(body.contains("Auth fallback cooldowns"));
        assert!(body.contains("group/&lt;repo&gt;"));
        assert!(body.contains("primary&lt;script&gt;"));
        assert!(!body.contains("primary<script>"));
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

        let status_service = StatusService::new(test_config(), state, false);
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

        let status_service = StatusService::new(test_config(), state, false);
        let snapshot = status_service.snapshot().await?;

        assert_eq!(snapshot.scan.scan_state, "idle".to_string());
        assert_eq!(snapshot.scan.mode, None);
        Ok(())
    }

    #[tokio::test]
    async fn status_service_scan_updates_roundtrip() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let status_service = StatusService::new(test_config(), Arc::clone(&state), false);

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
        let status_service = Arc::new(StatusService::new(config, state, false));
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
        let status_service = StatusService::new(test_config(), Arc::clone(&state), false);

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
        Ok(())
    }

    fn test_config() -> Config {
        Config {
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
                comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                stale_in_progress_minutes: 120,
                dry_run: true,
                additional_developer_instructions: None,
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
                exec_sandbox: "danger-full-access".to_string(),
                fallback_auth_accounts: vec![],
                usage_limit_fallback_cooldown_seconds: 3600,
                deps: Default::default(),
                browser_mcp: BrowserMcpConfig::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                reasoning_effort: ReasoningEffortOverridesConfig::default(),
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
}

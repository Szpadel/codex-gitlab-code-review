mod status;
mod view;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{Html, IntoResponse},
    routing::get,
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

pub use status::StatusService;
use view::{
    render_history_page, render_mr_history_page, render_run_detail_page, render_status_page,
};

pub fn app_router(status_service: Arc<StatusService>) -> Router {
    let mut router = Router::new().route("/healthz", get(healthcheck));
    if status_service.status_ui_enabled() {
        // The status UI is expected to sit behind the same trusted auth proxy for
        // both operational status and historical session data when enabled.
        router = router
            .route("/", get(status_page))
            .route("/status", get(status_page))
            .route("/history", get(history_page))
            .route("/history/{run_id}", get(run_detail_page))
            .route("/mr/{repo_key}/{iid}/history", get(mr_history_page))
            .route("/api/status", get(status_json))
            .route("/api/history", get(history_json))
            .route("/api/history/{run_id}", get(run_detail_json))
            .route("/api/mr/{repo_key}/{iid}/history", get(mr_history_json));
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

async fn history_json(
    State(status_service): State<Arc<StatusService>>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = status_service
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Json(snapshot))
}

async fn history_page(
    State(status_service): State<Arc<StatusService>>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = status_service
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Html(render_history_page(&snapshot)))
}

async fn mr_history_json(
    State(status_service): State<Arc<StatusService>>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    Ok(Json(status_service.mr_history_snapshot(&repo, iid).await?))
}

async fn mr_history_page(
    State(status_service): State<Arc<StatusService>>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    let snapshot = status_service.mr_history_snapshot(&repo, iid).await?;
    Ok(Html(render_mr_history_page(&snapshot)))
}

async fn run_detail_json(
    State(status_service): State<Arc<StatusService>>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = status_service.run_detail_snapshot(run_id).await? else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Json(snapshot))
}

async fn run_detail_page(
    State(status_service): State<Arc<StatusService>>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = status_service.run_detail_snapshot(run_id).await? else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Html(render_run_detail_page(&snapshot)))
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
        let message = self.0.to_string();
        let status = if message.contains("not found") {
            axum::http::StatusCode::NOT_FOUND
        } else if message.contains("invalid") {
            axum::http::StatusCode::BAD_REQUEST
        } else {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, format!("status endpoint error: {}", self.0)).into_response()
    }
}

#[derive(Debug, Default, Deserialize)]
struct HistoryQueryParams {
    repo: Option<String>,
    iid: Option<u64>,
    kind: Option<String>,
    result: Option<String>,
    q: Option<String>,
    limit: Option<usize>,
}

impl HistoryQueryParams {
    fn into_query(self) -> anyhow::Result<status::HistoryQuery> {
        Ok(status::HistoryQuery {
            repo: self.repo,
            iid: self.iid,
            kind: match self
                .kind
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                Some("all") => None,
                Some("review") => Some(crate::state::RunHistoryKind::Review),
                Some("mention") => Some(crate::state::RunHistoryKind::Mention),
                Some(other) => anyhow::bail!("invalid kind filter: {other}"),
                None => None,
            },
            result: self.result.filter(|value| !value.trim().is_empty()),
            search: self.q.filter(|value| !value.trim().is_empty()),
            limit: self.limit.unwrap_or(100),
        })
    }
}

fn decode_repo_key(repo_key: &str) -> anyhow::Result<String> {
    if repo_key.len() % 2 != 0 {
        anyhow::bail!("invalid repo key");
    }
    let mut bytes = Vec::with_capacity(repo_key.len() / 2);
    let chars = repo_key.as_bytes().chunks_exact(2);
    for chunk in chars {
        let hex = std::str::from_utf8(chunk)?;
        let value = u8::from_str_radix(hex, 16)?;
        bytes.push(value);
    }
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex_runner::{CodexResult, CodexRunner, ReviewContext};
    use crate::config::{
        BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabTargets, McpServerOverridesConfig, ReasoningEffortOverridesConfig, ReviewConfig,
        ReviewMentionCommandsConfig, ScheduleConfig, ServerConfig, TargetSelector,
    };
    use crate::state::{
        NewRunHistory, NewRunHistoryEvent, PersistedScanStatus, ReviewStateStore, RunHistoryFinish,
        RunHistoryKind, RunHistorySessionUpdate, ScanMode, ScanOutcome, ScanState,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use reqwest::StatusCode;
    use serde_json::{Value, json};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

        let status_service = Arc::new(StatusService::new(
            test_config(),
            Arc::clone(&state),
            false,
            None,
        ));
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

        let status_service = Arc::new(StatusService::new(
            test_config(),
            Arc::clone(&state),
            false,
            None,
        ));
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
    async fn history_snapshot_filters_runs_and_includes_trigger_message() -> Result<()> {
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
            runs[0].get("trigger_note_id").and_then(Value::as_u64),
            Some(99)
        );
        assert_eq!(
            runs[0].get("trigger_note_body").and_then(Value::as_str),
            Some("please inspect failing pipeline")
        );
        Ok(())
    }

    #[tokio::test]
    async fn history_page_renders_field_based_filters_layout() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let status_service = Arc::new(StatusService::new(
            test_config(),
            Arc::clone(&state),
            false,
            None,
        ));
        let address = spawn_test_server(app_router(status_service)).await?;

        let response = reqwest::get(format!(
            "http://{address}/history?repo=group%2Frepo&iid=7&kind=mention&q=note"
        ))
        .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.text().await?;
        assert!(body.contains("class=\"filter-field\""));
        assert!(body.contains("class=\"filter-field filter-field-wide\""));
        assert!(body.contains("class=\"filter-actions\""));
        assert!(body.contains("name=\"repo\" value=\"group/repo\""));
        assert!(body.contains("name=\"iid\" value=\"7\""));
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
        }
        .into_query()?;

        assert_eq!(query.kind, None);
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
                auth_account_name: Some("primary".to_string()),
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
                    sequence: 5,
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
                    sequence: 6,
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
                    sequence: 7,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "webSearch",
                        "query": "ci retry strategy",
                        "action": { "type": "search", "query": "ci retry strategy" }
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 8,
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
                    sequence: 9,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "AgentMessage",
                        "phase": "final",
                        "content": [{ "type": "Text", "text": "Implemented the requested fix." }]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 10,
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
        assert!(body.contains("12:54 PM UTC"));
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
            },
            RunHistoryFinish {
                result: "commented".to_string(),
                preview: Some("Review group/repo !9".to_string()),
                summary: Some("Posted findings".to_string()),
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
                auth_account_name: Some("primary".to_string()),
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("12:54 PM UTC"));
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
                auth_account_name: Some("primary".to_string()),
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
                auth_account_name: Some("primary".to_string()),
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
                auth_account_name: Some("primary".to_string()),
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
    async fn run_detail_page_falls_back_to_thread_reader_for_legacy_runs() -> Result<()> {
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("Legacy history still renders."));
        assert!(!body.contains("Codex thread detail is unavailable for this run."));
        Ok(())
    }

    #[tokio::test]
    async fn run_detail_prefers_thread_reader_when_event_history_is_partial() -> Result<()> {
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("Complete live thread history."));
        assert!(body.contains("Follow-up turn from live replay."));
        assert!(!body.contains("Codex thread detail is unavailable for this run."));
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
                auth_account_name: Some("primary".to_string()),
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
                auth_account_name: Some("primary".to_string()),
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
    async fn run_detail_uses_live_thread_when_event_persistence_is_marked_incomplete() -> Result<()>
    {
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("Recovered from live replay."));
        Ok(())
    }

    #[tokio::test]
    async fn run_detail_uses_live_thread_when_completed_persisted_turn_has_no_items() -> Result<()>
    {
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("Recovered delta-only reply."));
        Ok(())
    }

    #[tokio::test]
    async fn run_detail_uses_live_thread_when_persisted_command_has_no_body() -> Result<()> {
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
                auth_account_name: Some("primary".to_string()),
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
        assert!(body.contains("Recovered command output"));
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
}

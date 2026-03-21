mod status;
mod timestamp;
mod transcript;
mod view;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse},
    routing::{get, post},
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
        // The status UI is expected to sit behind an admin-only trusted auth
        // proxy when enabled. Server-side CSRF enforcement protects the
        // runtime feature-flag write path within that authenticated surface.
        router = router
            .route("/", get(status_page))
            .route("/status", get(status_page))
            .route("/history", get(history_page))
            .route("/history/{run_id}", get(run_detail_page))
            .route("/mr/{repo_key}/{iid}/history", get(mr_history_page))
            .route("/api/status", get(status_json))
            .route(
                "/api/feature-flags/{flag_name}",
                post(update_feature_flag_json),
            )
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
    Ok(Html(render_status_page(
        &snapshot,
        Some(status_service.feature_flag_csrf_token()),
    )))
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
    Ok(Html(render_history_page(
        &snapshot,
        Some(status_service.feature_flag_csrf_token()),
    )))
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
    Ok(Html(render_mr_history_page(
        &snapshot,
        Some(status_service.feature_flag_csrf_token()),
    )))
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
    Ok(Html(render_run_detail_page(
        &snapshot,
        Some(status_service.feature_flag_csrf_token()),
    )))
}

async fn update_feature_flag_json(
    State(status_service): State<Arc<StatusService>>,
    Path(flag_name): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FeatureFlagUpdateJson>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_feature_flag_csrf_header(&headers, status_service.feature_flag_csrf_token())?;
    Ok(Json(
        status_service
            .update_runtime_feature_flag(&flag_name, request.enabled)
            .await?,
    ))
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
    page: Option<usize>,
    after: Option<String>,
    before: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FeatureFlagUpdateJson {
    enabled: Option<bool>,
}

fn require_feature_flag_csrf_header(
    headers: &HeaderMap,
    expected_token: &str,
) -> anyhow::Result<()> {
    let matches_expected = headers
        .get("x-codex-status-csrf")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        anyhow::bail!("invalid feature flag csrf token")
    }
}

impl HistoryQueryParams {
    fn into_query(self) -> anyhow::Result<status::HistoryQuery> {
        if self.page.is_some() {
            anyhow::bail!("invalid history query: page-based pagination is no longer supported");
        }
        if self.after.is_some() && self.before.is_some() {
            anyhow::bail!("invalid history query: cannot include both after and before cursors");
        }
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
            after: self.after.filter(|value| !value.trim().is_empty()),
            before: self.before.filter(|value| !value.trim().is_empty()),
        })
    }
}

fn decode_repo_key(repo_key: &str) -> anyhow::Result<String> {
    if !repo_key.len().is_multiple_of(2) {
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
mod tests;

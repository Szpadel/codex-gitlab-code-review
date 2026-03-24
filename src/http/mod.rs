mod markdown;
mod status;
mod timestamp;
mod transcript;
mod view;

use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use serde::Deserialize;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

pub use status::StatusService;
use view::{
    render_history_page, render_mr_history_page, render_run_detail_page, render_skill_detail_page,
    render_skills_page, render_status_page,
};

const MAX_SKILL_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;

pub fn app_router(status_service: Arc<StatusService>) -> Router {
    let mut router = Router::new().route("/healthz", get(healthcheck));
    if status_service.status_ui_enabled() {
        let skill_upload_router = Router::new()
            .route("/skills/upload", post(upload_skill))
            .layer(DefaultBodyLimit::max(MAX_SKILL_ARCHIVE_BYTES));
        // The status UI is expected to sit behind an admin-only trusted auth
        // proxy when enabled. Server-side CSRF enforcement protects the
        // runtime feature-flag write path within that authenticated surface.
        router = router
            .merge(skill_upload_router)
            .route("/", get(status_page))
            .route("/status", get(status_page))
            .route("/history", get(history_page))
            .route("/history/{run_id}", get(run_detail_page))
            .route("/mr/{repo_key}/{iid}/history", get(mr_history_page))
            .route("/skills", get(skills_page))
            .route("/skills/{skill_name}", get(skill_detail_page))
            .route("/skills/{skill_name}/delete", post(delete_skill))
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
        status_service.gitlab_base_url(),
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

async fn skills_page(
    State(status_service): State<Arc<StatusService>>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = status_service.skills_snapshot().await?;
    Ok(Html(render_skills_page(
        &snapshot,
        Some(status_service.admin_csrf_token()),
    )))
}

async fn skill_detail_page(
    State(status_service): State<Arc<StatusService>>,
    Path(skill_name): Path<String>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = status_service.skill_preview_snapshot(&skill_name).await? else {
        return Err(StatusHandlerError(anyhow::anyhow!("skill not found")));
    };
    Ok(Html(render_skill_detail_page(
        &snapshot,
        Some(status_service.admin_csrf_token()),
    )))
}

async fn upload_skill(
    State(status_service): State<Arc<StatusService>>,
    mut multipart: Multipart,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let mut csrf_token = None;
    let mut archive_name = None;
    let mut archive_bytes = None;
    while let Some(field) = multipart.next_field().await.map_err(anyhow::Error::from)? {
        match field.name() {
            Some("csrf_token") => {
                csrf_token = Some(field.text().await.map_err(anyhow::Error::from)?)
            }
            Some("archive") => {
                archive_name = field.file_name().map(ToOwned::to_owned);
                archive_bytes = Some(field.bytes().await.map_err(anyhow::Error::from)?.to_vec());
            }
            _ => {}
        }
    }
    require_admin_csrf_form_token(csrf_token.as_deref(), status_service.admin_csrf_token())?;
    let archive_name = archive_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("upload.zip");
    let archive_bytes = archive_bytes
        .ok_or_else(|| anyhow::anyhow!("invalid skill archive: missing upload file"))?;
    let skill_name = status_service
        .install_skill_archive(archive_name, archive_bytes)
        .await?;
    Ok(Redirect::to(&format!(
        "/skills/{}",
        urlencoding::encode(&skill_name)
    )))
}

async fn delete_skill(
    State(status_service): State<Arc<StatusService>>,
    Path(skill_name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(Some(&form.csrf_token), status_service.admin_csrf_token())?;
    status_service.delete_skill(&skill_name).await?;
    Ok(Redirect::to("/skills"))
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
        } else if message.contains("already exists") {
            axum::http::StatusCode::CONFLICT
        } else if message.contains("unsupported archive type") {
            axum::http::StatusCode::BAD_REQUEST
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

#[derive(Debug, Deserialize)]
struct CsrfForm {
    csrf_token: String,
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

fn require_admin_csrf_form_token(
    actual_token: Option<&str>,
    expected_token: &str,
) -> anyhow::Result<()> {
    let matches_expected = actual_token.is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        anyhow::bail!("invalid csrf token")
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
                Some("security") => Some(crate::state::RunHistoryKind::Security),
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

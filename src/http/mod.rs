mod markdown;
mod status;
mod timestamp;
mod transcript;
mod view;

use crate::dev_mode::DevToolsService;
use crate::state::{
    ReviewRateLimitBucketMode, ReviewRateLimitRuleUpsert, ReviewRateLimitScope,
    ReviewRateLimitTarget,
};
use anyhow::Context;
use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Multipart, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
};
use serde::Deserialize;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

pub use status::StatusService;
use view::{
    render_development_page, render_history_page, render_mr_history_page, render_rate_limits_page,
    render_run_detail_page, render_skill_detail_page, render_skills_page, render_status_page,
};

const MAX_SKILL_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;

pub fn app_router(status_service: Arc<StatusService>) -> Router {
    app_router_with_dev_tools(status_service, None)
}

#[derive(Clone)]
pub struct HttpAppState {
    status_service: Arc<StatusService>,
    dev_tools_service: Option<Arc<DevToolsService>>,
}

impl HttpAppState {
    fn development_enabled(&self) -> bool {
        self.dev_tools_service.is_some()
    }
}

pub fn app_router_with_dev_tools(
    status_service: Arc<StatusService>,
    dev_tools_service: Option<Arc<DevToolsService>>,
) -> Router {
    let app_state = HttpAppState {
        status_service,
        dev_tools_service,
    };
    let mut router = Router::new().route("/healthz", get(healthcheck));
    if app_state.status_service.status_ui_enabled() {
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
            .route("/rate-limits", get(rate_limits_page))
            .route("/skills/{skill_name}", get(skill_detail_page))
            .route("/skills/{skill_name}/delete", post(delete_skill))
            .route("/rate-limits/create", post(create_rate_limit_rule))
            .route(
                "/rate-limits/{rule_id}/update",
                post(update_rate_limit_rule),
            )
            .route(
                "/rate-limits/{rule_id}/delete",
                post(delete_rate_limit_rule),
            )
            .route(
                "/rate-limits/buckets/regen",
                post(regen_rate_limit_bucket_slot),
            )
            .route("/api/status", get(status_json))
            .route(
                "/api/feature-flags/{flag_name}",
                post(update_feature_flag_json),
            )
            .route("/api/history", get(history_json))
            .route("/api/history/{run_id}", get(run_detail_json))
            .route("/api/mr/{repo_key}/{iid}/history", get(mr_history_json));
        if app_state.development_enabled() {
            router = router
                .route("/development", get(development_page))
                .route("/development/repos/create", post(create_development_repo))
                .route(
                    "/development/repos/{repo_key}/update",
                    post(update_development_repo),
                )
                .route(
                    "/development/repos/{repo_key}/delete",
                    post(delete_development_repo),
                )
                .route(
                    "/development/repos/{repo_key}/simulate-mr",
                    post(simulate_development_mr),
                )
                .route(
                    "/development/repos/{repo_key}/simulate-commit",
                    post(simulate_development_commit),
                );
        }
    }
    router.with_state(app_state)
}

pub async fn run_http_server(bind_addr: String, status_service: Arc<StatusService>) {
    run_http_server_with_dev_tools(bind_addr, status_service, None).await;
}

pub async fn run_http_server_with_dev_tools(
    bind_addr: String,
    status_service: Arc<StatusService>,
    dev_tools_service: Option<Arc<DevToolsService>>,
) {
    match TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            if let Err(err) = axum::serve(
                listener,
                app_router_with_dev_tools(status_service, dev_tools_service),
            )
            .await
            {
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
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    Ok(Json(app_state.status_service.snapshot().await?))
}

async fn status_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state.status_service.snapshot().await?;
    Ok(Html(render_status_page(
        &snapshot,
        Some(app_state.status_service.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn history_json(
    State(app_state): State<HttpAppState>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state
        .status_service
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Json(snapshot))
}

async fn history_page(
    State(app_state): State<HttpAppState>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state
        .status_service
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Html(render_history_page(
        &snapshot,
        Some(app_state.status_service.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn mr_history_json(
    State(app_state): State<HttpAppState>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    Ok(Json(
        app_state
            .status_service
            .mr_history_snapshot(&repo, iid)
            .await?,
    ))
}

async fn mr_history_page(
    State(app_state): State<HttpAppState>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    let snapshot = app_state
        .status_service
        .mr_history_snapshot(&repo, iid)
        .await?;
    Ok(Html(render_mr_history_page(
        &snapshot,
        Some(app_state.status_service.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn run_detail_json(
    State(app_state): State<HttpAppState>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state.status_service.run_detail_snapshot(run_id).await? else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Json(snapshot))
}

async fn run_detail_page(
    State(app_state): State<HttpAppState>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state.status_service.run_detail_snapshot(run_id).await? else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Html(render_run_detail_page(
        &snapshot,
        app_state.status_service.gitlab_base_url(),
        Some(app_state.status_service.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn update_feature_flag_json(
    State(app_state): State<HttpAppState>,
    Path(flag_name): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FeatureFlagUpdateJson>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_feature_flag_csrf_header(&headers, app_state.status_service.feature_flag_csrf_token())?;
    Ok(Json(
        app_state
            .status_service
            .update_runtime_feature_flag(&flag_name, request.enabled)
            .await?,
    ))
}

async fn skills_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state.status_service.skills_snapshot().await?;
    Ok(Html(render_skills_page(
        &snapshot,
        Some(app_state.status_service.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn skill_detail_page(
    State(app_state): State<HttpAppState>,
    Path(skill_name): Path<String>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state
        .status_service
        .skill_preview_snapshot(&skill_name)
        .await?
    else {
        return Err(StatusHandlerError(anyhow::anyhow!("skill not found")));
    };
    Ok(Html(render_skill_detail_page(
        &snapshot,
        Some(app_state.status_service.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn rate_limits_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state
        .status_service
        .review_rate_limit_snapshot()
        .await?;
    let mut target_suggestions = app_state
        .status_service
        .review_rate_limit_target_suggestions()
        .await?;
    if let Some(dev_tools) = &app_state.dev_tools_service {
        let dev_snapshot = dev_tools.snapshot().await;
        for repo in dev_snapshot.repos {
            target_suggestions.push(crate::state::ReviewRateLimitTarget {
                kind: crate::state::ReviewRateLimitTargetKind::Repo,
                path: repo.repo_path,
            });
        }
    }
    target_suggestions.sort_by(|left, right| {
        left.path.cmp(&right.path).then_with(|| {
            let left_kind = match left.kind {
                crate::state::ReviewRateLimitTargetKind::Repo => 0u8,
                crate::state::ReviewRateLimitTargetKind::Group => 1u8,
            };
            let right_kind = match right.kind {
                crate::state::ReviewRateLimitTargetKind::Repo => 0u8,
                crate::state::ReviewRateLimitTargetKind::Group => 1u8,
            };
            left_kind.cmp(&right_kind)
        })
    });
    target_suggestions.dedup_by(|left, right| left.kind == right.kind && left.path == right.path);
    Ok(Html(render_rate_limits_page(
        &snapshot,
        &target_suggestions,
        Some(app_state.status_service.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

async fn create_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Form(form): Form<RateLimitRuleForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let upsert = parse_rate_limit_rule_upsert(form)
        .with_context(|| "invalid create rate limit rule form")?;
    app_state
        .status_service
        .create_review_rate_limit_rule(&upsert)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

async fn update_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Path(rule_id): Path<String>,
    Form(form): Form<RateLimitRuleForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let mut upsert = parse_rate_limit_rule_upsert(form)
        .with_context(|| "invalid update rate limit rule form")?;
    upsert.id = Some(rule_id);
    app_state
        .status_service
        .update_review_rate_limit_rule(&upsert)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

async fn delete_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Path(rule_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    app_state
        .status_service
        .delete_review_rate_limit_rule(&rule_id)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

async fn regen_rate_limit_bucket_slot(
    State(app_state): State<HttpAppState>,
    Form(form): Form<CsrfBucketForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    app_state
        .status_service
        .refund_one_review_rate_limit_bucket_slot(&form.bucket_id)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

async fn upload_skill(
    State(app_state): State<HttpAppState>,
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
    require_admin_csrf_form_token(
        csrf_token.as_deref(),
        app_state.status_service.admin_csrf_token(),
    )?;
    let archive_name = archive_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("upload.zip");
    let archive_bytes = archive_bytes
        .ok_or_else(|| anyhow::anyhow!("invalid skill archive: missing upload file"))?;
    let skill_name = app_state
        .status_service
        .install_skill_archive(archive_name, archive_bytes)
        .await?;
    Ok(Redirect::to(&format!(
        "/skills/{}",
        urlencoding::encode(&skill_name)
    )))
}

async fn delete_skill(
    State(app_state): State<HttpAppState>,
    Path(skill_name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    app_state.status_service.delete_skill(&skill_name).await?;
    Ok(Redirect::to("/skills"))
}

async fn development_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let dev_tools = dev_tools_service(&app_state)?;
    let snapshot = dev_tools.snapshot().await;
    Ok(Html(render_development_page(
        &snapshot,
        Some(app_state.status_service.admin_csrf_token()),
    )))
}

async fn create_development_repo(
    State(app_state): State<HttpAppState>,
    Form(form): Form<DevelopmentRepoForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    dev_tools_service(&app_state)?
        .create_repo(&form.repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

async fn update_development_repo(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<DevelopmentRepoForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .update_repo(&repo_path, &form.repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

async fn delete_development_repo(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .delete_repo(&repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

async fn simulate_development_mr(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .simulate_new_mr(&repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

async fn simulate_development_commit(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.status_service.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .simulate_new_commit(&repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

fn dev_tools_service(app_state: &HttpAppState) -> anyhow::Result<Arc<DevToolsService>> {
    app_state
        .dev_tools_service
        .clone()
        .ok_or_else(|| anyhow::anyhow!("development tools not found"))
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
        } else if message.contains("unsupported archive type") || message.contains("invalid") {
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

#[derive(Debug, Deserialize)]
struct CsrfBucketForm {
    csrf_token: String,
    bucket_id: String,
}

#[derive(Debug, Deserialize)]
struct DevelopmentRepoForm {
    csrf_token: String,
    repo_path: String,
}

#[derive(Debug, Deserialize)]
struct RateLimitRuleForm {
    csrf_token: String,
    label: String,
    scope: String,
    targets_json: String,
    bucket_mode: String,
    applies_to_review: Option<bool>,
    applies_to_security: Option<bool>,
    capacity: u64,
    window_text: String,
}

fn parse_rate_limit_rule_upsert(
    form: RateLimitRuleForm,
) -> anyhow::Result<crate::state::ReviewRateLimitRuleUpsert> {
    let scope_input = form.scope.trim();
    let scope = ReviewRateLimitScope::from_str(scope_input)
        .with_context(|| format!("invalid scope: {scope_input}"))?;
    let capacity = u32::try_from(form.capacity).context("invalid capacity: must fit in u32")?;
    let targets = serde_json::from_str::<Vec<ReviewRateLimitTarget>>(&form.targets_json)
        .with_context(|| "invalid targets_json")?;
    let bucket_mode = ReviewRateLimitBucketMode::from_str(form.bucket_mode.trim())
        .with_context(|| format!("invalid bucket_mode: {}", form.bucket_mode.trim()))?;
    let window_seconds = parse_duration_text_to_seconds(&form.window_text)
        .with_context(|| format!("invalid window_text: {}", form.window_text.trim()))?;
    Ok(ReviewRateLimitRuleUpsert {
        id: None,
        label: form.label,
        targets,
        bucket_mode,
        scope_iid: None,
        applies_to_review: form.applies_to_review.unwrap_or(false),
        applies_to_security: form.applies_to_security.unwrap_or(false),
        scope,
        capacity,
        window_seconds,
    })
}

fn parse_duration_text_to_seconds(raw: &str) -> anyhow::Result<u64> {
    let mut chars = raw.trim().chars().peekable();
    let mut total = 0u64;
    let mut parsed_any = false;
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut value = String::new();
        while chars.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            value.push(chars.next().expect("peeked digit"));
        }
        if value.is_empty() {
            anyhow::bail!("duration must use value-unit pairs like `2h 15m`");
        }
        while chars.peek().is_some_and(|ch| ch.is_whitespace()) {
            chars.next();
        }
        let mut unit = String::new();
        while chars.peek().is_some_and(|ch| ch.is_ascii_alphabetic()) {
            unit.push(chars.next().expect("peeked unit"));
        }
        if unit.is_empty() {
            anyhow::bail!("duration must include a unit after each number");
        }
        let factor = match unit.as_str() {
            "h" | "hr" | "hrs" | "hour" | "hours" => 3600u64,
            "m" | "min" | "mins" | "minute" | "minutes" => 60u64,
            "s" | "sec" | "secs" | "second" | "seconds" => 1u64,
            _ => anyhow::bail!("unsupported duration unit: {unit}"),
        };
        let numeric = value
            .parse::<u64>()
            .with_context(|| format!("invalid duration value: {value}"))?;
        total = total
            .checked_add(numeric.saturating_mul(factor))
            .context("duration is too large")?;
        parsed_any = true;
    }
    if !parsed_any || total == 0 {
        anyhow::bail!("duration must be greater than zero");
    }
    Ok(total)
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

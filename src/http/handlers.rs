use super::HttpAppState;
use super::errors::{
    StatusHandlerError, require_admin_csrf_form_token, require_feature_flag_csrf_header,
};
use super::forms::{
    CsrfBucketForm, CsrfForm, DevelopmentRepoForm, FeatureFlagUpdateJson, HistoryQueryParams,
    RateLimitRuleForm, parse_rate_limit_rule_upsert,
};
use super::view::{
    render_development_page, render_history_page, render_mr_history_page, render_rate_limits_page,
    render_run_detail_page, render_skill_detail_page, render_skills_page, render_status_page,
};
use crate::dev_mode::DevToolsService;
use anyhow::Context;
use axum::{
    Form, Json,
    extract::{Multipart, Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect},
};
use std::sync::Arc;

pub(crate) async fn healthcheck() -> &'static str {
    "OK"
}

pub(crate) async fn status_json(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    Ok(Json(app_state.http_services.status.snapshot().await?))
}

pub(crate) async fn status_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state.http_services.status.snapshot().await?;
    Ok(Html(render_status_page(
        &snapshot,
        Some(app_state.http_services.admin.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn history_json(
    State(app_state): State<HttpAppState>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state
        .http_services
        .status
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Json(snapshot))
}

pub(crate) async fn history_page(
    State(app_state): State<HttpAppState>,
    Query(params): Query<HistoryQueryParams>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state
        .http_services
        .status
        .history_snapshot(params.into_query()?)
        .await?;
    Ok(Html(render_history_page(
        &snapshot,
        Some(app_state.http_services.admin.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn mr_history_json(
    State(app_state): State<HttpAppState>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    Ok(Json(
        app_state
            .http_services
            .status
            .mr_history_snapshot(&repo, iid)
            .await?,
    ))
}

pub(crate) async fn mr_history_page(
    State(app_state): State<HttpAppState>,
    Path((repo_key, iid)): Path<(String, u64)>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let repo = decode_repo_key(&repo_key)?;
    let snapshot = app_state
        .http_services
        .status
        .mr_history_snapshot(&repo, iid)
        .await?;
    Ok(Html(render_mr_history_page(
        &snapshot,
        Some(app_state.http_services.admin.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn run_detail_json(
    State(app_state): State<HttpAppState>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state
        .http_services
        .status
        .run_detail_snapshot(run_id)
        .await?
    else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Json(snapshot))
}

pub(crate) async fn run_detail_page(
    State(app_state): State<HttpAppState>,
    Path(run_id): Path<i64>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state
        .http_services
        .status
        .run_detail_snapshot(run_id)
        .await?
    else {
        return Err(StatusHandlerError(anyhow::anyhow!("run not found")));
    };
    Ok(Html(render_run_detail_page(
        &snapshot,
        app_state.http_services.status.gitlab_base_url(),
        Some(app_state.http_services.admin.feature_flag_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn update_feature_flag_json(
    State(app_state): State<HttpAppState>,
    Path(flag_name): Path<String>,
    headers: HeaderMap,
    Json(request): Json<FeatureFlagUpdateJson>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_feature_flag_csrf_header(
        &headers,
        app_state.http_services.admin.feature_flag_csrf_token(),
    )?;
    Ok(Json(
        app_state
            .http_services
            .admin
            .update_runtime_feature_flag(&flag_name, request.enabled)
            .await?,
    ))
}

pub(crate) async fn skills_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state.http_services.skills.snapshot().await?;
    Ok(Html(render_skills_page(
        &snapshot,
        Some(app_state.http_services.admin.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn skill_detail_page(
    State(app_state): State<HttpAppState>,
    Path(skill_name): Path<String>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let Some(snapshot) = app_state
        .http_services
        .skills
        .preview_snapshot(&skill_name)
        .await?
    else {
        return Err(StatusHandlerError(anyhow::anyhow!("skill not found")));
    };
    Ok(Html(render_skill_detail_page(
        &snapshot,
        Some(app_state.http_services.admin.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn rate_limits_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let snapshot = app_state.http_services.ratelimit.snapshot().await?;
    let mut target_suggestions = app_state
        .http_services
        .ratelimit
        .target_suggestions()
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
        Some(app_state.http_services.admin.admin_csrf_token()),
        app_state.development_enabled(),
    )))
}

pub(crate) async fn create_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Form(form): Form<RateLimitRuleForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let upsert = parse_rate_limit_rule_upsert(form)
        .with_context(|| "invalid create rate limit rule form")?;
    app_state
        .http_services
        .ratelimit
        .create_rule(&upsert)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

pub(crate) async fn update_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Path(rule_id): Path<String>,
    Form(form): Form<RateLimitRuleForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let mut upsert = parse_rate_limit_rule_upsert(form)
        .with_context(|| "invalid update rate limit rule form")?;
    upsert.id = Some(rule_id);
    app_state
        .http_services
        .ratelimit
        .update_rule(&upsert)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

pub(crate) async fn delete_rate_limit_rule(
    State(app_state): State<HttpAppState>,
    Path(rule_id): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    app_state
        .http_services
        .ratelimit
        .delete_rule(&rule_id)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

pub(crate) async fn regen_rate_limit_bucket_slot(
    State(app_state): State<HttpAppState>,
    Form(form): Form<CsrfBucketForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    app_state
        .http_services
        .ratelimit
        .refund_one_bucket_slot(&form.bucket_id)
        .await?;
    Ok(Redirect::to("/rate-limits"))
}

pub(crate) async fn upload_skill(
    State(app_state): State<HttpAppState>,
    mut multipart: Multipart,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let mut csrf_token = None;
    let mut archive_name = None;
    let mut archive_bytes = None;
    while let Some(field) = multipart.next_field().await.map_err(anyhow::Error::from)? {
        match field.name() {
            Some("csrf_token") => {
                csrf_token = Some(field.text().await.map_err(anyhow::Error::from)?);
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
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let archive_name = archive_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("upload.zip");
    let archive_bytes = archive_bytes
        .ok_or_else(|| anyhow::anyhow!("invalid skill archive: missing upload file"))?;
    let skill_name = app_state
        .http_services
        .skills
        .install_archive(archive_name, archive_bytes)
        .await?;
    Ok(Redirect::to(&format!(
        "/skills/{}",
        urlencoding::encode(&skill_name)
    )))
}

pub(crate) async fn delete_skill(
    State(app_state): State<HttpAppState>,
    Path(skill_name): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    app_state
        .http_services
        .skills
        .delete_skill(&skill_name)
        .await?;
    Ok(Redirect::to("/skills"))
}

pub(crate) async fn development_page(
    State(app_state): State<HttpAppState>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    let dev_tools = dev_tools_service(&app_state)?;
    let snapshot = dev_tools.snapshot().await;
    Ok(Html(render_development_page(
        &snapshot,
        Some(app_state.http_services.admin.admin_csrf_token()),
    )))
}

pub(crate) async fn create_development_repo(
    State(app_state): State<HttpAppState>,
    Form(form): Form<DevelopmentRepoForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    dev_tools_service(&app_state)?
        .create_repo(&form.repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

pub(crate) async fn update_development_repo(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<DevelopmentRepoForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .update_repo(&repo_path, &form.repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

pub(crate) async fn delete_development_repo(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .delete_repo(&repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

pub(crate) async fn simulate_development_mr(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
    )?;
    let repo_path = decode_repo_key(&repo_key)?;
    dev_tools_service(&app_state)?
        .simulate_new_mr(&repo_path)
        .await?;
    Ok(Redirect::to("/development"))
}

pub(crate) async fn simulate_development_commit(
    State(app_state): State<HttpAppState>,
    Path(repo_key): Path<String>,
    Form(form): Form<CsrfForm>,
) -> std::result::Result<impl IntoResponse, StatusHandlerError> {
    require_admin_csrf_form_token(
        Some(&form.csrf_token),
        app_state.http_services.admin.admin_csrf_token(),
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

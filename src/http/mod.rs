mod errors;
mod forms;
mod handlers;
mod markdown;
mod oidc;
mod status;
mod timestamp;
mod transcript;
mod view;

use crate::dev_mode::DevToolsService;
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use handlers::{
    apply_usage_limit_reset, create_development_repo, create_rate_limit_rule,
    delete_development_repo, delete_rate_limit_rule, delete_skill, development_page, healthcheck,
    history_json, history_page, mr_history_json, mr_history_page, rate_limits_page,
    regen_rate_limit_bucket_slot, run_detail_json, run_detail_page, simulate_development_commit,
    simulate_development_mr, skill_detail_page, skills_page, status_json, status_page,
    transcript_entry_body, update_development_repo, update_feature_flag_json,
    update_rate_limit_rule, upload_skill, usage_page,
};
pub use status::{
    AdminService, BackfillService, HistoryQuery, HistorySnapshot, HttpServices, MrHistorySnapshot,
    RateLimitService, RunDetailSnapshot, SecurityContextPreview, SkillsService, StatusService,
    TranscriptBackfillSource, UsageService,
};

const MAX_SKILL_ARCHIVE_BYTES: usize = 32 * 1024 * 1024;

#[cfg(test)]
pub(crate) use forms::{HistoryQueryParams, RateLimitRuleForm, parse_rate_limit_rule_upsert};

pub fn app_router(http_services: Arc<HttpServices>) -> Router {
    app_router_with_dev_tools(http_services, None)
}

#[derive(Clone)]
pub struct HttpAppState {
    http_services: Arc<HttpServices>,
    dev_tools_service: Option<Arc<DevToolsService>>,
}

impl HttpAppState {
    fn development_enabled(&self) -> bool {
        self.dev_tools_service.is_some()
    }

    fn navigation(&self) -> view::PageNavigation {
        view::PageNavigation {
            development_enabled: self.development_enabled(),
            oidc_enabled: self.http_services.oidc_config().is_some(),
        }
    }
}

pub fn app_router_with_dev_tools(
    http_services: Arc<HttpServices>,
    dev_tools_service: Option<Arc<DevToolsService>>,
) -> Router {
    let app_state = HttpAppState {
        http_services,
        dev_tools_service,
    };
    let mut router = Router::new();
    if app_state.http_services.admin.status_ui_enabled() {
        let skill_upload_router = Router::new()
            .route("/skills/upload", post(upload_skill))
            .layer(DefaultBodyLimit::max(MAX_SKILL_ARCHIVE_BYTES));
        // Apply one authentication boundary after all UI routes are registered.
        // Existing CSRF checks continue to protect authenticated writes.
        router = router
            .merge(skill_upload_router)
            .route("/", get(status_page))
            .route("/status", get(status_page))
            .route("/history", get(history_page))
            .route("/history/{run_id}", get(run_detail_page))
            .route("/mr/{repo_key}/{iid}/history", get(mr_history_page))
            .route("/skills", get(skills_page))
            .route("/usage", get(usage_page))
            .route("/usage/reset", post(apply_usage_limit_reset))
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
            .route(
                "/api/history/{run_id}/entries/{event_id}/body",
                get(transcript_entry_body),
            )
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
        if let Some(config) = app_state.http_services.oidc_config() {
            router = oidc::protect(router, config.clone());
        }
    }
    router
        .route("/healthz", get(healthcheck))
        .with_state(app_state)
}

/// Serves a bound listener until cancellation. Returns server errors.
pub async fn run_http_server_with_dev_tools(
    listener: TcpListener,
    http_services: Arc<HttpServices>,
    dev_tools_service: Option<Arc<DevToolsService>>,
    cancellation: CancellationToken,
) -> Result<()> {
    axum::serve(
        listener,
        app_router_with_dev_tools(http_services, dev_tools_service),
    )
    .with_graceful_shutdown(cancellation.cancelled_owned())
    .await
    .context("serve HTTP requests")
}

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod tests;

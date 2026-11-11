//! HTML rendering for the admin status UI.

mod development;
mod history;
mod html;
mod rate_limits;
mod run_detail;
mod skills;
mod status_page;
mod usage;

/// Selects navigation actions that the current HTTP runtime supports.
#[derive(Clone, Copy, Default)]
pub(super) struct PageNavigation {
    pub(super) development_enabled: bool,
    pub(super) oidc_enabled: bool,
}

pub(super) use html::escape_html;

pub(super) use development::render_development_page;
pub(super) use history::{render_history_page, render_mr_history_page};
pub(super) use rate_limits::render_rate_limits_page;
pub(super) use run_detail::render_run_detail_page;
pub(super) use skills::{render_skill_detail_page, render_skills_page};
pub(super) use status_page::render_status_page;
pub(super) use usage::render_usage_page;

#[cfg(test)]
pub(super) use html::encode_repo_key;

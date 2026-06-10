use super::super::status::{StatusFeatureFlagSnapshot, StatusSnapshot};
use super::html::{
    NavItem, bool_label, escape_html, mr_history_href, render_definition_list,
    render_rfc3339_timestamp, render_shell, render_table_section, render_unix_timestamp,
    target_label,
};
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, ProjectCatalogSummary,
};

pub(in crate::http) fn render_status_page(
    snapshot: &StatusSnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let scan = &snapshot.scan;
    let config = &snapshot.config;
    let scan_summary = vec![
        ("State".to_string(), escape_html(&scan.scan_state)),
        (
            "Mode".to_string(),
            escape_html(scan.mode.as_deref().unwrap_or("-")),
        ),
        (
            "Started".to_string(),
            render_rfc3339_timestamp(scan.started_at.as_deref()),
        ),
        (
            "Finished".to_string(),
            render_rfc3339_timestamp(scan.finished_at.as_deref()),
        ),
        (
            "Outcome".to_string(),
            escape_html(scan.outcome.as_deref().unwrap_or("-")),
        ),
        (
            "Error".to_string(),
            escape_html(scan.error.as_deref().unwrap_or("-")),
        ),
        (
            "Next scan".to_string(),
            render_rfc3339_timestamp(scan.next_scan_at.as_deref()),
        ),
    ];
    let config_summary = vec![
        ("Mode".to_string(), escape_html(&config.runtime_mode)),
        ("GitLab".to_string(), escape_html(&config.gitlab_base_url)),
        ("Database".to_string(), escape_html(&config.database_path)),
        ("Bind".to_string(), escape_html(&config.bind_addr)),
        (
            "Run once".to_string(),
            escape_html(bool_label(config.run_once)),
        ),
        (
            "Dry run".to_string(),
            escape_html(bool_label(config.dry_run)),
        ),
        (
            "Mention commands".to_string(),
            escape_html(bool_label(config.mention_commands_enabled)),
        ),
        (
            "Browser MCP".to_string(),
            escape_html(bool_label(config.browser_mcp_enabled)),
        ),
        (
            "GitLab Discovery MCP".to_string(),
            escape_html(bool_label(config.gitlab_discovery_mcp_configured)),
        ),
        (
            "Max concurrent".to_string(),
            escape_html(&config.max_concurrent.to_string()),
        ),
        ("Cron".to_string(), escape_html(&config.schedule_cron)),
        (
            "Timezone".to_string(),
            escape_html(&config.schedule_timezone),
        ),
        (
            "Created after".to_string(),
            render_rfc3339_timestamp(config.created_after.as_deref()),
        ),
        (
            "Repo targets".to_string(),
            escape_html(&target_label(config.repo_targets_all, config.repo_targets)),
        ),
        (
            "Group targets".to_string(),
            escape_html(&target_label(
                config.group_targets_all,
                config.group_targets,
            )),
        ),
    ];
    let body = format!(
        "<section class=\"hero\"><h1>Service status</h1><p class=\"muted\">Generated {}</p></section>\
         <section class=\"grid\">\
         <article class=\"card\"><h2>Scan</h2><dl>{}</dl></article>\
         <article class=\"card\"><h2>Configuration</h2><dl>{}</dl></article>\
         </section>\
         {}{}{}{}{}",
        render_rfc3339_timestamp(Some(&snapshot.generated_at)),
        render_definition_list(&scan_summary),
        render_definition_list(&config_summary),
        render_feature_flags_section(&config.feature_flags),
        render_reviews_section(&snapshot.in_progress_reviews),
        render_mentions_section(&snapshot.in_progress_mentions),
        render_auth_section(&snapshot.auth_limit_resets),
        render_catalog_section(&snapshot.project_catalogs),
    );
    render_shell(
        "Status",
        NavItem::Status,
        body,
        csrf_token,
        development_enabled,
    )
}

fn render_reviews_section(reviews: &[InProgressReview]) -> String {
    render_table_section(
        "In-progress reviews",
        if reviews.is_empty() {
            "<p class=\"empty\">No in-progress reviews.</p>".to_string()
        } else {
            let rows = reviews
                .iter()
                .map(|review| {
                    format!(
                        "<tr><td>{}</td><td><a href=\"{}\">!{}</a></td><td><code>{}</code></td></tr>",
                        escape_html(&review.repo),
                        mr_history_href(&review.repo, review.iid),
                        review.iid,
                        escape_html(&review.head_sha)
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Repo</th><th>MR</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_mentions_section(mentions: &[InProgressMentionCommand]) -> String {
    render_table_section(
        "In-progress mention commands",
        if mentions.is_empty() {
            "<p class=\"empty\">No in-progress mention commands.</p>".to_string()
        } else {
            let rows = mentions
                .iter()
                .map(|mention| {
                    format!(
                        "<tr><td>{}</td><td><a href=\"{}\">!{}</a></td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                        escape_html(&mention.key.repo),
                        mr_history_href(&mention.key.repo, mention.key.iid),
                        mention.key.iid,
                        escape_html(&mention.key.discussion_id),
                        mention.key.trigger_note_id,
                        escape_html(&mention.head_sha)
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Repo</th><th>MR</th><th>Discussion</th><th>Trigger note</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_auth_section(entries: &[AuthLimitResetEntry]) -> String {
    render_table_section(
        "Auth fallback cooldowns",
        if entries.is_empty() {
            "<p class=\"empty\">No auth cooldowns are currently tracked.</p>".to_string()
        } else {
            let rows = entries
                .iter()
                .map(|entry| {
                    format!(
                        "<tr><td>{}</td><td>{}</td></tr>",
                        escape_html(&entry.account_name),
                        render_rfc3339_timestamp(Some(&entry.reset_at))
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Account</th><th>Reset at</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_catalog_section(catalogs: &[ProjectCatalogSummary]) -> String {
    render_table_section(
        "Project catalog cache",
        if catalogs.is_empty() {
            "<p class=\"empty\">No cached project catalogs.</p>".to_string()
        } else {
            let rows = catalogs
                .iter()
                .map(|catalog| {
                    format!(
                        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                        escape_html(&catalog.cache_key),
                        catalog.project_count,
                        render_unix_timestamp(catalog.fetched_at)
                    )
                })
                .collect::<String>();
            format!(
                "<table><thead><tr><th>Cache key</th><th>Projects</th><th>Fetched at</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_feature_flags_section(flags: &[StatusFeatureFlagSnapshot]) -> String {
    render_table_section(
        "Feature flags",
        if flags.is_empty() {
            "<p class=\"empty\">No runtime feature flags are registered.</p>".to_string()
        } else {
            let rows = flags
                .iter()
                .map(|flag| {
                    let runtime_override = match flag.runtime_override {
                        Some(value) => bool_label(value),
                        None => "default",
                    };
                    format!(
                        "<tr>\
                         <td><code>{}</code></td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         <td>{}</td>\
                         </tr>",
                        escape_html(&flag.name),
                        escape_html(bool_label(flag.available)),
                        escape_html(bool_label(flag.default_enabled)),
                        escape_html(runtime_override),
                        escape_html(bool_label(flag.effective_enabled)),
                        render_feature_flag_controls(flag),
                    )
                })
                .collect::<String>();
            format!(
                "<p class=\"muted\">Runtime changes apply only to newly started runs.</p>\
                 <table><thead><tr><th>Flag</th><th>Available</th><th>Default</th><th>Runtime override</th><th>Effective</th><th>Controls</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_feature_flag_controls(flag: &StatusFeatureFlagSnapshot) -> String {
    if !flag.available {
        return "<span class=\"muted\">Unavailable</span>".to_string();
    }
    [
        ("true", "Enable"),
        ("false", "Disable"),
        ("default", "Default"),
    ]
    .into_iter()
    .map(|(value, label)| {
        format!(
            "<button type=\"button\" data-feature-flag=\"{name}\" data-feature-flag-value=\"{value}\" style=\"margin-right:0.4rem;\">{label}</button>",
            name = escape_html(&flag.name),
            value = value,
            label = label,
        )
    })
    .collect::<String>()
}

use super::status::StatusSnapshot;
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, ProjectCatalogSummary,
};

pub(super) fn render_status_page(snapshot: &StatusSnapshot) -> String {
    let scan = &snapshot.scan;
    let config = &snapshot.config;
    let scan_summary = vec![
        ("State".to_string(), scan.scan_state.clone()),
        (
            "Mode".to_string(),
            scan.mode.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Started".to_string(),
            scan.started_at.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Finished".to_string(),
            scan.finished_at.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Outcome".to_string(),
            scan.outcome.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Error".to_string(),
            scan.error.clone().unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Next scan".to_string(),
            scan.next_scan_at.clone().unwrap_or_else(|| "-".to_string()),
        ),
    ];
    let config_summary = vec![
        ("GitLab".to_string(), config.gitlab_base_url.clone()),
        ("Bind".to_string(), config.bind_addr.clone()),
        (
            "Run once".to_string(),
            bool_label(config.run_once).to_string(),
        ),
        (
            "Dry run".to_string(),
            bool_label(config.dry_run).to_string(),
        ),
        (
            "Mention commands".to_string(),
            bool_label(config.mention_commands_enabled).to_string(),
        ),
        (
            "Browser MCP".to_string(),
            bool_label(config.browser_mcp_enabled).to_string(),
        ),
        (
            "Max concurrent".to_string(),
            config.max_concurrent.to_string(),
        ),
        ("Cron".to_string(), config.schedule_cron.clone()),
        ("Timezone".to_string(), config.schedule_timezone.clone()),
        (
            "Created after".to_string(),
            config
                .created_after
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ),
        (
            "Repo targets".to_string(),
            target_label(config.repo_targets_all, config.repo_targets),
        ),
        (
            "Group targets".to_string(),
            target_label(config.group_targets_all, config.group_targets),
        ),
    ];
    format!(
        concat!(
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>Codex GitLab Review Status</title><style>{style}</style></head><body>",
            "<main class=\"page\">",
            "<section class=\"hero\"><h1>Service status</h1>",
            "<p class=\"muted\">Generated {generated_at}</p></section>",
            "<section class=\"grid\">",
            "<article class=\"card\"><h2>Scan</h2><dl>{scan_summary}</dl></article>",
            "<article class=\"card\"><h2>Configuration</h2><dl>{config_summary}</dl></article>",
            "</section>",
            "{reviews_section}{mentions_section}{auth_section}{catalog_section}",
            "</main></body></html>"
        ),
        style = page_style(),
        generated_at = escape_html(&snapshot.generated_at),
        scan_summary = render_definition_list(&scan_summary),
        config_summary = render_definition_list(&config_summary),
        reviews_section = render_reviews_section(&snapshot.in_progress_reviews),
        mentions_section = render_mentions_section(&snapshot.in_progress_mentions),
        auth_section = render_auth_section(&snapshot.auth_limit_resets),
        catalog_section = render_catalog_section(&snapshot.project_catalogs),
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
                        "<tr><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                        escape_html(&review.repo),
                        review.iid,
                        escape_html(&review.head_sha)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Repo</th><th>IID</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
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
                        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                        escape_html(&mention.key.repo),
                        mention.key.iid,
                        escape_html(&mention.key.discussion_id),
                        mention.key.trigger_note_id,
                        escape_html(&mention.head_sha)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Repo</th><th>IID</th><th>Discussion</th><th>Trigger note</th><th>Head SHA</th></tr></thead><tbody>{rows}</tbody></table>"
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
                        escape_html(&entry.reset_at)
                    )
                })
                .collect::<Vec<_>>()
                .join("");
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
                        catalog.fetched_at
                    )
                })
                .collect::<Vec<_>>()
                .join("");
            format!(
                "<table><thead><tr><th>Cache key</th><th>Projects</th><th>Fetched at</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_table_section(title: &str, content: String) -> String {
    format!(
        "<section class=\"card\"><h2>{}</h2>{}</section>",
        escape_html(title),
        content
    )
}

fn render_definition_list(items: &[(String, String)]) -> String {
    items
        .iter()
        .map(|(label, value)| {
            format!(
                "<div class=\"pair\"><dt>{}</dt><dd>{}</dd></div>",
                escape_html(label),
                escape_html(value)
            )
        })
        .collect::<Vec<_>>()
        .join("")
}

fn target_label(include_all: bool, count: usize) -> String {
    if include_all {
        "all".to_string()
    } else {
        count.to_string()
    }
}

fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn page_style() -> &'static str {
    r#"
body { margin: 0; background: #f5f2ea; color: #1f2933; font-family: Georgia, "Times New Roman", serif; }
.page { max-width: 1100px; margin: 0 auto; padding: 24px; }
.hero { margin-bottom: 20px; }
.hero h1 { margin: 0 0 6px; font-size: 2.1rem; }
.muted { margin: 0; color: #52606d; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 16px; }
.card { background: #fffdf8; border: 1px solid #d9cbb7; border-radius: 16px; padding: 18px; box-shadow: 0 8px 24px rgba(84, 70, 35, 0.08); margin-bottom: 16px; }
.card h2 { margin-top: 0; font-size: 1.2rem; }
dl { margin: 0; }
.pair { display: grid; grid-template-columns: 140px 1fr; gap: 10px; padding: 6px 0; border-top: 1px solid #efe6d6; }
.pair:first-child { border-top: 0; padding-top: 0; }
dt { font-weight: 700; color: #7c4d27; }
dd { margin: 0; word-break: break-word; }
table { width: 100%; border-collapse: collapse; }
th, td { text-align: left; padding: 10px 8px; border-top: 1px solid #efe6d6; vertical-align: top; }
thead th { border-top: 0; color: #7c4d27; font-size: 0.95rem; }
code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 0.92rem; }
.empty { margin: 0; color: #52606d; }
@media (max-width: 720px) {
  .page { padding: 16px; }
  .pair { grid-template-columns: 1fr; gap: 4px; }
  th, td { font-size: 0.95rem; }
}
"#
}

use super::super::timestamp::{self, UiTimestamp};
use super::rate_limits::rate_limits_script;
use crate::state::RunHistoryKind;
use std::fmt::Write as _;

const FEATURE_FLAG_SCRIPT: &str = include_str!("../assets/feature_flag.js");
const PAGE_STYLE: &str = include_str!("../assets/page.css");

pub(in crate::http) fn encode_repo_key(repo: &str) -> String {
    let mut output = String::with_capacity(repo.len() * 2);
    for byte in repo.as_bytes() {
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn render_table_section(title: &str, content: String) -> String {
    let content = content.into_boxed_str();
    format!(
        "<section class=\"card\"><h2>{}</h2>{}</section>",
        escape_html(title),
        content
    )
}

pub(super) fn render_definition_list(items: &[(String, String)]) -> String {
    items
        .iter()
        .map(|(label, value)| {
            format!(
                "<div class=\"pair\"><dt>{}</dt><dd>{}</dd></div>",
                escape_html(label),
                value
            )
        })
        .collect::<String>()
}

pub(super) fn pretty_print_json(raw: &str) -> String {
    serde_json::from_str::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| serde_json::to_string_pretty(&value).ok())
        .unwrap_or_else(|| raw.to_string())
}

pub(super) fn render_shell(
    title: &str,
    active: NavItem,
    content: String,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let content = content.into_boxed_str();
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <title>Codex GitLab Review {}</title>{}<style>{}{}</style></head><body>\
         <div class=\"layout\">\
         <aside class=\"sidebar\"><div class=\"brand\">Codex GitLab Review</div>{}</aside>\
         <main class=\"content\">{}</main>\
         </div>{}\
         <script>{}</script><script>{}</script></body></html>",
        escape_html(title),
        render_feature_flag_csrf_meta_tag(csrf_token),
        page_style(),
        timestamp::style_fragment(),
        render_nav(active, development_enabled),
        content,
        timestamp::script_tag(),
        feature_flag_script(),
        rate_limits_script(),
    )
}

pub(super) fn render_rfc3339_timestamp(timestamp: Option<&str>) -> String {
    match timestamp {
        Some(value) => UiTimestamp::from_rfc3339_text(value).map_or_else(
            || escape_html(value),
            |timestamp| timestamp::render(&timestamp, &[]),
        ),
        None => "-".to_string(),
    }
}

pub(super) fn render_unix_timestamp(timestamp: i64) -> String {
    UiTimestamp::from_unix_timestamp(timestamp).map_or_else(
        || escape_html(&timestamp.to_string()),
        |timestamp| timestamp::render(&timestamp, &[]),
    )
}

pub(super) fn render_optional_unix_timestamp(timestamp: Option<i64>) -> String {
    timestamp.map_or_else(|| "-".to_string(), render_unix_timestamp)
}

fn render_nav(active: NavItem, development_enabled: bool) -> String {
    let mut items = vec![
        (NavItem::Status, "/status", "Status"),
        (NavItem::History, "/history", "History"),
        (NavItem::RateLimits, "/rate-limits", "Rate limits"),
        (NavItem::Skills, "/skills", "Skills"),
    ];
    if development_enabled {
        items.push((NavItem::Development, "/development", "Development"));
    }
    let links = items
        .iter()
        .map(|(item, href, label)| {
            let class = if *item == active {
                "nav-link active"
            } else {
                "nav-link"
            };
            format!(
                "<a class=\"{}\" href=\"{}\">{}</a>",
                class,
                href,
                escape_html(label)
            )
        })
        .collect::<String>();
    format!("<nav class=\"nav\">{links}</nav>")
}

pub(super) fn mr_history_href(repo: &str, iid: u64) -> String {
    format!("/mr/{}/{}/history", encode_repo_key(repo), iid)
}

pub(super) fn target_label(include_all: bool, count: usize) -> String {
    if include_all {
        "all".to_string()
    } else {
        count.to_string()
    }
}

pub(super) fn bool_label(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

pub(super) fn run_kind_label(kind: RunHistoryKind) -> &'static str {
    match kind {
        RunHistoryKind::Review => "review",
        RunHistoryKind::Security => "security",
        RunHistoryKind::Mention => "mention",
    }
}

pub(super) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn render_feature_flag_csrf_meta_tag(csrf_token: Option<&str>) -> String {
    csrf_token
        .map(|csrf_token| {
            format!(
                "<meta name=\"codex-status-csrf\" content=\"{}\">",
                escape_html(csrf_token)
            )
        })
        .unwrap_or_default()
}

pub(super) fn render_csrf_hidden_input(csrf_token: Option<&str>) -> String {
    csrf_token
        .map(|csrf_token| {
            format!(
                "<input type=\"hidden\" name=\"csrf_token\" value=\"{}\">",
                escape_html(csrf_token)
            )
        })
        .unwrap_or_default()
}

fn feature_flag_script() -> &'static str {
    FEATURE_FLAG_SCRIPT
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum NavItem {
    Status,
    History,
    RateLimits,
    Skills,
    Development,
}

fn page_style() -> &'static str {
    PAGE_STYLE
}

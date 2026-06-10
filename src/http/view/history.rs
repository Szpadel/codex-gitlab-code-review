use super::super::status::{HistoryQuery, HistorySnapshot, MrHistorySnapshot};
use super::html::{
    NavItem, escape_html, mr_history_href, render_shell, render_table_section,
    render_unix_timestamp, run_kind_label,
};
use crate::state::{RunHistoryKind, RunHistoryListItem, RunHistoryRecord};
use urlencoding::encode;

pub(in crate::http) fn render_history_page(
    snapshot: &HistorySnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let filters = &snapshot.filters;
    let body = format!(
        "<section class=\"hero\"><h1>Run history</h1><p class=\"muted\">Append-only review and mention sessions.</p></section>\
         {}\
         {}\
         {}",
        render_history_filters(filters),
        render_history_run_table("All runs", &snapshot.runs),
        render_history_pagination(snapshot)
    );
    render_shell(
        "History",
        NavItem::History,
        body,
        csrf_token,
        development_enabled,
    )
}

pub(in crate::http) fn render_mr_history_page(
    snapshot: &MrHistorySnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let body = format!(
        "<section class=\"hero\"><h1>MR history</h1><p class=\"muted\">{} !{} has {} recorded session(s).</p></section>{}",
        escape_html(&snapshot.repo),
        snapshot.iid,
        snapshot.runs.len(),
        render_record_run_table("Sessions for this MR", &snapshot.runs)
    );
    render_shell(
        "MR History",
        NavItem::History,
        body,
        csrf_token,
        development_enabled,
    )
}

fn render_history_filters(filters: &HistorySnapshotFilters) -> String {
    format!(
        "<section class=\"card\"><h2>Filters</h2>\
         <form class=\"filters\" method=\"get\" action=\"/history\">\
         <input type=\"hidden\" name=\"limit\" value=\"{}\">\
         <label class=\"filter-field\"><span>Repo</span><input name=\"repo\" value=\"{}\"></label>\
         <label class=\"filter-field\"><span>MR IID</span><input name=\"iid\" value=\"{}\"></label>\
         <label class=\"filter-field\"><span>Kind</span><select name=\"kind\">{}</select></label>\
         <label class=\"filter-field\"><span>Result</span><input name=\"result\" value=\"{}\"></label>\
         <label class=\"filter-field filter-field-wide\"><span>Search</span><input name=\"q\" value=\"{}\"></label>\
         <div class=\"filter-actions\"><button type=\"submit\">Apply</button></div>\
         </form></section>",
        filters.limit,
        escape_html(filters.repo.as_deref().unwrap_or("")),
        filters
            .iid
            .map(|value| value.to_string())
            .unwrap_or_default(),
        render_kind_options(filters.kind),
        escape_html(filters.result.as_deref().unwrap_or("")),
        escape_html(filters.search.as_deref().unwrap_or(""))
    )
}

type HistorySnapshotFilters = HistoryQuery;

fn render_history_pagination(snapshot: &HistorySnapshot) -> String {
    let summary = if snapshot.runs.is_empty() {
        "0 matching runs".to_string()
    } else {
        format!("Showing up to {} matching runs", snapshot.limit)
    };
    let previous = if let Some(cursor) = snapshot.previous_cursor.as_deref() {
        let href = history_page_href(&snapshot.filters, Some(cursor), None);
        format!(
            "<a class=\"pagination-link\" href=\"{}\">Previous</a>",
            escape_html(&href)
        )
    } else {
        "<span class=\"pagination-link pagination-link-disabled\">Previous</span>".to_string()
    };
    let next = if let Some(cursor) = snapshot.next_cursor.as_deref() {
        let href = history_page_href(&snapshot.filters, None, Some(cursor));
        format!(
            "<a class=\"pagination-link\" href=\"{}\">Next</a>",
            escape_html(&href)
        )
    } else {
        "<span class=\"pagination-link pagination-link-disabled\">Next</span>".to_string()
    };
    format!(
        "<section class=\"card\"><div class=\"pagination\"><p class=\"muted\">{}</p><div class=\"pagination-links\">{}{}</div></div></section>",
        escape_html(&summary),
        previous,
        next
    )
}

fn history_page_href(
    filters: &HistorySnapshotFilters,
    before: Option<&str>,
    after: Option<&str>,
) -> String {
    let mut params = vec![format!("limit={}", filters.limit)];
    if let Some(repo) = filters.repo.as_deref() {
        params.push(format!("repo={}", encode(repo)));
    }
    if let Some(iid) = filters.iid {
        params.push(format!("iid={iid}"));
    }
    if let Some(kind) = filters.kind {
        params.push(format!("kind={}", run_kind_label(kind)));
    }
    if let Some(result) = filters.result.as_deref() {
        params.push(format!("result={}", encode(result)));
    }
    if let Some(search) = filters.search.as_deref() {
        params.push(format!("q={}", encode(search)));
    }
    if let Some(before) = before {
        params.push(format!("before={}", encode(before)));
    }
    if let Some(after) = after {
        params.push(format!("after={}", encode(after)));
    }
    format!("/history?{}", params.join("&"))
}

fn render_kind_options(selected: Option<RunHistoryKind>) -> String {
    let values = [
        (None, "all"),
        (Some(RunHistoryKind::Review), "review"),
        (Some(RunHistoryKind::Security), "security"),
        (Some(RunHistoryKind::Mention), "mention"),
    ];
    values
        .iter()
        .map(|(value, label)| {
            let selected_attr = if *value == selected { " selected" } else { "" };
            format!("<option value=\"{label}\"{selected_attr}>{label}</option>")
        })
        .collect::<String>()
}

fn render_history_run_table(title: &str, runs: &[RunHistoryListItem]) -> String {
    render_table_section(
        title,
        if runs.is_empty() {
            "<p class=\"empty\">No recorded sessions matched this view.</p>".to_string()
        } else {
            let rows = runs.iter().map(render_history_run_row).collect::<String>();
            format!(
                "<table><thead><tr><th>Kind</th><th>Repo</th><th>MR</th><th>Result</th><th>Started</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_history_run_row(run: &RunHistoryListItem) -> String {
    format!(
        "<tr>\
         <td><span class=\"badge badge-{}\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"{}\">!{}</a></td>\
         <td><span class=\"badge badge-result\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"/history/{}\">{}</a></td>\
         </tr>",
        escape_html(run_kind_label(run.kind)),
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        mr_history_href(&run.repo, run.iid),
        run.iid,
        escape_html(run.result.as_deref().unwrap_or(&run.status)),
        render_unix_timestamp(run.started_at),
        run.id,
        escape_html(&run_row_preview(
            run.result.as_deref(),
            run.preview.as_deref(),
            run.summary.as_deref(),
            run.error.as_deref()
        ))
    )
}

fn render_record_run_table(title: &str, runs: &[RunHistoryRecord]) -> String {
    render_table_section(
        title,
        if runs.is_empty() {
            "<p class=\"empty\">No recorded sessions matched this view.</p>".to_string()
        } else {
            let rows = runs.iter().map(render_record_run_row).collect::<String>();
            format!(
                "<table><thead><tr><th>Kind</th><th>Repo</th><th>MR</th><th>Result</th><th>Started</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table>"
            )
        },
    )
}

fn render_record_run_row(run: &RunHistoryRecord) -> String {
    format!(
        "<tr>\
         <td><span class=\"badge badge-{}\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"{}\">!{}</a></td>\
         <td><span class=\"badge badge-result\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"/history/{}\">{}</a></td>\
         </tr>",
        escape_html(run_kind_label(run.kind)),
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        mr_history_href(&run.repo, run.iid),
        run.iid,
        escape_html(run.result.as_deref().unwrap_or(&run.status)),
        render_unix_timestamp(run.started_at),
        run.id,
        escape_html(&run_row_preview(
            run.result.as_deref(),
            run.preview.as_deref(),
            run.summary.as_deref(),
            run.error.as_deref()
        ))
    )
}

fn run_row_preview(
    result: Option<&str>,
    preview: Option<&str>,
    summary: Option<&str>,
    error: Option<&str>,
) -> String {
    let value = if result == Some("error") {
        non_empty_text(error)
            .or_else(|| non_empty_text(summary))
            .or_else(|| non_empty_text(preview))
    } else {
        non_empty_text(preview).or_else(|| non_empty_text(summary))
    }
    .unwrap_or("(no preview)");
    compact_text_excerpt(value, 220)
}

fn non_empty_text(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn compact_text_excerpt(value: &str, max_chars: usize) -> String {
    let compact = value.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut output = String::new();
    for (index, ch) in compact.chars().enumerate() {
        if index >= max_chars {
            output.push_str("...");
            break;
        }
        output.push(ch);
    }
    output
}

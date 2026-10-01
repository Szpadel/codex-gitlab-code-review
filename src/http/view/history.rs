use super::super::status::{
    HistoryQuery, HistoryRunListItem, HistorySnapshot, MrHistorySnapshot,
    TokenUsageStatisticSnapshot,
};
use super::html::{
    NavItem, escape_html, format_number, mr_history_href, render_shell, render_table_section,
    render_unix_timestamp, run_kind_label,
};
use crate::review::RunRetryStatus;
use crate::run_history_kind::RunHistoryKind;
use urlencoding::encode;

pub(in crate::http) fn render_history_page(
    snapshot: &HistorySnapshot,
    csrf_token: Option<&str>,
    development_enabled: bool,
) -> String {
    let filters = &snapshot.filters;
    let body = format!(
        "<section class=\"hero\"><h1>Run history</h1><p class=\"muted\">Append-only review, security, and mention sessions.</p></section>\
         {}\
         {}\
         {}\
         {}",
        render_history_filters(filters),
        render_token_statistics(&snapshot.token_statistics),
        render_history_run_table("All runs", &snapshot.runs),
        render_history_pagination(snapshot, "/history")
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
        "<section class=\"hero\"><h1>MR history</h1><p class=\"muted\">Sessions for {} !{}.</p></section>{}{}",
        escape_html(&snapshot.repo),
        snapshot.iid,
        render_history_run_table("Sessions for this MR", &snapshot.history.runs),
        render_history_pagination(
            &snapshot.history,
            &mr_history_href(&snapshot.repo, snapshot.iid)
        )
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

fn render_history_pagination(snapshot: &HistorySnapshot, path: &str) -> String {
    let summary = if snapshot.runs.is_empty() {
        "0 matching runs".to_string()
    } else {
        format!("Showing up to {} matching runs", snapshot.limit)
    };
    let previous = if let Some(cursor) = snapshot.previous_cursor.as_deref() {
        let href = history_page_href(path, &snapshot.filters, Some(cursor), None);
        format!(
            "<a class=\"pagination-link\" href=\"{}\">Previous</a>",
            escape_html(&href)
        )
    } else {
        "<span class=\"pagination-link pagination-link-disabled\">Previous</span>".to_string()
    };
    let next = if let Some(cursor) = snapshot.next_cursor.as_deref() {
        let href = history_page_href(path, &snapshot.filters, None, Some(cursor));
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
    path: &str,
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
    format!("{path}?{}", params.join("&"))
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

fn render_token_statistics(statistics: &[TokenUsageStatisticSnapshot]) -> String {
    let all = statistics.iter().find(|statistic| statistic.kind.is_none());
    let recorded_total = all.map_or(0, |statistic| statistic.usage.total_tokens);
    let recorded_responses = all.map_or(0, |statistic| statistic.usage.response_count);
    if statistics.is_empty() || recorded_responses == 0 {
        return render_table_section(
            "Token usage for matching history",
            "<p class=\"empty\">No token usage has been recorded for matching runs.</p>"
                .to_string(),
        );
    }
    let show_cache_write = statistics
        .iter()
        .any(|statistic| statistic.usage.cache_write_input_tokens > 0);
    let cache_write_header = if show_cache_write {
        "<th class=\"numeric\">Cache write</th>"
    } else {
        ""
    };
    let rows = statistics
        .iter()
        .map(|statistic| {
            let kind = statistic.kind.map_or("all", run_kind_label);
            let cache_write = if show_cache_write {
                format!(
                    "<td class=\"numeric\">{}</td>",
                    format_number(statistic.usage.cache_write_input_tokens)
                )
            } else {
                String::new()
            };
            let share = if recorded_total == 0 {
                0.0
            } else {
                statistic.usage.total_tokens as f64 * 100.0 / recorded_total as f64
            };
            format!(
                "<tr><td>{}</td><td class=\"numeric\">{}</td><td class=\"numeric\">{}</td><td class=\"numeric\">{}</td>{}<td class=\"numeric\">{}</td><td class=\"numeric\">{}</td><td class=\"numeric\"><strong>{}</strong></td><td class=\"numeric\">{share:.1}%</td></tr>",
                escape_html(kind),
                format_number(statistic.recorded_runs),
                format_number(statistic.usage.input_tokens),
                format_number(statistic.usage.cached_input_tokens),
                cache_write,
                format_number(statistic.usage.output_tokens),
                format_number(statistic.usage.reasoning_output_tokens),
                format_number(statistic.usage.total_tokens),
            )
        })
        .collect::<String>();
    render_table_section(
        "Token usage for matching history",
        format!(
            "<p class=\"muted token-usage-note\">Exact usage recorded from Codex model responses. Cached input and reasoning output are included in the total, not added to it.</p><div class=\"table-scroll\"><table><thead><tr><th>Kind</th><th class=\"numeric\">Runs</th><th class=\"numeric\">Input</th><th class=\"numeric\">Cached input</th>{cache_write_header}<th class=\"numeric\">Output</th><th class=\"numeric\">Reasoning</th><th class=\"numeric\">Total</th><th class=\"numeric\">Share</th></tr></thead><tbody>{rows}</tbody></table></div>"
        ),
    )
}

fn render_history_run_table(title: &str, runs: &[HistoryRunListItem]) -> String {
    render_table_section(
        title,
        if runs.is_empty() {
            "<p class=\"empty\">No recorded sessions matched this view.</p>".to_string()
        } else {
            let rows = runs.iter().map(render_history_run_row).collect::<String>();
            format!(
                "<div class=\"table-scroll\"><table><thead><tr><th>Kind</th><th>Repo</th><th>MR</th><th>Result</th><th>Started</th><th class=\"numeric\">Total tokens</th><th>Preview</th></tr></thead><tbody>{rows}</tbody></table></div>"
            )
        },
    )
}

fn render_history_run_row(run: &HistoryRunListItem) -> String {
    format!(
        "<tr>\
         <td><span class=\"badge badge-{}\">{}</span></td>\
         <td>{}</td>\
         <td><a href=\"{}\">!{}</a></td>\
         <td><span class=\"badge badge-result\">{}</span></td>\
         <td>{}</td>\
         <td class=\"numeric\">{}</td>\
         <td><a href=\"/history/{}\">{}</a></td>\
         </tr>",
        escape_html(run_kind_label(run.kind)),
        escape_html(run_kind_label(run.kind)),
        escape_html(&run.repo),
        mr_history_href(&run.repo, run.iid),
        run.iid,
        escape_html(&run_result_label(
            run.result.as_deref(),
            &run.status,
            run.retry.as_ref()
        )),
        render_unix_timestamp(run.started_at),
        render_optional_tokens(run.token_usage.as_ref().map(|usage| usage.total_tokens)),
        run.id,
        escape_html(&run_row_preview(
            run.result.as_deref(),
            run.preview.as_deref(),
            run.summary.as_deref(),
            run.error.as_deref()
        ))
    )
}

fn render_optional_tokens(tokens: Option<i64>) -> String {
    tokens.map_or_else(|| "Not recorded".to_string(), format_number)
}

fn run_row_preview(
    result: Option<&str>,
    preview: Option<&str>,
    summary: Option<&str>,
    error: Option<&str>,
) -> String {
    let value = if matches!(result, Some("error" | "flagged")) {
        non_empty_text(error)
            .or_else(|| non_empty_text(summary))
            .or_else(|| non_empty_text(preview))
    } else {
        non_empty_text(preview).or_else(|| non_empty_text(summary))
    }
    .unwrap_or("(no preview)");
    compact_text_excerpt(value, 220)
}

fn run_result_label(result: Option<&str>, status: &str, retry: Option<&RunRetryStatus>) -> String {
    let base = result.unwrap_or(status);
    match retry {
        Some(retry) if base == "error" => format!("{base} {}", retry.label),
        _ => base.to_string(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::RunHistoryListItem;

    #[test]
    fn history_result_column_includes_retry_label_for_error_run() {
        let snapshot = HistorySnapshot {
            generated_at: "2026-03-23T00:00:00Z".to_string(),
            filters: HistoryQuery::default(),
            limit: 100,
            has_previous: false,
            has_next: false,
            previous_cursor: None,
            next_cursor: None,
            token_statistics: Vec::new(),
            runs: vec![HistoryRunListItem::new(
                RunHistoryListItem {
                    id: 7,
                    kind: RunHistoryKind::Review,
                    repo: "group/repo".to_string(),
                    iid: 11,
                    status: "done".to_string(),
                    result: Some("error".to_string()),
                    started_at: 0,
                    preview: Some("Review group/repo !11".to_string()),
                    summary: None,
                    error: Some("runner failed".to_string()),
                },
                Some(RunRetryStatus {
                    retry_number: 1,
                    max_retries: 5,
                    next_retry_at: Some(900),
                    exhausted: false,
                    label: "retry 1/5 in 15m".to_string(),
                }),
                None,
            )],
        };

        let html = render_history_page(&snapshot, None, false);

        assert!(html.contains("error retry 1/5 in 15m"));
    }
}

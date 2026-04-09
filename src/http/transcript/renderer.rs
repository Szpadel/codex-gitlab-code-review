use super::models::{FileChangeBodyFormat, ThreadItemKind, ThreadItemSnapshot, ThreadSnapshot};
use crate::http::markdown::render_safe_markdown;
use crate::http::timestamp;
use serde::Deserialize;

trait CollectHtml: Iterator<Item = String> + Sized {
    fn collect_html(self) -> String {
        self.fold(String::new(), |mut html, part| {
            html.push_str(&part);
            html
        })
    }
}

impl<I> CollectHtml for I where I: Iterator<Item = String> {}

pub(crate) fn render_thread_stream(thread: &ThreadSnapshot, gitlab_base_url: &str) -> String {
    let multiple_turns = thread.turns.len() > 1;
    let items = thread
        .turns
        .iter()
        .enumerate()
        .flat_map(|(index, turn)| {
            let mut rendered = Vec::new();
            if multiple_turns {
                rendered.push(render_turn_divider(&turn.id, &turn.status, index == 0));
            }
            rendered.extend(
                turn.items
                    .iter()
                    .map(|item| render_thread_item(item, gitlab_base_url)),
            );
            rendered
        })
        .collect_html();

    if items.is_empty() {
        "<div class=\"thread-empty\"><p class=\"empty\">No persisted items.</p></div>".to_string()
    } else {
        format!("<div class=\"transcript-stream\">{items}</div>")
    }
}

fn render_thread_item(item: &ThreadItemSnapshot, gitlab_base_url: &str) -> String {
    match &item.kind {
        ThreadItemKind::UserMessage => render_message_entry("User", "user", item, gitlab_base_url),
        ThreadItemKind::AgentMessage { .. } => {
            render_message_entry("Agent", "agent", item, gitlab_base_url)
        }
        ThreadItemKind::Reasoning => render_reasoning_entry(item),
        ThreadItemKind::CommandExecution { .. } => render_terminal_entry(item),
        ThreadItemKind::McpToolCall { .. } => render_mcp_entry(item),
        ThreadItemKind::DynamicToolCall { .. } => render_dynamic_tool_entry(item),
        ThreadItemKind::FileChange { .. } => render_file_change_entry(item),
        ThreadItemKind::WebSearch => render_web_search_entry(item),
        _ => render_activity_entry(item, gitlab_base_url),
    }
}

fn render_turn_divider(turn_id: &str, status: &str, is_first: bool) -> String {
    format!(
        "<div class=\"turn-divider{}\"><span class=\"turn-divider-label\">Turn {}</span><span class=\"status-pill status-{}\">{}</span></div>",
        if is_first { " turn-divider-first" } else { "" },
        escape_html(turn_id),
        status_class(status),
        escape_html(status)
    )
}

fn render_message_entry(
    role: &str,
    role_class: &str,
    item: &ThreadItemSnapshot,
    gitlab_base_url: &str,
) -> String {
    let mut meta = Vec::new();
    if let Some(phase) = item.phase() {
        meta.push(("phase".to_string(), phase.to_string()));
    }

    format!(
        "<article class=\"transcript-entry message-entry message-entry-{}\">\
         <header class=\"message-header\">\
         <div class=\"message-identity\"><span class=\"message-role\">{}</span></div>\
         <div class=\"entry-meta-cluster\">{}{}</div>\
         </header>{}</article>",
        role_class,
        escape_html(role),
        render_meta_pills(&meta),
        render_entry_timestamp(item),
        render_markdown_block(
            item.body.as_deref().unwrap_or(""),
            "message-body",
            gitlab_base_url
        )
    )
}

fn render_mcp_entry(item: &ThreadItemSnapshot) -> String {
    let mut meta = Vec::new();
    if let Some(status) = item.status() {
        meta.push(("status".to_string(), status.to_string()));
    }
    if let Some(duration) = item.duration_ms() {
        meta.push(("durationMs".to_string(), duration.to_string()));
    }

    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "mcp-entry",
            summary_class: "tool-summary",
            kicker: "MCP tool",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        Some(render_tool_preview_box(
            item.preview
                .as_deref()
                .unwrap_or("No argument preview available."),
        )),
        render_entry_meta(item, &meta),
        item.body
            .as_deref()
            .map(|body| {
                format!(
                    "<pre class=\"activity-body mcp-body\">{}</pre>",
                    escape_html(body)
                )
            })
            .unwrap_or_default(),
    )
}

fn render_dynamic_tool_entry(item: &ThreadItemSnapshot) -> String {
    let mut meta = Vec::new();
    if let Some(status) = item.status() {
        meta.push(("status".to_string(), status.to_string()));
    }
    if let Some(duration) = item.duration_ms() {
        meta.push(("durationMs".to_string(), duration.to_string()));
    }

    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "dynamic-tool-entry",
            summary_class: "tool-summary",
            kicker: "Dynamic tool",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        Some(render_tool_preview_box(
            item.preview.as_deref().unwrap_or("No preview available."),
        )),
        render_entry_meta(item, &meta),
        item.body
            .as_deref()
            .map(|body| {
                format!(
                    "<pre class=\"activity-body tool-body\">{}</pre>",
                    escape_html(body)
                )
            })
            .unwrap_or_default(),
    )
}

fn render_reasoning_entry(item: &ThreadItemSnapshot) -> String {
    let (summary, detail) = split_reasoning_content(item.body.as_deref());
    let open = detail.is_none();

    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "reasoning-entry",
            summary_class: "reasoning-summary",
            kicker: "Reasoning",
            open,
        },
        format!(
            "<span class=\"entry-title reasoning-summary-text\">{}</span>",
            escape_html(summary.as_deref().unwrap_or(&item.title))
        ),
        None,
        render_entry_meta(item, &[]),
        detail
            .map(|body| format!("<div class=\"reasoning-body\">{}</div>", escape_html(&body)))
            .unwrap_or_default(),
    )
}

fn render_web_search_entry(item: &ThreadItemSnapshot) -> String {
    if let Some(body) = item.body.as_deref() {
        return render_expandable_entry(
            ExpandableEntryOptions {
                entry_class: "web-search-entry",
                summary_class: "web-search-summary",
                kicker: "Web search",
                open: false,
            },
            format!(
                "<span class=\"entry-title\">{}</span>",
                escape_html(item.preview.as_deref().unwrap_or(&item.title))
            ),
            None,
            render_entry_meta(item, &[]),
            format!(
                "<pre class=\"activity-body compact-activity-body\">{}</pre>",
                escape_html(body)
            ),
        );
    }

    render_static_entry(
        "web-search-entry",
        "Web search",
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(item.preview.as_deref().unwrap_or(&item.title))
        ),
        None,
        render_entry_meta(item, &[]),
        String::new(),
    )
}

fn render_terminal_entry(item: &ThreadItemSnapshot) -> String {
    let status_value = item.status().unwrap_or("unknown");
    let exit_value = item.exit_code();
    let cwd_value = item.cwd();
    let duration_value = item.duration_ms();
    let mut header_meta = Vec::new();
    if let Some(duration) = duration_value {
        header_meta.push(("duration".to_string(), duration.to_string()));
    }
    if let Some(exit) = exit_value {
        header_meta.push(("exit".to_string(), exit.to_string()));
    }

    render_static_entry(
        "terminal-entry",
        "Command",
        format!(
            "<span class=\"entry-title\"><code>{}</code></span>",
            escape_html(&item.title)
        ),
        None,
        format!(
            "<span class=\"status-pill status-{}\">{}</span>{}{}",
            terminal_status_class(status_value, exit_value),
            escape_html(terminal_status_label(status_value, exit_value)),
            render_meta_pills(&header_meta),
            render_entry_timestamp(item)
        ),
        format!(
            "<div class=\"terminal-surface\">\
             {}\
             <div class=\"terminal-command-line\"><span class=\"term-prompt\">$</span><code>{}</code></div>\
             {}\
             </div>",
            cwd_value
                .map(|cwd| format!("<div class=\"terminal-path\">{}</div>", escape_html(cwd)))
                .unwrap_or_default(),
            escape_html(&item.title),
            item.body.as_deref().map_or_else(
                || "<p class=\"terminal-empty\">No aggregated output was captured.</p>".to_string(),
                |body| format!("<pre class=\"terminal-output\">{}</pre>", escape_html(body))
            )
        ),
    )
}

fn terminal_status_class(status: &str, exit: Option<&str>) -> &'static str {
    if terminal_exit_failed(exit) {
        "danger"
    } else {
        status_class(status)
    }
}

fn terminal_status_label<'a>(status: &'a str, exit: Option<&str>) -> &'a str {
    if terminal_exit_failed(exit) {
        "failed"
    } else {
        status
    }
}

fn terminal_exit_failed(exit: Option<&str>) -> bool {
    exit.and_then(|value| value.parse::<i64>().ok())
        .is_some_and(|value| value != 0)
}

fn render_file_change_entry(item: &ThreadItemSnapshot) -> String {
    let mut meta = Vec::new();
    if let Some(status) = item.status() {
        meta.push(("status".to_string(), status.to_string()));
    }

    render_expandable_entry(
        ExpandableEntryOptions {
            entry_class: "file-change-entry",
            summary_class: "file-change-summary",
            kicker: "File change",
            open: false,
        },
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(item.preview.as_deref().unwrap_or(&item.title))
        ),
        None,
        format!(
            "{}{}{}{}",
            render_file_change_stats(item),
            render_optional_body_badge(item.file_change_format()),
            render_meta_pills(&meta),
            render_entry_timestamp(item)
        ),
        render_file_change_body(item),
    )
}

fn render_activity_entry(item: &ThreadItemSnapshot, gitlab_base_url: &str) -> String {
    render_static_entry(
        &format!("activity-entry activity-entry-{}", item.css_token()),
        item.kind_label(),
        format!(
            "<span class=\"entry-title\">{}</span>",
            escape_html(&item.title)
        ),
        None,
        format!(
            "{}{}",
            render_optional_preview_badge(item.preview.as_deref()),
            render_entry_timestamp(item)
        ),
        format!(
            "{}{}",
            render_optional_preview_text(item.preview.as_deref()),
            render_activity_body(item, gitlab_base_url)
        ),
    )
}

fn render_activity_body(item: &ThreadItemSnapshot, gitlab_base_url: &str) -> String {
    let Some(body) = item.body.as_deref() else {
        return String::new();
    };

    if matches!(&item.kind, ThreadItemKind::ReviewModeTransition { .. }) {
        return render_markdown_block(body, "activity-body review-markdown-body", gitlab_base_url);
    }

    format!("<pre class=\"activity-body\">{}</pre>", escape_html(body))
}

fn render_static_entry(
    entry_class: &str,
    kicker: &str,
    title_html: String,
    preview_html: Option<String>,
    meta_html: String,
    body_html: String,
) -> String {
    let title_html = title_html.into_boxed_str();
    let preview_html = preview_html.map(String::into_boxed_str);
    let meta_html = meta_html.into_boxed_str();
    let body_html = body_html.into_boxed_str();

    format!(
        "<article class=\"transcript-entry {}\">{}{}</article>",
        entry_class,
        render_entry_header_shell(kicker, &title_html, preview_html.as_deref(), &meta_html),
        body_html
    )
}

struct ExpandableEntryOptions<'a> {
    entry_class: &'a str,
    summary_class: &'a str,
    kicker: &'a str,
    open: bool,
}

fn render_expandable_entry(
    options: ExpandableEntryOptions<'_>,
    title_html: String,
    preview_html: Option<String>,
    meta_html: String,
    body_html: String,
) -> String {
    let title_html = title_html.into_boxed_str();
    let preview_html = preview_html.map(String::into_boxed_str);
    let meta_html = meta_html.into_boxed_str();
    let body_html = body_html.into_boxed_str();

    format!(
        "<details class=\"transcript-entry {}\"{}>\
         <summary class=\"entry-summary {}\">{}\
         </summary>\
         {}\
         </details>",
        options.entry_class,
        if options.open { " open" } else { "" },
        options.summary_class,
        render_entry_header_content(
            options.kicker,
            &title_html,
            preview_html.as_deref(),
            &meta_html,
        ),
        body_html
    )
}

fn render_entry_header_shell(
    kicker: &str,
    title_html: &str,
    preview_html: Option<&str>,
    meta_html: &str,
) -> String {
    format!(
        "<header class=\"entry-header-shell\">{}</header>",
        render_entry_header_content(kicker, title_html, preview_html, meta_html)
    )
}

fn render_entry_header_content(
    kicker: &str,
    title_html: &str,
    preview_html: Option<&str>,
    meta_html: &str,
) -> String {
    format!(
        "<span class=\"entry-summary-content\">\
         <span class=\"entry-heading entry-summary-main\">\
         <span class=\"entry-kicker\">{}</span>{}\
         </span>\
         {}\
         </span>\
         <span class=\"entry-meta-cluster entry-summary-meta\">{}</span>",
        escape_html(kicker),
        title_html,
        preview_html.unwrap_or_default(),
        meta_html
    )
}

fn render_entry_meta(item: &ThreadItemSnapshot, meta: &[(String, String)]) -> String {
    format!(
        "{}{}",
        render_meta_pills(meta),
        render_entry_timestamp(item)
    )
}

fn render_markdown_block(body: &str, class_name: &str, gitlab_base_url: &str) -> String {
    if body.is_empty() {
        return String::new();
    }

    format!(
        "<div class=\"{} markdown-body\">{}</div>",
        class_name,
        render_safe_markdown(body, gitlab_base_url)
    )
}

fn render_tool_preview_box(preview: &str) -> String {
    format!(
        "<span class=\"tool-preview-box\">{}</span>",
        escape_html(preview)
    )
}

fn render_meta_pills(meta: &[(String, String)]) -> String {
    if meta.is_empty() {
        return String::new();
    }

    let pills = meta
        .iter()
        .map(|(label, value)| {
            format!(
                "<span class=\"meta-pill\"><span class=\"meta-pill-label\">{}</span>{}</span>",
                escape_html(display_meta_label(label)),
                escape_html(&display_meta_value(label, value))
            )
        })
        .collect_html();

    format!("<span class=\"meta-pills\">{pills}</span>")
}

fn render_entry_timestamp(item: &ThreadItemSnapshot) -> String {
    item.ui_timestamp
        .as_ref()
        .map(|timestamp| timestamp::render(timestamp, &["message-timestamp"]))
        .or_else(|| {
            item.timestamp.as_deref().map(|timestamp| {
                format!(
                    "<span class=\"message-timestamp\">{}</span>",
                    escape_html(timestamp)
                )
            })
        })
        .unwrap_or_default()
}

fn render_optional_preview_text(preview: Option<&str>) -> String {
    preview
        .map(|preview| {
            format!(
                "<span class=\"activity-preview\">{}</span>",
                escape_html(preview)
            )
        })
        .unwrap_or_default()
}

fn render_optional_preview_badge(preview: Option<&str>) -> String {
    preview
        .map(|preview| {
            format!(
                "<span class=\"meta-pill preview-pill\" title=\"{}\">preview</span>",
                escape_html(preview)
            )
        })
        .unwrap_or_default()
}

fn render_optional_body_badge(body_format: Option<FileChangeBodyFormat>) -> String {
    matches!(
        body_format,
        Some(FileChangeBodyFormat::Diff | FileChangeBodyFormat::Mixed)
    )
    .then(|| "<span class=\"meta-pill preview-pill\">diff</span>".to_string())
    .unwrap_or_default()
}

fn render_file_change_stats(item: &ThreadItemSnapshot) -> String {
    let added = item.file_change_added_lines();
    let removed = item.file_change_removed_lines();
    if added == 0 && removed == 0 {
        return String::new();
    }

    format!(
        "<span class=\"meta-pill diff-stats-pill\">\
         <span class=\"diff-stats-add\">+{added}</span>\
         <span class=\"diff-stats-remove\">-{removed}\
         </span></span>"
    )
}

fn render_colored_diff(body: &str) -> String {
    let lines = body
        .lines()
        .map(|line| {
            let class_name = if line.starts_with('+') && !is_diff_metadata_line(line) {
                "diff-line diff-line-add"
            } else if line.starts_with('-') && !is_diff_metadata_line(line) {
                "diff-line diff-line-remove"
            } else if line.starts_with("@@") {
                "diff-line diff-line-hunk"
            } else if is_diff_metadata_line(line) {
                "diff-line diff-line-meta"
            } else {
                "diff-line"
            };
            format!("<div class=\"{}\">{}</div>", class_name, escape_html(line))
        })
        .collect_html();
    format!("<div class=\"diff-view\">{lines}</div>")
}

fn render_file_change_body(item: &ThreadItemSnapshot) -> String {
    let Some(body) = item.body.as_deref() else {
        return String::new();
    };
    match item.file_change_format() {
        Some(FileChangeBodyFormat::Diff) => render_colored_diff(body),
        Some(FileChangeBodyFormat::Mixed) => render_mixed_file_change_body(body),
        _ => format!("<pre class=\"activity-body\">{}</pre>", escape_html(body)),
    }
}

fn is_diff_metadata_line(line: &str) -> bool {
    if line.starts_with("diff --git ") {
        return true;
    }
    let Some(path) = line
        .strip_prefix("+++ ")
        .or_else(|| line.strip_prefix("--- "))
    else {
        return false;
    };
    let path = path.trim();
    path == "/dev/null" || path.starts_with("a/") || path.starts_with("b/")
}

#[derive(Deserialize)]
struct FileChangeBodySection {
    kind: String,
    path: String,
    body: String,
}

fn render_mixed_file_change_body(body: &str) -> String {
    let Ok(sections) = serde_json::from_str::<Vec<FileChangeBodySection>>(body) else {
        return format!("<pre class=\"activity-body\">{}</pre>", escape_html(body));
    };

    sections
        .iter()
        .map(|section| {
            let content = if section.kind == "diff" {
                render_colored_diff(&section.body)
            } else {
                format!(
                    "<pre class=\"activity-body\">{}</pre>",
                    escape_html(&section.body)
                )
            };
            format!(
                "<section class=\"file-change-section\">\
                 <div class=\"file-change-section-path\"><code>{}</code></div>\
                 {}\
                 </section>",
                escape_html(&section.path),
                content
            )
        })
        .collect_html()
}

fn split_reasoning_content(body: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(body) = body.map(str::trim).filter(|body| !body.is_empty()) else {
        return (None, None);
    };

    if let Some((summary, detail)) = body.split_once("\n\n") {
        return (
            Some(summary.trim().to_string()),
            Some(detail.trim().to_string()),
        );
    }

    let summary = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .map_or_else(|| body.to_string(), |line| line.trim().to_string());
    let detail = (summary != body).then(|| body.to_string());
    (Some(summary), detail)
}

fn display_meta_label(label: &str) -> &str {
    match label {
        "durationMs" => "duration",
        _ => label,
    }
}

fn display_meta_value(label: &str, value: &str) -> String {
    match label {
        "duration" | "durationMs" => format_duration_ms(value),
        _ => value.to_string(),
    }
}

fn format_duration_ms(value: &str) -> String {
    let Ok(ms) = value.parse::<u64>() else {
        return format!("{value} ms");
    };
    if ms < 1_000 {
        return format!("{ms} ms");
    }
    let rounded_tenths = (ms + 50) / 100;
    if rounded_tenths % 10 == 0 {
        return format!("{} s", rounded_tenths / 10);
    }
    format!("{}.{} s", rounded_tenths / 10, rounded_tenths % 10)
}

fn status_class(status: &str) -> &'static str {
    match status {
        "completed" | "success" => "success",
        "failed" | "error" => "danger",
        "in_progress" | "running" => "info",
        _ => "neutral",
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_flags::FeatureFlagSnapshot;
    use crate::http::transcript::parser::thread_snapshot_from_events;
    use crate::state::{
        RunHistoryEventRecord, RunHistoryKind, RunHistoryRecord, TranscriptBackfillState,
    };
    use insta::assert_snapshot;
    use serde_json::json;

    fn base_run() -> RunHistoryRecord {
        RunHistoryRecord {
            id: 1,
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 1,
            head_sha: "sha".to_string(),
            status: "done".to_string(),
            result: Some("commented".to_string()),
            started_at: 0,
            finished_at: Some(0),
            updated_at: 0,
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            security_context_base_branch: None,
            security_context_base_head_sha: None,
            security_context_prompt_version: None,
            security_context_payload_json: None,
            security_context_generated_at: None,
            security_context_expires_at: None,
            preview: Some("Preview".to_string()),
            summary: None,
            error: None,
            auth_account_name: None,
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            commit_sha: None,
            feature_flags: FeatureFlagSnapshot::default(),
            events_persisted_cleanly: false,
            transcript_backfill_state: TranscriptBackfillState::NotRequested,
            transcript_backfill_error: None,
        }
    }

    #[test]
    fn render_thread_stream_snapshot_full() {
        let thread = thread_snapshot_from_events(
            &base_run(),
            &[
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "createdAt": "2026-03-11T12:54:00Z",
                        "type": "userMessage",
                        "content": [{ "type": "text", "text": "Please inspect the failing job." }]
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "createdAt": "2026-03-11T12:54:05Z",
                        "type": "reasoning",
                        "summary": ["Need to inspect CI output"],
                        "content": ["The failure looks deterministic."]
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "commandExecution",
                        "command": "cargo test",
                        "cwd": "/workdir",
                        "status": "completed",
                        "exitCode": 1,
                        "durationMs": 250,
                        "aggregatedOutput": "1 test failed"
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 5,
                    run_history_id: 1,
                    sequence: 5,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "mcpToolCall",
                        "server": "gitlab",
                        "tool": "get_merge_request",
                        "arguments": { "iid": 7 },
                        "status": "completed",
                        "durationMs": 50,
                        "result": { "iid": 7 }
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 6,
                    run_history_id: 1,
                    sequence: 6,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "AgentMessage",
                        "phase": "final",
                        "content": [{ "type": "Text", "text": "Implemented the requested fix." }]
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 7,
                    run_history_id: 1,
                    sequence: 7,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread");

        let html = render_thread_stream(&thread, "https://gitlab.example.com/api/v4");
        assert_snapshot!("thread_stream_full", html);
    }

    #[test]
    fn render_thread_stream_snapshot_mixed_file_changes() {
        let thread = thread_snapshot_from_events(
            &base_run(),
            &[
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "fileChange",
                        "status": "completed",
                        "changes": {
                            "src/lib.rs": {
                                "type": "update",
                                "unified_diff": "@@ -1 +1 @@\n-old\n+new\n"
                            },
                            "README.md": {
                                "type": "rename",
                                "previous_path": "README-old.md"
                            }
                        }
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread");

        let html = render_thread_stream(&thread, "https://gitlab.example.com/api/v4");
        assert_snapshot!("thread_stream_mixed_file_changes", html);
    }

    #[test]
    fn render_thread_stream_snapshot_review_markdown() {
        let thread = thread_snapshot_from_events(
            &base_run(),
            &[
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "enteredReviewMode",
                        "review": "# Review\n\n- [ ] Check this",
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread");

        let html = render_thread_stream(&thread, "https://gitlab.example.com/api/v4");
        assert_snapshot!("thread_stream_review_markdown", html);
    }
}

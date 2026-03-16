use super::timestamp::UiTimestamp;
use crate::state::{RunHistoryEventRecord, RunHistoryRecord};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadSnapshot {
    pub id: String,
    pub preview: String,
    pub status: String,
    pub turns: Vec<TurnSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TurnSnapshot {
    pub id: String,
    pub status: String,
    pub items: Vec<ThreadItemSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadItemSnapshot {
    pub item_type: String,
    pub title: String,
    pub preview: Option<String>,
    pub body: Option<String>,
    pub meta: Vec<(String, String)>,
    pub timestamp: Option<String>,
    #[serde(skip)]
    pub(crate) ui_timestamp: Option<UiTimestamp>,
}

pub fn thread_snapshot_from_events(
    run: &RunHistoryRecord,
    events: &[RunHistoryEventRecord],
) -> Option<ThreadSnapshot> {
    if events.is_empty() {
        return None;
    }
    let mut turns = Vec::<TurnSnapshot>::new();
    for event in events {
        let turn_id = event.turn_id.as_deref().unwrap_or("<unknown>");
        let turn = if let Some(existing) = turns.iter_mut().find(|entry| entry.id == turn_id) {
            existing
        } else {
            turns.push(TurnSnapshot {
                id: turn_id.to_string(),
                status: "in_progress".to_string(),
                items: Vec::new(),
            });
            turns.last_mut().expect("turn inserted")
        };
        match event.event_type.as_str() {
            "turn_started" => {}
            "item_completed" => turn.items.push(parse_thread_item_snapshot(
                &event.payload,
                extract_item_timestamp(&event.payload),
            )),
            "turn_completed" => {
                turn.status = json_string(event.payload.get("status"))
                    .unwrap_or_else(|| "unknown".to_string());
            }
            _ => {}
        }
    }
    let status = turns
        .last()
        .map(|turn| turn.status.clone())
        .unwrap_or_else(|| "unknown".to_string());
    Some(ThreadSnapshot {
        id: run
            .review_thread_id
            .clone()
            .or_else(|| run.thread_id.clone())
            .unwrap_or_else(|| format!("run-{}", run.id)),
        preview: run.preview.clone().unwrap_or_default(),
        status,
        turns,
    })
}

pub fn thread_snapshot_is_complete(thread: &ThreadSnapshot) -> bool {
    !thread.turns.is_empty()
        && !thread
            .turns
            .iter()
            .any(|turn| !turn_snapshot_is_complete(turn))
}

pub fn thread_snapshot_only_target_turn_is_incomplete(
    thread: &ThreadSnapshot,
    target_turn_id: &str,
) -> bool {
    let incomplete_turns = thread
        .turns
        .iter()
        .filter(|turn| !turn_snapshot_is_complete(turn))
        .map(|turn| turn.id.as_str())
        .collect::<Vec<_>>();
    !incomplete_turns.is_empty()
        && incomplete_turns
            .iter()
            .all(|turn_id| *turn_id == target_turn_id)
}

fn thread_item_is_self_contained(item: &ThreadItemSnapshot) -> bool {
    match item.item_type.as_str() {
        "agentMessage" | "AgentMessage" => {
            item.body.as_deref().is_some_and(|body| !body.is_empty())
        }
        "commandExecution" => {
            item.body.as_deref().is_some_and(|body| !body.is_empty()) || item.title != "Command"
        }
        "reasoning" => item.body.as_deref().is_some_and(|body| !body.is_empty()),
        _ => true,
    }
}

fn turn_snapshot_is_complete(turn: &TurnSnapshot) -> bool {
    if matches!(turn.status.as_str(), "in_progress" | "unknown") || turn.items.is_empty() {
        return false;
    }
    let has_renderable_non_reasoning_item = turn
        .items
        .iter()
        .any(|item| reasoning_fallback_supports_completeness(item));
    turn.items.iter().all(|item| {
        thread_item_is_self_contained(item)
            || (item.item_type == "reasoning" && has_renderable_non_reasoning_item)
    })
}

fn reasoning_fallback_supports_completeness(item: &ThreadItemSnapshot) -> bool {
    thread_item_is_self_contained(item)
        && matches!(
            item.item_type.as_str(),
            "agentMessage" | "AgentMessage" | "exitedReviewMode"
        )
}

fn parse_thread_item_snapshot(item: &Value, timestamp: Option<UiTimestamp>) -> ThreadItemSnapshot {
    let item_type = json_string(item.get("type")).unwrap_or_else(|| "unknown".to_string());
    let timestamp_text = timestamp.as_ref().map(|value| value.fallback_text.clone());
    match item_type.as_str() {
        "userMessage" => ThreadItemSnapshot {
            item_type,
            title: "User message".to_string(),
            preview: None,
            body: Some(join_user_content(item.get("content"))),
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "agentMessage" | "AgentMessage" => ThreadItemSnapshot {
            item_type,
            title: "Agent message".to_string(),
            preview: None,
            body: json_string(item.get("text")).or_else(|| {
                let content = join_agent_message_content(item.get("content"));
                (!content.is_empty()).then_some(content)
            }),
            meta: phase_meta(item),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "reasoning" => ThreadItemSnapshot {
            item_type,
            title: "Reasoning".to_string(),
            preview: None,
            body: Some(join_reasoning_content(item)),
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "commandExecution" => ThreadItemSnapshot {
            item_type,
            title: json_string(item.get("command")).unwrap_or_else(|| "Command".to_string()),
            preview: None,
            body: json_string(item.get("aggregatedOutput")),
            meta: vec![
                optional_meta("cwd", item.get("cwd")),
                optional_meta("status", item.get("status")),
                optional_meta("exit", item.get("exitCode")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "mcpToolCall" => ThreadItemSnapshot {
            item_type,
            title: format!(
                "{}:{}",
                json_string(item.get("server")).unwrap_or_else(|| "mcp".to_string()),
                json_string(item.get("tool")).unwrap_or_else(|| "tool".to_string())
            ),
            preview: tool_call_preview(item),
            body: combine_detail_sections(&[
                ("Arguments", tool_call_arguments(item)),
                ("Result", item.get("result")),
                ("Error", item.get("error")),
            ]),
            meta: vec![
                optional_meta("status", item.get("status")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "dynamicToolCall" => ThreadItemSnapshot {
            item_type,
            title: json_string(item.get("tool")).unwrap_or_else(|| "Dynamic tool".to_string()),
            preview: item
                .get("contentItems")
                .map(single_line_preview)
                .or_else(|| item.get("result").map(single_line_preview))
                .or_else(|| item.get("error").map(single_line_preview)),
            body: combine_detail_sections(&[
                ("Input", item.get("contentItems")),
                ("Result", item.get("result")),
                ("Error", item.get("error")),
            ]),
            meta: vec![
                optional_meta("status", item.get("status")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "webSearch" => ThreadItemSnapshot {
            item_type,
            title: "Web search".to_string(),
            preview: json_string(item.get("query"))
                .or_else(|| item.get("action").map(single_line_preview)),
            body: item
                .get("action")
                .map(compact_json)
                .filter(|body| Some(body.as_str()) != json_string(item.get("query")).as_deref()),
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "fileChange" => {
            let summary = file_change_preview_and_body(item.get("changes"));
            ThreadItemSnapshot {
                item_type,
                title: "File change".to_string(),
                preview: summary.preview,
                body: summary.body,
                meta: vec![
                    optional_meta("status", item.get("status")),
                    Some(("bodyFormat".to_string(), summary.body_format.to_string())),
                    Some(("addedLines".to_string(), summary.added_lines.to_string())),
                    Some((
                        "removedLines".to_string(),
                        summary.removed_lines.to_string(),
                    )),
                ]
                .into_iter()
                .flatten()
                .collect(),
                timestamp: timestamp_text,
                ui_timestamp: timestamp,
            }
        }
        "enteredReviewMode" | "exitedReviewMode" => ThreadItemSnapshot {
            item_type: item_type.clone(),
            title: if item_type == "enteredReviewMode" {
                "Entered review mode".to_string()
            } else {
                "Exited review mode".to_string()
            },
            preview: None,
            body: json_string(item.get("review")),
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        "contextCompaction" => ThreadItemSnapshot {
            item_type,
            title: "Context compaction".to_string(),
            preview: None,
            body: None,
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
        _ => ThreadItemSnapshot {
            item_type,
            title: "Event".to_string(),
            preview: None,
            body: Some(compact_json(item)),
            meta: Vec::new(),
            timestamp: timestamp_text,
            ui_timestamp: timestamp,
        },
    }
}

fn extract_item_timestamp(item: &Value) -> Option<UiTimestamp> {
    let value = item
        .get("createdAt")
        .or_else(|| item.get("created_at"))
        .or_else(|| item.get("timestamp"))?;
    UiTimestamp::from_history_value(value)
}

fn join_user_content(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("type").and_then(Value::as_str) == Some("text") {
                        json_string(item.get("text"))
                    } else {
                        Some(compact_json(item))
                    }
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn join_agent_message_content(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item.get("type").and_then(Value::as_str) {
                    Some("Text") => json_string(item.get("text")),
                    _ => Some(compact_json(item)),
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn join_reasoning_content(item: &Value) -> String {
    const ENCRYPTED_REASONING_PLACEHOLDER: &str =
        "Reasoning is unavailable because Codex returned only encrypted history for this step.";
    let summary = join_reasoning_entries(item.get("summary"));
    let content = join_reasoning_entries(item.get("content"));
    match (summary.is_empty(), content.is_empty()) {
        (false, false) => format!("{summary}\n\n{content}"),
        (false, true) => summary,
        (true, false) => content,
        (true, true) => item
            .get("encrypted_content")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|_| ENCRYPTED_REASONING_PLACEHOLDER.to_string())
            .unwrap_or_default(),
    }
}

fn join_reasoning_entries(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(reasoning_entry_text)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn reasoning_entry_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Object(_) => value
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some(compact_json(value))),
        _ => None,
    }
}

fn tool_call_arguments(item: &Value) -> Option<&Value> {
    item.get("arguments")
        .or_else(|| item.get("args"))
        .or_else(|| item.get("input"))
        .or_else(|| item.get("params"))
}

fn tool_call_preview(item: &Value) -> Option<String> {
    tool_call_arguments(item)
        .map(single_line_preview)
        .or_else(|| item.get("result").map(single_line_preview))
        .or_else(|| item.get("error").map(single_line_preview))
}

fn combine_detail_sections(sections: &[(&str, Option<&Value>)]) -> Option<String> {
    let rendered = sections
        .iter()
        .filter_map(|(label, value)| value.map(|value| format!("{label}\n{}", compact_json(value))))
        .collect::<Vec<_>>();
    (!rendered.is_empty()).then(|| rendered.join("\n\n"))
}

fn single_line_preview(value: &Value) -> String {
    let compact = compact_json(value)
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    truncate_preview(&compact, 140)
}

fn truncate_preview(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            output.push('…');
            break;
        }
        output.push(ch);
    }
    output
}

struct FileChangeSummary {
    preview: Option<String>,
    body: Option<String>,
    body_format: &'static str,
    added_lines: usize,
    removed_lines: usize,
}

fn file_change_preview_and_body(changes: Option<&Value>) -> FileChangeSummary {
    #[derive(Serialize)]
    struct FileChangeBodySection {
        kind: &'static str,
        path: String,
        body: String,
    }

    let Some(changes) = changes.and_then(Value::as_object) else {
        return FileChangeSummary {
            preview: None,
            body: None,
            body_format: "payload",
            added_lines: 0,
            removed_lines: 0,
        };
    };
    let preview = match changes.len() {
        0 => None,
        1 => changes.keys().next().cloned(),
        count => Some(format!("{count} files changed")),
    };
    let sections = changes
        .iter()
        .map(|(path, value)| {
            if let Some(diff) = value.get("unified_diff").and_then(Value::as_str) {
                FileChangeBodySection {
                    kind: "diff",
                    path: path.clone(),
                    body: format!("diff --git a/{path} b/{path}\n{diff}"),
                }
            } else {
                FileChangeBodySection {
                    kind: "payload",
                    path: path.clone(),
                    body: compact_json(value),
                }
            }
        })
        .collect::<Vec<_>>();
    let (added_lines, removed_lines) = sections
        .iter()
        .filter(|section| section.kind == "diff")
        .map(|section| unified_diff_stats(&section.body))
        .fold(
            (0usize, 0usize),
            |(added_acc, removed_acc), (added, removed)| (added_acc + added, removed_acc + removed),
        );
    let has_diff = sections.iter().any(|section| section.kind == "diff");
    let has_payload = sections.iter().any(|section| section.kind == "payload");
    let (body, body_format) = if has_diff && has_payload {
        (serde_json::to_string(&sections).ok(), "mixed")
    } else if has_diff {
        (
            Some(
                sections
                    .into_iter()
                    .map(|section| section.body)
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            ),
            "diff",
        )
    } else {
        (
            Some(
                sections
                    .into_iter()
                    .map(|section| format!("{}\n{}", section.path, section.body))
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            ),
            "payload",
        )
    };
    FileChangeSummary {
        preview,
        body: body.filter(|body| !body.is_empty()),
        body_format,
        added_lines,
        removed_lines,
    }
}

fn unified_diff_stats(diff: &str) -> (usize, usize) {
    diff.lines()
        .fold((0usize, 0usize), |(added, removed), line| {
            if line.starts_with('+') && !is_unified_diff_header(line) {
                (added + 1, removed)
            } else if line.starts_with('-') && !is_unified_diff_header(line) {
                (added, removed + 1)
            } else {
                (added, removed)
            }
        })
}

fn is_unified_diff_header(line: &str) -> bool {
    if line.starts_with("diff --git ") || line.starts_with("@@") {
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

fn phase_meta(item: &Value) -> Vec<(String, String)> {
    optional_meta("phase", item.get("phase"))
        .into_iter()
        .collect()
}

fn optional_meta(label: &str, value: Option<&Value>) -> Option<(String, String)> {
    json_string(value).map(|value| (label.to_string(), value))
}

fn json_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(Value::Null) | None => None,
        Some(other) => Some(compact_json(other)),
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{RunHistoryKind, RunHistoryRecord};
    use serde_json::json;

    #[test]
    fn join_reasoning_content_extracts_typed_summary_and_content_entries() {
        let item = json!({
            "type": "reasoning",
            "summary": [
                { "type": "summary_text", "text": "Typed reasoning summary" }
            ],
            "content": [
                { "type": "reasoning_text", "text": "Typed reasoning detail." }
            ]
        });

        assert_eq!(
            join_reasoning_content(&item),
            "Typed reasoning summary\n\nTyped reasoning detail."
        );
    }

    #[test]
    fn join_reasoning_content_returns_placeholder_for_encrypted_only_reasoning() {
        let item = json!({
            "type": "reasoning",
            "summary": [],
            "content": null,
            "encrypted_content": "opaque-reasoning-blob"
        });

        assert_eq!(
            join_reasoning_content(&item),
            "Reasoning is unavailable because Codex returned only encrypted history for this step."
        );
    }

    #[test]
    fn thread_snapshot_treats_zero_output_command_as_complete() {
        let run = RunHistoryRecord {
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
            events_persisted_cleanly: false,
            transcript_backfill_state: crate::state::TranscriptBackfillState::NotRequested,
            transcript_backfill_error: None,
        };
        let thread = thread_snapshot_from_events(
            &run,
            &[
                crate::state::RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "commandExecution",
                        "command": "true",
                        "status": "completed"
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
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
        .expect("thread snapshot");
        assert!(thread_snapshot_is_complete(&thread));
    }

    #[test]
    fn thread_snapshot_treats_empty_reasoning_as_complete_when_turn_is_otherwise_renderable() {
        let run = RunHistoryRecord {
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
            events_persisted_cleanly: false,
            transcript_backfill_state: crate::state::TranscriptBackfillState::NotRequested,
            transcript_backfill_error: None,
        };
        let thread = thread_snapshot_from_events(
            &run,
            &[
                crate::state::RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": null
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "commandExecution",
                        "command": "git diff",
                        "aggregatedOutput": "diff output",
                        "status": "completed"
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "All clear."
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 5,
                    run_history_id: 1,
                    sequence: 5,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread snapshot");
        assert!(thread_snapshot_is_complete(&thread));
    }

    #[test]
    fn thread_snapshot_does_not_treat_user_message_as_reasoning_fallback() {
        let run = RunHistoryRecord {
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
            events_persisted_cleanly: false,
            transcript_backfill_state: crate::state::TranscriptBackfillState::NotRequested,
            transcript_backfill_error: None,
        };
        let thread = thread_snapshot_from_events(
            &run,
            &[
                crate::state::RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": null
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "userMessage",
                        "content": [{ "type": "text", "text": "Please review this." }]
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread snapshot");
        assert!(!thread_snapshot_is_complete(&thread));
    }

    #[test]
    fn thread_snapshot_does_not_treat_tool_output_as_reasoning_fallback() {
        let run = RunHistoryRecord {
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
            events_persisted_cleanly: false,
            transcript_backfill_state: crate::state::TranscriptBackfillState::NotRequested,
            transcript_backfill_error: None,
        };
        let thread = thread_snapshot_from_events(
            &run,
            &[
                crate::state::RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": null
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "commandExecution",
                        "command": "git diff",
                        "aggregatedOutput": "diff output",
                        "status": "completed"
                    }),
                    created_at: 0,
                },
                crate::state::RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
        )
        .expect("thread snapshot");
        assert!(!thread_snapshot_is_complete(&thread));
    }
}

use crate::state::NewRunHistoryEvent;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tokio::task;

pub const TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR: &str =
    "local Codex session history directory is unavailable";
pub const TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR: &str =
    "local session history is still being written";

#[async_trait]
pub trait TranscriptBackfillSource: Send + Sync {
    async fn load_events(
        &self,
        thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>>;
}

#[derive(Clone, Debug)]
pub struct SessionHistoryBackfillSource {
    root: PathBuf,
}

#[derive(Debug)]
struct PendingToolCall {
    name: String,
    input: Value,
}

impl SessionHistoryBackfillSource {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

#[async_trait]
impl TranscriptBackfillSource for SessionHistoryBackfillSource {
    async fn load_events(
        &self,
        thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        let root = self.root.clone();
        let thread_id = thread_id.to_string();
        let turn_id = turn_id.map(ToOwned::to_owned);
        task::spawn_blocking(move || load_events_from_root(&root, &thread_id, turn_id.as_deref()))
            .await
            .context("join transcript backfill task")?
    }
}

fn load_events_from_root(
    root: &Path,
    thread_id: &str,
    turn_id: Option<&str>,
) -> Result<Option<Vec<NewRunHistoryEvent>>> {
    let Some(path) = find_session_file(root, thread_id)? else {
        return Ok(None);
    };
    parse_session_file(&path, thread_id, turn_id)
}

fn find_session_file(root: &Path, thread_id: &str) -> Result<Option<PathBuf>> {
    if !root.exists() {
        return Err(anyhow!(TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut candidates = Vec::<PathBuf>::new();
    while let Some(path) = pending.pop() {
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                if path == root {
                    return Err(anyhow!(TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR));
                }
                continue;
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read session directory {}", path.display()));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| format!("read entry in {}", path.display()))?;
            let candidate = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("read file type for {}", candidate.display()))?;
            if file_type.is_dir() {
                pending.push(candidate);
                continue;
            }
            let Some(name) = candidate.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if name.ends_with(".jsonl") && session_file_name_matches(name, thread_id) {
                candidates.push(candidate);
            }
        }
    }
    candidates.sort_by(|left, right| {
        let left_modified = fs::metadata(left)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let right_modified = fs::metadata(right)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        right_modified
            .cmp(&left_modified)
            .then_with(|| left.cmp(right))
    });
    Ok(candidates.into_iter().next())
}

fn parse_session_file(
    path: &Path,
    thread_id: &str,
    target_turn_id: Option<&str>,
) -> Result<Option<Vec<NewRunHistoryEvent>>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read session file {}", path.display()))?;
    let non_empty_line_count = raw.lines().filter(|line| !line.trim().is_empty()).count();
    let mut events = Vec::new();
    let mut sequence = 1i64;
    let mut current_turn_id = None::<String>;
    let mut started_turns = HashSet::<String>::new();
    let mut completed_turns = HashSet::<String>::new();
    let mut pending_calls = HashMap::<String, PendingToolCall>::new();
    let mut session_matches = None::<bool>;

    let mut non_empty_line_index = 0usize;
    for (line_no, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        non_empty_line_index += 1;
        let record: Value = match serde_json::from_str(line) {
            Ok(record) => record,
            Err(err)
                if err.is_eof()
                    || (non_empty_line_index == non_empty_line_count && !raw.ends_with('\n')) =>
            {
                return Err(anyhow!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR));
            }
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("parse session line {} from {}", line_no + 1, path.display())
                });
            }
        };
        let timestamp = record
            .get("timestamp")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match record.get("type").and_then(Value::as_str) {
            Some("session_meta") => {
                session_matches = Some(
                    record
                        .get("payload")
                        .and_then(|payload| payload.get("id"))
                        .and_then(Value::as_str)
                        == Some(thread_id),
                );
            }
            Some("turn_context") => {
                current_turn_id = record
                    .get("payload")
                    .and_then(|payload| payload.get("turn_id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
            }
            Some("event_msg") => {
                let payload = record.get("payload").unwrap_or(&Value::Null);
                match payload.get("type").and_then(Value::as_str) {
                    Some("task_started") => {
                        current_turn_id = payload
                            .get("turn_id")
                            .and_then(Value::as_str)
                            .map(ToOwned::to_owned)
                            .or(current_turn_id);
                        if let Some(turn_id) =
                            active_turn_id(current_turn_id.as_deref(), target_turn_id)
                            && started_turns.insert(turn_id.to_string())
                        {
                            push_event(
                                &mut events,
                                &mut sequence,
                                Some(turn_id.to_string()),
                                "turn_started",
                                json!({}),
                            );
                        }
                    }
                    Some("task_complete") | Some("turn_complete") => {
                        if let Some(turn_id) = payload
                            .get("turn_id")
                            .and_then(Value::as_str)
                            .or(current_turn_id.as_deref())
                            .filter(|turn_id| turn_matches(Some(*turn_id), target_turn_id))
                            && completed_turns.insert(turn_id.to_string())
                        {
                            push_event(
                                &mut events,
                                &mut sequence,
                                Some(turn_id.to_string()),
                                "turn_completed",
                                json!({ "status": "completed" }),
                            );
                        }
                    }
                    _ => {}
                }
            }
            Some("response_item") => {
                let Some(turn_id) = active_turn_id(current_turn_id.as_deref(), target_turn_id)
                else {
                    continue;
                };
                if started_turns.insert(turn_id.to_string()) {
                    push_event(
                        &mut events,
                        &mut sequence,
                        Some(turn_id.to_string()),
                        "turn_started",
                        json!({}),
                    );
                }
                let Some(payload) = record.get("payload") else {
                    continue;
                };
                let Some(item) = normalize_response_item(payload, timestamp, &mut pending_calls)?
                else {
                    continue;
                };
                push_event(
                    &mut events,
                    &mut sequence,
                    Some(turn_id.to_string()),
                    "item_completed",
                    item,
                );
            }
            _ => {}
        }
    }

    match session_matches {
        Some(true) => {}
        Some(false) => return Ok(None),
        None if !path_matches_thread(path, thread_id) => return Ok(None),
        None => {}
    }
    if events.is_empty() {
        return Ok(None);
    }
    Ok(Some(events))
}

fn path_matches_thread(path: &Path, thread_id: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| session_file_name_matches(name, thread_id))
}

fn session_file_name_matches(file_name: &str, thread_id: &str) -> bool {
    file_name == format!("{thread_id}.jsonl") || file_name.ends_with(&format!("-{thread_id}.jsonl"))
}

fn active_turn_id<'a>(
    current_turn_id: Option<&'a str>,
    target_turn_id: Option<&str>,
) -> Option<&'a str> {
    match target_turn_id {
        Some(target_turn_id) => current_turn_id.filter(|turn_id| *turn_id == target_turn_id),
        None => current_turn_id,
    }
}

fn turn_matches(turn_id: Option<&str>, target_turn_id: Option<&str>) -> bool {
    match target_turn_id {
        Some(target_turn_id) => turn_id == Some(target_turn_id),
        None => turn_id.is_some(),
    }
}

fn push_event(
    events: &mut Vec<NewRunHistoryEvent>,
    sequence: &mut i64,
    turn_id: Option<String>,
    event_type: &str,
    payload: Value,
) {
    events.push(NewRunHistoryEvent {
        sequence: *sequence,
        turn_id,
        event_type: event_type.to_string(),
        payload,
    });
    *sequence += 1;
}

fn normalize_response_item(
    payload: &Value,
    timestamp: &str,
    pending_calls: &mut HashMap<String, PendingToolCall>,
) -> Result<Option<Value>> {
    let item_type = payload
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut item = match item_type {
        "message" => normalize_message_item(payload),
        "reasoning" => Some(payload.clone()),
        "function_call" | "custom_tool_call" => {
            if let Some(call_id) = payload.get("call_id").and_then(Value::as_str) {
                pending_calls.insert(
                    call_id.to_string(),
                    PendingToolCall {
                        name: payload
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("tool")
                            .to_string(),
                        input: parse_pending_tool_input(payload),
                    },
                );
            }
            None
        }
        "function_call_output" | "custom_tool_call_output" => {
            let call_id = payload
                .get("call_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let tool = pending_calls.remove(call_id).unwrap_or(PendingToolCall {
                name: "tool".to_string(),
                input: Value::Null,
            });
            Some(json!({
                "type": "dynamicToolCall",
                "tool": tool.name,
                "contentItems": tool.input,
                "result": parse_tool_output(payload.get("output")),
                "status": "completed"
            }))
        }
        "userMessage" | "agentMessage" | "AgentMessage" | "commandExecution" | "mcpToolCall"
        | "dynamicToolCall" | "webSearch" | "fileChange" | "contextCompaction" => {
            Some(payload.clone())
        }
        "local_shell_call" => Some(normalize_local_shell_call(payload)),
        "web_search_call" => Some(normalize_web_search_call(payload)),
        "image_generation_call" => Some(rename_item_type(payload, "imageGenerationCall")),
        "compaction" => Some(rename_item_type(payload, "contextCompaction")),
        _ => None,
    };
    if let Some(item) = item.as_mut() {
        add_timestamp(item, timestamp);
    }
    Ok(item)
}

fn normalize_message_item(payload: &Value) -> Option<Value> {
    let role = payload.get("role").and_then(Value::as_str)?;
    let content = payload.get("content").and_then(Value::as_array)?;
    match role {
        "user" => Some(json!({
            "type": "userMessage",
            "content": content
                .iter()
                .map(normalize_user_content_item)
                .collect::<Vec<_>>()
        })),
        "assistant" => {
            let normalized_content = content
                .iter()
                .map(normalize_agent_content_item)
                .collect::<Vec<_>>();
            let text = normalized_content
                .iter()
                .filter_map(|item| item.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>()
                .join("\n\n");
            let mut item = json!({
                "type": "agentMessage",
                "content": normalized_content
            });
            if let Some(phase) = payload.get("phase").and_then(Value::as_str) {
                item["phase"] = json!(phase);
            }
            if !text.is_empty() {
                item["text"] = json!(text);
            }
            Some(item)
        }
        _ => None,
    }
}

fn normalize_local_shell_call(payload: &Value) -> Value {
    let mut item = rename_item_type(payload, "commandExecution");
    copy_field(&mut item, "aggregated_output", "aggregatedOutput");
    copy_field(&mut item, "exit_code", "exitCode");
    copy_field(&mut item, "duration_ms", "durationMs");
    copy_field(&mut item, "working_directory", "cwd");
    item
}

fn normalize_web_search_call(payload: &Value) -> Value {
    let mut item = rename_item_type(payload, "webSearch");
    copy_field(&mut item, "search_query", "query");
    item
}

fn rename_item_type(payload: &Value, item_type: &str) -> Value {
    let mut item = payload.clone();
    if let Some(object) = item.as_object_mut() {
        object.insert("type".to_string(), Value::String(item_type.to_string()));
    }
    item
}

fn copy_field(item: &mut Value, from: &str, to: &str) {
    let Some(object) = item.as_object_mut() else {
        return;
    };
    if object.contains_key(to) {
        return;
    }
    if let Some(value) = object.get(from).cloned() {
        object.insert(to.to_string(), value);
    }
}

fn normalize_user_content_item(item: &Value) -> Value {
    match item.get("type").and_then(Value::as_str) {
        Some("input_text") => json!({
            "type": "text",
            "text": item.get("text").and_then(Value::as_str).unwrap_or_default()
        }),
        _ => item.clone(),
    }
}

fn normalize_agent_content_item(item: &Value) -> Value {
    match item.get("type").and_then(Value::as_str) {
        Some("output_text") => json!({
            "type": "Text",
            "text": item.get("text").and_then(Value::as_str).unwrap_or_default()
        }),
        _ => item.clone(),
    }
}

fn add_timestamp(item: &mut Value, timestamp: &str) {
    if timestamp.is_empty() {
        return;
    }
    if let Some(object) = item.as_object_mut() {
        object
            .entry("createdAt".to_string())
            .or_insert_with(|| Value::String(timestamp.to_string()));
    }
}

fn parse_pending_tool_input(payload: &Value) -> Value {
    payload
        .get("arguments")
        .and_then(Value::as_str)
        .map(parse_embedded_json)
        .or_else(|| payload.get("input").cloned())
        .unwrap_or(Value::Null)
}

fn parse_tool_output(output: Option<&Value>) -> Value {
    match output {
        Some(Value::String(text)) => parse_embedded_json(text),
        Some(value) => value.clone(),
        None => Value::Null,
    }
}

fn parse_embedded_json(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| Value::String(raw.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::env;
    use std::thread;
    use std::time::Duration;
    use uuid::Uuid;

    #[test]
    fn normalize_response_item_builds_dynamic_tool_call_from_function_pair() -> Result<()> {
        let mut pending = HashMap::new();
        let function_call = json!({
            "type": "function_call",
            "call_id": "call-1",
            "name": "exec_command",
            "arguments": "{\"cmd\":\"git status\"}"
        });
        assert_eq!(
            normalize_response_item(&function_call, "2026-03-11T10:00:00Z", &mut pending)?,
            None
        );
        let output = json!({
            "type": "function_call_output",
            "call_id": "call-1",
            "output": "{\"stdout\":\"clean\"}"
        });
        let item = normalize_response_item(&output, "2026-03-11T10:00:01Z", &mut pending)?
            .context("tool output item")?;
        assert_eq!(item["type"], "dynamicToolCall");
        assert_eq!(item["tool"], "exec_command");
        assert_eq!(item["contentItems"]["cmd"], "git status");
        assert_eq!(item["result"]["stdout"], "clean");
        assert_eq!(item["createdAt"], "2026-03-11T10:00:01Z");
        Ok(())
    }

    #[test]
    fn normalize_response_item_maps_assistant_messages() -> Result<()> {
        let mut pending = HashMap::new();
        let item = normalize_response_item(
            &json!({
                "type": "message",
                "role": "assistant",
                "phase": "commentary",
                "content": [{ "type": "output_text", "text": "Working on it." }]
            }),
            "2026-03-11T10:00:00Z",
            &mut pending,
        )?
        .context("assistant message")?;
        assert_eq!(item["type"], "agentMessage");
        assert_eq!(item["text"], "Working on it.");
        assert_eq!(item["phase"], "commentary");
        Ok(())
    }

    #[test]
    fn normalize_response_item_preserves_supported_transcript_items() -> Result<()> {
        let mut pending = HashMap::new();
        let item = normalize_response_item(
            &json!({
                "type": "commandExecution",
                "command": "cargo test",
                "aggregatedOutput": "ok",
                "status": "completed"
            }),
            "2026-03-11T10:00:00Z",
            &mut pending,
        )?
        .context("command execution item")?;
        assert_eq!(item["type"], "commandExecution");
        assert_eq!(item["command"], "cargo test");
        assert_eq!(item["aggregatedOutput"], "ok");
        Ok(())
    }

    #[test]
    fn normalize_response_item_maps_current_snake_case_transcript_items() -> Result<()> {
        let mut pending = HashMap::new();
        let shell_call = normalize_response_item(
            &json!({
                "type": "local_shell_call",
                "command": "cargo test",
                "aggregated_output": "ok",
                "exit_code": 0,
                "duration_ms": 42,
                "working_directory": "/repo"
            }),
            "2026-03-11T10:00:00Z",
            &mut pending,
        )?
        .context("local shell call item")?;
        assert_eq!(shell_call["type"], "commandExecution");
        assert_eq!(shell_call["aggregatedOutput"], "ok");
        assert_eq!(shell_call["exitCode"], 0);
        assert_eq!(shell_call["durationMs"], 42);
        assert_eq!(shell_call["cwd"], "/repo");

        let web_search = normalize_response_item(
            &json!({
                "type": "web_search_call",
                "search_query": "sqlite transcript backfill"
            }),
            "2026-03-11T10:00:01Z",
            &mut pending,
        )?
        .context("web search item")?;
        assert_eq!(web_search["type"], "webSearch");
        assert_eq!(web_search["query"], "sqlite transcript backfill");

        let image_generation = normalize_response_item(
            &json!({
                "type": "image_generation_call",
                "prompt": "diagram"
            }),
            "2026-03-11T10:00:02Z",
            &mut pending,
        )?
        .context("image generation item")?;
        assert_eq!(image_generation["type"], "imageGenerationCall");
        assert_eq!(image_generation["prompt"], "diagram");

        let compaction = normalize_response_item(
            &json!({
                "type": "compaction"
            }),
            "2026-03-11T10:00:03Z",
            &mut pending,
        )?
        .context("compaction item")?;
        assert_eq!(compaction["type"], "contextCompaction");
        Ok(())
    }

    #[test]
    fn normalize_response_item_builds_dynamic_tool_call_from_custom_tool_pair() -> Result<()> {
        let mut pending = HashMap::new();
        let function_call = json!({
            "type": "custom_tool_call",
            "call_id": "call-2",
            "name": "apply_patch",
            "input": "*** Begin Patch\n*** End Patch\n"
        });
        assert_eq!(
            normalize_response_item(&function_call, "2026-03-11T10:00:00Z", &mut pending)?,
            None
        );
        let output = json!({
            "type": "custom_tool_call_output",
            "call_id": "call-2",
            "output": {"output": "Success"}
        });
        let item = normalize_response_item(&output, "2026-03-11T10:00:01Z", &mut pending)?
            .context("custom tool output item")?;
        assert_eq!(item["type"], "dynamicToolCall");
        assert_eq!(item["tool"], "apply_patch");
        assert_eq!(item["contentItems"], "*** Begin Patch\n*** End Patch\n");
        assert_eq!(item["result"]["output"], "Success");
        Ok(())
    }

    #[test]
    fn session_file_name_matches_requires_exact_session_id_suffix() {
        assert!(session_file_name_matches(
            "rollout-2026-03-11T10-00-00-thread-123.jsonl",
            "thread-123"
        ));
        assert!(session_file_name_matches("thread-123.jsonl", "thread-123"));
        assert!(!session_file_name_matches(
            "rollout-thread-123-old.jsonl",
            "thread-123"
        ));
        assert!(!session_file_name_matches(
            "rollout-other-thread-1234.jsonl",
            "thread-123"
        ));
    }

    #[test]
    fn find_session_file_prefers_newest_matching_jsonl() -> Result<()> {
        let temp_root = env::temp_dir().join(format!(
            "codex-gitlab-review-session-history-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_root)?;
        let older = temp_root.join("archive-thread-123.jsonl");
        fs::write(&older, "")?;
        thread::sleep(Duration::from_millis(20));
        let newer = temp_root.join("thread-123.jsonl");
        fs::write(&newer, "")?;

        let selected =
            find_session_file(&temp_root, "thread-123")?.context("selected session file")?;
        assert_eq!(selected, newer);
        fs::remove_dir_all(&temp_root)?;
        Ok(())
    }

    #[test]
    fn parse_session_file_does_not_assign_pre_context_items_to_target_turn() -> Result<()> {
        let temp_root = env::temp_dir().join(format!(
            "codex-gitlab-review-session-parse-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_root)?;
        let session_file = temp_root.join("thread-123.jsonl");
        fs::write(
            &session_file,
            concat!(
                "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thread-123\"}}\n",
                "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"old turn\"}]}}\n",
                "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"turn-target\"}}\n",
                "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"target turn\"}]}}\n",
                "{\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\",\"turn_id\":\"turn-target\"}}\n"
            ),
        )?;

        let events = parse_session_file(&session_file, "thread-123", Some("turn-target"))?
            .context("parsed session events")?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(events[0].event_type, "turn_started");
        assert_eq!(events[1].payload["text"], "target turn");

        fs::remove_dir_all(&temp_root)?;
        Ok(())
    }

    #[test]
    fn parse_session_file_accepts_turn_complete_events() -> Result<()> {
        let temp_root = env::temp_dir().join(format!(
            "codex-gitlab-review-session-turn-complete-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_root)?;
        let session_file = temp_root.join("thread-123.jsonl");
        fs::write(
            &session_file,
            concat!(
                "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thread-123\"}}\n",
                "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"turn-target\"}}\n",
                "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"target turn\"}]}}\n",
                "{\"type\":\"event_msg\",\"payload\":{\"type\":\"turn_complete\",\"turn_id\":\"turn-target\"}}\n"
            ),
        )?;

        let events = parse_session_file(&session_file, "thread-123", Some("turn-target"))?
            .context("parsed session events")?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[2].event_type, "turn_completed");

        fs::remove_dir_all(&temp_root)?;
        Ok(())
    }

    #[test]
    fn parse_session_file_rejects_mismatched_session_metadata() -> Result<()> {
        let temp_root = env::temp_dir().join(format!(
            "codex-gitlab-review-session-mismatch-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_root)?;
        let session_file = temp_root.join("thread-123.jsonl");
        fs::write(
            &session_file,
            concat!(
                "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thread-other\"}}\n",
                "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"turn-target\"}}\n",
                "{\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"wrong thread\"}]}}\n",
                "{\"type\":\"event_msg\",\"payload\":{\"type\":\"turn_complete\",\"turn_id\":\"turn-target\"}}\n"
            ),
        )?;

        let events = parse_session_file(&session_file, "thread-123", Some("turn-target"))?;
        assert!(events.is_none());

        fs::remove_dir_all(&temp_root)?;
        Ok(())
    }

    #[test]
    fn parse_session_file_retries_partial_last_line() -> Result<()> {
        let temp_root = env::temp_dir().join(format!(
            "codex-gitlab-review-session-partial-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&temp_root)?;
        let session_file = temp_root.join("thread-123.jsonl");
        fs::write(
            &session_file,
            concat!(
                "{\"type\":\"session_meta\",\"payload\":{\"id\":\"thread-123\"}}\n",
                "{\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"turn-target\"}}\n",
                "{\"type\":\"response_item\",\"payload\":"
            ),
        )?;

        let error = parse_session_file(&session_file, "thread-123", Some("turn-target"))
            .expect_err("partial final line should stay retryable");
        assert_eq!(
            error.to_string(),
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
        );

        fs::remove_dir_all(&temp_root)?;
        Ok(())
    }
}

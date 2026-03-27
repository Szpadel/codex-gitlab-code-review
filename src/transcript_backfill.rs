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
pub const REVIEW_MISSING_CHILD_TURN_IDS_KEY: &str = "reviewMissingChildTurnIds";

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

#[derive(Debug)]
struct ReviewSessionCandidate {
    matched_child_turn_ids: HashSet<String>,
    filtered_events: Vec<NewRunHistoryEvent>,
    modified_at: SystemTime,
}

#[derive(Debug, Default)]
struct ParsedSessionFile {
    session_id: Option<String>,
    session_started_at: Option<String>,
    is_review_subagent: bool,
    review_child_turn_ids_by_parent: HashMap<String, HashSet<String>>,
    events: Vec<NewRunHistoryEvent>,
}

#[derive(Debug, Default)]
struct ReviewSubagentLoad {
    events: Vec<NewRunHistoryEvent>,
    missing_child_turn_ids: HashSet<String>,
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
    let Some(outer) = parse_session_file_details(&path, Some(thread_id), turn_id)? else {
        return Ok(None);
    };

    let review_mappings = review_mappings_for_turn(&outer, turn_id);
    let mut events = outer.events;
    if !review_mappings.is_empty() {
        let review_child_turn_ids = review_mappings
            .iter()
            .flat_map(|(_, child_turn_ids)| child_turn_ids.iter().cloned())
            .collect::<HashSet<_>>();
        for (parent_turn_id, child_turn_ids) in &review_mappings {
            let sibling_load = load_review_subagent_events(
                root,
                &path,
                child_turn_ids.iter().map(String::as_str).collect(),
                parent_turn_id,
            )?;
            if !sibling_load.missing_child_turn_ids.is_empty() {
                events = annotate_parent_missing_review_child_turn_ids(
                    events,
                    parent_turn_id,
                    &sibling_load.missing_child_turn_ids,
                );
            }
            if !sibling_load.events.is_empty() {
                events.extend(sibling_load.events);
            }
        }
        events = annotate_parent_review_child_turn_ids(events, &review_mappings);
        events = sort_item_events(events);
        if let Some(parent_turn_id) = turn_id {
            events = ensure_parent_turn_shape(
                events,
                parent_turn_id,
                outer.session_started_at.as_deref(),
            );
        } else {
            events = prune_empty_review_child_turns(events, &review_child_turn_ids);
        }
    }

    if events.is_empty() {
        return Ok(None);
    }
    Ok(Some(resequence_events(events)))
}

fn find_session_file(root: &Path, thread_id: &str) -> Result<Option<PathBuf>> {
    if !root.exists() {
        return Err(anyhow!(TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR));
    }
    let candidates = collect_session_files(root)?
        .into_iter()
        .filter(|candidate| {
            candidate
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| session_file_name_matches(name, thread_id))
        })
        .collect::<Vec<_>>();
    Ok(select_newest_session_file(candidates))
}

fn collect_session_files(root: &Path) -> Result<Vec<PathBuf>> {
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
            if Path::new(name)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            {
                candidates.push(candidate);
            }
        }
    }
    Ok(candidates)
}

fn select_newest_session_file(mut candidates: Vec<PathBuf>) -> Option<PathBuf> {
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
    candidates.into_iter().next()
}

#[cfg(test)]
fn parse_session_file(
    path: &Path,
    thread_id: &str,
    target_turn_id: Option<&str>,
) -> Result<Option<Vec<NewRunHistoryEvent>>> {
    Ok(
        parse_session_file_details(path, Some(thread_id), target_turn_id)?
            .map(|parsed| parsed.events),
    )
}

fn parse_session_file_details(
    path: &Path,
    expected_session_id: Option<&str>,
    target_turn_id: Option<&str>,
) -> Result<Option<ParsedSessionFile>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read session file {}", path.display()))?;
    let non_empty_line_count = raw.lines().filter(|line| !line.trim().is_empty()).count();
    let mut parsed = ParsedSessionFile::default();
    let mut current_turn_id = None::<String>;
    let mut started_turns = HashSet::<String>::new();
    let mut completed_turns = HashSet::<String>::new();
    let mut last_completed_turn_id = None::<String>;
    let mut pending_calls = HashMap::<String, PendingToolCall>::new();
    let mut in_review_wrapper = false;
    let mut active_review_child_turn_ids = HashSet::<String>::new();
    let mut review_wrapper_started_turn_ids = HashSet::<String>::new();
    let mut review_wrapper_child_turn_ids = HashSet::<String>::new();
    let mut pending_review_wrapper_items = Vec::<Value>::new();
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
                parsed.session_id = record
                    .get("payload")
                    .and_then(|payload| payload.get("id"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                parsed.session_started_at = record
                    .get("payload")
                    .and_then(|payload| payload.get("timestamp"))
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                parsed.is_review_subagent = record
                    .get("payload")
                    .and_then(|payload| payload.get("source"))
                    .and_then(|source| source.get("subagent"))
                    .and_then(Value::as_str)
                    == Some("review");
                session_matches = expected_session_id
                    .map(|thread_id| parsed.session_id.as_deref() == Some(thread_id));
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
                        if let Some(turn_id) = current_turn_id.as_deref() {
                            if in_review_wrapper && target_turn_id != Some(turn_id) {
                                if target_turn_id.is_some() {
                                    active_review_child_turn_ids.insert(turn_id.to_string());
                                } else {
                                    review_wrapper_started_turn_ids.insert(turn_id.to_string());
                                    review_wrapper_child_turn_ids.insert(turn_id.to_string());
                                }
                            }
                            if started_turns.insert(turn_id.to_string()) {
                                push_event(
                                    &mut parsed.events,
                                    Some(turn_id.to_string()),
                                    "turn_started",
                                    json!({ "createdAt": timestamp }),
                                );
                            }
                        }
                    }
                    Some("task_complete" | "turn_complete") => {
                        if let Some(turn_id) = payload
                            .get("turn_id")
                            .and_then(Value::as_str)
                            .or(current_turn_id.as_deref())
                            .filter(|turn_id| !turn_id.is_empty())
                            && completed_turns.insert(turn_id.to_string())
                        {
                            last_completed_turn_id = Some(turn_id.to_string());
                            if in_review_wrapper
                                && active_review_child_turn_ids.contains(turn_id)
                                && target_turn_id == Some(turn_id)
                            {
                                active_review_child_turn_ids.remove(turn_id);
                            }
                            let is_review_child_completion = if !in_review_wrapper {
                                false
                            } else if target_turn_id.is_some() {
                                active_review_child_turn_ids.contains(turn_id)
                            } else if review_wrapper_started_turn_ids.contains(turn_id) {
                                let completing_latest_started_turn =
                                    current_turn_id.as_deref() == Some(turn_id);
                                !(completing_latest_started_turn
                                    && review_wrapper_started_turn_ids.len() > 1)
                            } else {
                                false
                            };
                            if is_review_child_completion && target_turn_id.is_none() {
                                review_wrapper_started_turn_ids.remove(turn_id);
                            }
                            if in_review_wrapper
                                && !is_review_child_completion
                                && (target_turn_id.is_none() || target_turn_id == Some(turn_id))
                            {
                                for item in pending_review_wrapper_items.drain(..) {
                                    push_event(
                                        &mut parsed.events,
                                        Some(turn_id.to_string()),
                                        "item_completed",
                                        item,
                                    );
                                }
                                parsed
                                    .review_child_turn_ids_by_parent
                                    .entry(turn_id.to_string())
                                    .or_default()
                                    .extend(if target_turn_id.is_none() {
                                        review_wrapper_child_turn_ids
                                            .iter()
                                            .filter(|child_turn_id| {
                                                child_turn_id.as_str() != turn_id
                                            })
                                            .cloned()
                                            .collect::<HashSet<_>>()
                                    } else {
                                        active_review_child_turn_ids.clone()
                                    });
                                pending_review_wrapper_items.clear();
                                active_review_child_turn_ids = HashSet::new();
                                review_wrapper_started_turn_ids = HashSet::new();
                                review_wrapper_child_turn_ids = HashSet::new();
                                in_review_wrapper = false;
                            } else if !is_review_child_completion {
                                pending_review_wrapper_items.clear();
                                active_review_child_turn_ids = HashSet::new();
                                review_wrapper_started_turn_ids = HashSet::new();
                                review_wrapper_child_turn_ids = HashSet::new();
                                in_review_wrapper = false;
                            }
                            push_event(
                                &mut parsed.events,
                                Some(turn_id.to_string()),
                                "turn_completed",
                                json!({ "status": "completed", "createdAt": timestamp }),
                            );
                        }
                    }
                    Some("entered_review_mode") => {
                        if let Some(item) =
                            normalize_review_mode_event(payload, timestamp, "enteredReviewMode")
                        {
                            if !in_review_wrapper {
                                in_review_wrapper = true;
                                active_review_child_turn_ids.clear();
                                review_wrapper_started_turn_ids.clear();
                                review_wrapper_child_turn_ids.clear();
                                pending_review_wrapper_items.clear();
                            }
                            pending_review_wrapper_items.push(item);
                        }
                    }
                    Some("exited_review_mode") => {
                        if let Some(item) =
                            normalize_review_mode_event(payload, timestamp, "exitedReviewMode")
                            && in_review_wrapper
                        {
                            pending_review_wrapper_items.push(item);
                        }
                    }
                    Some("agent_message") => {
                        if let Some(item) = normalize_agent_message_event(payload, timestamp)
                            && in_review_wrapper
                        {
                            pending_review_wrapper_items.push(item);
                        }
                    }
                    _ => {}
                }
            }
            Some("response_item") => {
                let Some(turn_id) = current_turn_id.as_deref() else {
                    continue;
                };
                if started_turns.insert(turn_id.to_string()) {
                    push_event(
                        &mut parsed.events,
                        Some(turn_id.to_string()),
                        "turn_started",
                        json!({ "createdAt": timestamp }),
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
                    &mut parsed.events,
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
        None if expected_session_id
            .is_some_and(|thread_id| !path_matches_thread(path, thread_id)) =>
        {
            return Ok(None);
        }
        None => {}
    }
    if in_review_wrapper
        && target_turn_id.is_none()
        && !pending_review_wrapper_items.is_empty()
        && let Some(parent_turn_id) = last_completed_turn_id
    {
        for item in pending_review_wrapper_items.drain(..) {
            push_event(
                &mut parsed.events,
                Some(parent_turn_id.clone()),
                "item_completed",
                item,
            );
        }
        parsed
            .review_child_turn_ids_by_parent
            .entry(parent_turn_id.clone())
            .or_default()
            .extend(
                review_wrapper_child_turn_ids
                    .iter()
                    .filter(|child_turn_id| child_turn_id.as_str() != parent_turn_id)
                    .cloned(),
            );
    }
    parsed.events = scope_events_to_target_turn(parsed.events, target_turn_id)?;
    if parsed.events.is_empty() && parsed.review_child_turn_ids_by_parent.is_empty() {
        return Ok(None);
    }
    Ok(Some(parsed))
}

fn review_mappings_for_turn(
    parsed: &ParsedSessionFile,
    target_turn_id: Option<&str>,
) -> Vec<(String, HashSet<String>)> {
    match target_turn_id {
        Some(turn_id) => parsed
            .review_child_turn_ids_by_parent
            .get(turn_id)
            .cloned()
            .map(|child_turn_ids| vec![(turn_id.to_string(), child_turn_ids)])
            .unwrap_or_default(),
        None => parsed
            .review_child_turn_ids_by_parent
            .iter()
            .map(|(parent_turn_id, child_turn_ids)| {
                (parent_turn_id.clone(), child_turn_ids.clone())
            })
            .collect(),
    }
}

fn scope_events_to_target_turn(
    events: Vec<NewRunHistoryEvent>,
    target_turn_id: Option<&str>,
) -> Result<Vec<NewRunHistoryEvent>> {
    let Some(target_turn_id) = target_turn_id else {
        return Ok(resequence_events(events));
    };

    let direct_events = events
        .iter()
        .filter(|event| event.turn_id.as_deref() == Some(target_turn_id))
        .cloned()
        .collect::<Vec<_>>();
    Ok(resequence_events(direct_events))
}

fn resequence_events(events: Vec<NewRunHistoryEvent>) -> Vec<NewRunHistoryEvent> {
    events
        .into_iter()
        .enumerate()
        .map(|(index, mut event)| {
            event.sequence = i64::try_from(index + 1).expect("event sequence");
            event
        })
        .collect()
}

fn path_matches_thread(path: &Path, thread_id: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| session_file_name_matches(name, thread_id))
}

fn session_file_name_matches(file_name: &str, thread_id: &str) -> bool {
    file_name == format!("{thread_id}.jsonl") || file_name.ends_with(&format!("-{thread_id}.jsonl"))
}

fn push_event(
    events: &mut Vec<NewRunHistoryEvent>,
    turn_id: Option<String>,
    event_type: &str,
    payload: Value,
) {
    events.push(NewRunHistoryEvent {
        sequence: i64::try_from(events.len() + 1).expect("event sequence"),
        turn_id,
        event_type: event_type.to_string(),
        payload,
    });
}

fn normalize_review_mode_event(payload: &Value, timestamp: &str, item_type: &str) -> Option<Value> {
    let review = match item_type {
        "enteredReviewMode" => payload
            .get("user_facing_hint")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| payload.get("target").map(compact_json)),
        "exitedReviewMode" => payload
            .get("review_output")
            .and_then(|review| review.get("overall_explanation"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| payload.get("review_output").map(compact_json)),
        _ => None,
    }?;
    let mut item = json!({
        "type": item_type,
        "review": review,
    });
    add_timestamp(&mut item, timestamp);
    Some(item)
}

fn normalize_agent_message_event(payload: &Value, timestamp: &str) -> Option<Value> {
    let text = payload.get("message").and_then(Value::as_str)?;
    let mut item = json!({
        "type": "agentMessage",
        "text": text,
        "content": [{ "type": "Text", "text": text }],
    });
    if let Some(phase) = payload.get("phase").and_then(Value::as_str) {
        item["phase"] = json!(phase);
    }
    add_timestamp(&mut item, timestamp);
    Some(item)
}

fn load_review_subagent_events(
    root: &Path,
    outer_path: &Path,
    child_turn_ids: Vec<&str>,
    parent_turn_id: &str,
) -> Result<ReviewSubagentLoad> {
    if child_turn_ids.is_empty() {
        return Ok(ReviewSubagentLoad::default());
    }
    let matching_paths = collect_session_files(root)?
        .into_iter()
        .filter(|candidate| candidate != outer_path)
        .collect::<Vec<_>>();
    let mut matching_paths = matching_paths;
    matching_paths.sort_by(|left, right| {
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

    let mut matching_review_session_events = Vec::new();
    let mut review_session_candidates = HashMap::<String, ReviewSessionCandidate>::new();
    let mut unmatched_child_turn_ids = child_turn_ids
        .iter()
        .map(|turn_id| (*turn_id).to_string())
        .collect::<HashSet<_>>();
    for candidate in matching_paths {
        let candidate_modified = fs::metadata(&candidate)
            .and_then(|metadata| metadata.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let parsed = match parse_session_file_details(&candidate, None, None) {
            Ok(Some(parsed)) => parsed,
            Ok(None) => continue,
            Err(err) if err.to_string() == TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR => {
                let _ = raw_session_file_might_match_review_sibling(&candidate, &child_turn_ids)?;
                continue;
            }
            Err(err) => return Err(err),
        };
        if !parsed.is_review_subagent {
            continue;
        }
        if !parsed.events.iter().any(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| child_turn_ids.contains(&turn_id))
        }) {
            continue;
        }
        let matched_child_turn_ids = parsed
            .events
            .iter()
            .filter(|event| {
                event
                    .turn_id
                    .as_deref()
                    .is_some_and(|turn_id| child_turn_ids.contains(&turn_id))
            })
            .filter(|event| review_subagent_event_has_review_content(event))
            .filter_map(|event| event.turn_id.clone())
            .collect::<HashSet<_>>();
        if matched_child_turn_ids.is_empty() {
            continue;
        }
        let filtered_events =
            filter_review_subagent_events(parsed.events, &child_turn_ids, parent_turn_id);
        if filtered_events.is_empty() {
            continue;
        }
        if let Some(session_id) = parsed.session_id {
            let candidate = ReviewSessionCandidate {
                matched_child_turn_ids,
                filtered_events,
                modified_at: candidate_modified,
            };
            match review_session_candidates.entry(session_id) {
                std::collections::hash_map::Entry::Occupied(mut entry) => {
                    if review_session_candidate_is_better(&candidate, entry.get()) {
                        entry.insert(candidate);
                    }
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(candidate);
                }
            }
        } else {
            unmatched_child_turn_ids
                .retain(|child_turn_id| !matched_child_turn_ids.contains(child_turn_id));
            matching_review_session_events.push(filtered_events);
        }
    }

    for candidate in review_session_candidates.into_values() {
        unmatched_child_turn_ids
            .retain(|child_turn_id| !candidate.matched_child_turn_ids.contains(child_turn_id));
        matching_review_session_events.push(candidate.filtered_events);
    }

    if matching_review_session_events.is_empty() {
        return Ok(ReviewSubagentLoad {
            events: Vec::new(),
            missing_child_turn_ids: unmatched_child_turn_ids,
        });
    }
    Ok(ReviewSubagentLoad {
        events: sort_item_events(
            matching_review_session_events
                .into_iter()
                .flatten()
                .collect::<Vec<_>>(),
        ),
        missing_child_turn_ids: unmatched_child_turn_ids,
    })
}

fn raw_session_file_might_match_review_sibling(
    path: &Path,
    child_turn_ids: &[&str],
) -> Result<bool> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read session file {}", path.display()))?;
    Ok(raw_session_file_looks_like_review_subagent(&raw)
        && (child_turn_ids.is_empty()
            || child_turn_ids.iter().any(|turn_id| raw.contains(turn_id))))
}

fn raw_session_file_looks_like_review_subagent(raw: &str) -> bool {
    raw.contains("\"subagent\":\"review\"") || raw.contains("\"subagent\": \"review\"")
}

fn review_session_candidate_is_better(
    candidate: &ReviewSessionCandidate,
    existing: &ReviewSessionCandidate,
) -> bool {
    candidate.matched_child_turn_ids.len() > existing.matched_child_turn_ids.len()
        || (candidate.matched_child_turn_ids.len() == existing.matched_child_turn_ids.len()
            && candidate.filtered_events.len() > existing.filtered_events.len())
        || (candidate.matched_child_turn_ids.len() == existing.matched_child_turn_ids.len()
            && candidate.filtered_events.len() == existing.filtered_events.len()
            && candidate.modified_at > existing.modified_at)
}

fn filter_review_subagent_events(
    events: Vec<NewRunHistoryEvent>,
    child_turn_ids: &[&str],
    parent_turn_id: &str,
) -> Vec<NewRunHistoryEvent> {
    events
        .into_iter()
        .filter(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| child_turn_ids.contains(&turn_id))
        })
        .filter(review_subagent_event_is_renderable)
        .map(|mut event| {
            event.turn_id = Some(parent_turn_id.to_string());
            event
        })
        .collect()
}

fn review_subagent_event_is_renderable(event: &NewRunHistoryEvent) -> bool {
    event.event_type == "item_completed"
        && !matches!(
            event.payload.get("type").and_then(Value::as_str),
            Some("userMessage")
        )
}

fn review_subagent_event_has_review_content(event: &NewRunHistoryEvent) -> bool {
    event.event_type == "item_completed"
        && matches!(
            event.payload.get("type").and_then(Value::as_str),
            Some("agentMessage" | "AgentMessage" | "reasoning" | "exitedReviewMode")
        )
}

fn annotate_parent_review_child_turn_ids(
    mut events: Vec<NewRunHistoryEvent>,
    review_mappings: &[(String, HashSet<String>)],
) -> Vec<NewRunHistoryEvent> {
    for (parent_turn_id, child_turn_ids) in review_mappings {
        if child_turn_ids.is_empty() {
            continue;
        }
        let mut child_turn_ids = child_turn_ids.iter().cloned().collect::<Vec<_>>();
        child_turn_ids.sort();
        let child_turn_ids_value = json!(child_turn_ids);
        for event in events.iter_mut().filter(|event| {
            event.turn_id.as_deref() == Some(parent_turn_id.as_str())
                && event.event_type == "item_completed"
        }) {
            if let Some(object) = event.payload.as_object_mut() {
                object.insert(
                    "reviewChildTurnIds".to_string(),
                    child_turn_ids_value.clone(),
                );
            }
        }
    }
    events
}

fn annotate_parent_missing_review_child_turn_ids(
    mut events: Vec<NewRunHistoryEvent>,
    parent_turn_id: &str,
    missing_child_turn_ids: &HashSet<String>,
) -> Vec<NewRunHistoryEvent> {
    if missing_child_turn_ids.is_empty() {
        return events;
    }
    let mut missing_child_turn_ids = missing_child_turn_ids.iter().cloned().collect::<Vec<_>>();
    missing_child_turn_ids.sort();
    let missing_child_turn_ids_value = json!(missing_child_turn_ids);
    for event in events.iter_mut().filter(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.event_type == "item_completed"
            && parent_turn_item_can_carry_missing_review_child_marker(event)
    }) {
        if let Some(object) = event.payload.as_object_mut() {
            object.insert(
                REVIEW_MISSING_CHILD_TURN_IDS_KEY.to_string(),
                missing_child_turn_ids_value.clone(),
            );
        }
    }
    events
}

fn parent_turn_item_can_carry_missing_review_child_marker(event: &NewRunHistoryEvent) -> bool {
    match event.payload.get("type").and_then(Value::as_str) {
        Some("enteredReviewMode" | "exitedReviewMode") => true,
        Some("agentMessage") => {
            event
                .payload
                .get("text")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty())
                && event
                    .payload
                    .get("phase")
                    .is_none_or(serde_json::Value::is_null)
        }
        _ => false,
    }
}

fn sort_item_events(events: Vec<NewRunHistoryEvent>) -> Vec<NewRunHistoryEvent> {
    let mut indexed = events.into_iter().enumerate().collect::<Vec<_>>();
    indexed.sort_by(|(left_index, left), (right_index, right)| {
        event_timestamp(left)
            .cmp(&event_timestamp(right))
            .then_with(|| left_index.cmp(right_index))
    });
    indexed.into_iter().map(|(_, event)| event).collect()
}

fn event_timestamp(event: &NewRunHistoryEvent) -> Option<&str> {
    event.payload.get("createdAt").and_then(Value::as_str)
}

fn ensure_parent_turn_shape(
    events: Vec<NewRunHistoryEvent>,
    parent_turn_id: &str,
    default_timestamp: Option<&str>,
) -> Vec<NewRunHistoryEvent> {
    let mut items = events
        .into_iter()
        .filter(|event| event.turn_id.as_deref() == Some(parent_turn_id))
        .collect::<Vec<_>>();
    let turn_completed = items
        .iter()
        .rfind(|event| event.event_type == "turn_completed")
        .cloned();
    items.retain(|event| event.event_type == "item_completed");
    if items.is_empty() && turn_completed.is_none() {
        return Vec::new();
    }

    let mut normalized = Vec::new();
    let start_timestamp = items
        .iter()
        .find_map(event_timestamp)
        .or(default_timestamp)
        .unwrap_or_default();
    push_event(
        &mut normalized,
        Some(parent_turn_id.to_string()),
        "turn_started",
        json!({ "createdAt": start_timestamp }),
    );
    normalized.extend(items);
    if let Some(mut completed) = turn_completed {
        completed.turn_id = Some(parent_turn_id.to_string());
        normalized.push(completed);
    }
    normalized
}

fn prune_empty_review_child_turns(
    events: Vec<NewRunHistoryEvent>,
    child_turn_ids: &HashSet<String>,
) -> Vec<NewRunHistoryEvent> {
    if child_turn_ids.is_empty() {
        return events;
    }
    let empty_child_turn_ids = child_turn_ids
        .iter()
        .filter(|turn_id| {
            let turn_events = events
                .iter()
                .filter(|event| event.turn_id.as_deref() == Some(turn_id.as_str()))
                .collect::<Vec<_>>();
            !turn_events.is_empty()
                && turn_events
                    .iter()
                    .all(|event| event.event_type != "item_completed")
        })
        .cloned()
        .collect::<HashSet<_>>();
    if empty_child_turn_ids.is_empty() {
        return events;
    }
    events
        .into_iter()
        .filter(|event| {
            !event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| empty_child_turn_ids.contains(turn_id))
        })
        .collect()
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

fn compact_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests;

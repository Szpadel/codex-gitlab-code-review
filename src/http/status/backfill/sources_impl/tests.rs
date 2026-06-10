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

fn sorted_item_types(events: &[NewRunHistoryEvent]) -> Vec<&str> {
    let mut item_types = events
        .iter()
        .filter(|event| event.event_type == "item_completed")
        .map(|event| event.payload["type"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    item_types.sort_unstable();
    item_types
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

    let selected = find_session_file(&temp_root, "thread-123")?.context("selected session file")?;
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

#[test]
fn load_events_from_root_merges_outer_review_wrapper_with_sibling_review_session() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-merge-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer =
        temp_root.join("rollout-2026-03-11T21-29-59-019cdece-7b5f-7bd2-9f3c-37451f58c376.jsonl");
    fs::write(
        &outer,
        concat!(
            "{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019cdece-7b5f-7bd2-9f3c-37451f58c376\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"entered_review_mode\",\"target\":{\"type\":\"baseBranch\",\"branch\":\"master\"},\"user_facing_hint\":\"changes against 'master'\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_started\",\"turn_id\":\"019cdece-7b7f-7e42-a4aa-67ac17f228bd\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"agent_message\",\"message\":\"The patch is correct.\",\"phase\":null}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"exited_review_mode\",\"review_output\":{\"overall_explanation\":\"The patch is correct.\"}}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\",\"turn_id\":\"019cdece-7b69-7a72-9428-d501f13fd0e3\"}}\n"
        ),
    )?;

    let sibling =
        temp_root.join("rollout-2026-03-11T21-29-59-019cdece-7b77-75a1-9ef8-c646a8bc3857.jsonl");
    fs::write(
        &sibling,
        concat!(
            "{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019cdece-7b77-75a1-9ef8-c646a8bc3857\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{\"subagent\":\"review\"}}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_started\",\"turn_id\":\"019cdece-7b7f-7e42-a4aa-67ac17f228bd\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{\"turn_id\":\"019cdece-7b7f-7e42-a4aa-67ac17f228bd\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"reasoning\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"Reasoning summary\"}],\"content\":[{\"type\":\"reasoning_text\",\"text\":\"Reasoning detail.\"}]}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:21.658Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"call_id\":\"call-1\",\"name\":\"exec_command\",\"arguments\":\"{\\\"cmd\\\":\\\"git diff\\\"}\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:21.871Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call_output\",\"call_id\":\"call-1\",\"output\":\"{\\\"stdout\\\":\\\"diff output\\\"}\"}}\n",
            "{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"task_complete\",\"turn_id\":\"019cdece-7b7f-7e42-a4aa-67ac17f228bd\"}}\n"
        ),
    )?;

    let events = load_events_from_root(
        &temp_root,
        "019cdece-7b5f-7bd2-9f3c-37451f58c376",
        Some("019cdece-7b69-7a72-9428-d501f13fd0e3"),
    )?
    .context("merged transcript backfill events")?;

    assert!(
        events.iter().all(|event| {
            event.turn_id.as_deref() == Some("019cdece-7b69-7a72-9428-d501f13fd0e3")
        })
    );
    assert_eq!(
        events.first().map(|event| event.event_type.as_str()),
        Some("turn_started")
    );
    assert_eq!(
        sorted_item_types(&events),
        vec![
            "agentMessage",
            "dynamicToolCall",
            "enteredReviewMode",
            "exitedReviewMode",
            "reasoning",
        ]
    );
    assert_eq!(
        events
            .iter()
            .find(|event| event.payload["type"] == "dynamicToolCall")
            .context("dynamic tool call item")?
            .payload["result"]["stdout"],
        json!("diff output")
    );
    assert_eq!(
        events.last().map(|event| event.event_type.as_str()),
        Some("turn_completed")
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_review_wrapper_state_after_child_completion() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-child-complete-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Outer wrapper summary.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"reasoning\",\"summary\":[{{\"type\":\"summary_text\",\"text\":\"Reasoning summary\"}}],\"content\":[]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert_eq!(
        sorted_item_types(&events),
        vec!["agentMessage", "enteredReviewMode", "reasoning"]
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_renderable_wrapper_items_when_review_sibling_is_missing()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-missing-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Wrapper-only review message.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"exited_review_mode\",\"review_output\":{{\"overall_explanation\":\"Wrapper-only summary.\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("wrapper-only transcript backfill events")?;

    assert!(
        events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some(parent_turn_id))
    );
    assert_eq!(
        sorted_item_types(&events),
        vec!["agentMessage", "enteredReviewMode", "exitedReviewMode"]
    );
    assert!(events.iter().any(|event| {
        event.payload["type"] == "enteredReviewMode"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id])
    }));
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Wrapper-only review message."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_final_wrapper_agent_message_without_exited_review_mode() -> Result<()>
{
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-wrapper-final-message-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Wrapper final review message.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("wrapper final-message transcript backfill events")?;

    assert!(
        events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some(parent_turn_id))
    );
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id])
    }));
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Wrapper final review message."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_missing_marker_when_some_review_siblings_are_still_missing()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-partial-wrapper-fallback-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let child_turn_id_two = "019cdece-7b7f-7e42-a4aa-67ac17f228be";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Wrapper final review message.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.166Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id_one = child_turn_id_one,
            child_turn_id_two = child_turn_id_two,
            parent_turn_id = parent_turn_id,
        ),
    )?;
    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}-review-child-one.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"review-child-one\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"reasoning\",\"summary\":[{{\"type\":\"summary_text\",\"text\":\"Reasoning summary\"}}],\"content\":[]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n"
            ),
            child_turn_id_one = child_turn_id_one,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("partial wrapper fallback transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "enteredReviewMode"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id_two])
    }));
    assert!(!events.iter().any(|event| {
        event.payload["type"] == "reasoning"
            && event.payload.get("reviewMissingChildTurnIds").is_some()
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_marks_wrapper_without_renderable_output_as_waiting_for_review_sibling()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-missing-sibling-pending-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Review still running\",\"phase\":\"analysis\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("pending wrapper-only transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "enteredReviewMode"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id])
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_missing_marker_for_tool_only_review_sibling() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-tool-only-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Wrapper final review message.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;
    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"commandExecution\",\"command\":\"git diff\",\"aggregatedOutput\":\"diff --git a/file b/file\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("tool-only review sibling transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id])
    }));
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Wrapper final review message."
    }));
    assert!(!events.iter().any(|event| {
        event.payload["type"] == "commandExecution" && event.payload["command"] == "git diff"
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_parent_wrapper_items_with_multiple_review_children() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-multi-child-parent-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let child_turn_id_two = "019cdece-7b80-76f1-a1bb-d4950ec0a1be";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"agent_message\",\"message\":\"Wrapper summary.\",\"phase\":null}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"exited_review_mode\",\"review_output\":{{\"overall_explanation\":\"Wrapper explanation.\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.166Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.167Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.168Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            parent_turn_id = parent_turn_id,
            child_turn_id_one = child_turn_id_one,
            child_turn_id_two = child_turn_id_two,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, None)?
        .context("full-thread multi-child wrapper events")?;

    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "enteredReviewMode"
    }));
    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Wrapper summary."
    }));
    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "exitedReviewMode"
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_marks_partially_missing_review_siblings_for_wrapper_fallback() -> Result<()>
{
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-partial-siblings-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let child_turn_id_two = "019cdece-7b91-7b11-ae35-f44c60c590cb";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id_one = child_turn_id_one,
            child_turn_id_two = child_turn_id_two,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"reasoning\",\"summary\":[{{\"type\":\"summary_text\",\"text\":\"First sibling reasoning\"}}],\"content\":[{{\"type\":\"reasoning_text\",\"text\":\"First sibling detail\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id_one = child_turn_id_one,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("partial review sibling transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "reasoning"
            && event.payload["content"][0]["text"] == "First sibling detail"
    }));
    assert!(events.iter().any(|event| {
        event.payload["type"] == "enteredReviewMode"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id_two])
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_empty_review_sibling_marked_as_missing() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-empty-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"user\",\"content\":[{{\"type\":\"input_text\",\"text\":\"ignored\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("empty review sibling transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "enteredReviewMode"
            && event.payload["reviewMissingChildTurnIds"] == json!([child_turn_id])
    }));
    assert!(
        !events
            .iter()
            .any(|event| event.payload["type"] == "userMessage")
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_merges_review_child_ids_across_multiple_wrapper_segments() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-multi-wrapper-parent-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let child_turn_id_two = "019cdece-7b80-76f1-a1bb-d4950ec0a1be";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"first segment\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"exited_review_mode\",\"review_output\":{{\"overall_explanation\":\"first explanation\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"second segment\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.166Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"exited_review_mode\",\"review_output\":{{\"overall_explanation\":\"second explanation\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.167Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            parent_turn_id = parent_turn_id,
            child_turn_id_one = child_turn_id_one,
            child_turn_id_two = child_turn_id_two,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("multi-wrapper parent events")?;

    let review_child_turn_ids = events
        .iter()
        .find_map(|event| event.payload.get("reviewChildTurnIds"))
        .and_then(Value::as_array)
        .cloned()
        .context("review child turn ids on parent event")?;
    assert_eq!(
        review_child_turn_ids,
        vec![json!(child_turn_id_one), json!(child_turn_id_two)]
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_keeps_agent_message_from_review_sibling_session() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-agent-message-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert_eq!(
        sorted_item_types(&events),
        vec!["agentMessage", "enteredReviewMode"]
    );
    assert_eq!(
        events
            .iter()
            .find(|event| event.payload["type"] == "agentMessage")
            .context("agent message item")?
            .payload["text"],
        json!("Sibling-only review summary.")
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_merges_plain_named_review_sibling_sessions() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-plain-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!("{outer_thread_id}.jsonl"));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!("{sibling_thread_id}.jsonl"));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_ignores_unrelated_partial_review_sibling_without_turn_id() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-unrelated-partial-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let unrelated_sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3858";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let unrelated_partial = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{unrelated_sibling_thread_id}.jsonl"
    ));
    fs::write(
        &unrelated_partial,
        concat!(
            "{\"timestamp\":\"2026-03-11T21:30:14.247Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019cdece-7b77-75a1-9ef8-c646a8bc3858\",\"timestamp\":\"2026-03-11T21:29:59.931Z\",\"cwd\":\"/work/repo\",\"source\":{\"subagent\":\"review\"}}}\n",
            "{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"response_item\",\"payload\":"
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_prunes_empty_review_child_turns_for_full_thread_backfill() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-full-thread-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, None)?
        .context("merged transcript backfill events")?;

    assert!(
        !events
            .iter()
            .any(|event| { event.turn_id.as_deref() == Some(child_turn_id) })
    );
    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id) && event.payload["type"] == "agentMessage"
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_merges_multiple_review_sibling_sessions() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-multi-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let child_turn_id_two = "019cdece-7b80-76f1-a1bb-d4950ec0a1be";
    let sibling_thread_id_one = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let sibling_thread_id_two = "019cdece-7b77-75a1-9ef8-c646a8bc3858";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id_one = child_turn_id_one,
            child_turn_id_two = child_turn_id_two,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling_one = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_one}.jsonl"
    ));
    fs::write(
        &sibling_one,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_one}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"reasoning\",\"summary\":[{{\"type\":\"summary_text\",\"text\":\"First summary\"}}],\"content\":[]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n"
            ),
            sibling_thread_id_one = sibling_thread_id_one,
            child_turn_id_one = child_turn_id_one,
        ),
    )?;

    let sibling_two = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_two}.jsonl"
    ));
    fs::write(
        &sibling_two,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:14.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_two}\",\"timestamp\":\"2026-03-11T21:29:59.931Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:19.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Second sibling summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n"
            ),
            sibling_thread_id_two = sibling_thread_id_two,
            child_turn_id_two = child_turn_id_two,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert_eq!(
        sorted_item_types(&events),
        vec!["agentMessage", "enteredReviewMode", "reasoning"]
    );
    assert_eq!(
        events
            .iter()
            .find(|event| event.payload["type"] == "agentMessage")
            .context("agent message item")?
            .payload["text"],
        json!("Second sibling summary.")
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_uses_matching_review_wrapper_for_earlier_parent_turn() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-multi-wrapper-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id_one = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let parent_turn_id_two = "019cdece-7b90-74c2-a6dd-66ca79a92c14";
    let child_turn_id_two = "019cdece-7b91-7b11-ae35-f44c60c590cb";
    let sibling_thread_id_one = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let sibling_thread_id_two = "019cdece-7b77-75a1-9ef8-c646a8bc3858";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"first wrapper\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"second wrapper\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.165Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.166Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id_two}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id_one = child_turn_id_one,
            parent_turn_id_one = parent_turn_id_one,
            child_turn_id_two = child_turn_id_two,
            parent_turn_id_two = parent_turn_id_two,
        ),
    )?;

    let sibling_one = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_one}.jsonl"
    ));
    fs::write(
        &sibling_one,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_one}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"First sibling summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n"
            ),
            sibling_thread_id_one = sibling_thread_id_one,
            child_turn_id_one = child_turn_id_one,
        ),
    )?;

    let sibling_two = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_two}.jsonl"
    ));
    fs::write(
        &sibling_two,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:14.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_two}\",\"timestamp\":\"2026-03-11T21:29:59.931Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:19.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Second sibling summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n"
            ),
            sibling_thread_id_two = sibling_thread_id_two,
            child_turn_id_two = child_turn_id_two,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id_one))?
        .context("merged transcript backfill events")?;

    assert!(
        events
            .iter()
            .all(|event| { event.turn_id.as_deref() == Some(parent_turn_id_one) })
    );
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage" && event.payload["text"] == "First sibling summary."
    }));
    assert!(
        !events
            .iter()
            .any(|event| { event.payload["text"] == "Second sibling summary." })
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_preserves_review_wrapper_chronology_for_full_thread_backfill() -> Result<()>
{
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-wrapper-chronology-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id_one = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id_one = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let parent_turn_id_two = "019cdece-7b90-74c2-a6dd-66ca79a92c14";
    let child_turn_id_two = "019cdece-7b91-7b11-ae35-f44c60c590cb";
    let sibling_thread_id_one = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let sibling_thread_id_two = "019cdece-7b77-75a1-9ef8-c646a8bc3858";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"first wrapper\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"second wrapper\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id_two}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id_one = child_turn_id_one,
            parent_turn_id_one = parent_turn_id_one,
            child_turn_id_two = child_turn_id_two,
            parent_turn_id_two = parent_turn_id_two,
        ),
    )?;

    let sibling_one = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_one}.jsonl"
    ));
    fs::write(
        &sibling_one,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_one}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_one}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"First sibling summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_one}\"}}}}\n"
            ),
            sibling_thread_id_one = sibling_thread_id_one,
            child_turn_id_one = child_turn_id_one,
        ),
    )?;

    let sibling_two = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id_two}.jsonl"
    ));
    fs::write(
        &sibling_two,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:14.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id_two}\",\"timestamp\":\"2026-03-11T21:29:59.931Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:14.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id_two}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:19.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Second sibling summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:38.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id_two}\"}}}}\n"
            ),
            sibling_thread_id_two = sibling_thread_id_two,
            child_turn_id_two = child_turn_id_two,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, None)?
        .context("merged transcript backfill events")?;
    let wrapper_reviews = events
        .iter()
        .filter(|event| event.payload["type"] == "enteredReviewMode")
        .map(|event| event.payload["review"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();

    assert_eq!(wrapper_reviews, vec!["first wrapper", "second wrapper"]);

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_treats_parent_task_started_inside_wrapper_as_parent() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-parent-started-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{parent_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_full_thread_treats_parent_task_started_inside_wrapper_as_parent()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-parent-started-full-thread-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{parent_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, None)?
        .context("full-thread merged transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));
    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "enteredReviewMode"
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_full_thread_keeps_parent_wrapper_items_with_later_turns() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-parent-started-full-thread-later-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let later_turn_id = "019cdece-7b90-74c2-a6dd-66ca79a92c14";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{parent_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.164Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:40:00.000Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{later_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:40:01.000Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Later turn message.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:40:02.000Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{later_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
            later_turn_id = later_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, None)?
        .context("full-thread merged transcript backfill events with later turn")?;

    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some(parent_turn_id)
            && event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));
    assert!(!events.iter().any(|event| {
        event.turn_id.as_deref() == Some(later_turn_id)
            && event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_review_subagent_events_deduplicates_duplicate_session_files() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-dedup-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling_payload = format!(
        concat!(
            "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
        ),
        sibling_thread_id = sibling_thread_id,
        child_turn_id = child_turn_id,
    );
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
        )),
        &sibling_payload,
    )?;
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-copy-{sibling_thread_id}.jsonl"
        )),
        &sibling_payload,
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;
    let agent_messages = events
        .iter()
        .filter(|event| event.payload["type"] == "agentMessage")
        .count();

    assert_eq!(agent_messages, 1);

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_review_subagent_events_prefers_older_complete_copy_over_newer_partial_duplicate()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-dedup-partial-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let complete_sibling_payload = format!(
        concat!(
            "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
        ),
        sibling_thread_id = sibling_thread_id,
        child_turn_id = child_turn_id,
    );
    let partial_sibling_payload = format!(
        concat!(
            "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n"
        ),
        sibling_thread_id = sibling_thread_id,
        child_turn_id = child_turn_id,
    );
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
        )),
        &complete_sibling_payload,
    )?;
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-copy-{sibling_thread_id}.jsonl"
        )),
        &partial_sibling_payload,
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events with partial duplicate sibling")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));
    assert!(
        events
            .iter()
            .all(|event| { event.payload.get("reviewMissingChildTurnIds").is_none() })
    );

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_review_subagent_events_prefers_more_complete_older_copy_over_newer_partial_renderable_duplicate()
-> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-dedup-renderable-partial-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let complete_sibling_payload = format!(
        concat!(
            "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Older complete sibling summary.\"}}]}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:19.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Older complete sibling detail.\"}}]}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
        ),
        sibling_thread_id = sibling_thread_id,
        child_turn_id = child_turn_id,
    );
    let partial_sibling_payload = format!(
        concat!(
            "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
            "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Newer partial sibling summary.\"}}]}}}}\n"
        ),
        sibling_thread_id = sibling_thread_id,
        child_turn_id = child_turn_id,
    );
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
        )),
        &complete_sibling_payload,
    )?;
    fs::write(
        temp_root.join(format!(
            "rollout-2026-03-11T21-29-59-copy-{sibling_thread_id}.jsonl"
        )),
        &partial_sibling_payload,
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events with renderable partial duplicate sibling")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Older complete sibling summary."
    }));
    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Older complete sibling detail."
    }));
    assert!(!events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Newer partial sibling summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_finds_review_siblings_when_outer_file_is_a_copy() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-copy-outer-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-copy-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Sibling-only review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Sibling-only review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_finds_plain_named_review_siblings_for_rollout_named_outer() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-plain-sibling-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!("{sibling_thread_id}.jsonl"));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:30:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:30:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Plain sibling review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events with plain sibling session")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Plain sibling review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

#[test]
fn load_events_from_root_finds_review_siblings_with_different_rollout_prefix() -> Result<()> {
    let temp_root = env::temp_dir().join(format!(
        "codex-gitlab-review-session-mixed-rollout-prefix-{}",
        Uuid::new_v4()
    ));
    fs::create_dir_all(&temp_root)?;

    let outer_thread_id = "019cdece-7b5f-7bd2-9f3c-37451f58c376";
    let parent_turn_id = "019cdece-7b69-7a72-9428-d501f13fd0e3";
    let child_turn_id = "019cdece-7b7f-7e42-a4aa-67ac17f228bd";
    let sibling_thread_id = "019cdece-7b77-75a1-9ef8-c646a8bc3857";
    let outer = temp_root.join(format!(
        "rollout-2026-03-11T21-29-59-{outer_thread_id}.jsonl"
    ));
    fs::write(
        &outer,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:32:37.160Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{outer_thread_id}\",\"timestamp\":\"2026-03-11T21:29:59.906Z\",\"cwd\":\"/work/repo\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.161Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"entered_review_mode\",\"target\":{{\"type\":\"baseBranch\",\"branch\":\"master\"}},\"user_facing_hint\":\"changes against 'master'\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.162Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:32:37.163Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{parent_turn_id}\"}}}}\n"
            ),
            outer_thread_id = outer_thread_id,
            child_turn_id = child_turn_id,
            parent_turn_id = parent_turn_id,
        ),
    )?;

    let sibling = temp_root.join(format!(
        "rollout-2026-03-11T21-45-00-{sibling_thread_id}.jsonl"
    ));
    fs::write(
        &sibling,
        format!(
            concat!(
                "{{\"timestamp\":\"2026-03-11T21:45:13.247Z\",\"type\":\"session_meta\",\"payload\":{{\"id\":\"{sibling_thread_id}\",\"timestamp\":\"2026-03-11T21:45:00.930Z\",\"cwd\":\"/work/repo\",\"source\":{{\"subagent\":\"review\"}}}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:45:13.248Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_started\",\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:45:13.248Z\",\"type\":\"turn_context\",\"payload\":{{\"turn_id\":\"{child_turn_id}\"}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:45:18.270Z\",\"type\":\"response_item\",\"payload\":{{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{{\"type\":\"output_text\",\"text\":\"Mixed-prefix sibling review summary.\"}}]}}}}\n",
                "{{\"timestamp\":\"2026-03-11T21:45:37.153Z\",\"type\":\"event_msg\",\"payload\":{{\"type\":\"task_complete\",\"turn_id\":\"{child_turn_id}\"}}}}\n"
            ),
            sibling_thread_id = sibling_thread_id,
            child_turn_id = child_turn_id,
        ),
    )?;

    let events = load_events_from_root(&temp_root, outer_thread_id, Some(parent_turn_id))?
        .context("merged transcript backfill events with mixed rollout prefixes")?;

    assert!(events.iter().any(|event| {
        event.payload["type"] == "agentMessage"
            && event.payload["text"] == "Mixed-prefix sibling review summary."
    }));

    fs::remove_dir_all(&temp_root)?;
    Ok(())
}

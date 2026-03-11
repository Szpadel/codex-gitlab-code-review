use crate::config::Config;
use crate::state::{
    NewRunHistory, NewRunHistoryEvent, ReviewStateStore, RunHistoryFinish, RunHistoryKind,
    RunHistoryRecord, RunHistorySessionUpdate,
};
use anyhow::{Context, Result};
use chrono::{Duration, SecondsFormat, TimeZone, Utc};
use serde_json::{Value, json};
#[cfg(test)]
use std::fs;
use uuid::Uuid;

const PRIMARY_ACCOUNT_NAME: &str = "primary";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedExampleHistoryReport {
    pub database_path: String,
    pub runs: Vec<SeededRunSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededRunSummary {
    pub run_id: i64,
    pub kind: RunHistoryKind,
    pub repo: String,
    pub iid: u64,
    pub result: String,
    pub thread_id: Option<String>,
    pub review_thread_id: Option<String>,
    pub history_path: String,
    pub mr_history_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DemoTranscriptKind {
    ReviewRich,
    ReviewFailure,
    MentionRich,
    MentionMcpHeavy,
}

#[derive(Debug, Clone)]
struct DemoRunSpec {
    kind: RunHistoryKind,
    repo: &'static str,
    iid: u64,
    head_sha: &'static str,
    result: &'static str,
    preview: &'static str,
    summary: &'static str,
    error: Option<&'static str>,
    discussion_id: Option<&'static str>,
    trigger_note_id: Option<u64>,
    trigger_note_author_name: Option<&'static str>,
    trigger_note_body: Option<&'static str>,
    command_repo: Option<&'static str>,
    transcript: Option<DemoTranscriptKind>,
    use_review_thread_id: bool,
}

#[derive(Debug, Clone)]
struct SeededTranscript {
    thread_id: String,
    primary_turn_id: String,
    events: Vec<NewRunHistoryEvent>,
}

pub async fn seed_example_history(config: &Config) -> Result<SeedExampleHistoryReport> {
    let state = ReviewStateStore::new(&config.database.path).await?;
    seed_example_history_with_store(&state, &config.database.path).await
}

async fn seed_example_history_with_store(
    state: &ReviewStateStore,
    database_path: &str,
) -> Result<SeedExampleHistoryReport> {
    let mut runs = Vec::new();
    let seed_specs = demo_run_specs();
    for spec in seed_specs {
        let transcript = match spec.transcript {
            Some(kind) => Some(seed_transcript(kind)),
            None => None,
        };
        let run_id = state
            .start_run_history(NewRunHistory {
                kind: spec.kind,
                repo: spec.repo.to_string(),
                iid: spec.iid,
                head_sha: spec.head_sha.to_string(),
                discussion_id: spec.discussion_id.map(str::to_string),
                trigger_note_id: spec.trigger_note_id,
                trigger_note_author_name: spec.trigger_note_author_name.map(str::to_string),
                trigger_note_body: spec.trigger_note_body.map(str::to_string),
                command_repo: spec.command_repo.map(str::to_string),
            })
            .await
            .with_context(|| format!("insert demo run history for {} !{}", spec.repo, spec.iid))?;
        if let Some(transcript) = transcript.as_ref() {
            state
                .update_run_history_session(
                    run_id,
                    RunHistorySessionUpdate {
                        thread_id: if spec.use_review_thread_id {
                            Some(format!("demo-parent-{}", Uuid::new_v4()))
                        } else {
                            Some(transcript.thread_id.clone())
                        },
                        turn_id: Some(transcript.primary_turn_id.clone()),
                        review_thread_id: spec
                            .use_review_thread_id
                            .then(|| transcript.thread_id.clone()),
                        auth_account_name: Some(PRIMARY_ACCOUNT_NAME.to_string()),
                    },
                )
                .await
                .with_context(|| format!("update demo run session metadata for run {run_id}"))?;
            state
                .append_run_history_events(run_id, &transcript.events)
                .await
                .with_context(|| format!("append demo run events for run {run_id}"))?;
        }
        state
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: spec.result.to_string(),
                    thread_id: transcript.as_ref().and_then(|written| {
                        (!spec.use_review_thread_id).then(|| written.thread_id.clone())
                    }),
                    turn_id: transcript
                        .as_ref()
                        .map(|written| written.primary_turn_id.clone()),
                    review_thread_id: transcript.as_ref().and_then(|written| {
                        spec.use_review_thread_id.then(|| written.thread_id.clone())
                    }),
                    preview: Some(spec.preview.to_string()),
                    summary: Some(spec.summary.to_string()),
                    error: spec.error.map(str::to_string),
                    auth_account_name: transcript
                        .as_ref()
                        .map(|_| PRIMARY_ACCOUNT_NAME.to_string()),
                    commit_sha: (spec.kind == RunHistoryKind::Mention
                        && spec.result == "committed")
                        .then(|| spec.head_sha.to_string()),
                },
            )
            .await
            .with_context(|| format!("finish demo run history for run {run_id}"))?;
        let stored = state
            .get_run_history(run_id)
            .await?
            .with_context(|| format!("demo run {run_id} missing after insert"))?;
        runs.push(build_seeded_run_summary(stored));
    }

    Ok(SeedExampleHistoryReport {
        database_path: database_path.to_string(),
        runs,
    })
}

fn build_seeded_run_summary(run: RunHistoryRecord) -> SeededRunSummary {
    SeededRunSummary {
        run_id: run.id,
        kind: run.kind,
        repo: run.repo.clone(),
        iid: run.iid,
        result: run.result.unwrap_or_else(|| "unknown".to_string()),
        thread_id: run.thread_id,
        review_thread_id: run.review_thread_id,
        history_path: format!("/history/{}", run.id),
        mr_history_path: format!("/mr/{}/{}/history", encode_repo_key(&run.repo), run.iid),
    }
}

fn demo_run_specs() -> Vec<DemoRunSpec> {
    vec![
        DemoRunSpec {
            kind: RunHistoryKind::Review,
            repo: "demo/group/service-a",
            iid: 101,
            head_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            result: "comment",
            preview: "Demo review: service-a pagination regression walkthrough",
            summary: "Demo review flagged a pagination regression and prepared a review comment about cursor handling on empty pages.",
            error: None,
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            transcript: Some(DemoTranscriptKind::ReviewRich),
            use_review_thread_id: true,
        },
        DemoRunSpec {
            kind: RunHistoryKind::Review,
            repo: "demo/group/service-a",
            iid: 101,
            head_sha: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            result: "error",
            preview: "Demo review: service-a failing validation command",
            summary: "Demo review failed after a validation command exited with status 1.",
            error: Some("Demo command failure: cargo test review_flow --lib"),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            transcript: Some(DemoTranscriptKind::ReviewFailure),
            use_review_thread_id: false,
        },
        DemoRunSpec {
            kind: RunHistoryKind::Mention,
            repo: "demo/group/service-b",
            iid: 202,
            head_sha: "cccccccccccccccccccccccccccccccccccccccc",
            result: "committed",
            preview: "Demo mention: service-b release note follow-up",
            summary: "Demo mention run prepared a synthetic docs commit after a direct note trigger.",
            error: None,
            discussion_id: Some("discussion-demo-202-a"),
            trigger_note_id: Some(9001),
            trigger_note_author_name: Some("qa-bot"),
            trigger_note_body: Some(
                "@codex please update the release note and summarize what changed.\n\nFocus on the MR description and leave code untouched unless it is required for the note.",
            ),
            command_repo: Some("demo/group/shared-lib"),
            transcript: Some(DemoTranscriptKind::MentionRich),
            use_review_thread_id: false,
        },
        DemoRunSpec {
            kind: RunHistoryKind::Review,
            repo: "demo/group/service-c",
            iid: 303,
            head_sha: "dddddddddddddddddddddddddddddddddddddddd",
            result: "pass",
            preview: "Demo fallback review without persisted thread replay",
            summary: "Demo fallback row validates the detail page when only coarse run metadata exists.",
            error: None,
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            transcript: None,
            use_review_thread_id: false,
        },
        DemoRunSpec {
            kind: RunHistoryKind::Mention,
            repo: "demo/group/service-d",
            iid: 404,
            head_sha: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            result: "no_changes",
            preview: "Demo mention: MCP-heavy inspection with no repository changes",
            summary: "Demo mention explored MCP data sources and concluded no code changes were needed.",
            error: None,
            discussion_id: Some("discussion-demo-404-a"),
            trigger_note_id: Some(9002),
            trigger_note_author_name: Some("release-manager"),
            trigger_note_body: Some(
                "@codex inspect the deployment notes and confirm whether anything in this MR still needs adjustment.\n\nIf not, explain why no changes are required.",
            ),
            command_repo: None,
            transcript: Some(DemoTranscriptKind::MentionMcpHeavy),
            use_review_thread_id: false,
        },
    ]
}

fn seed_transcript(kind: DemoTranscriptKind) -> SeededTranscript {
    let mut sequence = 0i64;
    let push = |events: &mut Vec<NewRunHistoryEvent>,
                sequence: &mut i64,
                turn_id: Option<&str>,
                event_type: &str,
                mut payload: Value| {
        *sequence += 1;
        if let Some(object) = payload.as_object_mut()
            && !object.contains_key("createdAt")
            && !object.contains_key("created_at")
            && !object.contains_key("timestamp")
        {
            object.insert(
                "createdAt".to_string(),
                Value::String(demo_event_timestamp(*sequence)),
            );
        }
        events.push(NewRunHistoryEvent {
            sequence: *sequence,
            turn_id: turn_id.map(ToOwned::to_owned),
            event_type: event_type.to_string(),
            payload,
        });
    };
    let mut events = Vec::new();
    let primary_turn_id = primary_turn_id(kind).to_string();
    match kind {
        DemoTranscriptKind::ReviewRich => review_rich_events(&mut events, &mut sequence, &push),
        DemoTranscriptKind::ReviewFailure => {
            review_failure_events(&mut events, &mut sequence, &push)
        }
        DemoTranscriptKind::MentionRich => mention_rich_events(&mut events, &mut sequence, &push),
        DemoTranscriptKind::MentionMcpHeavy => {
            mention_mcp_heavy_events(&mut events, &mut sequence, &push)
        }
    }
    SeededTranscript {
        thread_id: Uuid::new_v4().to_string(),
        primary_turn_id,
        events,
    }
}

fn demo_event_timestamp(sequence: i64) -> String {
    let base = Utc
        .with_ymd_and_hms(2026, 3, 11, 12, 54, 0)
        .single()
        .expect("valid demo timestamp");
    (base + Duration::seconds(sequence)).to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn review_rich_events<F>(events: &mut Vec<NewRunHistoryEvent>, sequence: &mut i64, push: &F)
where
    F: Fn(&mut Vec<NewRunHistoryEvent>, &mut i64, Option<&str>, &str, Value),
{
    let turn_one = primary_turn_id(DemoTranscriptKind::ReviewRich);
    let turn_two = "demo-review-rich-follow-up";
    push(events, sequence, Some(turn_one), "turn_started", json!({}));
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        user_message_item("Demo review the pagination patch and point out risky follow-ups."),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({"type": "enteredReviewMode", "review": "Reviewing merge request diff"}),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        reasoning_item(
            "Checking whether pagination preserves the cursor across empty page transitions.",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({
            "type": "webSearch",
            "query": "pagination empty cursor regression demo",
            "action": {"type": "search", "query": "pagination empty cursor regression demo"}
        }),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({
            "type": "mcpToolCall",
            "server": "gitlab",
            "tool": "fetch_merge_request",
            "status": "completed",
            "durationMs": 14,
            "result": {"iid": 101, "changes": 3}
        }),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({
            "type": "commandExecution",
            "command": "cargo test review_flow --lib",
            "cwd": "/workspace/demo/group/service-a",
            "status": "completed",
            "exitCode": 0,
            "durationMs": 1250,
            "aggregatedOutput": "running 3 tests\nok\n"
        }),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({
            "type": "fileChange",
            "status": "completed",
            "changes": {
                "src/pagination.rs": {
                    "type": "update",
                    "unified_diff": "@@ -1,5 +1,7 @@\n- state.cursor = None;\n+ if items.is_empty() {\n+     state.cursor = previous_cursor.clone();\n+ }\n",
                    "move_path": null
                }
            }
        }),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        agent_message_item(
            "Demo review found a cursor regression and drafted a narrow patch.",
            "commentary",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "item_completed",
        json!({"type": "contextCompaction"}),
    );
    push(
        events,
        sequence,
        Some(turn_one),
        "turn_completed",
        json!({"status": "completed"}),
    );
    push(events, sequence, Some(turn_two), "turn_started", json!({}));
    push(
        events,
        sequence,
        Some(turn_two),
        "item_completed",
        user_message_item("Demo summarize the findings as if they were ready to post."),
    );
    push(
        events,
        sequence,
        Some(turn_two),
        "item_completed",
        agent_message_item(
            "Demo summary: preserve the previous cursor when an intermediate page returns no rows, then cover the retry path with a regression test.",
            "final_answer",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_two),
        "item_completed",
        json!({"type": "exitedReviewMode", "review": "Cursor state is lost on empty intermediate pages."}),
    );
    push(
        events,
        sequence,
        Some(turn_two),
        "turn_completed",
        json!({"status": "completed"}),
    );
}

fn review_failure_events<F>(events: &mut Vec<NewRunHistoryEvent>, sequence: &mut i64, push: &F)
where
    F: Fn(&mut Vec<NewRunHistoryEvent>, &mut i64, Option<&str>, &str, Value),
{
    let turn_id = primary_turn_id(DemoTranscriptKind::ReviewFailure);
    push(events, sequence, Some(turn_id), "turn_started", json!({}));
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        user_message_item("Demo validate the branch and stop if tests fail."),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({"type": "enteredReviewMode", "review": "Running review validation"}),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        reasoning_item("Running the narrow test target before writing the review summary."),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "commandExecution",
            "command": "cargo test review_flow --lib",
            "cwd": "/workspace/demo/group/service-a",
            "status": "failed",
            "exitCode": 1,
            "durationMs": 842,
            "aggregatedOutput": "test failed: pagination_preserves_cursor\n"
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        agent_message_item(
            "Demo validation failed before the review could be posted.",
            "final_answer",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({"type": "exitedReviewMode", "review": "The synthetic review command failed before generating a stable summary."}),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "turn_completed",
        json!({"status": "failed"}),
    );
}

fn mention_rich_events<F>(events: &mut Vec<NewRunHistoryEvent>, sequence: &mut i64, push: &F)
where
    F: Fn(&mut Vec<NewRunHistoryEvent>, &mut i64, Option<&str>, &str, Value),
{
    let turn_id = primary_turn_id(DemoTranscriptKind::MentionRich);
    push(events, sequence, Some(turn_id), "turn_started", json!({}));
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        user_message_item("Demo update the release note and show what changed."),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        reasoning_item(
            "Checking whether the existing release note already covers the MR behavior.",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "dynamicToolCall",
            "tool": "resolve_release_note_template",
            "status": "completed",
            "durationMs": 18,
            "contentItems": [{"type": "inputText", "text": "Use the customer-facing changelog template."}]
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "commandExecution",
            "command": "git status --short",
            "cwd": "/workspace/demo/group/service-b",
            "status": "completed",
            "exitCode": 0,
            "durationMs": 55,
            "aggregatedOutput": " M docs/release-notes.md\n"
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        agent_message_item(
            "Demo mention run updated the release note wording and prepared a synthetic commit.",
            "final_answer",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "turn_completed",
        json!({"status": "completed"}),
    );
}

fn mention_mcp_heavy_events<F>(events: &mut Vec<NewRunHistoryEvent>, sequence: &mut i64, push: &F)
where
    F: Fn(&mut Vec<NewRunHistoryEvent>, &mut i64, Option<&str>, &str, Value),
{
    let turn_id = primary_turn_id(DemoTranscriptKind::MentionMcpHeavy);
    push(events, sequence, Some(turn_id), "turn_started", json!({}));
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        user_message_item(
            "Demo inspect deployment notes and explain whether any changes are still required.",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "mcpToolCall",
            "server": "gitlab",
            "tool": "load_discussion_context",
            "status": "failed",
            "durationMs": 22,
            "error": {"message": "Demo MCP note lookup timed out on the first attempt"}
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "mcpToolCall",
            "server": "gitlab",
            "tool": "load_pipeline_summary",
            "status": "completed",
            "durationMs": 31,
            "result": {"pipeline": "green", "warnings": 0}
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "webSearch",
            "query": "demo deployment note wording best practice",
            "action": {"type": "search", "queries": ["demo deployment note wording best practice"]}
        }),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "item_completed",
        agent_message_item(
            "Demo inspection found the deployment note already matches the MR behavior, so no repository changes are required.",
            "final_answer",
        ),
    );
    push(
        events,
        sequence,
        Some(turn_id),
        "turn_completed",
        json!({"status": "completed"}),
    );
}

fn primary_turn_id(kind: DemoTranscriptKind) -> &'static str {
    match kind {
        DemoTranscriptKind::ReviewRich => "demo-review-rich-turn",
        DemoTranscriptKind::ReviewFailure => "demo-review-failure-turn",
        DemoTranscriptKind::MentionRich => "demo-mention-rich-turn",
        DemoTranscriptKind::MentionMcpHeavy => "demo-mention-mcp-heavy-turn",
    }
}

fn user_message_item(message: &str) -> Value {
    json!({
        "type": "userMessage",
        "content": [{"type": "text", "text": message}]
    })
}

fn reasoning_item(message: &str) -> Value {
    json!({
        "type": "reasoning",
        "summary": [message],
        "content": [message]
    })
}

fn agent_message_item(message: &str, phase: &str) -> Value {
    json!({
        "type": "agentMessage",
        "phase": phase,
        "text": message
    })
}

fn encode_repo_key(repo: &str) -> String {
    let mut output = String::with_capacity(repo.len() * 2);
    for byte in repo.as_bytes() {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    struct TempDirGuard {
        path: std::path::PathBuf,
    }

    impl TempDirGuard {
        fn new(prefix: &str) -> Result<Self> {
            let path = std::env::temp_dir().join(format!("{prefix}-{}", Uuid::new_v4()));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn seed_example_history_appends_runs_and_events() -> Result<()> {
        let temp = TempDirGuard::new("demo-history-seed")?;
        let db_path = temp.path().join("state.sqlite");
        let state = ReviewStateStore::new(db_path.to_string_lossy().as_ref()).await?;

        let report =
            seed_example_history_with_store(&state, db_path.to_string_lossy().as_ref()).await?;

        assert_eq!(report.runs.len(), 5);
        let mr_runs = state
            .list_run_history_for_mr("demo/group/service-a", 101)
            .await?;
        assert_eq!(mr_runs.len(), 2);

        let mention_run = report
            .runs
            .iter()
            .find(|run| run.repo == "demo/group/service-b")
            .context("seeded mention run")?;
        let stored_mention = state
            .get_run_history(mention_run.run_id)
            .await?
            .context("stored mention row")?;
        assert_eq!(
            stored_mention.trigger_note_body.as_deref(),
            Some(
                "@codex please update the release note and summarize what changed.\n\nFocus on the MR description and leave code untouched unless it is required for the note."
            )
        );

        let rich_run = report
            .runs
            .iter()
            .find(|run| run.review_thread_id.is_some())
            .context("rich review run")?;
        let rich_events = state.list_run_history_events(rich_run.run_id).await?;
        assert!(rich_events.iter().any(|event| {
            event.event_type == "item_completed" && event.payload["type"] == "enteredReviewMode"
        }));
        assert!(rich_events.iter().any(|event| {
            event.event_type == "item_completed" && event.payload["type"] == "commandExecution"
        }));
        assert!(rich_events.iter().any(|event| {
            event.event_type == "item_completed" && event.payload["type"] == "mcpToolCall"
        }));
        assert!(rich_events.iter().any(|event| {
            event.event_type == "item_completed" && event.payload["type"] == "fileChange"
        }));
        assert!(rich_events.iter().any(|event| {
            event.event_type == "item_completed" && event.payload["type"] == "contextCompaction"
        }));

        let fallback_run = report
            .runs
            .iter()
            .find(|run| run.repo == "demo/group/service-c")
            .context("fallback run")?;
        let fallback = state
            .get_run_history(fallback_run.run_id)
            .await?
            .context("stored fallback row")?;
        assert!(fallback.thread_id.is_none());
        assert!(fallback.review_thread_id.is_none());
        assert_eq!(fallback.auth_account_name, None);
        Ok(())
    }

    #[tokio::test]
    async fn seed_example_history_is_append_only() -> Result<()> {
        let temp = TempDirGuard::new("demo-history-append")?;
        let db_path = temp.path().join("state.sqlite");
        let state = ReviewStateStore::new(db_path.to_string_lossy().as_ref()).await?;

        seed_example_history_with_store(&state, db_path.to_string_lossy().as_ref()).await?;
        seed_example_history_with_store(&state, db_path.to_string_lossy().as_ref()).await?;

        let runs = state
            .list_run_history_for_mr("demo/group/service-a", 101)
            .await?;
        assert_eq!(runs.len(), 4);

        let all_runs = state
            .list_run_history_for_mr("demo/group/service-d", 404)
            .await?;
        assert_eq!(all_runs.len(), 2);

        Ok(())
    }
}

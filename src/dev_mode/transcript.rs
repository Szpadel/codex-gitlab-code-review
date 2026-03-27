use crate::review_lane::ReviewLane;
use crate::state::NewRunHistoryEvent;
use chrono::{DateTime, Duration, Utc};
use serde_json::{Value, json};
use uuid::Uuid;

pub struct MockReviewTranscript {
    pub thread_id: String,
    pub primary_turn_id: String,
    pub events: Vec<NewRunHistoryEvent>,
    pub summary: String,
    pub body: String,
}

pub fn build_mock_review_transcript(
    lane: ReviewLane,
    repo: &str,
    iid: u64,
    head_sha: &str,
    title: Option<&str>,
    started_at: DateTime<Utc>,
) -> MockReviewTranscript {
    let label = if lane.is_security() {
        "security review"
    } else {
        "review"
    };
    let summary = format!(
        "Mock {label} completed for {repo} !{iid} at `{}`.",
        short_sha(head_sha)
    );
    let body = match title {
        Some(title) if !title.trim().is_empty() => {
            format!("{summary}\n\nSynthetic MR title: {title}.")
        }
        _ => summary.clone(),
    };
    let thread_id = Uuid::new_v4().to_string();
    let primary_turn_id = format!("dev-mode-{}-{iid}", lane.as_str());
    let mut sequence = 0_i64;
    let mut events = Vec::new();
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "turn_started",
        json!({}),
        started_at,
    );
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "item_completed",
        user_message_item(&format!(
            "Mock {} {} !{} for synthetic development-mode validation.",
            lane.review_label().to_lowercase(),
            repo,
            iid
        )),
        started_at,
    );
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "item_completed",
        reasoning_item(&format!(
            "Using a deterministic mocked Codex transcript for {} !{} at {}.",
            repo,
            iid,
            short_sha(head_sha)
        )),
        started_at,
    );
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "item_completed",
        json!({
            "type": "commandExecution",
            "command": "dev-mode mock review",
            "cwd": format!("/work/repo/{repo}"),
            "status": "completed",
            "exitCode": 0,
            "durationMs": 12,
            "aggregatedOutput": format!("mocked {} completed for {} !{}\n", label, repo, iid),
        }),
        started_at,
    );
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "item_completed",
        agent_message_item(&summary, "final_answer"),
        started_at,
    );
    push_event(
        &mut events,
        &mut sequence,
        Some(primary_turn_id.as_str()),
        "turn_completed",
        json!({"status": "completed"}),
        started_at,
    );
    MockReviewTranscript {
        thread_id,
        primary_turn_id,
        events,
        summary,
        body,
    }
}

fn push_event(
    events: &mut Vec<NewRunHistoryEvent>,
    sequence: &mut i64,
    turn_id: Option<&str>,
    event_type: &str,
    mut payload: Value,
    started_at: DateTime<Utc>,
) {
    *sequence += 1;
    if let Some(object) = payload.as_object_mut()
        && !object.contains_key("createdAt")
    {
        object.insert(
            "createdAt".to_string(),
            Value::String(
                (started_at + Duration::seconds(*sequence))
                    .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            ),
        );
    }
    events.push(NewRunHistoryEvent {
        sequence: *sequence,
        turn_id: turn_id.map(ToOwned::to_owned),
        event_type: event_type.to_string(),
        payload,
    });
}

fn user_message_item(text: &str) -> Value {
    json!({
        "type": "message",
        "role": "user",
        "text": text,
    })
}

fn reasoning_item(text: &str) -> Value {
    json!({
        "type": "reasoning",
        "text": text,
    })
}

fn agent_message_item(text: &str, kind: &str) -> Value {
    json!({
        "type": "agentMessage",
        "kind": kind,
        "text": text,
    })
}

fn short_sha(head_sha: &str) -> String {
    head_sha.chars().take(7).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn mock_transcript_uses_run_start_time_for_event_timestamps() {
        let started_at = Utc.with_ymd_and_hms(2026, 3, 26, 9, 16, 0).unwrap();

        let transcript = build_mock_review_transcript(
            ReviewLane::General,
            "demo/group/service-z",
            1,
            "6cd3ccf0e4dea8ff4a22aea63ec8337621236958",
            Some("Synthetic review for demo/group/service-z"),
            started_at,
        );

        let timestamps = transcript
            .events
            .iter()
            .map(|event| {
                event
                    .payload
                    .get("createdAt")
                    .and_then(Value::as_str)
                    .expect("event timestamp")
                    .to_string()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            timestamps,
            vec![
                "2026-03-26T09:16:01.000Z",
                "2026-03-26T09:16:02.000Z",
                "2026-03-26T09:16:03.000Z",
                "2026-03-26T09:16:04.000Z",
                "2026-03-26T09:16:05.000Z",
                "2026-03-26T09:16:06.000Z",
            ]
        );
    }
}

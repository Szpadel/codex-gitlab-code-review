use crate::http::transcript::is_auxiliary_transcript_turn_id;
use crate::state::{RunHistoryEventRecord, merge_rewritten_turn_events};
use anyhow::Result;
use std::collections::HashSet;

pub(super) fn persisted_turn_ids(persisted_events: &[RunHistoryEventRecord]) -> HashSet<String> {
    persisted_events
        .iter()
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>()
}

pub(super) fn persisted_turn_ids_with_target_turn_id(
    persisted_turn_ids: &HashSet<String>,
    target_turn_id: &str,
) -> HashSet<String> {
    let mut turn_ids = persisted_turn_ids.clone();
    turn_ids.insert(target_turn_id.to_string());
    turn_ids
}

pub(crate) fn sanitize_persisted_events_for_backfill(
    persisted_events: Vec<RunHistoryEventRecord>,
    target_turn_id: Option<&str>,
    review_wrapper_turn_events: Option<&[crate::state::NewRunHistoryEvent]>,
) -> Vec<RunHistoryEventRecord> {
    let Some(target_turn_id) = target_turn_id else {
        return persisted_events;
    };
    let review_child_turn_ids = review_wrapper_turn_events
        .map(review_wrapper_child_turn_ids)
        .unwrap_or_default();
    let drop_review_child_turns = !review_child_turn_ids.is_empty();
    let has_target_events = persisted_events
        .iter()
        .any(|event| event.turn_id.as_deref() == Some(target_turn_id));
    if drop_review_child_turns && !has_target_events {
        return persisted_events
            .into_iter()
            .filter(|event| {
                !event
                    .turn_id
                    .as_deref()
                    .is_some_and(|turn_id| review_child_turn_ids.contains(turn_id))
            })
            .collect();
    }
    if !has_target_events {
        return persisted_events;
    }
    let stale_turn_ids = persisted_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .filter(|turn_id| *turn_id != target_turn_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|turn_id| {
            let turn_events = persisted_events
                .iter()
                .filter(|event| event.turn_id.as_deref() == Some(*turn_id))
                .collect::<Vec<_>>();
            let turn_has_no_items = turn_events
                .iter()
                .all(|event| event.event_type != "item_completed");
            let turn_is_completed = turn_events
                .iter()
                .any(|event| event.event_type == "turn_completed");
            !turn_events.is_empty()
                && ((turn_has_no_items && turn_is_completed)
                    || (drop_review_child_turns && review_child_turn_ids.contains(*turn_id)))
        })
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>();
    persisted_events
        .into_iter()
        .filter(|event| {
            !event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| stale_turn_ids.contains(turn_id))
        })
        .collect()
}

pub(super) fn turn_events_include_review_wrapper_items(
    events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    events.iter().any(|event| {
        event.event_type == "item_completed"
            && matches!(
                event
                    .payload
                    .get("type")
                    .and_then(serde_json::Value::as_str),
                Some("enteredReviewMode" | "exitedReviewMode")
            )
    })
}

fn review_wrapper_child_turn_ids(
    review_wrapper_turn_events: &[crate::state::NewRunHistoryEvent],
) -> HashSet<String> {
    review_wrapper_turn_events
        .iter()
        .filter_map(|event| event.payload.get("reviewChildTurnIds"))
        .filter_map(serde_json::Value::as_array)
        .flat_map(|turn_ids| turn_ids.iter())
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>()
}

pub(super) fn filter_events_to_turn_ids(
    events: &[crate::state::NewRunHistoryEvent],
    turn_ids: &HashSet<String>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    events
        .iter()
        .filter(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| turn_ids.contains(turn_id))
        })
        .enumerate()
        .map(|(index, event)| crate::state::NewRunHistoryEvent {
            sequence: i64::try_from(index + 1).expect("filtered event sequence"),
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
        })
        .collect()
}

pub(crate) fn persisted_turn_ids_are_covered(
    persisted_turn_ids: &HashSet<String>,
    full_thread_events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    let full_thread_turn_ids = full_thread_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .collect::<HashSet<_>>();
    persisted_turn_ids
        .iter()
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .all(|turn_id| full_thread_turn_ids.contains(turn_id.as_str()))
}

pub(crate) fn turn_ids_from_new_events(
    events: &[crate::state::NewRunHistoryEvent],
) -> HashSet<String> {
    events
        .iter()
        .filter_map(|event| event.turn_id.clone())
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .collect::<HashSet<_>>()
}

pub(crate) fn preserve_auxiliary_persisted_events(
    persisted_events: &[RunHistoryEventRecord],
    mut rewritten_events: Vec<crate::state::NewRunHistoryEvent>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    let rewritten_auxiliary_turn_ids = rewritten_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .filter(|turn_id| is_auxiliary_transcript_turn_id(turn_id))
        .collect::<std::collections::HashSet<_>>();

    let mut auxiliary_events = persisted_events
        .iter()
        .filter(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(is_auxiliary_transcript_turn_id)
        })
        .filter(|event| {
            !event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| rewritten_auxiliary_turn_ids.contains(turn_id))
        })
        .map(|event| crate::state::NewRunHistoryEvent {
            sequence: event.sequence,
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
        })
        .collect::<Vec<_>>();
    if auxiliary_events.is_empty() {
        return rewritten_events;
    }

    auxiliary_events.sort_by_key(|event| event.sequence);
    for event in &mut rewritten_events {
        event.sequence += auxiliary_events.len() as i64;
    }
    auxiliary_events.extend(rewritten_events);
    for (index, event) in auxiliary_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).expect("auxiliary preserved event index");
    }
    auxiliary_events
}

pub(crate) fn merge_recovered_target_turn_events(
    existing_events: Vec<RunHistoryEventRecord>,
    turn_id: &str,
    rewritten_events: &[crate::state::NewRunHistoryEvent],
) -> Result<Vec<crate::state::NewRunHistoryEvent>> {
    let existing_events = sanitize_persisted_events_for_backfill(
        existing_events,
        Some(turn_id),
        Some(rewritten_events),
    );
    if existing_events
        .iter()
        .any(|event| event.turn_id.as_deref() == Some(turn_id))
    {
        return merge_rewritten_turn_events(existing_events, turn_id, rewritten_events);
    }

    let mut existing_events = existing_events;
    existing_events.sort_by_key(|event| (event.sequence, event.id));

    let insertion_sequence = recovered_turn_insertion_sequence(&existing_events, rewritten_events)
        .unwrap_or_else(|| existing_events.last().map_or(1, |event| event.sequence + 1));
    let delta = rewritten_events.len() as i64;

    let mut merged_events = Vec::new();
    for event in existing_events {
        let shifted_sequence = if event.sequence >= insertion_sequence {
            event.sequence + delta
        } else {
            event.sequence
        };
        merged_events.push(crate::state::NewRunHistoryEvent {
            sequence: shifted_sequence,
            turn_id: event.turn_id,
            event_type: event.event_type,
            payload: event.payload,
        });
    }

    merged_events.extend(
        rewritten_events
            .iter()
            .map(|event| crate::state::NewRunHistoryEvent {
                sequence: insertion_sequence + event.sequence - 1,
                turn_id: event.turn_id.clone(),
                event_type: event.event_type.clone(),
                payload: event.payload.clone(),
            }),
    );

    merged_events.sort_by_key(|event| event.sequence);
    for (index, event) in merged_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).expect("merged recovered event index");
    }
    Ok(merged_events)
}

fn recovered_turn_insertion_sequence(
    existing_events: &[RunHistoryEventRecord],
    rewritten_events: &[crate::state::NewRunHistoryEvent],
) -> Option<i64> {
    let recovered_last_timestamp = rewritten_events
        .iter()
        .filter_map(|event| history_event_timestamp(&event.payload))
        .max()?;
    let later_turn_ids = existing_events
        .iter()
        .filter(|event| {
            run_history_event_timestamp(event)
                .is_some_and(|timestamp| timestamp > recovered_last_timestamp)
        })
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();
    if !later_turn_ids.is_empty() {
        return existing_events
            .iter()
            .find(|event| {
                event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| later_turn_ids.contains(turn_id))
            })
            .map(|event| event.sequence);
    }
    existing_events
        .iter()
        .find(|event| {
            run_history_event_timestamp(event)
                .is_some_and(|timestamp| timestamp > recovered_last_timestamp)
        })
        .map(|event| event.sequence)
}

fn run_history_event_timestamp(event: &RunHistoryEventRecord) -> Option<i64> {
    history_event_timestamp(&event.payload).or((event.created_at > 0).then_some(event.created_at))
}

fn history_event_timestamp(payload: &serde_json::Value) -> Option<i64> {
    let timestamp = payload
        .get("createdAt")
        .or_else(|| payload.get("timestamp"))?;
    match timestamp {
        serde_json::Value::Number(number) => number.as_i64().map(normalize_history_timestamp),
        serde_json::Value::String(text) => chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|value| value.timestamp()),
        _ => None,
    }
}

fn normalize_history_timestamp(timestamp: i64) -> i64 {
    if timestamp.unsigned_abs() >= 1_000_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
    }
}

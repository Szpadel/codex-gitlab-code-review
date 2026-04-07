use super::retry::TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR;
use super::rewrite::{
    filter_events_to_turn_ids, merge_recovered_target_turn_events, persisted_turn_ids,
    persisted_turn_ids_are_covered, persisted_turn_ids_with_target_turn_id,
    preserve_auxiliary_persisted_events, sanitize_persisted_events_for_backfill,
    turn_events_include_review_wrapper_items, turn_ids_from_new_events,
};
use crate::http::transcript::{
    thread_snapshot_from_events, thread_snapshot_is_complete,
    thread_snapshot_only_target_turn_is_incomplete,
};
use crate::state::{
    ReviewStateStore, RunHistoryEventRecord, RunHistoryKind, RunHistoryRecord,
    TranscriptBackfillState,
};
use crate::transcript_backfill::{
    REVIEW_MISSING_CHILD_TURN_IDS_KEY, TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
    TranscriptBackfillSource,
};
use anyhow::Result;

pub(super) fn transcript_needs_backfill(
    run: &RunHistoryRecord,
    thread: Option<&super::super::ThreadSnapshot>,
) -> bool {
    !run.events_persisted_cleanly || !thread.is_some_and(thread_snapshot_is_complete)
}

pub(crate) async fn run_transcript_backfill(
    state: &ReviewStateStore,
    source: &dyn TranscriptBackfillSource,
    run: &RunHistoryRecord,
    retry_window_open_at_attempt_start: bool,
) -> Result<()> {
    let preserve_all_thread_turns =
        run.kind == RunHistoryKind::Security && run.review_thread_id.is_none();
    let Some(thread_id) = run.thread_id.as_deref().or(run.review_thread_id.as_deref()) else {
        state
            .run_history
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::Failed,
                Some("run is missing Codex thread metadata"),
            )
            .await?;
        return Ok(());
    };

    let allow_missing_review_child_history = !retry_window_open_at_attempt_start;
    let turn_scoped_events = match load_validated_transcript_backfill_events(
        source,
        run,
        thread_id,
        run.turn_id.as_deref(),
        allow_missing_review_child_history,
    )
    .await
    {
        Ok(events) => events,
        Err(err)
            if run.turn_id.is_some()
                && err.to_string() == TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR =>
        {
            None
        }
        Err(err) => return Err(err),
    };
    let review_wrapper_turn_events = turn_scoped_events
        .as_ref()
        .filter(|events| turn_events_include_review_wrapper_items(events))
        .cloned();
    let original_persisted_events = state.run_history.list_run_history_events(run.id).await?;
    let target_turn_missing_in_persisted = run.turn_id.as_deref().is_some_and(|turn_id| {
        !original_persisted_events
            .iter()
            .any(|event| event.turn_id.as_deref() == Some(turn_id))
    });
    let had_any_original_persisted_events = !original_persisted_events.is_empty();
    let persisted_events = sanitize_persisted_events_for_backfill(
        original_persisted_events,
        run.turn_id.as_deref(),
        review_wrapper_turn_events.as_deref(),
    );
    let mut candidate_events = initial_backfill_candidate_events(
        &persisted_events,
        run.turn_id.as_deref(),
        turn_scoped_events,
    )?;
    let mut rebuilt_thread = (!candidate_events.is_empty())
        .then(|| thread_snapshot_from_events(run, &ephemeral_run_history_events(&candidate_events)))
        .flatten();
    let persisted_turn_id_set = persisted_turn_ids(&persisted_events);
    let needs_review_wrapper_missing_target_recovery = review_wrapper_turn_events.is_some()
        && target_turn_missing_in_persisted
        && run.turn_id.is_some()
        && had_any_original_persisted_events;
    let only_target_turn_is_incomplete = run.turn_id.as_deref().is_some_and(|turn_id| {
        rebuilt_thread
            .as_ref()
            .is_some_and(|thread| thread_snapshot_only_target_turn_is_incomplete(thread, turn_id))
    });
    let needs_full_thread_rebuild = preserve_all_thread_turns
        || (run.turn_id.as_deref().is_some()
            && (candidate_events.is_empty()
                || target_turn_missing_in_persisted
                || needs_review_wrapper_missing_target_recovery
                || (!rebuilt_thread
                    .as_ref()
                    .is_some_and(thread_snapshot_is_complete)
                    && !only_target_turn_is_incomplete)));
    if needs_full_thread_rebuild
        && let Some(full_thread_events) = source.load_events(thread_id, None).await?
    {
        let persisted_events_for_full_thread = sanitize_persisted_events_for_backfill(
            persisted_events.clone(),
            run.turn_id.as_deref(),
            Some(&full_thread_events),
        );
        let persisted_turn_ids_in_full_thread =
            persisted_turn_ids(&persisted_events_for_full_thread);
        let filtered_turn_ids = if preserve_all_thread_turns {
            turn_ids_from_new_events(&full_thread_events)
        } else if persisted_turn_ids_in_full_thread.is_empty() {
            run.turn_id.as_deref().map_or_else(
                || turn_ids_from_new_events(&full_thread_events),
                |turn_id| std::collections::HashSet::from([turn_id.to_string()]),
            )
        } else if needs_review_wrapper_missing_target_recovery
            || (target_turn_missing_in_persisted && run.turn_id.is_some())
        {
            persisted_turn_ids_with_target_turn_id(
                &persisted_turn_ids_in_full_thread,
                run.turn_id.as_deref().expect("turn id checked above"),
            )
        } else {
            persisted_turn_ids_in_full_thread.clone()
        };
        let filtered_full_thread_events =
            if persisted_turn_id_set.is_empty() && run.turn_id.is_none() {
                full_thread_events.clone()
            } else {
                filter_events_to_turn_ids(&full_thread_events, &filtered_turn_ids)
            };
        let filtered_full_thread_has_missing_review_child_history =
            events_have_missing_review_child_history(&filtered_full_thread_events);
        let filtered_full_thread_can_fall_back =
            !filtered_full_thread_has_missing_review_child_history
                || missing_review_child_history_has_renderable_fallback(
                    &filtered_full_thread_events,
                );
        let allow_target_only_recovery_despite_unrelated_missing_child_history =
            target_turn_missing_in_persisted
                && run.turn_id.is_some()
                && filtered_full_thread_has_missing_review_child_history
                && (!allow_missing_review_child_history || !filtered_full_thread_can_fall_back);
        if filtered_full_thread_has_missing_review_child_history
            && !allow_missing_review_child_history
            && !allow_target_only_recovery_despite_unrelated_missing_child_history
        {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        if filtered_full_thread_has_missing_review_child_history
            && allow_missing_review_child_history
            && !filtered_full_thread_can_fall_back
            && !allow_target_only_recovery_despite_unrelated_missing_child_history
        {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        let filtered_full_thread_events =
            strip_missing_review_child_history_markers(filtered_full_thread_events);
        let filtered_full_thread_events = preserve_auxiliary_persisted_events(
            &persisted_events_for_full_thread,
            filtered_full_thread_events,
        );
        let filtered_thread = thread_snapshot_from_events(
            run,
            &ephemeral_run_history_events(&filtered_full_thread_events),
        );
        let should_accept_filtered_full_thread = !(filtered_full_thread_events.is_empty()
            || (allow_target_only_recovery_despite_unrelated_missing_child_history
                && filtered_full_thread_has_missing_review_child_history));
        if should_accept_filtered_full_thread
            && persisted_turn_ids_are_covered(&filtered_turn_ids, &filtered_full_thread_events)
            && filtered_thread
                .as_ref()
                .is_some_and(thread_snapshot_is_complete)
        {
            rebuilt_thread = filtered_thread;
            candidate_events = filtered_full_thread_events;
        } else if target_turn_missing_in_persisted && run.turn_id.is_some() {
            let target_only_turn_ids = std::collections::HashSet::from([run
                .turn_id
                .as_deref()
                .expect("turn id checked above")
                .to_string()]);
            let target_only_full_thread_events =
                filter_events_to_turn_ids(&full_thread_events, &target_only_turn_ids);
            let target_only_has_missing_review_child_history =
                events_have_missing_review_child_history(&target_only_full_thread_events);
            if target_only_has_missing_review_child_history && !allow_missing_review_child_history {
                anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
            }
            if target_only_has_missing_review_child_history
                && allow_missing_review_child_history
                && !missing_review_child_history_has_renderable_fallback(
                    &target_only_full_thread_events,
                )
            {
                anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
            }
            let target_only_full_thread_events =
                strip_missing_review_child_history_markers(target_only_full_thread_events);
            let target_only_thread = thread_snapshot_from_events(
                run,
                &ephemeral_run_history_events(&target_only_full_thread_events),
            );
            if !target_only_full_thread_events.is_empty()
                && persisted_turn_ids_are_covered(
                    &target_only_turn_ids,
                    &target_only_full_thread_events,
                )
                && target_only_thread
                    .as_ref()
                    .is_some_and(thread_snapshot_is_complete)
            {
                candidate_events = merge_recovered_target_turn_events(
                    persisted_events.clone(),
                    run.turn_id.as_deref().expect("turn id checked above"),
                    &target_only_full_thread_events,
                )?;
                rebuilt_thread = thread_snapshot_from_events(
                    run,
                    &ephemeral_run_history_events(&candidate_events),
                );
            }
        }
    }
    if candidate_events.is_empty() {
        anyhow::bail!(TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR);
    }
    if !rebuilt_thread
        .as_ref()
        .is_some_and(thread_snapshot_is_complete)
    {
        state
            .run_history
            .mark_run_history_events_incomplete(run.id)
            .await?;
        if run.turn_id.as_deref().is_some_and(|turn_id| {
            rebuilt_thread.as_ref().is_some_and(|thread| {
                thread_snapshot_only_target_turn_is_incomplete(thread, turn_id)
            })
        }) {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        state
            .run_history
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::Failed,
                Some("transcript remains incomplete after local session-history backfill"),
            )
            .await?;
        return Ok(());
    }
    state
        .run_history
        .replace_run_history_events(run.id, &candidate_events)
        .await?;
    state
        .run_history
        .mark_run_history_transcript_backfill_complete(run.id)
        .await?;
    Ok(())
}

pub(crate) fn initial_backfill_candidate_events(
    persisted_events: &[RunHistoryEventRecord],
    turn_id: Option<&str>,
    turn_scoped_events: Option<Vec<crate::state::NewRunHistoryEvent>>,
) -> Result<Vec<crate::state::NewRunHistoryEvent>> {
    match (turn_id, turn_scoped_events) {
        (Some(turn_id), Some(events)) => {
            crate::state::merge_rewritten_turn_events(persisted_events.to_vec(), turn_id, &events)
        }
        (Some(_), None) => Ok(Vec::new()),
        (None, Some(events)) => Ok(preserve_auxiliary_persisted_events(
            persisted_events,
            events,
        )),
        (None, None) => anyhow::bail!(TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR),
    }
}

async fn load_validated_transcript_backfill_events(
    source: &dyn TranscriptBackfillSource,
    run: &RunHistoryRecord,
    thread_id: &str,
    turn_id: Option<&str>,
    allow_missing_review_child_history: bool,
) -> Result<Option<Vec<crate::state::NewRunHistoryEvent>>> {
    let Some(events) = load_backfill_events(
        source,
        thread_id,
        turn_id,
        allow_missing_review_child_history,
    )
    .await?
    else {
        return Ok(None);
    };
    let source_thread = thread_snapshot_from_events(run, &ephemeral_run_history_events(&events));
    if !source_thread
        .as_ref()
        .is_some_and(thread_snapshot_is_complete)
    {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    Ok(Some(events))
}

async fn load_backfill_events(
    source: &dyn TranscriptBackfillSource,
    thread_id: &str,
    turn_id: Option<&str>,
    allow_missing_review_child_history: bool,
) -> Result<Option<Vec<crate::state::NewRunHistoryEvent>>> {
    let Some(events) = source.load_events(thread_id, turn_id).await? else {
        return Ok(None);
    };
    let has_missing_review_child_history = events_have_missing_review_child_history(&events);
    if has_missing_review_child_history && !allow_missing_review_child_history {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    if has_missing_review_child_history
        && allow_missing_review_child_history
        && !missing_review_child_history_has_renderable_fallback(&events)
    {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    Ok(Some(strip_missing_review_child_history_markers(events)))
}

pub(crate) fn events_have_missing_review_child_history(
    events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    events.iter().any(|event| {
        event.event_type == "item_completed"
            && event
                .payload
                .get(REVIEW_MISSING_CHILD_TURN_IDS_KEY)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|turn_ids| !turn_ids.is_empty())
    })
}

pub(crate) fn strip_missing_review_child_history_markers(
    mut events: Vec<crate::state::NewRunHistoryEvent>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    for event in &mut events {
        let Some(object) = event.payload.as_object_mut() else {
            continue;
        };
        object.remove(REVIEW_MISSING_CHILD_TURN_IDS_KEY);
    }
    events
}

pub(crate) fn missing_review_child_history_has_renderable_fallback(
    events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    let marked_wrapper_items = events
        .iter()
        .filter(|event| event.event_type == "item_completed")
        .filter(|event| {
            event
                .payload
                .get(REVIEW_MISSING_CHILD_TURN_IDS_KEY)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|turn_ids| !turn_ids.is_empty())
        })
        .collect::<Vec<_>>();

    let turns_with_missing_review_children = marked_wrapper_items
        .iter()
        .map(|event| event.turn_id.clone())
        .collect::<std::collections::HashSet<_>>();

    !turns_with_missing_review_children.is_empty()
        && turns_with_missing_review_children.iter().all(|turn_id| {
            marked_wrapper_items.iter().any(|event| {
                event.turn_id == *turn_id
                    && review_wrapper_item_is_renderable_fallback(&event.payload)
            })
        })
}

fn renderable_review_value_present(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(items) => !items.is_empty(),
        _ => true,
    }
}

fn review_wrapper_item_is_renderable_fallback(payload: &serde_json::Value) -> bool {
    let Some(item_type) = payload.get("type").and_then(serde_json::Value::as_str) else {
        return false;
    };
    match item_type {
        "agentMessage" | "AgentMessage" => {
            payload.get("phase").is_none_or(serde_json::Value::is_null)
                && (payload
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|text| !text.is_empty())
                    || payload
                        .get("content")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|content| !content.is_empty()))
        }
        "exitedReviewMode" => payload
            .get("review")
            .is_some_and(renderable_review_value_present),
        _ => false,
    }
}

fn ephemeral_run_history_events(
    events: &[crate::state::NewRunHistoryEvent],
) -> Vec<RunHistoryEventRecord> {
    events
        .iter()
        .enumerate()
        .map(|(index, event)| RunHistoryEventRecord {
            id: i64::try_from(index + 1).expect("ephemeral run history event id"),
            run_history_id: 0,
            sequence: event.sequence,
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            created_at: 0,
        })
        .collect()
}

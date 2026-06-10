use super::*;
#[tokio::test]
async fn run_transcript_backfill_preserves_all_turns_for_security_shared_thread() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::security("group/repo", 19, "feed333")
        .thread("thread-security")
        .turn("turn-review")
        .auth_account("primary")
        .result("pass")
        .preview("Security review group/repo !19")
        .summary("Rebuild shared-thread security transcript")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-review"),
            run_event(2, Some("turn-review"), "item_completed", json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                })),
            turn_completed_event(3, "turn-review"),
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .expect("run history should exist");
    let source = TurnScopedFallbackTranscriptBackfillSource {
        turn_events: Some(vec![
            turn_started_event(1, "turn-review"),
            run_event(
                2,
                Some("turn-review"),
                "item_completed",
                json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            ),
            turn_completed_event(3, "turn-review"),
        ]),
        full_thread_events: vec![
            turn_started_event(1, "turn-threat"),
            run_event(
                2,
                Some("turn-threat"),
                "item_completed",
                json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"focus_paths\":[]}"}]
                }),
            ),
            turn_completed_event(3, "turn-threat"),
            turn_started_event(4, "turn-review"),
            run_event(
                5,
                Some("turn-review"),
                "item_completed",
                json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            ),
            turn_completed_event(6, "turn-review"),
        ],
        seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
    };

    crate::http::status::run_transcript_backfill(&state, &source, &run, false).await?;

    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    let persisted_turn_ids = persisted_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        persisted_turn_ids,
        std::collections::HashSet::from(["turn-threat", "turn-review"])
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_replaces_child_only_persisted_review_turns() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
            events: vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Investigating",
                        "reviewChildTurnIds": ["turn-stale-child"]
                    }),
                ),
                agent_message_event(3, "turn-parent", "fresh review transcript"),
                turn_completed_event(4, "turn-parent"),
            ],
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 27, "feedchild")
        .thread("thread-review-wrapper")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !27")
        .summary("Replace child-only persisted review turn")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-stale-child"),
            agent_message_event(2, "turn-stale-child", "stale child transcript"),
            turn_completed_event(3, "turn-stale-child"),
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _initial_body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after child-only backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_recovers_missing_parent_turn_from_full_thread_after_sanitize_empties_persisted_events()
-> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Investigating",
                        "reviewChildTurnIds": ["turn-stale-child"]
                    }),
                ),
                agent_message_event(3, "turn-parent", "fresh review transcript"),
                turn_completed_event(4, "turn-parent"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 127, "feedsanitize")
        .thread("thread-review-missing-parent-only-child")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !127")
        .summary("Recover missing parent turn from full thread")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-stale-child"),
            agent_message_event(2, "turn-stale-child", "stale child transcript"),
            turn_completed_event(3, "turn-stale-child"),
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _body = response.text().await?;

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after sanitize-empty recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("sanitize-empty recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_drops_partial_stale_review_child_items_before_rewrite() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
            events: vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Investigating",
                        "reviewChildTurnIds": ["turn-stale-child"]
                    }),
                ),
                agent_message_event(3, "turn-parent", "fresh review transcript"),
                turn_completed_event(4, "turn-parent"),
            ],
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 28, "feeddup")
        .thread("thread-review-duplicate")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !28")
        .summary("Drop partial stale child review items")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-parent"),
            empty_reasoning_event(2, "turn-parent"),
            turn_started_event(3, "turn-stale-child"),
            agent_message_event(4, "turn-stale-child", "stale child transcript"),
            turn_completed_event(5, "turn-stale-child"),
            turn_completed_event(6, "turn-parent"),
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .text()
            .await?
            .contains("Transcript backfill is in progress")
    );

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after duplicate child backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

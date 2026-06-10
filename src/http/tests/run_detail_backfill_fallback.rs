use super::*;
#[tokio::test]
async fn run_detail_empty_history_target_only_recovery_waits_for_missing_review_sibling()
-> Result<()> {
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
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                agent_message_event(3, "turn-parent", "wrapper summary"),
                turn_completed_event(4, "turn-parent"),
            ],
            seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 35, "feedemptytargetreview")
        .thread("thread-review-empty-target")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !35")
        .summary("Do not finalize target-only recovery while review sibling is missing".to_string())
        .insert(&state)
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
            .context("run history row after empty target-only missing-child recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after empty target-only missing-child recovery")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("local session history is still being written")
    );
    assert!(
        state
            .run_history
            .list_run_history_events(run_id)
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_stale_missing_review_sibling_without_wrapper_fallback_stays_failed()
-> Result<()> {
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                turn_completed_event(3, "turn-parent"),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                turn_completed_event(3, "turn-parent"),
            ],
            seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 37, "feedstalemissingsibling")
        .thread("thread-review-stale-missing-sibling")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !37")
        .summary("Do not accept stale missing review siblings when the wrapper has no renderable fallback"
                    .to_string(),)
        .insert(&state)
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
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
            .context("run history row after stale missing-sibling retry window")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after stale missing-sibling retry window")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("local session history remained incomplete after retry window")
    );
    assert!(
        state
            .run_history
            .list_run_history_events(run_id)
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_stale_missing_review_sibling_with_wrapper_fallback_recovers() -> Result<()> {
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                run_event(
                    3,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "agentMessage",
                        "text": "Wrapper fallback summary",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                turn_completed_event(4, "turn-parent"),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-parent"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                run_event(
                    3,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "agentMessage",
                        "text": "Wrapper fallback summary",
                        "reviewMissingChildTurnIds": ["turn-child-missing"]
                    }),
                ),
                turn_completed_event(4, "turn-parent"),
            ],
            seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 38, "feedstalewrapperfallback")
        .thread("thread-review-stale-wrapper-fallback")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !38")
        .summary(
            "Recover stale missing review siblings when wrapper output is renderable".to_string(),
        )
        .insert(&state)
        .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
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
            .context("run history row after stale wrapper fallback recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after stale wrapper fallback recovery final state")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Complete
    );

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Wrapper fallback summary"));
    assert!(!body.contains("Transcript backfill failed"));
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_drops_multi_child_stale_turns_without_timestamps() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event_at(1, "turn-parent", "2026-03-11T21:32:37.160Z"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Investigating",
                        "createdAt": "2026-03-11T21:32:37.160Z",
                        "reviewChildTurnIds": [
                            "turn-stale-child-one",
                            "turn-stale-child-two"
                        ]
                    }),
                ),
                agent_message_event_at(
                    3,
                    "turn-parent",
                    "fresh review transcript",
                    "2026-03-11T21:32:37.162Z",
                ),
                turn_completed_event_at(4, "turn-parent", "2026-03-11T21:32:37.164Z"),
            ]),
            full_thread_events: vec![
                turn_started_event_at(1, "turn-parent", "2026-03-11T21:32:37.160Z"),
                run_event(
                    2,
                    Some("turn-parent"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Investigating",
                        "createdAt": "2026-03-11T21:32:37.160Z",
                        "reviewChildTurnIds": [
                            "turn-stale-child-one",
                            "turn-stale-child-two"
                        ]
                    }),
                ),
                agent_message_event_at(
                    3,
                    "turn-parent",
                    "fresh review transcript",
                    "2026-03-11T21:32:37.162Z",
                ),
                turn_completed_event_at(4, "turn-parent", "2026-03-11T21:32:37.164Z"),
                turn_started_event_at(5, "turn-later", "2026-03-11T21:40:00.000Z"),
                agent_message_event_at(
                    6,
                    "turn-later",
                    "later legitimate turn",
                    "2026-03-11T21:40:01.000Z",
                ),
                turn_completed_event_at(7, "turn-later", "2026-03-11T21:40:02.000Z"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 31, "feedmultichild")
        .thread("thread-review-multi-child-missing-parent")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !31")
        .summary("Drop multiple stale child turns without timestamps")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-stale-child-one"),
            agent_message_event(2, "turn-stale-child-one", "stale child one"),
            turn_completed_event(3, "turn-stale-child-one"),
            turn_started_event(4, "turn-stale-child-two"),
            agent_message_event(5, "turn-stale-child-two", "stale child two"),
            turn_completed_event(6, "turn-stale-child-two"),
            turn_started_event_at(7, "turn-later", "2026-03-11T21:40:00.000Z"),
            agent_message_event_at(
                8,
                "turn-later",
                "later legitimate turn",
                "2026-03-11T21:40:01.000Z",
            ),
            turn_completed_event_at(9, "turn-later", "2026-03-11T21:40:02.000Z"),
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
            .context("run history row after multi-child missing-parent backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(body.contains("later legitimate turn"));
    assert!(!body.contains("stale child one"));
    assert!(!body.contains("stale child two"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("multi-child missing-parent fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_does_not_queue_backfill_for_active_runs() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
            events: Vec::new(),
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 19, "feed333")
        .thread("thread-active")
        .turn("turn-active")
        .auth_account("primary")
        .start(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-active"),
            empty_reasoning_event(2, "turn-active"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(!body.contains("Transcript backfill is in progress"));
    sleep(Duration::from_millis(20)).await;
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_stale_in_progress_backfill_after_restart() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
            events: vec![
                turn_started_event(1, "turn-stale-backfill"),
                reasoning_event(
                    2,
                    "turn-stale-backfill",
                    "Recovered after restart",
                    "Backfill retried successfully",
                ),
                turn_completed_event(3, "turn-stale-backfill"),
            ],
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 20, "feed444")
        .thread("thread-stale-backfill")
        .turn("turn-stale-backfill")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !20")
        .summary("Retry stale transcript backfill")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-stale-backfill"),
            empty_reasoning_event(2, "turn-stale-backfill"),
            turn_completed_event(3, "turn-stale-backfill"),
        ],
    )
    .await?;
    state
        .run_history
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after retry")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after restart"));
    assert!(body.contains("Backfill retried successfully"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_after_transient_missing_session_history() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            None,
            None,
            Some(vec![
                turn_started_event(1, "turn-transient"),
                reasoning_event(
                    2,
                    "turn-transient",
                    "Recovered after missing file",
                    "Second attempt found session history",
                ),
                turn_completed_event(3, "turn-transient"),
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(backfill_source)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 21, "feed555")
        .thread("thread-transient")
        .turn("turn-transient")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !21")
        .summary("Retry after transient session-history miss")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-transient"),
            empty_reasoning_event(2, "turn-transient"),
            turn_completed_event(3, "turn-transient"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if backfill_calls.load(Ordering::SeqCst) >= 1 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    for _ in 0..20 {
        if state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after transient miss")?
            .transcript_backfill_state
            == TranscriptBackfillState::Failed
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after transient miss")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert_eq!(
        run.transcript_backfill_error.as_deref(),
        Some("matching Codex session history was not found")
    );

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill failed"));

    sleep(Duration::from_millis(1100)).await;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after retry success")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after missing file"));
    assert!(body.contains("Second attempt found session history"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_after_partial_session_history_file() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            Some(vec![
                turn_started_event(1, "turn-partial-file"),
                empty_reasoning_event(2, "turn-partial-file"),
            ]),
            Some(vec![
                turn_started_event(1, "turn-partial-file"),
                reasoning_event(
                    2,
                    "turn-partial-file",
                    "Recovered after partial write",
                    "Second parse saw the finished turn",
                ),
                turn_completed_event(3, "turn-partial-file"),
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(backfill_source)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 24, "feed888")
        .thread("thread-partial-file")
        .turn("turn-partial-file")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !24")
        .summary("Retry partial session-history file after cooldown")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-partial-file"),
            empty_reasoning_event(2, "turn-partial-file"),
            turn_completed_event(3, "turn-partial-file"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        if state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after partial file fallback")?
            .transcript_backfill_state
            == TranscriptBackfillState::Complete
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered after partial write"));
    assert!(body.contains("Second parse saw the finished turn"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

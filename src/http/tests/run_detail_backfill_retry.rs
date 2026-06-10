use super::*;
#[tokio::test]
async fn run_detail_marks_backfill_failed_when_other_turns_remain_incomplete() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
            events: vec![
                turn_started_event(1, "turn-new"),
                reasoning_event(
                    2,
                    "turn-new",
                    "Recovered current turn",
                    "Older turn still missing",
                ),
                turn_completed_event(3, "turn-new"),
            ],
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 22, "feed666")
        .thread("thread-partial")
        .turn("turn-new")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !22")
        .summary("Do not mark partial multi-turn transcript complete")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            empty_reasoning_event(2, "turn-old"),
            turn_completed_event(3, "turn-old"),
            turn_started_event(4, "turn-new"),
            empty_reasoning_event(5, "turn-new"),
            turn_completed_event(6, "turn-new"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after partial multi-turn backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Failed {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after failed partial backfill")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Failed
    );
    assert!(!run.events_persisted_cleanly);

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(!body.contains("Recovered current turn"));
    assert!(body.contains("Transcript backfill failed"));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_falls_back_to_full_thread_when_older_turn_missing() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-new"),
                reasoning_event(
                    2,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(3, "turn-new"),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-old"),
                reasoning_event(2, "turn-old", "Recovered older turn", "Older turn detail"),
                turn_completed_event(3, "turn-old"),
                turn_started_event(4, "turn-new"),
                reasoning_event(
                    5,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(6, "turn-new"),
                turn_started_event(7, "turn-later"),
                agent_message_event(8, "turn-later", "Later turn should be ignored"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 23, "feed777")
        .thread("thread-full-fallback")
        .turn("turn-new")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !23")
        .summary("Recover older turns from the full local thread")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            empty_reasoning_event(2, "turn-old"),
            turn_completed_event(3, "turn-old"),
            turn_started_event(4, "turn-new"),
            empty_reasoning_event(5, "turn-new"),
            turn_completed_event(6, "turn-new"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after full-thread fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Older turn detail"));
    assert!(body.contains("Recovered current turn"));
    assert!(body.contains("Current turn detail"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_full_thread_fallback_ignores_unrelated_pending_review_markers() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-new"),
                reasoning_event(
                    2,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(3, "turn-new"),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-old"),
                reasoning_event(2, "turn-old", "Recovered older turn", "Older turn detail"),
                turn_completed_event(3, "turn-old"),
                turn_started_event(4, "turn-new"),
                reasoning_event(
                    5,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(6, "turn-new"),
                turn_started_event(7, "turn-unrelated-pending"),
                run_event(
                    8,
                    Some("turn-unrelated-pending"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Waiting on unrelated child",
                        "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                    }),
                ),
                turn_completed_event(9, "turn-unrelated-pending"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 123, "feedignore")
        .thread("thread-ignore-unrelated-pending")
        .turn("turn-new")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !123")
        .summary("Ignore unrelated pending review markers during full-thread fallback".to_string())
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            empty_reasoning_event(2, "turn-old"),
            turn_completed_event(3, "turn-old"),
            turn_started_event(4, "turn-new"),
            empty_reasoning_event(5, "turn-new"),
            turn_completed_event(6, "turn-new"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after unrelated marker fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Waiting on unrelated child"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("ignore unrelated pending seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_uses_full_thread_fallback_when_turn_scoped_backfill_is_incomplete() -> Result<()>
{
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-new"),
                reasoning_event(
                    2,
                    "turn-new",
                    "Partial current turn",
                    "Missing turn completion",
                ),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-old"),
                reasoning_event(2, "turn-old", "Recovered older turn", "Older turn detail"),
                turn_completed_event(3, "turn-old"),
                turn_started_event(4, "turn-new"),
                reasoning_event(
                    5,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(6, "turn-new"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 124, "feedfullthread")
        .thread("thread-turn-incomplete-full-ready")
        .turn("turn-new")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !124")
        .summary("Use full-thread fallback when turn-scoped backfill is incomplete".to_string())
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            empty_reasoning_event(2, "turn-old"),
            turn_completed_event(3, "turn-old"),
            turn_started_event(4, "turn-new"),
            empty_reasoning_event(5, "turn-new"),
            turn_completed_event(6, "turn-new"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));

    for _ in 0..20 {
        let run = state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after incomplete-turn full-thread fallback")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Partial current turn"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("incomplete-turn full-thread fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_falls_back_to_full_thread_when_turn_lookup_is_missing() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event(1, "turn-old"),
                reasoning_event(2, "turn-old", "Recovered older turn", "Older turn detail"),
                turn_completed_event(3, "turn-old"),
                turn_started_event(4, "turn-new"),
                reasoning_event(
                    5,
                    "turn-new",
                    "Recovered current turn",
                    "Current turn detail",
                ),
                turn_completed_event(6, "turn-new"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 26, "feedabc")
        .thread("thread-missing-turn")
        .turn("turn-new")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !26")
        .summary("Fallback to whole-thread session history when turn lookup is missing".to_string())
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            empty_reasoning_event(2, "turn-old"),
            turn_completed_event(3, "turn-old"),
            turn_started_event(4, "turn-new"),
            empty_reasoning_event(5, "turn-new"),
            turn_completed_event(6, "turn-new"),
        ],
    )
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
            .context("run history row after missing turn fallback backfill")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Recovered older turn"));
    assert!(body.contains("Recovered current turn"));
    assert!(!body.contains("Later turn should be ignored"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex"),
        vec![Some("turn-new".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_uses_base_thread_id_when_review_thread_differs() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let seen_thread_id = Arc::new(Mutex::new(None));
    let seen_turn_id = Arc::new(Mutex::new(None));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(CapturingTranscriptBackfillSource {
            events: vec![
                turn_started_event(1, "turn-review"),
                reasoning_event(2, "turn-review", "Recovered", "Base thread history used"),
                turn_completed_event(3, "turn-review"),
            ],
            calls: Arc::clone(&backfill_calls),
            seen_thread_id: Arc::clone(&seen_thread_id),
            seen_turn_id: Arc::clone(&seen_turn_id),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 25, "feed999")
        .thread("thread-base")
        .turn("turn-review")
        .review_thread("thread-review")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !25")
        .summary("Backfill should read base thread history")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-review"),
            empty_reasoning_event(2, "turn-review"),
            turn_completed_event(3, "turn-review"),
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

    assert_eq!(
        seen_thread_id
            .lock()
            .expect("captured thread id mutex")
            .as_deref(),
        Some("thread-base")
    );
    assert_eq!(
        seen_turn_id
            .lock()
            .expect("captured turn id mutex")
            .as_deref(),
        Some("turn-review")
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_retries_when_session_history_directory_appears_later() -> Result<()> {
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(ErroringTranscriptBackfillSource {
            error: TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR,
            calls: Arc::clone(&backfill_calls),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 23, "feed777")
        .thread("thread-unavailable")
        .turn("turn-unavailable")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !23")
        .summary("Do not retry unavailable local session history")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-unavailable"),
            empty_reasoning_event(2, "turn-unavailable"),
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
            .context("run history row after unavailable backfill source")?
            .transcript_backfill_state
            == TranscriptBackfillState::Failed
        {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    sleep(Duration::from_millis(1100)).await;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));
    for _ in 0..20 {
        if backfill_calls.load(Ordering::SeqCst) >= 2 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 2);
    Ok(())
}

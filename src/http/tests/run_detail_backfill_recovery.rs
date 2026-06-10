use super::*;
#[tokio::test]
async fn run_detail_backfill_preserves_later_turns_while_removing_stale_review_child_turns()
-> Result<()> {
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
    let run_id = RunFixture::review("group/repo", 29, "feedlater")
        .thread("thread-review-later")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !29")
        .summary("Preserve later turns while removing stale child review turns".to_string())
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
            turn_started_event(7, "turn-later"),
            agent_message_event(8, "turn-later", "later legitimate turn"),
            turn_completed_event(9, "turn-later"),
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
            .context("run history row after later-turn preserving backfill")?;
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
    assert!(!body.contains("stale child transcript"));

    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    assert!(persisted_events.iter().all(|event| {
        matches!(
            event.turn_id.as_deref(),
            Some("turn-parent") | Some("turn-later")
        )
    }));
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn run_detail_backfill_preserves_later_turns_when_parent_turn_was_missing() -> Result<()> {
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
                        "reviewChildTurnIds": ["turn-stale-child"]
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
                        "reviewChildTurnIds": ["turn-stale-child"]
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
    let run_id = RunFixture::review("group/repo", 30, "feedmissing")
        .thread("thread-review-missing-parent")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !30")
        .summary("Preserve later turns when parent turn is missing")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event_at(1, "turn-stale-child", "2026-03-11T21:32:37.161Z"),
            agent_message_event_at(
                2,
                "turn-stale-child",
                "stale child transcript",
                "2026-03-11T21:32:37.162Z",
            ),
            turn_completed_event_at(3, "turn-stale-child", "2026-03-11T21:32:37.163Z"),
            turn_started_event_at(4, "turn-later", "2026-03-11T21:40:00.000Z"),
            agent_message_event_at(
                5,
                "turn-later",
                "later legitimate turn",
                "2026-03-11T21:40:01.000Z",
            ),
            turn_completed_event_at(6, "turn-later", "2026-03-11T21:40:02.000Z"),
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
            .context("run history row after missing-parent backfill")?;
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
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("missing-parent fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_target_only_fallback_preserves_known_good_later_turns() -> Result<()> {
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
                        "reviewChildTurnIds": ["turn-stale-child"]
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
                        "reviewChildTurnIds": ["turn-stale-child"]
                    }),
                ),
                agent_message_event_at(
                    3,
                    "turn-parent",
                    "fresh review transcript",
                    "2026-03-11T21:32:37.162Z",
                ),
                turn_completed_event_at(4, "turn-parent", "2026-03-11T21:32:37.164Z"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 31, "feedtargetonly")
        .thread("thread-review-target-only")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !31")
        .summary("Preserve later turns during target-only fallback")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event_at(1, "turn-stale-child", "2026-03-11T21:32:37.161Z"),
            agent_message_event_at(
                2,
                "turn-stale-child",
                "stale child transcript",
                "2026-03-11T21:32:37.162Z",
            ),
            turn_completed_event_at(3, "turn-stale-child", "2026-03-11T21:32:37.163Z"),
            turn_started_event_at(4, "turn-later", "2026-03-11T21:40:00.000Z"),
            agent_message_event_at(
                5,
                "turn-later",
                "later legitimate turn",
                "2026-03-11T21:40:01.000Z",
            ),
            turn_completed_event_at(6, "turn-later", "2026-03-11T21:40:02.000Z"),
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
            .context("run history row after target-only fallback backfill")?;
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
    assert!(!body.contains("stale child transcript"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("target-only fallback seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_recovers_missing_plain_target_turn_before_later_persisted_turns() -> Result<()>
{
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: Some(vec![
                turn_started_event(1, "turn-target"),
                agent_message_event(2, "turn-target", "recovered target turn"),
                turn_completed_event(3, "turn-target"),
            ]),
            full_thread_events: vec![
                turn_started_event(1, "turn-target"),
                agent_message_event(2, "turn-target", "recovered target turn"),
                turn_completed_event(3, "turn-target"),
                turn_started_event(4, "turn-later"),
                agent_message_event(5, "turn-later", "later legitimate turn"),
                turn_completed_event(6, "turn-later"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 34, "feedplainmissing")
        .thread("thread-review-plain-missing")
        .turn("turn-target")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !34")
        .summary("Recover plain missing target turn before later turns")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-later"),
            agent_message_event(2, "turn-later", "later legitimate turn"),
            turn_completed_event(3, "turn-later"),
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
            .context("run history row after plain missing-target recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    let target_first_sequence = persisted_events
        .iter()
        .find(|event| event.turn_id.as_deref() == Some("turn-target"))
        .expect("target turn persisted")
        .sequence;
    let later_first_sequence = persisted_events
        .iter()
        .find(|event| event.turn_id.as_deref() == Some("turn-later"))
        .expect("later turn persisted")
        .sequence;
    assert!(target_first_sequence < later_first_sequence);
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("plain missing-target recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_empty_history_recovery_keeps_target_turn_scoped() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event_at(1, "turn-parent", "2026-03-11T21:32:37.160Z"),
                agent_message_event_at(
                    2,
                    "turn-parent",
                    "fresh review transcript",
                    "2026-03-11T21:32:37.162Z",
                ),
                turn_completed_event_at(3, "turn-parent", "2026-03-11T21:32:37.164Z"),
                turn_started_event_at(4, "turn-later", "2026-03-11T21:40:00.000Z"),
                agent_message_event_at(
                    5,
                    "turn-later",
                    "later legitimate turn",
                    "2026-03-11T21:40:01.000Z",
                ),
                turn_completed_event_at(6, "turn-later", "2026-03-11T21:40:02.000Z"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 32, "feedempty")
        .thread("thread-review-empty")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !32")
        .summary("Recover only the target turn when persisted history is empty".to_string())
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
            .context("run history row after empty-history recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("later legitimate turn"));
    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("empty-history recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_empty_history_recovery_ignores_unrelated_pending_review_markers() -> Result<()>
{
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event_at(1, "turn-parent", "2026-03-11T21:32:37.160Z"),
                agent_message_event_at(
                    2,
                    "turn-parent",
                    "fresh review transcript",
                    "2026-03-11T21:32:37.162Z",
                ),
                turn_completed_event_at(3, "turn-parent", "2026-03-11T21:32:37.164Z"),
                turn_started_event_at(4, "turn-unrelated", "2026-03-11T21:40:00.000Z"),
                run_event(
                    5,
                    Some("turn-unrelated"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-unrelated-child"],
                        "createdAt": "2026-03-11T21:40:01.000Z"
                    }),
                ),
                turn_completed_event_at(6, "turn-unrelated", "2026-03-11T21:40:02.000Z"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 33, "feedemptyother")
        .thread("thread-review-empty-other")
        .turn("turn-parent")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !33")
        .summary(
            "Recover target turn even when another turn is still waiting for review child history"
                .to_string(),
        )
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
            .context("run history row after empty-history unrelated marker recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("fresh review transcript"));
    assert!(!body.contains("Transcript backfill failed"));
    let persisted_events = state.run_history.list_run_history_events(run_id).await?;
    assert!(
        persisted_events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("empty-history unrelated marker recovery seen turn ids mutex"),
        vec![Some("turn-parent".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_target_only_recovery_ignores_unrelated_missing_child_history() -> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event(1, "turn-unrelated"),
                run_event(
                    2,
                    Some("turn-unrelated"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "review": "Waiting on unrelated child",
                        "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                    }),
                ),
                turn_completed_event(3, "turn-unrelated"),
                turn_started_event(4, "turn-target"),
                agent_message_event(5, "turn-target", "recovered target turn"),
                turn_completed_event(6, "turn-target"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 36, "feedtargetothermissing")
        .thread("thread-review-target-other-missing")
        .turn("turn-target")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !36")
        .summary("Recover missing target turn even when another persisted turn still waits on review child history"
                    .to_string(),)
        .insert(&state)
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-unrelated"),
            agent_message_event(2, "turn-unrelated", "persisted unrelated turn"),
            turn_completed_event(3, "turn-unrelated"),
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
            .context("run history row after target-only unrelated-marker recovery")?;
        if run.transcript_backfill_state == TranscriptBackfillState::Complete {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("persisted unrelated turn"));
    assert!(body.contains("recovered target turn"));
    assert!(!body.contains("Transcript backfill failed"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("target-only unrelated-marker recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_full_thread_recovery_replaces_recoverable_stale_turns_when_target_missing()
-> Result<()> {
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let srv = HttpTestServerBuilder::new()
        .with_transcript_backfill_source(Arc::new(TurnScopedFallbackTranscriptBackfillSource {
            turn_events: None,
            full_thread_events: vec![
                turn_started_event(1, "turn-old"),
                run_event(
                    2,
                    Some("turn-old"),
                    "item_completed",
                    json!({
                        "type": "enteredReviewMode",
                        "reviewMissingChildTurnIds": ["turn-old-child"]
                    }),
                ),
                run_event(
                    3,
                    Some("turn-old"),
                    "item_completed",
                    json!({
                        "type": "agentMessage",
                        "text": "Recovered older turn",
                        "reviewMissingChildTurnIds": ["turn-old-child"]
                    }),
                ),
                turn_completed_event(4, "turn-old"),
                turn_started_event(5, "turn-target"),
                agent_message_event(6, "turn-target", "Recovered current turn"),
                turn_completed_event(7, "turn-target"),
            ],
            seen_turn_ids: Arc::clone(&seen_turn_ids),
        }))
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 137, "feedstaleoldertargetmissing")
        .thread("thread-review-stale-older-target-missing")
        .turn("turn-target")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !137")
        .summary("Recover stale older review-wrapper turns from full-thread backfill when the current target turn is missing"
                    .to_string(),)
        .insert(&state)
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-old"),
            run_event(
                2,
                Some("turn-old"),
                "item_completed",
                json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-old-child"]
                }),
            ),
            turn_completed_event(3, "turn-old"),
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
            .context("run history row after stale full-thread recovery")?;
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
    assert!(!body.contains("Transcript backfill failed"));
    assert_eq!(
        *seen_turn_ids
            .lock()
            .expect("stale full-thread recovery seen turn ids mutex"),
        vec![Some("turn-target".to_string()), None]
    );
    Ok(())
}

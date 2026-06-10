use super::*;
#[tokio::test]
async fn run_detail_page_shows_unavailable_transcript_for_legacy_runs() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-legacy",
                "preview": "Legacy thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-legacy",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Legacy history still renders."
                    }]
                }]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::mention("group/repo", 11, "feed123")
        .discussion("discussion-11", 777)
        .trigger_note("qa", "please inspect the legacy thread")
        .command_repo("group/repo")
        .thread("thread-legacy")
        .turn("turn-legacy")
        .auth_account("primary")
        .result("committed")
        .preview("Mention group/repo !11 legacy thread")
        .summary("Used legacy thread replay")
        .insert(&state)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    assert!(!body.contains("Legacy history still renders."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_partial_persisted_history_without_thread_reader() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-live",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [
                    {
                        "id": "turn-live",
                        "status": "completed",
                        "items": [{
                            "type": "agentMessage",
                            "text": "Complete live thread history."
                        }]
                    },
                    {
                        "id": "turn-follow-up",
                        "status": "completed",
                        "items": [{
                            "type": "agentMessage",
                            "text": "Follow-up turn from live replay."
                        }]
                    }
                ]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 12, "feed456")
        .thread("thread-live")
        .turn("turn-live")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !12")
        .summary("Used complete live thread")
        .insert(&state)
        .await?;
    insert_run_history_events(&state, run_id, vec![turn_started_event(1, "turn-live")]).await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Complete live thread history."));
    assert!(!body.contains("Follow-up turn from live replay."));
    Ok(())
}

#[tokio::test]
async fn run_detail_prefers_complete_persisted_event_history() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-persisted",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-persisted",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Live replay should not replace persisted transcript."
                    }]
                }]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 13, "feed789")
        .thread("thread-persisted")
        .turn("turn-persisted")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !13")
        .summary("Prefer persisted event history")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-persisted"),
            agent_message_event(2, "turn-persisted", "Persisted transcript wins."),
            turn_completed_event(3, "turn-persisted"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript wins."));
    assert!(!body.contains("Live replay should not replace persisted transcript."));
    Ok(())
}

#[tokio::test]
async fn run_detail_skips_live_thread_when_complete_persisted_history_exists() -> Result<()> {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 14, "feedabc")
        .thread("thread-richer")
        .turn("turn-richer")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !14")
        .summary("Prefer richer live transcript")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-richer"),
            agent_message_event(2, "turn-richer", "Persisted transcript item."),
            turn_completed_event(3, "turn-richer"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript item."));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_incomplete_persisted_history_without_thread_reader() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-incomplete",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-incomplete",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Recovered from live replay."
                    }]
                }]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 15, "feeddef")
        .thread("thread-incomplete")
        .turn("turn-incomplete")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !15")
        .summary("Use live replay after persistence failure")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-incomplete"),
            turn_completed_event(2, "turn-incomplete"),
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered from live replay."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_completed_turn_without_items_without_thread_reader() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-delta-only",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-delta-only",
                    "status": "completed",
                    "items": [{
                        "type": "agentMessage",
                        "text": "Recovered delta-only reply."
                    }]
                }]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::mention("group/repo", 16, "feed000")
        .discussion("discussion-16", 16)
        .trigger_note("qa", "show delta-only completion")
        .command_repo("group/repo")
        .thread("thread-delta-only")
        .turn("turn-delta-only")
        .auth_account("primary")
        .result("committed")
        .preview("Mention group/repo !16")
        .summary("Recover delta-only turn via live replay")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-delta-only"),
            turn_completed_event(2, "turn-delta-only"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered delta-only reply."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_command_without_body_without_thread_reader() -> Result<()> {
    let runner = Arc::new(ThreadReaderRunner {
        response: json!({
            "thread": {
                "id": "thread-command-body",
                "preview": "Live thread replay",
                "status": "completed",
                "turns": [{
                    "id": "turn-command-body",
                    "status": "completed",
                    "items": [{
                        "type": "commandExecution",
                        "command": "cargo test",
                        "aggregatedOutput": "Recovered command output"
                    }]
                }]
            }
        }),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 17, "feed111")
        .thread("thread-command-body")
        .turn("turn-command-body")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !17")
        .summary("Recover command output from live replay")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-command-body"),
            run_event(
                2,
                Some("turn-command-body"),
                "item_completed",
                json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "status": "completed"
                }),
            ),
            turn_completed_event(3, "turn-command-body"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("cargo test"));
    assert!(!body.contains("Recovered command output"));
    Ok(())
}

#[tokio::test]
async fn run_detail_queues_async_backfill_and_serves_rewritten_persisted_history() -> Result<()> {
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(StaticTranscriptBackfillSource {
        events: vec![
            turn_started_event(1, "turn-backfill"),
            reasoning_event(2, "turn-backfill", "Recovered summary", "Recovered detail"),
            turn_completed_event(3, "turn-backfill"),
        ],
        calls: Arc::clone(&backfill_calls),
    });
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner)
        .with_transcript_backfill_source(backfill_source)
        .spawn()
        .await?;
    let address = srv.address;

    let state = Arc::clone(&srv.state);
    let run_id = RunFixture::review("group/repo", 18, "feed222")
        .thread("thread-backfill")
        .turn("turn-backfill")
        .auth_account("primary")
        .result("commented")
        .preview("Review group/repo !18")
        .summary("Queue background transcript backfill")
        .insert(&state)
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            turn_started_event(1, "turn-backfill"),
            empty_reasoning_event(2, "turn-backfill"),
            turn_completed_event(3, "turn-backfill"),
        ],
    )
    .await?;
    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript backfill is in progress"));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);

    for _ in 0..20 {
        if state
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row after async backfill")?
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
    assert!(body.contains("Recovered summary"));
    assert!(body.contains("Recovered detail"));
    assert!(!body.contains("Transcript backfill is in progress"));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backfill_calls.load(Ordering::SeqCst), 1);
    Ok(())
}

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

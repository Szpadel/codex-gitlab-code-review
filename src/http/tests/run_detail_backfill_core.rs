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

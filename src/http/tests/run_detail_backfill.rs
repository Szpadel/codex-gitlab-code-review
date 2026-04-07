use super::*;
#[tokio::test]
async fn run_detail_page_shows_unavailable_transcript_for_legacy_runs() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "feed123".to_string(),
            discussion_id: Some("discussion-11".to_string()),
            trigger_note_id: Some(777),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("please inspect the legacy thread".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-legacy".to_string()),
            turn_id: Some("turn-legacy".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !11 legacy thread".to_string()),
            summary: Some("Used legacy thread replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    assert!(!body.contains("Legacy history still renders."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_partial_persisted_history_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "feed456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-live".to_string()),
            turn_id: Some("turn-live".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !12".to_string()),
            summary: Some("Used complete live thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-live".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        }],
    )
    .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 13,
            head_sha: "feed789".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-persisted".to_string()),
            turn_id: Some("turn-persisted".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !13".to_string()),
            summary: Some("Prefer persisted event history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Persisted transcript wins."
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-persisted".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript wins."));
    assert!(!body.contains("Live replay should not replace persisted transcript."));
    Ok(())
}

#[tokio::test]
async fn run_detail_skips_live_thread_when_complete_persisted_history_exists() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 14,
            head_sha: "feedabc".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-richer".to_string()),
            turn_id: Some("turn-richer".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !14".to_string()),
            summary: Some("Prefer richer live transcript".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-richer".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-richer".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Persisted transcript item."
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-richer".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Persisted transcript item."));
    assert_eq!(read_calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_incomplete_persisted_history_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 15,
            head_sha: "feeddef".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-incomplete".to_string()),
            turn_id: Some("turn-incomplete".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !15".to_string()),
            summary: Some("Use live replay after persistence failure".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-incomplete".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-incomplete".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered from live replay."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_completed_turn_without_items_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 16,
            head_sha: "feed000".to_string(),
            discussion_id: Some("discussion-16".to_string()),
            trigger_note_id: Some(16),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("show delta-only completion".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-delta-only".to_string()),
            turn_id: Some("turn-delta-only".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !16".to_string()),
            summary: Some("Recover delta-only turn via live replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-delta-only".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-delta-only".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("No persisted items."));
    assert!(!body.contains("Recovered delta-only reply."));
    Ok(())
}

#[tokio::test]
async fn run_detail_keeps_command_without_body_without_thread_reader() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 17,
            head_sha: "feed111".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-command-body".to_string()),
            turn_id: Some("turn-command-body".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !17".to_string()),
            summary: Some("Recover command output from live replay".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "status": "completed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-command-body".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
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
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        Some(runner),
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("cargo test"));
    assert!(!body.contains("Recovered command output"));
    Ok(())
}

#[tokio::test]
async fn run_detail_queues_async_backfill_and_serves_rewritten_persisted_history() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 18,
            head_sha: "feed222".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-backfill".to_string()),
            turn_id: Some("turn-backfill".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !18".to_string()),
            summary: Some("Queue background transcript backfill".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let read_calls = Arc::new(AtomicUsize::new(0));
    let runner = Arc::new(CountingThreadReaderRunner {
        read_calls: Arc::clone(&read_calls),
    });
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(StaticTranscriptBackfillSource {
        events: vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [{"type": "summary_text", "text": "Recovered summary"}],
                    "content": [{"type": "reasoning_text", "text": "Recovered detail"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, Some(runner))
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 19,
            head_sha: "feed333".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-security".to_string()),
            turn_id: Some("turn-review".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "pass".to_string(),
            preview: Some("Security review group/repo !19".to_string()),
            summary: Some("Rebuild shared-thread security transcript".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
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
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ]),
        full_thread_events: vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-threat".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-threat".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"focus_paths\":[]}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-threat".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "content": [{"type": "text", "text": "{\"findings\":[],\"overall_correctness\":\"patch is correct\"}"}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 27,
            head_sha: "feedchild".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-wrapper".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !27".to_string()),
            summary: Some("Replace child-only persisted review turn".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 127,
            head_sha: "feedsanitize".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-missing-parent-only-child".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !127".to_string()),
            summary: Some("Recover missing parent turn from full thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 28,
            head_sha: "feeddup".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-duplicate".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !28".to_string()),
            summary: Some("Drop partial stale child review items".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 29,
            head_sha: "feedlater".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-later".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !29".to_string()),
            summary: Some(
                "Preserve later turns while removing stale child review turns".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript"
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "enteredReviewMode",
                            "review": "Investigating",
                            "reviewChildTurnIds": ["turn-stale-child"]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "agentMessage",
                            "text": "fresh review transcript"
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-parent".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 30,
            head_sha: "feedmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-missing-parent".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !30".to_string()),
            summary: Some("Preserve later turns when parent turn is missing".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.161Z"}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript",
                    "createdAt": "2026-03-11T21:32:37.162Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:37.163Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 31,
            head_sha: "feedtargetonly".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-target-only".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !31".to_string()),
            summary: Some("Preserve later turns during target-only fallback".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.161Z"}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child transcript",
                    "createdAt": "2026-03-11T21:32:37.162Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:37.163Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": ["turn-stale-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 34,
            head_sha: "feedplainmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-plain-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !34".to_string()),
            summary: Some("Recover plain missing target turn before later turns".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 32,
            head_sha: "feedempty".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !32".to_string()),
            summary: Some(
                "Recover only the target turn when persisted history is empty".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 33,
            head_sha: "feedemptyother".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty-other".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !33".to_string()),
            summary: Some(
                "Recover target turn even when another turn is still waiting for review child history"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"],
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 36,
            head_sha: "feedtargetothermissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-target-other-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !36".to_string()),
            summary: Some(
                "Recover missing target turn even when another persisted turn still waits on review child history"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "persisted unrelated turn"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-unrelated".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Waiting on unrelated child",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-unrelated".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "recovered target turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 137,
            head_sha: "feedstaleoldertargetmissing".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-older-target-missing".to_string()),
            turn_id: Some("turn-target".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !137".to_string()),
            summary: Some(
                "Recover stale older review-wrapper turns from full-thread backfill when the current target turn is missing"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-old-child"]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-old-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Recovered older turn",
                                "reviewMissingChildTurnIds": ["turn-old-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Recovered current turn"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-target".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 35,
            head_sha: "feedemptytargetreview".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-empty-target".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !35".to_string()),
            summary: Some(
                "Do not finalize target-only recovery while review sibling is missing".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "wrapper summary"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 37,
            head_sha: "feedstalemissingsibling".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-missing-sibling".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !37".to_string()),
            summary: Some(
                "Do not accept stale missing review siblings when the wrapper has no renderable fallback"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 38,
            head_sha: "feedstalewrapperfallback".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-stale-wrapper-fallback".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !38".to_string()),
            summary: Some(
                "Recover stale missing review siblings when wrapper output is renderable"
                    .to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    sqlx::query("UPDATE run_history SET finished_at = 0, updated_at = 0 WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Wrapper fallback summary",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Wrapper fallback summary",
                                "reviewMissingChildTurnIds": ["turn-child-missing"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::new(Mutex::new(Vec::new())),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 31,
            head_sha: "feedmultichild".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-review-multi-child-missing-parent".to_string()),
            turn_id: Some("turn-parent".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !31".to_string()),
            summary: Some("Drop multiple stale child turns without timestamps".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child one"
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-child-one".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "stale child two"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-stale-child-two".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later legitimate turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
            },
        ],
    )
    .await?;
    state
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": [
                                    "turn-stale-child-one",
                                    "turn-stale-child-two"
                                ]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:32:37.160Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Investigating",
                                "createdAt": "2026-03-11T21:32:37.160Z",
                                "reviewChildTurnIds": [
                                    "turn-stale-child-one",
                                    "turn-stale-child-two"
                                ]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "fresh review transcript",
                                "createdAt": "2026-03-11T21:32:37.162Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-parent".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:32:37.164Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "later legitimate turn",
                                "createdAt": "2026-03-11T21:40:01.000Z"
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({
                                "status": "completed",
                                "createdAt": "2026-03-11T21:40:02.000Z"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 19,
            head_sha: "feed333".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .run_history
        .update_run_history_session(
            run_id,
            RunHistorySessionUpdate {
                thread_id: Some("thread-active".to_string()),
                turn_id: Some("turn-active".to_string()),
                review_thread_id: None,
                security_context_source_run_id: None,
                auth_account_name: Some("primary".to_string()),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-active".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-active".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: Vec::new(),
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 20,
            head_sha: "feed444".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-stale-backfill".to_string()),
            turn_id: Some("turn-stale-backfill".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !20".to_string()),
            summary: Some("Retry stale transcript backfill".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-stale-backfill".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    state
        .run_history
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered after restart"}],
                            "content": [{"type": "reasoning_text", "text": "Backfill retried successfully"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-stale-backfill".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "feed555".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-transient".to_string()),
            turn_id: Some("turn-transient".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !21".to_string()),
            summary: Some("Retry after transient session-history miss".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-transient".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-transient".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-transient".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            None,
            None,
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "Recovered after missing file"}],
                        "content": [{"type": "reasoning_text", "text": "Second attempt found session history"}]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-transient".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                },
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 24,
            head_sha: "feed888".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-partial-file".to_string()),
            turn_id: Some("turn-partial-file".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !24".to_string()),
            summary: Some("Retry partial session-history file after cooldown".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-partial-file".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let backfill_source = Arc::new(SequencedTranscriptBackfillSource {
        responses: Arc::new(Mutex::new(vec![
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": []
                    }),
                },
            ]),
            Some(vec![
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "Recovered after partial write"}],
                        "content": [{"type": "reasoning_text", "text": "Second parse saw the finished turn"}]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-partial-file".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                },
            ]),
        ])),
        calls: Arc::clone(&backfill_calls),
    });
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(backfill_source),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "feed666".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-partial".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !22".to_string()),
            summary: Some("Do not mark partial multi-turn transcript complete".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(StaticTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                            "content": [{"type": "reasoning_text", "text": "Older turn still missing"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-new".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feed777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-full-fallback".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Recover older turns from the full local thread".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 8,
                            turn_id: Some("turn-later".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "agentMessage",
                                "text": "Later turn should be ignored"
                            }),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 123,
            head_sha: "feedignore".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-ignore-unrelated-pending".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !123".to_string()),
            summary: Some(
                "Ignore unrelated pending review markers during full-thread fallback".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 7,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 8,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "enteredReviewMode",
                                "review": "Waiting on unrelated child",
                                "reviewMissingChildTurnIds": ["turn-unrelated-child"]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 9,
                            turn_id: Some("turn-unrelated-pending".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 124,
            head_sha: "feedfullthread".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-turn-incomplete-full-ready".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !124".to_string()),
            summary: Some(
                "Use full-thread fallback when turn-scoped backfill is incomplete".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: Some(vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Partial current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Missing turn completion"}]
                            }),
                        },
                    ]),
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 26,
            head_sha: "feedabc".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-missing-turn".to_string()),
            turn_id: Some("turn-new".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !26".to_string()),
            summary: Some(
                "Fallback to whole-thread session history when turn lookup is missing".to_string(),
            ),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-old".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-new".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-new".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let seen_turn_ids = Arc::new(Mutex::new(Vec::new()));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(
                TurnScopedFallbackTranscriptBackfillSource {
                    turn_events: None,
                    full_thread_events: vec![
                        NewRunHistoryEvent {
                            sequence: 1,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 2,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered older turn"}],
                                "content": [{"type": "reasoning_text", "text": "Older turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 3,
                            turn_id: Some("turn-old".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                        NewRunHistoryEvent {
                            sequence: 4,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_started".to_string(),
                            payload: json!({}),
                        },
                        NewRunHistoryEvent {
                            sequence: 5,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "item_completed".to_string(),
                            payload: json!({
                                "type": "reasoning",
                                "summary": [{"type": "summary_text", "text": "Recovered current turn"}],
                                "content": [{"type": "reasoning_text", "text": "Current turn detail"}]
                            }),
                        },
                        NewRunHistoryEvent {
                            sequence: 6,
                            turn_id: Some("turn-new".to_string()),
                            event_type: "turn_completed".to_string(),
                            payload: json!({"status": "completed"}),
                        },
                    ],
                    seen_turn_ids: Arc::clone(&seen_turn_ids),
                },
            )),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 25,
            head_sha: "feed999".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-base".to_string()),
            turn_id: Some("turn-review".to_string()),
            review_thread_id: Some("thread-review".to_string()),
            auth_account_name: Some("primary".to_string()),
            security_context_source_run_id: None,
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !25".to_string()),
            summary: Some("Backfill should read base thread history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-review".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-review".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let seen_thread_id = Arc::new(Mutex::new(None));
    let seen_turn_id = Arc::new(Mutex::new(None));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(CapturingTranscriptBackfillSource {
                events: vec![
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered"}],
                            "content": [{"type": "reasoning_text", "text": "Base thread history used"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-review".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: json!({"status": "completed"}),
                    },
                ],
                calls: Arc::clone(&backfill_calls),
                seen_thread_id: Arc::clone(&seen_thread_id),
                seen_turn_id: Arc::clone(&seen_turn_id),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feed777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-unavailable".to_string()),
            turn_id: Some("turn-unavailable".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Do not retry unavailable local session history".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-unavailable".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-unavailable".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "reasoning",
                    "summary": [],
                    "content": []
                }),
            },
        ],
    )
    .await?;
    let backfill_calls = Arc::new(AtomicUsize::new(0));
    let status_service = Arc::new(
        HttpServices::new(test_config(), Arc::clone(&state), false, None)
            .with_transcript_backfill_source(Arc::new(ErroringTranscriptBackfillSource {
                error: TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR,
                calls: Arc::clone(&backfill_calls),
            })),
    );
    let address = spawn_test_server(app_router(status_service)).await?;

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

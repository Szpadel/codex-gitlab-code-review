use super::*;

#[tokio::test]
async fn stream_batches_events_and_preserves_order_on_completion_and_io_failure() -> Result<()> {
    for complete in [true, false] {
        let state = ReviewStateStore::new(":memory:").await?;
        let run_id = state
            .run_history
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Mention,
                repo: "group/repo".to_string(),
                iid: 1,
                head_sha: "sha".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        let mut client = empty_app_server_client();
        let mut frames = Vec::new();
        for index in 0..65 {
            frames.push(Ok(LogOutput::StdOut {
                message: format!("{}\n", json!({"method":"item/completed", "params": {
                    "item": {"id": format!("item-{index}"), "type":"agentMessage", "text":index.to_string()}
                }})).into(),
            }));
        }
        if complete {
            frames.push(Ok(LogOutput::StdOut {
                message: format!(
                    "{}\n",
                    json!({"method":"turn/completed", "params":{"turn":{"status":"completed"}}})
                )
                .into(),
            }));
        }
        client.output = Box::pin(futures::stream::iter(frames));
        let batches = std::sync::Mutex::new(Vec::new());
        let result = client
            .stream_turn_message(
                "thread",
                "turn",
                None,
                |events| async {
                    state
                        .run_history
                        .append_run_history_events(run_id, &events)
                        .await
                        .expect("persist batch");
                    batches.lock().unwrap().push(events);
                },
                || async {},
            )
            .await;
        assert_eq!(result.is_ok(), complete);
        let batches = batches.into_inner().unwrap();
        assert_eq!(batches.len(), 3);
        let items = batches
            .iter()
            .flatten()
            .filter(|event| event.event_type == "item_completed")
            .map(|event| event.payload["text"].as_str().unwrap().to_string())
            .collect::<Vec<_>>();
        assert_eq!(
            items,
            (0..65).map(|index| index.to_string()).collect::<Vec<_>>()
        );
        if complete {
            assert_eq!(
                batches.last().unwrap().last().unwrap().event_type,
                "turn_completed"
            );
        }
        let persisted = state.run_history.list_run_history_events(run_id).await?;
        assert_eq!(persisted.len(), if complete { 66 } else { 65 });
        assert_eq!(
            persisted
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            (1..=i64::try_from(persisted.len())?).collect::<Vec<_>>()
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelled_stream_flushes_its_partial_batch_when_session_closes() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![]));
    let runner = test_runner_with_fake_runtime(test_codex_config(), false, harness, None).await;
    let run_id = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 1,
            head_sha: "sha".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let mut session = runner
        .start_runner_session(super::super::session_runner::RunnerSessionConfig {
            script: String::new(),
            auth_account: runner.auth_accounts[0].clone(),
            run_history_id: Some(run_id),
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            gitlab_discovery_extra_hosts: vec![],
            startup_cleanup: None,
        })
        .await?;
    session.client.output = Box::pin(
        futures::stream::once(async {
            Ok(LogOutput::StdOut {
                message: format!("{}\n", json!({"method":"turn/started", "params":{}})).into(),
            })
        })
        .chain(futures::stream::pending()),
    );
    let result = tokio::time::timeout(
        Duration::from_millis(20),
        runner.session_stream_review(&mut session, "thread", "turn"),
    )
    .await;
    assert!(result.is_err());
    runner.close_runner_session(session).await;
    runner.state.flush_background_writes().await?;
    let events = runner
        .state
        .run_history
        .list_run_history_events(run_id)
        .await?;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, "turn_started");
    Ok(())
}

#[tokio::test]
async fn completed_agent_message_without_deltas_returns_text() -> Result<()> {
    for item in [
        json!({"type": "agentMessage", "text": "Final answer"}),
        json!({
            "type": "AgentMessage",
            "text": "Final answer",
            "content": [{"type": "Text", "text": "Old content"}]
        }),
        json!({
            "type": "agentMessage",
            "text": " ",
            "content": [{"type": "Text", "text": "Final answer"}]
        }),
    ] {
        let mut client = empty_app_server_client();
        client.output = Box::pin(futures::stream::iter([
            Ok(LogOutput::StdOut {
                message: format!(
                    "{}\n",
                    json!({"method": "item/completed", "params": {"item": item}})
                )
                .into(),
            }),
            Ok(LogOutput::StdOut {
                message: format!(
                    "{}\n",
                    json!({"method": "turn/completed", "params": {"turn": {"status": "completed"}}})
                )
                .into(),
            }),
        ]));
        let message = client
            .stream_turn_message("thread", "turn", None, |_| async {}, || async {})
            .await?;
        assert_eq!(message, "Final answer");
    }
    Ok(())
}

#[tokio::test]
async fn interleaved_stderr_does_not_corrupt_stdout_json() -> Result<()> {
    let mut client = empty_app_server_client();
    client.output = Box::pin(futures::stream::iter([
        Ok(LogOutput::StdOut {
            message: br#"{"method":"turn/"#.as_slice().into(),
        }),
        Ok(LogOutput::StdErr {
            message: b"codex-runner-error: diagnostic\n{\"method\":\"stderr-json\"}\n"
                .as_slice()
                .into(),
        }),
        Ok(LogOutput::StdOut {
            message: b"completed\"}\n".as_slice().into(),
        }),
    ]));
    assert_eq!(
        client.next_message().await?,
        json!({"method": "turn/completed"})
    );
    assert_eq!(
        client.recent_runner_errors,
        VecDeque::from(["codex-runner-error: diagnostic".to_string()])
    );
    Ok(())
}

#[tokio::test]
async fn fragmented_long_lines_complete_within_deadline() -> Result<()> {
    let text = "x".repeat(2 * 1024 * 1024);
    let expected = json!({"text": text});
    let stdout = format!("{expected}\n{{\"next\":true}}\n");
    let stderr = format!("codex-runner-error: {text}\n");
    let frames = stderr
        .as_bytes()
        .chunks(128)
        .map(|chunk| LogOutput::StdErr {
            message: chunk.to_vec().into(),
        })
        .chain(
            stdout
                .as_bytes()
                .chunks(128)
                .map(|chunk| LogOutput::StdOut {
                    message: chunk.to_vec().into(),
                }),
        )
        .collect::<VecDeque<_>>();
    let mut client = empty_app_server_client();
    client.output = Box::pin(futures::stream::unfold(frames, |mut frames| async {
        tokio::task::yield_now().await;
        frames.pop_front().map(|frame| (Ok(frame), frames))
    }));

    // A generous deadline rejects repeated scans of multi-megabyte lines.
    let first = tokio::time::timeout(Duration::from_secs(5), client.next_message()).await??;
    assert_eq!(first, expected);
    assert_eq!(client.next_message().await?, json!({"next": true}));
    assert_eq!(client.recent_runner_errors.len(), 1);
    Ok(())
}

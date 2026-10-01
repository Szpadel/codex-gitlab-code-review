use super::*;

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

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

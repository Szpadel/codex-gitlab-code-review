use super::*;

fn write_review_sessions(root: &Path) -> Result<PathBuf> {
    let outer = [
        json!({"type": "session_meta", "payload": {"id": "outer"}}),
        json!({"type": "event_msg", "payload": {
            "type": "entered_review_mode", "user_facing_hint": "Review changes"
        }}),
        json!({"type": "event_msg", "payload": {
            "type": "task_started", "turn_id": "child"
        }}),
        json!({"type": "event_msg", "payload": {
            "type": "task_complete", "turn_id": "parent"
        }}),
    ];
    let sibling = [
        json!({"type": "session_meta", "payload": {
            "id": "sibling", "source": {"subagent": "review"}
        }}),
        json!({"type": "turn_context", "payload": {"turn_id": "child"}}),
        json!({"type": "response_item", "payload": {
            "type": "agentMessage", "text": "Recovered sibling transcript."
        }}),
        json!({"type": "event_msg", "payload": {
            "type": "task_complete", "turn_id": "child"
        }}),
    ];
    let sibling_path = root.join("sibling.jsonl");
    for (path, records) in [
        (root.join("outer.jsonl"), outer),
        (sibling_path.clone(), sibling),
    ] {
        let lines = records.map(|record| record.to_string()).join("\n") + "\n";
        fs::write(path, lines)?;
    }
    Ok(sibling_path)
}

#[tokio::test]
async fn unrelated_corrupt_session_does_not_block_sibling_recovery() -> Result<()> {
    let root = tempfile::tempdir()?;
    write_review_sessions(root.path())?;
    fs::write(
        root.path().join("unrelated.jsonl"),
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"unrelated\",\"source\":{\"subagent\":\"review\"}}}\nnot-json\n",
    )?;

    let events = SessionHistoryBackfillSource::new(root.path())
        .load_events("outer", Some("parent"))
        .await?
        .context("recovered transcript")?;
    assert!(events.iter().any(|event| {
        event.turn_id.as_deref() == Some("parent")
            && event.payload["text"] == "Recovered sibling transcript."
    }));
    assert!(!events.iter().any(|event| {
        event
            .payload
            .get(REVIEW_MISSING_CHILD_TURN_IDS_KEY)
            .is_some()
    }));
    Ok(())
}

#[tokio::test]
async fn selected_corrupt_sibling_returns_its_parse_error() -> Result<()> {
    let root = tempfile::tempdir()?;
    let sibling = write_review_sessions(root.path())?;
    let mut raw = fs::read_to_string(&sibling)?;
    raw.push_str("not-json\n");
    fs::write(&sibling, raw)?;

    let error = SessionHistoryBackfillSource::new(root.path())
        .load_events("outer", Some("parent"))
        .await
        .expect_err("selected sibling must report corruption");
    assert!(error.to_string().contains("parse session line 5"));
    assert!(error.to_string().contains("sibling.jsonl"));
    Ok(())
}

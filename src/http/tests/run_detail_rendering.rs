use super::*;

#[tokio::test]
async fn run_detail_loads_large_collapsed_bodies_one_entry_at_a_time() -> Result<()> {
    // Persist a completed turn with all five verbose entry kinds.
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let run_id = RunFixture::review("group/repo", 7, "sha")
        .thread("thread-1")
        .turn("turn-1")
        .result("pass")
        .insert(&srv.state)
        .await?;
    let long_body = format!("{}<script>entry-tail</script>", "x".repeat(64 * 1024));
    let payloads = [
        json!({"type": "mcpToolCall", "server": "gitlab", "tool": "get_mr", "arguments": {}, "result": long_body}),
        json!({"type": "dynamicToolCall", "tool": "inspect", "contentItems": {}, "result": long_body}),
        json!({"type": "reasoning", "summary": ["Short reasoning summary"], "content": [long_body]}),
        json!({"type": "fileChange", "changes": {"src/lib.rs": {"unified_diff": format!("--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+{long_body}\n")}}}),
        json!({"type": "webSearch", "query": "small query", "action": {"output": long_body}}),
    ];
    let mut events = vec![turn_started_event(1, "turn-1")];
    events.extend(payloads.into_iter().enumerate().map(|(index, payload)| {
        run_event(index as i64 + 2, Some("turn-1"), "item_completed", payload)
    }));
    events.extend([
        reasoning_event(7, "turn-1", "Small summary", "Small detail"),
        agent_message_event(8, "turn-1", "Visible **message**"),
        turn_completed_event(9, "turn-1"),
    ]);
    insert_run_history_events(&srv.state, run_id, events).await?;
    // Keep summaries and short entries visible without verbose body markup.
    let page = test_get(format!("http://{}/history/{run_id}", srv.address))
        .await?
        .text()
        .await?;
    assert!(
        !page.contains("entry-tail"),
        "large collapsed body is absent from the page"
    );
    assert!(page.contains("Short reasoning summary"));
    assert!(page.contains("Small detail"));
    assert!(page.contains("Visible <strong>message</strong>"));
    assert_eq!(page.matches("data-transcript-body-url=").count(), 5);
    let persisted = srv
        .state
        .run_history
        .list_run_history_events(run_id)
        .await?;
    // Fetch each body separately and retain escaping and diff markup.
    for event in &persisted[1..6] {
        let route = format!("/api/history/{run_id}/entries/{}/body", event.id);
        assert!(page.contains(&route));
        let response = test_get(format!("http://{}{route}", srv.address)).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()["content-type"]
                .to_str()?
                .starts_with("text/html")
        );
        let body = response.text().await?;
        assert!(body.contains("entry-tail"));
        assert!(!body.contains("<script>entry-tail</script>"));
        assert!(!body.contains("Small detail"));
        if event.payload["type"] == "fileChange" {
            assert!(body.contains("diff-line-add"));
            assert!(body.contains("diff-line-remove"));
        }
    }
    // Keep the existing run JSON response complete.
    let json: Value = test_get(format!("http://{}/api/history/{run_id}", srv.address))
        .await?
        .json()
        .await?;
    assert!(
        json["thread"]["turns"][0]["items"][0]["body"]
            .as_str()
            .unwrap()
            .contains("entry-tail")
    );
    assert!(
        json["thread"]["turns"][0]["items"][0]
            .get("event_id")
            .is_none()
    );

    // Reject unknown entries, other runs, and non-expandable events.
    let other_run = RunFixture::review("group/other", 2, "sha")
        .insert(&srv.state)
        .await?;
    for (requested_run, event_id) in [
        (other_run, persisted[1].id),
        (run_id, persisted[0].id),
        (run_id, persisted[7].id),
        (run_id, i64::MAX),
    ] {
        assert_eq!(
            test_get(format!(
                "http://{}/api/history/{requested_run}/entries/{event_id}/body",
                srv.address
            ))
            .await?
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    // A body request must not parse an unrelated event from the same run.
    sqlx::query("UPDATE run_history_event SET payload_json = 'not-json' WHERE id = ?")
        .bind(persisted[7].id)
        .execute(srv.state.pool())
        .await?;
    assert_eq!(
        test_get(format!(
            "http://{}/api/history/{run_id}/entries/{}/body",
            srv.address, persisted[1].id
        ))
        .await?
        .status(),
        StatusCode::OK
    );
    Ok(())
}

#[tokio::test]
async fn transcript_entry_body_route_is_disabled_with_the_status_ui() -> Result<()> {
    let mut config = test_config();
    config.server.status_ui_enabled = false;
    let srv = HttpTestServerBuilder::new()
        .with_config(config)
        .spawn()
        .await?;
    let run_id = RunFixture::review("group/repo", 7, "sha")
        .insert(&srv.state)
        .await?;
    insert_run_history_events(
        &srv.state,
        run_id,
        vec![reasoning_event(1, "turn-1", "Summary", "Detail")],
    )
    .await?;
    let event_id = srv
        .state
        .run_history
        .list_run_history_events(run_id)
        .await?[0]
        .id;
    assert!(
        srv.services
            .status
            .transcript_entry_body(run_id, event_id)
            .await?
            .is_some()
    );
    assert_eq!(
        test_get(format!(
            "http://{}/api/history/{run_id}/entries/{event_id}/body",
            srv.address
        ))
        .await?
        .status(),
        StatusCode::NOT_FOUND
    );
    Ok(())
}

#[tokio::test]
async fn run_detail_limits_related_sessions_and_links_to_mr_history() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let mut ids = Vec::new();
    for _ in 0..60 {
        ids.push(
            RunFixture::review("group/repo", 7, "sha")
                .result("pass")
                .insert(&srv.state)
                .await?,
        );
    }
    let run_id = ids[0];
    let snapshot = srv
        .services
        .status
        .run_detail_snapshot(run_id)
        .await?
        .unwrap();
    assert_eq!(snapshot.related_runs.len(), 50);
    assert_eq!(snapshot.related_runs[0].id, ids[59]);
    assert_eq!(snapshot.related_runs[49].id, ids[10]);
    let serialized = serde_json::to_value(&snapshot)?;
    assert!(
        serialized["related_runs"][0]
            .get("security_context_payload_json")
            .is_none()
    );
    assert!(
        serialized["related_runs"][0]
            .get("trigger_note_body")
            .is_none()
    );
    let body = reqwest::get(format!("http://{}/history/{run_id}", srv.address))
        .await?
        .text()
        .await?;
    assert!(body.contains("View MR history"));
    assert!(body.contains(&format!(
        "/mr/{}/7/history",
        crate::http::view::encode_repo_key("group/repo")
    )));
    Ok(())
}
#[tokio::test]
async fn run_detail_page_renders_trigger_note_and_thread_preview() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: Some("discussion-7".to_string()),
            trigger_note_id: Some(321),
            trigger_note_author_name: Some("qa<script>".to_string()),
            trigger_note_body: Some("please fix <broken> command".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7 note 321".to_string()),
            summary: Some("Implemented requested fix".to_string()),
            commit_sha: Some("deadbeef".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-11T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    let finished_at = DateTime::parse_from_rfc3339("2026-03-11T12:05:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query(
        "UPDATE run_history SET started_at = ?, finished_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(started_at)
    .bind(finished_at)
    .bind(finished_at)
    .bind(run_id)
    .execute(state.pool())
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:00Z",
                    "type": "userMessage",
                    "content": [{ "type": "text", "text": "Please inspect the failing job." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:05Z",
                    "type": "reasoning",
                    "summary": ["Need to inspect CI output"],
                    "content": ["The failure looks deterministic."]
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:06Z",
                    "type": "reasoning",
                    "summary": [
                        { "type": "summary_text", "text": "Typed reasoning summary" }
                    ],
                    "content": [
                        { "type": "reasoning_text", "text": "Typed reasoning detail." }
                    ]
                }),
            },
            NewRunHistoryEvent {
                sequence: 5,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "createdAt": "2026-03-11T12:54:07Z",
                    "type": "reasoning",
                    "summary": [],
                    "content": null,
                    "encrypted_content": "opaque-reasoning-blob"
                }),
            },
            NewRunHistoryEvent {
                sequence: 6,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "cwd": "/workdir",
                    "status": "completed",
                    "exitCode": 0,
                    "durationMs": 1200,
                    "aggregatedOutput": "all tests passed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 7,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "mcpToolCall",
                    "server": "gitlab",
                    "tool": "get_merge_request",
                    "arguments": { "iid": 7, "include": "changes" },
                    "status": "completed",
                    "durationMs": 50,
                    "result": { "iid": 7 }
                }),
            },
            NewRunHistoryEvent {
                sequence: 8,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "dynamicToolCall",
                    "tool": "resolve_release_note_template",
                    "status": "completed",
                    "durationMs": 18,
                    "contentItems": [{"type": "inputText", "text": "Use the customer-facing changelog template."}]
                }),
            },
            NewRunHistoryEvent {
                sequence: 9,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "webSearch",
                    "query": "ci retry strategy",
                    "action": { "type": "search", "query": "ci retry strategy" }
                }),
            },
            NewRunHistoryEvent {
                sequence: 10,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "src/main.rs": {
                            "type": "update",
                            "unified_diff": "@@ -1,7 +1,8 @@\n---- banner\n--- docs/readme\n-old line\n+new line\n+--- frontmatter\n+++ heading\n+++ /tmp/cache\n unchanged\n"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 11,
                turn_id: Some("turn-1".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "AgentMessage",
                    "phase": "final",
                    "content": [{ "type": "Text", "text": "Implemented the requested fix." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 12,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Trigger note"));
    assert!(body.contains("qa&lt;script&gt;"));
    assert!(body.contains("please fix &lt;broken&gt; command"));
    assert!(body.contains("Session transcript"));
    assert!(body.contains("transcript-panel"));
    assert!(body.contains("transcript-stream"));
    assert!(body.contains("message-entry"));
    assert!(body.contains("message-timestamp"));
    assert!(body.contains("class=\"localized-timestamp message-timestamp\""));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:54:00Z\""));
    assert!(body.contains("Mar 11, 2026, 12:54 PM UTC"));
    assert!(body.contains("reasoning-entry"));
    assert!(body.contains("terminal-entry"));
    assert!(body.contains("mcp-entry"));
    assert!(body.contains("dynamic-tool-entry"));
    assert!(body.contains("<summary class=\"entry-summary reasoning-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary tool-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary web-search-summary\">"));
    assert!(body.contains("<summary class=\"entry-summary file-change-summary\">"));
    assert!(!body.contains("<summary class=\"entry-summary reasoning-summary\"><div"));
    assert!(body.contains("tool-preview-box"));
    assert!(body.contains("web-search-entry"));
    assert!(body.contains("diff-view"));
    assert!(body.contains("1.2 s"));
    assert!(body.contains("50 ms"));
    assert!(!body.contains("turn-label\">Turn</p>"));
    assert!(body.contains(">src/main.rs</span>"));
    assert!(body.contains("diff-stats-add\">+4</span>"));
    assert!(body.contains("diff-stats-remove\">-3</span>"));
    assert!(body.contains("Reasoning"));
    assert!(body.contains("Need to inspect CI output"));
    assert!(body.contains("The failure looks deterministic."));
    assert!(body.contains("Typed reasoning summary"));
    assert!(body.contains("Typed reasoning detail."));
    assert!(body.contains(
        "Reasoning is unavailable because Codex returned only encrypted history for this step."
    ));
    assert!(body.contains("cargo test"));
    assert!(body.contains("gitlab:get_merge_request"));
    assert!(body.contains("Arguments"));
    assert!(body.contains("&quot;include&quot;: &quot;changes&quot;"));
    assert!(body.contains("Result"));
    assert!(body.contains("resolve_release_note_template"));
    assert!(body.contains("Use the customer-facing changelog template."));
    assert!(body.contains("ci retry strategy"));
    assert!(body.contains("diff-line-add"));
    assert!(body.contains("diff-line-remove"));
    assert!(body.contains("diff-line-add\">+--- frontmatter</div>"));
    assert!(body.contains("diff-line-add\">+++ heading</div>"));
    assert!(body.contains("diff-line-add\">+++ /tmp/cache</div>"));
    assert!(body.contains("diff-line-remove\">---- banner</div>"));
    assert!(body.contains("diff-line-remove\">--- docs/readme</div>"));
    assert!(body.contains("Implemented the requested fix."));
    assert!(body.contains("Please inspect the failing job."));
    Ok(())
}

#[tokio::test]
async fn run_detail_uses_review_thread_id_in_metadata_when_events_exist() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 9,
            head_sha: "abc777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-base".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: Some("thread-review".to_string()),
            auth_account_name: Some("primary".to_string()),
            security_context_source_run_id: None,
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !9".to_string()),
            summary: Some("Posted findings".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-11T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    let finished_at = DateTime::parse_from_rfc3339("2026-03-11T12:05:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query(
        "UPDATE run_history SET started_at = ?, finished_at = ?, updated_at = ? WHERE id = ?",
    )
    .bind(started_at)
    .bind(finished_at)
    .bind(finished_at)
    .bind(run_id)
    .execute(state.pool())
    .await?;
    insert_run_history_events(
        &state,
        run_id,
        vec![
            NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("meta-chip-label\">Thread</span><code>thread-review</code>"));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:00:00Z\""));
    assert!(body.contains("data-timestamp=\"2026-03-11T12:05:00Z\""));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_dynamic_tool_results_and_failed_command_status() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "deadbeef".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-21".to_string()),
            turn_id: Some("turn-21".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !21".to_string()),
            summary: Some("Check dynamic tool result and failed command styling".to_string()),
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
                turn_id: Some("turn-21".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-21".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "dynamicToolCall",
                    "tool": "resolve_release_note_template",
                    "status": "completed",
                    "durationMs": 18,
                    "result": { "template": "customer-facing" }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-21".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "commandExecution",
                    "command": "cargo test",
                    "status": "completed",
                    "exitCode": 1,
                    "durationMs": 250,
                    "aggregatedOutput": "1 test failed"
                }),
            },
            NewRunHistoryEvent {
                sequence: 4,
                turn_id: Some("turn-21".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("resolve_release_note_template"));
    assert!(body.contains("customer-facing"));
    assert!(body.contains("Result"));
    assert!(body.contains("status-pill status-danger\">failed</span>"));
    assert!(body.contains("1 test failed"));
    assert!(!body.contains("<span class=\"message-timestamp\">"));
    Ok(())
}

#[tokio::test]
async fn run_detail_formats_numeric_millisecond_timestamps_as_utc() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 24,
            head_sha: "cafebabe".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-24".to_string()),
            turn_id: Some("turn-24".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !24".to_string()),
            summary: Some("Format millisecond timestamps".to_string()),
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
                turn_id: Some("turn-24".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-24".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "userMessage",
                    "createdAt": 1773233640000i64,
                    "content": [{ "type": "text", "text": "Check timestamp formatting." }]
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-24".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("data-timestamp=\"2026-03-11T12:54:00Z\""));
    assert!(body.contains("Mar 11, 2026, 12:54 PM UTC"));
    assert!(!body.contains("1773233640000"));
    Ok(())
}

#[tokio::test]
async fn run_detail_page_falls_back_when_event_history_is_missing() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: Some("discussion-7".to_string()),
            trigger_note_id: Some(321),
            trigger_note_author_name: Some("qa".to_string()),
            trigger_note_body: Some("please fix command".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7 note 321".to_string()),
            summary: Some("Implemented requested fix".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Run metadata"));
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    Ok(())
}

#[tokio::test]
async fn run_detail_page_renders_failure_details_without_event_history() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "error".to_string(),
            preview: Some("Review group/repo !7".to_string()),
            error: Some("codex turn failed: <network timeout>".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Failure details"));
    assert!(body.contains("codex turn failed: &lt;network timeout&gt;"));
    assert!(body.contains("Codex thread detail is unavailable for this run."));
    Ok(())
}

#[tokio::test]
async fn run_detail_page_renders_failed_turn_error_from_transcript_events() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc999".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "error".to_string(),
            preview: Some("Review group/repo !7".to_string()),
            error: Some("review failed".to_string()),
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
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "failed",
                    "error": "model stream closed before final response"
                }),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("status-pill status-danger\">failed</span>"));
    assert!(body.contains("model stream closed before final response"));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_non_diff_file_change_payload_as_plain_body() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "beadfeed".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-22".to_string()),
            turn_id: Some("turn-22".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !22".to_string()),
            summary: Some("Show file change payload without unified diff".to_string()),
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
                turn_id: Some("turn-22".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-22".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "README.md": {
                            "type": "rename",
                            "previous_path": "README-old.md"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-22".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("README.md"));
    assert!(body.contains("&quot;type&quot;: &quot;rename&quot;"));
    assert!(!body.contains("meta-pill preview-pill\">diff</span>"));
    assert!(!body.contains("<div class=\"diff-view\">"));
    Ok(())
}

#[tokio::test]
async fn run_detail_renders_mixed_file_change_payloads_with_diff_sections() -> Result<()> {
    let srv = HttpTestServerBuilder::new().spawn().await?;
    let state = Arc::clone(&srv.state);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 23,
            head_sha: "feedbead".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate {
            thread_id: Some("thread-23".to_string()),
            turn_id: Some("turn-23".to_string()),
            review_thread_id: None,
            security_context_source_run_id: None,
            auth_account_name: Some("primary".to_string()),
            ..RunHistorySessionUpdate::default()
        },
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !23".to_string()),
            summary: Some("Show mixed file changes".to_string()),
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
                turn_id: Some("turn-23".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-23".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "fileChange",
                    "status": "completed",
                    "changes": {
                        "src/lib.rs": {
                            "type": "update",
                            "unified_diff": "@@ -1 +1 @@\n-old\n+new\n"
                        },
                        "README.md": {
                            "type": "rename",
                            "previous_path": "README-old.md"
                        }
                    }
                }),
            },
            NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-23".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .await?;
    let address = srv.address;

    let response = reqwest::get(format!("http://{address}/history/{run_id}")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains(">2 files changed</span>"));
    assert!(body.contains("diff-stats-add\">+1</span>"));
    assert!(body.contains("diff-stats-remove\">-1</span>"));
    assert!(body.contains("meta-pill preview-pill\">diff</span>"));
    assert!(body.contains("file-change-section-path\"><code>src/lib.rs</code>"));
    assert!(body.contains("file-change-section-path\"><code>README.md</code>"));
    assert!(body.contains("diff-line-add\">+new</div>"));
    assert!(body.contains("&quot;previous_path&quot;: &quot;README-old.md&quot;"));
    Ok(())
}

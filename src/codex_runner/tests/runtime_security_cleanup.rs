use super::*;

#[tokio::test]
async fn security_context_startup_timeout_removes_nested_containers() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    for (arguments, stdout) in [
        (vec!["merge-base", "HEAD", "main"], "merge-base-sha"),
        (
            vec!["rev-parse", "refs/remotes/origin/main"],
            "base-head-sha",
        ),
    ] {
        harness.push_exec_output(
            ExecContainerCommandRequest {
                container_id: "app-1".to_string(),
                command: auxiliary_git_exec_command(
                    &arguments
                        .into_iter()
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                ),
                cwd: Some(repo_dir.clone()),
                env: None,
            },
            ContainerExecOutput {
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        );
    }
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({"thread": {"id": "review"}})),
    ]));
    harness.push_app_server(ScriptedAppServer::default());
    let browser_mcp = test_browser_mcp_config("npx");
    harness.set_browser_diagnostics(
        "browser-2",
        vec![BrowserContainerDiagnostics {
            container_id: "browser-2".to_string(),
            launch: BrowserLaunchConfig::from_browser_mcp(&browser_mcp),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("created".to_string()),
                running: Some(false),
                exit_code: None,
                oom_killed: None,
                error: None,
                started_at: None,
                finished_at: None,
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail::default(),
            log_collection_error: None,
        }],
    );
    let codex = CodexConfig {
        timeout_seconds: 1,
        browser_mcp,
        ..test_codex_config()
    };
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review::ReviewLane::Security;
    ctx.min_confidence_score = Some(0.85);

    let error = runner.run_review(ctx).await.expect_err("startup timeout");
    assert!(format!("{error:#}").contains("codex review timed out"));
    let mut removed = harness.removed_containers();
    removed.sort();
    assert_eq!(removed, vec!["app-1", "app-2", "browser-1", "browser-2"]);
    Ok(())
}

#[tokio::test]
async fn security_context_timeout_preserves_its_partial_transcript() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let worktree_path = "/tmp/codex-security-context-123456";
    for (container_id, command, stdout) in [
        (
            "app-1",
            auxiliary_git_exec_command(&["merge-base".into(), "HEAD".into(), "main".into()]),
            "merge-base-sha",
        ),
        (
            "app-1",
            auxiliary_git_exec_command(&["rev-parse".into(), "refs/remotes/origin/main".into()]),
            "base-head-sha",
        ),
        (
            "app-2",
            vec![
                "mktemp".into(),
                "-d".into(),
                "/tmp/codex-security-context-XXXXXX".into(),
            ],
            worktree_path,
        ),
        (
            "app-2",
            auxiliary_git_exec_command(&[
                "worktree".into(),
                "add".into(),
                "--detach".into(),
                worktree_path.into(),
                "base-head-sha".into(),
            ]),
            "",
        ),
    ] {
        harness.push_exec_output(
            ExecContainerCommandRequest {
                container_id: container_id.to_string(),
                command,
                cwd: Some(repo_dir.clone()),
                env: None,
            },
            ContainerExecOutput {
                exit_code: 0,
                stdout: stdout.to_string(),
                stderr: String::new(),
            },
        );
    }
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({"thread": {"id": "review"}})),
    ]));
    // Complete one batch, then leave two events pending until the timeout.
    let mut partial_turn = vec![ScriptedAppChunk::Json(json!({
        "method": "turn/started",
        "params": {"threadId": "context", "turnId": "context-turn"}
    }))];
    for index in 0..33 {
        partial_turn.push(ScriptedAppChunk::Json(json!({
            "method": "item/completed",
            "params": {
                "threadId": "context",
                "turnId": "context-turn",
                "item": {
                    "type": "agentMessage",
                    "id": format!("partial-{index}"),
                    "text": format!("Partial context {index}")
                }
            }
        })));
    }
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({"thread": {"id": "context"}})),
        ScriptedAppRequest::result("turn/start", json!({"turn": {"id": "context-turn"}}))
            .with_after_response(partial_turn),
    ]));
    let codex = CodexConfig {
        timeout_seconds: 1,
        ..test_codex_config()
    };
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;
    let run_history_id = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review::ReviewLane::Security;
    ctx.min_confidence_score = Some(0.85);
    ctx.run_history_id = Some(run_history_id);

    let error = runner.run_review(ctx).await.expect_err("context timeout");
    assert!(format!("{error:#}").contains("codex review timed out"));
    runner.state.flush_background_writes().await?;
    let events = runner
        .state
        .run_history
        .list_run_history_events(run_history_id)
        .await?;
    assert_eq!(
        events.len(),
        34,
        "retain the cancelled nested session batch"
    );
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("context-turn"));
    assert_eq!(events[0].event_type, "turn_started");
    for (index, event) in events[1..].iter().enumerate() {
        assert_eq!(event.sequence, index as i64 + 2);
        assert_eq!(event.turn_id.as_deref(), Some("context-turn"));
        assert_eq!(event.event_type, "item_completed");
        assert_eq!(event.payload["id"], format!("partial-{index}"));
        assert_eq!(event.payload["text"], format!("Partial context {index}"));
    }
    let mut removed = harness.removed_containers();
    removed.sort();
    assert_eq!(removed, vec!["app-1", "app-2"]);
    Ok(())
}

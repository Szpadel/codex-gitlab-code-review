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

use super::*;
#[tokio::test]
async fn run_review_with_fake_runtime_security_lane_uses_split_sessions_on_cache_miss() -> Result<()>
{
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_app_server(scripted_security_review_server(
        "thread-review",
        None,
        None,
        0,
        "turn-review",
        "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}",
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context",
        "turn-threat",
        "{\"components\":[],\"entry_points\":[],\"trust_boundaries\":[],\"attacker_controlled_inputs\":[],\"privileged_operations\":[],\"sensitive_assets\":[],\"security_critical_paths\":[],\"runtime_notes\":[],\"focus_paths\":[]}",
        0,
    ));

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
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
    ctx.lane = crate::review_lane::ReviewLane::Security;
    ctx.min_confidence_score = Some(0.85);
    ctx.run_history_id = Some(run_history_id);

    let result = runner.run_review(ctx).await?;
    match result {
        CodexResult::Pass { summary } => {
            assert_eq!(summary, "No confirmed security issues.");
        }
        other => bail!("expected pass result, got {other:?}"),
    }

    let request_methods = harness
        .app_protocol_requests()
        .into_iter()
        .filter_map(|message| {
            message
                .get("method")
                .and_then(|value| value.as_str())
                .map(ToOwned::to_owned)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        request_methods,
        vec![
            "initialize".to_string(),
            "initialized".to_string(),
            "thread/start".to_string(),
            "initialize".to_string(),
            "initialized".to_string(),
            "thread/start".to_string(),
            "turn/start".to_string(),
            "turn/start".to_string(),
        ]
    );
    let app_server_starts = harness.app_server_starts();
    assert_eq!(app_server_starts.len(), 2);
    assert!(
        app_server_starts[0]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    assert!(
        app_server_starts[1]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"xhigh\""))
    );

    let run = runner
        .state
        .run_history
        .get_run_history(run_history_id)
        .await?
        .expect("run history");
    assert_eq!(run.thread_id.as_deref(), Some("thread-review"));
    assert_eq!(run.turn_id.as_deref(), Some("turn-review"));
    assert_eq!(run.review_thread_id, None);
    assert_eq!(run.security_context_source_run_id, Some(run_history_id));
    assert_eq!(run.security_context_base_branch.as_deref(), Some("main"));
    assert_eq!(
        run.security_context_base_head_sha.as_deref(),
        Some("base-head-sha")
    );
    assert_eq!(
        run.security_context_prompt_version.as_deref(),
        Some("security-review-context-v1")
    );
    assert!(run.security_context_payload_json.is_some());
    assert!(run.security_context_generated_at.is_some());
    assert!(run.security_context_expires_at.is_some());

    let events = runner
        .state
        .run_history
        .list_run_history_events(run_history_id)
        .await?;
    let turn_ids = events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(turn_ids, BTreeSet::from(["turn-review", "turn-threat"]));

    let cache_entry = runner
        .state
        .security_context_cache
        .get_security_review_context_cache(
            "group/repo",
            "main",
            "base-head-sha",
            "security-review-context-v1",
            1_000_000_000,
        )
        .await?
        .expect("cache entry");
    assert_eq!(cache_entry.source_run_history_id, run_history_id);
    Ok(())
}

#[tokio::test]
async fn concurrent_security_reviews_reuse_single_inflight_context_build() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let security_context_json = "{\"components\":[],\"entry_points\":[],\"trust_boundaries\":[],\"attacker_controlled_inputs\":[],\"privileged_operations\":[],\"sensitive_assets\":[],\"security_critical_paths\":[],\"runtime_notes\":[],\"focus_paths\":[]}";
    let security_review_json = "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}";

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-123456".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );

    harness.push_app_server(scripted_security_review_server(
        "thread-review-1",
        None,
        None,
        0,
        "turn-review-1",
        security_review_json,
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context-1",
        "turn-threat-1",
        security_context_json,
        200,
    ));
    harness.push_app_server(scripted_security_review_server(
        "thread-review-2",
        None,
        None,
        0,
        "turn-review-2",
        security_review_json,
    ));

    let mut codex = test_codex_config();
    codex.session_overrides.security_review.model = Some("gpt-5.4".to_string());
    codex.session_overrides.security_context.model = Some("gpt-5.4-mini".to_string());
    let runner =
        Arc::new(test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await);
    let run_history_id_1 = runner
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
    let run_history_id_2 = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "def456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let mut ctx1 = review_context_with_target_branch(Some("main"));
    ctx1.lane = crate::review_lane::ReviewLane::Security;
    ctx1.min_confidence_score = Some(0.85);
    ctx1.run_history_id = Some(run_history_id_1);

    let mut ctx2 = review_context_with_target_branch(Some("main"));
    ctx2.lane = crate::review_lane::ReviewLane::Security;
    ctx2.min_confidence_score = Some(0.85);
    ctx2.run_history_id = Some(run_history_id_2);
    ctx2.head_sha = "def456".to_string();
    ctx2.mr.iid = 12;
    ctx2.mr.sha = Some("def456".to_string());
    ctx2.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/12".to_string());
    ctx2.mr.source_branch = Some("feature-2".to_string());

    let leader_runner = Arc::clone(&runner);
    let leader = tokio::spawn(async move { leader_runner.run_review(ctx1).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let follower_runner = Arc::clone(&runner);
    let follower = tokio::spawn(async move { follower_runner.run_review(ctx2).await });

    let leader_result = leader.await??;
    let follower_result = follower.await??;
    assert!(matches!(leader_result, CodexResult::Pass { .. }));
    assert!(matches!(follower_result, CodexResult::Pass { .. }));

    let exec_requests = harness.exec_requests();
    let mktemp_requests = exec_requests
        .iter()
        .filter(|request| {
            request
                .command
                .first()
                .is_some_and(|command| command == "mktemp")
        })
        .count();
    assert_eq!(mktemp_requests, 1);

    let cache_entry = runner
        .state
        .security_context_cache
        .get_security_review_context_cache(
            "group/repo",
            "main",
            "base-head-sha",
            "security-review-context-v1",
            1_000_000_000,
        )
        .await?
        .expect("cache entry");
    assert_eq!(cache_entry.source_run_history_id, run_history_id_1);

    let follower_run = runner
        .state
        .run_history
        .get_run_history(run_history_id_2)
        .await?
        .expect("follower run history");
    assert_eq!(follower_run.thread_id.as_deref(), Some("thread-review-2"));
    let follower_events = runner
        .state
        .run_history
        .list_run_history_events(run_history_id_2)
        .await?;
    let follower_turn_ids = follower_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<BTreeSet<_>>();
    assert_eq!(follower_turn_ids, BTreeSet::from(["turn-review-2"]));
    let app_server_starts = harness.app_server_starts();
    assert_eq!(app_server_starts.len(), 3);
    assert!(
        app_server_starts[0]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    assert!(
        app_server_starts[1]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"xhigh\""))
    );
    assert!(
        app_server_starts[2]
            .request
            .cmd
            .iter()
            .any(|part| part.contains("model_reasoning_effort=\"high\""))
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_security_reviews_wake_followers_when_context_build_fails() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let security_review_json = "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}";

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-security-context-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-security-context-654321\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "add".to_string(),
                "--detach".to_string(),
                "/tmp/codex-security-context-654321".to_string(),
                "base-head-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-2".to_string(),
            command: auxiliary_git_exec_command(&[
                "worktree".to_string(),
                "remove".to_string(),
                "--force".to_string(),
                "/tmp/codex-security-context-654321".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-3".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );

    harness.push_app_server(scripted_security_review_server(
        "thread-review-1",
        None,
        None,
        0,
        "turn-review-1",
        security_review_json,
    ));
    harness.push_app_server(scripted_security_context_server(
        "thread-context-1",
        "turn-threat-fail",
        "not-json",
        200,
    ));
    harness.push_app_server(scripted_security_review_server(
        "thread-review-2",
        None,
        None,
        0,
        "turn-review-2",
        security_review_json,
    ));

    let runner = Arc::new(
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await,
    );
    let run_history_id_1 = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 21,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let run_history_id_2 = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 22,
            head_sha: "def456".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let mut ctx1 = review_context_with_target_branch(Some("main"));
    ctx1.lane = crate::review_lane::ReviewLane::Security;
    ctx1.min_confidence_score = Some(0.85);
    ctx1.run_history_id = Some(run_history_id_1);
    ctx1.mr.iid = 21;
    ctx1.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/21".to_string());

    let mut ctx2 = review_context_with_target_branch(Some("main"));
    ctx2.lane = crate::review_lane::ReviewLane::Security;
    ctx2.min_confidence_score = Some(0.85);
    ctx2.run_history_id = Some(run_history_id_2);
    ctx2.head_sha = "def456".to_string();
    ctx2.mr.iid = 22;
    ctx2.mr.sha = Some("def456".to_string());
    ctx2.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/22".to_string());
    ctx2.mr.source_branch = Some("feature-2".to_string());

    let leader_runner = Arc::clone(&runner);
    let leader = tokio::spawn(async move { leader_runner.run_review(ctx1).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let follower_runner = Arc::clone(&runner);
    let follower = tokio::spawn(async move { follower_runner.run_review(ctx2).await });

    let leader_result = leader.await??;
    let follower_result = follower.await??;
    assert!(matches!(leader_result, CodexResult::Pass { .. }));
    assert!(matches!(follower_result, CodexResult::Pass { .. }));

    let exec_requests = harness.exec_requests();
    let mktemp_requests = exec_requests
        .iter()
        .filter(|request| {
            request
                .command
                .first()
                .is_some_and(|command| command == "mktemp")
        })
        .count();
    assert_eq!(mktemp_requests, 1);

    assert!(
        runner
            .state
            .security_context_cache
            .get_security_review_context_cache(
                "group/repo",
                "main",
                "base-head-sha",
                "security-review-context-v1",
                1_000_000_000,
            )
            .await?
            .is_none()
    );
    let follower_run = runner
        .state
        .run_history
        .get_run_history(run_history_id_2)
        .await?
        .expect("follower run history");
    assert!(follower_run.security_context_payload_json.is_none());
    assert_eq!(follower_run.thread_id.as_deref(), Some("thread-review-2"));
    Ok(())
}

#[tokio::test]
async fn security_review_reuses_branch_cached_context_when_ignore_base_head_enabled() -> Result<()>
{
    let harness = Arc::new(FakeRunnerHarness::default());
    let repo_dir = repo_checkout_root("group/repo");
    let cached_payload = "{\"components\":[\"api\"],\"entry_points\":[],\"trust_boundaries\":[],\"attacker_controlled_inputs\":[],\"privileged_operations\":[],\"sensitive_assets\":[],\"security_critical_paths\":[],\"runtime_notes\":[],\"focus_paths\":[]}";

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "HEAD".to_string(),
                "main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "merge-base-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-parse".to_string(),
                "refs/remotes/origin/main".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "current-base-head-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_app_server(scripted_security_review_server(
        "thread-review",
        None,
        None,
        0,
        "turn-review",
        "{\"findings\":[],\"overall_correctness\":\"patch is correct\",\"overall_explanation\":\"No confirmed security issues.\",\"overall_confidence_score\":0.95}",
    ));

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
    runner
        .state
        .security_context_cache
        .upsert_security_review_context_cache(&crate::state::SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "cached-base-head-sha".to_string(),
            prompt_version: "security-review-context-v1".to_string(),
            payload_json: cached_payload.to_string(),
            source_run_history_id: 777,
            generated_at: 100,
            expires_at: 4_000_000_000,
        })
        .await?;

    let run_history_id = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 31,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review_lane::ReviewLane::Security;
    ctx.feature_flags = FeatureFlagSnapshot {
        security_context_ignore_base_head: true,
        ..FeatureFlagSnapshot::default()
    };
    ctx.min_confidence_score = Some(0.85);
    ctx.run_history_id = Some(run_history_id);
    ctx.mr.iid = 31;
    ctx.mr.web_url = Some("https://gitlab.example.com/group/repo/-/merge_requests/31".to_string());

    let result = runner.run_review(ctx).await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let mktemp_requests = harness
        .exec_requests()
        .iter()
        .filter(|request| {
            request
                .command
                .first()
                .is_some_and(|command| command == "mktemp")
        })
        .count();
    assert_eq!(mktemp_requests, 0);

    let app_server_starts = harness.app_server_starts();
    assert_eq!(app_server_starts.len(), 1);

    let turn_start = harness
        .app_protocol_requests()
        .into_iter()
        .find(|message| {
            message.get("method").and_then(|value| value.as_str()) == Some("turn/start")
        })
        .expect("turn/start request");
    let prompt_text = turn_start["params"]["input"][0]["text"]
        .as_str()
        .expect("security review prompt text");
    assert!(prompt_text.contains("Cached repository security context (base branch):"));
    assert!(prompt_text.contains(cached_payload));

    let run = runner
        .state
        .run_history
        .get_run_history(run_history_id)
        .await?
        .expect("run history");
    assert_eq!(run.thread_id.as_deref(), Some("thread-review"));
    assert_eq!(run.turn_id.as_deref(), Some("turn-review"));
    assert_eq!(run.security_context_source_run_id, Some(777));
    assert_eq!(run.security_context_base_branch.as_deref(), Some("main"));
    assert_eq!(
        run.security_context_base_head_sha.as_deref(),
        Some("cached-base-head-sha")
    );
    assert_eq!(
        run.security_context_payload_json.as_deref(),
        Some(cached_payload)
    );
    assert_eq!(run.security_context_generated_at, Some(100));
    assert_eq!(run.security_context_expires_at, Some(4_000_000_000));
    Ok(())
}

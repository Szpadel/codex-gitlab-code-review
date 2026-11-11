use super::*;
#[tokio::test]
async fn run_review_with_fake_runtime_persists_gitlab_discovery_startup_warning() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_peer_ips("app-1", BTreeSet::from(["10.42.0.15".to_string()]));
    let discovery = Arc::new(FakeGitLabDiscoveryHandle::new(
        "gitlab-discovery",
        "http://gitlab-discovery.internal:8091/mcp",
        "/work/mcp",
    ));
    discovery.set_allow_list(
        "group/repo",
        ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from(["group/shared".to_string()]),
            target_groups: BTreeSet::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: gitlab_discovery_mcp_probe_exec_command(&GitLabDiscoveryMcpRuntimeConfig {
                server_name: "gitlab-discovery".to_string(),
                advertise_url: "http://gitlab-discovery.internal:8091/mcp".to_string(),
                clone_root: "/work/mcp".to_string(),
            })
            .expect("probe command"),
            cwd: None,
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "ERROR healthz failed\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result(
            "review/start",
            json!({
                "turn": { "id": "turn-1" },
                "reviewThreadId": "thread-1",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "item": {
                        "id": "review-item-1",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"pass\",\"summary\":\"ok\",\"comment_markdown\":\"\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));

    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        false,
        Arc::clone(&harness),
        Some(discovery.clone() as Arc<dyn GitLabDiscoveryHandle>),
    )
    .await;
    let run_history_id = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
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

    let result = runner
        .run_review(ReviewContext {
            run_history_id: Some(run_history_id),
            feature_flags: FeatureFlagSnapshot {
                gitlab_discovery_mcp: true,
                gitlab_inline_review_comments: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
                security_review: false,
                security_context_ignore_base_head: false,
            },
            ..review_context_with_target_branch(Some("main"))
        })
        .await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let app_start = harness.app_server_starts();
    assert_eq!(app_start.len(), 1);
    assert!(app_start[0].request.cmd[1].contains(
        "mcp_servers.gitlab-discovery.url=\"http://gitlab-discovery.internal:8091/mcp\""
    ));

    runner.state.flush_background_writes().await?;
    let events = runner
        .state
        .run_history
        .list_run_history_events(run_history_id)
        .await?;
    assert!(
        events
            .iter()
            .any(|event| event.turn_id.as_deref() == Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID))
    );
    assert_eq!(discovery.registered_bindings().len(), 1);
    assert_eq!(discovery.removed_bindings(), vec!["app-1"]);
    Ok(())
}

#[tokio::test]
async fn discovery_probe_updates_warning_from_status_not_informational_output() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
    let prepared = PreparedGitLabDiscoveryMcp {
        source_repo: "group/repo".to_string(),
        feature_flags: FeatureFlagSnapshot::default(),
        allow: ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::new(),
            target_groups: BTreeSet::new(),
        },
        runtime_config: GitLabDiscoveryMcpRuntimeConfig {
            server_name: "gitlab-discovery".to_string(),
            advertise_url: "http://gitlab-discovery.internal:8091/mcp".to_string(),
            clone_root: "/work/mcp".to_string(),
        },
    };
    let run_history_id = runner
        .state
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
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

    // Each probe must replace or clear the earlier warning, not leave stale events.
    for (stdout, expected_detail) in [
        (Some("INFO healthz\n OK reachable\nERROR later\n"), None),
        (Some("INFO healthz\nSKIP no curl\n"), None),
        (Some(" \n"), None),
        (None, None),
        (
            Some("INFO healthz\n ERROR connect failure\n"),
            Some("ERROR connect failure"),
        ),
        (
            Some("unrecognized diagnostic\n"),
            Some("unrecognized diagnostic"),
        ),
        (Some("OK\n"), Some("OK")),
    ] {
        runner
            .append_gitlab_discovery_mcp_startup_failure(
                Some(run_history_id),
                &prepared.runtime_config.advertise_url,
                "earlier failure",
            )
            .await;
        let request = ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: gitlab_discovery_mcp_probe_exec_command(&prepared.runtime_config)
                .expect("probe command"),
            cwd: None,
            env: None,
        };
        if let Some(stdout) = stdout {
            harness.push_exec_output(
                request,
                ContainerExecOutput {
                    exit_code: 0,
                    stdout: stdout.to_string(),
                    stderr: String::new(),
                },
            );
        } else {
            harness.push_exec_error(request, "container exec failed");
        }

        runner
            .probe_gitlab_discovery_mcp_endpoint(
                Some(&prepared),
                "app-1",
                None,
                Some(run_history_id),
            )
            .await;
        runner.state.flush_background_writes().await?;
        let events = runner
            .state
            .run_history
            .list_run_history_events(run_history_id)
            .await?;
        let warning = events
            .iter()
            .find(|event| event.event_type == "item_completed");
        match expected_detail {
            Some(detail) => {
                let expected = format!(
                    "GitLab discovery MCP startup warning: endpoint http://gitlab-discovery.internal:8091/mcp {detail}. MCP tools may be unavailable in this run."
                );
                assert_eq!(warning.expect("startup warning").payload["text"], expected);
            }
            None => assert!(warning.is_none(), "stale warning for {stdout:?}"),
        }
    }
    Ok(())
}

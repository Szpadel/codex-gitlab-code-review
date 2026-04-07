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

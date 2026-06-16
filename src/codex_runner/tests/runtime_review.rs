use super::*;
#[tokio::test]
async fn run_review_with_fake_runtime_starts_browser_and_returns_comment() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
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
                        "review": "{\"verdict\":\"comment\",\"summary\":\"needs changes\",\"comment_markdown\":\"- fix it\"}"
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

    let mut codex = test_codex_config();
    codex.browser_mcp.enabled = true;
    codex.mcp_server_overrides.review = BTreeMap::from([("serena".to_string(), false)]);
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;

    let result = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await?;

    match result {
        CodexResult::Comment(comment) => {
            assert_eq!(comment.summary, "needs changes");
            assert_eq!(comment.body, "- fix it");
        }
        _ => bail!("expected comment result"),
    }

    let app_starts = harness.app_server_starts();
    assert_eq!(app_starts.len(), 1);
    assert_eq!(
        app_starts[0].browser_container_id.as_deref(),
        Some("browser-1")
    );
    assert_eq!(
        app_starts[0].network_mode.as_deref(),
        Some("container:browser-1")
    );
    assert!(app_starts[0].request.cmd[1].contains("--browserUrl=http://127.0.0.1:9222"));
    assert!(app_starts[0].request.cmd[1].contains("mcp_servers.serena.enabled=false"));

    let browser_starts = harness.browser_starts();
    assert_eq!(browser_starts.len(), 1);
    assert_eq!(browser_starts[0].container_id, "browser-1");
    assert_eq!(
        harness.ensured_images(),
        vec![
            "ghcr.io/openai/codex-universal:latest".to_string(),
            "chromedp/headless-shell:latest".to_string(),
        ]
    );
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
            "review/start".to_string(),
        ]
    );
    assert_eq!(harness.removed_containers(), vec!["app-1", "browser-1"]);
    Ok(())
}

#[tokio::test]
async fn run_review_with_fake_runtime_persists_failed_turn_error() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
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
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-1",
                    "turnId": "turn-1",
                    "turn": {
                        "status": "failed",
                        "error": { "message": "model stream closed before final response" }
                    }
                }
            })),
        ]),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
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
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.run_history_id = Some(run_history_id);

    let err = runner
        .run_review(ctx)
        .await
        .expect_err("review should fail when the Codex turn fails");
    assert!(format!("{err:#}").contains("model stream closed before final response"));

    let events = runner
        .state
        .run_history
        .list_run_history_events(run_history_id)
        .await?;
    let turn_completed = events
        .iter()
        .find(|event| event.event_type == "turn_completed")
        .expect("turn completion event should be persisted");
    assert_eq!(turn_completed.payload["status"], "failed");
    assert_eq!(
        turn_completed.payload["error"],
        "model stream closed before final response"
    );
    Ok(())
}

#[tokio::test]
async fn run_review_with_fake_runtime_initializes_before_composer_install() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
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
    let composer_command = composer_install_exec_command(
        ComposerInstallMode::Full,
        DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS,
        None,
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: composer_command.clone(),
            cwd: Some("/work/repo".to_string()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 86,
            stdout: format!("{COMPOSER_SKIP_MARKER}:missing-composer-json\n"),
            stderr: String::new(),
        },
    );

    let mut codex = test_codex_config();
    codex.session_overrides.security_review.model = Some("gpt-5.4".to_string());
    codex.session_overrides.security_context.model = Some("gpt-5.4-mini".to_string());
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.feature_flags = FeatureFlagSnapshot {
        composer_install: true,
        ..FeatureFlagSnapshot::default()
    };

    let result = runner.run_review(ctx).await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let operations = harness.operation_log();
    let initialize_index = operations
        .iter()
        .position(|entry| entry == "app:initialize")
        .expect("initialize request");
    let initialized_index = operations
        .iter()
        .position(|entry| entry == "app:initialized")
        .expect("initialized notification");
    let composer_index = operations
        .iter()
        .position(|entry| {
            entry.starts_with("exec:")
                && entry.contains(
                    "composer install --no-interaction --no-progress --ignore-platform-reqs",
                )
        })
        .expect("composer exec");
    assert!(initialize_index < composer_index);
    assert!(initialized_index < composer_index);

    Ok(())
}

#[tokio::test]
async fn run_review_with_fake_runtime_mounts_work_tmpfs_when_enabled() -> Result<()> {
    let harness = Arc::new(FakeRunnerHarness::default());
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

    let mut codex = test_codex_config();
    codex.work_tmpfs.enabled = true;
    codex.work_tmpfs.size_mib = Some(256);
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;
    let result = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await?;
    assert!(matches!(result, CodexResult::Pass { .. }));

    let app_starts = harness.app_server_starts();
    assert_eq!(app_starts.len(), 1);
    let mounts = app_starts[0]
        .request
        .mounts
        .as_ref()
        .expect("tmpfs mount should be set");
    assert_eq!(mounts.len(), 1);
    assert_eq!(mounts[0].target.as_deref(), Some("/work"));
    assert_eq!(mounts[0].typ, Some(MountTypeEnum::TMPFS));
    let tmpfs_options = mounts[0]
        .tmpfs_options
        .as_ref()
        .expect("tmpfs options should be set");
    assert_eq!(tmpfs_options.size_bytes, Some(268_435_456));
    assert_eq!(
        tmpfs_options
            .options
            .as_ref()
            .expect("tmpfs mount options should be set")
            .as_slice(),
        [vec!["exec".to_string()]]
    );

    Ok(())
}

#[tokio::test]
async fn docker_work_tmpfs_mount_is_visible_in_inspect_mounts_when_enabled() -> Result<()> {
    if std::env::var("CODEX_REVIEW_DOCKER_TMPFS_TEST")
        .ok()
        .as_deref()
        != Some("1")
    {
        return Ok(());
    }

    let image = std::env::var("CODEX_REVIEW_DOCKER_TMPFS_TEST_IMAGE")
        .unwrap_or_else(|_| "fedora:43".to_string());
    let docker = crate::codex_runner::docker::connect_docker(&DockerConfig::default())?;
    let mut codex = test_codex_config();
    codex.work_tmpfs.enabled = true;
    codex.work_tmpfs.size_mib = Some(16);
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    let name = format!("codex-work-tmpfs-test-{}", Uuid::new_v4());
    let create = docker
        .create_container(
            Some(CreateContainerOptionsBuilder::new().name(&name).build()),
            ContainerCreateBody {
                image: Some(image),
                cmd: Some(vec![
                    "sh".to_string(),
                    "-lc".to_string(),
                    "sleep 30".to_string(),
                ]),
                host_config: Some(HostConfig {
                    mounts: runner.work_tmpfs_mounts(),
                    auto_remove: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await?;

    let inspect_result: Result<(ContainerInspectResponse, String, String)> = async {
        docker
            .start_container(
                &create.id,
                Some(StartContainerOptionsBuilder::new().build()),
            )
            .await?;
        let inspect = docker
            .inspect_container(
                &create.id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await?;
        let exec = docker
            .create_exec(
                &create.id,
                ExecConfig {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(vec![
                        "sh".to_string(),
                        "-lc".to_string(),
                        "printf '#!/bin/sh\\nexit 0\\n' > /work/probe && chmod +x /work/probe && /work/probe && mount | grep ' /work '".to_string(),
                    ]),
                    ..Default::default()
                },
            )
            .await?;
        let start_result = docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await?;
        let mut stdout = String::new();
        let mut stderr = String::new();
        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(message) = output.next().await {
                    match message? {
                        LogOutput::StdOut { message } | LogOutput::Console { message } => {
                            stdout.push_str(String::from_utf8_lossy(&message).as_ref());
                        }
                        LogOutput::StdErr { message } => {
                            stderr.push_str(String::from_utf8_lossy(&message).as_ref());
                        }
                        LogOutput::StdIn { .. } => {}
                    }
                }
            }
            StartExecResults::Detached => bail!("docker exec unexpectedly detached"),
        }
        let exec_inspect = docker.inspect_exec(&exec.id).await?;
        let exit_code = exec_inspect.exit_code.unwrap_or(-1);
        if exit_code != 0 {
            bail!(
                "docker exec mount probe exited with {exit_code}, stdout: {stdout:?}, stderr: {stderr:?}"
            );
        }
        Ok((inspect, stdout, stderr))
    }
    .await;

    let remove_result = docker
        .remove_container(
            &create.id,
            Some(RemoveContainerOptionsBuilder::new().force(true).build()),
        )
        .await;

    let (inspect, mount_output, mount_stderr) = inspect_result?;
    remove_result?;
    let mounts = inspect.mounts.unwrap_or_default();

    assert!(
        mounts.iter().any(|mount| {
            mount.typ == Some(bollard::models::MountPointTypeEnum::TMPFS)
                && mount.destination.as_deref() == Some("/work")
        }),
        "expected /work tmpfs in inspect mounts, got {mounts:?}"
    );
    assert!(
        !mount_output.contains("noexec"),
        "expected /work tmpfs to be executable, stdout: {mount_output:?}, stderr: {mount_stderr:?}"
    );

    Ok(())
}

#[tokio::test]
async fn wait_for_browser_container_ready_with_fake_runtime_reports_exit() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_browser_diagnostics(
        "browser-1",
        vec![BrowserContainerDiagnostics {
            container_id: "browser-1".to_string(),
            launch: BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default()),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(137),
                oom_killed: Some(false),
                error: Some("process exited".to_string()),
                started_at: Some("2026-03-18T10:00:00Z".to_string()),
                finished_at: Some("2026-03-18T10:00:02Z".to_string()),
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: Vec::new(),
                stderr: vec!["browser failed to boot".to_string()],
            },
            log_collection_error: None,
        }],
    );
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .wait_for_browser_container_ready(
            "browser-1",
            &BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default()),
        )
        .await
        .expect_err("browser readiness should fail");

    let text = format!("{err:#}");
    assert!(text.contains("browser container exited before reporting readiness on port 9222"));
    assert!(text.contains("browser failed to boot"));
}

#[tokio::test]
async fn wait_for_browser_container_ready_accepts_headless_shell_wrapper_internal_devtools_port() {
    let harness = Arc::new(FakeRunnerHarness::default());
    let launch = BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default());
    harness.set_browser_diagnostics(
        "browser-1",
        vec![BrowserContainerDiagnostics {
            container_id: "browser-1".to_string(),
            launch: launch.clone(),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("running".to_string()),
                running: Some(true),
                exit_code: Some(0),
                oom_killed: Some(false),
                error: None,
                started_at: Some("2026-03-18T10:00:00Z".to_string()),
                finished_at: None,
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: Vec::new(),
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9223/devtools/browser/fake".to_string(),
                ],
            },
            log_collection_error: None,
        }],
    );
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    tokio::time::timeout(
        Duration::from_secs(1),
        runner.wait_for_browser_container_ready("browser-1", &launch),
    )
    .await
    .expect("wrapper internal DevTools port should be accepted without grace-period delay")
    .expect("browser readiness should pass");
}

#[tokio::test]
async fn run_review_with_fake_runtime_enriches_app_server_stdout_close_with_diagnostics() {
    let harness = Arc::new(FakeRunnerHarness::default());
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
        .with_after_response(vec![ScriptedAppChunk::Json(json!({
            "method": "turn/started",
            "params": { "threadId": "thread-1", "turnId": "turn-1" }
        }))])
        .close_output_after(),
    ]));
    harness.set_app_server_diagnostics(
        "app-1",
        vec![AppServerContainerDiagnostics {
            container_id: "app-1".to_string(),
            state: Some(AppServerContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(1),
                oom_killed: Some(false),
                error: Some("process exited".to_string()),
                started_at: Some("2026-06-11T10:19:06Z".to_string()),
                finished_at: Some("2026-06-11T10:19:33Z".to_string()),
            }),
            state_collection_error: None,
            log_tail: AppServerLogTail {
                stdout: vec![
                    "codex-runner-error: browser MCP endpoint did not become ready".to_string(),
                    "npm ERR! 429 Too Many Requests".to_string(),
                ],
                stderr: vec!["MCP server chrome-devtools failed to start".to_string()],
            },
            log_collection_error: None,
        }],
    );
    harness.set_browser_diagnostics(
        "browser-1",
        vec![BrowserContainerDiagnostics {
            container_id: "browser-1".to_string(),
            launch: BrowserLaunchConfig::from_browser_mcp(&BrowserMcpConfig::default()),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("running".to_string()),
                running: Some(true),
                exit_code: Some(0),
                oom_killed: Some(false),
                error: None,
                started_at: Some("2026-06-11T10:19:06Z".to_string()),
                finished_at: None,
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: Vec::new(),
                stderr: vec![
                    "DevTools listening on ws://127.0.0.1:9223/devtools/browser/fake".to_string(),
                ],
            },
            log_collection_error: None,
        }],
    );

    let mut codex = test_codex_config();
    codex.browser_mcp.enabled = true;
    let runner = test_runner_with_fake_runtime(codex, false, Arc::clone(&harness), None).await;

    let err = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await
        .expect_err("review should fail when app-server closes stdout");

    let text = format!("{err:#}");
    assert!(text.contains("codex app-server closed stdout"));
    assert!(text.contains("app-server container diagnostics"));
    assert!(text.contains("status=exited"));
    assert!(text.contains("exit_code=1"));
    assert!(text.contains("codex-runner-error: browser MCP endpoint did not become ready"));
    assert!(text.contains("npm ERR! 429 Too Many Requests"));
    assert!(text.contains("MCP server chrome-devtools failed to start"));
    assert!(text.contains("browser container diagnostics"));
    assert!(text.contains("DevTools listening on ws://127.0.0.1:9223"));
}

#[tokio::test]
async fn run_review_with_fake_runtime_enriches_app_server_initialize_write_failure_with_diagnostics()
 {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::close_input_before_requests());
    harness.set_app_server_diagnostics(
        "app-1",
        vec![AppServerContainerDiagnostics {
            container_id: "app-1".to_string(),
            state: Some(AppServerContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(1),
                oom_killed: Some(false),
                error: Some("process exited".to_string()),
                started_at: Some("2026-06-11T10:19:06Z".to_string()),
                finished_at: Some("2026-06-11T10:19:07Z".to_string()),
            }),
            state_collection_error: None,
            log_tail: AppServerLogTail {
                stdout: vec!["npm ERR! 429 Too Many Requests".to_string()],
                stderr: vec!["MCP server chrome-devtools failed to start".to_string()],
            },
            log_collection_error: None,
        }],
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await
        .expect_err("review should fail when app-server stdin closes during initialize");

    let text = format!("{err:#}");
    assert!(text.contains("write codex app-server input"), "{text}");
    assert!(text.contains("app-server container diagnostics"), "{text}");
    assert!(text.contains("status=exited"), "{text}");
    assert!(text.contains("exit_code=1"), "{text}");
    assert!(text.contains("npm ERR! 429 Too Many Requests"), "{text}");
    assert!(!text.contains("codex app-server stdout before write failed"));
    assert!(
        text.contains("MCP server chrome-devtools failed to start"),
        "{text}"
    );
}

#[tokio::test]
async fn read_thread_with_fake_runtime_enriches_app_server_initialize_write_failure_with_diagnostics()
 {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::close_input_before_requests());
    harness.set_app_server_diagnostics(
        "app-1",
        vec![AppServerContainerDiagnostics {
            container_id: "app-1".to_string(),
            state: Some(AppServerContainerStateSnapshot {
                status: Some("exited".to_string()),
                running: Some(false),
                exit_code: Some(1),
                oom_killed: Some(false),
                error: Some("process exited".to_string()),
                started_at: Some("2026-06-11T10:19:06Z".to_string()),
                finished_at: Some("2026-06-11T10:19:07Z".to_string()),
            }),
            state_collection_error: None,
            log_tail: AppServerLogTail {
                stdout: vec!["npm ERR! 429 Too Many Requests".to_string()],
                stderr: vec!["MCP server chrome-devtools failed to start".to_string()],
            },
            log_collection_error: None,
        }],
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .read_thread("primary", "thread-1")
        .await
        .expect_err("thread read should fail when app-server stdin closes during initialize");

    let text = format!("{err:#}");
    assert!(text.contains("write codex app-server input"), "{text}");
    assert!(text.contains("app-server container diagnostics"), "{text}");
    assert!(text.contains("status=exited"), "{text}");
    assert!(text.contains("exit_code=1"), "{text}");
    assert!(text.contains("npm ERR! 429 Too Many Requests"), "{text}");
    assert!(
        text.contains("MCP server chrome-devtools failed to start"),
        "{text}"
    );
}

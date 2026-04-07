use super::*;
#[tokio::test]
async fn run_mention_command_with_fake_runtime_executes_git_helpers_and_returns_commit()
-> Result<()> {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        ScriptedAppRequest::result("thread/start", json!({ "thread": { "id": "thread-1" } })),
        ScriptedAppRequest::result("turn/start", json!({ "turn": { "id": "turn-1" } }))
            .with_after_response(vec![
                ScriptedAppChunk::Json(json!({
                    "method": "turn/started",
                    "params": { "threadId": "thread-1", "turnId": "turn-1" }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/agentMessage/delta",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "itemId": "agent-1",
                        "delta": "Implemented and committed deadbeef"
                    }
                })),
                ScriptedAppChunk::Json(json!({
                    "method": "item/completed",
                    "params": {
                        "threadId": "thread-1",
                        "turnId": "turn-1",
                        "item": {
                            "id": "agent-1",
                            "type": "AgentMessage",
                            "phase": "final"
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

    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    for command in [
        vec![
            "config".to_string(),
            "user.name".to_string(),
            "Requester".to_string(),
        ],
        vec![
            "config".to_string(),
            "user.email".to_string(),
            "requester@example.com".to_string(),
        ],
        vec![
            "remote".to_string(),
            "set-url".to_string(),
            "--push".to_string(),
            "origin".to_string(),
            "no_push://disabled".to_string(),
        ],
    ] {
        harness.push_exec_output(
            ExecContainerCommandRequest {
                container_id: "app-1".to_string(),
                command: auxiliary_git_exec_command(&command),
                cwd: Some(repo_dir.clone()),
                env: None,
            },
            ContainerExecOutput {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
        );
    }
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["rev-parse".to_string(), "HEAD".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "before-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["rev-parse".to_string(), "HEAD".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "after-sha\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "merge-base".to_string(),
                "--is-ancestor".to_string(),
                "before-sha".to_string(),
                "after-sha".to_string(),
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
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "rev-list".to_string(),
                "--count".to_string(),
                "before-sha..after-sha".to_string(),
            ]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "1\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: restore_push_remote_url_exec_command(
                "https://oauth2:${GITLAB_TOKEN}@gitlab.example.com/group/repo.git",
            ),
            cwd: Some(repo_dir.clone()),
            env: Some(vec!["GITLAB_TOKEN=token".to_string()]),
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&[
                "push".to_string(),
                "origin".to_string(),
                "HEAD:feature".to_string(),
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

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let result = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                draft: false,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot::default(),
            run_history_id: None,
        })
        .await?;

    assert_eq!(result.status, MentionCommandStatus::Committed);
    assert_eq!(result.commit_sha.as_deref(), Some("after-sha"));
    assert_eq!(result.reply_message, "Implemented and committed deadbeef");

    let exec_requests = harness.exec_requests();
    assert_eq!(exec_requests.len(), 10);
    assert_eq!(
        exec_requests.last().unwrap().command,
        auxiliary_git_exec_command(&[
            "push".to_string(),
            "origin".to_string(),
            "HEAD:feature".to_string(),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn prepare_mention_inputs_downloads_images_inside_container() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: vec![
                "mktemp".to_string(),
                "-d".to_string(),
                "/tmp/codex-mention-images-XXXXXX".to_string(),
            ],
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: "/tmp/codex-mention-images-123456\n".to_string(),
            stderr: String::new(),
        },
    );
    harness.push_exec_output(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: super::mention_inputs::mention_image_download_exec_command(
                "/tmp/codex-mention-images-123456/01-screenshot.png",
                "https://gitlab.example.com/api/v4/projects/group%2Frepo/uploads/hash/screenshot.png",
            ),
            cwd: Some(repo_dir.clone()),
            env: Some(vec!["GITLAB_TOKEN=token".to_string()]),
        },
        ContainerExecOutput {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        },
    );
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;

    let prepared = runner
        .prepare_mention_inputs(
            "app-1",
            repo_dir.as_str(),
            &MentionCommandContext {
                repo: "group/repo".to_string(),
                project_path: "group/repo".to_string(),
                discussion_project_path: "group/repo".to_string(),
                mr: MergeRequest {
                    iid: 11,
                    title: Some("Title".to_string()),
                    web_url: None,
                    draft: false,
                    created_at: None,
                    updated_at: None,
                    sha: Some("before-sha".to_string()),
                    source_branch: Some("feature".to_string()),
                    target_branch: Some("main".to_string()),
                    author: None,
                    source_project_id: Some(1),
                    target_project_id: Some(1),
                    diff_refs: None,
                },
                head_sha: "before-sha".to_string(),
                discussion_id: "discussion-1".to_string(),
                trigger_note_id: 77,
                requester_name: "Requester".to_string(),
                requester_email: "requester@example.com".to_string(),
                additional_developer_instructions: None,
                prompt: "Please fix it".to_string(),
                image_uploads: vec![crate::gitlab_links::GitLabMarkdownImageUpload {
                    markdown_path: "/uploads/hash/screenshot.png".to_string(),
                    absolute_url: "https://gitlab.example.com/uploads/hash/screenshot.png"
                        .to_string(),
                    secret: "hash".to_string(),
                    filename: "screenshot.png".to_string(),
                }],
                feature_flags: FeatureFlagSnapshot::default(),
                run_history_id: None,
            },
        )
        .await;

    assert_eq!(
        prepared.turn_input,
        vec![
            json!({
                "type": "text",
                "text": "Please fix it",
            }),
            json!({
                "type": "localImage",
                "path": "/tmp/codex-mention-images-123456/01-screenshot.png",
            }),
        ]
    );
}

#[tokio::test]
async fn run_mention_command_with_fake_runtime_initializes_before_composer_install() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
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
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        ContainerExecOutput {
            exit_code: 86,
            stdout: format!("{COMPOSER_SKIP_MARKER}:missing-composer-json\n"),
            stderr: String::new(),
        },
    );
    harness.push_exec_error(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        "git status failed",
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let err = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                draft: false,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot {
                composer_install: true,
                ..FeatureFlagSnapshot::default()
            },
            run_history_id: None,
        })
        .await
        .expect_err("mention command should fail after baseline git status");

    assert!(format!("{err:#}").contains("git status failed"));

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
}

#[tokio::test]
async fn run_mention_command_with_fake_runtime_surfaces_exec_failures() {
    let repo_dir = repo_checkout_root("group/repo");
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
    ]));
    harness.push_exec_error(
        ExecContainerCommandRequest {
            container_id: "app-1".to_string(),
            command: auxiliary_git_exec_command(&["status".to_string(), "--porcelain".to_string()]),
            cwd: Some(repo_dir.clone()),
            env: None,
        },
        "git status failed",
    );

    let runner =
        test_runner_with_fake_runtime(test_codex_config(), true, Arc::clone(&harness), None).await;
    let err = runner
        .run_mention_command(MentionCommandContext {
            repo: "group/repo".to_string(),
            project_path: "group/repo".to_string(),
            discussion_project_path: "group/repo".to_string(),
            mr: MergeRequest {
                iid: 11,
                title: Some("Title".to_string()),
                web_url: None,
                draft: false,
                created_at: None,
                updated_at: None,
                sha: Some("before-sha".to_string()),
                source_branch: Some("feature".to_string()),
                target_branch: Some("main".to_string()),
                author: None,
                source_project_id: Some(1),
                target_project_id: Some(1),
                diff_refs: None,
            },
            head_sha: "before-sha".to_string(),
            discussion_id: "discussion-1".to_string(),
            trigger_note_id: 77,
            requester_name: "Requester".to_string(),
            requester_email: "requester@example.com".to_string(),
            additional_developer_instructions: None,
            prompt: "Please fix it".to_string(),
            image_uploads: Vec::new(),
            feature_flags: FeatureFlagSnapshot::default(),
            run_history_id: None,
        })
        .await
        .expect_err("mention command should fail");

    assert!(format!("{err:#}").contains("git status failed"));
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn run_review_with_fake_runtime_surfaces_closed_stdout_with_recent_runner_errors() {
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
            ScriptedAppChunk::Line("codex-runner-error: git clone failed with 429".to_string()),
            ScriptedAppChunk::Json(json!({
                "method": "turn/started",
                "params": { "threadId": "thread-1", "turnId": "turn-1" }
            })),
        ])
        .close_output_after(),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    let err = runner
        .run_review(review_context_with_target_branch(Some("main")))
        .await
        .expect_err("review should fail when app-server closes stdout");

    let text = format!("{err:#}");
    assert!(text.contains("codex app-server closed stdout"));
    assert!(text.contains("recent runner errors: codex-runner-error: git clone failed with 429"));
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

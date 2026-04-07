use super::*;
#[tokio::test]
async fn scan_once_with_fake_runtime_runner_posts_review_comment() -> Result<()> {
    let config = test_config();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(vec![mr(41, "sha41")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", serde_json::json!({})),
        ScriptedAppRequest::result(
            "thread/start",
            serde_json::json!({ "thread": { "id": "thread-41" } }),
        ),
        ScriptedAppRequest::result(
            "review/start",
            serde_json::json!({
                "turn": { "id": "turn-41" },
                "reviewThreadId": "thread-41",
            }),
        )
        .with_after_response(vec![
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "turn/started",
                "params": { "threadId": "thread-41", "turnId": "turn-41" }
            })),
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "item/completed",
                "params": {
                    "threadId": "thread-41",
                    "turnId": "turn-41",
                    "item": {
                        "id": "review-item-41",
                        "type": "exitedReviewMode",
                        "review": "{\"verdict\":\"comment\",\"summary\":\"needs changes\",\"comment_markdown\":\"- scan-level check\"}"
                    }
                }
            })),
            ScriptedAppChunk::Json(serde_json::json!({
                "method": "turn/completed",
                "params": {
                    "threadId": "thread-41",
                    "turnId": "turn-41",
                    "turn": { "status": "completed" }
                }
            })),
        ]),
    ]));
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let runner = Arc::new(DockerCodexRunner::new_with_test_runtime(
        config.codex.clone(),
        url::Url::parse("https://gitlab.example.com").expect("url"),
        Arc::clone(&state),
        None,
        RunnerRuntimeOptions {
            gitlab_token: config.gitlab.token.clone(),
            log_all_json: false,
            owner_id: state.service_state.get_or_create_review_owner_id().await?,
            mention_commands_active: false,
            review_additional_developer_instructions: None,
        },
        harness.clone(),
    ));
    let service = ReviewService::new(
        config.clone(),
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:41:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:41"))
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:41:thumbsup")
    );
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_post_inline_discussions_and_fallback_note() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(42, "sha42");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/42".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha42".to_string(),
            base_commit_sha: "base42".to_string(),
            start_commit_sha: "start42".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,2 @@\n-old\n+new\n+extra\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some(
                    "Overall see /work/repo/group/repo/src/other.rs:8 for fallback context."
                        .to_string(),
                ),
                overall_confidence_score: None,
                findings: vec![
                    crate::codex_runner::ReviewFinding {
                        title: "Inline finding".to_string(),
                        body: "Please fix /work/repo/group/repo/src/lib.rs:10 before merging."
                            .to_string(),
                        confidence_score: None,
                        priority: None,
                        code_location: crate::codex_runner::ReviewCodeLocation {
                            absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                            line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                        },
                    },
                    crate::codex_runner::ReviewFinding {
                        title: "Fallback finding".to_string(),
                        body: "This remains unresolved near /work/repo/group/repo/src/other.rs:8."
                            .to_string(),
                        confidence_score: None,
                        priority: None,
                        code_location: crate::codex_runner::ReviewCodeLocation {
                            absolute_file_path: "/work/repo/group/repo/src/other.rs".to_string(),
                            line_range: crate::codex_runner::ReviewLineRange { start: 8, end: 8 },
                        },
                    },
                ],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let inline_discussions = gitlab.created_diff_discussions();
    assert_eq!(inline_discussions.len(), 1);
    assert!(inline_discussions[0].body.contains("Inline finding"));
    assert!(
        inline_discussions[0]
            .body
            .contains("https://gitlab.example.com/group/repo/-/blob/sha42/src/lib.rs#L10")
    );

    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("Overall see"));
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha42/src/other.rs#L8")
    );
    assert!(fallback_notes[0].contains("<!-- codex-review:sha=sha42 -->"));

    let calls = inner.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_diff_discussion:group/repo:42")
    );
    assert!(
        calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:42"))
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_plain_note_when_no_diff_anchor_exists() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(43, "sha43");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/43".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha43".to_string(),
            base_commit_sha: "base43".to_string(),
            start_commit_sha: "start43".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/unrelated.rs".to_string(),
            new_path: "src/unrelated.rs".to_string(),
            diff: "@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback only".to_string(),
                    body: "See /work/repo/group/repo/src/lib.rs:30 for the broken call."
                        .to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 30, end: 30 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha43/src/lib.rs#L30")
    );
    assert!(fallback_notes[0].contains("[src/lib.rs:30]"));
    Ok(())
}

#[tokio::test]
async fn completed_review_state_skips_same_sha_without_note_marker() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(44, "sha44")]);
    gitlab.discussions.lock().unwrap().insert(
        ("group/repo".to_string(), 44),
        vec![MergeRequestDiscussion {
            id: "discussion-44".to_string(),
            notes: vec![DiscussionNote {
                id: 1,
                body: "<!-- codex-review-finding:sha=sha44 key=deadbeef -->".to_string(),
                author: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            }],
        }],
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .run_history
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 44,
            head_sha: "sha44".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .run_history
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .run_history
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    let outcome = service.scan_once().await?;

    assert_eq!(outcome, ScanRunStatus::Completed);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("add_award:group/repo:44"))
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:44"))
    );
    Ok(())
}

#[tokio::test]
async fn legacy_dry_run_comment_history_without_gitlab_markers_does_not_skip_same_sha() -> Result<()>
{
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(441, "sha441")]);
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .run_history
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 441,
            head_sha: "sha441".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .run_history
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .run_history
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    Ok(())
}

#[tokio::test]
async fn completed_inline_review_state_skips_when_discussion_lookup_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let inner = fake_gitlab(vec![mr(442, "sha442")]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(Arc::clone(&inner), Vec::new(), Vec::new())
            .with_list_discussions_error("discussions unavailable"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .run_history
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 442,
            head_sha: "sha442".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .run_history
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .run_history
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "comment".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn errored_review_state_does_not_skip_same_sha() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(45, "sha45")]);
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = state
        .run_history
        .start_run_history(crate::state::NewRunHistory {
            kind: crate::state::RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 45,
            head_sha: "sha45".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    state
        .run_history
        .set_run_history_feature_flags(
            run_id,
            &crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
        )
        .await?;
    state
        .run_history
        .finish_run_history(
            run_id,
            crate::state::RunHistoryFinish {
                result: "error".to_string(),
                ..crate::state::RunHistoryFinish::default()
            },
        )
        .await?;

    let service = ReviewService::new(
        config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:45:thumbsup")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_when_head_sha_no_longer_matches_latest_diff() -> Result<()>
{
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(46, "sha46");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/46".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "newer-sha".to_string(),
            base_commit_sha: "base46".to_string(),
            start_commit_sha: "start46".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Head moved".to_string(),
                    body: "See /work/repo/group/repo/src/lib.rs:10 before merging.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha46/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_use_matching_diff_version_even_when_not_first() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(47, "sha47");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/47".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![
            MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "stale-sha".to_string(),
                base_commit_sha: "base-stale".to_string(),
                start_commit_sha: "start-stale".to_string(),
            },
            MergeRequestDiffVersion {
                id: 2,
                head_commit_sha: "sha47".to_string(),
                base_commit_sha: "base47".to_string(),
                start_commit_sha: "start47".to_string(),
            },
        ],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Inline finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(gitlab.created_diff_discussions().len(), 1);
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_note_when_marker_prefetch_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(48, "sha48");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/48".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(
            Arc::clone(&inner),
            vec![MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "sha48".to_string(),
                base_commit_sha: "base48".to_string(),
                start_commit_sha: "start48".to_string(),
            }],
            vec![MergeRequestDiff {
                old_path: "src/lib.rs".to_string(),
                new_path: "src/lib.rs".to_string(),
                diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
                new_file: false,
                deleted_file: false,
                renamed_file: false,
                collapsed: false,
                too_large: false,
            }],
        )
        .with_list_discussions_error("discussions unavailable"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("[src/lib.rs:10-10]"));
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/group/repo/-/blob/sha48/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_fallback_to_note_when_inline_post_fails() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(49, "sha49");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/49".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(
        InlineReviewGitLab::new(
            Arc::clone(&inner),
            vec![MergeRequestDiffVersion {
                id: 1,
                head_commit_sha: "sha49".to_string(),
                base_commit_sha: "base49".to_string(),
                start_commit_sha: "start49".to_string(),
            }],
            vec![MergeRequestDiff {
                old_path: "src/lib.rs".to_string(),
                new_path: "src/lib.rs".to_string(),
                diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
                new_file: false,
                deleted_file: false,
                renamed_file: false,
                collapsed: false,
                too_large: false,
            }],
        )
        .with_create_diff_discussion_error("invalid position"),
    );
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some("Overall context.".to_string()),
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fallback finding".to_string(),
                    body: "Fix /work/repo/group/repo/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert!(gitlab.created_diff_discussions().is_empty());
    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(fallback_notes[0].contains("Overall context."));
    assert!(fallback_notes[0].contains("[src/lib.rs:10-10]"));
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_use_source_project_links_for_fork_mrs() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(50, "sha50");
    merge_request.web_url =
        Some("https://gitlab.example.com/target/repo/-/merge_requests/50".to_string());
    merge_request.source_project_id = Some(123);
    merge_request.target_project_id = Some(456);
    let inner = fake_gitlab(vec![merge_request]);
    inner
        .projects
        .lock()
        .unwrap()
        .insert("123".to_string(), "fork/source".to_string());
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha50".to_string(),
            base_commit_sha: "base50".to_string(),
            start_commit_sha: "start50".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/unrelated.rs".to_string(),
            new_path: "src/unrelated.rs".to_string(),
            diff: "@@ -1,1 +1,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: Some("See /work/repo/fork/source/src/lib.rs:10.".to_string()),
                overall_confidence_score: None,
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "Fork fallback".to_string(),
                    body: "Fix /work/repo/fork/source/src/lib.rs:10.".to_string(),
                    confidence_score: None,
                    priority: None,
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/fork/source/src/lib.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let fallback_notes = gitlab.created_note_bodies();
    assert_eq!(fallback_notes.len(), 1);
    assert!(
        fallback_notes[0]
            .contains("https://gitlab.example.com/fork/source/-/blob/sha50/src/lib.rs#L10")
    );
    Ok(())
}

#[tokio::test]
async fn skips_when_thumbsup_exists() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(1, "sha1")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 1),
            vec![AwardEmoji {
                id: 10,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn skips_when_comment_marker_exists() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let marker = format!("{}sha1 -->", config.review.comment_marker_prefix);
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(2, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 2),
            vec![Note {
                id: 99,
                body: format!("Review\n\n{}", marker),
                author: bot_user,
            }],
        )])),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn skips_when_created_before_cutoff() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let created_at = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let cutoff = Utc
        .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr_with_created_at(5, "sha1", created_at)]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab.clone(), state, runner.clone(), 1, cutoff);

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn dry_run_skips_writes() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(3, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn dry_run_completion_does_not_block_followup_real_review_for_same_sha() -> Result<()> {
    let mut dry_run_config = test_config();
    dry_run_config.review.dry_run = true;
    dry_run_config.feature_flags.gitlab_inline_review_comments = true;
    let mut live_config = test_config();
    live_config.feature_flags.gitlab_inline_review_comments = true;
    let gitlab = fake_gitlab(vec![mr(47, "sha47")]);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);

    let dry_run_runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let dry_run_service = ReviewService::new(
        dry_run_config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        Arc::clone(&state),
        dry_run_runner,
        1,
        default_created_after(),
    );
    dry_run_service.scan_once().await?;
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);

    let live_runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let live_service = ReviewService::new(
        live_config,
        Arc::clone(&gitlab) as Arc<dyn GitLabApi>,
        state,
        live_runner.clone(),
        1,
        default_created_after(),
    );

    live_service.scan_once().await?;

    assert_eq!(*live_runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:47:thumbsup")
    );
    Ok(())
}

#[tokio::test]
async fn inline_review_comments_dedupe_duplicate_findings_in_single_response() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;

    let mut merge_request = mr(48, "sha48");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/48".to_string());
    let inner = fake_gitlab(vec![merge_request]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha48".to_string(),
            base_commit_sha: "base48".to_string(),
            start_commit_sha: "start48".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/lib.rs".to_string(),
            new_path: "src/lib.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let finding = crate::codex_runner::ReviewFinding {
        title: "Duplicate".to_string(),
        body: "See /work/repo/group/repo/src/lib.rs:10.".to_string(),
        confidence_score: None,
        priority: None,
        code_location: crate::codex_runner::ReviewCodeLocation {
            absolute_file_path: "/work/repo/group/repo/src/lib.rs".to_string(),
            line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
        },
    };
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "needs changes".to_string(),
                overall_explanation: None,
                overall_confidence_score: None,
                findings: vec![finding.clone(), finding],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(gitlab.created_diff_discussions().len(), 1);
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

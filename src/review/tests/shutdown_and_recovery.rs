use super::*;
#[tokio::test]
async fn review_finishes_when_eye_removal_fails() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(4, "sha1")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 4),
            vec![AwardEmoji {
                id: 55,
                name: "eyes".to_string(),
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
        delete_award_fails: true,
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
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    service.review_mr("group/repo", 4).await?;

    let row = sqlx::query("SELECT status FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(4i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    assert_eq!(status, "done");
    Ok(())
}

#[tokio::test]
async fn scan_skips_review_for_draft_merge_request() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut draft_mr = mr(52, "sha52");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![draft_mr]),
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
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_draft_merge_request_without_reviewing_it() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.review.mention_commands.eyes_emoji = Some("inspect".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let mut draft_mr = mr(53, "sha53");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![draft_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 53),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "review note".to_string(),
                        author: bot_user,
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser question".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
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
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn explicit_review_still_runs_for_draft_merge_request() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut draft_mr = mr(54, "sha54");
    draft_mr.draft = true;
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![draft_mr]),
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
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.review_mr("group/repo", 54).await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_cancels_and_removes_eyes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 20),
            vec![AwardEmoji {
                id: 200,
                name: "eyes".to_string(),
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
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 20, "sha20")
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:20:200")
    );
    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(20i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_marks_mentions_error_without_review_rows() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
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
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    assert!(
        state
            .mention_commands
            .begin_mention_command("group/repo", 21, "discussion-1", 901, "sha21")
            .await?
    );
    gitlab
        .calls
        .lock()
        .unwrap()
        .push("add_discussion_note_award:group/repo:21:discussion-1:901:eyes".to_string());
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:21:discussion-1:901:10901"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(21i64)
    .bind("discussion-1")
    .bind(901i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn recover_in_progress_reviews_dry_run_skips_mention_reaction_cleanup() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
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
    let runner = Arc::new(RecoveryRunner {
        stop_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    assert!(
        state
            .mention_commands
            .begin_mention_command("group/repo", 22, "discussion-2", 902, "sha22")
            .await?
    );
    gitlab
        .calls
        .lock()
        .unwrap()
        .push("add_discussion_note_award:group/repo:22:discussion-2:902:eyes".to_string());
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.recover_in_progress_reviews().await?;

    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(!calls.iter().any(|call| {
        call.starts_with("delete_discussion_note_award:group/repo:22:discussion-2:902:")
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(22i64)
    .bind("discussion-2")
    .bind(902i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn shutdown_request_skips_new_review_runs() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(21, "sha21")]),
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
    service.request_shutdown();

    service.review_mr("group/repo", 21).await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
    Ok(())
}

#[tokio::test]
async fn scan_once_reports_interrupted_when_shutdown_requested_before_start() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let service = ReviewService::new(
        config,
        Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(Vec::new()),
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
        }),
        Arc::new(ReviewStateStore::new(":memory:").await?),
        Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        }),
        1,
        default_created_after(),
    );
    service.request_shutdown();

    let status = service.scan_once().await?;

    assert_eq!(status, ScanRunStatus::Interrupted);
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_when_shutdown_requested_after_runner_completes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 22),
            vec![AwardEmoji {
                id: 220,
                name: "eyes".to_string(),
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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 22, "sha22")
        .await?;
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let runner = Arc::new(ShutdownTriggerRunner {
        lifecycle: Arc::clone(&lifecycle),
        calls: Mutex::new(0),
    });
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(22, "sha22"),
            "sha22",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:22:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:22:220")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:22:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:22"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(22i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_without_starting_runner_when_shutdown_requested_during_eyes_award()
-> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 23),
            vec![AwardEmoji {
                id: 230,
                name: "eyes".to_string(),
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
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let gitlab = Arc::new(ShutdownOnEyesAwardGitLab {
        inner: Arc::clone(&base_gitlab),
        lifecycle: Arc::clone(&lifecycle),
        eyes_emoji: config.review.eyes_emoji.clone(),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 23, "sha23")
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab,
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(23, "sha23"),
            "sha23",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let calls = base_gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:23:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:23:230")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:23:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:23"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(23i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_marks_cancelled_when_shutdown_requested_during_eyes_removal() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 24),
            vec![AwardEmoji {
                id: 240,
                name: "eyes".to_string(),
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
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let gitlab = Arc::new(ShutdownOnListAwardsGitLab {
        inner: Arc::clone(&base_gitlab),
        lifecycle: Arc::clone(&lifecycle),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 24, "sha24")
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab,
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(24, "sha24"),
            "sha24",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = base_gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:24:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:24:240")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call == "add_award:group/repo:24:thumbsup")
    );
    assert!(
        !calls
            .iter()
            .any(|call| call.starts_with("create_note:group/repo:24"))
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(24i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("cancelled".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_finishes_successfully_when_graceful_drain_starts_after_runner_begins() -> Result<()>
{
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 26),
            vec![AwardEmoji {
                id: 260,
                name: "eyes".to_string(),
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
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 26, "sha26")
        .await?;
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let runner = Arc::new(GracefulDrainTriggerRunner {
        lifecycle: Arc::clone(&lifecycle),
        calls: Mutex::new(0),
    });
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::General,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle,
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(26, "sha26"),
            "sha26",
            crate::feature_flags::FeatureFlagSnapshot::default(),
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:26:eyes")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "delete_award:group/repo:26:260")
    );
    assert!(
        calls
            .iter()
            .any(|call| call == "add_award:group/repo:26:thumbsup")
    );

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(26i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn graceful_drain_cancels_queued_review_without_starting_second_codex_run() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(90, "sha90");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let mut second_mr = mr(91, "sha91");
    second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![first_mr.clone(), second_mr.clone()]),
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
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        90
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let first_scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    let first_scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task).await???;
    assert_eq!(first_scan_status, ScanRunStatus::Completed);
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert_eq!(
        state.review_state.list_in_progress_reviews().await?.len(),
        2
    );

    service.request_graceful_drain();
    release_first.notify_waiters();

    for _ in 0..50 {
        if state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    let results: Vec<(i64, String)> =
        sqlx::query_as("SELECT iid, result FROM review_state ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(
        results,
        vec![(90, "pass".to_string()), (91, "cancelled".to_string())]
    );
    Ok(())
}

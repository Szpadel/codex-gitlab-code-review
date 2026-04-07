use super::*;
#[tokio::test]
async fn review_history_insert_failure_releases_review_lock() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(40, "sha40")]),
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
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(service.scan_once().await.is_err());
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(40i64)
        .fetch_one(state.pool())
        .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result.as_deref(), Some("error"));
    Ok(())
}

#[tokio::test]
async fn error_backoff_skips_repeat_and_no_error_comment() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(6, "sha1")]),
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
    let runner = Arc::new(FailingRunner {
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
    service.scan_once().await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap();
    assert!(calls.iter().all(|call| !call.starts_with("create_note:")));
    Ok(())
}

#[tokio::test]
async fn fork_reviews_use_source_project_path_for_runner_context() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::List(vec!["target/repo".to_string()]);
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut fork_mr = mr(12, "sha1");
    fork_mr.source_project_id = Some(42);
    fork_mr.target_project_id = Some(7);
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![fork_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "42".to_string(),
            "forks/source-repo".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
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

    let _ = service.scan_once().await?;

    let contexts = runner.review_contexts.lock().unwrap();
    assert_eq!(contexts.len(), 1);
    assert_eq!(contexts[0].repo, "target/repo");
    assert_eq!(contexts[0].project_path, "forks/source-repo");
    Ok(())
}

#[tokio::test]
async fn security_reviews_use_canonical_project_path_for_runner_context() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::List(vec!["target/repo".to_string()]);
    config.feature_flags.security_review = true;
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let mut fork_mr = mr(12, "sha1");
    fork_mr.source_project_id = Some(42);
    fork_mr.target_project_id = Some(7);
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![fork_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "42".to_string(),
            "forks/source-repo".to_string(),
        )])),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
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

    let _ = service.scan_once().await?;

    {
        let contexts = runner.review_contexts.lock().unwrap();
        assert_eq!(contexts.len(), 2);
        assert_eq!(
            contexts
                .iter()
                .find(|ctx| ctx.lane == crate::review_lane::ReviewLane::General)
                .map(|ctx| ctx.project_path.as_str()),
            Some("forks/source-repo")
        );
        assert_eq!(
            contexts
                .iter()
                .find(|ctx| ctx.lane == crate::review_lane::ReviewLane::Security)
                .map(|ctx| ctx.project_path.as_str()),
            Some("target/repo")
        );
    }
    let run_kinds = service
        .state
        .run_history
        .list_run_history_for_mr("target/repo", 12)
        .await?
        .into_iter()
        .map(|record| record.kind)
        .collect::<Vec<_>>();
    assert!(run_kinds.contains(&crate::state::RunHistoryKind::Review));
    assert!(run_kinds.contains(&crate::state::RunHistoryKind::Security));
    Ok(())
}

#[test]
fn retry_backoff_doubles_delay() {
    let backoff = RetryBackoff::new(Duration::hours(1));
    let key = RetryKey::new(
        crate::review_lane::ReviewLane::General,
        "group/repo",
        1,
        "sha1",
    );
    let start = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");

    let next_first = backoff.record_failure(key.clone(), start);
    assert_eq!(next_first, start + Duration::hours(1));

    let next_second = backoff.record_failure(key.clone(), next_first);
    assert_eq!(next_second, next_first + Duration::hours(2));

    let state = backoff.state_for(&key).expect("backoff state");
    assert_eq!(state.failures, 2);
}

#[tokio::test]
async fn incremental_skips_when_activity_unchanged() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(10, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "group/repo".to_string(),
            "2025-01-01T00:00:00Z".to_string(),
        )])),
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
    let activity_marker = format!("{}|{}", default_created_at().to_rfc3339(), 10);
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &activity_marker)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn incremental_scans_when_activity_changes() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(11, "sha1")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::from([(
            "group/repo".to_string(),
            "2025-01-02T00:00:00Z".to_string(),
        )])),
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
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        11
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 1);
    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let stored = state
        .project_catalog
        .get_project_last_mr_activity("group/repo")
        .await?;
    let current_marker = format!("{}|{}", default_created_at().to_rfc3339(), 11);
    assert_eq!(stored, Some(current_marker));
    Ok(())
}

#[tokio::test]
async fn incremental_does_not_advance_marker_when_repo_scan_is_interrupted() -> Result<()> {
    let config = test_config();
    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let base_gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(12, "sha12")]),
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
    let signal_open = Arc::new(tokio::sync::Notify::new());
    let gitlab = Arc::new(ShutdownOnListOpenGitLab {
        inner: Arc::clone(&base_gitlab),
        signal_open: Arc::clone(&signal_open),
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        12
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    ));
    let drain_service = Arc::clone(&service);
    tokio::spawn(async move {
        signal_open.notified().await;
        drain_service.request_graceful_drain();
    });

    service.scan_once_incremental().await?;

    assert_eq!(*base_gitlab.list_open_calls.lock().unwrap(), 1);
    assert_eq!(*runner.calls.lock().unwrap(), 0);
    let stored = state
        .project_catalog
        .get_project_last_mr_activity("group/repo")
        .await?;
    assert_eq!(stored, Some(previous_marker));
    Ok(())
}

#[tokio::test]
async fn incremental_uses_cached_project_catalog() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::All;
    config.gitlab.targets.refresh_seconds = 3600;

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(vec!["group/ignored".to_string()]),
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
    let cache_key = config.gitlab.targets.cache_key_for_all();
    state
        .project_catalog
        .save_project_catalog(&cache_key, &["group/repo".to_string()])
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 0);
    assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
    Ok(())
}

#[tokio::test]
async fn incremental_refreshes_project_catalog_when_expired() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos = TargetSelector::All;
    config.gitlab.targets.refresh_seconds = 0;

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(vec!["group/fresh".to_string()]),
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
    let cache_key = config.gitlab.targets.cache_key_for_all();
    state
        .project_catalog
        .save_project_catalog(&cache_key, &["group/stale".to_string()])
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 1);
    let loaded = state
        .project_catalog
        .load_project_catalog(&cache_key)
        .await?
        .expect("catalog");
    assert_eq!(loaded.projects, vec!["group/fresh".to_string()]);
    Ok(())
}

#[tokio::test]
async fn incremental_scan_returns_before_blocking_review_finishes() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let review_mr = mr(40, "sha40");
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![review_mr]),
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
        40
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
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once_incremental().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    let scan_status =
        tokio::time::timeout(std::time::Duration::from_millis(200), scan_task).await???;
    assert_eq!(scan_status, ScanRunStatus::Completed);

    let in_progress = state.review_state.list_in_progress_reviews().await?;
    assert_eq!(in_progress.len(), 1);
    assert_eq!(in_progress[0].iid, 40);
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);

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
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn second_incremental_scan_returns_while_first_review_holds_only_permit() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(70, "sha70");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![first_mr.clone()]),
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
        70
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab.clone(),
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

    let mut second_mr = mr(71, "sha71");
    second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr];

    let second_scan_status = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        service.scan_once_incremental(),
    )
    .await??;
    assert_eq!(second_scan_status, ScanRunStatus::Completed);

    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    let review_iids: Vec<i64> =
        sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(review_iids, vec![70, 71]);
    let in_progress = state.review_state.list_in_progress_reviews().await?;
    assert_eq!(in_progress.len(), 2);

    release_first.notify_waiters();
    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 2
            && state
                .review_state
                .list_in_progress_reviews()
                .await?
                .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 2);
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn queued_reviews_are_heartbeated_across_incremental_scans() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.review.stale_in_progress_minutes = 0;
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let mut first_mr = mr(80, "sha80");
    first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let mut second_mr = mr(81, "sha81");
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
        80
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab.clone(),
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

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    let mut third_mr = mr(82, "sha82");
    third_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
    *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr, third_mr];

    let second_scan_status = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        service.scan_once_incremental(),
    )
    .await??;
    assert_eq!(second_scan_status, ScanRunStatus::Completed);

    let run_counts: Vec<(i64, i64)> = sqlx::query_as(
        "SELECT iid, COUNT(*) FROM run_history WHERE kind = 'review' GROUP BY iid ORDER BY iid",
    )
    .fetch_all(state.pool())
    .await?;
    assert_eq!(run_counts, vec![(80, 1), (81, 1), (82, 1)]);

    release_first.notify_waiters();
    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 3
            && state
                .review_state
                .list_in_progress_reviews()
                .await?
                .is_empty()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 3);
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn incremental_defers_same_mr_mentions_while_active_mention_blocks_review() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
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
    let mut busy_mr = mr(41, "sha41");
    busy_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
    let mut other_mr = mr(42, "sha42");
    other_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![busy_mr, other_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![MergeRequestDiscussion {
                id: "discussion-41".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 1040,
                        body: "bot context".to_string(),
                        author: bot_user.clone(),
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1041,
                        body: "@botuser first request".to_string(),
                        author: requester.clone(),
                        system: false,
                        in_reply_to_id: Some(1040),
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1042,
                        body: "@botuser second request".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(1040),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
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
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        41
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    state
        .mention_commands
        .begin_mention_command("group/repo", 41, "discussion-41", 1041, "sha41")
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    for _ in 0..50 {
        if *runner.review_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let review_iids: Vec<i64> =
        sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
            .fetch_all(state.pool())
            .await?;
    assert_eq!(review_iids, vec![42]);
    let mention_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
            .fetch_one(state.pool())
            .await?;
    assert_eq!(mention_rows, 0);
    let stored = state
        .project_catalog
        .get_project_last_mr_activity("group/repo")
        .await?;
    assert_eq!(stored, Some(previous_marker.clone()));

    state
        .mention_commands
        .finish_mention_command(
            "group/repo",
            41,
            "discussion-41",
            1041,
            "sha41",
            "no_changes",
        )
        .await?;

    service.scan_once_incremental().await?;

    for _ in 0..50 {
        if *runner.mention_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let blocked_review_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'review' AND iid = ?")
            .bind(41i64)
            .fetch_one(state.pool())
            .await?;
    assert_eq!(blocked_review_rows, 0);
    let second_trigger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(41i64)
    .bind("discussion-41")
    .bind(1042i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(second_trigger_rows, 1);
    Ok(())
}

#[tokio::test]
async fn incremental_defers_new_mentions_while_same_mr_review_is_in_progress() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
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
    let mut active_review_mr = mr(51, "sha51");
    active_review_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![active_review_mr]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 51),
            vec![MergeRequestDiscussion {
                id: "discussion-51".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 1050,
                        body: "bot context".to_string(),
                        author: bot_user.clone(),
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 1051,
                        body: "@botuser please follow up".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(1050),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
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
    let previous_marker = format!(
        "{}|{}",
        (default_created_at() - Duration::days(1)).to_rfc3339(),
        51
    );
    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", &previous_marker)
        .await?;
    state
        .review_state
        .begin_review("group/repo", 51, "sha51")
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let mention_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
            .fetch_one(state.pool())
            .await?;
    assert_eq!(mention_rows, 0);
    let stored = state
        .project_catalog
        .get_project_last_mr_activity("group/repo")
        .await?;
    assert_eq!(stored, Some(previous_marker.clone()));

    state
        .review_state
        .finish_review("group/repo", 51, "sha51", "pass")
        .await?;

    service.scan_once_incremental().await?;

    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    for _ in 0..50 {
        if *runner.mention_calls.lock().unwrap() == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let scheduled_trigger_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(51i64)
    .bind("discussion-51")
    .bind(1051i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(scheduled_trigger_rows, 1);
    Ok(())
}

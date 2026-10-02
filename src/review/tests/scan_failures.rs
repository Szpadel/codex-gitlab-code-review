use super::*;
use async_trait::async_trait;

struct DynamicTargets(Mutex<Vec<String>>);

#[async_trait]
impl DynamicRepoSource for DynamicTargets {
    async fn list_repos(&self) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn scan_removes_overdue_retries_outside_resolved_targets() -> Result<()> {
    for remaining_targets in [vec!["group/current".to_string()], vec![]] {
        let gitlab = fake_gitlab(vec![mr(1, "sha1")]);
        let targets = Arc::new(DynamicTargets(Mutex::new(vec![
            "group/removed".to_string(),
        ])));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            test_config(),
            gitlab.clone(),
            state,
            Arc::new(FailingRunner {
                calls: Mutex::new(0),
            }),
            1,
            default_created_after(),
        )
        .with_dynamic_repo_source(targets.clone());
        service.scan_once().await?;
        let now = Utc::now();
        assert_eq!(
            service.defer_review_backoff_retries_for_mr(
                "group/removed",
                1,
                now + Duration::hours(1),
                now - Duration::minutes(1),
            ),
            1
        );
        assert!(
            service
                .next_review_backoff_retry_at()
                .is_some_and(|next| next < now)
        );
        gitlab.awards.lock().unwrap().insert(
            ("group/removed".to_string(), 1),
            vec![AwardEmoji {
                id: 99,
                name: "warning".to_string(),
                user: gitlab.bot_user.clone(),
            }],
        );
        *targets.0.lock().unwrap() = remaining_targets.clone();

        service.scan_once().await?;

        assert!(!service.has_active_review_backoff_retry_for_mr("group/removed", 1));
        assert!(
            service
                .next_review_backoff_retry_at()
                .is_none_or(|next| next > now)
        );
        assert_eq!(
            service.has_active_review_backoff_retry_for_mr("group/current", 1),
            !remaining_targets.is_empty()
        );
        assert!(
            gitlab
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call == "delete_award:group/removed:1:99")
        );
    }
    Ok(())
}

#[tokio::test]
async fn scan_continues_after_repository_failure_and_joins_reviews() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos =
        TargetSelector::List(vec!["group/a-fail".to_string(), "group/b-ok".to_string()]);
    let mut gitlab = InlineReviewGitLab::new(fake_gitlab(vec![mr(1, "sha1")]), vec![], vec![]);
    gitlab.list_open_error_project = Some("group/a-fail".to_string());
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        Arc::new(gitlab),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    let err = service
        .scan_once()
        .await
        .expect_err("repository failure must remain visible");

    assert!(format!("{err:#}").contains("MR listing failed"));
    assert_eq!(
        *runner.calls.lock().unwrap(),
        1,
        "the second repository must still be scanned"
    );
    let history = state
        .run_history
        .list_run_history_for_mr("group/b-ok", 1)
        .await?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].result.as_deref(), Some("pass"));
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
async fn failed_incremental_scan_returns_while_its_queued_review_runs() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos =
        TargetSelector::List(vec!["group/a-ok".to_string(), "group/b-fail".to_string()]);
    let mut gitlab = InlineReviewGitLab::new(fake_gitlab(vec![mr(1, "sha1")]), vec![], vec![]);
    gitlab.list_open_error_project = Some("group/b-fail".to_string());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::new(tokio::sync::Notify::new()),
        release_first: Arc::new(tokio::sync::Notify::new()),
        review_calls: Mutex::new(0),
    });
    let started = runner.first_started.notified();
    tokio::pin!(started);
    started.as_mut().enable();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = Arc::new(ReviewService::new(
        config,
        Arc::new(gitlab),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    ));
    let scan_result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        service.scan_once_incremental(),
    )
    .await?;
    tokio::time::timeout(std::time::Duration::from_secs(2), started).await?;
    let running_after_scan = *runner.review_calls.lock().unwrap();
    runner.release_first.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert!(
        scan_result.is_err(),
        "the failed repository must fail the scan"
    );
    assert_eq!(running_after_scan, 1, "the queued review keeps running");
    let history = state
        .run_history
        .list_run_history_for_mr("group/a-ok", 1)
        .await?;
    assert_eq!(history[0].result.as_deref(), Some("pass"));
    Ok(())
}

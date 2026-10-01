use super::*;
use crate::flow::admission::AdmissionHistory;

#[tokio::test]
async fn scan_bounds_spawned_reviews_and_waiting_claims() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let gitlab = fake_gitlab((1..=8).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: first_started.clone(),
        release_first: release_first.clone(),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    ));
    let first_started_wait = first_started.notified();
    let scan = {
        let service = service.clone();
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let claimed = state.review_state.list_in_progress_reviews().await?.len();
    let running = *runner.review_calls.lock().unwrap();

    release_first.notify_one();
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), scan).await???;
    assert!(
        claimed <= 4,
        "one running review, two queued reviews, and one admission claim must bound the scan, got {claimed}"
    );
    assert_eq!(running, 1, "the concurrency limit must remain one");
    assert_eq!(status, ScanRunStatus::Completed);
    assert_eq!(*runner.review_calls.lock().unwrap(), 8);
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
async fn scan_reaps_completed_review_handles() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let merge_requests: Vec<_> = (1..=12).map(|iid| mr(iid, &format!("sha{iid}"))).collect();
    let gitlab = fake_gitlab(merge_requests.clone());
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
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
    let mut tasks = vec![];
    for merge_request in merge_requests {
        let head_sha = merge_request.head_sha().unwrap();
        let history =
            AdmissionHistory::new(service.gitlab.as_ref(), "group/repo", merge_request.iid);
        service
            .general_review_flow
            .schedule_for_scan("group/repo", merge_request, &head_sha, &mut tasks, &history)
            .await?;
        assert!(tasks.len() <= 3, "completed handles must not accumulate");
    }
    for task in tasks {
        task.await?;
    }
    assert_eq!(*runner.calls.lock().unwrap(), 12);
    Ok(())
}

#[tokio::test]
async fn shutdown_cancels_a_scan_waiting_for_task_admission() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let gitlab = fake_gitlab((1..=8).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: first_started.clone(),
        release_first: release_first.clone(),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    ));
    let first_started_wait = first_started.notified();
    let scan = {
        let service = service.clone();
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while state.review_state.list_in_progress_reviews().await?.len() < 4 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    service.request_shutdown();
    release_first.notify_one();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), scan).await???,
        ScanRunStatus::Interrupted
    );
    service.wait_for_active_tasks().await;
    assert_eq!(*runner.review_calls.lock().unwrap(), 1);
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    Ok(())
}

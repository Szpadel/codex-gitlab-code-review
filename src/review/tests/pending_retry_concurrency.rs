use super::*;
use crate::codex_runner::{
    CodexRunner, MentionCommandContext, MentionCommandResult, MentionCommandStatus,
};
use tokio::sync::{Semaphore, mpsc};

struct PendingRetryRunner {
    started: mpsc::UnboundedSender<u64>,
    release: Arc<Semaphore>,
}

#[async_trait::async_trait]
impl CodexRunner for PendingRetryRunner {
    async fn run_review(&self, context: crate::codex_runner::ReviewContext) -> Result<CodexResult> {
        self.started.send(context.mr.iid)?;
        self.release.acquire().await?.forget();
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }

    async fn run_mention_command(
        &self,
        context: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        self.started.send(context.mr.iid)?;
        self.release.acquire().await?.forget();
        Ok(MentionCommandResult {
            status: MentionCommandStatus::NoChanges,
            commit_sha: None,
            reply_message: "No changes.".to_string(),
        })
    }
}

#[tokio::test]
async fn pending_reviews_start_concurrently_within_the_limit() -> Result<()> {
    check_pending_review_batch(RetryBatchExit::Complete).await
}

#[tokio::test]
async fn pending_review_drain_finishes_started_retries_and_keeps_unadmitted_rows() -> Result<()> {
    check_pending_review_batch(RetryBatchExit::GracefulDrain).await
}

enum RetryBatchExit {
    Complete,
    GracefulDrain,
}

async fn check_pending_review_batch(exit: RetryBatchExit) -> Result<()> {
    let drain = matches!(exit, RetryBatchExit::GracefulDrain);
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let gitlab = fake_gitlab((1..=4).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    for iid in 1..=4 {
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                iid,
                &format!("sha{iid}"),
                0,
                0,
            )
            .await?;
    }
    let (started, mut starts) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let runner = Arc::new(PendingRetryRunner {
        started,
        release: release.clone(),
    });
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner,
        1,
        default_created_after(),
    ));
    let retries = {
        let service = service.clone();
        tokio::spawn(async move { service.process_due_pending_rate_limit_reviews().await })
    };
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?;
    assert!(first.is_some());
    let second = tokio::time::timeout(std::time::Duration::from_millis(200), starts.recv()).await;
    let extra = tokio::time::timeout(std::time::Duration::from_millis(50), starts.recv()).await;
    if drain {
        service.request_graceful_drain();
    }
    release.add_permits(4);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), retries).await???;

    assert!(
        matches!(second, Ok(Some(_))),
        "two due pending reviews must start before either completes"
    );
    assert!(extra.is_err(), "the third retry must wait for a permit");
    let pending = state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    if drain {
        assert_eq!(status, ScanRunStatus::Interrupted);
        assert_eq!(
            pending.iter().map(|row| row.iid).collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert!(pending.iter().all(|row| row.next_retry_at == 0));
    } else {
        assert_eq!(status, ScanRunStatus::Completed);
        assert!(pending.is_empty());
    }
    assert_eq!(
        state
            .run_history
            .list_run_history(&RunHistoryListQuery::default())
            .await?
            .runs
            .len(),
        if drain { 2 } else { 4 }
    );
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
async fn pending_mentions_start_concurrently_on_separate_branches() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("bot".to_string());
    let merge_requests = (1..=2)
        .map(|iid| {
            let mut merge_request = mr(iid, &format!("sha{iid}"));
            merge_request.source_branch = Some(format!("branch-{iid}"));
            merge_request
        })
        .collect();
    let gitlab = fake_gitlab(merge_requests);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    for iid in 1..=2 {
        gitlab.discussions.lock().unwrap().insert(
            ("group/repo".to_string(), iid),
            vec![MergeRequestDiscussion {
                id: "discussion".to_string(),
                individual_note: false,
                notes: vec![DiscussionNote {
                    id: 10,
                    body: "@bot please check".to_string(),
                    author: GitLabUser {
                        id: 7,
                        username: Some("alice".to_string()),
                        name: None,
                    },
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                }],
            }],
        );
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(crate::state::MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid,
                discussion_id: "discussion",
                trigger_note_id: 10,
                head_sha: &format!("sha{iid}"),
                blocked_at: 0,
                next_retry_at: 0,
            })
            .await?;
    }
    let (started, mut starts) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        Arc::new(PendingRetryRunner {
            started,
            release: release.clone(),
        }),
        1,
        default_created_after(),
    ));
    let retries =
        tokio::spawn(async move { service.process_due_pending_rate_limit_reviews().await });
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv())
            .await?
            .is_some()
    );
    let second = tokio::time::timeout(std::time::Duration::from_millis(200), starts.recv()).await;
    release.add_permits(2);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(5), retries).await???,
        ScanRunStatus::Completed
    );
    assert!(
        matches!(second, Ok(Some(_))),
        "due mentions on separate branches must start concurrently"
    );
    assert!(
        state
            .mention_quota_pending
            .list_mention_quota_pending()
            .await?
            .is_empty()
    );
    assert!(
        state
            .mention_commands
            .list_in_progress_mention_commands()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn pending_retry_failure_drains_started_work_and_keeps_unadmitted_rows() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let gitlab = fake_gitlab((1..=3).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("CREATE TRIGGER reject_first_history BEFORE INSERT ON run_history WHEN NEW.iid = 1 BEGIN SELECT RAISE(FAIL, 'history unavailable'); END")
        .execute(state.pool()).await?;
    for iid in 1..=3 {
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                iid,
                &format!("sha{iid}"),
                0,
                0,
            )
            .await?;
    }
    let (started, mut starts) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state.clone(),
        Arc::new(PendingRetryRunner {
            started,
            release: release.clone(),
        }),
        1,
        default_created_after(),
    ));
    let retries = {
        let service = service.clone();
        tokio::spawn(async move { service.process_due_pending_rate_limit_reviews().await })
    };
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?,
        Some(2)
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            let pending = state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?;
            if pending
                .iter()
                .any(|row| row.iid == 1 && row.next_retry_at > Utc::now().timestamp())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    assert!(
        !retries.is_finished(),
        "a retry error must not abandon started work"
    );
    release.add_permits(1);
    let error = tokio::time::timeout(std::time::Duration::from_secs(5), retries)
        .await??
        .unwrap_err();
    assert!(format!("{error:#}").contains("history unavailable"));
    service.wait_for_active_tasks().await;
    let pending = state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    assert_eq!(pending.len(), 2);
    assert!(
        pending
            .iter()
            .any(|row| row.iid == 1 && row.next_retry_at > Utc::now().timestamp())
    );
    assert!(
        pending
            .iter()
            .any(|row| row.iid == 3 && row.next_retry_at == 0),
        "unadmitted work must stay due"
    );
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    Ok(())
}

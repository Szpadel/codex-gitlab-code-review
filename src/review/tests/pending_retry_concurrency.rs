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

async fn due_general_reviews(
    state: &ReviewStateStore,
    iids: std::ops::RangeInclusive<u64>,
) -> Result<()> {
    for iid in iids {
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
    Ok(())
}

fn blocking_service(
    config: crate::config::Config,
    gitlab: Arc<FakeGitLab>,
    state: Arc<ReviewStateStore>,
) -> (
    Arc<ReviewService>,
    mpsc::UnboundedReceiver<u64>,
    Arc<Semaphore>,
) {
    let (started, starts) = mpsc::unbounded_channel();
    let release = Arc::new(Semaphore::new(0));
    let runner = Arc::new(PendingRetryRunner {
        started,
        release: release.clone(),
    });
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        state,
        runner,
        1,
        default_created_after(),
    ));
    (service, starts, release)
}

#[tokio::test]
async fn pending_wake_returns_before_queued_reviews_finish() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let gitlab = fake_gitlab((1..=4).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    due_general_reviews(&state, 1..=4).await?;
    let (service, mut starts, release) = blocking_service(config, gitlab, state.clone());

    let status = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        service.queue_due_pending_retries(),
    )
    .await??;
    let first = tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?;
    let second = tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?;
    let extra = tokio::time::timeout(std::time::Duration::from_millis(50), starts.recv()).await;
    release.add_permits(4);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(status, ScanRunStatus::Completed);
    assert!(first.is_some() && second.is_some());
    assert!(extra.is_err(), "the third review must wait for a run slot");
    assert!(
        state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .is_empty()
    );
    assert_eq!(
        state
            .run_history
            .list_run_history(&RunHistoryListQuery::default())
            .await?
            .runs
            .len(),
        4
    );
    Ok(())
}

#[tokio::test]
async fn graceful_drain_keeps_pending_rows_of_dropped_reviews() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let gitlab = fake_gitlab((1..=4).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    due_general_reviews(&state, 1..=4).await?;
    let (service, mut starts, release) = blocking_service(config, gitlab, state.clone());

    service.queue_due_pending_retries().await?;
    let mut started = vec![
        tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?,
        tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?,
    ];
    service.request_graceful_drain();
    release.add_permits(4);
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        service.wait_for_active_tasks(),
    )
    .await?;

    started.sort();
    assert_eq!(started, vec![Some(1), Some(2)]);
    let pending = state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    assert_eq!(
        pending.iter().map(|row| row.iid).collect::<Vec<_>>(),
        vec![3, 4],
        "dropped reviews keep their pending rows for the next process"
    );
    assert_eq!(
        state
            .run_history
            .list_run_history(&RunHistoryListQuery::default())
            .await?
            .runs
            .len(),
        2
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
    let status = service.queue_due_pending_retries().await?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv())
            .await?
            .is_some()
    );
    let second = tokio::time::timeout(std::time::Duration::from_millis(200), starts.recv()).await;
    release.add_permits(2);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;
    assert_eq!(status, ScanRunStatus::Completed);
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
async fn pending_review_start_failure_keeps_its_row_and_requests_a_rescan() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let gitlab = fake_gitlab((1..=3).map(|iid| mr(iid, &format!("sha{iid}"))).collect());
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("CREATE TRIGGER reject_first_history BEFORE INSERT ON run_history WHEN NEW.iid = 1 BEGIN SELECT RAISE(FAIL, 'history unavailable'); END")
        .execute(state.pool()).await?;
    due_general_reviews(&state, 1..=3).await?;
    let (service, _starts, release) = blocking_service(config, gitlab, state.clone());

    release.add_permits(3);
    let status = service.process_due_pending_retries().await?;

    assert_eq!(status, ScanRunStatus::Completed);
    let pending = state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].iid, 1);
    assert!(
        pending[0].next_retry_at > Utc::now().timestamp(),
        "the failed review must wait before its next attempt"
    );
    assert!(
        service.rescan_requests.pending("group/repo").is_some(),
        "a start failure must make the next incremental scan read the repository"
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
async fn pending_mention_keeps_its_row_while_a_mention_of_its_mr_runs() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("bot".to_string());
    let gitlab = fake_gitlab(vec![mr(1, "sha1")]);
    let author = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: None,
    };
    gitlab.discussions.lock().unwrap().insert(
        ("group/repo".to_string(), 1),
        vec![MergeRequestDiscussion {
            id: "discussion".to_string(),
            individual_note: false,
            notes: [10, 11]
                .into_iter()
                .map(|id| DiscussionNote {
                    id,
                    body: "@bot please check".to_string(),
                    author: author.clone(),
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                })
                .collect(),
        }],
    );
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    for trigger_note_id in [10, 11] {
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(crate::state::MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid: 1,
                discussion_id: "discussion",
                trigger_note_id,
                head_sha: "sha1",
                blocked_at: 0,
                next_retry_at: 0,
            })
            .await?;
    }
    let (service, mut starts, release) = blocking_service(config, gitlab, state.clone());

    service.queue_due_pending_retries().await?;
    tokio::time::timeout(std::time::Duration::from_secs(1), starts.recv()).await?;
    let second_start =
        tokio::time::timeout(std::time::Duration::from_millis(50), starts.recv()).await;
    let waiting_rows = state
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?;
    release.add_permits(2);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert!(
        second_start.is_err(),
        "two mentions of one MR never run at the same time"
    );
    assert_eq!(waiting_rows.len(), 1, "the waiting mention keeps its row");
    assert!(waiting_rows[0].next_retry_at > Utc::now().timestamp());
    assert!(
        state
            .mention_quota_pending
            .list_mention_quota_pending()
            .await?
            .is_empty()
    );
    Ok(())
}

use super::*;
use crate::codex_runner::{
    CodexRunner, MentionCommandContext, MentionCommandResult, MentionCommandStatus, ReviewContext,
};
use async_trait::async_trait;
use tokio::sync::{Notify, Semaphore};

/// Records the lane, MR, and head of each review start.
/// The first review holds its run slot until the test releases it.
struct OrderRecordingRunner {
    starts: Mutex<Vec<(ReviewLane, u64, String)>>,
    first_started: Notify,
    release_first: Semaphore,
}

impl OrderRecordingRunner {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            starts: Mutex::new(Vec::new()),
            first_started: Notify::new(),
            release_first: Semaphore::new(0),
        })
    }

    fn starts(&self) -> Vec<(ReviewLane, u64, String)> {
        self.starts.lock().unwrap().clone()
    }

    async fn wait_for_first_start(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.first_started.notified(),
        )
        .await
        .expect("first review should start");
    }
}

#[async_trait]
impl CodexRunner for OrderRecordingRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        let first = {
            let mut starts = self.starts.lock().unwrap();
            starts.push((ctx.lane, ctx.mr.iid, ctx.head_sha.clone()));
            starts.len() == 1
        };
        if first {
            self.first_started.notify_one();
            self.release_first.acquire().await?.forget();
        }
        // A comment marks only its own head, so a later head still needs a review.
        Ok(CodexResult::Comment(crate::codex_runner::ReviewComment {
            summary: "needs changes".to_string(),
            body: "Review text".to_string(),
            overall_explanation: None,
            overall_confidence_score: None,
            findings: vec![],
            omitted_duplicate_count: 0,
        }))
    }
}

fn service_with_one_slot(
    gitlab: Arc<FakeGitLab>,
    state: Arc<ReviewStateStore>,
    runner: Arc<OrderRecordingRunner>,
) -> ReviewService {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.feature_flags.security_review = true;
    ReviewService::new(config, gitlab, state, runner, 1, default_created_after())
}

/// Simulates a push: a new head and a newer activity time for incremental scans.
fn set_head(gitlab: &FakeGitLab, iid: u64, head_sha: &str) {
    let mut mrs = gitlab.mrs.lock().unwrap();
    let merge_request = mrs
        .iter_mut()
        .find(|merge_request| merge_request.iid == iid)
        .expect("test MR exists");
    merge_request.sha = Some(head_sha.to_string());
    merge_request.updated_at = Some(Utc::now());
}

#[tokio::test]
async fn security_reviews_start_after_queued_general_reviews() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1"), mr(2, "b1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = service_with_one_slot(gitlab, state, Arc::clone(&runner));

    service.scan_once_incremental().await?;
    runner.wait_for_first_start().await;
    runner.release_first.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(
        runner.starts(),
        vec![
            (ReviewLane::General, 1, "a1".to_string()),
            (ReviewLane::General, 2, "b1".to_string()),
            (ReviewLane::Security, 1, "a1".to_string()),
            (ReviewLane::Security, 2, "b1".to_string()),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn queued_review_takes_no_claim_or_history_before_it_starts() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1"), mr(2, "b1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = service_with_one_slot(gitlab, Arc::clone(&state), Arc::clone(&runner));

    service.scan_once_incremental().await?;
    runner.wait_for_first_start().await;
    let claims = state.review_state.list_in_progress_reviews().await?;
    let history = state
        .run_history
        .list_run_history(&RunHistoryListQuery::default())
        .await?;
    runner.release_first.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(
        claims
            .iter()
            .map(|claim| (claim.lane, claim.iid))
            .collect::<Vec<_>>(),
        vec![(ReviewLane::General, 1)],
        "only the running review holds a claim"
    );
    assert_eq!(history.runs.len(), 1, "only the running review has history");
    Ok(())
}

#[tokio::test]
async fn waiting_review_reviews_the_latest_head_only() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1"), mr(2, "b1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.review.max_concurrent = 1;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    runner.wait_for_first_start().await;
    set_head(&gitlab, 2, "b2");
    runner.release_first.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(
        runner.starts(),
        vec![
            (ReviewLane::General, 1, "a1".to_string()),
            (ReviewLane::General, 2, "b2".to_string()),
        ]
    );
    let history = state
        .run_history
        .list_run_history_for_mr("group/repo", 2)
        .await?;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].head_sha, "b2");
    Ok(())
}

#[tokio::test]
async fn new_head_while_review_runs_queues_a_follow_up_review() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.review.max_concurrent = 2;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    runner.wait_for_first_start().await;
    set_head(&gitlab, 1, "a2");
    service.scan_once_incremental().await?;
    tokio::task::yield_now().await;
    let starts_while_first_runs = runner.starts().len();
    runner.release_first.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(
        starts_while_first_runs, 1,
        "the follow-up waits for the running review of its MR and lane"
    );
    assert_eq!(
        runner.starts(),
        vec![
            (ReviewLane::General, 1, "a1".to_string()),
            (ReviewLane::General, 1, "a2".to_string()),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn failed_queued_review_makes_the_next_incremental_scan_read_the_repository() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        test_config(),
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    service.wait_for_idle().await;
    service.scan_once_incremental().await?;
    service.wait_for_idle().await;

    assert!(
        runner.starts().is_empty(),
        "the review fails before codex runs"
    );
    assert_eq!(
        *gitlab.list_open_calls.lock().unwrap(),
        2,
        "the unchanged repository must be read again after the failure"
    );
    Ok(())
}

#[derive(Clone, Copy, PartialEq)]
enum RunKind {
    Review,
    Mention,
}

/// Records review and mention runs per MR. Runs of one kind for `held_iid` wait until the
/// test releases them.
struct HeldRunner {
    held_kind: RunKind,
    held_iid: u64,
    held_started: Notify,
    release: Semaphore,
    reviews: Mutex<Vec<u64>>,
    mentions: Mutex<Vec<u64>>,
}

impl HeldRunner {
    fn new(held_kind: RunKind, held_iid: u64) -> Arc<Self> {
        Arc::new(Self {
            held_kind,
            held_iid,
            held_started: Notify::new(),
            release: Semaphore::new(0),
            reviews: Mutex::new(Vec::new()),
            mentions: Mutex::new(Vec::new()),
        })
    }

    async fn hold_if_selected(&self, kind: RunKind, iid: u64) -> Result<()> {
        if kind == self.held_kind && iid == self.held_iid {
            self.held_started.notify_one();
            self.release.acquire().await?.forget();
        }
        Ok(())
    }

    async fn wait_for_held_start(&self) {
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            self.held_started.notified(),
        )
        .await
        .expect("held run should start");
    }
}

#[async_trait]
impl CodexRunner for HeldRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        self.reviews.lock().unwrap().push(ctx.mr.iid);
        self.hold_if_selected(RunKind::Review, ctx.mr.iid).await?;
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }

    async fn run_mention_command(
        &self,
        ctx: MentionCommandContext,
    ) -> Result<MentionCommandResult> {
        self.mentions.lock().unwrap().push(ctx.mr.iid);
        self.hold_if_selected(RunKind::Mention, ctx.mr.iid).await?;
        Ok(MentionCommandResult {
            status: MentionCommandStatus::NoChanges,
            commit_sha: None,
            reply_message: "No code changes required.".to_string(),
        })
    }
}

fn mention_config() -> crate::config::Config {
    let mut config = test_config();
    config.review.max_concurrent = 2;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config
}

fn add_mention_trigger(gitlab: &FakeGitLab, iid: u64, trigger_note_id: u64) {
    gitlab.discussions.lock().unwrap().insert(
        ("group/repo".to_string(), iid),
        vec![MergeRequestDiscussion {
            id: format!("discussion-{iid}"),
            individual_note: true,
            notes: vec![DiscussionNote {
                id: trigger_note_id,
                body: "@botuser please check".to_string(),
                author: GitLabUser {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            }],
        }],
    );
}

async fn wait_until(condition: impl Fn() -> bool) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition should become true");
}

#[tokio::test]
async fn running_mention_holds_back_reviews_of_its_merge_request() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(41, "sha41"), mr(42, "sha42")]);
    add_mention_trigger(&gitlab, 41, 410);
    let runner = HeldRunner::new(RunKind::Mention, 41);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        mention_config(),
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    runner.wait_for_held_start().await;
    wait_until(|| runner.reviews.lock().unwrap().contains(&42)).await;
    let reviews_while_mention_runs = runner.reviews.lock().unwrap().clone();
    runner.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(reviews_while_mention_runs, vec![42]);
    assert_eq!(*runner.reviews.lock().unwrap(), vec![42, 41]);
    assert_eq!(*runner.mentions.lock().unwrap(), vec![41]);
    Ok(())
}

#[tokio::test]
async fn running_review_holds_back_a_new_mention_of_its_merge_request() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(51, "sha51")]);
    let runner = HeldRunner::new(RunKind::Review, 51);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        mention_config(),
        gitlab.clone(),
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    runner.wait_for_held_start().await;
    add_mention_trigger(&gitlab, 51, 510);
    set_head(&gitlab, 51, "sha51");
    service.scan_once_incremental().await?;
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let mentions_while_review_runs = runner.mentions.lock().unwrap().len();
    runner.release.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), service.wait_for_idle()).await?;

    assert_eq!(mentions_while_review_runs, 0);
    assert_eq!(*runner.mentions.lock().unwrap(), vec![51]);
    assert_eq!(*runner.reviews.lock().unwrap(), vec![51]);
    Ok(())
}

#[tokio::test]
async fn busy_claim_requests_a_rescan_instead_of_dropping_the_review() -> Result<()> {
    let gitlab = fake_gitlab(vec![mr(1, "a1")]);
    let runner = OrderRecordingRunner::new();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    // A run that ended without its cleanup left this claim behind.
    state
        .review_state
        .begin_review_for_lane("group/repo", 1, "old-head", ReviewLane::General)
        .await?;
    let service = ReviewService::new(
        test_config(),
        gitlab,
        state,
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once_incremental().await?;
    service.wait_for_idle().await;

    assert!(runner.starts().is_empty());
    assert!(
        service.rescan_requests.pending("group/repo").is_some(),
        "the next scan must queue the review again"
    );
    Ok(())
}

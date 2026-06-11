use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::ActiveTaskRegistry;
use crate::flow::FlowShared;
use crate::flow::award_service::AwardService;
use crate::flow::mention::{MentionFlow, MentionScheduleOutcome};
use crate::flow::review::{RetryBackoff, ReviewFlow, ReviewScheduleOutcome};
use crate::gitlab::{GitLabApi, MergeRequest, gitlab_error_has_status};
use crate::lifecycle::ServiceLifecycle;
use crate::review::ReviewLane;
use crate::review::lane_policies::{GeneralLanePolicy, SecurityLanePolicy};
use crate::review::scan_coordinator::{DefaultScanCoordinator, ScanCoordinator};
use crate::review::scan_pipeline::{run_pending_rate_limit_pipeline, run_scan_pipeline};
use crate::review::target_resolver::{DefaultTargetResolver, TargetResolver};
use crate::state::{
    MentionQuotaPendingEntry, MentionQuotaPendingUpsert, ReviewRateLimitPendingEntry,
    ReviewStateStore,
};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

pub(super) const NO_OPEN_MRS_MARKER: &str = "__no_open_mrs__";
const MR_NOT_FOUND_ERROR: &str = "mr not found";
const PENDING_RETRY_LOOKUP_BACKOFF_SECONDS: i64 = 60;

#[derive(Clone, Copy)]
pub(crate) enum ScanMode {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanRunStatus {
    Completed,
    Interrupted,
}

#[async_trait]
pub trait DynamicRepoSource: Send + Sync {
    async fn list_repos(&self) -> Result<Vec<String>>;
}

pub struct ReviewService {
    config: Config,
    pub(super) gitlab: Arc<dyn GitLabApi>,
    pub(super) state: Arc<ReviewStateStore>,
    pub(super) created_after: DateTime<Utc>,
    award_service: AwardService,
    pub(super) general_review_flow: Arc<ReviewFlow>,
    pub(super) security_review_flow: Arc<ReviewFlow>,
    mention_flow: Arc<MentionFlow>,
    lifecycle: Arc<ServiceLifecycle>,
    active_tasks: Arc<ActiveTaskRegistry>,
    scan_coordinator: Box<dyn ScanCoordinator>,
    target_resolver: Box<dyn TargetResolver>,
}

impl ReviewService {
    pub fn new(
        config: Config,
        gitlab: Arc<dyn GitLabApi>,
        state: Arc<ReviewStateStore>,
        codex: Arc<dyn CodexRunner>,
        bot_user_id: u64,
        created_after: DateTime<Utc>,
    ) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.review.max_concurrent));
        let mention_branch_locks = Arc::new(Mutex::new(HashMap::new()));
        let retry_backoff = Arc::new(RetryBackoff::new(Duration::hours(1)));
        let lifecycle = Arc::new(ServiceLifecycle::default());
        let active_tasks = Arc::new(ActiveTaskRegistry::default());
        let award_service = AwardService::new(Arc::clone(&gitlab), bot_user_id);
        let flow_shared = FlowShared {
            config: config.clone(),
            gitlab: Arc::clone(&gitlab),
            award_service: award_service.clone(),
            state: Arc::clone(&state),
            codex: Arc::clone(&codex),
            bot_user_id,
            semaphore: Arc::clone(&semaphore),
            lifecycle: Arc::clone(&lifecycle),
            active_tasks: Arc::clone(&active_tasks),
        };
        let mention_flow = Arc::new(MentionFlow::new(flow_shared.clone(), mention_branch_locks));
        let general_review_flow = Arc::new(ReviewFlow::new(
            flow_shared.clone(),
            Arc::clone(&retry_backoff),
            ReviewLane::General,
            Arc::new(GeneralLanePolicy),
        ));
        let security_review_flow = Arc::new(ReviewFlow::new(
            flow_shared,
            retry_backoff,
            ReviewLane::Security,
            Arc::new(SecurityLanePolicy),
        ));
        let scan_coordinator = Box::new(DefaultScanCoordinator::new(
            Arc::clone(&state),
            Arc::clone(&active_tasks),
            Arc::clone(&codex),
            Arc::clone(&general_review_flow),
            Arc::clone(&security_review_flow),
            Arc::clone(&mention_flow),
        ));
        let target_resolver = Box::new(DefaultTargetResolver::new(
            config.clone(),
            Arc::clone(&gitlab),
            Arc::clone(&state),
        ));
        Self {
            config,
            gitlab,
            state,
            created_after,
            award_service,
            general_review_flow,
            security_review_flow,
            mention_flow,
            lifecycle,
            active_tasks,
            scan_coordinator,
            target_resolver,
        }
    }

    #[must_use]
    pub fn with_dynamic_repo_source(
        mut self,
        dynamic_repo_source: Arc<dyn DynamicRepoSource>,
    ) -> Self {
        self.target_resolver
            .set_dynamic_repo_source(dynamic_repo_source);
        self
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn scan_once(&self) -> Result<ScanRunStatus> {
        self.scan(ScanMode::Full).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn scan_once_incremental(&self) -> Result<ScanRunStatus> {
        self.scan(ScanMode::Incremental).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn next_pending_rate_limit_retry_at(&self) -> Result<Option<DateTime<Utc>>> {
        let review_retry = self
            .state
            .review_rate_limit
            .earliest_review_rate_limit_pending_retry_at()
            .await?
            .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());
        let mention_retry = self
            .state
            .mention_quota_pending
            .earliest_mention_quota_pending_retry_at()
            .await?
            .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single());
        Ok(match (review_retry, mention_retry) {
            (Some(review), Some(mention)) => Some(review.min(mention)),
            (Some(review), None) => Some(review),
            (None, Some(mention)) => Some(mention),
            (None, None) => None,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn process_due_pending_rate_limit_reviews(&self) -> Result<ScanRunStatus> {
        run_pending_rate_limit_pipeline(self).await
    }

    pub fn request_shutdown(&self) {
        self.lifecycle.request_fast_stop();
    }

    pub fn request_graceful_drain(&self) {
        self.lifecycle.request_graceful_drain();
    }

    pub async fn wait_for_started_runs(&self) {
        self.lifecycle.wait_for_started_runs().await;
    }

    pub async fn wait_for_active_tasks(&self) {
        self.active_tasks.wait_for_idle().await;
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn recover_in_progress_reviews(&self) -> Result<()> {
        self.scan_coordinator.recover_in_progress().await
    }

    pub(super) fn shutdown_requested(&self) -> bool {
        !self.lifecycle.accepts_new_work()
    }

    pub(super) async fn clear_stale_flow_state(&self) -> Result<()> {
        self.scan_coordinator.clear_stale_flow_state().await
    }

    pub(super) async fn schedule_mention_commands_for_mr(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<MentionScheduleOutcome> {
        self.mention_flow
            .schedule_for_scan(repo, mr, head_sha, tasks)
            .await
    }

    fn review_flow_for_lane(&self, lane: ReviewLane) -> &ReviewFlow {
        match lane {
            ReviewLane::General => self.general_review_flow.as_ref(),
            ReviewLane::Security => self.security_review_flow.as_ref(),
        }
    }

    async fn defer_pending_review_rate_limit_retry(
        &self,
        pending: &ReviewRateLimitPendingEntry,
        head_sha: &str,
        retry_started_at: i64,
        deferred_until: i64,
    ) -> Result<()> {
        self.state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                pending.lane,
                &pending.repo,
                pending.iid,
                head_sha,
                retry_started_at,
                deferred_until,
            )
            .await
    }

    async fn defer_pending_mention_quota_retry(
        &self,
        pending: &MentionQuotaPendingEntry,
        retry_started_at: i64,
        deferred_until: i64,
    ) -> Result<()> {
        self.state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: &pending.repo,
                iid: pending.iid,
                discussion_id: &pending.discussion_id,
                trigger_note_id: pending.trigger_note_id,
                head_sha: &pending.last_seen_head_sha,
                blocked_at: retry_started_at,
                next_retry_at: deferred_until,
            })
            .await
    }

    pub(super) async fn retry_pending_mention_quota_row(
        &self,
        pending: &MentionQuotaPendingEntry,
    ) -> Result<()> {
        debug!(
            repo = pending.repo.as_str(),
            iid = pending.iid,
            discussion_id = pending.discussion_id.as_str(),
            trigger_note_id = pending.trigger_note_id,
            next_retry_at = pending.next_retry_at,
            "retrying due pending mention quota row"
        );
        let mr = match self.gitlab.get_mr(&pending.repo, pending.iid).await {
            Ok(mr) => mr,
            Err(err) if should_clear_pending_retry_after_mr_lookup_error(&err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    discussion_id = pending.discussion_id.as_str(),
                    trigger_note_id = pending.trigger_note_id,
                    error = %err,
                    "merge request lookup failed while retrying pending mention; clearing pending row"
                );
                if self
                    .state
                    .mention_quota_pending
                    .clear_mention_quota_pending(
                        &pending.repo,
                        pending.iid,
                        &pending.discussion_id,
                        pending.trigger_note_id,
                    )
                    .await?
                {
                    self.remove_mention_quota_award_after_pending_clear(pending)
                        .await;
                }
                return Ok(());
            }
            Err(err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    discussion_id = pending.discussion_id.as_str(),
                    trigger_note_id = pending.trigger_note_id,
                    error = %err,
                    "merge request lookup failed while retrying pending mention; deferring retry"
                );
                let retry_started_at = Utc::now().timestamp();
                let deferred_until =
                    retry_started_at.saturating_add(PENDING_RETRY_LOOKUP_BACKOFF_SECONDS);
                self.defer_pending_mention_quota_retry(pending, retry_started_at, deferred_until)
                    .await?;
                return Ok(());
            }
        };
        let Some(head_sha) = mr.head_sha() else {
            warn!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                discussion_id = pending.discussion_id.as_str(),
                trigger_note_id = pending.trigger_note_id,
                "missing head sha while retrying pending mention; clearing pending row"
            );
            if self
                .state
                .mention_quota_pending
                .clear_mention_quota_pending(
                    &pending.repo,
                    pending.iid,
                    &pending.discussion_id,
                    pending.trigger_note_id,
                )
                .await?
            {
                self.remove_mention_quota_award_after_pending_clear(pending)
                    .await;
            }
            return Ok(());
        };

        let mut tasks = Vec::new();
        let outcome = self
            .mention_flow
            .schedule_for_scan(&pending.repo, &mr, &head_sha, &mut tasks)
            .await?;
        let _ = join_all(tasks).await;

        match self
            .state
            .mention_commands
            .mention_command_scan_state(
                &pending.repo,
                pending.iid,
                &pending.discussion_id,
                pending.trigger_note_id,
            )
            .await?
        {
            crate::state::MentionCommandScanState::Completed => {
                if self
                    .state
                    .mention_quota_pending
                    .clear_mention_quota_pending(
                        &pending.repo,
                        pending.iid,
                        &pending.discussion_id,
                        pending.trigger_note_id,
                    )
                    .await?
                {
                    self.remove_mention_quota_award_after_pending_clear(pending)
                        .await;
                }
            }
            crate::state::MentionCommandScanState::Ready => {
                let now = Utc::now().timestamp();
                let still_due = self
                    .state
                    .mention_quota_pending
                    .list_mention_quota_pending()
                    .await?
                    .into_iter()
                    .any(|entry| {
                        entry.repo == pending.repo
                            && entry.iid == pending.iid
                            && entry.discussion_id == pending.discussion_id
                            && entry.trigger_note_id == pending.trigger_note_id
                            && entry.next_retry_at <= now
                    });
                if still_due
                    && !outcome.blocked_pending_work
                    && self
                        .state
                        .mention_quota_pending
                        .clear_mention_quota_pending(
                            &pending.repo,
                            pending.iid,
                            &pending.discussion_id,
                            pending.trigger_note_id,
                        )
                        .await?
                {
                    self.remove_mention_quota_award_after_pending_clear(pending)
                        .await;
                }
            }
            crate::state::MentionCommandScanState::InProgress => {}
        }
        Ok(())
    }

    pub(super) async fn retry_pending_review_rate_limit_row(
        &self,
        pending: &ReviewRateLimitPendingEntry,
    ) -> Result<ReviewScheduleOutcome> {
        debug!(
            repo = pending.repo.as_str(),
            iid = pending.iid,
            lane = pending.lane.as_str(),
            next_retry_at = pending.next_retry_at,
            "retrying due pending review rate-limit row"
        );
        let mr = match self.gitlab.get_mr(&pending.repo, pending.iid).await {
            Ok(mr) => mr,
            Err(err) if should_clear_pending_retry_after_mr_lookup_error(&err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    lane = pending.lane.as_str(),
                    error = %err,
                    "merge request lookup failed while retrying pending review; clearing pending row"
                );
                if self
                    .state
                    .review_rate_limit
                    .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
                    .await?
                {
                    self.remove_pending_awards_after_clear(
                        pending.lane,
                        &pending.repo,
                        pending.iid,
                    )
                    .await;
                }
                return Ok(ReviewScheduleOutcome::SkippedCompleted);
            }
            Err(err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    lane = pending.lane.as_str(),
                    error = %err,
                    "merge request lookup failed while retrying pending review; deferring retry"
                );
                let retry_started_at = Utc::now().timestamp();
                let deferred_until =
                    retry_started_at.saturating_add(PENDING_RETRY_LOOKUP_BACKOFF_SECONDS);
                self.defer_pending_review_rate_limit_retry(
                    pending,
                    &pending.last_seen_head_sha,
                    retry_started_at,
                    deferred_until,
                )
                .await?;
                return Ok(ReviewScheduleOutcome::SkippedRateLimit);
            }
        };
        let head_sha = if let Some(value) = mr.head_sha() {
            value
        } else {
            warn!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                lane = pending.lane.as_str(),
                "missing head sha while retrying pending review; clearing pending row"
            );
            if self
                .state
                .review_rate_limit
                .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
                .await?
            {
                self.remove_pending_awards_after_clear(pending.lane, &pending.repo, pending.iid)
                    .await;
            }
            return Ok(ReviewScheduleOutcome::SkippedCompleted);
        };
        let outcome = self
            .review_flow_for_lane(pending.lane)
            .run_for_mr(&pending.repo, mr, &head_sha)
            .await
            .map_err(|err| {
                let retry_started_at = Utc::now().timestamp();
                let deferred_until =
                    retry_started_at.saturating_add(PENDING_RETRY_LOOKUP_BACKOFF_SECONDS);
                (err, retry_started_at, deferred_until)
            });
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err((err, retry_started_at, deferred_until)) => {
                self.defer_pending_review_rate_limit_retry(
                    pending,
                    &head_sha,
                    retry_started_at,
                    deferred_until,
                )
                .await?;
                return Err(err);
            }
        };
        if !matches!(
            outcome,
            ReviewScheduleOutcome::SkippedRateLimit
                | ReviewScheduleOutcome::Interrupted
                | ReviewScheduleOutcome::SkippedQuota
        ) && self
            .state
            .review_rate_limit
            .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
            .await?
        {
            self.remove_pending_awards_after_clear(pending.lane, &pending.repo, pending.iid)
                .await;
        }
        Ok(outcome)
    }

    async fn remove_pending_awards_after_clear(&self, lane: ReviewLane, repo: &str, iid: u64) {
        if !self.review_flow_for_lane(lane).uses_awards() || self.config.review.dry_run {
            return;
        }
        if let Err(err) = self
            .award_service
            .remove_award(repo, iid, &self.config.review.rate_limit_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                lane = lane.as_str(),
                error = %err,
                "failed to remove rate-limit award after pending state cleared"
            );
        }
        if let Err(err) = self
            .award_service
            .remove_award(repo, iid, &self.config.review.quota_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                lane = lane.as_str(),
                error = %err,
                "failed to remove quota award after pending state cleared"
            );
        }
    }

    async fn remove_mention_quota_award_after_pending_clear(
        &self,
        pending: &MentionQuotaPendingEntry,
    ) {
        if self.config.review.dry_run {
            return;
        }
        if let Err(err) = self
            .award_service
            .remove_discussion_note_award(
                &pending.repo,
                pending.iid,
                &pending.discussion_id,
                pending.trigger_note_id,
                &self.config.review.quota_emoji,
            )
            .await
        {
            warn!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                discussion_id = pending.discussion_id.as_str(),
                trigger_note_id = pending.trigger_note_id,
                error = %err,
                "failed to remove mention quota award after pending state cleared"
            );
        }
    }

    pub(super) async fn remove_rate_limit_awards_for_closed_pending_mrs(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        let open_iids_set = open_iids.iter().copied().collect::<HashSet<_>>();
        let pending_to_clear = self
            .state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .into_iter()
            .filter(|pending| pending.repo == repo && !open_iids_set.contains(&pending.iid))
            .collect::<Vec<_>>();
        if pending_to_clear.is_empty() {
            return Ok(());
        }
        self.state
            .review_rate_limit
            .sync_review_rate_limit_pending_rows(repo, open_iids)
            .await?;
        for pending in pending_to_clear {
            self.remove_pending_awards_after_clear(
                pending.lane,
                pending.repo.as_str(),
                pending.iid,
            )
            .await;
        }
        Ok(())
    }

    pub(super) async fn clear_mention_quota_pending_for_closed_mrs(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        let deleted = self
            .state
            .mention_quota_pending
            .sync_mention_quota_pending_rows(repo, open_iids)
            .await?;
        for pending in &deleted {
            self.remove_mention_quota_award_after_pending_clear(pending)
                .await;
        }
        Ok(())
    }

    async fn scan(&self, mode: ScanMode) -> Result<ScanRunStatus> {
        run_scan_pipeline(self, mode).await
    }

    pub(super) async fn load_latest_mr_activity_marker(&self, repo: &str) -> Option<String> {
        match self.gitlab.get_latest_open_mr_activity(repo).await {
            Ok(Some(mr)) => {
                if let Some(updated_at) = mr.updated_at {
                    Some(format!("{}|{}", updated_at.to_rfc3339(), mr.iid))
                } else {
                    warn!(
                        repo = repo,
                        iid = mr.iid,
                        "latest MR missing updated_at; scanning"
                    );
                    None
                }
            }
            Ok(None) => Some(NO_OPEN_MRS_MARKER.to_string()),
            Err(err) => {
                warn!(
                    repo = repo,
                    error = %format!("{err:#}"),
                    "failed to load latest MR activity; scanning"
                );
                None
            }
        }
    }

    pub(super) async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>> {
        self.target_resolver.resolve_repos(mode).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn review_mr(&self, repo: &str, iid: u64) -> Result<()> {
        if self.shutdown_requested() {
            info!(repo = repo, iid = iid, "skip: shutdown requested");
            return Ok(());
        }
        self.clear_stale_flow_state().await?;
        let mut mr = self.gitlab.get_mr(repo, iid).await?;
        let mut head_sha = if let Some(value) = mr.head_sha() {
            value
        } else {
            warn!(repo = repo, iid = iid, "missing head sha, skipping");
            return Ok(());
        };
        let mut mention_tasks = Vec::new();
        let mention_outcome = self
            .schedule_mention_commands_for_mr(repo, &mr, &head_sha, &mut mention_tasks)
            .await?;
        let _ = join_all(mention_tasks).await;
        if mention_outcome.blocks_review && mention_outcome.scheduled == 0 {
            debug!(
                repo = repo,
                iid = iid,
                "skip review scheduling in this request: same-MR mention work is already in progress"
            );
            return Ok(());
        }
        if mention_outcome.scheduled > 0 {
            mr = self.gitlab.get_mr(repo, iid).await?;
            head_sha = if let Some(value) = mr.head_sha() {
                value
            } else {
                warn!(
                    repo = repo,
                    iid = iid,
                    "missing head sha after mention commands, skipping review"
                );
                return Ok(());
            };
        }
        let created_at = if let Some(value) = mr.created_at.as_ref() {
            value
        } else {
            warn!(repo = repo, iid = iid, "missing created_at, skipping");
            return Ok(());
        };
        if created_at <= &self.created_after {
            debug!(
                repo = repo,
                iid = iid,
                created_at = %created_at,
                cutoff = %self.created_after,
                "skip: MR created before cutoff"
            );
            return Ok(());
        }
        let _ = self
            .general_review_flow
            .run_for_mr(repo, mr.clone(), &head_sha)
            .await?;
        let _ = self
            .security_review_flow
            .run_for_mr(repo, mr, &head_sha)
            .await?;
        Ok(())
    }
}

fn should_clear_pending_retry_after_mr_lookup_error(err: &anyhow::Error) -> bool {
    gitlab_error_has_status(err, &[404]) || format!("{err:#}").contains(MR_NOT_FOUND_ERROR)
}

#[cfg(test)]
mod pending_rate_limit_tests {
    use super::*;
    use crate::codex_runner::{
        CodexResult, MentionCommandContext, MentionCommandResult, MentionCommandStatus,
        ReviewContext,
    };
    use crate::config::test_builder::ConfigBuilder;
    use crate::gitlab::GitLabUser;
    use anyhow::{Result, anyhow};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    type DiscussionNoteAwardKey = (String, u64, String, u64);
    type DiscussionNoteAwardMap = HashMap<DiscussionNoteAwardKey, Vec<crate::gitlab::AwardEmoji>>;

    struct TestGitLab {
        bot_user: GitLabUser,
        open_mrs: Mutex<Vec<MergeRequest>>,
        mrs_by_iid: Mutex<HashMap<u64, MergeRequest>>,
        discussions: Mutex<HashMap<(String, u64), Vec<crate::gitlab::MergeRequestDiscussion>>>,
        users: Mutex<HashMap<u64, crate::gitlab::GitLabUserDetail>>,
        awards: Mutex<HashMap<(String, u64), Vec<crate::gitlab::AwardEmoji>>>,
        discussion_note_awards: Mutex<DiscussionNoteAwardMap>,
        calls: Mutex<Vec<String>>,
        mr_lookup_error: Mutex<Option<String>>,
        list_open_calls: Mutex<u32>,
    }

    impl TestGitLab {
        fn new(open_mrs: Vec<MergeRequest>) -> Self {
            let mrs_by_iid = open_mrs.iter().map(|mr| (mr.iid, mr.clone())).collect();
            Self {
                bot_user: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
                open_mrs: Mutex::new(open_mrs),
                mrs_by_iid: Mutex::new(mrs_by_iid),
                discussions: Mutex::new(HashMap::new()),
                users: Mutex::new(HashMap::new()),
                awards: Mutex::new(HashMap::new()),
                discussion_note_awards: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                mr_lookup_error: Mutex::new(None),
                list_open_calls: Mutex::new(0),
            }
        }

        fn insert_mr(&self, mr: MergeRequest) {
            self.mrs_by_iid.lock().unwrap().insert(mr.iid, mr);
        }

        fn insert_discussions(
            &self,
            repo: &str,
            iid: u64,
            discussions: Vec<crate::gitlab::MergeRequestDiscussion>,
        ) {
            self.discussions
                .lock()
                .unwrap()
                .insert((repo.to_string(), iid), discussions);
        }

        fn insert_user(&self, user: crate::gitlab::GitLabUserDetail) {
            self.users.lock().unwrap().insert(user.id, user);
        }

        fn fail_mr_lookup(&self, message: &str) {
            *self.mr_lookup_error.lock().unwrap() = Some(message.to_string());
        }
    }

    #[async_trait]
    impl GitLabApi for TestGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            Ok(self.bot_user.clone())
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_group_projects(
            &self,
            _group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
            *self.list_open_calls.lock().unwrap() += 1;
            Ok(self.open_mrs.lock().unwrap().clone())
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<MergeRequest>> {
            Ok(self
                .open_mrs
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .max_by_key(|mr| mr.updated_at.or(mr.created_at)))
        }

        async fn get_mr(&self, _project: &str, iid: u64) -> Result<MergeRequest> {
            if let Some(message) = self.mr_lookup_error.lock().unwrap().clone() {
                return Err(anyhow!(message));
            }
            self.mrs_by_iid
                .lock()
                .unwrap()
                .get(&iid)
                .cloned()
                .ok_or_else(|| anyhow!(MR_NOT_FOUND_ERROR))
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            Ok(crate::gitlab::GitLabProject {
                path_with_namespace: Some(project.to_string()),
                web_url: None,
                default_branch: None,
                last_activity_at: None,
            })
        }

        async fn list_awards(
            &self,
            project: &str,
            iid: u64,
        ) -> Result<Vec<crate::gitlab::AwardEmoji>> {
            Ok(self
                .awards
                .lock()
                .unwrap()
                .get(&(project.to_string(), iid))
                .cloned()
                .unwrap_or_default())
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("add_award:{project}:{iid}:{name}"));
            Ok(())
        }

        async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_award:{project}:{iid}:{award_id}"));
            Ok(())
        }

        async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<crate::gitlab::Note>> {
            Ok(Vec::new())
        }

        async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
            Ok(())
        }

        async fn list_discussions(
            &self,
            project: &str,
            iid: u64,
        ) -> Result<Vec<crate::gitlab::MergeRequestDiscussion>> {
            Ok(self
                .discussions
                .lock()
                .unwrap()
                .get(&(project.to_string(), iid))
                .cloned()
                .unwrap_or_default())
        }

        async fn create_discussion_note(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            _body: &str,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(format!(
                "create_discussion_note:{project}:{iid}:{discussion_id}"
            ));
            Ok(())
        }

        async fn list_discussion_note_awards(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
        ) -> Result<Vec<crate::gitlab::AwardEmoji>> {
            Ok(self
                .discussion_note_awards
                .lock()
                .unwrap()
                .get(&(project.to_string(), iid, discussion_id.to_string(), note_id))
                .cloned()
                .unwrap_or_default())
        }

        async fn add_discussion_note_award(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
            name: &str,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(format!(
                "add_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:{name}"
            ));
            Ok(())
        }

        async fn delete_discussion_note_award(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
            award_id: u64,
        ) -> Result<()> {
            self.calls.lock().unwrap().push(format!(
                "delete_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:{award_id}"
            ));
            Ok(())
        }

        async fn get_user(&self, user_id: u64) -> Result<crate::gitlab::GitLabUserDetail> {
            self.users
                .lock()
                .unwrap()
                .get(&user_id)
                .cloned()
                .ok_or_else(|| anyhow!("user not found"))
        }
    }

    #[derive(Default)]
    struct CapturingRunner {
        review_contexts: Mutex<Vec<ReviewContext>>,
        mention_contexts: Mutex<Vec<MentionCommandContext>>,
    }

    #[async_trait]
    impl crate::codex_runner::CodexRunner for CapturingRunner {
        async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
            self.review_contexts.lock().unwrap().push(ctx);
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }

        async fn run_mention_command(
            &self,
            ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            self.mention_contexts.lock().unwrap().push(ctx);
            Ok(MentionCommandResult {
                status: MentionCommandStatus::NoChanges,
                commit_sha: None,
                reply_message: "No changes needed.".to_string(),
            })
        }
    }

    fn test_config() -> crate::config::Config {
        ConfigBuilder::for_review_service_tests().build()
    }

    fn mention_test_config() -> crate::config::Config {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        config.review.quota_emoji = "fuelpump".to_string();
        config
    }

    fn test_mr(iid: u64, sha: &str, updated_at: chrono::DateTime<Utc>) -> MergeRequest {
        MergeRequest {
            iid,
            title: None,
            web_url: None,
            draft: false,
            created_at: Some(updated_at),
            updated_at: Some(updated_at),
            sha: Some(sha.to_string()),
            source_branch: None,
            target_branch: None,
            author: None,
            source_project_id: Some(1),
            target_project_id: Some(1),
            diff_refs: None,
        }
    }

    fn mention_discussion(
        discussion_id: &str,
        trigger_note_id: u64,
    ) -> crate::gitlab::MergeRequestDiscussion {
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        crate::gitlab::MergeRequestDiscussion {
            id: discussion_id.to_string(),
            notes: vec![
                crate::gitlab::DiscussionNote {
                    id: trigger_note_id - 1,
                    body: "parent".to_string(),
                    author: bot_user,
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                },
                crate::gitlab::DiscussionNote {
                    id: trigger_note_id,
                    body: "@botuser please fix".to_string(),
                    author: requester,
                    system: false,
                    in_reply_to_id: Some(trigger_note_id - 1),
                    created_at: None,
                },
            ],
        }
    }

    #[tokio::test]
    async fn incremental_scan_retries_due_pending_reviews_even_when_repo_is_unchanged() -> Result<()>
    {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .project_catalog
            .set_project_last_mr_activity("group/repo", "2025-01-02T00:00:00Z|77")
            .await?;
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                77,
                "sha-old",
                0,
                0,
            )
            .await?;
        let service = ReviewService::new(
            test_config(),
            gitlab.clone(),
            state.clone(),
            Arc::new(CapturingRunner::default()),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 1);
        assert!(
            state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn incremental_scan_wakes_for_due_mention_quota_pending_rows() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .project_catalog
            .set_project_last_mr_activity("group/repo", "2025-01-02T00:00:00Z|77")
            .await?;
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid: 77,
                discussion_id: "discussion-77",
                trigger_note_id: 977,
                head_sha: "sha77",
                blocked_at: 0,
                next_retry_at: 0,
            })
            .await?;
        let service = ReviewService::new(
            mention_test_config(),
            gitlab.clone(),
            state,
            Arc::new(CapturingRunner::default()),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn next_pending_retry_at_includes_mention_quota_rows() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                78,
                "sha78",
                0,
                500,
            )
            .await?;
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid: 79,
                discussion_id: "discussion-79",
                trigger_note_id: 979,
                head_sha: "sha79",
                blocked_at: 0,
                next_retry_at: 300,
            })
            .await?;
        let service = ReviewService::new(
            mention_test_config(),
            gitlab,
            state,
            Arc::new(CapturingRunner::default()),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        assert_eq!(
            service.next_pending_rate_limit_retry_at().await?,
            Utc.timestamp_opt(300, 0).single()
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_rate_limit_pipeline_retries_due_mention_quota_rows() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.insert_mr(test_mr(
            80,
            "sha80-new",
            Utc.with_ymd_and_hms(2025, 1, 2, 0, 5, 0).unwrap(),
        ));
        gitlab.insert_discussions(
            "group/repo",
            80,
            vec![mention_discussion("discussion-80", 980)],
        );
        gitlab.insert_user(crate::gitlab::GitLabUserDetail {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
            public_email: Some("alice@example.com".to_string()),
        });
        gitlab.discussion_note_awards.lock().unwrap().insert(
            (
                "group/repo".to_string(),
                80,
                "discussion-80".to_string(),
                980,
            ),
            vec![crate::gitlab::AwardEmoji {
                id: 9800,
                name: "fuelpump".to_string(),
                user: gitlab.bot_user.clone(),
            }],
        );
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid: 80,
                discussion_id: "discussion-80",
                trigger_note_id: 980,
                head_sha: "sha80-old",
                blocked_at: 100,
                next_retry_at: 0,
            })
            .await?;
        let runner = Arc::new(CapturingRunner::default());
        let service = ReviewService::new(
            mention_test_config(),
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.process_due_pending_rate_limit_reviews().await?;

        {
            let mention_contexts = runner.mention_contexts.lock().unwrap();
            assert_eq!(mention_contexts.len(), 1);
            assert_eq!(mention_contexts[0].head_sha, "sha80-new");
            assert_eq!(mention_contexts[0].discussion_id, "discussion-80");
            assert_eq!(mention_contexts[0].trigger_note_id, 980);
        }
        assert!(
            state
                .mention_quota_pending
                .list_mention_quota_pending()
                .await?
                .is_empty()
        );
        assert!(gitlab.calls.lock().unwrap().iter().any(|call| {
            call == "delete_discussion_note_award:group/repo:80:discussion-80:980:9800"
        }));
        Ok(())
    }

    #[tokio::test]
    async fn pending_mention_quota_retry_preserves_row_when_same_mr_work_is_active() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.insert_mr(test_mr(
            81,
            "sha81-new",
            Utc.with_ymd_and_hms(2025, 1, 2, 0, 5, 0).unwrap(),
        ));
        gitlab.insert_discussions(
            "group/repo",
            81,
            vec![mention_discussion("discussion-81", 981)],
        );
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .mention_commands
            .begin_mention_command("group/repo", 81, "other-discussion", 1981, "sha81-new")
            .await?;
        state
            .mention_quota_pending
            .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
                repo: "group/repo",
                iid: 81,
                discussion_id: "discussion-81",
                trigger_note_id: 981,
                head_sha: "sha81-old",
                blocked_at: 100,
                next_retry_at: 0,
            })
            .await?;
        let runner = Arc::new(CapturingRunner::default());
        let service = ReviewService::new(
            mention_test_config(),
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.process_due_pending_rate_limit_reviews().await?;

        assert!(runner.mention_contexts.lock().unwrap().is_empty());
        let pending = state
            .mention_quota_pending
            .list_mention_quota_pending()
            .await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].iid, 81);
        assert_eq!(pending[0].discussion_id, "discussion-81");
        assert_eq!(pending[0].trigger_note_id, 981);
        Ok(())
    }

    #[tokio::test]
    async fn pending_rate_limit_wake_retries_only_the_blocked_lane_with_latest_head() -> Result<()>
    {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.insert_mr(test_mr(
            82,
            "sha82-new",
            Utc.with_ymd_and_hms(2025, 1, 2, 0, 5, 0).unwrap(),
        ));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                82,
                "sha82-old",
                100,
                0,
            )
            .await?;
        let runner = Arc::new(CapturingRunner::default());
        let service = ReviewService::new(
            test_config(),
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.process_due_pending_rate_limit_reviews().await?;

        {
            let review_contexts = runner.review_contexts.lock().unwrap();
            assert_eq!(review_contexts.len(), 1);
            assert_eq!(review_contexts[0].lane, ReviewLane::General);
            assert_eq!(review_contexts[0].head_sha, "sha82-new");
        }
        assert!(
            state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_rate_limit_wake_clears_rows_when_mr_lookup_reports_missing() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.awards.lock().unwrap().insert(
            ("group/repo".to_string(), 91),
            vec![crate::gitlab::AwardEmoji {
                id: 910,
                name: "hourglass_flowing_sand".to_string(),
                user: gitlab.bot_user.clone(),
            }],
        );
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                91,
                "sha91-old",
                100,
                0,
            )
            .await?;
        let runner = Arc::new(CapturingRunner::default());
        let service = ReviewService::new(
            test_config(),
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.process_due_pending_rate_limit_reviews().await?;

        assert!(runner.review_contexts.lock().unwrap().is_empty());
        assert!(
            state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?
                .is_empty()
        );
        assert!(
            gitlab
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call == "delete_award:group/repo:91:910")
        );
        Ok(())
    }

    #[tokio::test]
    async fn pending_rate_limit_wake_defers_rows_when_mr_lookup_is_transient() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.fail_mr_lookup("request failed: status=500 Internal Server Error");
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                92,
                "sha92-old",
                100,
                0,
            )
            .await?;
        let runner = Arc::new(CapturingRunner::default());
        let service = ReviewService::new(
            test_config(),
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        service.process_due_pending_rate_limit_reviews().await?;

        assert!(runner.review_contexts.lock().unwrap().is_empty());
        let pending = state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].iid, 92);
        assert!(pending[0].next_retry_at > 0);
        Ok(())
    }

    #[tokio::test]
    async fn pending_rate_limit_wake_defers_rows_when_review_start_errors() -> Result<()> {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        gitlab.insert_mr(test_mr(
            93,
            "sha93-new",
            Utc.with_ymd_and_hms(2025, 1, 2, 0, 5, 0).unwrap(),
        ));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                ReviewLane::General,
                "group/repo",
                93,
                "sha93-old",
                100,
                0,
            )
            .await?;
        sqlx::query(
            "INSERT INTO service_state (key, value) VALUES ('feature_flag_overrides', '{')",
        )
        .execute(state.pool())
        .await?;
        let service = ReviewService::new(
            test_config(),
            gitlab,
            state.clone(),
            Arc::new(CapturingRunner::default()),
            1,
            Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0).unwrap(),
        );

        let err = service
            .process_due_pending_rate_limit_reviews()
            .await
            .expect_err("pending retry should surface setup failure");
        assert!(
            err.to_string()
                .contains("deserialize feature flag overrides")
        );
        let pending = state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].iid, 93);
        assert_eq!(pending[0].last_seen_head_sha, "sha93-new");
        assert!(pending[0].next_retry_at > 0);
        Ok(())
    }
}

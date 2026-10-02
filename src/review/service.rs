use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::admission::AdmissionHistory;
use crate::flow::award_service::AwardService;
use crate::flow::mention::MentionFlow;
use crate::flow::retry::{
    RetryBackoff, RetryKey, RetryWarningAwardService, RunRetryStatus, RunRetryStatusProvider,
};
use crate::flow::review::{
    QueuedReview, ReviewEligibility, ReviewFlow, merge_request_lookup_reports_missing,
    review_skip_reason,
};
use crate::flow::run_queue::{
    EnqueueOutcome, JobKey, QueuedRun, QueuedRunsProvider, RunJob, RunQueue,
};
use crate::flow::{ActiveTaskRegistry, FlowJob, FlowShared, RescanRequests};
use crate::gitlab::{GitLabApi, gitlab_error_has_status};
use crate::lifecycle::ServiceLifecycle;
use crate::review::scan_coordinator::ScanCoordinator;
use crate::review::scan_pipeline::{run_pending_retry_pipeline, run_scan_pipeline};
use crate::review::target_resolver::TargetResolver;
use crate::review_lane::ReviewLane;
use crate::state::{MentionQuotaPendingEntry, ReviewRateLimitPendingEntry, ReviewStateStore};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, info, warn};

pub(super) const NO_OPEN_MRS_MARKER: &str = "__no_open_mrs__";
const PENDING_RETRY_LOOKUP_BACKOFF_SECONDS: i64 = 60;
const REVIEW_FAILURE_RETRY_BASE_DELAY: Duration = Duration::minutes(15);
const REVIEW_FAILURE_MAX_RETRIES: u32 = 5;

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
    pub(super) mention_flow: Arc<MentionFlow>,
    lifecycle: Arc<ServiceLifecycle>,
    run_queue: Arc<RunQueue<FlowJob>>,
    pub(super) rescan_requests: Arc<RescanRequests>,
    retry_backoff: Arc<RetryBackoff>,
    retry_warning_awards: RetryWarningAwardService,
    scan_coordinator: ScanCoordinator,
    target_resolver: TargetResolver,
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
        let retry_backoff = Arc::new(RetryBackoff::new(
            REVIEW_FAILURE_RETRY_BASE_DELAY,
            REVIEW_FAILURE_MAX_RETRIES,
        ));
        let lifecycle = Arc::new(ServiceLifecycle::default());
        let active_tasks = Arc::new(ActiveTaskRegistry::default());
        let rescan_requests = Arc::new(RescanRequests::default());
        let award_service = AwardService::new(Arc::clone(&gitlab), bot_user_id);
        let retry_warning_awards =
            RetryWarningAwardService::new(config.clone(), award_service.clone());
        let flow_shared = FlowShared {
            config: config.clone(),
            gitlab: Arc::clone(&gitlab),
            award_service: award_service.clone(),
            state: Arc::clone(&state),
            codex: Arc::clone(&codex),
            bot_user_id,
            created_after,
            lifecycle: Arc::clone(&lifecycle),
            active_tasks: Arc::clone(&active_tasks),
            rescan_requests: Arc::clone(&rescan_requests),
        };
        let mention_flow = Arc::new(MentionFlow::new(flow_shared.clone()));
        let general_review_flow = Arc::new(ReviewFlow::new(
            flow_shared.clone(),
            Arc::clone(&retry_backoff),
            ReviewLane::General,
        ));
        let security_review_flow = Arc::new(ReviewFlow::new(
            flow_shared,
            Arc::clone(&retry_backoff),
            ReviewLane::Security,
        ));
        let run_queue = RunQueue::new(
            config.review.max_concurrent,
            flow_job_runner(&general_review_flow, &security_review_flow, &mention_flow),
        );
        let scan_coordinator = ScanCoordinator::new(
            Arc::clone(&state),
            Arc::clone(&active_tasks),
            Arc::clone(&codex),
            Arc::clone(&general_review_flow),
            Arc::clone(&security_review_flow),
            Arc::clone(&mention_flow),
        );
        let target_resolver =
            TargetResolver::new(config.clone(), Arc::clone(&gitlab), Arc::clone(&state));
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
            run_queue,
            rescan_requests,
            retry_backoff,
            retry_warning_awards,
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

    /// Scans all repositories, queues the needed runs, and waits until the queue is empty.
    /// Waits also when a repository scan fails, so started runs finish before the error returns.
    ///
    /// # Errors
    ///
    /// Returns the first repository scan error.
    pub async fn scan_once(&self) -> Result<ScanRunStatus> {
        let result = run_scan_pipeline(self, ScanMode::Full).await;
        self.run_queue.wait_for_idle().await;
        result
    }

    /// Scans all repositories and queues the needed runs. Does not wait for the runs.
    ///
    /// # Errors
    ///
    /// Returns the first repository scan error.
    pub async fn queue_full_scan(&self) -> Result<ScanRunStatus> {
        run_scan_pipeline(self, ScanMode::Full).await
    }

    /// Scans repositories with new MR activity or due retries and queues the needed runs.
    /// Does not wait for the runs.
    ///
    /// # Errors
    ///
    /// Returns the first repository scan error.
    pub async fn scan_once_incremental(&self) -> Result<ScanRunStatus> {
        run_scan_pipeline(self, ScanMode::Incremental).await
    }

    /// Waits until no run waits in the queue and no run is active.
    pub async fn wait_for_idle(&self) {
        self.run_queue.wait_for_idle().await;
    }

    /// Returns when a run finished after the previous call returned. Runs change retry and
    /// pending times, so the scheduler computes its next wake again.
    pub(crate) async fn wait_for_run_finished(&self) {
        self.run_queue.wait_for_job_finished().await;
    }

    pub(crate) fn next_review_backoff_retry_at(&self) -> Option<DateTime<Utc>> {
        self.retry_backoff.earliest_retry_at(|key| {
            self.run_queue.contains(&JobKey::Review {
                lane: key.lane,
                repo: key.repo.clone(),
                iid: key.iid,
            })
        })
    }

    pub(super) fn repo_has_due_review_backoff_retry(&self, repo: &str, now: DateTime<Utc>) -> bool {
        self.retry_backoff.repo_has_due_retry(repo, now)
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

    /// Queues the reviews and mention commands whose pending rows are due.
    /// Does not wait for the runs.
    ///
    /// # Errors
    ///
    /// Returns the first error after all due rows were handled.
    pub async fn queue_due_pending_retries(&self) -> Result<ScanRunStatus> {
        run_pending_retry_pipeline(self).await
    }

    /// Scans repositories with due review retries and queues the reviews.
    /// Does not wait for the runs.
    ///
    /// # Errors
    ///
    /// Returns the first repository scan error.
    pub async fn queue_due_review_backoff_retries(&self) -> Result<ScanRunStatus> {
        run_scan_pipeline(self, ScanMode::Incremental).await
    }

    pub(super) async fn clear_review_backoff_retries_for_closed_mrs(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) {
        let removed = self
            .retry_backoff
            .clear_for_repo_iids_not_in(repo, open_iids);
        self.remove_retry_warning_awards_for_removed_keys(removed)
            .await;
    }

    /// Removes retries and their warning awards outside the resolved targets.
    pub(super) async fn clear_review_backoff_retries_outside_targets(&self, repos: &[String]) {
        let removed = self.retry_backoff.clear_for_repos_not_in(repos);
        self.remove_retry_warning_awards_for_removed_keys(removed)
            .await;
    }

    pub(super) async fn clear_stale_review_backoff_retries_for_mr(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
    ) {
        let mut removed =
            self.retry_backoff
                .clear_for_mr_other_heads(ReviewLane::General, repo, iid, head_sha);
        removed.extend(self.retry_backoff.clear_for_mr_other_heads(
            ReviewLane::Security,
            repo,
            iid,
            head_sha,
        ));
        self.remove_retry_warning_awards_for_removed_keys(removed)
            .await;
    }

    pub(super) async fn clear_review_backoff_retries_for_mr(&self, repo: &str, iid: u64) {
        let removed = self.retry_backoff.clear_for_mr(repo, iid);
        self.remove_retry_warning_awards_for_removed_keys(removed)
            .await;
    }

    /// Queues due pending rows, then waits until the queue is empty.
    #[cfg(test)]
    pub(super) async fn process_due_pending_retries(&self) -> Result<ScanRunStatus> {
        let result = self.queue_due_pending_retries().await;
        self.wait_for_idle().await;
        result
    }

    /// Queues one explicit review of the MR's current head, then waits until the queue is empty.
    #[cfg(test)]
    pub(super) async fn review_lane_now(&self, lane: ReviewLane, repo: &str, iid: u64) {
        self.enqueue(FlowJob::Review(QueuedReview {
            lane,
            repo: repo.to_string(),
            iid,
            head_sha: String::new(),
            eligibility: ReviewEligibility::Explicit,
        }));
        self.wait_for_idle().await;
    }

    #[cfg(test)]
    pub(super) fn defer_review_backoff_retries_for_mr(
        &self,
        repo: &str,
        iid: u64,
        now: DateTime<Utc>,
        next_retry_at: DateTime<Utc>,
    ) -> usize {
        self.retry_backoff
            .defer_due_for_mr(repo, iid, now, next_retry_at)
    }

    #[cfg(test)]
    pub(super) fn has_active_review_backoff_retry_for_mr(&self, repo: &str, iid: u64) -> bool {
        self.retry_backoff.has_active_retry_for_mr(repo, iid)
    }

    async fn remove_retry_warning_awards_for_removed_keys(&self, removed: Vec<RetryKey>) {
        let mut removed_mrs = HashSet::new();
        for key in removed {
            removed_mrs.insert((key.repo, key.iid));
        }
        for (repo, iid) in removed_mrs {
            self.retry_warning_awards
                .remove_if_no_active_retry(self.retry_backoff.as_ref(), &repo, iid)
                .await;
        }
    }

    /// Stops new runs, drops waiting runs, and asks running runs to cancel.
    pub fn request_shutdown(&self) {
        self.lifecycle.request_fast_stop();
        self.run_queue.close();
    }

    /// Stops new runs and drops waiting runs. Running runs finish.
    pub fn request_graceful_drain(&self) {
        self.lifecycle.request_graceful_drain();
        self.run_queue.close();
    }

    pub async fn wait_for_started_runs(&self) {
        self.lifecycle.wait_for_started_runs().await;
    }

    /// Waits until no queued job runs, including jobs that have not reached their codex run.
    pub async fn wait_for_active_tasks(&self) {
        self.run_queue.wait_for_running().await;
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

    /// Adds a job to the run queue. Returns `false` when shutdown closed the queue.
    pub(super) fn enqueue(&self, job: FlowJob) -> bool {
        self.run_queue.enqueue(job) != EnqueueOutcome::Closed
    }

    pub(super) async fn clear_stale_flow_state(&self) -> Result<()> {
        self.scan_coordinator.clear_stale_flow_state().await
    }

    fn review_flow_for_lane(&self, lane: ReviewLane) -> &ReviewFlow {
        match lane {
            ReviewLane::General => self.general_review_flow.as_ref(),
            ReviewLane::Security => self.security_review_flow.as_ref(),
        }
    }

    /// Queues the mention command of a due pending row. Clears rows whose trigger is gone.
    pub(super) async fn queue_pending_mention_row(
        &self,
        pending: &MentionQuotaPendingEntry,
    ) -> Result<()> {
        debug!(
            repo = pending.repo.as_str(),
            iid = pending.iid,
            discussion_id = pending.discussion_id.as_str(),
            trigger_note_id = pending.trigger_note_id,
            next_retry_at = pending.next_retry_at,
            "queueing due pending mention quota row"
        );
        let mr = match self.gitlab.get_mr(&pending.repo, pending.iid).await {
            Ok(mr) => mr,
            Err(err) if merge_request_lookup_reports_missing(&err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    discussion_id = pending.discussion_id.as_str(),
                    trigger_note_id = pending.trigger_note_id,
                    error = %err,
                    "merge request lookup failed while retrying pending mention; clearing pending row"
                );
                return self.clear_pending_mention(pending).await;
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
                self.defer_pending_mention(pending).await?;
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
            return self.clear_pending_mention(pending).await;
        };
        let history = AdmissionHistory::new(self.gitlab.as_ref(), &pending.repo, pending.iid);
        let admission = match self
            .mention_flow
            .admit_for_scan(&pending.repo, &mr, &head_sha, &history)
            .await
        {
            Ok(admission) => admission,
            Err(err) => {
                self.defer_pending_mention(pending).await?;
                return Err(err);
            }
        };
        let pending_job_found = admission.jobs.iter().any(|job| {
            job.discussion_id() == pending.discussion_id
                && job.trigger_note_id() == pending.trigger_note_id
        });
        if pending_job_found {
            // The job clears or rewrites the row when it starts. Deferring first lets that write win.
            self.defer_pending_mention(pending).await?;
        }
        for job in admission.jobs {
            if !self.enqueue(FlowJob::Mention(Box::new(job))) {
                return Ok(());
            }
        }
        if pending_job_found || self.shutdown_requested() {
            return Ok(());
        }
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
                self.clear_pending_mention(pending).await?;
            }
            crate::state::MentionCommandScanState::InProgress => {
                self.defer_pending_mention(pending).await?;
            }
            crate::state::MentionCommandScanState::Ready => {
                // A quota block during admission wrote a later retry time. A row that is still
                // due has no trigger left: the note was deleted or no longer mentions the bot.
                let still_due = self
                    .state
                    .mention_quota_pending
                    .mention_quota_pending_is_due(
                        &pending.repo,
                        pending.iid,
                        &pending.discussion_id,
                        pending.trigger_note_id,
                        Utc::now().timestamp(),
                    )
                    .await?;
                if still_due {
                    self.clear_pending_mention(pending).await?;
                }
            }
        }
        Ok(())
    }

    async fn clear_pending_mention(&self, pending: &MentionQuotaPendingEntry) -> Result<()> {
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
        Ok(())
    }

    async fn defer_pending_mention(&self, pending: &MentionQuotaPendingEntry) -> Result<bool> {
        let next_retry_at = Utc::now()
            .timestamp()
            .saturating_add(PENDING_RETRY_LOOKUP_BACKOFF_SECONDS);
        self.state
            .mention_quota_pending
            .defer_mention_quota_pending_if_unchanged(pending, next_retry_at)
            .await
    }

    /// Queues the review of a due pending row. Clears rows that no longer need a review.
    pub(super) async fn queue_pending_review_row(
        &self,
        pending: &ReviewRateLimitPendingEntry,
        repos: &HashSet<String>,
    ) -> Result<()> {
        debug!(
            repo = pending.repo.as_str(),
            iid = pending.iid,
            lane = pending.lane.as_str(),
            next_retry_at = pending.next_retry_at,
            "queueing due pending review rate-limit row"
        );
        if !repos.contains(&pending.repo) {
            debug!(
                repo = pending.repo,
                iid = pending.iid,
                "clear pending review: repository is outside targets"
            );
            return self.clear_pending_review(pending).await;
        }
        let mr = match self.gitlab.get_mr(&pending.repo, pending.iid).await {
            Ok(mr) => mr,
            Err(err) if merge_request_lookup_reports_missing(&err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    lane = pending.lane.as_str(),
                    error = %err,
                    "merge request lookup failed while retrying pending review; clearing pending row"
                );
                return self.clear_pending_review(pending).await;
            }
            Err(err) => {
                warn!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    lane = pending.lane.as_str(),
                    error = %err,
                    "merge request lookup failed while retrying pending review; deferring retry"
                );
                self.defer_pending_review(pending).await?;
                return Ok(());
            }
        };
        if let Some(reason) = review_skip_reason(&mr, self.created_after) {
            debug!(
                repo = pending.repo,
                iid = pending.iid,
                ?reason,
                "clear pending review: MR is not eligible"
            );
            return self.clear_pending_review(pending).await;
        }
        let Some(head_sha) = mr.head_sha() else {
            warn!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                lane = pending.lane.as_str(),
                "missing head sha while retrying pending review; clearing pending row"
            );
            return self.clear_pending_review(pending).await;
        };
        // The job clears or rewrites the row when it starts. Deferring first lets that write win.
        // A failed defer means that another writer already changed the row.
        if !self.defer_pending_review(pending).await? {
            return Ok(());
        }
        self.enqueue(FlowJob::Review(QueuedReview {
            lane: pending.lane,
            repo: pending.repo.clone(),
            iid: pending.iid,
            head_sha,
            eligibility: ReviewEligibility::Automatic,
        }));
        Ok(())
    }

    async fn defer_pending_review(&self, pending: &ReviewRateLimitPendingEntry) -> Result<bool> {
        let next_retry_at = Utc::now()
            .timestamp()
            .saturating_add(PENDING_RETRY_LOOKUP_BACKOFF_SECONDS);
        self.state
            .review_rate_limit
            .defer_review_rate_limit_pending_if_unchanged(
                pending.lane,
                &pending.repo,
                pending.iid,
                pending.next_retry_at,
                next_retry_at,
            )
            .await
    }

    /// Clears the pending row, then attempts to remove its quota and rate-limit awards.
    async fn clear_pending_review(&self, pending: &ReviewRateLimitPendingEntry) -> Result<()> {
        if self
            .state
            .review_rate_limit
            .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
            .await?
        {
            self.remove_pending_awards_after_clear(pending.lane, &pending.repo, pending.iid)
                .await;
        }
        Ok(())
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
            .list_review_rate_limit_pending_for_repo(repo)
            .await?
            .into_iter()
            .filter(|pending| !open_iids_set.contains(&pending.iid))
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

    pub(super) async fn should_skip_inactive_project_after_mr_listing_error(
        &self,
        repo: &str,
        err: &anyhow::Error,
    ) -> bool {
        if !gitlab_error_has_status(err, &[403]) {
            return false;
        }

        match self.gitlab.get_project(repo).await {
            Ok(project) if !project.is_active() => {
                warn!(
                    repo = repo,
                    archived = project.archived,
                    marked_for_deletion_on = project.marked_for_deletion_on.as_deref(),
                    marked_for_deletion_at = project.marked_for_deletion_at.as_deref(),
                    "skip: project is inactive after forbidden MR listing"
                );
                true
            }
            Ok(_) => false,
            Err(project_err) => {
                warn!(
                    repo = repo,
                    error = %project_err,
                    "failed to load project after forbidden MR listing"
                );
                false
            }
        }
    }

    pub(super) async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>> {
        self.target_resolver.resolve_repos(mode).await
    }

    /// Queues the mention commands and both review lanes of one MR, then waits until the
    /// queue is empty. Reviews also drafts. MRs created before the cutoff get no review.
    ///
    /// # Errors
    ///
    /// Returns an error if the MR or its discussions cannot be loaded.
    pub async fn review_mr(&self, repo: &str, iid: u64) -> Result<()> {
        if self.shutdown_requested() {
            info!(repo = repo, iid = iid, "skip: shutdown requested");
            return Ok(());
        }
        self.clear_stale_flow_state().await?;
        let mr = self.gitlab.get_mr(repo, iid).await?;
        let Some(head_sha) = mr.head_sha() else {
            warn!(repo = repo, iid = iid, "missing head sha, skipping");
            return Ok(());
        };
        let history = AdmissionHistory::new(self.gitlab.as_ref(), repo, iid);
        let mentions = self
            .mention_flow
            .admit_for_scan(repo, &mr, &head_sha, &history)
            .await?;
        for job in mentions.jobs {
            self.enqueue(FlowJob::Mention(Box::new(job)));
        }
        match mr.created_at {
            None => warn!(
                repo = repo,
                iid = iid,
                "missing created_at, skipping review"
            ),
            Some(created_at) if created_at <= self.created_after => debug!(
                repo = repo,
                iid = iid,
                created_at = %created_at,
                cutoff = %self.created_after,
                "skip: MR created before cutoff"
            ),
            Some(_) => {
                for lane in [ReviewLane::General, ReviewLane::Security] {
                    self.enqueue(FlowJob::Review(QueuedReview {
                        lane,
                        repo: repo.to_string(),
                        iid,
                        head_sha: head_sha.clone(),
                        eligibility: ReviewEligibility::Explicit,
                    }));
                }
            }
        }
        self.wait_for_idle().await;
        Ok(())
    }
}

/// Starts each queued job in the flow that owns it.
fn flow_job_runner(
    general_review_flow: &Arc<ReviewFlow>,
    security_review_flow: &Arc<ReviewFlow>,
    mention_flow: &Arc<MentionFlow>,
) -> RunJob<FlowJob> {
    let general_review_flow = Arc::clone(general_review_flow);
    let security_review_flow = Arc::clone(security_review_flow);
    let mention_flow = Arc::clone(mention_flow);
    Arc::new(move |job, running_head| match job {
        FlowJob::Review(review) => {
            let flow = match review.lane {
                ReviewLane::General => Arc::clone(&general_review_flow),
                ReviewLane::Security => Arc::clone(&security_review_flow),
            };
            Box::pin(async move { flow.run_queued(review, running_head).await })
        }
        FlowJob::Mention(mention) => {
            let flow = Arc::clone(&mention_flow);
            Box::pin(async move { flow.run_queued(*mention).await })
        }
    })
}

impl RunRetryStatusProvider for ReviewService {
    fn retry_statuses_for_run_ids(&self, run_ids: &[i64]) -> HashMap<i64, RunRetryStatus> {
        self.retry_backoff.statuses_for_run_ids(run_ids, Utc::now())
    }
}

impl QueuedRunsProvider for ReviewService {
    fn queued_runs(&self) -> Vec<QueuedRun> {
        self.run_queue.queued_runs()
    }
}

#[cfg(test)]
mod pending_rate_limit_tests {
    use super::*;
    use crate::codex_runner::{
        CodexResult, MentionCommandContext, MentionCommandResult, MentionCommandStatus,
        ReviewContext,
    };
    use crate::config::test_builder::ConfigBuilder;
    use crate::gitlab::{GitLabUser, MergeRequest};
    use crate::state::MentionQuotaPendingUpsert;
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
                .ok_or_else(|| anyhow!("mr not found"))
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            Ok(crate::gitlab::GitLabProject {
                path_with_namespace: Some(project.to_string()),
                web_url: None,
                default_branch: None,
                last_activity_at: None,
                archived: false,
                marked_for_deletion_on: None,
                marked_for_deletion_at: None,
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
            state: Some("opened".to_string()),
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
            individual_note: false,
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

        service.process_due_pending_retries().await?;

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

        service.process_due_pending_retries().await?;

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

        service.process_due_pending_retries().await?;

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

        service.process_due_pending_retries().await?;

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
    async fn pending_review_start_error_keeps_the_row_deferred() -> Result<()> {
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

        service.process_due_pending_retries().await?;

        let pending = state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].iid, 93);
        assert!(
            pending[0].next_retry_at > Utc::now().timestamp(),
            "the row waits before the next attempt"
        );
        assert!(
            service.rescan_requests.pending("group/repo").is_some(),
            "the failed start must make the next scan read the repository"
        );
        Ok(())
    }
}

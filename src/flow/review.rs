use crate::codex_runner::{
    CodexQuotaExhausted, CodexResult, ReviewComment, ReviewContext, SecurityReviewContentFlagged,
};
use crate::config::Config;
use crate::config::FeatureFlagSnapshot;
use crate::flow::admission::AdmissionHistory;
use crate::flow::award_service::AwardService;
use crate::flow::orchestration::{
    ScheduledTaskContext, finish_task_run_history, refund_review_rate_limits,
    task_cancelled_finish, task_error_finish,
};
use crate::flow::retry::{
    REVIEW_RETRY_BLOCKED_DEFER_SECONDS, RetryBackoff, RetryGateStatus, RetryKey,
    RetryWarningAwardService,
};
use crate::flow::review_comments::{
    PostReviewCommentRequest, REVIEW_FINDING_MARKER_PREFIX, post_review_comment,
};
use crate::flow::review_project::{ResolvedReviewProject, resolve_review_project};
use crate::flow::run_queue::{JobKey, QueueJob, RunningHead};
use crate::flow::{ActiveReviewKey, FlowShared, MergeRequestFlow};
use crate::gitlab::{
    GitLabApi, MergeRequest, MergeRequestDiscussion, Note, gitlab_error_has_status,
};
use crate::lifecycle::ServiceLifecycle;
use crate::review_deduplication::ReviewDiscussionSource;
use crate::review_lane::ReviewLane;
use crate::state::{
    NewRunHistory, ReviewRateLimitAcquireOutcome, ReviewStateStore, RunHistoryFinish,
};
use anyhow::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// Error text of the fake GitLab clients in development mode and tests for a missing MR.
const MR_NOT_FOUND_ERROR: &str = "mr not found";

/// Decision for one lane of one MR, made by a scan or by a queued review when it starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewScheduleOutcome {
    Scheduled,
    Disabled,
    SkippedBackoff,
    SkippedRetryExhausted,
    SkippedQuota,
    SkippedMarker,
    SkippedCompleted,
    Interrupted,
}

impl ReviewScheduleOutcome {
    /// Reports whether a pending rate-limit row must stay for this decision.
    /// A quota block writes its own retry time, and an interrupted start retries later.
    const fn keeps_pending_retry(self) -> bool {
        matches!(self, Self::SkippedQuota | Self::Interrupted)
    }
}

/// Why automatic reviews ignore an MR.
#[derive(Debug)]
pub(crate) enum ReviewSkipReason {
    NotOpened,
    Draft,
    MissingCreatedAt,
    BeforeCutoff,
}

/// Requires an opened, non-draft MR with a creation time after the cutoff.
pub(crate) fn review_skip_reason(
    mr: &MergeRequest,
    created_after: DateTime<Utc>,
) -> Option<ReviewSkipReason> {
    if mr.state.as_deref() != Some("opened") {
        return Some(ReviewSkipReason::NotOpened);
    }
    if mr.draft {
        return Some(ReviewSkipReason::Draft);
    }
    let Some(created_at) = mr.created_at else {
        return Some(ReviewSkipReason::MissingCreatedAt);
    };
    if created_at <= created_after {
        return Some(ReviewSkipReason::BeforeCutoff);
    }
    None
}

/// Reports whether an MR lookup failed because the MR no longer exists.
pub(crate) fn merge_request_lookup_reports_missing(err: &anyhow::Error) -> bool {
    gitlab_error_has_status(err, &[404]) || format!("{err:#}").contains(MR_NOT_FOUND_ERROR)
}

/// MR states that a queued review still reviews when it starts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewEligibility {
    /// Opened, non-draft MRs created after the cutoff, as scans require.
    Automatic,
    /// Any MR that a caller asked to review. The caller checks the cutoff.
    Explicit,
}

/// Review that waits in the run queue. When it starts, it reviews the latest MR head.
#[derive(Clone, Debug)]
pub(crate) struct QueuedReview {
    pub(crate) lane: ReviewLane,
    pub(crate) repo: String,
    pub(crate) iid: u64,
    /// Head that the producer saw. Used only to recognize a running review of this head.
    pub(crate) head_sha: String,
    pub(crate) eligibility: ReviewEligibility,
}

impl QueueJob for QueuedReview {
    fn key(&self) -> JobKey {
        JobKey::Review {
            lane: self.lane,
            repo: self.repo.clone(),
            iid: self.iid,
        }
    }

    fn head_sha(&self) -> &str {
        &self.head_sha
    }

    fn mention_branch(&self) -> Option<&str> {
        None
    }
}

/// Scan result for one lane: a job to queue, or the reason why no review is needed.
pub(crate) enum ReviewAdmission {
    Queue(QueuedReview),
    Skip(ReviewScheduleOutcome),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReviewRunResult {
    Pass,
    DryRunPass,
    Comment,
    DryRunComment,
    Error,
    Flagged,
    Cancelled,
}

impl ReviewRunResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::DryRunPass => "dry_run_pass",
            Self::Comment => "comment",
            Self::DryRunComment => "dry_run_comment",
            Self::Error => "error",
            Self::Flagged => "flagged",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "pass" => Some(Self::Pass),
            "dry_run_pass" => Some(Self::DryRunPass),
            "comment" => Some(Self::Comment),
            "dry_run_comment" => Some(Self::DryRunComment),
            "error" => Some(Self::Error),
            "flagged" => Some(Self::Flagged),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub(crate) const fn is_completed_review(self) -> bool {
        matches!(self, Self::Pass | Self::Comment | Self::Flagged)
    }
}

enum ReviewGateOutcome {
    Ready(ReviewGateReady),
    Skip(ReviewScheduleOutcome),
    /// Another run holds the claim of this MR and lane. The retry gate is deferred.
    ClaimBusy,
    /// A rate limit blocks the review. The gate wrote a pending row.
    RateLimited,
}

struct ReviewGateReady {
    acquired_rule_ids: Vec<String>,
}

struct PreparedReviewRun {
    task: ScheduledTaskContext,
    feature_flags: FeatureFlagSnapshot,
}

/// Admits and schedules reviews for one lane.
pub(crate) struct ReviewFlow {
    shared: FlowShared,
    retry_backoff: Arc<RetryBackoff>,
    retry_warning_awards: RetryWarningAwardService,
    lane: ReviewLane,
}

impl ReviewFlow {
    /// Creates a flow whose behavior is determined entirely by its lane.
    pub(crate) fn new(
        shared: FlowShared,
        retry_backoff: Arc<RetryBackoff>,
        lane: ReviewLane,
    ) -> Self {
        let retry_warning_awards =
            RetryWarningAwardService::new(shared.config.clone(), shared.award_service.clone());
        Self {
            shared,
            retry_backoff,
            retry_warning_awards,
            lane,
        }
    }

    fn review_marker_prefix(&self) -> &str {
        self.lane.comment_marker_prefix(&self.shared.config)
    }

    fn finding_marker_prefix(&self) -> &str {
        self.lane.finding_marker_prefix(&self.shared.config)
    }

    /// Reports whether this lane publishes review awards.
    pub(crate) fn uses_awards(&self) -> bool {
        self.lane.uses_awards()
    }

    fn is_enabled(&self, feature_flags: &FeatureFlagSnapshot) -> bool {
        self.lane.is_enabled(feature_flags)
    }

    pub(crate) async fn clear_stale_in_progress(&self) -> Result<()> {
        self.shared
            .state
            .review_state
            .clear_stale_in_progress(self.shared.config.review.stale_in_progress_minutes)
            .await
    }

    pub(crate) async fn recover_in_progress(&self) -> Result<()> {
        let in_progress = self
            .shared
            .state
            .review_state
            .list_in_progress_reviews()
            .await?;
        if !in_progress.is_empty() {
            info!(
                count = in_progress.len(),
                "recovering interrupted in-progress reviews"
            );
            for review in in_progress {
                if review.lane != self.lane {
                    continue;
                }
                let retry_key = RetryKey::new(
                    review.lane,
                    review.repo.as_str(),
                    review.iid,
                    review.head_sha.as_str(),
                );
                if self.shared.config.review.dry_run || !self.uses_awards() {
                    info!(
                        repo = review.repo.as_str(),
                        iid = review.iid,
                        "dry run: skipping eyes removal during recovery"
                    );
                } else if let Err(err) = self
                    .shared
                    .award_service
                    .remove_award(
                        review.repo.as_str(),
                        review.iid,
                        &self.shared.config.review.eyes_emoji,
                    )
                    .await
                {
                    warn!(
                        repo = review.repo.as_str(),
                        iid = review.iid,
                        error = %err,
                        "failed to remove eyes award while recovering review"
                    );
                }
                self.retry_backoff.clear(&retry_key);
                if let Err(err) = self
                    .shared
                    .state
                    .review_state
                    .finish_review_for_lane(
                        review.repo.as_str(),
                        review.iid,
                        review.head_sha.as_str(),
                        review.lane,
                        ReviewRunResult::Cancelled.as_str(),
                    )
                    .await
                {
                    warn!(
                        repo = review.repo.as_str(),
                        iid = review.iid,
                        error = %err,
                        "failed to mark interrupted review as cancelled"
                    );
                }
            }
        }
        Ok(())
    }

    /// Checks whether this lane must review `head_sha`. Takes no claim and no rate-limit bucket.
    async fn review_skip_decision(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<Option<ReviewScheduleOutcome>> {
        let feature_flags = self.resolve_feature_flags().await?;
        if !self.is_enabled(&feature_flags) {
            let retry_key = RetryKey::new(self.lane, repo, mr.iid, head_sha);
            if !matches!(
                self.retry_gate_status(&retry_key),
                RetryGateStatus::Ready(None)
            ) {
                self.clear_retry_gate_for_terminal_skip(&retry_key, repo, mr.iid)
                    .await;
            }
            return Ok(Some(ReviewScheduleOutcome::Disabled));
        }
        self.find_skip_reason(repo, mr, head_sha, &feature_flags, history)
            .await
    }

    async fn evaluate_review_gate(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<ReviewGateOutcome> {
        if let Some(outcome) = self
            .review_skip_decision(repo, mr, head_sha, history)
            .await?
        {
            return Ok(ReviewGateOutcome::Skip(outcome));
        }
        self.acquire_review_slot(repo, mr, head_sha, Utc::now().timestamp())
            .await
    }

    async fn find_skip_reason(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        feature_flags: &FeatureFlagSnapshot,
        history: &AdmissionHistory<'_>,
    ) -> Result<Option<ReviewScheduleOutcome>> {
        let retry_key = RetryKey::new(self.lane, repo, mr.iid, head_sha);
        let retry_was_due = match self.retry_gate_status(&retry_key) {
            RetryGateStatus::Ready(state) => state.is_some(),
            RetryGateStatus::Pending(_) => return Ok(Some(ReviewScheduleOutcome::SkippedBackoff)),
            RetryGateStatus::Exhausted(_) => {
                return Ok(Some(ReviewScheduleOutcome::SkippedRetryExhausted));
            }
        };
        if self
            .skipped_by_completed_result(repo, mr.iid, head_sha)
            .await?
        {
            if retry_was_due {
                self.clear_retry_gate_for_terminal_skip(&retry_key, repo, mr.iid)
                    .await;
            }
            return Ok(Some(ReviewScheduleOutcome::SkippedCompleted));
        }
        if self.skipped_by_review_marker(history, head_sha).await? {
            if retry_was_due {
                self.clear_retry_gate_for_terminal_skip(&retry_key, repo, mr.iid)
                    .await;
            }
            return Ok(Some(ReviewScheduleOutcome::SkippedMarker));
        }
        if let Some(outcome) = self
            .skipped_by_inline_markers(repo, mr.iid, head_sha, feature_flags, history)
            .await?
        {
            if retry_was_due {
                self.clear_retry_gate_for_terminal_skip(&retry_key, repo, mr.iid)
                    .await;
            }
            return Ok(Some(outcome));
        }
        if self.skipped_by_codex_quota(repo, mr.iid, head_sha).await? {
            return Ok(Some(ReviewScheduleOutcome::SkippedQuota));
        }
        Ok(None)
    }

    fn retry_gate_status(&self, retry_key: &RetryKey) -> RetryGateStatus {
        self.retry_backoff.gate_status(retry_key, Utc::now())
    }

    fn defer_retry_gate(&self, repo: &str, iid: u64, head_sha: &str, next_retry_at: DateTime<Utc>) {
        let retry_key = RetryKey::new(self.lane, repo, iid, head_sha);
        if self.retry_backoff.defer_until(&retry_key, next_retry_at) {
            debug!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                retry_at = %next_retry_at,
                "deferred in-memory review retry gate"
            );
        }
    }

    async fn clear_retry_gate_for_terminal_skip(&self, retry_key: &RetryKey, repo: &str, iid: u64) {
        self.retry_backoff.clear(retry_key);
        self.retry_warning_awards
            .remove_if_no_active_retry(self.retry_backoff.as_ref(), repo, iid)
            .await
    }

    async fn skipped_by_codex_quota(&self, repo: &str, iid: u64, head_sha: &str) -> Result<bool> {
        let now = Utc::now();
        let Some(block) = self.shared.codex.quota_block(now).await? else {
            return Ok(false);
        };
        self.shared
            .state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                self.lane,
                repo,
                iid,
                head_sha,
                now.timestamp(),
                block.retry_at.timestamp(),
            )
            .await?;
        self.defer_retry_gate(repo, iid, head_sha, block.retry_at);
        self.ensure_quota_award_best_effort(repo, iid).await;
        Ok(true)
    }

    /// Skips a head whose stored result completes this lane's review. A stored pass always
    /// counts, because a pass publishes only the thumbs award, which names no head.
    async fn skipped_by_completed_result(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
    ) -> Result<bool> {
        let result = self
            .shared
            .state
            .review_state
            .review_result_for_lane(repo, iid, head_sha, self.lane)
            .await?;
        Ok(result
            .as_deref()
            .and_then(ReviewRunResult::parse)
            .is_some_and(|result| {
                result == ReviewRunResult::Pass
                    || (self.lane.skips_completed_review_result() && result.is_completed_review())
            }))
    }

    async fn skipped_by_review_marker(
        &self,
        history: &AdmissionHistory<'_>,
        head_sha: &str,
    ) -> Result<bool> {
        let notes = history.notes().await?;
        Ok(has_review_marker(
            notes,
            self.shared.bot_user_id,
            self.review_marker_prefix(),
            head_sha,
        ))
    }

    async fn skipped_by_inline_markers(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        feature_flags: &FeatureFlagSnapshot,
        history: &AdmissionHistory<'_>,
    ) -> Result<Option<ReviewScheduleOutcome>> {
        let completed_inline_review = self
            .shared
            .state
            .run_history
            .has_completed_inline_review_for_lane(repo, iid, head_sha, self.lane)
            .await?;
        let review_result = self
            .shared
            .state
            .review_state
            .review_result_for_lane(repo, iid, head_sha, self.lane)
            .await?;
        let parsed_review_result = review_result.as_deref().and_then(ReviewRunResult::parse);
        let should_check_inline_markers = feature_flags.gitlab_inline_review_comments
            || completed_inline_review
            || review_result.is_some();
        if !should_check_inline_markers {
            return Ok(None);
        }
        self.inline_marker_discussion_skip(
            repo,
            iid,
            head_sha,
            completed_inline_review,
            parsed_review_result,
            history,
        )
        .await
    }

    async fn inline_marker_discussion_skip(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        completed_inline_review: bool,
        parsed_review_result: Option<ReviewRunResult>,
        history: &AdmissionHistory<'_>,
    ) -> Result<Option<ReviewScheduleOutcome>> {
        match history.discussions().await {
            Ok(discussions) => {
                if has_inline_review_marker(
                    discussions,
                    self.shared.bot_user_id,
                    head_sha,
                    self.finding_marker_prefix(),
                ) && parsed_review_result != Some(ReviewRunResult::Error)
                    && (completed_inline_review
                        || parsed_review_result == Some(ReviewRunResult::Comment))
                {
                    return Ok(Some(ReviewScheduleOutcome::SkippedMarker));
                }
            }
            Err(err) => {
                warn!(
                    repo,
                    iid,
                    head_sha,
                    error = %err,
                    "failed to load MR discussions while checking inline review markers"
                );
                if completed_inline_review {
                    return Ok(Some(ReviewScheduleOutcome::SkippedMarker));
                }
            }
        }
        Ok(None)
    }

    async fn acquire_review_slot(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        now: i64,
    ) -> Result<ReviewGateOutcome> {
        if !self
            .shared
            .state
            .review_state
            .begin_review_for_lane(repo, mr.iid, head_sha, self.lane)
            .await?
        {
            self.defer_retry_gate(
                repo,
                mr.iid,
                head_sha,
                Utc::now() + Duration::seconds(REVIEW_RETRY_BLOCKED_DEFER_SECONDS),
            );
            return Ok(ReviewGateOutcome::ClaimBusy);
        }
        let Some(acquired_bucket_ids) = self
            .consume_review_rate_limits_for_gate(repo, mr.iid, head_sha, now)
            .await?
        else {
            return Ok(ReviewGateOutcome::RateLimited);
        };
        if self.shared.shutdown_requested() {
            return self
                .rollback_review_slot_for_shutdown(
                    repo,
                    mr.iid,
                    head_sha,
                    now,
                    &acquired_bucket_ids,
                )
                .await;
        }
        Ok(ReviewGateOutcome::Ready(ReviewGateReady {
            acquired_rule_ids: acquired_bucket_ids,
        }))
    }

    async fn consume_review_rate_limits_for_gate(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        now: i64,
    ) -> Result<Option<Vec<String>>> {
        match self
            .shared
            .state
            .review_rate_limit
            .try_consume_review_rate_limits(self.lane, repo, iid, now)
            .await
        {
            Err(err) => {
                self.release_review_lock_after_gate_failure(repo, iid, head_sha, &err)
                    .await;
                Err(err)
            }
            Ok(ReviewRateLimitAcquireOutcome::Unmatched) => Ok(Some(Vec::new())),
            Ok(ReviewRateLimitAcquireOutcome::Acquired { bucket_ids }) => Ok(Some(bucket_ids)),
            Ok(ReviewRateLimitAcquireOutcome::Blocked { next_retry_at }) => {
                self.finish_review_slot_as_cancelled(repo, iid, head_sha)
                    .await?;
                self.shared
                    .state
                    .review_rate_limit
                    .upsert_review_rate_limit_pending(
                        self.lane,
                        repo,
                        iid,
                        head_sha,
                        now,
                        next_retry_at,
                    )
                    .await?;
                if let Some(next_retry_at) = DateTime::<Utc>::from_timestamp(next_retry_at, 0) {
                    self.defer_retry_gate(repo, iid, head_sha, next_retry_at);
                }
                self.ensure_rate_limit_award_best_effort(repo, iid).await;
                Ok(None)
            }
        }
    }

    async fn rollback_review_slot_for_shutdown(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        now: i64,
        acquired_bucket_ids: &[String],
    ) -> Result<ReviewGateOutcome> {
        let refund_err = if acquired_bucket_ids.is_empty() {
            None
        } else {
            self.shared
                .state
                .review_rate_limit
                .refund_review_rate_limit_buckets(acquired_bucket_ids, now)
                .await
                .err()
        };
        if let Err(lock_err) = self
            .finish_review_slot_as_cancelled(repo, iid, head_sha)
            .await
        {
            if let Some(refund_err) = refund_err {
                warn!(
                    repo = repo,
                    iid = iid,
                    head_sha = head_sha,
                    lane = self.lane.as_str(),
                    error = %refund_err,
                    "failed to refund rate limit rules while shutting down review gate"
                );
            }
            return Err(lock_err);
        }
        if let Some(refund_err) = refund_err {
            return Err(refund_err);
        }
        Ok(ReviewGateOutcome::Skip(ReviewScheduleOutcome::Interrupted))
    }

    async fn finish_review_slot_as_cancelled(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
    ) -> Result<()> {
        self.shared
            .state
            .review_state
            .finish_review_for_lane(
                repo,
                iid,
                head_sha,
                self.lane,
                ReviewRunResult::Cancelled.as_str(),
            )
            .await
    }

    fn new_review_run_history(&self, repo: &str, iid: u64, head_sha: &str) -> NewRunHistory {
        NewRunHistory {
            kind: self.lane.run_history_kind(),
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        }
    }

    async fn prepare_review_run(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        acquired_rule_ids: &[String],
    ) -> Result<PreparedReviewRun> {
        let run_history_id = match self
            .shared
            .state
            .run_history
            .start_run_history_for_lane(
                self.new_review_run_history(repo, iid, head_sha),
                Some(self.lane),
            )
            .await
        {
            Ok(run_history_id) => run_history_id,
            Err(err) => {
                self.release_review_lock_after_history_failure(
                    repo,
                    iid,
                    head_sha,
                    acquired_rule_ids,
                )
                .await;
                return Err(err);
            }
        };
        let feature_flags = match self.resolve_feature_flags().await {
            Ok(feature_flags) => feature_flags,
            Err(err) => {
                self.abort_review_after_setup_failure(
                    repo,
                    iid,
                    head_sha,
                    run_history_id,
                    acquired_rule_ids,
                    &err,
                )
                .await;
                return Err(err);
            }
        };
        if let Err(err) = self
            .shared
            .state
            .run_history
            .set_run_history_feature_flags(run_history_id, &feature_flags)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                iid,
                head_sha,
                run_history_id,
                acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        Ok(PreparedReviewRun {
            task: ScheduledTaskContext::new(repo, iid, head_sha, run_history_id),
            feature_flags,
        })
    }

    fn run_context(&self, acquired_rate_limit_rule_ids: Vec<String>) -> ReviewRunContext {
        ReviewRunContext {
            lane: self.lane,
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
            award_service: self.shared.award_service.clone(),
            retry_warning_awards: self.retry_warning_awards.clone(),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            lifecycle: Arc::clone(&self.shared.lifecycle),
            acquired_rate_limit_rule_ids,
        }
    }

    /// Decides whether this lane must review `head_sha`. The caller queues the returned job.
    ///
    /// Takes no claim and no rate-limit bucket. The job checks again when it starts.
    pub(crate) async fn admit_for_scan(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<ReviewAdmission> {
        if let Some(outcome) = self
            .review_skip_decision(repo, mr, head_sha, history)
            .await?
        {
            return Ok(ReviewAdmission::Skip(outcome));
        }
        Ok(ReviewAdmission::Queue(QueuedReview {
            lane: self.lane,
            repo: repo.to_string(),
            iid: mr.iid,
            head_sha: head_sha.to_string(),
            eligibility: ReviewEligibility::Automatic,
        }))
    }

    /// Runs a queued review for the latest head of its MR. Holds a run slot for the whole call.
    ///
    /// A failure is logged and makes the next incremental scan read the repository again.
    pub(crate) async fn run_queued(&self, job: QueuedReview, running_head: RunningHead) {
        assert_eq!(
            job.lane, self.lane,
            "a queued review must run in its own lane"
        );
        if let Err(err) = self.start_queued(&job, &running_head).await {
            warn!(
                repo = job.repo.as_str(),
                iid = job.iid,
                lane = self.lane.as_str(),
                error = %format!("{err:#}"),
                "queued review failed"
            );
            self.request_rescan(&job);
        }
    }

    async fn start_queued(&self, job: &QueuedReview, running_head: &RunningHead) -> Result<()> {
        let repo = job.repo.as_str();
        let mr = match self.shared.gitlab.get_mr(repo, job.iid).await {
            Ok(mr) => mr,
            Err(err) if merge_request_lookup_reports_missing(&err) => {
                debug!(
                    repo,
                    iid = job.iid,
                    lane = self.lane.as_str(),
                    "skip queued review: merge request no longer exists"
                );
                return self
                    .clear_review_rate_limit_pending_if_needed(repo, job.iid)
                    .await;
            }
            Err(err) => return Err(err.context("refresh merge request for queued review")),
        };
        if job.eligibility == ReviewEligibility::Automatic
            && let Some(reason) = review_skip_reason(&mr, self.shared.created_after)
        {
            debug!(
                repo,
                iid = job.iid,
                lane = self.lane.as_str(),
                ?reason,
                "skip queued review: merge request is not eligible"
            );
            return self
                .clear_review_rate_limit_pending_if_needed(repo, job.iid)
                .await;
        }
        let Some(head_sha) = mr.head_sha() else {
            warn!(
                repo,
                iid = job.iid,
                lane = self.lane.as_str(),
                "skip queued review: merge request has no head sha"
            );
            return Ok(());
        };
        running_head.set(&head_sha);
        if head_sha != job.head_sha {
            debug!(
                repo,
                iid = job.iid,
                lane = self.lane.as_str(),
                queued_head_sha = job.head_sha.as_str(),
                head_sha = head_sha.as_str(),
                "queued review uses the latest head"
            );
        }
        let history = AdmissionHistory::new(self.shared.gitlab.as_ref(), repo, job.iid);
        let acquired_rule_ids = match self
            .evaluate_review_gate(repo, &mr, &head_sha, &history)
            .await?
        {
            ReviewGateOutcome::Ready(ready) => ready.acquired_rule_ids,
            ReviewGateOutcome::Skip(outcome) => {
                if !outcome.keeps_pending_retry() {
                    self.clear_review_rate_limit_pending_if_needed(repo, job.iid)
                        .await?;
                }
                return Ok(());
            }
            // Only a run that ended without cleanup leaves a busy claim. Retry after the stale sweep.
            ReviewGateOutcome::ClaimBusy => {
                self.request_rescan(job);
                return Ok(());
            }
            ReviewGateOutcome::RateLimited => return Ok(()),
        };
        // Heartbeats keep the claim alive while the review runs.
        let _active_review = self.shared.active_tasks.track_review(ActiveReviewKey {
            lane: self.lane,
            repo: repo.to_string(),
            iid: job.iid,
            head_sha: head_sha.clone(),
        });
        let prepared = self
            .prepare_review_run(repo, job.iid, &head_sha, &acquired_rule_ids)
            .await?;
        self.clear_review_rate_limit_pending_or_abort(
            repo,
            job.iid,
            &head_sha,
            prepared.task.run_history_id,
            &acquired_rule_ids,
        )
        .await?;
        self.run_context(acquired_rule_ids)
            .run(
                repo,
                mr,
                &head_sha,
                prepared.feature_flags,
                prepared.task.run_history_id,
            )
            .await
    }

    /// Makes the next incremental scan queue this review again. Delays a due retry of the MR.
    fn request_rescan(&self, job: &QueuedReview) {
        self.shared.rescan_requests.request(&job.repo);
        // A due retry wakes the scheduler at once. Without a delay, a repeating failure would loop.
        let now = Utc::now();
        self.retry_backoff.defer_due_for_mr(
            &job.repo,
            job.iid,
            now,
            now + Duration::seconds(REVIEW_RETRY_BLOCKED_DEFER_SECONDS),
        );
    }

    async fn resolve_feature_flags(&self) -> Result<FeatureFlagSnapshot> {
        let overrides = self
            .shared
            .state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?;
        Ok(self.shared.config.resolve_feature_flags(&overrides))
    }

    async fn clear_review_rate_limit_pending_if_needed(&self, repo: &str, iid: u64) -> Result<()> {
        let cleared = self
            .shared
            .state
            .review_rate_limit
            .clear_review_rate_limit_pending(self.lane, repo, iid)
            .await?;
        if cleared {
            self.remove_rate_limit_award_best_effort(repo, iid).await;
            self.remove_quota_award_best_effort(repo, iid).await;
        }
        Ok(())
    }

    async fn clear_review_rate_limit_pending_or_abort(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        run_history_id: i64,
        acquired_rule_ids: &[String],
    ) -> Result<()> {
        if let Err(err) = self
            .clear_review_rate_limit_pending_if_needed(repo, iid)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                iid,
                head_sha,
                run_history_id,
                acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        Ok(())
    }

    async fn ensure_rate_limit_award_best_effort(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .ensure_award(repo, iid, &self.shared.config.review.rate_limit_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to add rate-limit award"
            );
        }
    }

    async fn ensure_quota_award_best_effort(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .ensure_award(repo, iid, &self.shared.config.review.quota_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to add quota award"
            );
        }
    }

    /// Removes the bot's thumbs award, which says that the bot accepts the MR in its latest
    /// form. Lanes without awards and dry runs do nothing. A failure is logged.
    pub(crate) async fn withdraw_pass_award(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .remove_award(repo, iid, &self.shared.config.review.thumbs_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to withdraw thumbs award from MR that needs a review"
            );
        }
    }

    async fn remove_rate_limit_award_best_effort(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .remove_award(repo, iid, &self.shared.config.review.rate_limit_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to remove rate-limit award"
            );
        }
    }

    async fn remove_quota_award_best_effort(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .shared
            .award_service
            .remove_award(repo, iid, &self.shared.config.review.quota_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to remove quota award"
            );
        }
    }

    async fn release_review_lock_after_gate_failure(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        err: &anyhow::Error,
    ) {
        if let Err(recovery_err) = self
            .shared
            .state
            .review_state
            .finish_review_for_lane(
                repo,
                iid,
                head_sha,
                self.lane,
                ReviewRunResult::Error.as_str(),
            )
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                lane = self.lane.as_str(),
                error = %recovery_err,
                cause = %err,
                "failed to release review lock after review gate error"
            );
        }
    }

    async fn release_review_lock_after_history_failure(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        acquired_rule_ids: &[String],
    ) {
        if let Err(recovery_err) =
            refund_review_rate_limits(&self.shared.state, acquired_rule_ids).await
        {
            warn!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                error = %recovery_err,
                "failed to refund rate limit rules after run history creation error"
            );
        }
        if let Err(recovery_err) = self
            .shared
            .state
            .review_state
            .finish_review_for_lane(
                repo,
                iid,
                head_sha,
                self.lane,
                ReviewRunResult::Error.as_str(),
            )
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                error = %recovery_err,
                "failed to release review lock after run history creation error"
            );
        }
    }

    async fn abort_review_after_setup_failure(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        run_history_id: i64,
        acquired_rule_ids: &[String],
        err: &anyhow::Error,
    ) {
        self.release_review_lock_after_history_failure(repo, iid, head_sha, acquired_rule_ids)
            .await;
        let task = ScheduledTaskContext::new(repo, iid, head_sha, run_history_id);
        if let Err(recovery_err) = finish_task_run_history(
            &self.shared.state,
            &task,
            task_error_finish(
                ReviewRunResult::Error.as_str(),
                format!("{} {repo} !{iid}", self.lane.review_label()),
                err,
            ),
        )
        .await
        {
            warn!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                error = %recovery_err,
                "failed to finalize run history after review setup error"
            );
        }
    }
}

#[async_trait]
impl MergeRequestFlow for ReviewFlow {
    fn flow_name(&self) -> &'static str {
        self.lane.flow_name()
    }

    async fn clear_stale_in_progress(&self) -> Result<()> {
        ReviewFlow::clear_stale_in_progress(self).await
    }

    async fn recover_in_progress(&self) -> Result<()> {
        ReviewFlow::recover_in_progress(self).await
    }
}

/// Holds dependencies and acquired rate limits for executing one lane's review.
pub(crate) struct ReviewRunContext {
    pub(crate) lane: ReviewLane,
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) award_service: AwardService,
    pub(crate) retry_warning_awards: RetryWarningAwardService,
    pub(crate) codex: Arc<dyn crate::codex_runner::CodexRunner>,
    pub(crate) state: Arc<ReviewStateStore>,
    pub(crate) retry_backoff: Arc<RetryBackoff>,
    pub(crate) bot_user_id: u64,
    pub(crate) lifecycle: Arc<ServiceLifecycle>,
    pub(crate) acquired_rate_limit_rule_ids: Vec<String>,
}

struct ReviewRunIdentity<'a> {
    repo: &'a str,
    iid: u64,
    head_sha: &'a str,
    run_history_id: i64,
    retry_key: &'a RetryKey,
}

impl ReviewRunContext {
    fn uses_awards(&self) -> bool {
        self.lane.uses_awards()
    }

    fn review_preview(&self, repo: &str, iid: u64) -> String {
        format!("{} {repo} !{iid}", self.lane.review_label())
    }

    fn should_reject_new_starts(&self) -> bool {
        !self.lifecycle.accepts_new_work()
    }

    fn should_cancel_active_work(&self) -> bool {
        self.lifecycle.should_cancel_active_work()
    }

    async fn remove_eyes_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run || !self.uses_awards() {
            info!(repo = repo, iid = iid, "dry run: skipping eyes removal");
            return;
        }
        if let Err(err) = self
            .award_service
            .remove_award(repo, iid, &self.config.review.eyes_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to remove eyes award"
            );
        }
    }

    async fn withdraw_pass_award(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .award_service
            .remove_award(repo, iid, &self.config.review.thumbs_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to withdraw thumbs award before review"
            );
        }
    }

    async fn add_eyes_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run || !self.uses_awards() {
            info!(repo = repo, iid = iid, "dry run: skipping eyes award");
            return;
        }
        if let Err(err) = self
            .award_service
            .ensure_award(repo, iid, &self.config.review.eyes_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to add eyes award"
            );
        }
    }

    async fn finalize_cancelled(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        retry_key: &RetryKey,
        run_history_id: i64,
    ) -> Result<()> {
        self.remove_eyes_best_effort(repo, iid).await;
        refund_review_rate_limits(&self.state, &self.acquired_rate_limit_rule_ids).await?;
        self.retry_warning_awards
            .clear_key_and_remove_if_inactive(self.retry_backoff.as_ref(), retry_key)
            .await;
        self.state
            .review_state
            .finish_review_for_lane(
                repo,
                iid,
                head_sha,
                self.lane,
                ReviewRunResult::Cancelled.as_str(),
            )
            .await?;
        let task = ScheduledTaskContext::new(repo, iid, head_sha, run_history_id);
        finish_task_run_history(
            &self.state,
            &task,
            task_cancelled_finish(
                ReviewRunResult::Cancelled.as_str(),
                self.review_preview(repo, iid),
            ),
        )
        .await?;
        info!(repo = repo, iid = iid, "review cancelled due to shutdown");
        Ok(())
    }

    async fn ensure_quota_award_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = self
            .award_service
            .ensure_award(repo, iid, &self.config.review.quota_emoji)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to add quota award"
            );
        }
    }

    async fn handle_quota_exhausted(
        &self,
        run: &ReviewRunIdentity<'_>,
        quota: &CodexQuotaExhausted,
    ) -> Result<()> {
        refund_review_rate_limits(&self.state, &self.acquired_rate_limit_rule_ids).await?;
        self.retry_warning_awards
            .clear_key_and_remove_if_inactive(self.retry_backoff.as_ref(), run.retry_key)
            .await;
        self.state
            .review_state
            .finish_review_for_lane(
                run.repo,
                run.iid,
                run.head_sha,
                self.lane,
                ReviewRunResult::Cancelled.as_str(),
            )
            .await?;
        let task = ScheduledTaskContext::new(run.repo, run.iid, run.head_sha, run.run_history_id);
        let mut finish = task_cancelled_finish(
            ReviewRunResult::Cancelled.as_str(),
            self.review_preview(run.repo, run.iid),
        );
        finish.summary = Some(format!(
            "deferred: codex quota exhausted until {}",
            quota.reset_at
        ));
        finish_task_run_history(&self.state, &task, finish).await?;
        self.state
            .review_rate_limit
            .upsert_review_rate_limit_pending(
                self.lane,
                run.repo,
                run.iid,
                run.head_sha,
                Utc::now().timestamp(),
                quota.retry_at.timestamp(),
            )
            .await?;
        self.ensure_quota_award_best_effort(run.repo, run.iid).await;
        info!(
            repo = run.repo,
            iid = run.iid,
            reset_at = %quota.reset_at,
            retry_at = %quota.retry_at,
            "review deferred because codex quota is exhausted"
        );
        Ok(())
    }

    async fn bail_if_start_rejected(&self, run: &ReviewRunIdentity<'_>) -> Result<bool> {
        if self.should_reject_new_starts() {
            self.finalize_cancelled(
                run.repo,
                run.iid,
                run.head_sha,
                run.retry_key,
                run.run_history_id,
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn bail_if_cancelled(&self, run: &ReviewRunIdentity<'_>) -> Result<bool> {
        if self.should_cancel_active_work() {
            self.finalize_cancelled(
                run.repo,
                run.iid,
                run.head_sha,
                run.retry_key,
                run.run_history_id,
            )
            .await?;
            return Ok(true);
        }
        Ok(false)
    }

    fn build_codex_review_context(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        project_path: String,
        feature_flags: FeatureFlagSnapshot,
        run_history_id: i64,
    ) -> ReviewContext {
        let discussion_source = feature_flags.gitlab_inline_review_comments.then(|| {
            Arc::new(ReviewDiscussionSource::new(
                Arc::clone(&self.gitlab),
                repo.to_string(),
                mr.iid,
                self.bot_user_id,
                self.lane.finding_marker_prefix(&self.config).to_string(),
                vec![
                    REVIEW_FINDING_MARKER_PREFIX.to_string(),
                    self.config.review.security.finding_marker_prefix.clone(),
                ],
            ))
        });
        ReviewContext {
            lane: self.lane,
            repo: repo.to_string(),
            project_path,
            mr: mr.clone(),
            head_sha: head_sha.to_string(),
            feature_flags,
            additional_developer_instructions: self
                .lane
                .additional_developer_instructions(&self.config),
            min_confidence_score: self.lane.min_confidence_score(&self.config),
            security_context_ttl_seconds: self.lane.context_ttl_seconds(&self.config),
            run_history_id: Some(run_history_id),
            discussion_source,
        }
    }

    async fn record_outcome(
        &self,
        run: &ReviewRunIdentity<'_>,
        clear_retry_key: bool,
        result: ReviewRunResult,
        mut finish: RunHistoryFinish,
    ) -> Result<()> {
        if clear_retry_key {
            self.retry_warning_awards
                .clear_key_and_remove_if_inactive(self.retry_backoff.as_ref(), run.retry_key)
                .await;
        }
        self.state
            .review_state
            .finish_review_for_lane(run.repo, run.iid, run.head_sha, self.lane, result.as_str())
            .await?;
        finish.result = result.as_str().to_string();
        let task = ScheduledTaskContext::new(run.repo, run.iid, run.head_sha, run.run_history_id);
        finish_task_run_history(&self.state, &task, finish).await
    }

    async fn handle_pass(&self, run: &ReviewRunIdentity<'_>, summary: String) -> Result<()> {
        if self.bail_if_cancelled(run).await? {
            return Ok(());
        }
        if self.config.review.dry_run || !self.uses_awards() {
            info!(
                repo = run.repo,
                iid = run.iid,
                "dry run: skipping thumbs up"
            );
        } else {
            self.award_service
                .ensure_award(run.repo, run.iid, &self.config.review.thumbs_emoji)
                .await?;
        }
        let result = if self.config.review.dry_run {
            ReviewRunResult::DryRunPass
        } else {
            ReviewRunResult::Pass
        };
        self.record_outcome(
            run,
            true,
            result,
            RunHistoryFinish {
                preview: Some(self.review_preview(run.repo, run.iid)),
                summary: Some(summary.clone()),
                ..RunHistoryFinish::default()
            },
        )
        .await?;
        info!(
            repo = run.repo,
            iid = run.iid,
            summary = summary.as_str(),
            "review pass"
        );
        Ok(())
    }

    async fn handle_comment(
        &self,
        run: &ReviewRunIdentity<'_>,
        mr: &MergeRequest,
        inline_review_comments_enabled: bool,
        review_project: &ResolvedReviewProject,
        discussion_source: Option<&ReviewDiscussionSource>,
        comment: ReviewComment,
    ) -> Result<()> {
        if self.bail_if_cancelled(run).await? {
            return Ok(());
        }
        if self.config.review.dry_run {
            info!(repo = run.repo, iid = run.iid, "dry run: skipping comment");
        } else {
            post_review_comment(PostReviewCommentRequest {
                inline_review_comments_enabled,
                lane: self.lane,
                config: &self.config,
                gitlab: self.gitlab.as_ref(),
                bot_user_id: self.bot_user_id,
                project: review_project,
                repo: run.repo,
                mr,
                head_sha: run.head_sha,
                comment: &comment,
                discussion_source,
            })
            .await?;
        }
        let result = if self.config.review.dry_run {
            ReviewRunResult::DryRunComment
        } else {
            ReviewRunResult::Comment
        };
        self.record_outcome(
            run,
            true,
            result,
            RunHistoryFinish {
                preview: Some(self.review_preview(run.repo, run.iid)),
                summary: Some(comment.summary.clone()),
                error: Some(comment.body.clone()),
                ..RunHistoryFinish::default()
            },
        )
        .await?;
        info!(
            repo = run.repo,
            iid = run.iid,
            summary = comment.summary.as_str(),
            "review comment"
        );
        Ok(())
    }

    async fn handle_flagged(&self, run: &ReviewRunIdentity<'_>, err: Error) -> Result<()> {
        warn!(
            repo = run.repo,
            iid = run.iid,
            error = ?err,
            "security review content was flagged; not retrying"
        );
        self.record_outcome(
            run,
            true,
            ReviewRunResult::Flagged,
            task_error_finish(
                ReviewRunResult::Flagged.as_str(),
                self.review_preview(run.repo, run.iid),
                &err,
            ),
        )
        .await
    }

    async fn handle_error(&self, run: &ReviewRunIdentity<'_>, err: Error) -> Result<()> {
        let retry = self.retry_backoff.record_failure(
            (*run.retry_key).clone(),
            run.run_history_id,
            Utc::now(),
        );
        error!(
            repo = run.repo,
            iid = run.iid,
            error = ?err,
            retry_number = retry.retry_number,
            max_retries = retry.max_retries,
            retry_exhausted = retry.exhausted,
            next_retry_at = ?retry.next_retry_at,
            "review failed"
        );
        if self.bail_if_cancelled(run).await? {
            return Ok(());
        }
        if retry.exhausted {
            self.retry_warning_awards
                .remove_if_no_active_retry(self.retry_backoff.as_ref(), run.repo, run.iid)
                .await;
        } else {
            self.retry_warning_awards
                .ensure_best_effort(run.repo, run.iid)
                .await;
        }
        self.record_outcome(
            run,
            false,
            ReviewRunResult::Error,
            task_error_finish(
                ReviewRunResult::Error.as_str(),
                self.review_preview(run.repo, run.iid),
                &err,
            ),
        )
        .await
    }

    pub(crate) async fn run(
        &self,
        repo: &str,
        mr: MergeRequest,
        head_sha: &str,
        feature_flags: FeatureFlagSnapshot,
        run_history_id: i64,
    ) -> Result<()> {
        let retry_key = RetryKey::new(self.lane, repo, mr.iid, head_sha);
        let run_identity = ReviewRunIdentity {
            repo,
            iid: mr.iid,
            head_sha,
            run_history_id,
            retry_key: &retry_key,
        };
        let inline_review_comments_enabled = feature_flags.gitlab_inline_review_comments;
        if self.bail_if_start_rejected(&run_identity).await? {
            return Ok(());
        }

        self.retry_warning_awards
            .remove_if_no_other_active_retry(self.retry_backoff.as_ref(), &retry_key)
            .await;
        // A run of an earlier head can pass after this review was queued. This review
        // decides the award for the latest head.
        self.withdraw_pass_award(repo, mr.iid).await;
        self.add_eyes_best_effort(repo, mr.iid).await;
        let review_project =
            resolve_review_project(&self.config, self.gitlab.as_ref(), self.lane, repo, &mr).await;
        let review_ctx = self.build_codex_review_context(
            repo,
            &mr,
            head_sha,
            review_project.project_path.clone(),
            feature_flags,
            run_history_id,
        );
        let discussion_source = review_ctx.discussion_source.clone();

        if self.bail_if_start_rejected(&run_identity).await? {
            return Ok(());
        }

        let _started_run = self.lifecycle.track_started_run();
        let result = self.codex.run_review(review_ctx).await;
        if self.bail_if_cancelled(&run_identity).await? {
            return Ok(());
        }
        self.remove_eyes_best_effort(repo, mr.iid).await;
        if self.bail_if_cancelled(&run_identity).await? {
            return Ok(());
        }

        match result {
            Ok(CodexResult::Pass { summary }) => {
                if let Err(err) = self.handle_pass(&run_identity, summary).await {
                    self.handle_error(&run_identity, err).await?;
                }
            }
            Ok(CodexResult::Comment(comment)) => {
                if let Err(err) = self
                    .handle_comment(
                        &run_identity,
                        &mr,
                        inline_review_comments_enabled,
                        &review_project,
                        discussion_source.as_deref(),
                        comment,
                    )
                    .await
                {
                    self.handle_error(&run_identity, err).await?;
                }
            }
            Err(err) => {
                if let Some(quota) = err.downcast_ref::<CodexQuotaExhausted>() {
                    let quota = quota.clone();
                    self.handle_quota_exhausted(&run_identity, &quota).await?;
                } else if self.lane.is_security()
                    && err.downcast_ref::<SecurityReviewContentFlagged>().is_some()
                {
                    self.handle_flagged(&run_identity, err).await?;
                } else {
                    self.handle_error(&run_identity, err).await?;
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn has_review_marker(notes: &[Note], bot_user_id: u64, prefix: &str, sha: &str) -> bool {
    if bot_user_id == 0 {
        return false;
    }
    let marker = format!("{prefix}{sha} -->");
    notes
        .iter()
        .any(|note| note.author.id == bot_user_id && note.body.contains(&marker))
}

pub(crate) fn has_inline_review_marker(
    discussions: &[MergeRequestDiscussion],
    bot_user_id: u64,
    sha: &str,
    prefix: &str,
) -> bool {
    if bot_user_id == 0 {
        return false;
    }
    let marker_prefix = format!("{prefix}{sha} ");
    discussions
        .iter()
        .flat_map(|discussion| &discussion.notes)
        .any(|note| note.author.id == bot_user_id && note.body.contains(&marker_prefix))
}

#[cfg(test)]
mod tests {
    use super::ReviewRunResult;

    #[test]
    fn review_run_result_roundtrips_persisted_strings() {
        for result in [
            ReviewRunResult::Pass,
            ReviewRunResult::DryRunPass,
            ReviewRunResult::Comment,
            ReviewRunResult::DryRunComment,
            ReviewRunResult::Error,
            ReviewRunResult::Flagged,
            ReviewRunResult::Cancelled,
        ] {
            assert_eq!(ReviewRunResult::parse(result.as_str()), Some(result));
        }
    }
}

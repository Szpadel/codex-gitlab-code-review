use crate::codex_runner::{CodexQuotaExhausted, CodexResult, ReviewComment, ReviewContext};
use crate::config::Config;
use crate::config::FeatureFlagSnapshot;
use crate::flow::award_service::AwardService;
use crate::flow::orchestration::{
    ActiveTaskKey, ScheduledTaskContext, finish_task_run_history, refund_review_rate_limits,
    spawn_orchestrated_task, task_cancelled_finish, task_error_finish,
};
use crate::flow::review_comments::{PostReviewCommentRequest, post_review_comment};
use crate::flow::{ActiveReviewKey, FlowShared, MergeRequestFlow};
use crate::gitlab::{GitLabApi, MergeRequest, MergeRequestDiscussion, Note};
use crate::lifecycle::ServiceLifecycle;
use crate::review::ReviewLane;
use crate::review::lane_policies::ReviewLanePolicy;
use crate::state::{
    NewRunHistory, ReviewRateLimitAcquireOutcome, ReviewStateStore, RunHistoryFinish,
};
use anyhow::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct RetryKey {
    lane: ReviewLane,
    repo: String,
    iid: u64,
    head_sha: String,
}

impl RetryKey {
    pub(crate) fn new(lane: ReviewLane, repo: &str, iid: u64, head_sha: &str) -> Self {
        Self {
            lane,
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct RetryState {
    pub(crate) failures: u32,
    pub(crate) next_retry_at: DateTime<Utc>,
}

pub(crate) struct RetryBackoff {
    base_delay: Duration,
    entries: Mutex<HashMap<RetryKey, RetryState>>,
}

impl RetryBackoff {
    pub(crate) fn new(base_delay: Duration) -> Self {
        Self {
            base_delay,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn should_retry(&self, key: &RetryKey, now: DateTime<Utc>) -> bool {
        let entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some(state) => now >= state.next_retry_at,
            None => true,
        }
    }

    pub(crate) fn record_failure(&self, key: RetryKey, now: DateTime<Utc>) -> DateTime<Utc> {
        let mut entries = self.entries.lock().unwrap();
        let failures = entries.get(&key).map_or(1, |state| state.failures + 1);
        let base_seconds = self.base_delay.num_seconds().max(0);
        let exponent = failures.saturating_sub(1).min(30);
        let multiplier = 1i64 << exponent;
        let delay_seconds = base_seconds.saturating_mul(multiplier);
        let next_retry_at = now + Duration::seconds(delay_seconds);
        entries.insert(
            key,
            RetryState {
                failures,
                next_retry_at,
            },
        );
        next_retry_at
    }

    pub(crate) fn clear(&self, key: &RetryKey) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(key);
    }

    #[cfg(test)]
    pub(crate) fn state_for(&self, key: &RetryKey) -> Option<RetryState> {
        let entries = self.entries.lock().unwrap();
        entries.get(key).cloned()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReviewScheduleOutcome {
    Scheduled,
    Disabled,
    SkippedBackoff,
    SkippedRateLimit,
    SkippedQuota,
    SkippedAward,
    SkippedMarker,
    SkippedCompleted,
    SkippedLocked,
    Interrupted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReviewRunResult {
    Pass,
    DryRunPass,
    Comment,
    DryRunComment,
    Error,
    Cancelled,
}

pub(crate) enum ReviewRunStatus {
    Completed,
    QuotaDeferred,
}

impl ReviewRunResult {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::DryRunPass => "dry_run_pass",
            Self::Comment => "comment",
            Self::DryRunComment => "dry_run_comment",
            Self::Error => "error",
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
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    pub(crate) const fn is_completed_review(self) -> bool {
        matches!(self, Self::Pass | Self::Comment)
    }
}

enum ReviewGateOutcome {
    Ready(ReviewGateReady),
    Decision(ReviewScheduleOutcome),
}

struct ReviewGateReady {
    acquired_rule_ids: Vec<String>,
}

struct PreparedReviewRun {
    task: ScheduledTaskContext,
    feature_flags: FeatureFlagSnapshot,
}

pub(crate) struct ReviewFlow {
    shared: FlowShared,
    retry_backoff: Arc<RetryBackoff>,
    lane: ReviewLane,
    policy: Arc<dyn ReviewLanePolicy>,
}

impl ReviewFlow {
    pub(crate) fn new(
        shared: FlowShared,
        retry_backoff: Arc<RetryBackoff>,
        lane: ReviewLane,
        policy: Arc<dyn ReviewLanePolicy>,
    ) -> Self {
        Self {
            shared,
            retry_backoff,
            lane,
            policy,
        }
    }

    fn review_marker_prefix(&self) -> &str {
        self.policy.comment_marker_prefix(&self.shared.config)
    }

    fn finding_marker_prefix(&self) -> &str {
        self.policy.finding_marker_prefix(&self.shared.config)
    }

    pub(crate) fn uses_awards(&self) -> bool {
        self.policy.uses_awards()
    }

    fn is_enabled(&self, feature_flags: &FeatureFlagSnapshot) -> bool {
        self.policy.is_enabled(feature_flags)
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

    async fn evaluate_review_gate(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
    ) -> Result<ReviewGateOutcome> {
        let feature_flags = self.resolve_feature_flags().await?;
        if !self.is_enabled(&feature_flags) {
            return Ok(ReviewGateOutcome::Decision(ReviewScheduleOutcome::Disabled));
        }
        let now = Utc::now().timestamp();
        if let Some(outcome) = self
            .find_skip_reason(repo, mr, head_sha, &feature_flags)
            .await?
        {
            return Ok(ReviewGateOutcome::Decision(outcome));
        }
        self.acquire_review_slot(repo, mr, head_sha, now).await
    }

    async fn find_skip_reason(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        feature_flags: &FeatureFlagSnapshot,
    ) -> Result<Option<ReviewScheduleOutcome>> {
        if self.skipped_by_backoff(repo, mr.iid, head_sha) {
            return Ok(Some(ReviewScheduleOutcome::SkippedBackoff));
        }
        if self.skipped_by_thumbs_award(repo, mr.iid).await? {
            return Ok(Some(ReviewScheduleOutcome::SkippedAward));
        }
        if self
            .skipped_by_review_marker(repo, mr.iid, head_sha)
            .await?
        {
            return Ok(Some(ReviewScheduleOutcome::SkippedMarker));
        }
        if let Some(outcome) = self
            .skipped_by_inline_markers(repo, mr.iid, head_sha, feature_flags)
            .await?
        {
            return Ok(Some(outcome));
        }
        if self.skipped_by_mention_lock(repo, mr.iid).await? {
            return Ok(Some(ReviewScheduleOutcome::SkippedLocked));
        }
        if self.skipped_by_codex_quota(repo, mr.iid, head_sha).await? {
            return Ok(Some(ReviewScheduleOutcome::SkippedQuota));
        }
        Ok(None)
    }

    fn skipped_by_backoff(&self, repo: &str, iid: u64, head_sha: &str) -> bool {
        let retry_key = RetryKey::new(self.lane, repo, iid, head_sha);
        !self.retry_backoff.should_retry(&retry_key, Utc::now())
    }

    async fn skipped_by_thumbs_award(&self, repo: &str, iid: u64) -> Result<bool> {
        if !self.uses_awards() {
            return Ok(false);
        }
        self.shared
            .award_service
            .has_award(repo, iid, &self.shared.config.review.thumbs_emoji)
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
        self.ensure_quota_award_best_effort(repo, iid).await;
        Ok(true)
    }

    async fn skipped_by_review_marker(&self, repo: &str, iid: u64, head_sha: &str) -> Result<bool> {
        let notes = self.shared.gitlab.list_notes(repo, iid).await?;
        Ok(has_review_marker(
            &notes,
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
        if self.policy.skips_completed_review_result()
            && parsed_review_result.is_some_and(ReviewRunResult::is_completed_review)
        {
            return Ok(Some(ReviewScheduleOutcome::SkippedCompleted));
        }
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
    ) -> Result<Option<ReviewScheduleOutcome>> {
        match self.shared.gitlab.list_discussions(repo, iid).await {
            Ok(discussions) => {
                if has_inline_review_marker(
                    &discussions,
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

    async fn skipped_by_mention_lock(&self, repo: &str, iid: u64) -> Result<bool> {
        self.shared
            .state
            .mention_commands
            .has_in_progress_mention_for_mr(repo, iid)
            .await
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
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedLocked,
            ));
        }
        let acquired_bucket_ids = match self
            .consume_review_rate_limits_for_gate(repo, mr.iid, head_sha, now)
            .await?
        {
            Some(bucket_ids) => bucket_ids,
            None => {
                return Ok(ReviewGateOutcome::Decision(
                    ReviewScheduleOutcome::SkippedRateLimit,
                ));
            }
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
        Ok(ReviewGateOutcome::Decision(
            ReviewScheduleOutcome::Interrupted,
        ))
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
            kind: self.policy.run_history_kind(),
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
            policy: Arc::clone(&self.policy),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            lifecycle: Arc::clone(&self.shared.lifecycle),
            acquired_rate_limit_rule_ids,
        }
    }

    fn spawn_scheduled_review_task(
        &self,
        mr: MergeRequest,
        prepared: PreparedReviewRun,
        acquired_rule_ids: Vec<String>,
        tasks: &mut Vec<JoinHandle<()>>,
    ) {
        let review_context = Arc::new(self.run_context(acquired_rule_ids));
        let task = prepared.task.clone();
        let review_key = ActiveReviewKey {
            lane: review_context.lane,
            repo: task.repo.clone(),
            iid: task.iid,
            head_sha: task.head_sha.clone(),
        };
        let context_for_semaphore_closed = Arc::clone(&review_context);
        let closed_task = task.clone();
        let context_for_start_rejected = Arc::clone(&review_context);
        let rejected_task = task.clone();
        spawn_orchestrated_task(
            &self.shared,
            ActiveTaskKey::Review(review_key),
            tasks,
            async {},
            move |()| async move {
                let err = Error::msg("review cancelled: semaphore closed");
                context_for_semaphore_closed
                    .finalize_setup_failure(
                        &closed_task.repo,
                        closed_task.iid,
                        &closed_task.head_sha,
                        closed_task.run_history_id,
                        &err,
                    )
                    .await;
            },
            move |()| async move {
                let retry_key = RetryKey::new(
                    context_for_start_rejected.lane,
                    &rejected_task.repo,
                    rejected_task.iid,
                    &rejected_task.head_sha,
                );
                if let Err(err) = context_for_start_rejected
                    .finalize_cancelled(
                        &rejected_task.repo,
                        rejected_task.iid,
                        &rejected_task.head_sha,
                        &retry_key,
                        rejected_task.run_history_id,
                    )
                    .await
                {
                    warn!(
                        repo = rejected_task.repo.as_str(),
                        error = %err,
                        "failed to cancel queued review after shutdown"
                    );
                }
            },
            move |()| async move {
                if let Err(err) = review_context
                    .run(
                        &task.repo,
                        mr,
                        &task.head_sha,
                        prepared.feature_flags,
                        task.run_history_id,
                    )
                    .await
                {
                    warn!(repo = task.repo.as_str(), error = %err, "review failed");
                }
            },
        );
    }

    async fn acquire_review_permit_or_abort(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        run_history_id: i64,
        acquired_rule_ids: &[String],
    ) -> Result<OwnedSemaphorePermit> {
        match self.shared.semaphore.clone().acquire_owned().await {
            Ok(permit) => Ok(permit),
            Err(err) => {
                let err = Error::from(err);
                self.abort_review_after_setup_failure(
                    repo,
                    iid,
                    head_sha,
                    run_history_id,
                    acquired_rule_ids,
                    &err,
                )
                .await;
                Err(err)
            }
        }
    }

    pub(crate) async fn schedule_for_scan(
        &self,
        repo: &str,
        mr: MergeRequest,
        head_sha: &str,
        tasks: &mut Vec<JoinHandle<()>>,
    ) -> Result<ReviewScheduleOutcome> {
        let acquired_rule_ids = match self.evaluate_review_gate(repo, &mr, head_sha).await? {
            ReviewGateOutcome::Decision(decision) => return Ok(decision),
            ReviewGateOutcome::Ready(ready) => ready.acquired_rule_ids,
        };
        let prepared = self
            .prepare_review_run(repo, mr.iid, head_sha, &acquired_rule_ids)
            .await?;
        self.clear_review_rate_limit_pending_or_abort(
            repo,
            mr.iid,
            head_sha,
            prepared.task.run_history_id,
            &acquired_rule_ids,
        )
        .await?;
        self.spawn_scheduled_review_task(mr, prepared, acquired_rule_ids, tasks);
        Ok(ReviewScheduleOutcome::Scheduled)
    }

    pub(crate) async fn run_for_mr(
        &self,
        repo: &str,
        mr: MergeRequest,
        head_sha: &str,
    ) -> Result<ReviewScheduleOutcome> {
        let acquired_rule_ids = match self.evaluate_review_gate(repo, &mr, head_sha).await? {
            ReviewGateOutcome::Decision(decision) => return Ok(decision),
            ReviewGateOutcome::Ready(ready) => ready.acquired_rule_ids,
        };
        let prepared = self
            .prepare_review_run(repo, mr.iid, head_sha, &acquired_rule_ids)
            .await?;
        let _permit = self
            .acquire_review_permit_or_abort(
                repo,
                mr.iid,
                head_sha,
                prepared.task.run_history_id,
                &acquired_rule_ids,
            )
            .await?;
        self.clear_review_rate_limit_pending_or_abort(
            repo,
            mr.iid,
            head_sha,
            prepared.task.run_history_id,
            &acquired_rule_ids,
        )
        .await?;
        let review_context = self.run_context(acquired_rule_ids.clone());
        let _active_review = self.shared.active_tasks.track_review(ActiveReviewKey {
            lane: self.lane,
            repo: prepared.task.repo.clone(),
            iid: prepared.task.iid,
            head_sha: prepared.task.head_sha.clone(),
        });
        review_context
            .run(
                &prepared.task.repo,
                mr,
                &prepared.task.head_sha,
                prepared.feature_flags,
                prepared.task.run_history_id,
            )
            .await
            .map(|status| match status {
                ReviewRunStatus::Completed => ReviewScheduleOutcome::Scheduled,
                ReviewRunStatus::QuotaDeferred => ReviewScheduleOutcome::SkippedQuota,
            })
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
        self.policy.flow_name()
    }

    async fn clear_stale_in_progress(&self) -> Result<()> {
        ReviewFlow::clear_stale_in_progress(self).await
    }

    async fn recover_in_progress(&self) -> Result<()> {
        ReviewFlow::recover_in_progress(self).await
    }
}

pub(crate) struct ReviewRunContext {
    pub(crate) lane: ReviewLane,
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) award_service: AwardService,
    pub(crate) policy: Arc<dyn ReviewLanePolicy>,
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
        self.policy.uses_awards()
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

    async fn resolve_review_project_path(&self, repo: &str, mr: &MergeRequest) -> String {
        let Some(source_project_id) = mr.source_project_id else {
            return repo.to_string();
        };
        if mr.target_project_id == Some(source_project_id) {
            return repo.to_string();
        }

        match self
            .gitlab
            .get_project(&source_project_id.to_string())
            .await
        {
            Ok(project) => {
                if let Some(path_with_namespace) = project
                    .path_with_namespace
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    path_with_namespace.to_string()
                } else {
                    warn!(
                        repo,
                        iid = mr.iid,
                        source_project_id,
                        "source project path missing for fork MR; disabling GitLab discovery for this run"
                    );
                    String::new()
                }
            }
            Err(err) => {
                warn!(
                    repo,
                    iid = mr.iid,
                    source_project_id,
                    error = %err,
                    "failed to resolve source project path for fork MR; disabling GitLab discovery for this run"
                );
                String::new()
            }
        }
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
        self.retry_backoff.clear(retry_key);
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
        self.retry_backoff.clear(run.retry_key);
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

    async fn finalize_setup_failure(
        &self,
        repo: &str,
        iid: u64,
        head_sha: &str,
        run_history_id: i64,
        err: &anyhow::Error,
    ) {
        if let Err(recovery_err) =
            refund_review_rate_limits(&self.state, &self.acquired_rate_limit_rule_ids).await
        {
            warn!(
                repo = repo,
                iid = iid,
                head_sha = head_sha,
                error = %recovery_err,
                "failed to refund rate limit rules after queued review setup error"
            );
        }
        if let Err(recovery_err) = self
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
                "failed to release review lock after queued review setup error"
            );
        }
        let task = ScheduledTaskContext::new(repo, iid, head_sha, run_history_id);
        if let Err(recovery_err) = finish_task_run_history(
            &self.state,
            &task,
            task_error_finish(
                ReviewRunResult::Error.as_str(),
                self.review_preview(repo, iid),
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
                "failed to finalize run history after queued review setup error"
            );
        }
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
        ReviewContext {
            lane: self.lane,
            repo: repo.to_string(),
            project_path,
            mr: mr.clone(),
            head_sha: head_sha.to_string(),
            feature_flags,
            additional_developer_instructions: self
                .policy
                .additional_developer_instructions(&self.config),
            min_confidence_score: self.policy.min_confidence_score(&self.config),
            security_context_ttl_seconds: self.policy.context_ttl_seconds(&self.config),
            run_history_id: Some(run_history_id),
        }
    }

    async fn build_codex_review_context_for_run(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        feature_flags: FeatureFlagSnapshot,
        run_history_id: i64,
    ) -> ReviewContext {
        let project_path = if self.policy.resolves_review_project_path() {
            self.resolve_review_project_path(repo, mr).await
        } else {
            repo.to_string()
        };
        self.build_codex_review_context(
            repo,
            mr,
            head_sha,
            project_path,
            feature_flags,
            run_history_id,
        )
    }

    async fn record_outcome(
        &self,
        run: &ReviewRunIdentity<'_>,
        clear_retry_key: bool,
        result: ReviewRunResult,
        mut finish: RunHistoryFinish,
    ) -> Result<()> {
        if clear_retry_key {
            self.retry_backoff.clear(run.retry_key);
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
                .create_award(run.repo, run.iid, &self.config.review.thumbs_emoji)
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
        review_project_path: &str,
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
                project_path: review_project_path,
                repo: run.repo,
                mr,
                head_sha: run.head_sha,
                comment: &comment,
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

    async fn handle_error(&self, run: &ReviewRunIdentity<'_>, err: Error) -> Result<()> {
        let next_retry_at = self
            .retry_backoff
            .record_failure((*run.retry_key).clone(), Utc::now());
        error!(
            repo = run.repo,
            iid = run.iid,
            error = ?err,
            next_retry_at = %next_retry_at,
            "review failed"
        );
        if self.bail_if_cancelled(run).await? {
            return Ok(());
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
    ) -> Result<ReviewRunStatus> {
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
            return Ok(ReviewRunStatus::Completed);
        }

        self.add_eyes_best_effort(repo, mr.iid).await;
        let review_ctx = self
            .build_codex_review_context_for_run(repo, &mr, head_sha, feature_flags, run_history_id)
            .await;
        let review_project_path = review_ctx.project_path.clone();

        if self.bail_if_start_rejected(&run_identity).await? {
            return Ok(ReviewRunStatus::Completed);
        }

        let _started_run = self.lifecycle.track_started_run();
        let result = self.codex.run_review(review_ctx).await;
        if self.bail_if_cancelled(&run_identity).await? {
            return Ok(ReviewRunStatus::Completed);
        }
        self.remove_eyes_best_effort(repo, mr.iid).await;
        if self.bail_if_cancelled(&run_identity).await? {
            return Ok(ReviewRunStatus::Completed);
        }

        let status = match result {
            Ok(CodexResult::Pass { summary }) => {
                self.handle_pass(&run_identity, summary).await?;
                ReviewRunStatus::Completed
            }
            Ok(CodexResult::Comment(comment)) => {
                self.handle_comment(
                    &run_identity,
                    &mr,
                    inline_review_comments_enabled,
                    &review_project_path,
                    comment,
                )
                .await?;
                ReviewRunStatus::Completed
            }
            Err(err) => {
                if let Some(quota) = err.downcast_ref::<CodexQuotaExhausted>() {
                    let quota = quota.clone();
                    self.handle_quota_exhausted(&run_identity, &quota).await?;
                    ReviewRunStatus::QuotaDeferred
                } else {
                    self.handle_error(&run_identity, err).await?;
                    ReviewRunStatus::Completed
                }
            }
        };

        Ok(status)
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
            ReviewRunResult::Cancelled,
        ] {
            assert_eq!(ReviewRunResult::parse(result.as_str()), Some(result));
        }
    }
}

use crate::codex_runner::{CodexResult, ReviewComment, ReviewContext};
use crate::config::Config;
use crate::feature_flags::FeatureFlagSnapshot;
use crate::flow::review_comments::{PostReviewCommentRequest, post_review_comment};
use crate::flow::{ActiveReviewKey, FlowShared, MergeRequestFlow};
use crate::gitlab::{AwardEmoji, GitLabApi, MergeRequest, MergeRequestDiscussion, Note};
use crate::lifecycle::ServiceLifecycle;
use crate::review_lane::ReviewLane;
use crate::state::{
    NewRunHistory, ReviewRateLimitAcquireOutcome, ReviewStateStore, RunHistoryFinish,
    RunHistoryKind,
};
use anyhow::{Error, Result};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

const INLINE_REVIEW_MARKER_PREFIX: &str = "<!-- codex-review-finding:sha=";

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
    run_history_id: i64,
    feature_flags: FeatureFlagSnapshot,
}

pub(crate) struct ReviewFlow {
    shared: FlowShared,
    retry_backoff: Arc<RetryBackoff>,
    lane: ReviewLane,
}

impl ReviewFlow {
    pub(crate) fn new(
        shared: FlowShared,
        retry_backoff: Arc<RetryBackoff>,
        lane: ReviewLane,
    ) -> Self {
        Self {
            shared,
            retry_backoff,
            lane,
        }
    }

    fn review_marker_prefix(&self) -> &str {
        if self.lane.is_security() {
            &self.shared.config.review.security.comment_marker_prefix
        } else {
            &self.shared.config.review.comment_marker_prefix
        }
    }

    fn finding_marker_prefix(&self) -> &str {
        if self.lane.is_security() {
            &self.shared.config.review.security.finding_marker_prefix
        } else {
            INLINE_REVIEW_MARKER_PREFIX
        }
    }

    fn uses_awards(&self) -> bool {
        !self.lane.is_security()
    }

    fn is_enabled(&self, feature_flags: &FeatureFlagSnapshot) -> bool {
        !self.lane.is_security() || feature_flags.security_review
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
                } else if let Err(err) = remove_bot_award(
                    self.shared.gitlab.as_ref(),
                    review.repo.as_str(),
                    review.iid,
                    self.shared.bot_user_id,
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
        let awards = self.shared.gitlab.list_awards(repo, iid).await?;
        Ok(has_bot_award(
            &awards,
            self.shared.bot_user_id,
            &self.shared.config.review.thumbs_emoji,
        ))
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
        if self.lane.is_security()
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
            kind: if self.lane.is_security() {
                RunHistoryKind::Security
            } else {
                RunHistoryKind::Review
            },
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
            run_history_id,
            feature_flags,
        })
    }

    fn run_context(&self, acquired_rate_limit_rule_ids: Vec<String>) -> ReviewRunContext {
        ReviewRunContext {
            lane: self.lane,
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
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
        repo_name: String,
        mr: MergeRequest,
        head_sha: String,
        prepared: PreparedReviewRun,
        acquired_rule_ids: Vec<String>,
        tasks: &mut Vec<JoinHandle<()>>,
    ) {
        let semaphore = Arc::clone(&self.shared.semaphore);
        let active_tasks = Arc::clone(&self.shared.active_tasks);
        let review_context = self.run_context(acquired_rule_ids);
        let active_review = active_tasks.track_review(ActiveReviewKey {
            lane: review_context.lane,
            repo: repo_name.clone(),
            iid: mr.iid,
            head_sha: head_sha.clone(),
        });
        tasks.push(tokio::spawn(async move {
            let _active_review = active_review;
            let Ok(_permit) = semaphore.acquire_owned().await else {
                let err = Error::msg("review cancelled: semaphore closed");
                review_context
                    .finalize_setup_failure(
                        &repo_name,
                        mr.iid,
                        &head_sha,
                        prepared.run_history_id,
                        &err,
                    )
                    .await;
                return;
            };
            if let Err(err) = review_context
                .run(
                    &repo_name,
                    mr,
                    &head_sha,
                    prepared.feature_flags,
                    prepared.run_history_id,
                )
                .await
            {
                warn!(repo = repo_name.as_str(), error = %err, "review failed");
            }
        }));
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
            prepared.run_history_id,
            &acquired_rule_ids,
        )
        .await?;
        self.spawn_scheduled_review_task(
            repo.to_string(),
            mr,
            head_sha.to_string(),
            prepared,
            acquired_rule_ids,
            tasks,
        );
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
                prepared.run_history_id,
                &acquired_rule_ids,
            )
            .await?;
        self.clear_review_rate_limit_pending_or_abort(
            repo,
            mr.iid,
            head_sha,
            prepared.run_history_id,
            &acquired_rule_ids,
        )
        .await?;
        let review_context = self.run_context(acquired_rule_ids.clone());
        let _active_review = self.shared.active_tasks.track_review(ActiveReviewKey {
            lane: self.lane,
            repo: repo.to_string(),
            iid: mr.iid,
            head_sha: head_sha.to_string(),
        });
        review_context
            .run(
                repo,
                mr,
                head_sha,
                prepared.feature_flags,
                prepared.run_history_id,
            )
            .await?;
        Ok(ReviewScheduleOutcome::Scheduled)
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
        if let Err(err) = ensure_bot_award(
            self.shared.gitlab.as_ref(),
            repo,
            iid,
            self.shared.bot_user_id,
            &self.shared.config.review.rate_limit_emoji,
        )
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

    async fn remove_rate_limit_award_best_effort(&self, repo: &str, iid: u64) {
        if self.shared.config.review.dry_run || !self.uses_awards() {
            return;
        }
        if let Err(err) = remove_bot_award(
            self.shared.gitlab.as_ref(),
            repo,
            iid,
            self.shared.bot_user_id,
            &self.shared.config.review.rate_limit_emoji,
        )
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
        if !acquired_rule_ids.is_empty()
            && let Err(recovery_err) = self
                .shared
                .state
                .review_rate_limit
                .refund_review_rate_limit_buckets(acquired_rule_ids, Utc::now().timestamp())
                .await
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
        if let Err(recovery_err) = self
            .shared
            .state
            .run_history
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: ReviewRunResult::Error.as_str().to_string(),
                    preview: Some(format!("{} {repo} !{iid}", self.lane.review_label())),
                    error: Some(format!("{err:#}")),
                    ..RunHistoryFinish::default()
                },
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
        if self.lane.is_security() {
            "security_review"
        } else {
            "review"
        }
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
        !self.lane.is_security()
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
        if let Err(err) = remove_bot_award(
            self.gitlab.as_ref(),
            repo,
            iid,
            self.bot_user_id,
            &self.config.review.eyes_emoji,
        )
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
        if let Err(err) = ensure_bot_award(
            self.gitlab.as_ref(),
            repo,
            iid,
            self.bot_user_id,
            &self.config.review.eyes_emoji,
        )
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
        if !self.acquired_rate_limit_rule_ids.is_empty() {
            self.state
                .review_rate_limit
                .refund_review_rate_limit_buckets(
                    &self.acquired_rate_limit_rule_ids,
                    Utc::now().timestamp(),
                )
                .await?;
        }
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
        self.state
            .run_history
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: ReviewRunResult::Cancelled.as_str().to_string(),
                    preview: Some(self.review_preview(repo, iid)),
                    ..RunHistoryFinish::default()
                },
            )
            .await?;
        info!(repo = repo, iid = iid, "review cancelled due to shutdown");
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
        if !self.acquired_rate_limit_rule_ids.is_empty()
            && let Err(recovery_err) = self
                .state
                .review_rate_limit
                .refund_review_rate_limit_buckets(
                    &self.acquired_rate_limit_rule_ids,
                    Utc::now().timestamp(),
                )
                .await
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
        if let Err(recovery_err) = self
            .state
            .run_history
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: ReviewRunResult::Error.as_str().to_string(),
                    preview: Some(self.review_preview(repo, iid)),
                    error: Some(format!("{err:#}")),
                    ..RunHistoryFinish::default()
                },
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
            additional_developer_instructions: if self.lane.is_security() {
                self.config
                    .review
                    .security
                    .additional_developer_instructions
                    .clone()
            } else {
                None
            },
            min_confidence_score: self
                .lane
                .is_security()
                .then_some(self.config.review.security.min_confidence_score),
            security_context_ttl_seconds: self
                .lane
                .is_security()
                .then_some(self.config.review.security.context_ttl_seconds),
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
        let project_path = if self.lane.is_security() {
            repo.to_string()
        } else {
            self.resolve_review_project_path(repo, mr).await
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
        self.state
            .run_history
            .finish_run_history(run.run_history_id, finish)
            .await
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
            self.gitlab
                .add_award(run.repo, run.iid, &self.config.review.thumbs_emoji)
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
            RunHistoryFinish {
                preview: Some(self.review_preview(run.repo, run.iid)),
                error: Some(format!("{err:#}")),
                ..RunHistoryFinish::default()
            },
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

        self.add_eyes_best_effort(repo, mr.iid).await;
        let review_ctx = self
            .build_codex_review_context_for_run(repo, &mr, head_sha, feature_flags, run_history_id)
            .await;
        let review_project_path = review_ctx.project_path.clone();

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
                self.handle_pass(&run_identity, summary).await?;
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
            }
            Err(err) => {
                self.handle_error(&run_identity, err).await?;
            }
        }

        Ok(())
    }
}

pub(crate) fn has_bot_award(awards: &[AwardEmoji], bot_user_id: u64, name: &str) -> bool {
    if bot_user_id == 0 {
        return false;
    }
    awards
        .iter()
        .any(|award| award.user.id == bot_user_id && award.name == name)
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

pub(crate) async fn ensure_bot_award(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    bot_user_id: u64,
    award_name: &str,
) -> Result<()> {
    if bot_user_id == 0 {
        return Ok(());
    }
    let awards = gitlab.list_awards(repo, iid).await?;
    if awards
        .iter()
        .any(|award| award.user.id == bot_user_id && award.name == award_name)
    {
        return Ok(());
    }
    gitlab.add_award(repo, iid, award_name).await?;
    Ok(())
}

pub(crate) async fn remove_bot_award(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    bot_user_id: u64,
    award_name: &str,
) -> Result<()> {
    if bot_user_id == 0 {
        return Ok(());
    }
    let awards = gitlab.list_awards(repo, iid).await?;
    for award in awards {
        if award.user.id == bot_user_id && award.name == award_name {
            gitlab.delete_award(repo, iid, award.id).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ReviewRunContext, ReviewRunResult};
    use crate::codex_runner::{
        CodexResult, CodexRunner, MentionCommandContext, MentionCommandResult, ReviewContext,
    };
    use crate::config::{
        CodexConfig, Config, DatabaseConfig, DepsConfig, DockerConfig, GitLabConfig, GitLabTargets,
        McpServerOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ReviewSecurityConfig,
        ScheduleConfig, ServerConfig, SessionOverridesConfig, TargetSelector, WorkTmpfsConfig,
    };
    use crate::feature_flags::FeatureFlagDefaults;
    use crate::gitlab::{
        AwardEmoji, GitLabApi, GitLabProject, GitLabProjectSummary, GitLabUser, MergeRequest, Note,
    };
    use crate::lifecycle::ServiceLifecycle;
    use crate::review_lane::ReviewLane;
    use crate::state::ReviewStateStore;
    use anyhow::{Result, anyhow, bail};
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct AwardRecordingGitLab {
        bot_user: GitLabUser,
        awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
        add_award_calls: Mutex<Vec<String>>,
    }

    impl AwardRecordingGitLab {
        fn new(bot_user_id: u64) -> Self {
            Self {
                bot_user: GitLabUser {
                    id: bot_user_id,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
                awards: Mutex::new(HashMap::new()),
                add_award_calls: Mutex::new(Vec::new()),
            }
        }

        fn add_award_call_count(&self, repo: &str, iid: u64, award_name: &str) -> usize {
            let expected = format!("add_award:{repo}:{iid}:{award_name}");
            self.add_award_calls
                .lock()
                .unwrap()
                .iter()
                .filter(|call| *call == &expected)
                .count()
        }
    }

    #[async_trait]
    impl GitLabApi for AwardRecordingGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            Ok(self.bot_user.clone())
        }

        async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_group_projects(&self, _group: &str) -> Result<Vec<GitLabProjectSummary>> {
            Ok(Vec::new())
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
            Ok(Vec::new())
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<MergeRequest>> {
            Ok(None)
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
            Err(anyhow!("get_mr is not used by this test"))
        }

        async fn get_project(&self, project: &str) -> Result<GitLabProject> {
            Ok(GitLabProject {
                path_with_namespace: Some(project.to_string()),
                web_url: None,
                default_branch: None,
                last_activity_at: None,
            })
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            Ok(self
                .awards
                .lock()
                .unwrap()
                .get(&(project.to_string(), iid))
                .cloned()
                .unwrap_or_default())
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.add_award_calls
                .lock()
                .unwrap()
                .push(format!("add_award:{project}:{iid}:{name}"));
            let mut awards = self.awards.lock().unwrap();
            let entry = awards.entry((project.to_string(), iid)).or_default();
            entry.push(AwardEmoji {
                id: entry.len() as u64 + 1,
                name: name.to_string(),
                user: self.bot_user.clone(),
            });
            Ok(())
        }

        async fn delete_award(&self, _project: &str, _iid: u64, _award_id: u64) -> Result<()> {
            bail!("delete_award is not used by this test")
        }

        async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<Note>> {
            Ok(Vec::new())
        }

        async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
            bail!("create_note is not used by this test")
        }
    }

    struct UnusedCodexRunner;

    #[async_trait]
    impl CodexRunner for UnusedCodexRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            bail!("run_review is not used by this test")
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            bail!("run_mention_command is not used by this test")
        }
    }

    fn test_config() -> Config {
        Config {
            feature_flags: FeatureFlagDefaults::default(),
            gitlab: GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets {
                    repos: TargetSelector::List(vec!["group/repo".to_string()]),
                    ..Default::default()
                },
            },
            schedule: ScheduleConfig {
                cron: "* * * * *".to_string(),
                timezone: None,
            },
            review: ReviewConfig {
                max_concurrent: 1,
                eyes_emoji: "eyes".to_string(),
                thumbs_emoji: "thumbsup".to_string(),
                rate_limit_emoji: "hourglass_flowing_sand".to_string(),
                comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                stale_in_progress_minutes: 60,
                dry_run: false,
                additional_developer_instructions: None,
                security: ReviewSecurityConfig::default(),
                mention_commands: ReviewMentionCommandsConfig::default(),
            },
            codex: CodexConfig {
                image: "ghcr.io/openai/codex-universal:latest".to_string(),
                timeout_seconds: 300,
                auth_host_path: "/root/.codex".to_string(),
                auth_mount_path: "/root/.codex".to_string(),
                session_history_path: None,
                exec_sandbox: "danger-full-access".to_string(),
                fallback_auth_accounts: Vec::new(),
                usage_limit_fallback_cooldown_seconds: 3600,
                deps: DepsConfig { enabled: false },
                browser_mcp: crate::config::BrowserMcpConfig::default(),
                work_tmpfs: WorkTmpfsConfig::default(),
                gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                session_overrides: SessionOverridesConfig::default(),
                reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
            },
            docker: DockerConfig {
                host: "tcp://localhost:2375".to_string(),
            },
            database: DatabaseConfig {
                path: ":memory:".to_string(),
            },
            server: ServerConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                status_ui_enabled: false,
            },
        }
    }

    async fn review_run_context(
        gitlab: Arc<dyn GitLabApi>,
        bot_user_id: u64,
    ) -> Result<ReviewRunContext> {
        Ok(ReviewRunContext {
            lane: ReviewLane::General,
            config: test_config(),
            gitlab,
            codex: Arc::new(UnusedCodexRunner),
            state: Arc::new(ReviewStateStore::new(":memory:").await?),
            retry_backoff: Arc::new(super::RetryBackoff::new(chrono::Duration::seconds(60))),
            bot_user_id,
            lifecycle: Arc::new(ServiceLifecycle::default()),
            acquired_rate_limit_rule_ids: Vec::new(),
        })
    }

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

    #[tokio::test]
    async fn add_eyes_best_effort_does_not_duplicate_existing_bot_award() -> Result<()> {
        let gitlab = Arc::new(AwardRecordingGitLab::new(1));
        let context = review_run_context(gitlab.clone(), 1).await?;

        context.add_eyes_best_effort("group/repo", 42).await;
        context.add_eyes_best_effort("group/repo", 42).await;

        assert_eq!(gitlab.add_award_call_count("group/repo", 42, "eyes"), 1);
        Ok(())
    }
}

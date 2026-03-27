use crate::codex_runner::{CodexResult, ReviewContext};
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

enum ReviewGateOutcome {
    Ready(ReviewGateReady),
    Decision(ReviewScheduleOutcome),
}

struct ReviewGateReady {
    acquired_rule_ids: Vec<String>,
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
            .clear_stale_in_progress(self.shared.config.review.stale_in_progress_minutes)
            .await
    }

    pub(crate) async fn recover_in_progress(&self) -> Result<()> {
        let in_progress = self.shared.state.list_in_progress_reviews().await?;
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
                    .finish_review_for_lane(
                        review.repo.as_str(),
                        review.iid,
                        review.head_sha.as_str(),
                        review.lane,
                        "cancelled",
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
        let retry_key = RetryKey::new(self.lane, repo, mr.iid, head_sha);
        if !self.retry_backoff.should_retry(&retry_key, Utc::now()) {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedBackoff,
            ));
        }
        if self.uses_awards() {
            let awards = self.shared.gitlab.list_awards(repo, mr.iid).await?;
            if has_bot_award(
                &awards,
                self.shared.bot_user_id,
                &self.shared.config.review.thumbs_emoji,
            ) {
                return Ok(ReviewGateOutcome::Decision(
                    ReviewScheduleOutcome::SkippedAward,
                ));
            }
        }
        let notes = self.shared.gitlab.list_notes(repo, mr.iid).await?;
        if has_review_marker(
            &notes,
            self.shared.bot_user_id,
            self.review_marker_prefix(),
            head_sha,
        ) {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedMarker,
            ));
        }
        let inline_review_comments_enabled = feature_flags.gitlab_inline_review_comments;
        let completed_inline_review = self
            .shared
            .state
            .has_completed_inline_review_for_lane(repo, mr.iid, head_sha, self.lane)
            .await?;
        let review_result = self
            .shared
            .state
            .review_result_for_lane(repo, mr.iid, head_sha, self.lane)
            .await?;
        if self.lane.is_security() && matches!(review_result.as_deref(), Some("pass" | "comment")) {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedCompleted,
            ));
        }
        let should_check_inline_markers =
            inline_review_comments_enabled || completed_inline_review || review_result.is_some();
        if should_check_inline_markers {
            match self.shared.gitlab.list_discussions(repo, mr.iid).await {
                Ok(discussions) => {
                    if has_inline_review_marker(
                        &discussions,
                        self.shared.bot_user_id,
                        head_sha,
                        self.finding_marker_prefix(),
                    ) && review_result.as_deref() != Some("error")
                        && (completed_inline_review || review_result.as_deref() == Some("comment"))
                    {
                        return Ok(ReviewGateOutcome::Decision(
                            ReviewScheduleOutcome::SkippedMarker,
                        ));
                    }
                }
                Err(err) => {
                    warn!(
                        repo,
                        iid = mr.iid,
                        head_sha,
                        error = %err,
                        "failed to load MR discussions while checking inline review markers"
                    );
                    if completed_inline_review {
                        return Ok(ReviewGateOutcome::Decision(
                            ReviewScheduleOutcome::SkippedMarker,
                        ));
                    }
                }
            }
        }
        if self
            .shared
            .state
            .has_in_progress_mention_for_mr(repo, mr.iid)
            .await?
        {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedLocked,
            ));
        }
        if !self
            .shared
            .state
            .begin_review_for_lane(repo, mr.iid, head_sha, self.lane)
            .await?
        {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedLocked,
            ));
        }
        let acquired_bucket_ids = match self
            .shared
            .state
            .try_consume_review_rate_limits(self.lane, repo, mr.iid, now)
            .await
        {
            Err(err) => {
                self.release_review_lock_after_gate_failure(repo, mr.iid, head_sha, &err)
                    .await;
                return Err(err);
            }
            Ok(ReviewRateLimitAcquireOutcome::Unmatched) => Vec::new(),
            Ok(ReviewRateLimitAcquireOutcome::Acquired { bucket_ids }) => bucket_ids,
            Ok(ReviewRateLimitAcquireOutcome::Blocked { next_retry_at }) => {
                self.shared
                    .state
                    .finish_review_for_lane(repo, mr.iid, head_sha, self.lane, "cancelled")
                    .await?;
                self.shared
                    .state
                    .upsert_review_rate_limit_pending(
                        self.lane,
                        repo,
                        mr.iid,
                        head_sha,
                        now,
                        next_retry_at,
                    )
                    .await?;
                self.ensure_rate_limit_award_best_effort(repo, mr.iid).await;
                return Ok(ReviewGateOutcome::Decision(
                    ReviewScheduleOutcome::SkippedRateLimit,
                ));
            }
        };
        if self.shared.shutdown_requested() {
            let refund_err = if acquired_bucket_ids.is_empty() {
                None
            } else {
                self.shared
                    .state
                    .refund_review_rate_limit_buckets(&acquired_bucket_ids, now)
                    .await
                    .err()
            };
            if let Err(lock_err) = self
                .shared
                .state
                .finish_review_for_lane(repo, mr.iid, head_sha, self.lane, "cancelled")
                .await
            {
                if let Some(refund_err) = refund_err {
                    warn!(
                        repo = repo,
                        iid = mr.iid,
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
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::Interrupted,
            ));
        }
        Ok(ReviewGateOutcome::Ready(ReviewGateReady {
            acquired_rule_ids: acquired_bucket_ids,
        }))
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
        let run_history_id = match self
            .shared
            .state
            .start_run_history_for_lane(
                NewRunHistory {
                    kind: if self.lane.is_security() {
                        RunHistoryKind::Security
                    } else {
                        RunHistoryKind::Review
                    },
                    repo: repo.to_string(),
                    iid: mr.iid,
                    head_sha: head_sha.to_string(),
                    discussion_id: None,
                    trigger_note_id: None,
                    trigger_note_author_name: None,
                    trigger_note_body: None,
                    command_repo: None,
                },
                Some(self.lane),
            )
            .await
        {
            Ok(run_history_id) => run_history_id,
            Err(err) => {
                self.release_review_lock_after_history_failure(
                    repo,
                    mr.iid,
                    head_sha,
                    &acquired_rule_ids,
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
                    mr.iid,
                    head_sha,
                    run_history_id,
                    &acquired_rule_ids,
                    &err,
                )
                .await;
                return Err(err);
            }
        };
        if let Err(err) = self
            .shared
            .state
            .set_run_history_feature_flags(run_history_id, &feature_flags)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                mr.iid,
                head_sha,
                run_history_id,
                &acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        if let Err(err) = self
            .clear_review_rate_limit_pending_if_needed(repo, mr.iid)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                mr.iid,
                head_sha,
                run_history_id,
                &acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        let repo_name = repo.to_string();
        let semaphore = Arc::clone(&self.shared.semaphore);
        let active_tasks = Arc::clone(&self.shared.active_tasks);
        let review_context = ReviewRunContext {
            lane: self.lane,
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            lifecycle: Arc::clone(&self.shared.lifecycle),
            acquired_rate_limit_rule_ids: acquired_rule_ids.clone(),
        };
        let head_sha = head_sha.to_string();
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
                    .finalize_setup_failure(&repo_name, mr.iid, &head_sha, run_history_id, &err)
                    .await;
                return;
            };
            if let Err(err) = review_context
                .run(&repo_name, mr, &head_sha, feature_flags, run_history_id)
                .await
            {
                warn!(repo = repo_name.as_str(), error = %err, "review failed");
            }
        }));
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
        let run_history_id = match self
            .shared
            .state
            .start_run_history_for_lane(
                NewRunHistory {
                    kind: if self.lane.is_security() {
                        RunHistoryKind::Security
                    } else {
                        RunHistoryKind::Review
                    },
                    repo: repo.to_string(),
                    iid: mr.iid,
                    head_sha: head_sha.to_string(),
                    discussion_id: None,
                    trigger_note_id: None,
                    trigger_note_author_name: None,
                    trigger_note_body: None,
                    command_repo: None,
                },
                Some(self.lane),
            )
            .await
        {
            Ok(run_history_id) => run_history_id,
            Err(err) => {
                self.release_review_lock_after_history_failure(
                    repo,
                    mr.iid,
                    head_sha,
                    &acquired_rule_ids,
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
                    mr.iid,
                    head_sha,
                    run_history_id,
                    &acquired_rule_ids,
                    &err,
                )
                .await;
                return Err(err);
            }
        };
        if let Err(err) = self
            .shared
            .state
            .set_run_history_feature_flags(run_history_id, &feature_flags)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                mr.iid,
                head_sha,
                run_history_id,
                &acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        let _permit = match self.shared.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => {
                let err = Error::from(err);
                self.abort_review_after_setup_failure(
                    repo,
                    mr.iid,
                    head_sha,
                    run_history_id,
                    &acquired_rule_ids,
                    &err,
                )
                .await;
                return Err(err);
            }
        };
        if let Err(err) = self
            .clear_review_rate_limit_pending_if_needed(repo, mr.iid)
            .await
        {
            self.abort_review_after_setup_failure(
                repo,
                mr.iid,
                head_sha,
                run_history_id,
                &acquired_rule_ids,
                &err,
            )
            .await;
            return Err(err);
        }
        let review_context = ReviewRunContext {
            lane: self.lane,
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            lifecycle: Arc::clone(&self.shared.lifecycle),
            acquired_rate_limit_rule_ids: acquired_rule_ids.clone(),
        };
        let _active_review = self.shared.active_tasks.track_review(ActiveReviewKey {
            lane: self.lane,
            repo: repo.to_string(),
            iid: mr.iid,
            head_sha: head_sha.to_string(),
        });
        review_context
            .run(repo, mr, head_sha, feature_flags, run_history_id)
            .await?;
        Ok(ReviewScheduleOutcome::Scheduled)
    }

    async fn resolve_feature_flags(&self) -> Result<FeatureFlagSnapshot> {
        let overrides = self
            .shared
            .state
            .get_runtime_feature_flag_overrides()
            .await?;
        Ok(self.shared.config.resolve_feature_flags(&overrides))
    }

    async fn clear_review_rate_limit_pending_if_needed(&self, repo: &str, iid: u64) -> Result<()> {
        let cleared = self
            .shared
            .state
            .clear_review_rate_limit_pending(self.lane, repo, iid)
            .await?;
        if cleared {
            self.remove_rate_limit_award_best_effort(repo, iid).await;
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
            .finish_review_for_lane(repo, iid, head_sha, self.lane, "error")
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
            .finish_review_for_lane(repo, iid, head_sha, self.lane, "error")
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
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: "error".to_string(),
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
                .refund_review_rate_limit_buckets(
                    &self.acquired_rate_limit_rule_ids,
                    Utc::now().timestamp(),
                )
                .await?;
        }
        self.retry_backoff.clear(retry_key);
        self.state
            .finish_review_for_lane(repo, iid, head_sha, self.lane, "cancelled")
            .await?;
        self.state
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: "cancelled".to_string(),
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
            .finish_review_for_lane(repo, iid, head_sha, self.lane, "error")
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
            .finish_run_history(
                run_history_id,
                RunHistoryFinish {
                    result: "error".to_string(),
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

    pub(crate) async fn run(
        &self,
        repo: &str,
        mr: MergeRequest,
        head_sha: &str,
        feature_flags: FeatureFlagSnapshot,
        run_history_id: i64,
    ) -> Result<()> {
        let retry_key = RetryKey::new(self.lane, repo, mr.iid, head_sha);
        let inline_review_comments_enabled = feature_flags.gitlab_inline_review_comments;
        if self.should_reject_new_starts() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                .await?;
            return Ok(());
        }

        if self.config.review.dry_run || !self.uses_awards() {
            info!(repo = repo, iid = mr.iid, "dry run: skipping eyes award");
        } else {
            self.gitlab
                .add_award(repo, mr.iid, &self.config.review.eyes_emoji)
                .await
                .ok();
        }

        let project_path = if self.lane.is_security() {
            repo.to_string()
        } else {
            self.resolve_review_project_path(repo, &mr).await
        };
        let review_ctx = ReviewContext {
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
        };
        let review_project_path = review_ctx.project_path.clone();

        if self.should_reject_new_starts() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                .await?;
            return Ok(());
        }

        let _started_run = self.lifecycle.track_started_run();
        let result = self.codex.run_review(review_ctx).await;
        if self.should_cancel_active_work() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                .await?;
            return Ok(());
        }
        self.remove_eyes_best_effort(repo, mr.iid).await;
        if self.should_cancel_active_work() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                .await?;
            return Ok(());
        }

        match result {
            Ok(CodexResult::Pass { summary }) => {
                if self.should_cancel_active_work() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                        .await?;
                    return Ok(());
                }
                if self.config.review.dry_run || !self.uses_awards() {
                    info!(repo = repo, iid = mr.iid, "dry run: skipping thumbs up");
                } else {
                    self.gitlab
                        .add_award(repo, mr.iid, &self.config.review.thumbs_emoji)
                        .await?;
                }
                self.retry_backoff.clear(&retry_key);
                let review_result = if self.config.review.dry_run {
                    "dry_run_pass"
                } else {
                    "pass"
                };
                self.state
                    .finish_review_for_lane(repo, mr.iid, head_sha, self.lane, review_result)
                    .await?;
                self.state
                    .finish_run_history(
                        run_history_id,
                        RunHistoryFinish {
                            result: review_result.to_string(),
                            preview: Some(self.review_preview(repo, mr.iid)),
                            summary: Some(summary.clone()),
                            ..RunHistoryFinish::default()
                        },
                    )
                    .await?;
                info!(
                    repo = repo,
                    iid = mr.iid,
                    summary = summary.as_str(),
                    "review pass"
                );
            }
            Ok(CodexResult::Comment(comment)) => {
                if self.should_cancel_active_work() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                        .await?;
                    return Ok(());
                }
                if self.config.review.dry_run {
                    info!(repo = repo, iid = mr.iid, "dry run: skipping comment");
                } else {
                    post_review_comment(PostReviewCommentRequest {
                        inline_review_comments_enabled,
                        lane: self.lane,
                        config: &self.config,
                        gitlab: self.gitlab.as_ref(),
                        bot_user_id: self.bot_user_id,
                        project_path: &review_project_path,
                        repo,
                        mr: &mr,
                        head_sha,
                        comment: &comment,
                    })
                    .await?;
                }
                self.retry_backoff.clear(&retry_key);
                let review_result = if self.config.review.dry_run {
                    "dry_run_comment"
                } else {
                    "comment"
                };
                self.state
                    .finish_review_for_lane(repo, mr.iid, head_sha, self.lane, review_result)
                    .await?;
                self.state
                    .finish_run_history(
                        run_history_id,
                        RunHistoryFinish {
                            result: review_result.to_string(),
                            preview: Some(self.review_preview(repo, mr.iid)),
                            summary: Some(comment.summary.clone()),
                            error: Some(comment.body.clone()),
                            ..RunHistoryFinish::default()
                        },
                    )
                    .await?;
                info!(
                    repo = repo,
                    iid = mr.iid,
                    summary = comment.summary.as_str(),
                    "review comment"
                );
            }
            Err(err) => {
                let next_retry_at = self
                    .retry_backoff
                    .record_failure(retry_key.clone(), Utc::now());
                error!(
                    repo = repo,
                    iid = mr.iid,
                    error = ?err,
                    next_retry_at = %next_retry_at,
                    "review failed"
                );
                if self.should_cancel_active_work() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key, run_history_id)
                        .await?;
                    return Ok(());
                }
                self.state
                    .finish_review_for_lane(repo, mr.iid, head_sha, self.lane, "error")
                    .await?;
                self.state
                    .finish_run_history(
                        run_history_id,
                        RunHistoryFinish {
                            result: "error".to_string(),
                            preview: Some(self.review_preview(repo, mr.iid)),
                            error: Some(err.to_string()),
                            ..RunHistoryFinish::default()
                        },
                    )
                    .await?;
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

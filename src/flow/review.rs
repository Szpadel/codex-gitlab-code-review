use crate::codex_runner::{CodexResult, ReviewContext};
use crate::config::Config;
use crate::flow::{FlowShared, MergeRequestFlow};
use crate::gitlab::{AwardEmoji, GitLabApi, MergeRequest, Note};
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct RetryKey {
    repo: String,
    iid: u64,
    head_sha: String,
}

impl RetryKey {
    pub(crate) fn new(repo: &str, iid: u64, head_sha: &str) -> Self {
        Self {
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
        let failures = entries
            .get(&key)
            .map(|state| state.failures + 1)
            .unwrap_or(1);
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
    SkippedBackoff,
    SkippedAward,
    SkippedMarker,
    SkippedLocked,
    Interrupted,
}

enum ReviewGateOutcome {
    Ready,
    Decision(ReviewScheduleOutcome),
}

pub(crate) struct ReviewFlow {
    shared: FlowShared,
    retry_backoff: Arc<RetryBackoff>,
}

impl ReviewFlow {
    pub(crate) fn new(shared: FlowShared, retry_backoff: Arc<RetryBackoff>) -> Self {
        Self {
            shared,
            retry_backoff,
        }
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
                let retry_key =
                    RetryKey::new(review.repo.as_str(), review.iid, review.head_sha.as_str());
                if self.shared.config.review.dry_run {
                    info!(
                        repo = review.repo.as_str(),
                        iid = review.iid,
                        "dry run: skipping eyes removal during recovery"
                    );
                } else if let Err(err) = remove_eyes(
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
                    .finish_review(
                        review.repo.as_str(),
                        review.iid,
                        review.head_sha.as_str(),
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
        let retry_key = RetryKey::new(repo, mr.iid, head_sha);
        if !self.retry_backoff.should_retry(&retry_key, Utc::now()) {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedBackoff,
            ));
        }
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
        let notes = self.shared.gitlab.list_notes(repo, mr.iid).await?;
        if has_review_marker(
            &notes,
            self.shared.bot_user_id,
            &self.shared.config.review.comment_marker_prefix,
            head_sha,
        ) {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedMarker,
            ));
        }
        if !self
            .shared
            .state
            .begin_review(repo, mr.iid, head_sha)
            .await?
        {
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::SkippedLocked,
            ));
        }
        if self.shared.shutdown_requested() {
            self.shared
                .state
                .finish_review(repo, mr.iid, head_sha, "cancelled")
                .await?;
            return Ok(ReviewGateOutcome::Decision(
                ReviewScheduleOutcome::Interrupted,
            ));
        }
        Ok(ReviewGateOutcome::Ready)
    }

    pub(crate) async fn schedule_for_scan(
        &self,
        repo: &str,
        mr: MergeRequest,
        head_sha: &str,
        tasks: &mut Vec<JoinHandle<()>>,
    ) -> Result<ReviewScheduleOutcome> {
        match self.evaluate_review_gate(repo, &mr, head_sha).await? {
            ReviewGateOutcome::Decision(decision) => return Ok(decision),
            ReviewGateOutcome::Ready => {}
        }
        let permit = self.shared.semaphore.clone().acquire_owned().await?;
        let repo_name = repo.to_string();
        let review_context = ReviewRunContext {
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            shutdown: Arc::clone(&self.shared.shutdown),
        };
        let head_sha = head_sha.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = review_context.run(&repo_name, mr, &head_sha).await {
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
        match self.evaluate_review_gate(repo, &mr, head_sha).await? {
            ReviewGateOutcome::Decision(decision) => return Ok(decision),
            ReviewGateOutcome::Ready => {}
        }
        let _permit = self.shared.semaphore.clone().acquire_owned().await?;
        let review_context = ReviewRunContext {
            config: self.shared.config.clone(),
            gitlab: Arc::clone(&self.shared.gitlab),
            codex: Arc::clone(&self.shared.codex),
            state: Arc::clone(&self.shared.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.shared.bot_user_id,
            shutdown: Arc::clone(&self.shared.shutdown),
        };
        review_context.run(repo, mr, head_sha).await?;
        Ok(ReviewScheduleOutcome::Scheduled)
    }
}

#[async_trait]
impl MergeRequestFlow for ReviewFlow {
    fn flow_name(&self) -> &'static str {
        "review"
    }

    async fn clear_stale_in_progress(&self) -> Result<()> {
        ReviewFlow::clear_stale_in_progress(self).await
    }

    async fn recover_in_progress(&self) -> Result<()> {
        ReviewFlow::recover_in_progress(self).await
    }
}

pub(crate) struct ReviewRunContext {
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) codex: Arc<dyn crate::codex_runner::CodexRunner>,
    pub(crate) state: Arc<ReviewStateStore>,
    pub(crate) retry_backoff: Arc<RetryBackoff>,
    pub(crate) bot_user_id: u64,
    pub(crate) shutdown: Arc<AtomicBool>,
}

impl ReviewRunContext {
    fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    async fn remove_eyes_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run {
            info!(repo = repo, iid = iid, "dry run: skipping eyes removal");
            return;
        }
        if let Err(err) = remove_eyes(
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
    ) -> Result<()> {
        self.remove_eyes_best_effort(repo, iid).await;
        self.retry_backoff.clear(retry_key);
        self.state
            .finish_review(repo, iid, head_sha, "cancelled")
            .await?;
        info!(repo = repo, iid = iid, "review cancelled due to shutdown");
        Ok(())
    }

    pub(crate) async fn run(&self, repo: &str, mr: MergeRequest, head_sha: &str) -> Result<()> {
        let retry_key = RetryKey::new(repo, mr.iid, head_sha);
        if self.shutdown_requested() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                .await?;
            return Ok(());
        }

        if self.config.review.dry_run {
            info!(repo = repo, iid = mr.iid, "dry run: skipping eyes award");
        } else {
            self.gitlab
                .add_award(repo, mr.iid, &self.config.review.eyes_emoji)
                .await
                .ok();
        }

        let review_ctx = ReviewContext {
            repo: repo.to_string(),
            project_path: repo.to_string(),
            mr: mr.clone(),
            head_sha: head_sha.to_string(),
        };

        if self.shutdown_requested() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                .await?;
            return Ok(());
        }

        let result = self.codex.run_review(review_ctx).await;
        if self.shutdown_requested() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                .await?;
            return Ok(());
        }
        self.remove_eyes_best_effort(repo, mr.iid).await;
        if self.shutdown_requested() {
            self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                .await?;
            return Ok(());
        }

        match result {
            Ok(CodexResult::Pass { summary }) => {
                if self.shutdown_requested() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                        .await?;
                    return Ok(());
                }
                if self.config.review.dry_run {
                    info!(repo = repo, iid = mr.iid, "dry run: skipping thumbs up");
                } else {
                    self.gitlab
                        .add_award(repo, mr.iid, &self.config.review.thumbs_emoji)
                        .await?;
                }
                self.retry_backoff.clear(&retry_key);
                self.state
                    .finish_review(repo, mr.iid, head_sha, "pass")
                    .await?;
                info!(
                    repo = repo,
                    iid = mr.iid,
                    summary = summary.as_str(),
                    "review pass"
                );
            }
            Ok(CodexResult::Comment { summary, body }) => {
                if self.shutdown_requested() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                        .await?;
                    return Ok(());
                }
                let full_body = format!(
                    "{}\n\n{}{} -->",
                    body, self.config.review.comment_marker_prefix, head_sha
                );
                if self.config.review.dry_run {
                    info!(repo = repo, iid = mr.iid, "dry run: skipping comment");
                } else {
                    self.gitlab.create_note(repo, mr.iid, &full_body).await?;
                }
                self.retry_backoff.clear(&retry_key);
                self.state
                    .finish_review(repo, mr.iid, head_sha, "comment")
                    .await?;
                info!(
                    repo = repo,
                    iid = mr.iid,
                    summary = summary.as_str(),
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
                if self.shutdown_requested() {
                    self.finalize_cancelled(repo, mr.iid, head_sha, &retry_key)
                        .await?;
                    return Ok(());
                }
                self.state
                    .finish_review(repo, mr.iid, head_sha, "error")
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
    let marker = format!("{}{} -->", prefix, sha);
    notes
        .iter()
        .any(|note| note.author.id == bot_user_id && note.body.contains(&marker))
}

pub(crate) async fn remove_eyes(
    gitlab: &dyn GitLabApi,
    repo: &str,
    iid: u64,
    bot_user_id: u64,
    eyes: &str,
) -> Result<()> {
    let awards = gitlab.list_awards(repo, iid).await?;
    for award in awards {
        if award.user.id == bot_user_id && award.name == eyes {
            gitlab.delete_award(repo, iid, award.id).await?;
        }
    }
    Ok(())
}

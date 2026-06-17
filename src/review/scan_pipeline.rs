use super::ReviewLane;
use super::service::{NO_OPEN_MRS_MARKER, ReviewService, ScanMode, ScanRunStatus};
use crate::flow::mention::MentionScheduleOutcome;
use crate::flow::review::ReviewScheduleOutcome;
use anyhow::Result;
use chrono::Utc;
use futures::future::join_all;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepoScanStatus {
    Complete,
    PendingSameMrWork,
    Interrupted,
}

#[derive(Default)]
pub(super) struct ScanCounters {
    total_mrs: usize,
    scheduled: usize,
    security_scheduled: usize,
    mention_scheduled: usize,
    skipped_award: usize,
    skipped_marker: usize,
    skipped_completed: usize,
    skipped_locked: usize,
    skipped_rate_limit: usize,
    skipped_quota: usize,
    security_skipped_marker: usize,
    security_skipped_completed: usize,
    security_skipped_locked: usize,
    security_skipped_backoff: usize,
    security_skipped_rate_limit: usize,
    security_skipped_quota: usize,
    mention_skipped_processed: usize,
    mention_quota_blocked: usize,
    skipped_backoff: usize,
    missing_sha: usize,
    skipped_inactive: usize,
    skipped_draft: usize,
    skipped_created_before: usize,
}

#[derive(Default)]
struct ScanContext {
    counters: ScanCounters,
    tasks: Vec<JoinHandle<()>>,
    interrupted: bool,
}

impl ScanContext {
    fn record_mention_outcome(&mut self, outcome: MentionScheduleOutcome) {
        self.counters.mention_scheduled += outcome.scheduled;
        self.counters.mention_skipped_processed += outcome.skipped_processed;
        self.counters.mention_quota_blocked += outcome.quota_blocked;
    }

    fn apply_review_outcome(
        &mut self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        outcome: ReviewScheduleOutcome,
        pending_same_mr_work: &mut bool,
    ) -> Option<RepoScanStatus> {
        match (lane, outcome) {
            (_, ReviewScheduleOutcome::Scheduled) => {
                if lane.is_security() {
                    self.counters.security_scheduled += 1;
                } else {
                    self.counters.scheduled += 1;
                }
            }
            (_, ReviewScheduleOutcome::Disabled) => {}
            (ReviewLane::General, ReviewScheduleOutcome::SkippedBackoff) => {
                self.counters.skipped_backoff += 1;
                debug!(repo = repo, iid = iid, "skip: review backoff active");
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedBackoff) => {
                self.counters.security_skipped_backoff += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review backoff active"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedRateLimit) => {
                self.counters.skipped_rate_limit += 1;
                debug!(repo = repo, iid = iid, "skip: review rate limit active");
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedRateLimit) => {
                self.counters.security_skipped_rate_limit += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review rate limit active"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedQuota) => {
                self.counters.skipped_quota += 1;
                debug!(repo = repo, iid = iid, "skip: codex quota exhausted");
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedQuota) => {
                self.counters.security_skipped_quota += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: codex quota exhausted for security review"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedAward) => {
                self.counters.skipped_award += 1;
                debug!(repo = repo, iid = iid, "skip: thumbs up already present");
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedMarker) => {
                self.counters.skipped_marker += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: review marker already present"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedMarker) => {
                self.counters.security_skipped_marker += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review marker already present"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedCompleted) => {
                self.counters.skipped_completed += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: review already completed for this SHA"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedCompleted) => {
                self.counters.security_skipped_completed += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review already completed for this SHA"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedLocked) => {
                self.counters.skipped_locked += 1;
                *pending_same_mr_work = true;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: same-MR work already in progress"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedLocked) => {
                self.counters.security_skipped_locked += 1;
                *pending_same_mr_work = true;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: same-MR work already in progress for security review"
                );
            }
            (_, ReviewScheduleOutcome::Interrupted) => {
                return Some(RepoScanStatus::Interrupted);
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedAward) => {
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review returned award outcome"
                );
            }
        }
        None
    }

    fn mark_interrupted(&mut self) {
        self.interrupted = true;
    }

    fn run_status(&self) -> ScanRunStatus {
        if self.interrupted {
            ScanRunStatus::Interrupted
        } else {
            ScanRunStatus::Completed
        }
    }

    fn log_completion(&self, mode: ScanMode) {
        match mode {
            ScanMode::Full => {
                info!(
                    total_mrs = self.counters.total_mrs,
                    scheduled = self.counters.scheduled,
                    security_scheduled = self.counters.security_scheduled,
                    mention_scheduled = self.counters.mention_scheduled,
                    skipped_award = self.counters.skipped_award,
                    skipped_marker = self.counters.skipped_marker,
                    skipped_completed = self.counters.skipped_completed,
                    skipped_locked = self.counters.skipped_locked,
                    skipped_rate_limit = self.counters.skipped_rate_limit,
                    skipped_quota = self.counters.skipped_quota,
                    security_skipped_marker = self.counters.security_skipped_marker,
                    security_skipped_completed = self.counters.security_skipped_completed,
                    security_skipped_locked = self.counters.security_skipped_locked,
                    security_skipped_backoff = self.counters.security_skipped_backoff,
                    security_skipped_rate_limit = self.counters.security_skipped_rate_limit,
                    security_skipped_quota = self.counters.security_skipped_quota,
                    mention_skipped_processed = self.counters.mention_skipped_processed,
                    mention_quota_blocked = self.counters.mention_quota_blocked,
                    skipped_backoff = self.counters.skipped_backoff,
                    missing_sha = self.counters.missing_sha,
                    skipped_draft = self.counters.skipped_draft,
                    skipped_created_before = self.counters.skipped_created_before,
                    "scan complete"
                );
            }
            ScanMode::Incremental => {
                info!(
                    total_mrs = self.counters.total_mrs,
                    scheduled = self.counters.scheduled,
                    security_scheduled = self.counters.security_scheduled,
                    mention_scheduled = self.counters.mention_scheduled,
                    skipped_award = self.counters.skipped_award,
                    skipped_marker = self.counters.skipped_marker,
                    skipped_completed = self.counters.skipped_completed,
                    skipped_locked = self.counters.skipped_locked,
                    skipped_rate_limit = self.counters.skipped_rate_limit,
                    skipped_quota = self.counters.skipped_quota,
                    security_skipped_marker = self.counters.security_skipped_marker,
                    security_skipped_completed = self.counters.security_skipped_completed,
                    security_skipped_locked = self.counters.security_skipped_locked,
                    security_skipped_backoff = self.counters.security_skipped_backoff,
                    security_skipped_rate_limit = self.counters.security_skipped_rate_limit,
                    security_skipped_quota = self.counters.security_skipped_quota,
                    mention_skipped_processed = self.counters.mention_skipped_processed,
                    mention_quota_blocked = self.counters.mention_quota_blocked,
                    skipped_backoff = self.counters.skipped_backoff,
                    missing_sha = self.counters.missing_sha,
                    skipped_inactive = self.counters.skipped_inactive,
                    skipped_draft = self.counters.skipped_draft,
                    skipped_created_before = self.counters.skipped_created_before,
                    "scan complete"
                );
            }
        }
    }
}

struct ScanPipeline<'a> {
    service: &'a ReviewService,
    mode: ScanMode,
    context: ScanContext,
}

impl<'a> ScanPipeline<'a> {
    fn new(service: &'a ReviewService, mode: ScanMode) -> Self {
        Self {
            service,
            mode,
            context: ScanContext::default(),
        }
    }

    async fn run(mut self) -> Result<ScanRunStatus> {
        if self.service.shutdown_requested() {
            info!("scan skipped: shutdown requested");
            return Ok(ScanRunStatus::Interrupted);
        }
        match self.mode {
            ScanMode::Full => info!("starting scan"),
            ScanMode::Incremental => info!("starting incremental scan"),
        }
        self.service.clear_stale_flow_state().await?;
        let repos = self.service.resolve_repos(self.mode).await?;
        if repos.is_empty() {
            info!("no gitlab repositories configured");
            return Ok(ScanRunStatus::Completed);
        }
        for repo in &repos {
            if self.service.shutdown_requested() {
                info!("stopping scan early: shutdown requested");
                self.context.mark_interrupted();
                break;
            }
            self.scan_repo(repo).await?;
        }
        if matches!(self.mode, ScanMode::Full) {
            let _ = join_all(std::mem::take(&mut self.context.tasks)).await;
        }
        self.context.log_completion(self.mode);
        Ok(self.context.run_status())
    }

    async fn scan_repo(&mut self, repo: &str) -> Result<()> {
        let activity_marker = self.service.load_latest_mr_activity_marker(repo).await;
        let now_ts = Utc::now().timestamp();
        let due_pending_review = matches!(self.mode, ScanMode::Incremental)
            && self
                .service
                .state
                .review_rate_limit
                .repo_has_due_review_rate_limit_pending(repo, now_ts)
                .await?;
        let due_pending_mention = matches!(self.mode, ScanMode::Incremental)
            && self
                .service
                .state
                .mention_quota_pending
                .repo_has_due_mention_quota_pending(repo, now_ts)
                .await?;
        let due_pending_work = due_pending_review || due_pending_mention;
        if matches!(self.mode, ScanMode::Incremental)
            && let Some(marker) = activity_marker.as_ref()
        {
            let previous = self
                .service
                .state
                .project_catalog
                .get_project_last_mr_activity(repo)
                .await?;
            if marker.as_str() == NO_OPEN_MRS_MARKER {
                if previous.as_ref() != Some(marker) {
                    self.service
                        .state
                        .project_catalog
                        .set_project_last_mr_activity(repo, marker)
                        .await?;
                }
                if !due_pending_work {
                    self.context.counters.skipped_inactive += 1;
                    debug!(repo = repo, "skip: no open MRs");
                    return Ok(());
                }
            }
            if let Some(previous) = previous
                && previous == *marker
                && !due_pending_work
            {
                self.context.counters.skipped_inactive += 1;
                debug!(repo = repo, "skip: latest MR activity unchanged");
                return Ok(());
            }
        }
        let mrs = match self.service.gitlab.list_open_mrs(repo).await {
            Ok(mrs) => mrs,
            Err(err) => {
                if self
                    .service
                    .should_skip_inactive_project_after_mr_listing_error(repo, &err)
                    .await
                {
                    self.context.counters.skipped_inactive += 1;
                    return Ok(());
                }
                return Err(err);
            }
        };
        match self.scan_repo_mrs(repo, mrs).await? {
            RepoScanStatus::Complete => {
                if let Some(marker) = activity_marker {
                    self.service
                        .state
                        .project_catalog
                        .set_project_last_mr_activity(repo, &marker)
                        .await?;
                }
            }
            RepoScanStatus::PendingSameMrWork => {
                debug!(
                    repo = repo,
                    "skip: not advancing activity marker because same-MR work is still pending"
                );
            }
            RepoScanStatus::Interrupted => {
                self.context.mark_interrupted();
                debug!(
                    repo = repo,
                    "skip: not advancing activity marker because scan was interrupted"
                );
            }
        }
        Ok(())
    }

    async fn scan_repo_mrs(
        &mut self,
        repo: &str,
        mrs: Vec<crate::gitlab::MergeRequest>,
    ) -> Result<RepoScanStatus> {
        let mut pending_same_mr_work = false;
        self.context.counters.total_mrs += mrs.len();
        info!(repo = repo, count = mrs.len(), "loaded open MRs");
        let open_iids = mrs.iter().map(|mr| mr.iid).collect::<Vec<_>>();
        self.service
            .remove_rate_limit_awards_for_closed_pending_mrs(repo, &open_iids)
            .await?;
        self.service
            .clear_mention_quota_pending_for_closed_mrs(repo, &open_iids)
            .await?;
        for mr in mrs {
            if self.service.shutdown_requested() {
                info!(repo = repo, "stopping MR scheduling: shutdown requested");
                return Ok(RepoScanStatus::Interrupted);
            }
            let mut mr = mr;
            if mr.head_sha().is_none() || mr.created_at.is_none() {
                mr = self.service.gitlab.get_mr(repo, mr.iid).await?;
            }
            let head_sha = if let Some(value) = mr.head_sha() {
                value
            } else {
                self.context.counters.missing_sha += 1;
                warn!(repo = repo, iid = mr.iid, "missing head sha, skipping");
                continue;
            };
            let mention_outcome = self
                .service
                .schedule_mention_commands_for_mr(repo, &mr, &head_sha, &mut self.context.tasks)
                .await?;
            self.context.record_mention_outcome(mention_outcome);
            if mention_outcome.blocked_pending_work {
                pending_same_mr_work = true;
            }
            if mention_outcome.blocks_review {
                debug!(
                    repo = repo,
                    iid = mr.iid,
                    "skip review scheduling in this scan: same-MR mention work is active or pending"
                );
                continue;
            }
            if mr.draft {
                self.context.counters.skipped_draft += 1;
                debug!(repo = repo, iid = mr.iid, "skip: draft MR");
                continue;
            }
            let created_at = if let Some(value) = mr.created_at.as_ref() {
                value
            } else {
                self.context.counters.skipped_created_before += 1;
                warn!(repo = repo, iid = mr.iid, "missing created_at, skipping");
                continue;
            };
            if created_at <= &self.service.created_after {
                self.context.counters.skipped_created_before += 1;
                debug!(
                    repo = repo,
                    iid = mr.iid,
                    created_at = %created_at,
                    cutoff = %self.service.created_after,
                    "skip: MR created before cutoff"
                );
                continue;
            }
            let mr_iid = mr.iid;
            let review_outcome = self
                .service
                .general_review_flow
                .schedule_for_scan(repo, mr.clone(), &head_sha, &mut self.context.tasks)
                .await?;
            if let Some(status) = self.context.apply_review_outcome(
                ReviewLane::General,
                repo,
                mr_iid,
                review_outcome,
                &mut pending_same_mr_work,
            ) {
                return Ok(status);
            }
            let security_review_outcome = self
                .service
                .security_review_flow
                .schedule_for_scan(repo, mr, &head_sha, &mut self.context.tasks)
                .await?;
            if let Some(status) = self.context.apply_review_outcome(
                ReviewLane::Security,
                repo,
                mr_iid,
                security_review_outcome,
                &mut pending_same_mr_work,
            ) {
                return Ok(status);
            }
        }
        Ok(if pending_same_mr_work {
            RepoScanStatus::PendingSameMrWork
        } else {
            RepoScanStatus::Complete
        })
    }
}

pub(super) async fn run_scan_pipeline(
    service: &ReviewService,
    mode: ScanMode,
) -> Result<ScanRunStatus> {
    ScanPipeline::new(service, mode).run().await
}

pub(super) async fn run_pending_rate_limit_pipeline(
    service: &ReviewService,
) -> Result<ScanRunStatus> {
    if service.shutdown_requested() {
        info!("pending retry skipped: shutdown requested");
        return Ok(ScanRunStatus::Interrupted);
    }
    service.clear_stale_flow_state().await?;
    let now = Utc::now().timestamp();
    let due_pending_mentions = service
        .state
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?
        .into_iter()
        .filter(|entry| entry.next_retry_at <= now)
        .collect::<Vec<_>>();
    let due_pending_rows = service
        .state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?
        .into_iter()
        .filter(|entry| entry.next_retry_at <= now)
        .collect::<Vec<_>>();
    if due_pending_mentions.is_empty() && due_pending_rows.is_empty() {
        debug!("no pending review rate-limit retries are due");
        return Ok(ScanRunStatus::Completed);
    }
    for pending in due_pending_mentions {
        if service.shutdown_requested() {
            info!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                discussion_id = pending.discussion_id.as_str(),
                trigger_note_id = pending.trigger_note_id,
                "stopping pending mention quota retry processing: shutdown requested"
            );
            return Ok(ScanRunStatus::Interrupted);
        }
        service.retry_pending_mention_quota_row(&pending).await?;
    }
    for pending in due_pending_rows {
        if service.shutdown_requested() {
            info!(
                repo = pending.repo.as_str(),
                iid = pending.iid,
                lane = pending.lane.as_str(),
                "stopping pending retry processing: shutdown requested"
            );
            return Ok(ScanRunStatus::Interrupted);
        }
        let outcome = service
            .retry_pending_review_rate_limit_row(&pending)
            .await?;
        if matches!(outcome, ReviewScheduleOutcome::Interrupted) {
            return Ok(ScanRunStatus::Interrupted);
        }
    }
    Ok(ScanRunStatus::Completed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_outcome_updates_pipeline_counters() {
        let mut context = ScanContext::default();

        context.record_mention_outcome(MentionScheduleOutcome {
            scheduled: 2,
            skipped_processed: 3,
            quota_blocked: 0,
            blocks_review: true,
            blocked_pending_work: true,
        });

        assert_eq!(context.counters.mention_scheduled, 2);
        assert_eq!(context.counters.mention_skipped_processed, 3);
    }

    #[test]
    fn locked_review_outcome_marks_same_mr_pending() {
        let mut context = ScanContext::default();
        let mut pending_same_mr_work = false;

        let status = context.apply_review_outcome(
            ReviewLane::General,
            "group/repo",
            7,
            ReviewScheduleOutcome::SkippedLocked,
            &mut pending_same_mr_work,
        );

        assert_eq!(status, None);
        assert!(pending_same_mr_work);
        assert_eq!(context.counters.skipped_locked, 1);
    }

    #[test]
    fn interrupted_review_outcome_stops_repo_scan() {
        let mut context = ScanContext::default();
        let mut pending_same_mr_work = false;

        let status = context.apply_review_outcome(
            ReviewLane::Security,
            "group/repo",
            9,
            ReviewScheduleOutcome::Interrupted,
            &mut pending_same_mr_work,
        );

        assert_eq!(status, Some(RepoScanStatus::Interrupted));
        assert!(!pending_same_mr_work);
    }
}

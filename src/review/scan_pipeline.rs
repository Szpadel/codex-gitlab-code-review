//! Repository scans and due retries admit runs into the service queue without waiting for completion.

use super::service::{NO_OPEN_MRS_MARKER, ReviewService, ScanMode, ScanRunStatus};
use crate::flow::FlowJob;
use crate::flow::admission::AdmissionHistory;
use crate::flow::mention::MentionAdmission;
use crate::flow::review::{
    ReviewAdmission, ReviewScheduleOutcome, ReviewSkipReason, review_skip_reason,
};
use crate::gitlab::MergeRequest;
use crate::review_lane::ReviewLane;
use crate::state::{MentionQuotaPendingEntry, ReviewRateLimitPendingEntry};
use anyhow::Result;
use chrono::{DateTime, Utc};
use std::collections::HashSet;
use tracing::{debug, info, warn};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepoScanStatus {
    Complete,
    PendingSameMrWork,
    Interrupted,
}

#[derive(Default)]
pub(super) struct ScanCounters {
    failed_repos: usize,
    total_mrs: usize,
    scheduled: usize,
    security_scheduled: usize,
    mention_scheduled: usize,
    skipped_marker: usize,
    skipped_completed: usize,
    skipped_quota: usize,
    security_skipped_marker: usize,
    security_skipped_completed: usize,
    security_skipped_backoff: usize,
    security_skipped_quota: usize,
    mention_skipped_processed: usize,
    mention_quota_blocked: usize,
    skipped_backoff: usize,
    missing_sha: usize,
    skipped_inactive: usize,
    skipped_draft: usize,
    skipped_closed: usize,
    skipped_created_before: usize,
}

impl ScanCounters {
    /// Counts the lane outcome and returns its skip message, if any.
    fn record_review_outcome(
        &mut self,
        lane: ReviewLane,
        outcome: ReviewScheduleOutcome,
    ) -> Option<&'static str> {
        match (lane, outcome) {
            (ReviewLane::General, ReviewScheduleOutcome::Scheduled) => {
                self.scheduled += 1;
                None
            }
            (ReviewLane::Security, ReviewScheduleOutcome::Scheduled) => {
                self.security_scheduled += 1;
                None
            }
            (_, ReviewScheduleOutcome::Disabled | ReviewScheduleOutcome::Interrupted) => None,
            (ReviewLane::General, ReviewScheduleOutcome::SkippedBackoff) => {
                self.skipped_backoff += 1;
                Some("skip: review backoff active")
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedBackoff) => {
                self.security_skipped_backoff += 1;
                Some("skip: security review backoff active")
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedRetryExhausted) => {
                self.skipped_completed += 1;
                Some("skip: review retry exhausted")
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedRetryExhausted) => {
                self.security_skipped_completed += 1;
                Some("skip: security review retry exhausted")
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedQuota) => {
                self.skipped_quota += 1;
                Some("skip: codex quota exhausted")
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedQuota) => {
                self.security_skipped_quota += 1;
                Some("skip: codex quota exhausted for security review")
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedMarker) => {
                self.skipped_marker += 1;
                Some("skip: review marker already present")
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedMarker) => {
                self.security_skipped_marker += 1;
                Some("skip: security review marker already present")
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedCompleted) => {
                self.skipped_completed += 1;
                Some("skip: review already completed for this SHA")
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedCompleted) => {
                self.security_skipped_completed += 1;
                Some("skip: security review already completed for this SHA")
            }
        }
    }
}

#[derive(Default)]
struct ScanContext {
    counters: ScanCounters,
    interrupted: bool,
}

impl ScanContext {
    fn record_mention_admission(&mut self, admission: &MentionAdmission) {
        self.counters.mention_scheduled += admission.jobs.len();
        self.counters.mention_skipped_processed += admission.skipped_processed;
        self.counters.mention_quota_blocked += admission.quota_blocked;
    }

    fn apply_review_outcome(
        &mut self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        outcome: ReviewScheduleOutcome,
        pending_same_mr_work: &mut bool,
    ) -> Option<RepoScanStatus> {
        if outcome == ReviewScheduleOutcome::Interrupted {
            return Some(RepoScanStatus::Interrupted);
        }
        let message = self.counters.record_review_outcome(lane, outcome);
        if outcome == ReviewScheduleOutcome::SkippedBackoff {
            *pending_same_mr_work = true;
        }
        if let Some(message) = message {
            debug!(repo = repo, iid = iid, "{message}");
        }
        None
    }

    fn record_inactive_repo(&mut self, repo: &str, message: &str) {
        self.counters.skipped_inactive += 1;
        debug!(repo = repo, "{message}");
    }

    fn record_review_skip(
        &mut self,
        repo: &str,
        mr: &MergeRequest,
        reason: ReviewSkipReason,
        cutoff: DateTime<Utc>,
    ) {
        let message = match reason {
            ReviewSkipReason::NotOpened => {
                self.counters.skipped_closed += 1;
                "skip: MR is not opened"
            }
            ReviewSkipReason::Draft => {
                self.counters.skipped_draft += 1;
                "skip: draft MR"
            }
            ReviewSkipReason::MissingCreatedAt => {
                self.record_missing_created_at(repo, mr.iid);
                return;
            }
            ReviewSkipReason::BeforeCutoff => {
                self.record_created_before_cutoff(repo, mr, cutoff);
                return;
            }
        };
        debug!(repo, iid = mr.iid, "{message}");
    }

    fn record_missing_created_at(&mut self, repo: &str, iid: u64) {
        self.counters.skipped_created_before += 1;
        warn!(repo, iid, "missing created_at, skipping");
    }

    fn record_created_before_cutoff(
        &mut self,
        repo: &str,
        mr: &MergeRequest,
        cutoff: DateTime<Utc>,
    ) {
        self.counters.skipped_created_before += 1;
        debug!(repo, iid = mr.iid, created_at = ?mr.created_at,
            cutoff = %cutoff, "skip: MR created before cutoff");
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
                    failed_repos = self.counters.failed_repos,
                    total_mrs = self.counters.total_mrs,
                    scheduled = self.counters.scheduled,
                    security_scheduled = self.counters.security_scheduled,
                    mention_scheduled = self.counters.mention_scheduled,
                    skipped_marker = self.counters.skipped_marker,
                    skipped_completed = self.counters.skipped_completed,
                    skipped_quota = self.counters.skipped_quota,
                    security_skipped_marker = self.counters.security_skipped_marker,
                    security_skipped_completed = self.counters.security_skipped_completed,
                    security_skipped_backoff = self.counters.security_skipped_backoff,
                    security_skipped_quota = self.counters.security_skipped_quota,
                    mention_skipped_processed = self.counters.mention_skipped_processed,
                    mention_quota_blocked = self.counters.mention_quota_blocked,
                    skipped_backoff = self.counters.skipped_backoff,
                    missing_sha = self.counters.missing_sha,
                    skipped_draft = self.counters.skipped_draft,
                    skipped_closed = self.counters.skipped_closed,
                    skipped_created_before = self.counters.skipped_created_before,
                    "scan complete"
                );
            }
            ScanMode::Incremental => {
                info!(
                    failed_repos = self.counters.failed_repos,
                    total_mrs = self.counters.total_mrs,
                    scheduled = self.counters.scheduled,
                    security_scheduled = self.counters.security_scheduled,
                    mention_scheduled = self.counters.mention_scheduled,
                    skipped_marker = self.counters.skipped_marker,
                    skipped_completed = self.counters.skipped_completed,
                    skipped_quota = self.counters.skipped_quota,
                    security_skipped_marker = self.counters.security_skipped_marker,
                    security_skipped_completed = self.counters.security_skipped_completed,
                    security_skipped_backoff = self.counters.security_skipped_backoff,
                    security_skipped_quota = self.counters.security_skipped_quota,
                    mention_skipped_processed = self.counters.mention_skipped_processed,
                    mention_quota_blocked = self.counters.mention_quota_blocked,
                    skipped_backoff = self.counters.skipped_backoff,
                    missing_sha = self.counters.missing_sha,
                    skipped_inactive = self.counters.skipped_inactive,
                    skipped_draft = self.counters.skipped_draft,
                    skipped_closed = self.counters.skipped_closed,
                    skipped_created_before = self.counters.skipped_created_before,
                    "scan complete"
                );
            }
        }
    }
}

/// Activity and retry state captured before a repository scan starts.
struct RepoActivity {
    marker: Option<String>,
    due_pending_work: bool,
    rescan_request: Option<u64>,
}

/// The MR and head SHA used by all admission flows.
struct ScanMergeRequest {
    mr: MergeRequest,
    head_sha: String,
}

/// Scans repositories and queues the needed runs. Does not wait for the runs.
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
        if log_scan_shutdown_if_requested(self.service, "scan skipped: shutdown requested") {
            return Ok(ScanRunStatus::Interrupted);
        }
        let message = match self.mode {
            ScanMode::Full => "starting scan",
            ScanMode::Incremental => "starting incremental scan",
        };
        info!("{message}");
        self.service.clear_stale_flow_state().await?;
        let repos = self.service.resolve_repos(self.mode).await?;
        self.service
            .clear_review_backoff_retries_outside_targets(&repos)
            .await;
        if repos.is_empty() {
            info!("no gitlab repositories configured");
            return Ok(ScanRunStatus::Completed);
        }
        let first_repo_error = self.scan_repos(&repos).await;
        self.context.log_completion(self.mode);
        if let Some(err) = first_repo_error {
            return Err(err.context(format!(
                "scan failed in {} repositories",
                self.context.counters.failed_repos
            )));
        }
        Ok(self.context.run_status())
    }

    /// Continues after repository failures and retains the first error.
    async fn scan_repos(&mut self, repos: &[String]) -> Option<anyhow::Error> {
        let mut first_repo_error = None;
        for repo in repos {
            if log_scan_shutdown_if_requested(
                self.service,
                "stopping scan early: shutdown requested",
            ) {
                self.context.mark_interrupted();
                break;
            }
            self.scan_repo_recording_failure(repo, &mut first_repo_error)
                .await;
        }
        first_repo_error
    }

    /// Counts and logs repository failures without replacing an earlier error.
    async fn scan_repo_recording_failure(
        &mut self,
        repo: &str,
        first_repo_error: &mut Option<anyhow::Error>,
    ) {
        if let Err(err) = self.scan_repo(repo).await {
            warn!(repo, error = %err, "repository scan failed");
            self.context.counters.failed_repos += 1;
            first_repo_error.get_or_insert(err);
        }
    }

    async fn scan_repo(&mut self, repo: &str) -> Result<()> {
        let activity = self.load_repo_activity(repo).await?;
        if self.should_skip_inactive_repo(repo, &activity).await? {
            return Ok(());
        }
        let Some(mrs) = self.list_repo_mrs(repo).await? else {
            return Ok(());
        };
        let status = self.scan_repo_mrs(repo, mrs).await?;
        self.finish_repo_scan(repo, activity, status).await
    }

    /// Loads the activity marker in both modes. Only incremental scans check due retries.
    async fn load_repo_activity(&self, repo: &str) -> Result<RepoActivity> {
        let marker = self.service.load_latest_mr_activity_marker(repo).await;
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
        let due_review_backoff = matches!(self.mode, ScanMode::Incremental)
            && self
                .service
                .repo_has_due_review_backoff_retry(repo, Utc::now());
        let rescan_request = self.service.rescan_requests.pending(repo);
        let due_pending_work = due_pending_review
            || due_pending_mention
            || due_review_backoff
            || rescan_request.is_some();
        Ok(RepoActivity {
            marker,
            due_pending_work,
            rescan_request,
        })
    }

    /// Saves an empty-repository marker even when pending work prevents a skip.
    async fn should_skip_inactive_repo(
        &mut self,
        repo: &str,
        activity: &RepoActivity,
    ) -> Result<bool> {
        if matches!(self.mode, ScanMode::Full) {
            return Ok(false);
        }
        let Some(marker) = activity.marker.as_ref() else {
            return Ok(false);
        };
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
            if !activity.due_pending_work {
                self.context.record_inactive_repo(repo, "skip: no open MRs");
                return Ok(true);
            }
        }
        if let Some(previous) = previous
            && previous == *marker
            && !activity.due_pending_work
        {
            self.context
                .record_inactive_repo(repo, "skip: latest MR activity unchanged");
            return Ok(true);
        }
        Ok(false)
    }

    /// Treats a forbidden listing as inactive only after the project lookup confirms it.
    async fn list_repo_mrs(&mut self, repo: &str) -> Result<Option<Vec<MergeRequest>>> {
        match self.service.gitlab.list_open_mrs(repo).await {
            Ok(mrs) => Ok(Some(mrs)),
            Err(err) => {
                if self
                    .service
                    .should_skip_inactive_project_after_mr_listing_error(repo, &err)
                    .await
                {
                    self.context.counters.skipped_inactive += 1;
                    return Ok(None);
                }
                Err(err)
            }
        }
    }

    /// Keeps the activity snapshot unchanged for backoff or an interrupted scan.
    async fn finish_repo_scan(
        &mut self,
        repo: &str,
        activity: RepoActivity,
        status: RepoScanStatus,
    ) -> Result<()> {
        let message = match status {
            RepoScanStatus::Complete => {
                self.complete_repo_activity(repo, activity).await?;
                return Ok(());
            }
            RepoScanStatus::PendingSameMrWork => {
                "skip: not advancing activity marker because same-MR work is still pending"
            }
            RepoScanStatus::Interrupted => {
                self.context.mark_interrupted();
                "skip: not advancing activity marker because scan was interrupted"
            }
        };
        debug!(repo = repo, "{message}");
        Ok(())
    }

    /// Saves the marker before completing the captured rescan request.
    /// A failed marker write leaves the rescan request pending.
    async fn complete_repo_activity(&self, repo: &str, activity: RepoActivity) -> Result<()> {
        if let Some(marker) = activity.marker {
            self.service
                .state
                .project_catalog
                .set_project_last_mr_activity(repo, &marker)
                .await?;
        }
        if let Some(count) = activity.rescan_request {
            self.service.rescan_requests.complete(repo, count);
        }
        Ok(())
    }

    async fn scan_repo_mrs(
        &mut self,
        repo: &str,
        mrs: Vec<MergeRequest>,
    ) -> Result<RepoScanStatus> {
        let mut pending_same_mr_work = false;
        self.context.counters.total_mrs += mrs.len();
        info!(repo = repo, count = mrs.len(), "loaded open MRs");
        self.clear_pending_work_for_closed_mrs(repo, &mrs).await?;
        for mr in mrs {
            if self.service.shutdown_requested() {
                info!(repo = repo, "stopping MR scheduling: shutdown requested");
                return Ok(RepoScanStatus::Interrupted);
            }
            match self.scan_mr(repo, mr).await? {
                RepoScanStatus::Complete => {}
                RepoScanStatus::PendingSameMrWork => pending_same_mr_work = true,
                RepoScanStatus::Interrupted => return Ok(RepoScanStatus::Interrupted),
            }
        }
        Ok(if pending_same_mr_work {
            RepoScanStatus::PendingSameMrWork
        } else {
            RepoScanStatus::Complete
        })
    }

    async fn clear_pending_work_for_closed_mrs(
        &self,
        repo: &str,
        mrs: &[MergeRequest],
    ) -> Result<()> {
        let open_iids = mrs.iter().map(|mr| mr.iid).collect::<Vec<_>>();
        self.service
            .clear_review_backoff_retries_for_closed_mrs(repo, &open_iids)
            .await;
        self.service
            .remove_rate_limit_awards_for_closed_pending_mrs(repo, &open_iids)
            .await?;
        self.service
            .clear_mention_quota_pending_for_closed_mrs(repo, &open_iids)
            .await?;
        Ok(())
    }

    /// Refreshes incomplete listing entries and clears retries when no head SHA is available.
    async fn prepare_mr_for_scan(
        &mut self,
        repo: &str,
        mut mr: MergeRequest,
    ) -> Result<Option<ScanMergeRequest>> {
        if mr.head_sha().is_none() || mr.created_at.is_none() {
            mr = self.service.gitlab.get_mr(repo, mr.iid).await?;
        }
        let Some(head_sha) = mr.head_sha() else {
            self.skip_mr_without_head_sha(repo, mr.iid).await;
            return Ok(None);
        };
        self.service
            .clear_stale_review_backoff_retries_for_mr(repo, mr.iid, &head_sha)
            .await;
        Ok(Some(ScanMergeRequest { mr, head_sha }))
    }

    /// Counts the skipped MR and clears retry warnings before reporting the missing SHA.
    async fn skip_mr_without_head_sha(&mut self, repo: &str, iid: u64) {
        self.context.counters.missing_sha += 1;
        self.service
            .clear_review_backoff_retries_for_mr(repo, iid)
            .await;
        warn!(repo = repo, iid = iid, "missing head sha, skipping");
    }

    /// Admits mentions before review eligibility checks, using one shared history snapshot.
    async fn scan_mr(&mut self, repo: &str, mr: MergeRequest) -> Result<RepoScanStatus> {
        let Some(ScanMergeRequest { mr, head_sha }) = self.prepare_mr_for_scan(repo, mr).await?
        else {
            return Ok(RepoScanStatus::Complete);
        };
        let history = AdmissionHistory::new(self.service.gitlab.as_ref(), repo, mr.iid);
        if !self
            .schedule_mentions(repo, &mr, &head_sha, &history)
            .await?
        {
            return Ok(RepoScanStatus::Interrupted);
        }
        if let Some(reason) = review_skip_reason(&mr, self.service.created_after) {
            self.service
                .clear_review_backoff_retries_for_mr(repo, mr.iid)
                .await;
            self.context
                .record_review_skip(repo, &mr, reason, self.service.created_after);
            return Ok(RepoScanStatus::Complete);
        }
        self.schedule_reviews(repo, &mr, &head_sha, &history).await
    }

    /// Counts all admitted mentions before enqueueing. Returns false if enqueueing stops.
    async fn schedule_mentions(
        &mut self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<bool> {
        let admission = self
            .service
            .mention_flow
            .admit_for_scan(repo, mr, head_sha, history)
            .await?;
        self.context.record_mention_admission(&admission);
        for job in admission.jobs {
            if !self.service.enqueue(FlowJob::Mention(Box::new(job))) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Admits the general lane before the security lane. Backoff keeps the activity marker pending.
    async fn schedule_reviews(
        &mut self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        history: &AdmissionHistory<'_>,
    ) -> Result<RepoScanStatus> {
        let mut pending_same_mr_work = false;
        for (lane, flow) in [
            (ReviewLane::General, &self.service.general_review_flow),
            (ReviewLane::Security, &self.service.security_review_flow),
        ] {
            let outcome = match flow.admit_for_scan(repo, mr, head_sha, history).await? {
                ReviewAdmission::Skip(outcome) => outcome,
                ReviewAdmission::Queue(job) => {
                    if self.service.queue_review(job).await {
                        ReviewScheduleOutcome::Scheduled
                    } else {
                        ReviewScheduleOutcome::Interrupted
                    }
                }
            };
            if let Some(status) = self.context.apply_review_outcome(
                lane,
                repo,
                mr.iid,
                outcome,
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

/// Queues due mention rows before due review rows without waiting for runs.
/// Shutdown stops further rows. Row errors do not stop later rows.
/// Returns the first row error unless review target resolution fails.
/// Review target-resolution errors stop the batch and take precedence over earlier row errors.
pub(super) async fn run_pending_retry_pipeline(service: &ReviewService) -> Result<ScanRunStatus> {
    if log_scan_shutdown_if_requested(service, "pending retry skipped: shutdown requested") {
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
    let mention_error = queue_due_pending_mentions(service, &due_pending_mentions).await;
    let review_error = queue_due_pending_reviews(service, &due_pending_rows).await?;
    if let Some(err) = mention_error.or(review_error) {
        return Err(err);
    }
    if log_scan_shutdown_if_requested(service, "pending retry stopped: shutdown requested") {
        return Ok(ScanRunStatus::Interrupted);
    }
    Ok(ScanRunStatus::Completed)
}

/// Reports shutdown at a scan boundary and returns whether that boundary must stop.
fn log_scan_shutdown_if_requested(service: &ReviewService, message: &str) -> bool {
    if !service.shutdown_requested() {
        return false;
    }
    info!("{message}");
    true
}

/// Handles all due mention rows unless shutdown stops the batch. Retains the first error.
async fn queue_due_pending_mentions(
    service: &ReviewService,
    rows: &[MentionQuotaPendingEntry],
) -> Option<anyhow::Error> {
    let mut first_error = None;
    for pending in rows {
        if service.shutdown_requested() {
            break;
        }
        record_pending_retry_error(
            &mut first_error,
            service.queue_pending_mention_row(pending).await,
            "pending mention retry failed",
        );
    }
    first_error
}

/// Resolves targets only for a nonempty batch without shutdown. Target errors stop the batch.
/// Row errors do not stop later rows. Returns the first row error.
async fn queue_due_pending_reviews(
    service: &ReviewService,
    rows: &[ReviewRateLimitPendingEntry],
) -> Result<Option<anyhow::Error>> {
    if rows.is_empty() || service.shutdown_requested() {
        return Ok(None);
    }
    let repos: HashSet<String> = service
        .resolve_repos(ScanMode::Incremental)
        .await?
        .into_iter()
        .collect();
    let mut first_error = None;
    for pending in rows {
        if service.shutdown_requested() {
            break;
        }
        record_pending_retry_error(
            &mut first_error,
            service.queue_pending_review_row(pending, &repos).await,
            "pending review retry failed",
        );
    }
    Ok(first_error)
}

/// Logs every failed retry and retains only the first error for the batch result.
fn record_pending_retry_error(
    first_error: &mut Option<anyhow::Error>,
    result: Result<()>,
    message: &str,
) {
    if let Err(err) = result {
        warn!(error = %format!("{err:#}"), "{message}");
        first_error.get_or_insert(err);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mention_admission_updates_pipeline_counters() {
        let mut context = ScanContext::default();

        context.record_mention_admission(&MentionAdmission {
            jobs: Vec::new(),
            skipped_processed: 3,
            quota_blocked: 1,
        });

        assert_eq!(context.counters.mention_scheduled, 0);
        assert_eq!(context.counters.mention_skipped_processed, 3);
        assert_eq!(context.counters.mention_quota_blocked, 1);
    }

    #[test]
    fn backoff_review_outcome_marks_same_mr_pending() {
        let mut context = ScanContext::default();
        let mut pending_same_mr_work = false;

        let status = context.apply_review_outcome(
            ReviewLane::General,
            "group/repo",
            7,
            ReviewScheduleOutcome::SkippedBackoff,
            &mut pending_same_mr_work,
        );

        assert_eq!(status, None);
        assert!(pending_same_mr_work);
        assert_eq!(context.counters.skipped_backoff, 1);
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

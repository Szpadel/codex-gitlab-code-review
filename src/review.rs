use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::FlowShared;
use crate::flow::mention::{MentionFlow, MentionScheduleOutcome};
use crate::flow::review::{RetryBackoff, ReviewFlow, ReviewScheduleOutcome, remove_bot_award};
use crate::flow::{ActiveTaskRegistry, MergeRequestFlow};
use crate::gitlab::{GitLabApi, MergeRequest, gitlab_error_has_status};
use crate::review_lane::ReviewLane;
use crate::state::{ReviewRateLimitPendingEntry, ReviewStateStore};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Duration, TimeZone, Utc};
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

const NO_OPEN_MRS_MARKER: &str = "__no_open_mrs__";
const PENDING_RETRY_LOOKUP_BACKOFF_SECONDS: i64 = 60;

#[derive(Clone, Copy)]
enum ScanMode {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RepoScanStatus {
    Complete,
    PendingSameMrWork,
    Interrupted,
}

#[derive(Default)]
struct ScanCounters {
    total_mrs: usize,
    scheduled: usize,
    security_scheduled: usize,
    mention_scheduled: usize,
    skipped_award: usize,
    skipped_marker: usize,
    skipped_completed: usize,
    skipped_locked: usize,
    skipped_rate_limit: usize,
    security_skipped_marker: usize,
    security_skipped_completed: usize,
    security_skipped_locked: usize,
    security_skipped_backoff: usize,
    security_skipped_rate_limit: usize,
    mention_skipped_processed: usize,
    skipped_backoff: usize,
    missing_sha: usize,
    skipped_inactive: usize,
    skipped_draft: usize,
    skipped_created_before: usize,
}

pub struct ReviewService {
    config: Config,
    gitlab: Arc<dyn GitLabApi>,
    state: Arc<ReviewStateStore>,
    codex: Arc<dyn CodexRunner>,
    dynamic_repo_source: Option<Arc<dyn DynamicRepoSource>>,
    created_after: DateTime<Utc>,
    bot_user_id: u64,
    general_review_flow: ReviewFlow,
    security_review_flow: ReviewFlow,
    mention_flow: MentionFlow,
    shutdown: Arc<AtomicBool>,
    active_tasks: Arc<ActiveTaskRegistry>,
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
        let shutdown = Arc::new(AtomicBool::new(false));
        let active_tasks = Arc::new(ActiveTaskRegistry::default());
        let flow_shared = FlowShared::new(
            config.clone(),
            Arc::clone(&gitlab),
            Arc::clone(&state),
            Arc::clone(&codex),
            bot_user_id,
            Arc::clone(&semaphore),
            Arc::clone(&shutdown),
            Arc::clone(&active_tasks),
        );
        let mention_flow = MentionFlow::new(flow_shared.clone(), mention_branch_locks);
        let general_review_flow = ReviewFlow::new(
            flow_shared.clone(),
            Arc::clone(&retry_backoff),
            ReviewLane::General,
        );
        let security_review_flow =
            ReviewFlow::new(flow_shared, retry_backoff, ReviewLane::Security);
        Self {
            config,
            gitlab,
            state,
            codex,
            dynamic_repo_source: None,
            created_after,
            bot_user_id,
            general_review_flow,
            security_review_flow,
            mention_flow,
            shutdown,
            active_tasks,
        }
    }

    #[must_use]
    pub fn with_dynamic_repo_source(
        mut self,
        dynamic_repo_source: Arc<dyn DynamicRepoSource>,
    ) -> Self {
        self.dynamic_repo_source = Some(dynamic_repo_source);
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
        Ok(self
            .state
            .earliest_review_rate_limit_pending_retry_at()
            .await?
            .and_then(|timestamp| Utc.timestamp_opt(timestamp, 0).single()))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn process_due_pending_rate_limit_reviews(&self) -> Result<ScanRunStatus> {
        if self.shutdown_requested() {
            info!("pending retry skipped: shutdown requested");
            return Ok(ScanRunStatus::Interrupted);
        }
        self.clear_stale_flow_state().await?;
        let now = Utc::now().timestamp();
        let due_pending_rows = self
            .state
            .list_review_rate_limit_pending()
            .await?
            .into_iter()
            .filter(|entry| entry.next_retry_at <= now)
            .collect::<Vec<_>>();
        if due_pending_rows.is_empty() {
            debug!("no pending review rate-limit retries are due");
            return Ok(ScanRunStatus::Completed);
        }
        for pending in due_pending_rows {
            if self.shutdown_requested() {
                info!(
                    repo = pending.repo.as_str(),
                    iid = pending.iid,
                    lane = pending.lane.as_str(),
                    "stopping pending retry processing: shutdown requested"
                );
                return Ok(ScanRunStatus::Interrupted);
            }
            let outcome = self.retry_pending_review_rate_limit_row(&pending).await?;
            if matches!(outcome, ReviewScheduleOutcome::Interrupted) {
                return Ok(ScanRunStatus::Interrupted);
            }
        }
        Ok(ScanRunStatus::Completed)
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn recover_in_progress_reviews(&self) -> Result<()> {
        if let Err(err) = self.codex.stop_active_reviews().await {
            warn!(error = %err, "failed to stop active codex review containers");
        }
        self.recover_flows().await?;
        Ok(())
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    async fn recover_flows(&self) -> Result<()> {
        let flows: [&dyn MergeRequestFlow; 3] = [
            &self.general_review_flow,
            &self.security_review_flow,
            &self.mention_flow,
        ];
        for flow in flows {
            debug!(flow = flow.flow_name(), "recover in-progress flow state");
            flow.recover_in_progress().await?;
        }
        Ok(())
    }

    async fn clear_stale_flow_state(&self) -> Result<()> {
        self.refresh_active_flow_state().await?;
        let flows: [&dyn MergeRequestFlow; 3] = [
            &self.general_review_flow,
            &self.security_review_flow,
            &self.mention_flow,
        ];
        for flow in flows {
            flow.clear_stale_in_progress().await?;
        }
        Ok(())
    }

    async fn refresh_active_flow_state(&self) -> Result<()> {
        for review in self.active_tasks.active_reviews() {
            self.state
                .touch_in_progress_review_for_lane(
                    &review.repo,
                    review.iid,
                    &review.head_sha,
                    review.lane,
                )
                .await?;
        }
        for mention in self.active_tasks.active_mentions() {
            self.state
                .touch_in_progress_mention_command(
                    &mention.repo,
                    mention.iid,
                    &mention.discussion_id,
                    mention.trigger_note_id,
                    &mention.head_sha,
                )
                .await?;
        }
        Ok(())
    }

    async fn schedule_mention_commands_for_mr(
        &self,
        repo: &str,
        mr: &MergeRequest,
        head_sha: &str,
        counters: &mut ScanCounters,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<MentionScheduleOutcome> {
        let outcome = self
            .mention_flow
            .schedule_for_scan(repo, mr, head_sha, tasks)
            .await?;
        counters.mention_scheduled += outcome.scheduled;
        counters.mention_skipped_processed += outcome.skipped_processed;
        Ok(outcome)
    }

    fn review_flow_for_lane(&self, lane: ReviewLane) -> &ReviewFlow {
        if lane.is_security() {
            &self.security_review_flow
        } else {
            &self.general_review_flow
        }
    }

    async fn retry_pending_review_rate_limit_row(
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
                    .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
                    .await?
                {
                    self.remove_rate_limit_award_after_pending_clear(
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
                self.state
                    .upsert_review_rate_limit_pending(
                        pending.lane,
                        &pending.repo,
                        pending.iid,
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
                .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
                .await?
            {
                self.remove_rate_limit_award_after_pending_clear(
                    pending.lane,
                    &pending.repo,
                    pending.iid,
                )
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
                self.state
                    .upsert_review_rate_limit_pending(
                        pending.lane,
                        &pending.repo,
                        pending.iid,
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
            ReviewScheduleOutcome::SkippedRateLimit | ReviewScheduleOutcome::Interrupted
        ) && self
            .state
            .clear_review_rate_limit_pending(pending.lane, &pending.repo, pending.iid)
            .await?
        {
            self.remove_rate_limit_award_after_pending_clear(
                pending.lane,
                &pending.repo,
                pending.iid,
            )
            .await;
        }
        Ok(outcome)
    }

    async fn remove_rate_limit_award_after_pending_clear(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
    ) {
        if lane.is_security() || self.config.review.dry_run {
            return;
        }
        if let Err(err) = remove_bot_award(
            self.gitlab.as_ref(),
            repo,
            iid,
            self.bot_user_id,
            &self.config.review.rate_limit_emoji,
        )
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
    }

    async fn remove_rate_limit_awards_for_closed_pending_mrs(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        let open_iids_set = open_iids.iter().copied().collect::<HashSet<_>>();
        let pending_to_clear = self
            .state
            .list_review_rate_limit_pending()
            .await?
            .into_iter()
            .filter(|pending| pending.repo == repo && !open_iids_set.contains(&pending.iid))
            .collect::<Vec<_>>();
        if pending_to_clear.is_empty() {
            return Ok(());
        }
        self.state
            .sync_review_rate_limit_pending_rows(repo, open_iids)
            .await?;
        for pending in pending_to_clear {
            self.remove_rate_limit_award_after_pending_clear(
                pending.lane,
                pending.repo.as_str(),
                pending.iid,
            )
            .await;
        }
        Ok(())
    }

    fn apply_review_outcome(
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        outcome: ReviewScheduleOutcome,
        counters: &mut ScanCounters,
        pending_same_mr_work: &mut bool,
    ) -> Option<RepoScanStatus> {
        match (lane, outcome) {
            (_, ReviewScheduleOutcome::Scheduled) => {
                if lane.is_security() {
                    counters.security_scheduled += 1;
                } else {
                    counters.scheduled += 1;
                }
            }
            (_, ReviewScheduleOutcome::Disabled) => {}
            (ReviewLane::General, ReviewScheduleOutcome::SkippedBackoff) => {
                counters.skipped_backoff += 1;
                debug!(repo = repo, iid = iid, "skip: review backoff active");
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedBackoff) => {
                counters.security_skipped_backoff += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review backoff active"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedRateLimit) => {
                counters.skipped_rate_limit += 1;
                debug!(repo = repo, iid = iid, "skip: review rate limit active");
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedRateLimit) => {
                counters.security_skipped_rate_limit += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review rate limit active"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedAward) => {
                counters.skipped_award += 1;
                debug!(repo = repo, iid = iid, "skip: thumbs up already present");
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedMarker) => {
                counters.skipped_marker += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: review marker already present"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedMarker) => {
                counters.security_skipped_marker += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review marker already present"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedCompleted) => {
                counters.skipped_completed += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: review already completed for this SHA"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedCompleted) => {
                counters.security_skipped_completed += 1;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review already completed for this SHA"
                );
            }
            (ReviewLane::General, ReviewScheduleOutcome::SkippedLocked) => {
                counters.skipped_locked += 1;
                *pending_same_mr_work = true;
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: same-MR work already in progress"
                );
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedLocked) => {
                counters.security_skipped_locked += 1;
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

    async fn scan(&self, mode: ScanMode) -> Result<ScanRunStatus> {
        if self.shutdown_requested() {
            info!("scan skipped: shutdown requested");
            return Ok(ScanRunStatus::Interrupted);
        }
        match mode {
            ScanMode::Full => info!("starting scan"),
            ScanMode::Incremental => info!("starting incremental scan"),
        }
        self.clear_stale_flow_state().await?;
        let repos = self.resolve_repos(mode).await?;
        if repos.is_empty() {
            info!("no gitlab repositories configured");
            return Ok(ScanRunStatus::Completed);
        }
        let mut tasks = Vec::new();
        let mut counters = ScanCounters::default();
        let mut interrupted = false;
        for repo in &repos {
            if self.shutdown_requested() {
                info!("stopping scan early: shutdown requested");
                interrupted = true;
                break;
            }
            let activity_marker = self.load_latest_mr_activity_marker(repo).await;
            let now_ts = Utc::now().timestamp();
            let due_pending_review = matches!(mode, ScanMode::Incremental)
                && self
                    .state
                    .repo_has_due_review_rate_limit_pending(repo, now_ts)
                    .await?;
            if matches!(mode, ScanMode::Incremental)
                && let Some(marker) = activity_marker.as_ref()
            {
                let previous = self.state.get_project_last_mr_activity(repo).await?;
                if marker.as_str() == NO_OPEN_MRS_MARKER {
                    if previous.as_ref() != Some(marker) {
                        self.state
                            .set_project_last_mr_activity(repo, marker)
                            .await?;
                    }
                    if !due_pending_review {
                        counters.skipped_inactive += 1;
                        debug!(repo = repo.as_str(), "skip: no open MRs");
                        continue;
                    }
                }
                if let Some(previous) = previous
                    && previous == *marker
                    && !due_pending_review
                {
                    counters.skipped_inactive += 1;
                    debug!(repo = repo.as_str(), "skip: latest MR activity unchanged");
                    continue;
                }
            }
            let mrs = self.gitlab.list_open_mrs(repo).await?;
            match self
                .scan_repo_mrs(repo, mrs, &mut counters, &mut tasks)
                .await?
            {
                RepoScanStatus::Complete => {
                    if let Some(marker) = activity_marker {
                        self.state
                            .set_project_last_mr_activity(repo, &marker)
                            .await?;
                    }
                }
                RepoScanStatus::PendingSameMrWork => {
                    debug!(
                        repo = repo.as_str(),
                        "skip: not advancing activity marker because same-MR work is still pending"
                    );
                }
                RepoScanStatus::Interrupted => {
                    interrupted = true;
                    debug!(
                        repo = repo.as_str(),
                        "skip: not advancing activity marker because scan was interrupted"
                    );
                }
            }
        }
        if matches!(mode, ScanMode::Full) {
            let _ = join_all(tasks).await;
        }
        match mode {
            ScanMode::Full => {
                info!(
                    total_mrs = counters.total_mrs,
                    scheduled = counters.scheduled,
                    security_scheduled = counters.security_scheduled,
                    mention_scheduled = counters.mention_scheduled,
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_completed = counters.skipped_completed,
                    skipped_locked = counters.skipped_locked,
                    skipped_rate_limit = counters.skipped_rate_limit,
                    security_skipped_marker = counters.security_skipped_marker,
                    security_skipped_completed = counters.security_skipped_completed,
                    security_skipped_locked = counters.security_skipped_locked,
                    security_skipped_backoff = counters.security_skipped_backoff,
                    security_skipped_rate_limit = counters.security_skipped_rate_limit,
                    mention_skipped_processed = counters.mention_skipped_processed,
                    skipped_backoff = counters.skipped_backoff,
                    missing_sha = counters.missing_sha,
                    skipped_draft = counters.skipped_draft,
                    skipped_created_before = counters.skipped_created_before,
                    "scan complete"
                );
            }
            ScanMode::Incremental => {
                info!(
                    total_mrs = counters.total_mrs,
                    scheduled = counters.scheduled,
                    security_scheduled = counters.security_scheduled,
                    mention_scheduled = counters.mention_scheduled,
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_completed = counters.skipped_completed,
                    skipped_locked = counters.skipped_locked,
                    skipped_rate_limit = counters.skipped_rate_limit,
                    security_skipped_marker = counters.security_skipped_marker,
                    security_skipped_completed = counters.security_skipped_completed,
                    security_skipped_locked = counters.security_skipped_locked,
                    security_skipped_backoff = counters.security_skipped_backoff,
                    security_skipped_rate_limit = counters.security_skipped_rate_limit,
                    mention_skipped_processed = counters.mention_skipped_processed,
                    skipped_backoff = counters.skipped_backoff,
                    missing_sha = counters.missing_sha,
                    skipped_inactive = counters.skipped_inactive,
                    skipped_draft = counters.skipped_draft,
                    skipped_created_before = counters.skipped_created_before,
                    "scan complete"
                );
            }
        }
        Ok(if interrupted {
            ScanRunStatus::Interrupted
        } else {
            ScanRunStatus::Completed
        })
    }

    async fn load_latest_mr_activity_marker(&self, repo: &str) -> Option<String> {
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

    async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>> {
        if let Some(dynamic_repo_source) = self.dynamic_repo_source.as_ref() {
            let mut repos = dynamic_repo_source.list_repos().await?;
            repos.sort();
            repos.dedup();
            return Ok(repos);
        }

        let targets = &self.config.gitlab.targets;
        let include_all = targets.repos.is_all() || targets.groups.is_all();
        let mut included = HashSet::new();
        if include_all {
            for repo in self.resolve_all_targets(mode).await? {
                included.insert(repo);
            }
        } else {
            for repo in targets.repos.list() {
                included.insert(repo.clone());
            }
            if !targets.groups.list().is_empty() {
                for repo in self.resolve_group_targets(mode).await? {
                    included.insert(repo);
                }
            }
        }

        if included.is_empty() {
            return Ok(Vec::new());
        }

        let exclude_repos: HashSet<&str> =
            targets.exclude_repos.iter().map(String::as_str).collect();
        let exclude_group_prefixes: Vec<String> = targets
            .exclude_groups
            .iter()
            .map(|group| group.trim_end_matches('/'))
            .filter(|group| !group.is_empty())
            .map(|group| format!("{group}/"))
            .collect();

        let mut repos: Vec<String> = included
            .into_iter()
            .filter(|repo| {
                if exclude_repos.contains(repo.as_str()) {
                    return false;
                }
                if exclude_group_prefixes
                    .iter()
                    .any(|prefix| repo.starts_with(prefix))
                {
                    return false;
                }
                true
            })
            .collect();
        repos.sort();
        Ok(repos)
    }

    async fn resolve_all_targets(&self, mode: ScanMode) -> Result<Vec<String>> {
        let cache_key = self.config.gitlab.targets.cache_key_for_all();
        self.resolve_discovered_targets(
            mode,
            || async {
                let projects = self.gitlab.list_projects().await?;
                Ok(projects
                    .into_iter()
                    .map(|project| project.path_with_namespace)
                    .collect())
            },
            cache_key,
        )
        .await
    }

    async fn resolve_group_targets(&self, mode: ScanMode) -> Result<Vec<String>> {
        let groups = &self.config.gitlab.targets.groups;
        if groups.list().is_empty() {
            return Ok(Vec::new());
        }
        let cache_key = self.config.gitlab.targets.cache_key_for_groups();
        self.resolve_discovered_targets(
            mode,
            || async {
                let mut deduped = HashSet::new();
                for group in groups.list() {
                    let projects = self.gitlab.list_group_projects(group).await?;
                    for project in projects {
                        deduped.insert(project.path_with_namespace);
                    }
                }
                Ok(deduped.into_iter().collect())
            },
            cache_key,
        )
        .await
    }

    async fn resolve_discovered_targets<F, Fut>(
        &self,
        mode: ScanMode,
        fetch: F,
        cache_key: String,
    ) -> Result<Vec<String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<String>>>,
    {
        let cached = self.state.load_project_catalog(&cache_key).await?;
        let force_refresh = matches!(mode, ScanMode::Full);
        if let Some(cache) = cached.as_ref() {
            let refresh_seconds = self.config.gitlab.targets.refresh_seconds;
            if !force_refresh
                && refresh_seconds > 0
                && Utc::now().timestamp() - cache.fetched_at < refresh_seconds as i64
            {
                debug!(
                    cache_key = cache_key.as_str(),
                    count = cache.projects.len(),
                    "using cached project catalog"
                );
                return Ok(cache.projects.clone());
            }
        }
        match fetch().await {
            Ok(mut projects) => {
                projects.sort();
                projects.dedup();
                self.state
                    .save_project_catalog(&cache_key, &projects)
                    .await?;
                Ok(projects)
            }
            Err(err) => {
                if let Some(cache) = cached {
                    warn!(
                        cache_key = cache_key.as_str(),
                        error = %err,
                        "failed to refresh project catalog; using cached list"
                    );
                    Ok(cache.projects)
                } else {
                    Err(err)
                }
            }
        }
    }

    async fn scan_repo_mrs(
        &self,
        repo: &str,
        mrs: Vec<MergeRequest>,
        counters: &mut ScanCounters,
        tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    ) -> Result<RepoScanStatus> {
        let mut pending_same_mr_work = false;
        counters.total_mrs += mrs.len();
        info!(repo = repo, count = mrs.len(), "loaded open MRs");
        let open_iids = mrs.iter().map(|mr| mr.iid).collect::<Vec<_>>();
        self.remove_rate_limit_awards_for_closed_pending_mrs(repo, &open_iids)
            .await?;
        for mr in mrs {
            if self.shutdown_requested() {
                info!(repo = repo, "stopping MR scheduling: shutdown requested");
                return Ok(RepoScanStatus::Interrupted);
            }
            let mut mr = mr;
            if mr.head_sha().is_none() || mr.created_at.is_none() {
                mr = self.gitlab.get_mr(repo, mr.iid).await?;
            }
            let head_sha = if let Some(value) = mr.head_sha() {
                value
            } else {
                counters.missing_sha += 1;
                warn!(repo = repo, iid = mr.iid, "missing head sha, skipping");
                continue;
            };
            let mention_outcome = self
                .schedule_mention_commands_for_mr(repo, &mr, &head_sha, counters, tasks)
                .await?;
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
                counters.skipped_draft += 1;
                debug!(repo = repo, iid = mr.iid, "skip: draft MR");
                continue;
            }
            let created_at = if let Some(value) = mr.created_at.as_ref() {
                value
            } else {
                counters.skipped_created_before += 1;
                warn!(repo = repo, iid = mr.iid, "missing created_at, skipping");
                continue;
            };
            if created_at <= &self.created_after {
                counters.skipped_created_before += 1;
                debug!(
                    repo = repo,
                    iid = mr.iid,
                    created_at = %created_at,
                    cutoff = %self.created_after,
                    "skip: MR created before cutoff"
                );
                continue;
            }
            let mr_iid = mr.iid;
            let review_outcome = self
                .general_review_flow
                .schedule_for_scan(repo, mr.clone(), &head_sha, tasks)
                .await?;
            if let Some(status) = Self::apply_review_outcome(
                ReviewLane::General,
                repo,
                mr_iid,
                review_outcome,
                counters,
                &mut pending_same_mr_work,
            ) {
                return Ok(status);
            }
            let security_review_outcome = self
                .security_review_flow
                .schedule_for_scan(repo, mr, &head_sha, tasks)
                .await?;
            if let Some(status) = Self::apply_review_outcome(
                ReviewLane::Security,
                repo,
                mr_iid,
                security_review_outcome,
                counters,
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

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn review_mr(&self, repo: &str, iid: u64) -> Result<()> {
        if self.shutdown_requested() {
            info!(repo = repo, iid = iid, "skip: shutdown requested");
            return Ok(());
        }
        self.mention_flow.clear_stale_in_progress().await?;
        let mut mr = self.gitlab.get_mr(repo, iid).await?;
        let mut head_sha = if let Some(value) = mr.head_sha() {
            value
        } else {
            warn!(repo = repo, iid = iid, "missing head sha, skipping");
            return Ok(());
        };
        let mut mention_tasks = Vec::new();
        let mut counters = ScanCounters::default();
        let mention_outcome = self
            .schedule_mention_commands_for_mr(
                repo,
                &mr,
                &head_sha,
                &mut counters,
                &mut mention_tasks,
            )
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
    gitlab_error_has_status(err, &[404]) || format!("{err:#}").contains("mr not found")
}

#[cfg(test)]
mod pending_rate_limit_tests {
    use super::*;
    use crate::codex_runner::{CodexResult, ReviewContext};
    use crate::config::{
        BrowserMcpConfig, CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets,
        McpServerOverridesConfig, ReasoningSummaryOverridesConfig, ReviewConfig,
        ReviewMentionCommandsConfig, ReviewSecurityConfig, ScheduleConfig, ServerConfig,
        SessionOverridesConfig, TargetSelector,
    };
    use crate::feature_flags::FeatureFlagDefaults;
    use crate::gitlab::GitLabUser;
    use anyhow::{Result, anyhow};
    use async_trait::async_trait;
    use chrono::TimeZone;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct TestGitLab {
        bot_user: GitLabUser,
        open_mrs: Mutex<Vec<MergeRequest>>,
        mrs_by_iid: Mutex<HashMap<u64, MergeRequest>>,
        awards: Mutex<HashMap<(String, u64), Vec<crate::gitlab::AwardEmoji>>>,
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
                awards: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                mr_lookup_error: Mutex::new(None),
                list_open_calls: Mutex::new(0),
            }
        }

        fn insert_mr(&self, mr: MergeRequest) {
            self.mrs_by_iid.lock().unwrap().insert(mr.iid, mr);
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
    }

    #[derive(Default)]
    struct CapturingRunner {
        review_contexts: Mutex<Vec<ReviewContext>>,
    }

    #[async_trait]
    impl crate::codex_runner::CodexRunner for CapturingRunner {
        async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
            self.review_contexts.lock().unwrap().push(ctx);
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config {
            feature_flags: FeatureFlagDefaults::default(),
            gitlab: GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets {
                    repos: TargetSelector::List(vec!["group/repo".to_string()]),
                    groups: TargetSelector::List(vec![]),
                    exclude_repos: vec![],
                    exclude_groups: vec![],
                    refresh_seconds: 3600,
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
                deps: Default::default(),
                browser_mcp: BrowserMcpConfig::default(),
                gitlab_discovery_mcp: Default::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                session_overrides: SessionOverridesConfig::default(),
                reasoning_summary: ReasoningSummaryOverridesConfig::default(),
            },
            docker: DockerConfig::default(),
            database: DatabaseConfig {
                path: ":memory:".to_string(),
            },
            server: ServerConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                status_ui_enabled: false,
            },
        }
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

    #[tokio::test]
    async fn incremental_scan_retries_due_pending_reviews_even_when_repo_is_unchanged() -> Result<()>
    {
        let gitlab = Arc::new(TestGitLab::new(Vec::new()));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .set_project_last_mr_activity("group/repo", "2025-01-02T00:00:00Z|77")
            .await?;
        state
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
        assert!(state.list_review_rate_limit_pending().await?.is_empty());
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
        assert!(state.list_review_rate_limit_pending().await?.is_empty());
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
        assert!(state.list_review_rate_limit_pending().await?.is_empty());
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
        let pending = state.list_review_rate_limit_pending().await?;
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
        let pending = state.list_review_rate_limit_pending().await?;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].iid, 93);
        assert_eq!(pending[0].last_seen_head_sha, "sha93-new");
        assert!(pending[0].next_retry_at > 0);
        Ok(())
    }
}

#[cfg(test)]
mod tests;

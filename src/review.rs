use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::FlowShared;
use crate::flow::mention::{MentionFlow, MentionScheduleOutcome};
use crate::flow::review::{RetryBackoff, ReviewFlow, ReviewScheduleOutcome};
use crate::flow::{ActiveTaskRegistry, MergeRequestFlow};
use crate::gitlab::{GitLabApi, MergeRequest};
use crate::review_lane::ReviewLane;
use crate::state::ReviewStateStore;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

const NO_OPEN_MRS_MARKER: &str = "__no_open_mrs__";

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
    security_skipped_marker: usize,
    security_skipped_completed: usize,
    security_skipped_locked: usize,
    security_skipped_backoff: usize,
    mention_skipped_processed: usize,
    skipped_backoff: usize,
    missing_sha: usize,
    skipped_inactive: usize,
    skipped_created_before: usize,
}

pub struct ReviewService {
    config: Config,
    gitlab: Arc<dyn GitLabApi>,
    state: Arc<ReviewStateStore>,
    codex: Arc<dyn CodexRunner>,
    created_after: DateTime<Utc>,
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
            created_after,
            general_review_flow,
            security_review_flow,
            mention_flow,
            shutdown,
            active_tasks,
        }
    }

    pub async fn scan_once(&self) -> Result<ScanRunStatus> {
        self.scan(ScanMode::Full).await
    }

    pub async fn scan_once_incremental(&self) -> Result<ScanRunStatus> {
        self.scan(ScanMode::Incremental).await
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

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

    fn apply_review_outcome(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        outcome: ReviewScheduleOutcome,
        counters: &mut ScanCounters,
        pending_same_mr_work: &mut bool,
    ) -> Result<Option<RepoScanStatus>> {
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
                return Ok(Some(RepoScanStatus::Interrupted));
            }
            (ReviewLane::Security, ReviewScheduleOutcome::SkippedAward) => {
                debug!(
                    repo = repo,
                    iid = iid,
                    "skip: security review returned award outcome"
                );
            }
        }
        Ok(None)
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
                    counters.skipped_inactive += 1;
                    debug!(repo = repo.as_str(), "skip: no open MRs");
                    continue;
                }
                if let Some(previous) = previous
                    && previous == *marker
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
                    security_skipped_marker = counters.security_skipped_marker,
                    security_skipped_completed = counters.security_skipped_completed,
                    security_skipped_locked = counters.security_skipped_locked,
                    security_skipped_backoff = counters.security_skipped_backoff,
                    mention_skipped_processed = counters.mention_skipped_processed,
                    skipped_backoff = counters.skipped_backoff,
                    missing_sha = counters.missing_sha,
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
                    security_skipped_marker = counters.security_skipped_marker,
                    security_skipped_completed = counters.security_skipped_completed,
                    security_skipped_locked = counters.security_skipped_locked,
                    security_skipped_backoff = counters.security_skipped_backoff,
                    mention_skipped_processed = counters.mention_skipped_processed,
                    skipped_backoff = counters.skipped_backoff,
                    missing_sha = counters.missing_sha,
                    skipped_inactive = counters.skipped_inactive,
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
            Ok(Some(mr)) => match mr.updated_at {
                Some(updated_at) => Some(format!("{}|{}", updated_at.to_rfc3339(), mr.iid)),
                None => {
                    warn!(
                        repo = repo,
                        iid = mr.iid,
                        "latest MR missing updated_at; scanning"
                    );
                    None
                }
            },
            Ok(None) => Some(NO_OPEN_MRS_MARKER.to_string()),
            Err(err) => {
                warn!(
                    repo = repo,
                    error = %err,
                    "failed to load latest MR activity; scanning"
                );
                None
            }
        }
    }

    async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>> {
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
            .map(|group| format!("{}/", group))
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
        for mr in mrs {
            if self.shutdown_requested() {
                info!(repo = repo, "stopping MR scheduling: shutdown requested");
                return Ok(RepoScanStatus::Interrupted);
            }
            let mut mr = mr;
            if mr.head_sha().is_none() || mr.created_at.is_none() {
                mr = self.gitlab.get_mr(repo, mr.iid).await?;
            }
            let head_sha = match mr.head_sha() {
                Some(value) => value,
                None => {
                    counters.missing_sha += 1;
                    warn!(repo = repo, iid = mr.iid, "missing head sha, skipping");
                    continue;
                }
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
            let created_at = match mr.created_at.as_ref() {
                Some(value) => value,
                None => {
                    counters.skipped_created_before += 1;
                    warn!(repo = repo, iid = mr.iid, "missing created_at, skipping");
                    continue;
                }
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
            if let Some(status) = self.apply_review_outcome(
                ReviewLane::General,
                repo,
                mr_iid,
                review_outcome,
                counters,
                &mut pending_same_mr_work,
            )? {
                return Ok(status);
            }
            let security_review_outcome = self
                .security_review_flow
                .schedule_for_scan(repo, mr, &head_sha, tasks)
                .await?;
            if let Some(status) = self.apply_review_outcome(
                ReviewLane::Security,
                repo,
                mr_iid,
                security_review_outcome,
                counters,
                &mut pending_same_mr_work,
            )? {
                return Ok(status);
            }
        }
        Ok(if pending_same_mr_work {
            RepoScanStatus::PendingSameMrWork
        } else {
            RepoScanStatus::Complete
        })
    }

    pub async fn review_mr(&self, repo: &str, iid: u64) -> Result<()> {
        if self.shutdown_requested() {
            info!(repo = repo, iid = iid, "skip: shutdown requested");
            return Ok(());
        }
        self.mention_flow.clear_stale_in_progress().await?;
        let mut mr = self.gitlab.get_mr(repo, iid).await?;
        let mut head_sha = match mr.head_sha() {
            Some(value) => value,
            None => {
                warn!(repo = repo, iid = iid, "missing head sha, skipping");
                return Ok(());
            }
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
            head_sha = match mr.head_sha() {
                Some(value) => value,
                None => {
                    warn!(
                        repo = repo,
                        iid = iid,
                        "missing head sha after mention commands, skipping review"
                    );
                    return Ok(());
                }
            };
        }
        let created_at = match mr.created_at.as_ref() {
            Some(value) => value,
            None => {
                warn!(repo = repo, iid = iid, "missing created_at, skipping");
                return Ok(());
            }
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

#[cfg(test)]
mod tests;

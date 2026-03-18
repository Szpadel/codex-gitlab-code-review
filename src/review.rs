use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::FlowShared;
use crate::flow::mention::{MentionFlow, MentionScheduleOutcome};
use crate::flow::review::{RetryBackoff, ReviewFlow, ReviewScheduleOutcome};
use crate::flow::{ActiveTaskRegistry, MergeRequestFlow};
use crate::gitlab::{GitLabApi, MergeRequest};
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
    mention_scheduled: usize,
    skipped_award: usize,
    skipped_marker: usize,
    skipped_locked: usize,
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
    review_flow: ReviewFlow,
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
        let review_flow = ReviewFlow::new(flow_shared, retry_backoff);
        Self {
            config,
            gitlab,
            state,
            codex,
            created_after,
            review_flow,
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
        let flows: [&dyn MergeRequestFlow; 2] = [&self.review_flow, &self.mention_flow];
        for flow in flows {
            debug!(flow = flow.flow_name(), "recover in-progress flow state");
            flow.recover_in_progress().await?;
        }
        Ok(())
    }

    async fn clear_stale_flow_state(&self) -> Result<()> {
        self.refresh_active_flow_state().await?;
        let flows: [&dyn MergeRequestFlow; 2] = [&self.review_flow, &self.mention_flow];
        for flow in flows {
            flow.clear_stale_in_progress().await?;
        }
        Ok(())
    }

    async fn refresh_active_flow_state(&self) -> Result<()> {
        for review in self.active_tasks.active_reviews() {
            self.state
                .touch_in_progress_review(&review.repo, review.iid, &review.head_sha)
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
                    mention_scheduled = counters.mention_scheduled,
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_locked = counters.skipped_locked,
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
                    mention_scheduled = counters.mention_scheduled,
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_locked = counters.skipped_locked,
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
                .review_flow
                .schedule_for_scan(repo, mr, &head_sha, tasks)
                .await?;
            match review_outcome {
                ReviewScheduleOutcome::Scheduled => {
                    counters.scheduled += 1;
                }
                ReviewScheduleOutcome::SkippedBackoff => {
                    counters.skipped_backoff += 1;
                    debug!(repo = repo, iid = mr_iid, "skip: review backoff active");
                }
                ReviewScheduleOutcome::SkippedAward => {
                    counters.skipped_award += 1;
                    debug!(repo = repo, iid = mr_iid, "skip: thumbs up already present");
                }
                ReviewScheduleOutcome::SkippedMarker => {
                    counters.skipped_marker += 1;
                    debug!(
                        repo = repo,
                        iid = mr_iid,
                        "skip: review marker already present"
                    );
                }
                ReviewScheduleOutcome::SkippedLocked => {
                    counters.skipped_locked += 1;
                    pending_same_mr_work = true;
                    debug!(
                        repo = repo,
                        iid = mr_iid,
                        "skip: same-MR work already in progress"
                    );
                }
                ReviewScheduleOutcome::Interrupted => {
                    return Ok(RepoScanStatus::Interrupted);
                }
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
        let _ = self.review_flow.run_for_mr(repo, mr, &head_sha).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex_runner::{
        CodexResult, CodexRunner, MentionCommandContext, MentionCommandResult,
        MentionCommandStatus, ReviewContext,
    };
    use crate::config::{
        CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets,
        McpServerOverridesConfig, ReviewConfig, ReviewMentionCommandsConfig, ScheduleConfig,
        ServerConfig, TargetSelector,
    };
    use crate::flow::mention::{contains_mention, extract_parent_chain};
    use crate::flow::review::{RetryKey, ReviewRunContext};
    use crate::gitlab::{
        AwardEmoji, DiscussionNote, GitLabUser, GitLabUserDetail, MergeRequestDiscussion, Note,
    };
    use anyhow::anyhow;
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use pretty_assertions::assert_eq;
    use sqlx::Row;
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FakeGitLab {
        bot_user: GitLabUser,
        mrs: Mutex<Vec<MergeRequest>>,
        awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
        notes: Mutex<HashMap<(String, u64), Vec<Note>>>,
        discussions: Mutex<HashMap<(String, u64), Vec<MergeRequestDiscussion>>>,
        users: Mutex<HashMap<u64, GitLabUserDetail>>,
        projects: Mutex<HashMap<String, String>>,
        all_projects: Mutex<Vec<String>>,
        group_projects: Mutex<HashMap<String, Vec<String>>>,
        calls: Mutex<Vec<String>>,
        list_open_calls: Mutex<u32>,
        list_projects_calls: Mutex<u32>,
        list_group_projects_calls: Mutex<u32>,
        delete_award_fails: bool,
    }

    #[async_trait]
    impl GitLabApi for FakeGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            Ok(self.bot_user.clone())
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            *self.list_projects_calls.lock().unwrap() += 1;
            let projects = self.all_projects.lock().unwrap().clone();
            Ok(projects
                .into_iter()
                .map(|path| crate::gitlab::GitLabProjectSummary {
                    path_with_namespace: path,
                    archived: false,
                    marked_for_deletion_on: None,
                    marked_for_deletion_at: None,
                })
                .collect())
        }

        async fn list_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            *self.list_group_projects_calls.lock().unwrap() += 1;
            let map = self.group_projects.lock().unwrap();
            let projects = map.get(group).cloned().unwrap_or_default();
            Ok(projects
                .into_iter()
                .map(|path| crate::gitlab::GitLabProjectSummary {
                    path_with_namespace: path,
                    archived: false,
                    marked_for_deletion_on: None,
                    marked_for_deletion_at: None,
                })
                .collect())
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
            *self.list_open_calls.lock().unwrap() += 1;
            Ok(self.mrs.lock().unwrap().clone())
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<MergeRequest>> {
            let mrs = self.mrs.lock().unwrap();
            let mut latest: Option<MergeRequest> = None;
            for mr in mrs.iter() {
                let candidate_time = mr.updated_at.or(mr.created_at);
                let Some(candidate_time) = candidate_time else {
                    continue;
                };
                match latest.as_ref() {
                    Some(existing) => {
                        let existing_time = existing.updated_at.or(existing.created_at);
                        let replace = match existing_time {
                            Some(existing_time) => {
                                candidate_time > existing_time
                                    || (candidate_time == existing_time && mr.iid > existing.iid)
                            }
                            None => true,
                        };
                        if replace {
                            latest = Some(mr.clone());
                        }
                    }
                    None => latest = Some(mr.clone()),
                }
            }
            Ok(latest)
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
            let mrs = self.mrs.lock().unwrap();
            let found = mrs
                .iter()
                .find(|mr| mr.iid == _iid)
                .cloned()
                .ok_or_else(|| anyhow!("mr not found"))?;
            Ok(found)
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            let map = self.projects.lock().unwrap();
            let mapped = map.get(project).cloned();
            Ok(crate::gitlab::GitLabProject {
                path_with_namespace: mapped
                    .as_deref()
                    .filter(|value| value.contains('/'))
                    .map(ToOwned::to_owned)
                    .or_else(|| Some(project.to_string())),
                last_activity_at: mapped.filter(|value| !value.contains('/')),
            })
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            let map = self.awards.lock().unwrap();
            Ok(map
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
            if self.delete_award_fails {
                return Err(anyhow!("delete failed"));
            }
            self.calls
                .lock()
                .unwrap()
                .push(format!("delete_award:{project}:{iid}:{award_id}"));
            Ok(())
        }

        async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
            let map = self.notes.lock().unwrap();
            Ok(map
                .get(&(project.to_string(), iid))
                .cloned()
                .unwrap_or_default())
        }

        async fn create_note(&self, project: &str, iid: u64, _body: &str) -> Result<()> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("create_note:{project}:{iid}"));
            Ok(())
        }

        async fn list_discussions(
            &self,
            project: &str,
            iid: u64,
        ) -> Result<Vec<MergeRequestDiscussion>> {
            let map = self.discussions.lock().unwrap();
            Ok(map
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
        ) -> Result<Vec<AwardEmoji>> {
            let calls = self.calls.lock().unwrap();
            let add_prefix =
                format!("add_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:");
            let delete_prefix =
                format!("delete_discussion_note_award:{project}:{iid}:{discussion_id}:{note_id}:");
            let added_emoji = calls
                .iter()
                .rev()
                .find_map(|call| call.strip_prefix(&add_prefix).map(ToOwned::to_owned));
            let has_delete = calls.iter().any(|call| call.starts_with(&delete_prefix));
            if let Some(name) = added_emoji.filter(|_| !has_delete) {
                return Ok(vec![AwardEmoji {
                    id: note_id + 10_000,
                    name,
                    user: self.bot_user.clone(),
                }]);
            }
            Ok(Vec::new())
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

        async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
            self.users
                .lock()
                .unwrap()
                .get(&user_id)
                .cloned()
                .ok_or_else(|| anyhow!("user not found"))
        }
    }

    struct FakeRunner {
        result: Mutex<Option<CodexResult>>,
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for FakeRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            *self.calls.lock().unwrap() += 1;
            Ok(self
                .result
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(CodexResult::Pass {
                    summary: "ok".to_string(),
                }))
        }
    }

    struct CapturingReviewRunner {
        result: Mutex<Option<CodexResult>>,
        review_contexts: Mutex<Vec<ReviewContext>>,
    }

    #[async_trait]
    impl CodexRunner for CapturingReviewRunner {
        async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
            self.review_contexts.lock().unwrap().push(ctx);
            Ok(self
                .result
                .lock()
                .unwrap()
                .clone()
                .unwrap_or(CodexResult::Pass {
                    summary: "ok".to_string(),
                }))
        }
    }

    struct FailingRunner {
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for FailingRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            *self.calls.lock().unwrap() += 1;
            Err(anyhow!("runner failed"))
        }
    }

    struct BlockingReviewRunner {
        first_started: Arc<tokio::sync::Notify>,
        release_first: Arc<tokio::sync::Notify>,
        review_calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for BlockingReviewRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            let call_index = {
                let mut review_calls = self.review_calls.lock().unwrap();
                *review_calls += 1;
                *review_calls
            };
            if call_index == 1 {
                self.first_started.notify_waiters();
                self.release_first.notified().await;
            }
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }
    }

    struct MentionRunner {
        mention_calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for MentionRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            *self.mention_calls.lock().unwrap() += 1;
            Ok(MentionCommandResult {
                status: MentionCommandStatus::Committed,
                commit_sha: Some("deadbeef".to_string()),
                reply_message: "Implemented and committed deadbeef".to_string(),
            })
        }
    }

    struct BlockingMentionRunner {
        first_started: Arc<tokio::sync::Notify>,
        release_first: Arc<tokio::sync::Notify>,
        mention_calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for BlockingMentionRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            let call_index = {
                let mut mention_calls = self.mention_calls.lock().unwrap();
                *mention_calls += 1;
                *mention_calls
            };
            if call_index == 1 {
                self.first_started.notify_waiters();
                self.release_first.notified().await;
            }
            Ok(MentionCommandResult {
                status: MentionCommandStatus::NoChanges,
                commit_sha: None,
                reply_message: "No code changes required.".to_string(),
            })
        }
    }

    struct MentionAndReviewCounterRunner {
        mention_calls: Mutex<u32>,
        review_calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for MentionAndReviewCounterRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            *self.review_calls.lock().unwrap() += 1;
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }

        async fn run_mention_command(
            &self,
            _ctx: MentionCommandContext,
        ) -> Result<MentionCommandResult> {
            *self.mention_calls.lock().unwrap() += 1;
            Ok(MentionCommandResult {
                status: MentionCommandStatus::NoChanges,
                commit_sha: None,
                reply_message: "No code changes required.".to_string(),
            })
        }
    }

    struct RecoveryRunner {
        stop_calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for RecoveryRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            Err(anyhow!("run_review should not be called in recovery test"))
        }

        async fn stop_active_reviews(&self) -> Result<()> {
            *self.stop_calls.lock().unwrap() += 1;
            Ok(())
        }
    }

    struct ShutdownTriggerRunner {
        shutdown: Arc<AtomicBool>,
        calls: Mutex<u32>,
    }

    #[async_trait]
    impl CodexRunner for ShutdownTriggerRunner {
        async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
            *self.calls.lock().unwrap() += 1;
            self.shutdown.store(true, Ordering::SeqCst);
            Ok(CodexResult::Pass {
                summary: "ok".to_string(),
            })
        }
    }

    struct ShutdownOnEyesAwardGitLab {
        inner: Arc<FakeGitLab>,
        shutdown: Arc<AtomicBool>,
        eyes_emoji: String,
    }

    #[async_trait]
    impl GitLabApi for ShutdownOnEyesAwardGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.inner.current_user().await
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_projects().await
        }

        async fn list_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_group_projects(group).await
        }

        async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
            self.inner.list_open_mrs(project).await
        }

        async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
            self.inner.get_latest_open_mr_activity(project).await
        }

        async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
            self.inner.get_mr(project, iid).await
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            self.inner.get_project(project).await
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            self.inner.list_awards(project, iid).await
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            if name == self.eyes_emoji {
                self.shutdown.store(true, Ordering::SeqCst);
            }
            self.inner.add_award(project, iid, name).await
        }

        async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
            self.inner.delete_award(project, iid, award_id).await
        }

        async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
            self.inner.list_notes(project, iid).await
        }

        async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
            self.inner.create_note(project, iid, body).await
        }
    }

    struct ShutdownOnListOpenGitLab {
        inner: Arc<FakeGitLab>,
        shutdown: Arc<AtomicBool>,
    }

    #[async_trait]
    impl GitLabApi for ShutdownOnListOpenGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.inner.current_user().await
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_projects().await
        }

        async fn list_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_group_projects(group).await
        }

        async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
            self.shutdown.store(true, Ordering::SeqCst);
            self.inner.list_open_mrs(project).await
        }

        async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
            self.inner.get_latest_open_mr_activity(project).await
        }

        async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
            self.inner.get_mr(project, iid).await
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            self.inner.get_project(project).await
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            self.inner.list_awards(project, iid).await
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.inner.add_award(project, iid, name).await
        }

        async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
            self.inner.delete_award(project, iid, award_id).await
        }

        async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
            self.inner.list_notes(project, iid).await
        }

        async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
            self.inner.create_note(project, iid, body).await
        }
    }

    struct ShutdownOnListAwardsGitLab {
        inner: Arc<FakeGitLab>,
        shutdown: Arc<AtomicBool>,
    }

    #[async_trait]
    impl GitLabApi for ShutdownOnListAwardsGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.inner.current_user().await
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_projects().await
        }

        async fn list_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_group_projects(group).await
        }

        async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
            self.inner.list_open_mrs(project).await
        }

        async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
            self.inner.get_latest_open_mr_activity(project).await
        }

        async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
            self.inner.get_mr(project, iid).await
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            self.inner.get_project(project).await
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            self.shutdown.store(true, Ordering::SeqCst);
            self.inner.list_awards(project, iid).await
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.inner.add_award(project, iid, name).await
        }

        async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
            self.inner.delete_award(project, iid, award_id).await
        }

        async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
            self.inner.list_notes(project, iid).await
        }

        async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
            self.inner.create_note(project, iid, body).await
        }
    }

    struct RefreshedMentionGitLab {
        inner: Arc<FakeGitLab>,
        refreshed_mr: MergeRequest,
    }

    #[async_trait]
    impl GitLabApi for RefreshedMentionGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            self.inner.current_user().await
        }

        async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_projects().await
        }

        async fn list_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
            self.inner.list_group_projects(group).await
        }

        async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
            self.inner.list_open_mrs(project).await
        }

        async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
            self.inner.get_latest_open_mr_activity(project).await
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
            Ok(self.refreshed_mr.clone())
        }

        async fn get_project(&self, project: &str) -> Result<crate::gitlab::GitLabProject> {
            self.inner.get_project(project).await
        }

        async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
            self.inner.list_awards(project, iid).await
        }

        async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
            self.inner.add_award(project, iid, name).await
        }

        async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
            self.inner.delete_award(project, iid, award_id).await
        }

        async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
            self.inner.list_notes(project, iid).await
        }

        async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
            self.inner.create_note(project, iid, body).await
        }

        async fn list_discussions(
            &self,
            project: &str,
            iid: u64,
        ) -> Result<Vec<MergeRequestDiscussion>> {
            self.inner.list_discussions(project, iid).await
        }

        async fn create_discussion_note(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            body: &str,
        ) -> Result<()> {
            self.inner
                .create_discussion_note(project, iid, discussion_id, body)
                .await
        }

        async fn list_discussion_note_awards(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
        ) -> Result<Vec<AwardEmoji>> {
            self.inner
                .list_discussion_note_awards(project, iid, discussion_id, note_id)
                .await
        }

        async fn add_discussion_note_award(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
            name: &str,
        ) -> Result<()> {
            self.inner
                .add_discussion_note_award(project, iid, discussion_id, note_id, name)
                .await
        }

        async fn delete_discussion_note_award(
            &self,
            project: &str,
            iid: u64,
            discussion_id: &str,
            note_id: u64,
            award_id: u64,
        ) -> Result<()> {
            self.inner
                .delete_discussion_note_award(project, iid, discussion_id, note_id, award_id)
                .await
        }

        async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
            self.inner.get_user(user_id).await
        }
    }

    fn test_config() -> Config {
        Config {
            feature_flags: crate::feature_flags::FeatureFlagDefaults::default(),
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
                comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                stale_in_progress_minutes: 60,
                dry_run: false,
                additional_developer_instructions: None,
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
                deps: crate::config::DepsConfig { enabled: false },
                browser_mcp: crate::config::BrowserMcpConfig::default(),
                gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                reasoning_effort: crate::config::ReasoningEffortOverridesConfig::default(),
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

    fn default_created_at() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
            .single()
            .expect("valid datetime")
    }

    fn default_created_after() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2024, 12, 31, 0, 0, 0)
            .single()
            .expect("valid datetime")
    }

    fn mr(iid: u64, sha: &str) -> MergeRequest {
        mr_with_created_at(iid, sha, default_created_at())
    }

    fn mr_with_created_at(iid: u64, sha: &str, created_at: DateTime<Utc>) -> MergeRequest {
        MergeRequest {
            iid,
            title: None,
            web_url: None,
            created_at: Some(created_at),
            updated_at: Some(created_at),
            sha: Some(sha.to_string()),
            source_branch: None,
            target_branch: None,
            author: Some(GitLabUser {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
            }),
            source_project_id: Some(1),
            target_project_id: Some(1),
            diff_refs: None,
        }
    }

    #[tokio::test]
    async fn skips_when_thumbsup_exists() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(1, "sha1")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 1),
                vec![AwardEmoji {
                    id: 10,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.calls.lock().unwrap(), 0);
        assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn skips_when_comment_marker_exists() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let marker = format!("{}sha1 -->", config.review.comment_marker_prefix);
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(2, "sha1")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 2),
                vec![Note {
                    id: 99,
                    body: format!("Review\n\n{}", marker),
                    author: bot_user,
                }],
            )])),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.calls.lock().unwrap(), 0);
        assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn skips_when_created_before_cutoff() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let created_at = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let cutoff = Utc
            .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr_with_created_at(5, "sha1", created_at)]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(config, gitlab.clone(), state, runner.clone(), 1, cutoff);

        service.scan_once().await?;

        assert_eq!(*runner.calls.lock().unwrap(), 0);
        assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn dry_run_skips_writes() -> Result<()> {
        let mut config = test_config();
        config.review.dry_run = true;
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(3, "sha1")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.calls.lock().unwrap(), 1);
        assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn review_history_insert_failure_releases_review_lock() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![mr(40, "sha40")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        sqlx::query("DROP TABLE run_history")
            .execute(state.pool())
            .await?;
        let service = ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner.clone(),
            1,
            default_created_after(),
        );

        assert!(service.scan_once().await.is_err());
        assert_eq!(*runner.calls.lock().unwrap(), 0);
        assert!(state.list_in_progress_reviews().await?.is_empty());
        let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(40i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result.as_deref(), Some("error"));
        Ok(())
    }

    #[tokio::test]
    async fn error_backoff_skips_repeat_and_no_error_comment() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(6, "sha1")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FailingRunner {
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;
        service.scan_once().await?;

        assert_eq!(*runner.calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap();
        assert!(calls.iter().all(|call| !call.starts_with("create_note:")));
        Ok(())
    }

    #[tokio::test]
    async fn fork_reviews_use_source_project_path_for_runner_context() -> Result<()> {
        let mut config = test_config();
        config.gitlab.targets.repos = TargetSelector::List(vec!["target/repo".to_string()]);
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let mut fork_mr = mr(12, "sha1");
        fork_mr.source_project_id = Some(42);
        fork_mr.target_project_id = Some(7);
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![fork_mr]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::from([(
                "42".to_string(),
                "forks/source-repo".to_string(),
            )])),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(CapturingReviewRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            review_contexts: Mutex::new(Vec::new()),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab,
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        let _ = service.scan_once().await?;

        let contexts = runner.review_contexts.lock().unwrap();
        assert_eq!(contexts.len(), 1);
        assert_eq!(contexts[0].repo, "target/repo");
        assert_eq!(contexts[0].project_path, "forks/source-repo");
        Ok(())
    }

    #[test]
    fn retry_backoff_doubles_delay() {
        let backoff = RetryBackoff::new(Duration::hours(1));
        let key = RetryKey::new("group/repo", 1, "sha1");
        let start = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("valid datetime");

        let next_first = backoff.record_failure(key.clone(), start);
        assert_eq!(next_first, start + Duration::hours(1));

        let next_second = backoff.record_failure(key.clone(), next_first);
        assert_eq!(next_second, next_first + Duration::hours(2));

        let state = backoff.state_for(&key).expect("backoff state");
        assert_eq!(state.failures, 2);
    }

    #[tokio::test]
    async fn incremental_skips_when_activity_unchanged() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(10, "sha1")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::from([(
                "group/repo".to_string(),
                "2025-01-01T00:00:00Z".to_string(),
            )])),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let activity_marker = format!("{}|{}", default_created_at().to_rfc3339(), 10);
        state
            .set_project_last_mr_activity("group/repo", &activity_marker)
            .await?;
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
        assert_eq!(*runner.calls.lock().unwrap(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn incremental_scans_when_activity_changes() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(11, "sha1")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::from([(
                "group/repo".to_string(),
                "2025-01-02T00:00:00Z".to_string(),
            )])),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            11
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 1);
        assert_eq!(*runner.calls.lock().unwrap(), 1);
        let stored = state.get_project_last_mr_activity("group/repo").await?;
        let current_marker = format!("{}|{}", default_created_at().to_rfc3339(), 11);
        assert_eq!(stored, Some(current_marker));
        Ok(())
    }

    #[tokio::test]
    async fn incremental_does_not_advance_marker_when_repo_scan_is_interrupted() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let base_gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![mr(12, "sha12")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let gitlab = Arc::new(ShutdownOnListOpenGitLab {
            inner: Arc::clone(&base_gitlab),
            shutdown: Arc::clone(&shutdown),
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            12
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        let mut service = ReviewService::new(
            config,
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );
        service.shutdown = shutdown;

        service.scan_once_incremental().await?;

        assert_eq!(*base_gitlab.list_open_calls.lock().unwrap(), 1);
        assert_eq!(*runner.calls.lock().unwrap(), 0);
        let stored = state.get_project_last_mr_activity("group/repo").await?;
        assert_eq!(stored, Some(previous_marker));
        Ok(())
    }

    #[tokio::test]
    async fn incremental_uses_cached_project_catalog() -> Result<()> {
        let mut config = test_config();
        config.gitlab.targets.repos = TargetSelector::All;
        config.gitlab.targets.refresh_seconds = 3600;

        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(vec!["group/ignored".to_string()]),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let cache_key = config.gitlab.targets.cache_key_for_all();
        state
            .save_project_catalog(&cache_key, &["group/repo".to_string()])
            .await?;
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner,
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 0);
        assert_eq!(*gitlab.list_open_calls.lock().unwrap(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn incremental_refreshes_project_catalog_when_expired() -> Result<()> {
        let mut config = test_config();
        config.gitlab.targets.repos = TargetSelector::All;
        config.gitlab.targets.refresh_seconds = 0;

        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(vec!["group/fresh".to_string()]),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let cache_key = config.gitlab.targets.cache_key_for_all();
        state
            .save_project_catalog(&cache_key, &["group/stale".to_string()])
            .await?;
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner,
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*gitlab.list_projects_calls.lock().unwrap(), 1);
        let loaded = state
            .load_project_catalog(&cache_key)
            .await?
            .expect("catalog");
        assert_eq!(loaded.projects, vec!["group/fresh".to_string()]);
        Ok(())
    }

    #[tokio::test]
    async fn incremental_scan_returns_before_blocking_review_finishes() -> Result<()> {
        let mut config = test_config();
        config.review.max_concurrent = 1;
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let review_mr = mr(40, "sha40");
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![review_mr]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let first_started = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let runner = Arc::new(BlockingReviewRunner {
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            40
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        let service = Arc::new(ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner.clone(),
            1,
            default_created_after(),
        ));

        let first_started_wait = first_started.notified();
        let scan_task = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.scan_once_incremental().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

        let scan_status =
            tokio::time::timeout(std::time::Duration::from_millis(200), scan_task).await???;
        assert_eq!(scan_status, ScanRunStatus::Completed);

        let in_progress = state.list_in_progress_reviews().await?;
        assert_eq!(in_progress.len(), 1);
        assert_eq!(in_progress[0].iid, 40);
        assert_eq!(*runner.review_calls.lock().unwrap(), 1);

        release_first.notify_waiters();
        for _ in 0..50 {
            if state.list_in_progress_reviews().await?.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(state.list_in_progress_reviews().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn second_incremental_scan_returns_while_first_review_holds_only_permit() -> Result<()> {
        let mut config = test_config();
        config.review.max_concurrent = 1;
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let mut first_mr = mr(70, "sha70");
        first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![first_mr.clone()]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let first_started = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let runner = Arc::new(BlockingReviewRunner {
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            70
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        let service = Arc::new(ReviewService::new(
            config,
            gitlab.clone(),
            Arc::clone(&state),
            runner.clone(),
            1,
            default_created_after(),
        ));

        let first_started_wait = first_started.notified();
        let first_scan_task = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.scan_once_incremental().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
        let first_scan_status =
            tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task)
                .await???;
        assert_eq!(first_scan_status, ScanRunStatus::Completed);

        let mut second_mr = mr(71, "sha71");
        second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
        *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr];

        let second_scan_status = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            service.scan_once_incremental(),
        )
        .await??;
        assert_eq!(second_scan_status, ScanRunStatus::Completed);

        assert_eq!(*runner.review_calls.lock().unwrap(), 1);
        let review_iids: Vec<i64> =
            sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
                .fetch_all(state.pool())
                .await?;
        assert_eq!(review_iids, vec![70, 71]);
        let in_progress = state.list_in_progress_reviews().await?;
        assert_eq!(in_progress.len(), 2);

        release_first.notify_waiters();
        for _ in 0..50 {
            if *runner.review_calls.lock().unwrap() == 2
                && state.list_in_progress_reviews().await?.is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*runner.review_calls.lock().unwrap(), 2);
        assert!(state.list_in_progress_reviews().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn queued_reviews_are_heartbeated_across_incremental_scans() -> Result<()> {
        let mut config = test_config();
        config.review.max_concurrent = 1;
        config.review.stale_in_progress_minutes = 0;
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let mut first_mr = mr(80, "sha80");
        first_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
        let mut second_mr = mr(81, "sha81");
        second_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![first_mr.clone(), second_mr.clone()]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let first_started = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let runner = Arc::new(BlockingReviewRunner {
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            80
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        let service = Arc::new(ReviewService::new(
            config,
            gitlab.clone(),
            Arc::clone(&state),
            runner.clone(),
            1,
            default_created_after(),
        ));

        let first_started_wait = first_started.notified();
        let first_scan_task = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.scan_once_incremental().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;
        let first_scan_status =
            tokio::time::timeout(std::time::Duration::from_millis(200), first_scan_task)
                .await???;
        assert_eq!(first_scan_status, ScanRunStatus::Completed);

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let mut third_mr = mr(82, "sha82");
        third_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
        *gitlab.mrs.lock().unwrap() = vec![first_mr, second_mr, third_mr];

        let second_scan_status = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            service.scan_once_incremental(),
        )
        .await??;
        assert_eq!(second_scan_status, ScanRunStatus::Completed);

        let run_counts: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT iid, COUNT(*) FROM run_history WHERE kind = 'review' GROUP BY iid ORDER BY iid",
        )
        .fetch_all(state.pool())
        .await?;
        assert_eq!(run_counts, vec![(80, 1), (81, 1), (82, 1)]);

        release_first.notify_waiters();
        for _ in 0..50 {
            if *runner.review_calls.lock().unwrap() == 3
                && state.list_in_progress_reviews().await?.is_empty()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*runner.review_calls.lock().unwrap(), 3);
        assert!(state.list_in_progress_reviews().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn incremental_defers_same_mr_mentions_while_active_mention_blocks_review() -> Result<()>
    {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let mut busy_mr = mr(41, "sha41");
        busy_mr.updated_at = Some(default_created_at() + Duration::minutes(2));
        let mut other_mr = mr(42, "sha42");
        other_mr.updated_at = Some(default_created_at() + Duration::minutes(1));
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![busy_mr, other_mr]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 41),
                vec![MergeRequestDiscussion {
                    id: "discussion-41".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 1040,
                            body: "bot context".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 1041,
                            body: "@botuser first request".to_string(),
                            author: requester.clone(),
                            system: false,
                            in_reply_to_id: Some(1040),
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 1042,
                            body: "@botuser second request".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(1040),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionAndReviewCounterRunner {
            mention_calls: Mutex::new(0),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            41
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        state
            .begin_mention_command("group/repo", 41, "discussion-41", 1041, "sha41")
            .await?;
        let service = ReviewService::new(
            config,
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        for _ in 0..50 {
            if *runner.review_calls.lock().unwrap() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*runner.review_calls.lock().unwrap(), 1);
        assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
        let review_iids: Vec<i64> =
            sqlx::query_scalar("SELECT iid FROM run_history WHERE kind = 'review' ORDER BY iid")
                .fetch_all(state.pool())
                .await?;
        assert_eq!(review_iids, vec![42]);
        let mention_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
                .fetch_one(state.pool())
                .await?;
        assert_eq!(mention_rows, 0);
        let stored = state.get_project_last_mr_activity("group/repo").await?;
        assert_eq!(stored, Some(previous_marker.clone()));

        state
            .finish_mention_command(
                "group/repo",
                41,
                "discussion-41",
                1041,
                "sha41",
                "no_changes",
            )
            .await?;

        service.scan_once_incremental().await?;

        for _ in 0..50 {
            if *runner.mention_calls.lock().unwrap() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        let blocked_review_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM run_history WHERE kind = 'review' AND iid = ?",
        )
        .bind(41i64)
        .fetch_one(state.pool())
        .await?;
        assert_eq!(blocked_review_rows, 0);
        let second_trigger_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(41i64)
        .bind("discussion-41")
        .bind(1042i64)
        .fetch_one(state.pool())
        .await?;
        assert_eq!(second_trigger_rows, 1);
        Ok(())
    }

    #[tokio::test]
    async fn incremental_defers_new_mentions_while_same_mr_review_is_in_progress() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let mut active_review_mr = mr(51, "sha51");
        active_review_mr.updated_at = Some(default_created_at() + Duration::minutes(3));
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![active_review_mr]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 51),
                vec![MergeRequestDiscussion {
                    id: "discussion-51".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 1050,
                            body: "bot context".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 1051,
                            body: "@botuser please follow up".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(1050),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionAndReviewCounterRunner {
            mention_calls: Mutex::new(0),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let previous_marker = format!(
            "{}|{}",
            (default_created_at() - Duration::days(1)).to_rfc3339(),
            51
        );
        state
            .set_project_last_mr_activity("group/repo", &previous_marker)
            .await?;
        state.begin_review("group/repo", 51, "sha51").await?;
        let service = ReviewService::new(
            config,
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once_incremental().await?;

        assert_eq!(*runner.review_calls.lock().unwrap(), 0);
        assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
        let mention_rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
                .fetch_one(state.pool())
                .await?;
        assert_eq!(mention_rows, 0);
        let stored = state.get_project_last_mr_activity("group/repo").await?;
        assert_eq!(stored, Some(previous_marker.clone()));

        state
            .finish_review("group/repo", 51, "sha51", "pass")
            .await?;

        service.scan_once_incremental().await?;

        assert_eq!(*runner.review_calls.lock().unwrap(), 0);
        for _ in 0..50 {
            if *runner.mention_calls.lock().unwrap() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        let scheduled_trigger_rows: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(51i64)
        .bind("discussion-51")
        .bind(1051i64)
        .fetch_one(state.pool())
        .await?;
        assert_eq!(scheduled_trigger_rows, 1);
        Ok(())
    }

    #[tokio::test]
    async fn review_finishes_when_eye_removal_fails() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(4, "sha1")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 4),
                vec![AwardEmoji {
                    id: 55,
                    name: "eyes".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: true,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner,
            1,
            default_created_after(),
        );

        service.review_mr("group/repo", 4).await?;

        let row = sqlx::query("SELECT status FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(4i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        assert_eq!(status, "done");
        Ok(())
    }

    #[tokio::test]
    async fn recover_in_progress_reviews_cancels_and_removes_eyes() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 20),
                vec![AwardEmoji {
                    id: 200,
                    name: "eyes".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(RecoveryRunner {
            stop_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state.begin_review("group/repo", 20, "sha20").await?;
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.recover_in_progress_reviews().await?;

        assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "delete_award:group/repo:20:200")
        );
        let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(20i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("cancelled".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn recover_in_progress_reviews_marks_mentions_error_without_review_rows() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(RecoveryRunner {
            stop_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        assert!(
            state
                .begin_mention_command("group/repo", 21, "discussion-1", 901, "sha21")
                .await?
        );
        gitlab
            .calls
            .lock()
            .unwrap()
            .push("add_discussion_note_award:group/repo:21:discussion-1:901:eyes".to_string());
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.recover_in_progress_reviews().await?;

        assert_eq!(*runner.stop_calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(calls.iter().any(|call| {
            call.as_str() == "delete_discussion_note_award:group/repo:21:discussion-1:901:10901"
        }));
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(21i64)
        .bind("discussion-1")
        .bind(901i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("error".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn recover_in_progress_reviews_dry_run_skips_mention_reaction_cleanup() -> Result<()> {
        let mut config = test_config();
        config.review.dry_run = true;
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(RecoveryRunner {
            stop_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        assert!(
            state
                .begin_mention_command("group/repo", 22, "discussion-2", 902, "sha22")
                .await?
        );
        gitlab
            .calls
            .lock()
            .unwrap()
            .push("add_discussion_note_award:group/repo:22:discussion-2:902:eyes".to_string());
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.recover_in_progress_reviews().await?;

        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(!calls.iter().any(|call| {
            call.starts_with("delete_discussion_note_award:group/repo:22:discussion-2:902:")
        }));
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(22i64)
        .bind("discussion-2")
        .bind(902i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("error".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_request_skips_new_review_runs() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![mr(21, "sha21")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state,
            runner.clone(),
            1,
            default_created_after(),
        );
        service.request_shutdown();

        service.review_mr("group/repo", 21).await?;

        assert_eq!(*runner.calls.lock().unwrap(), 0);
        assert_eq!(gitlab.calls.lock().unwrap().len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn scan_once_reports_interrupted_when_shutdown_requested_before_start() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let service = ReviewService::new(
            config,
            Arc::new(FakeGitLab {
                bot_user,
                mrs: Mutex::new(Vec::new()),
                awards: Mutex::new(HashMap::new()),
                notes: Mutex::new(HashMap::new()),
                discussions: Mutex::new(HashMap::new()),
                users: Mutex::new(HashMap::new()),
                projects: Mutex::new(HashMap::new()),
                all_projects: Mutex::new(Vec::new()),
                group_projects: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                list_open_calls: Mutex::new(0),
                list_projects_calls: Mutex::new(0),
                list_group_projects_calls: Mutex::new(0),
                delete_award_fails: false,
            }),
            Arc::new(ReviewStateStore::new(":memory:").await?),
            Arc::new(FakeRunner {
                result: Mutex::new(None),
                calls: Mutex::new(0),
            }),
            1,
            default_created_after(),
        );
        service.request_shutdown();

        let status = service.scan_once().await?;

        assert_eq!(status, ScanRunStatus::Interrupted);
        Ok(())
    }

    #[tokio::test]
    async fn review_marks_cancelled_when_shutdown_requested_after_runner_completes() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 22),
                vec![AwardEmoji {
                    id: 220,
                    name: "eyes".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state.begin_review("group/repo", 22, "sha22").await?;
        let shutdown = Arc::new(AtomicBool::new(false));
        let runner = Arc::new(ShutdownTriggerRunner {
            shutdown: Arc::clone(&shutdown),
            calls: Mutex::new(0),
        });
        let review_context = ReviewRunContext {
            config,
            gitlab: gitlab.clone(),
            codex: runner.clone(),
            state: state.clone(),
            retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
            bot_user_id: 1,
            shutdown,
        };

        review_context
            .run(
                "group/repo",
                mr(22, "sha22"),
                "sha22",
                crate::feature_flags::FeatureFlagSnapshot::default(),
                0,
            )
            .await?;

        assert_eq!(*runner.calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "add_award:group/repo:22:eyes")
        );
        assert!(
            calls
                .iter()
                .any(|call| call == "delete_award:group/repo:22:220")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call == "add_award:group/repo:22:thumbsup")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.starts_with("create_note:group/repo:22"))
        );

        let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(22i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("cancelled".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn review_marks_cancelled_without_starting_runner_when_shutdown_requested_during_eyes_award()
    -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let base_gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 23),
                vec![AwardEmoji {
                    id: 230,
                    name: "eyes".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let gitlab = Arc::new(ShutdownOnEyesAwardGitLab {
            inner: Arc::clone(&base_gitlab),
            shutdown: Arc::clone(&shutdown),
            eyes_emoji: config.review.eyes_emoji.clone(),
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state.begin_review("group/repo", 23, "sha23").await?;
        let review_context = ReviewRunContext {
            config,
            gitlab,
            codex: runner.clone(),
            state: state.clone(),
            retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
            bot_user_id: 1,
            shutdown,
        };

        review_context
            .run(
                "group/repo",
                mr(23, "sha23"),
                "sha23",
                crate::feature_flags::FeatureFlagSnapshot::default(),
                0,
            )
            .await?;

        assert_eq!(*runner.calls.lock().unwrap(), 0);
        let calls = base_gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "add_award:group/repo:23:eyes")
        );
        assert!(
            calls
                .iter()
                .any(|call| call == "delete_award:group/repo:23:230")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call == "add_award:group/repo:23:thumbsup")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.starts_with("create_note:group/repo:23"))
        );

        let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(23i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("cancelled".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn review_marks_cancelled_when_shutdown_requested_during_eyes_removal() -> Result<()> {
        let config = test_config();
        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let base_gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 24),
                vec![AwardEmoji {
                    id: 240,
                    name: "eyes".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let shutdown = Arc::new(AtomicBool::new(false));
        let gitlab = Arc::new(ShutdownOnListAwardsGitLab {
            inner: Arc::clone(&base_gitlab),
            shutdown: Arc::clone(&shutdown),
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(Some(CodexResult::Pass {
                summary: "ok".to_string(),
            })),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state.begin_review("group/repo", 24, "sha24").await?;
        let review_context = ReviewRunContext {
            config,
            gitlab,
            codex: runner.clone(),
            state: state.clone(),
            retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
            bot_user_id: 1,
            shutdown,
        };

        review_context
            .run(
                "group/repo",
                mr(24, "sha24"),
                "sha24",
                crate::feature_flags::FeatureFlagSnapshot::default(),
                0,
            )
            .await?;

        assert_eq!(*runner.calls.lock().unwrap(), 1);
        let calls = base_gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "add_award:group/repo:24:eyes")
        );
        assert!(
            calls
                .iter()
                .any(|call| call == "delete_award:group/repo:24:240")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call == "add_award:group/repo:24:thumbsup")
        );
        assert!(
            !calls
                .iter()
                .any(|call| call.starts_with("create_note:group/repo:24"))
        );

        let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(24i64)
            .fetch_one(state.pool())
            .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("cancelled".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn queued_reviews_snapshot_feature_flags_before_runner_start() -> Result<()> {
        let mut config = test_config();
        config.review.max_concurrent = 1;
        config.codex.gitlab_discovery_mcp.enabled = true;
        config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["group/repo".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }];
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(vec![mr(60, "sha60"), mr(61, "sha61")]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let first_started = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let runner = Arc::new(BlockingReviewRunner {
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .set_runtime_feature_flag_overrides(
                &crate::feature_flags::RuntimeFeatureFlagOverrides {
                    gitlab_discovery_mcp: Some(true),
                    composer_install: None,
                    composer_safe_install: None,
                },
            )
            .await?;
        let service = Arc::new(ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner,
            1,
            default_created_after(),
        ));

        let first_started_wait = first_started.notified();
        let scan_task = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.scan_once().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

        for _ in 0..50 {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'review'")
                    .fetch_one(state.pool())
                    .await?;
            if count == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        state
            .set_runtime_feature_flag_overrides(
                &crate::feature_flags::RuntimeFeatureFlagOverrides {
                    gitlab_discovery_mcp: Some(false),
                    composer_install: None,
                    composer_safe_install: None,
                },
            )
            .await?;

        let mut snapshots = Vec::new();
        for _ in 0..50 {
            let rows = sqlx::query(
                "SELECT feature_flags_json FROM run_history WHERE kind = 'review' ORDER BY iid",
            )
            .fetch_all(state.pool())
            .await?;
            if rows.len() == 2 {
                snapshots = rows
                    .into_iter()
                    .map(|row| {
                        let json: String = row.try_get("feature_flags_json")?;
                        let snapshot = serde_json::from_str::<
                            crate::feature_flags::FeatureFlagSnapshot,
                        >(&json)?;
                        Ok(snapshot)
                    })
                    .collect::<Result<Vec<_>>>()?;
                if snapshots
                    .iter()
                    .all(|snapshot| snapshot.gitlab_discovery_mcp)
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(snapshots.len(), 2);
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
        );

        release_first.notify_waiters();
        scan_task.await??;
        Ok(())
    }

    #[test]
    fn mention_detection_honors_boundaries() {
        assert!(contains_mention("@botuser please fix", "botuser"));
        assert!(contains_mention("@botuser.", "botuser"));
        assert!(contains_mention("ping (@botuser).", "botuser"));
        assert!(!contains_mention("@botuser2 please fix", "botuser"));
        assert!(!contains_mention("@botuser.example please fix", "botuser"));
        assert!(!contains_mention("emailbotuser@example.com", "botuser"));
    }

    #[test]
    fn extract_parent_chain_uses_reply_chain_when_available() {
        let discussion = MergeRequestDiscussion {
            id: "discussion".to_string(),
            notes: vec![
                DiscussionNote {
                    id: 1,
                    body: "root".to_string(),
                    author: GitLabUser {
                        id: 1,
                        username: Some("a".to_string()),
                        name: None,
                    },
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                },
                DiscussionNote {
                    id: 2,
                    body: "reply".to_string(),
                    author: GitLabUser {
                        id: 2,
                        username: Some("b".to_string()),
                        name: None,
                    },
                    system: false,
                    in_reply_to_id: Some(1),
                    created_at: None,
                },
                DiscussionNote {
                    id: 3,
                    body: "second reply".to_string(),
                    author: GitLabUser {
                        id: 3,
                        username: Some("c".to_string()),
                        name: None,
                    },
                    system: false,
                    in_reply_to_id: Some(2),
                    created_at: None,
                },
            ],
        };
        let chain = extract_parent_chain(&discussion, 3).expect("chain");
        assert_eq!(
            chain.iter().map(|note| note.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[tokio::test]
    async fn scan_runs_mention_command_for_triggered_discussion_note() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        config.review.mention_commands.eyes_emoji = Some("inspect".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(30, "sha30")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 30),
                vec![AwardEmoji {
                    id: 301,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 30),
                vec![MergeRequestDiscussion {
                    id: "discussion-1".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 900,
                            body: "initial review comment".to_string(),
                            author: GitLabUser {
                                id: 1,
                                username: Some("botuser".to_string()),
                                name: Some("Bot User".to_string()),
                            },
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 901,
                            body: "@botuser please implement change".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(900),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "create_discussion_note:group/repo:30:discussion-1")
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| {
                    call.as_str() == "create_discussion_note:group/repo:30:discussion-1"
                })
                .count(),
            1
        );
        assert!(calls.iter().any(|call| {
            call.as_str() == "add_discussion_note_award:group/repo:30:discussion-1:901:inspect"
        }));
        assert!(calls.iter().any(|call| {
            call.as_str() == "delete_discussion_note_award:group/repo:30:discussion-1:901:10901"
        }));
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(30i64)
        .bind("discussion-1")
        .bind(901i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("committed".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn mention_history_insert_failure_releases_mention_lock() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(41, "sha41")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 41),
                vec![AwardEmoji {
                    id: 411,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 41),
                vec![MergeRequestDiscussion {
                    id: "discussion-1".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 910,
                            body: "initial review comment".to_string(),
                            author: GitLabUser {
                                id: 1,
                                username: Some("botuser".to_string()),
                                name: Some("Bot User".to_string()),
                            },
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 911,
                            body: "@botuser please implement change".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(910),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        sqlx::query("DROP TABLE run_history")
            .execute(state.pool())
            .await?;
        let service = ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner.clone(),
            1,
            default_created_after(),
        );

        assert!(service.scan_once().await.is_err());
        assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
        assert!(state.list_in_progress_mention_commands().await?.is_empty());
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(41i64)
        .bind("discussion-1")
        .bind(911i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result.as_deref(), Some("error"));
        Ok(())
    }

    #[tokio::test]
    async fn mention_run_history_uses_refreshed_mr_sha() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let inner_gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(42, "sha-old")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 42),
                vec![AwardEmoji {
                    id: 421,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 42),
                vec![MergeRequestDiscussion {
                    id: "discussion-1".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 920,
                            body: "initial review comment".to_string(),
                            author: GitLabUser {
                                id: 1,
                                username: Some("botuser".to_string()),
                                name: Some("Bot User".to_string()),
                            },
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 921,
                            body: "@botuser please implement change".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(920),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let gitlab = Arc::new(RefreshedMentionGitLab {
            inner: Arc::clone(&inner_gitlab),
            refreshed_mr: mr(42, "sha-new"),
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner,
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        let row = sqlx::query(
            "SELECT head_sha FROM run_history WHERE repo = ? AND iid = ? ORDER BY started_at DESC, id DESC LIMIT 1",
        )
        .bind("group/repo")
        .bind(42i64)
        .fetch_one(state.pool())
        .await?;
        let head_sha: String = row.try_get("head_sha")?;
        assert_eq!(head_sha, "sha-new");
        Ok(())
    }

    #[tokio::test]
    async fn queued_mentions_snapshot_feature_flags_before_runner_start() -> Result<()> {
        let mut config = test_config();
        config.review.max_concurrent = 1;
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        config.codex.gitlab_discovery_mcp.enabled = true;
        config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["group/repo".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }];
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(52, "sha52"), mr(53, "sha53")]),
            awards: Mutex::new(HashMap::from([
                (
                    ("group/repo".to_string(), 52),
                    vec![AwardEmoji {
                        id: 521,
                        name: "thumbsup".to_string(),
                        user: bot_user.clone(),
                    }],
                ),
                (
                    ("group/repo".to_string(), 53),
                    vec![AwardEmoji {
                        id: 531,
                        name: "thumbsup".to_string(),
                        user: bot_user.clone(),
                    }],
                ),
            ])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([
                (
                    ("group/repo".to_string(), 52),
                    vec![MergeRequestDiscussion {
                        id: "discussion-52".to_string(),
                        notes: vec![
                            DiscussionNote {
                                id: 952,
                                body: "initial review comment".to_string(),
                                author: bot_user.clone(),
                                system: false,
                                in_reply_to_id: None,
                                created_at: None,
                            },
                            DiscussionNote {
                                id: 953,
                                body: "@botuser please implement change".to_string(),
                                author: requester.clone(),
                                system: false,
                                in_reply_to_id: Some(952),
                                created_at: None,
                            },
                        ],
                    }],
                ),
                (
                    ("group/repo".to_string(), 53),
                    vec![MergeRequestDiscussion {
                        id: "discussion-53".to_string(),
                        notes: vec![
                            DiscussionNote {
                                id: 962,
                                body: "initial review comment".to_string(),
                                author: bot_user.clone(),
                                system: false,
                                in_reply_to_id: None,
                                created_at: None,
                            },
                            DiscussionNote {
                                id: 963,
                                body: "@botuser please implement another change".to_string(),
                                author: requester.clone(),
                                system: false,
                                in_reply_to_id: Some(962),
                                created_at: None,
                            },
                        ],
                    }],
                ),
            ])),
            users: Mutex::new(HashMap::from([(
                7,
                GitLabUserDetail {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: Some("Alice".to_string()),
                    public_email: Some("alice@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let first_started = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let runner = Arc::new(BlockingMentionRunner {
            first_started: Arc::clone(&first_started),
            release_first: Arc::clone(&release_first),
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .set_runtime_feature_flag_overrides(
                &crate::feature_flags::RuntimeFeatureFlagOverrides {
                    gitlab_discovery_mcp: Some(true),
                    composer_install: None,
                    composer_safe_install: None,
                },
            )
            .await?;
        let service = Arc::new(ReviewService::new(
            config,
            gitlab,
            Arc::clone(&state),
            runner,
            1,
            default_created_after(),
        ));

        let first_started_wait = first_started.notified();
        let scan_task = {
            let service = Arc::clone(&service);
            tokio::spawn(async move { service.scan_once().await })
        };
        tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

        for _ in 0..50 {
            let count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
                    .fetch_one(state.pool())
                    .await?;
            if count == 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        state
            .set_runtime_feature_flag_overrides(
                &crate::feature_flags::RuntimeFeatureFlagOverrides {
                    gitlab_discovery_mcp: Some(false),
                    composer_install: None,
                    composer_safe_install: None,
                },
            )
            .await?;

        let mut snapshots = Vec::new();
        for _ in 0..50 {
            let rows = sqlx::query(
                "SELECT feature_flags_json FROM run_history WHERE kind = 'mention' ORDER BY trigger_note_id",
            )
            .fetch_all(state.pool())
            .await?;
            if rows.len() == 2 {
                snapshots = rows
                    .into_iter()
                    .map(|row| {
                        let json: String = row.try_get("feature_flags_json")?;
                        let snapshot = serde_json::from_str::<
                            crate::feature_flags::FeatureFlagSnapshot,
                        >(&json)?;
                        Ok(snapshot)
                    })
                    .collect::<Result<Vec<_>>>()?;
                if snapshots
                    .iter()
                    .all(|snapshot| snapshot.gitlab_discovery_mcp)
                {
                    break;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(snapshots.len(), 2);
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
        );

        release_first.notify_waiters();
        scan_task.await??;
        Ok(())
    }

    #[tokio::test]
    async fn scan_runs_mention_command_for_standalone_discussion_comment() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let standalone_author = GitLabUser {
            id: 42,
            username: Some("reviewer".to_string()),
            name: Some("Reviewer".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(33, "sha33")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 33),
                vec![AwardEmoji {
                    id: 331,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 33),
                vec![MergeRequestDiscussion {
                    id: "discussion-standalone".to_string(),
                    notes: vec![DiscussionNote {
                        id: 930,
                        body: "@botuser please handle this standalone comment".to_string(),
                        author: standalone_author,
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    }],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                42,
                GitLabUserDetail {
                    id: 42,
                    username: Some("reviewer".to_string()),
                    name: Some("Reviewer".to_string()),
                    public_email: Some("reviewer@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "create_discussion_note:group/repo:33:discussion-standalone")
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| {
                    call.as_str() == "create_discussion_note:group/repo:33:discussion-standalone"
                })
                .count(),
            1
        );
        assert!(calls.iter().any(|call| {
            call.as_str()
                == "add_discussion_note_award:group/repo:33:discussion-standalone:930:eyes"
        }));
        assert!(calls.iter().any(|call| {
            call.as_str()
                == "delete_discussion_note_award:group/repo:33:discussion-standalone:930:10930"
        }));
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(33i64)
        .bind("discussion-standalone")
        .bind(930i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("committed".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn scan_runs_mention_command_for_reply_from_non_mr_author() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let reviewer = GitLabUser {
            id: 44,
            username: Some("reviewer2".to_string()),
            name: Some("Reviewer Two".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(34, "sha34")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 34),
                vec![AwardEmoji {
                    id: 341,
                    name: "thumbsup".to_string(),
                    user: bot_user.clone(),
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 34),
                vec![MergeRequestDiscussion {
                    id: "discussion-reply".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 940,
                            body: "Initial review thread note".to_string(),
                            author: bot_user,
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 941,
                            body: "@botuser please implement this follow-up".to_string(),
                            author: reviewer,
                            system: false,
                            in_reply_to_id: Some(940),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::from([(
                44,
                GitLabUserDetail {
                    id: 44,
                    username: Some("reviewer2".to_string()),
                    name: Some("Reviewer Two".to_string()),
                    public_email: Some("reviewer2@example.com".to_string()),
                },
            )])),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            calls
                .iter()
                .any(|call| call == "create_discussion_note:group/repo:34:discussion-reply")
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| {
                    call.as_str() == "create_discussion_note:group/repo:34:discussion-reply"
                })
                .count(),
            1
        );
        assert!(calls.iter().any(|call| {
            call.as_str() == "add_discussion_note_award:group/repo:34:discussion-reply:941:eyes"
        }));
        assert!(calls.iter().any(|call| {
            call.as_str() == "delete_discussion_note_award:group/repo:34:discussion-reply:941:10941"
        }));
        let row = sqlx::query(
            "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(34i64)
        .bind("discussion-reply")
        .bind(941i64)
        .fetch_one(state.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done");
        assert_eq!(result, Some("committed".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn dry_run_skips_mention_commands_and_thread_status_writes() -> Result<()> {
        let mut config = test_config();
        config.review.dry_run = true;
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr(31, "sha31")]),
            awards: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 31),
                vec![AwardEmoji {
                    id: 311,
                    name: "thumbsup".to_string(),
                    user: bot_user,
                }],
            )])),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 31),
                vec![MergeRequestDiscussion {
                    id: "discussion-1".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 910,
                            body: "review note".to_string(),
                            author: GitLabUser {
                                id: 1,
                                username: Some("botuser".to_string()),
                                name: Some("Bot User".to_string()),
                            },
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 911,
                            body: "@botuser please implement".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(910),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            config,
            gitlab.clone(),
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.scan_once().await?;

        assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
        let calls = gitlab.calls.lock().unwrap().clone();
        assert!(
            !calls
                .iter()
                .any(|call| call == "create_discussion_note:group/repo:31:discussion-1")
        );
        let processed_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
        )
        .bind("group/repo")
        .bind(31i64)
        .bind("discussion-1")
        .bind(911i64)
        .fetch_one(state.pool())
        .await?;
        assert_eq!(processed_count, 0);
        Ok(())
    }

    #[tokio::test]
    async fn mention_runs_even_when_mr_created_before_cutoff() -> Result<()> {
        let mut config = test_config();
        config.review.mention_commands.enabled = true;
        config.review.mention_commands.bot_username = Some("botuser".to_string());
        let bot_user = GitLabUser {
            id: 1,
            username: Some("botuser".to_string()),
            name: Some("Bot User".to_string()),
        };
        let requester = GitLabUser {
            id: 7,
            username: Some("alice".to_string()),
            name: Some("Alice".to_string()),
        };
        let created_at = Utc
            .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let cutoff = Utc
            .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
            .single()
            .expect("valid datetime");
        let gitlab = Arc::new(FakeGitLab {
            bot_user: bot_user.clone(),
            mrs: Mutex::new(vec![mr_with_created_at(32, "sha32", created_at)]),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::from([(
                ("group/repo".to_string(), 32),
                vec![MergeRequestDiscussion {
                    id: "discussion-1".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 920,
                            body: "review note".to_string(),
                            author: GitLabUser {
                                id: 1,
                                username: Some("botuser".to_string()),
                                name: Some("Bot User".to_string()),
                            },
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 921,
                            body: "@botuser question".to_string(),
                            author: requester,
                            system: false,
                            in_reply_to_id: Some(920),
                            created_at: None,
                        },
                    ],
                }],
            )])),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::new()),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(MentionAndReviewCounterRunner {
            mention_calls: Mutex::new(0),
            review_calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(config, gitlab, state, runner.clone(), 1, cutoff);

        service.scan_once().await?;

        assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
        assert_eq!(*runner.review_calls.lock().unwrap(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn resolves_targets_with_exclusions() -> Result<()> {
        let mut config = test_config();
        config.gitlab.targets.repos =
            TargetSelector::List(vec!["group/keep".to_string(), "group/drop".to_string()]);
        config.gitlab.targets.groups = TargetSelector::List(vec!["group".to_string()]);
        config.gitlab.targets.exclude_repos = vec!["group/drop".to_string()];
        config.gitlab.targets.exclude_groups = vec!["group/exclude".to_string()];

        let bot_user = GitLabUser {
            id: 1,
            username: None,
            name: None,
        };
        let gitlab = Arc::new(FakeGitLab {
            bot_user,
            mrs: Mutex::new(Vec::new()),
            awards: Mutex::new(HashMap::new()),
            notes: Mutex::new(HashMap::new()),
            discussions: Mutex::new(HashMap::new()),
            users: Mutex::new(HashMap::new()),
            projects: Mutex::new(HashMap::new()),
            all_projects: Mutex::new(Vec::new()),
            group_projects: Mutex::new(HashMap::from([(
                "group".to_string(),
                vec![
                    "group/include".to_string(),
                    "group/exclude/project".to_string(),
                ],
            )])),
            calls: Mutex::new(Vec::new()),
            list_open_calls: Mutex::new(0),
            list_projects_calls: Mutex::new(0),
            list_group_projects_calls: Mutex::new(0),
            delete_award_fails: false,
        });
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(config, gitlab, state, runner, 1, default_created_after());

        let repos = service.resolve_repos(ScanMode::Full).await?;

        assert_eq!(
            repos,
            vec!["group/include".to_string(), "group/keep".to_string()]
        );
        Ok(())
    }
}

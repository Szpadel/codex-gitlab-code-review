use crate::codex_runner::{CodexResult, CodexRunner, ReviewContext};
use crate::config::Config;
use crate::gitlab::{AwardEmoji, GitLabApi, MergeRequest, Note};
use crate::state::ReviewStateStore;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use futures::future::join_all;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

const NO_OPEN_MRS_MARKER: &str = "__no_open_mrs__";

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct RetryKey {
    repo: String,
    iid: u64,
    head_sha: String,
}

impl RetryKey {
    fn new(repo: &str, iid: u64, head_sha: &str) -> Self {
        Self {
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
        }
    }
}

#[derive(Clone, Debug)]
struct RetryState {
    failures: u32,
    next_retry_at: DateTime<Utc>,
}

struct RetryBackoff {
    base_delay: Duration,
    entries: Mutex<HashMap<RetryKey, RetryState>>,
}

impl RetryBackoff {
    fn new(base_delay: Duration) -> Self {
        Self {
            base_delay,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn should_retry(&self, key: &RetryKey, now: DateTime<Utc>) -> bool {
        let entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some(state) => now >= state.next_retry_at,
            None => true,
        }
    }

    fn record_failure(&self, key: RetryKey, now: DateTime<Utc>) -> DateTime<Utc> {
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

    fn clear(&self, key: &RetryKey) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(key);
    }

    #[cfg(test)]
    fn state_for(&self, key: &RetryKey) -> Option<RetryState> {
        let entries = self.entries.lock().unwrap();
        entries.get(key).cloned()
    }
}

#[derive(Clone, Copy)]
enum ScanMode {
    Full,
    Incremental,
}

#[derive(Default)]
struct ScanCounters {
    total_mrs: usize,
    scheduled: usize,
    skipped_award: usize,
    skipped_marker: usize,
    skipped_locked: usize,
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
    bot_user_id: u64,
    created_after: DateTime<Utc>,
    semaphore: Arc<Semaphore>,
    retry_backoff: Arc<RetryBackoff>,
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
        let retry_backoff = Arc::new(RetryBackoff::new(Duration::hours(1)));
        Self {
            config,
            gitlab,
            state,
            codex,
            bot_user_id,
            created_after,
            semaphore,
            retry_backoff,
        }
    }

    pub async fn scan_once(&self) -> Result<()> {
        self.scan(ScanMode::Full).await
    }

    pub async fn scan_once_incremental(&self) -> Result<()> {
        self.scan(ScanMode::Incremental).await
    }

    async fn scan(&self, mode: ScanMode) -> Result<()> {
        match mode {
            ScanMode::Full => info!("starting scan"),
            ScanMode::Incremental => info!("starting incremental scan"),
        }
        self.state
            .clear_stale_in_progress(self.config.review.stale_in_progress_minutes)
            .await?;
        let repos = self.resolve_repos(mode).await?;
        if repos.is_empty() {
            info!("no gitlab repositories configured");
            return Ok(());
        }
        let mut tasks = Vec::new();
        let mut counters = ScanCounters::default();
        for repo in &repos {
            let activity_marker = self.load_latest_mr_activity_marker(repo).await;
            if matches!(mode, ScanMode::Incremental) {
                if let Some(marker) = activity_marker.as_ref() {
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
                    if let Some(previous) = previous {
                        if previous == *marker {
                            counters.skipped_inactive += 1;
                            debug!(repo = repo.as_str(), "skip: latest MR activity unchanged");
                            continue;
                        }
                    }
                }
            }
            let mrs = self.gitlab.list_open_mrs(repo).await?;
            self.scan_repo_mrs(repo, mrs, &mut counters, &mut tasks)
                .await?;
            if let Some(marker) = activity_marker {
                self.state
                    .set_project_last_mr_activity(repo, &marker)
                    .await?;
            }
        }
        let _ = join_all(tasks).await;
        match mode {
            ScanMode::Full => {
                info!(
                    total_mrs = counters.total_mrs,
                    scheduled = counters.scheduled,
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_locked = counters.skipped_locked,
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
                    skipped_award = counters.skipped_award,
                    skipped_marker = counters.skipped_marker,
                    skipped_locked = counters.skipped_locked,
                    skipped_backoff = counters.skipped_backoff,
                    missing_sha = counters.missing_sha,
                    skipped_inactive = counters.skipped_inactive,
                    skipped_created_before = counters.skipped_created_before,
                    "scan complete"
                );
            }
        }
        Ok(())
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
    ) -> Result<()> {
        counters.total_mrs += mrs.len();
        info!(repo = repo, count = mrs.len(), "loaded open MRs");
        for mr in mrs {
            let mut mr = mr;
            if mr.head_sha().is_none() || mr.created_at.is_none() {
                mr = self.gitlab.get_mr(repo, mr.iid).await?;
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
            let head_sha = match mr.head_sha() {
                Some(value) => value,
                None => {
                    counters.missing_sha += 1;
                    warn!(repo = repo, iid = mr.iid, "missing head sha, skipping");
                    continue;
                }
            };
            let retry_key = RetryKey::new(repo, mr.iid, &head_sha);
            if !self.retry_backoff.should_retry(&retry_key, Utc::now()) {
                counters.skipped_backoff += 1;
                debug!(repo = repo, iid = mr.iid, "skip: review backoff active");
                continue;
            }
            let awards = self.gitlab.list_awards(repo, mr.iid).await?;
            if has_bot_award(&awards, self.bot_user_id, &self.config.review.thumbs_emoji) {
                counters.skipped_award += 1;
                debug!(repo = repo, iid = mr.iid, "skip: thumbs up already present");
                continue;
            }
            let notes = self.gitlab.list_notes(repo, mr.iid).await?;
            if has_review_marker(
                &notes,
                self.bot_user_id,
                &self.config.review.comment_marker_prefix,
                &head_sha,
            ) {
                counters.skipped_marker += 1;
                debug!(
                    repo = repo,
                    iid = mr.iid,
                    "skip: review marker already present"
                );
                continue;
            }
            if !self.state.begin_review(repo, mr.iid, &head_sha).await? {
                counters.skipped_locked += 1;
                debug!(
                    repo = repo,
                    iid = mr.iid,
                    "skip: review already in progress"
                );
                continue;
            }
            let permit = self.semaphore.clone().acquire_owned().await?;
            let repo_name = repo.to_string();
            let gitlab = Arc::clone(&self.gitlab);
            let codex = Arc::clone(&self.codex);
            let state = Arc::clone(&self.state);
            let retry_backoff = Arc::clone(&self.retry_backoff);
            let config = self.config.clone();
            let bot_user_id = self.bot_user_id;
            let review_context = ReviewRunContext {
                config,
                gitlab,
                codex,
                state,
                retry_backoff,
                bot_user_id,
            };
            counters.scheduled += 1;
            tasks.push(tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) = review_context.run(&repo_name, mr, &head_sha).await {
                    warn!(repo = repo_name.as_str(), error = %err, "review failed");
                }
            }));
        }
        Ok(())
    }

    pub async fn review_mr(&self, repo: &str, iid: u64) -> Result<()> {
        let mr = self.gitlab.get_mr(repo, iid).await?;
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
        let head_sha = match mr.head_sha() {
            Some(value) => value,
            None => {
                warn!(repo = repo, iid = iid, "missing head sha, skipping");
                return Ok(());
            }
        };
        let retry_key = RetryKey::new(repo, mr.iid, &head_sha);
        if !self.retry_backoff.should_retry(&retry_key, Utc::now()) {
            debug!(repo = repo, iid = iid, "skip: review backoff active");
            return Ok(());
        }
        let awards = self.gitlab.list_awards(repo, mr.iid).await?;
        if has_bot_award(&awards, self.bot_user_id, &self.config.review.thumbs_emoji) {
            return Ok(());
        }
        let notes = self.gitlab.list_notes(repo, mr.iid).await?;
        if has_review_marker(
            &notes,
            self.bot_user_id,
            &self.config.review.comment_marker_prefix,
            &head_sha,
        ) {
            return Ok(());
        }
        if !self.state.begin_review(repo, mr.iid, &head_sha).await? {
            return Ok(());
        }
        let _permit = self.semaphore.clone().acquire_owned().await?;
        let review_context = ReviewRunContext {
            config: self.config.clone(),
            gitlab: Arc::clone(&self.gitlab),
            codex: Arc::clone(&self.codex),
            state: Arc::clone(&self.state),
            retry_backoff: Arc::clone(&self.retry_backoff),
            bot_user_id: self.bot_user_id,
        };
        review_context.run(repo, mr, &head_sha).await
    }
}

struct ReviewRunContext {
    config: Config,
    gitlab: Arc<dyn GitLabApi>,
    codex: Arc<dyn CodexRunner>,
    state: Arc<ReviewStateStore>,
    retry_backoff: Arc<RetryBackoff>,
    bot_user_id: u64,
}

impl ReviewRunContext {
    async fn run(&self, repo: &str, mr: MergeRequest, head_sha: &str) -> Result<()> {
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

        let result = self.codex.run_review(review_ctx).await;
        let retry_key = RetryKey::new(repo, mr.iid, head_sha);
        if self.config.review.dry_run {
            info!(repo = repo, iid = mr.iid, "dry run: skipping eyes removal");
        } else if let Err(err) = remove_eyes(
            self.gitlab.as_ref(),
            repo,
            mr.iid,
            self.bot_user_id,
            &self.config.review.eyes_emoji,
        )
        .await
        {
            warn!(
                repo = repo,
                iid = mr.iid,
                error = %err,
                "failed to remove eyes award"
            );
        }

        match result {
            Ok(CodexResult::Pass { summary }) => {
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
                let next_retry_at = self.retry_backoff.record_failure(retry_key, Utc::now());
                error!(
                    repo = repo,
                    iid = mr.iid,
                    error = ?err,
                    next_retry_at = %next_retry_at,
                    "review failed"
                );
                self.state
                    .finish_review(repo, mr.iid, head_sha, "error")
                    .await?;
            }
        }

        Ok(())
    }
}

fn has_bot_award(awards: &[AwardEmoji], bot_user_id: u64, name: &str) -> bool {
    if bot_user_id == 0 {
        return false;
    }
    awards
        .iter()
        .any(|award| award.user.id == bot_user_id && award.name == name)
}

fn has_review_marker(notes: &[Note], bot_user_id: u64, prefix: &str, sha: &str) -> bool {
    if bot_user_id == 0 {
        return false;
    }
    let marker = format!("{}{} -->", prefix, sha);
    notes
        .iter()
        .any(|note| note.author.id == bot_user_id && note.body.contains(&marker))
}

async fn remove_eyes(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codex_runner::CodexRunner;
    use crate::config::{
        CodexConfig, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets, ProxyConfig,
        ReviewConfig, ScheduleConfig, ServerConfig, TargetSelector,
    };
    use crate::gitlab::{AwardEmoji, GitLabUser, Note};
    use anyhow::anyhow;
    use async_trait::async_trait;
    use chrono::{TimeZone, Utc};
    use pretty_assertions::assert_eq;
    use sqlx::Row;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeGitLab {
        bot_user: GitLabUser,
        mrs: Mutex<Vec<MergeRequest>>,
        awards: Mutex<HashMap<(String, u64), Vec<AwardEmoji>>>,
        notes: Mutex<HashMap<(String, u64), Vec<Note>>>,
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
            Ok(crate::gitlab::GitLabProject {
                last_activity_at: map.get(project).cloned(),
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

    fn test_config() -> Config {
        Config {
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
            },
            codex: CodexConfig {
                image: "ghcr.io/openai/codex-universal:latest".to_string(),
                timeout_seconds: 300,
                auth_host_path: "/root/.codex".to_string(),
                auth_mount_path: "/root/.codex".to_string(),
                exec_sandbox: "danger-full-access".to_string(),
                deps: crate::config::DepsConfig { enabled: false },
            },
            docker: DockerConfig {
                host: "tcp://localhost:2375".to_string(),
            },
            database: DatabaseConfig {
                path: ":memory:".to_string(),
            },
            server: ServerConfig {
                bind_addr: "127.0.0.1:0".to_string(),
            },
            proxy: ProxyConfig {
                http_proxy: None,
                https_proxy: None,
                no_proxy: None,
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

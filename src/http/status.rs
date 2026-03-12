use super::transcript::{
    thread_snapshot_from_events, thread_snapshot_is_complete,
    thread_snapshot_only_target_turn_is_incomplete,
};
use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, PersistedScanStatus,
    ProjectCatalogSummary, ReviewStateStore, RunHistoryEventRecord, RunHistoryKind,
    RunHistoryListQuery, RunHistoryRecord, ScanMode, ScanOutcome, ScanState,
    TranscriptBackfillState, merge_rewritten_turn_events,
};
use crate::transcript_backfill::{
    SessionHistoryBackfillSource, TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
    TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR, TranscriptBackfillSource,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;

pub use super::transcript::{ThreadItemSnapshot, ThreadSnapshot};

const TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR: &str =
    "matching Codex session history was not found";
const TRANSCRIPT_BACKFILL_RETRY_COOLDOWN: Duration = Duration::from_secs(1);
const TRANSCRIPT_BACKFILL_MISSING_HISTORY_RETRY_WINDOW: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub generated_at: String,
    pub config: StatusConfigSnapshot,
    pub scan: StatusScanSnapshot,
    pub in_progress_reviews: Vec<InProgressReview>,
    pub in_progress_mentions: Vec<InProgressMentionCommand>,
    pub auth_limit_resets: Vec<AuthLimitResetEntry>,
    pub project_catalogs: Vec<ProjectCatalogSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusConfigSnapshot {
    pub gitlab_base_url: String,
    pub bind_addr: String,
    pub run_once: bool,
    pub dry_run: bool,
    pub mention_commands_enabled: bool,
    pub browser_mcp_enabled: bool,
    pub max_concurrent: usize,
    pub schedule_cron: String,
    pub schedule_timezone: String,
    pub created_after: Option<String>,
    pub repo_targets: usize,
    pub repo_targets_all: bool,
    pub group_targets: usize,
    pub group_targets_all: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusScanSnapshot {
    pub scan_state: String,
    pub mode: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub next_scan_at: Option<String>,
}

#[derive(Clone)]
pub struct StatusService {
    config: StatusConfig,
    state: Arc<ReviewStateStore>,
    default_transcript_backfill_source: Option<Arc<dyn TranscriptBackfillSource>>,
    account_transcript_backfill_sources: HashMap<String, Arc<dyn TranscriptBackfillSource>>,
    active_backfills: Arc<Mutex<HashSet<i64>>>,
    backfill_retry_after: Arc<Mutex<HashMap<i64, Instant>>>,
}

#[derive(Clone)]
struct StatusConfig {
    gitlab_base_url: String,
    bind_addr: String,
    status_ui_enabled: bool,
    run_once: bool,
    dry_run: bool,
    mention_commands_enabled: bool,
    browser_mcp_enabled: bool,
    max_concurrent: usize,
    schedule_cron: String,
    schedule_timezone: String,
    repo_targets: usize,
    repo_targets_all: bool,
    group_targets: usize,
    group_targets_all: bool,
}

impl StatusService {
    pub fn new(
        config: Config,
        state: Arc<ReviewStateStore>,
        run_once: bool,
        // Status-page reads stay on persisted events plus local session history.
        // Do not reintroduce synchronous Codex thread reads on the HTTP path.
        _runner: Option<Arc<dyn CodexRunner>>,
    ) -> Self {
        let default_transcript_backfill_source = Arc::new(SessionHistoryBackfillSource::new(
            primary_session_history_path(
                &config.codex.auth_host_path,
                &config.codex.auth_mount_path,
                config.codex.session_history_path.as_deref(),
            ),
        )) as Arc<dyn TranscriptBackfillSource>;
        let account_transcript_backfill_sources = build_account_transcript_backfill_sources(
            &config,
            Arc::clone(&default_transcript_backfill_source),
        );
        Self {
            config: StatusConfig {
                gitlab_base_url: config.gitlab.base_url,
                bind_addr: config.server.bind_addr,
                status_ui_enabled: config.server.status_ui_enabled,
                run_once,
                dry_run: config.review.dry_run,
                mention_commands_enabled: config.review.mention_commands.enabled,
                browser_mcp_enabled: config.codex.browser_mcp.enabled,
                max_concurrent: config.review.max_concurrent,
                schedule_cron: config.schedule.cron,
                schedule_timezone: config
                    .schedule
                    .timezone
                    .unwrap_or_else(|| "UTC".to_string()),
                repo_targets: config.gitlab.targets.repos.list().len(),
                repo_targets_all: config.gitlab.targets.repos.is_all(),
                group_targets: config.gitlab.targets.groups.list().len(),
                group_targets_all: config.gitlab.targets.groups.is_all(),
            },
            state,
            default_transcript_backfill_source: Some(default_transcript_backfill_source),
            account_transcript_backfill_sources,
            active_backfills: Arc::new(Mutex::new(HashSet::new())),
            backfill_retry_after: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn with_transcript_backfill_source(
        mut self,
        transcript_backfill_source: Arc<dyn TranscriptBackfillSource>,
    ) -> Self {
        self.account_transcript_backfill_sources.insert(
            "primary".to_string(),
            Arc::clone(&transcript_backfill_source),
        );
        self.default_transcript_backfill_source = Some(transcript_backfill_source);
        self
    }

    pub(crate) fn status_ui_enabled(&self) -> bool {
        self.config.status_ui_enabled
    }

    pub async fn snapshot(&self) -> Result<StatusSnapshot> {
        let created_after = self.state.get_created_after().await?;
        let scan = self.state.get_scan_status().await?;
        Ok(StatusSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            config: StatusConfigSnapshot {
                gitlab_base_url: self.config.gitlab_base_url.clone(),
                bind_addr: self.config.bind_addr.clone(),
                run_once: self.config.run_once,
                dry_run: self.config.dry_run,
                mention_commands_enabled: self.config.mention_commands_enabled,
                browser_mcp_enabled: self.config.browser_mcp_enabled,
                max_concurrent: self.config.max_concurrent,
                schedule_cron: self.config.schedule_cron.clone(),
                schedule_timezone: self.config.schedule_timezone.clone(),
                created_after,
                repo_targets: self.config.repo_targets,
                repo_targets_all: self.config.repo_targets_all,
                group_targets: self.config.group_targets,
                group_targets_all: self.config.group_targets_all,
            },
            scan: scan_into_snapshot(scan),
            in_progress_reviews: self.state.list_in_progress_reviews().await?,
            in_progress_mentions: self.state.list_in_progress_mention_commands().await?,
            auth_limit_resets: self.state.list_auth_limit_reset_entries().await?,
            project_catalogs: self.state.list_project_catalog_summaries().await?,
        })
    }

    pub async fn mark_scan_started(&self, mode: ScanMode) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.state = ScanState::Scanning;
        scan.mode = Some(mode);
        scan.started_at = Some(Utc::now().to_rfc3339());
        scan.finished_at = None;
        scan.outcome = None;
        scan.error = None;
        scan.next_scan_at = None;
        self.state.set_scan_status(&scan).await
    }

    pub async fn mark_scan_finished(
        &self,
        mode: ScanMode,
        outcome: ScanOutcome,
        error: Option<String>,
    ) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.state = ScanState::Idle;
        scan.mode = Some(mode);
        if scan.started_at.is_none() {
            scan.started_at = Some(Utc::now().to_rfc3339());
        }
        scan.finished_at = Some(Utc::now().to_rfc3339());
        scan.outcome = Some(outcome);
        scan.error = error;
        self.state.set_scan_status(&scan).await
    }

    pub async fn set_next_scan_at(&self, next_scan_at: Option<DateTime<Utc>>) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.next_scan_at = next_scan_at.map(|value| value.to_rfc3339());
        self.state.set_scan_status(&scan).await
    }

    pub async fn clear_next_scan_at(&self) -> Result<()> {
        self.state.clear_next_scan_at().await
    }

    pub async fn recover_startup_status(&self) -> Result<()> {
        self.reconcile_interrupted_run_history().await?;
        let mut scan = self.state.get_scan_status().await?;
        scan.next_scan_at = None;
        if scan.state == ScanState::Scanning {
            scan.state = ScanState::Idle;
            scan.outcome = Some(ScanOutcome::Failure);
            scan.finished_at = Some(Utc::now().to_rfc3339());
            scan.error = Some("scan interrupted by service restart".to_string());
        }
        self.state.set_scan_status(&scan).await
    }

    pub async fn reconcile_interrupted_run_history(&self) -> Result<()> {
        self.state
            .reconcile_interrupted_run_history("run interrupted by service restart")
            .await?;
        Ok(())
    }

    pub async fn history_snapshot(&self, query: HistoryQuery) -> Result<HistorySnapshot> {
        let runs = self
            .state
            .list_run_history(&RunHistoryListQuery {
                repo: query.repo.clone(),
                iid: query.iid,
                kind: query.kind,
                result: query.result.clone(),
                search: query.search.clone(),
                limit: query.limit,
            })
            .await?;
        Ok(HistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            filters: query,
            runs,
        })
    }

    pub async fn mr_history_snapshot(&self, repo: &str, iid: u64) -> Result<MrHistorySnapshot> {
        let runs = self.state.list_run_history_for_mr(repo, iid).await?;
        Ok(MrHistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            repo: repo.to_string(),
            iid,
            runs,
        })
    }

    pub async fn run_detail_snapshot(&self, run_id: i64) -> Result<Option<RunDetailSnapshot>> {
        let Some(run) = self.state.get_run_history(run_id).await? else {
            return Ok(None);
        };
        let related_runs = self
            .state
            .list_run_history_for_mr(&run.repo, run.iid)
            .await?;
        let events = self.state.list_run_history_events(run.id).await?;
        let thread = thread_snapshot_from_events(&run, &events);
        let transcript_backfill = self
            .resolve_transcript_backfill(&run, thread.as_ref())
            .await?;
        Ok(Some(RunDetailSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            run,
            related_runs,
            thread,
            transcript_backfill,
        }))
    }

    async fn resolve_transcript_backfill(
        &self,
        run: &RunHistoryRecord,
        thread: Option<&ThreadSnapshot>,
    ) -> Result<Option<TranscriptBackfillSnapshot>> {
        if run.status != "done" {
            return Ok(None);
        }
        if !transcript_needs_backfill(run, thread) {
            return Ok(None);
        }

        let mut state = run.transcript_backfill_state;
        let mut error = run.transcript_backfill_error.clone();
        let has_transcript_backfill_source = self.transcript_backfill_source_for_run(run).is_some();
        let should_retry_missing_history = state == TranscriptBackfillState::Failed
            && error
                .as_deref()
                .is_some_and(|error| should_retry_transcript_backfill_error(run, error));
        let cooldown_elapsed = self.backfill_retry_due(run.id).await;
        if (matches!(
            state,
            TranscriptBackfillState::NotRequested | TranscriptBackfillState::InProgress
        ) || (should_retry_missing_history && cooldown_elapsed))
            && has_transcript_backfill_source
            && (run.review_thread_id.is_some() || run.thread_id.is_some())
            && !self.active_backfills.lock().await.contains(&run.id)
        {
            self.schedule_transcript_backfill(run.clone()).await?;
            state = TranscriptBackfillState::InProgress;
            error = None;
        }

        Ok(Some(TranscriptBackfillSnapshot { state, error }))
    }

    async fn schedule_transcript_backfill(&self, run: RunHistoryRecord) -> Result<()> {
        let Some(source) = self.transcript_backfill_source_for_run(&run) else {
            return Ok(());
        };

        {
            let mut active = self.active_backfills.lock().await;
            if !active.insert(run.id) {
                return Ok(());
            }
        }
        self.backfill_retry_after.lock().await.remove(&run.id);

        if let Err(err) = self
            .state
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::InProgress,
                None,
            )
            .await
        {
            self.active_backfills.lock().await.remove(&run.id);
            return Err(err);
        }

        let state = Arc::clone(&self.state);
        let active_backfills = Arc::clone(&self.active_backfills);
        let backfill_retry_after = Arc::clone(&self.backfill_retry_after);
        tokio::spawn(async move {
            let outcome = run_transcript_backfill(state.as_ref(), source.as_ref(), &run).await;
            match outcome {
                Ok(()) => {
                    backfill_retry_after.lock().await.remove(&run.id);
                }
                Err(err) => {
                    warn!(
                        run_id = run.id,
                        repo = %run.repo,
                        iid = run.iid,
                        error = %err,
                        "transcript backfill failed"
                    );
                    let error_text = err.to_string();
                    if is_retryable_transcript_backfill_error(&error_text) {
                        backfill_retry_after
                            .lock()
                            .await
                            .insert(run.id, Instant::now() + TRANSCRIPT_BACKFILL_RETRY_COOLDOWN);
                    } else {
                        backfill_retry_after.lock().await.remove(&run.id);
                    }
                    if let Err(update_err) = state
                        .update_run_history_transcript_backfill(
                            run.id,
                            TranscriptBackfillState::Failed,
                            Some(error_text.as_str()),
                        )
                        .await
                    {
                        warn!(
                            run_id = run.id,
                            error = %update_err,
                            "failed to persist transcript backfill error"
                        );
                    }
                }
            }
            active_backfills.lock().await.remove(&run.id);
        });

        Ok(())
    }

    fn transcript_backfill_source_for_run(
        &self,
        run: &RunHistoryRecord,
    ) -> Option<Arc<dyn TranscriptBackfillSource>> {
        run.auth_account_name
            .as_deref()
            .and_then(|account_name| {
                self.account_transcript_backfill_sources
                    .get(account_name)
                    .cloned()
            })
            .or_else(|| self.default_transcript_backfill_source.as_ref().cloned())
    }

    async fn backfill_retry_due(&self, run_id: i64) -> bool {
        let mut retry_after = self.backfill_retry_after.lock().await;
        match retry_after.get(&run_id).copied() {
            Some(deadline) if Instant::now() < deadline => false,
            Some(_) => {
                retry_after.remove(&run_id);
                true
            }
            None => true,
        }
    }
}

async fn run_transcript_backfill(
    state: &ReviewStateStore,
    source: &dyn TranscriptBackfillSource,
    run: &RunHistoryRecord,
) -> Result<()> {
    let Some(thread_id) = run.thread_id.as_deref().or(run.review_thread_id.as_deref()) else {
        state
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::Failed,
                Some("run is missing Codex thread metadata"),
            )
            .await?;
        return Ok(());
    };

    let persisted_events = state.list_run_history_events(run.id).await?;
    let turn_scoped_events =
        load_validated_transcript_backfill_events(source, run, thread_id, run.turn_id.as_deref())
            .await?;
    let mut candidate_events = match (run.turn_id.as_deref(), turn_scoped_events) {
        (Some(turn_id), Some(events)) => {
            merge_rewritten_turn_events(persisted_events.clone(), turn_id, &events)?
        }
        (Some(_), None) => Vec::new(),
        (None, Some(events)) => events,
        (None, None) => anyhow::bail!(TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR),
    };
    let mut rebuilt_thread = (!candidate_events.is_empty())
        .then(|| thread_snapshot_from_events(run, &ephemeral_run_history_events(&candidate_events)))
        .flatten();
    let persisted_turn_ids = persisted_turn_ids(&persisted_events);
    if run.turn_id.as_deref().is_some()
        && (candidate_events.is_empty()
            || (!rebuilt_thread
                .as_ref()
                .is_some_and(thread_snapshot_is_complete)
                && !run.turn_id.as_deref().is_some_and(|turn_id| {
                    rebuilt_thread.as_ref().is_some_and(|thread| {
                        thread_snapshot_only_target_turn_is_incomplete(thread, turn_id)
                    })
                })))
    {
        if let Some(full_thread_events) = source.load_events(thread_id, None).await? {
            let filtered_full_thread_events =
                filter_events_to_turn_ids(&full_thread_events, &persisted_turn_ids);
            let filtered_thread = thread_snapshot_from_events(
                run,
                &ephemeral_run_history_events(&filtered_full_thread_events),
            );
            if !filtered_full_thread_events.is_empty()
                && persisted_turn_ids_are_covered(&persisted_turn_ids, &filtered_full_thread_events)
                && filtered_thread
                    .as_ref()
                    .is_some_and(thread_snapshot_is_complete)
            {
                rebuilt_thread = filtered_thread;
                candidate_events = filtered_full_thread_events;
            }
        }
    }
    if candidate_events.is_empty() {
        anyhow::bail!(TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR);
    }
    if !rebuilt_thread
        .as_ref()
        .is_some_and(thread_snapshot_is_complete)
    {
        state.mark_run_history_events_incomplete(run.id).await?;
        if run.turn_id.as_deref().is_some_and(|turn_id| {
            rebuilt_thread.as_ref().is_some_and(|thread| {
                thread_snapshot_only_target_turn_is_incomplete(thread, turn_id)
            })
        }) {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        state
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::Failed,
                Some("transcript remains incomplete after local session-history backfill"),
            )
            .await?;
        return Ok(());
    }
    state
        .replace_run_history_events(run.id, &candidate_events)
        .await?;
    state
        .mark_run_history_transcript_backfill_complete(run.id)
        .await?;
    Ok(())
}

async fn load_validated_transcript_backfill_events(
    source: &dyn TranscriptBackfillSource,
    run: &RunHistoryRecord,
    thread_id: &str,
    turn_id: Option<&str>,
) -> Result<Option<Vec<crate::state::NewRunHistoryEvent>>> {
    let Some(events) = source.load_events(thread_id, turn_id).await? else {
        return Ok(None);
    };
    let source_thread = thread_snapshot_from_events(run, &ephemeral_run_history_events(&events));
    if !source_thread
        .as_ref()
        .is_some_and(thread_snapshot_is_complete)
    {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    Ok(Some(events))
}

fn transcript_needs_backfill(run: &RunHistoryRecord, thread: Option<&ThreadSnapshot>) -> bool {
    !run.events_persisted_cleanly || !thread.is_some_and(thread_snapshot_is_complete)
}

fn should_retry_transcript_backfill_error(run: &RunHistoryRecord, error: &str) -> bool {
    if error == TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR
        || error == TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR
    {
        return missing_history_retry_window_open(run, Utc::now().timestamp());
    }
    is_retryable_transcript_backfill_error(error)
}

fn missing_history_retry_window_open(run: &RunHistoryRecord, now: i64) -> bool {
    let reference = run.finished_at.unwrap_or(run.updated_at);
    let retry_window = i64::try_from(TRANSCRIPT_BACKFILL_MISSING_HISTORY_RETRY_WINDOW.as_secs())
        .unwrap_or(i64::MAX);
    now.saturating_sub(reference) <= retry_window
}

fn persisted_turn_ids(persisted_events: &[RunHistoryEventRecord]) -> HashSet<String> {
    persisted_events
        .iter()
        .filter_map(|event| event.turn_id.clone())
        .collect()
}

fn filter_events_to_turn_ids(
    events: &[crate::state::NewRunHistoryEvent],
    turn_ids: &HashSet<String>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    events
        .iter()
        .filter(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| turn_ids.contains(turn_id))
        })
        .enumerate()
        .map(|(index, event)| crate::state::NewRunHistoryEvent {
            sequence: i64::try_from(index + 1).expect("filtered event sequence"),
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
        })
        .collect()
}

fn persisted_turn_ids_are_covered(
    persisted_turn_ids: &HashSet<String>,
    full_thread_events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    let full_thread_turn_ids = full_thread_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .collect::<HashSet<_>>();
    persisted_turn_ids
        .iter()
        .all(|turn_id| full_thread_turn_ids.contains(turn_id.as_str()))
}

fn build_account_transcript_backfill_sources(
    config: &Config,
    default_source: Arc<dyn TranscriptBackfillSource>,
) -> HashMap<String, Arc<dyn TranscriptBackfillSource>> {
    let configured_session_history_path = config.codex.session_history_path.as_deref();
    let primary_session_history_path = primary_session_history_path(
        &config.codex.auth_host_path,
        &config.codex.auth_mount_path,
        configured_session_history_path,
    );

    let mut sources = HashMap::new();
    sources.insert("primary".to_string(), default_source);
    for account in &config.codex.fallback_auth_accounts {
        let session_history_path = fallback_session_history_path(
            &config.codex.auth_host_path,
            &config.codex.auth_mount_path,
            &primary_session_history_path,
            &account.auth_host_path,
        );
        sources.insert(
            account.name.clone(),
            Arc::new(SessionHistoryBackfillSource::new(session_history_path))
                as Arc<dyn TranscriptBackfillSource>,
        );
    }
    sources
}

fn primary_session_history_path(
    auth_host_path: &str,
    _auth_mount_path: &str,
    configured_session_history_path: Option<&str>,
) -> String {
    configured_session_history_path.map_or_else(
        || format!("{}/sessions", auth_host_path.trim_end_matches('/')),
        ToString::to_string,
    )
}

fn fallback_session_history_path(
    primary_auth_host_path: &str,
    primary_auth_mount_path: &str,
    primary_session_history_path: &str,
    fallback_auth_host_path: &str,
) -> String {
    let fallback_auth_host_path = fallback_auth_host_path.trim_end_matches('/');
    primary_session_history_path
        .strip_prefix(primary_auth_host_path.trim_end_matches('/'))
        .or_else(|| {
            primary_session_history_path.strip_prefix(primary_auth_mount_path.trim_end_matches('/'))
        })
        .map(|suffix| format!("{fallback_auth_host_path}{suffix}"))
        .unwrap_or_else(|| format!("{fallback_auth_host_path}/sessions"))
}

fn is_retryable_transcript_backfill_error(error: &str) -> bool {
    error == TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR
        || error == TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
        || error == TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR
}

fn ephemeral_run_history_events(
    events: &[crate::state::NewRunHistoryEvent],
) -> Vec<RunHistoryEventRecord> {
    events
        .iter()
        .enumerate()
        .map(|(index, event)| RunHistoryEventRecord {
            id: i64::try_from(index + 1).expect("ephemeral run history event id"),
            run_history_id: 0,
            sequence: event.sequence,
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
            created_at: 0,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        fallback_session_history_path, missing_history_retry_window_open,
        primary_session_history_path,
    };
    use crate::state::{RunHistoryKind, RunHistoryRecord, TranscriptBackfillState};

    #[test]
    fn primary_session_history_defaults_to_auth_host_sessions_dir() {
        assert_eq!(
            primary_session_history_path("/srv/codex-auth", "/root/.codex", None),
            "/srv/codex-auth/sessions"
        );
        assert_eq!(
            primary_session_history_path("/srv/codex-auth/", "/root/.codex", None),
            "/srv/codex-auth/sessions"
        );
    }

    #[test]
    fn fallback_session_history_preserves_primary_suffix() {
        assert_eq!(
            fallback_session_history_path(
                "/srv/codex-auth",
                "/root/.codex",
                "/srv/codex-auth/sessions/archive",
                "/srv/fallback-account",
            ),
            "/srv/fallback-account/sessions/archive"
        );
    }

    #[test]
    fn fallback_session_history_defaults_to_fallback_auth_sessions_dir_for_custom_primary_path() {
        assert_eq!(
            fallback_session_history_path(
                "/srv/codex-auth",
                "/root/.codex",
                "/custom/transcripts/archive",
                "/srv/fallback-account",
            ),
            "/srv/fallback-account/sessions"
        );
    }

    #[test]
    fn primary_session_history_preserves_explicit_custom_root() {
        assert_eq!(
            primary_session_history_path(
                "/srv/codex-auth",
                "/root/.codex",
                Some("/var/lib/codex-history"),
            ),
            "/var/lib/codex-history"
        );
    }

    #[test]
    fn missing_history_and_unavailable_source_retry_only_for_recent_runs() {
        let recent_run = sample_run_history_record(1_000);
        let stale_run = sample_run_history_record(0);

        assert!(missing_history_retry_window_open(&recent_run, 1_100));
        assert!(!missing_history_retry_window_open(&stale_run, 1_000));
    }

    fn sample_run_history_record(updated_at: i64) -> RunHistoryRecord {
        RunHistoryRecord {
            id: 1,
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 1,
            head_sha: "sha".to_string(),
            status: "done".to_string(),
            result: Some("commented".to_string()),
            started_at: updated_at,
            finished_at: Some(updated_at),
            updated_at,
            thread_id: Some("thread-1".to_string()),
            turn_id: Some("turn-1".to_string()),
            review_thread_id: None,
            preview: Some("Preview".to_string()),
            summary: None,
            error: None,
            auth_account_name: None,
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
            commit_sha: None,
            events_persisted_cleanly: false,
            transcript_backfill_state: TranscriptBackfillState::Failed,
            transcript_backfill_error: Some(
                "matching Codex session history was not found".to_string(),
            ),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct HistoryQuery {
    pub repo: Option<String>,
    pub iid: Option<u64>,
    pub kind: Option<RunHistoryKind>,
    pub result: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistorySnapshot {
    pub generated_at: String,
    pub filters: HistoryQuery,
    pub runs: Vec<RunHistoryRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MrHistorySnapshot {
    pub generated_at: String,
    pub repo: String,
    pub iid: u64,
    pub runs: Vec<RunHistoryRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RunDetailSnapshot {
    pub generated_at: String,
    pub run: RunHistoryRecord,
    pub related_runs: Vec<RunHistoryRecord>,
    pub thread: Option<ThreadSnapshot>,
    pub transcript_backfill: Option<TranscriptBackfillSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TranscriptBackfillSnapshot {
    pub state: TranscriptBackfillState,
    pub error: Option<String>,
}

fn scan_into_snapshot(scan: PersistedScanStatus) -> StatusScanSnapshot {
    StatusScanSnapshot {
        scan_state: match scan.state {
            ScanState::Idle => "idle".to_string(),
            ScanState::Scanning => "scanning".to_string(),
        },
        mode: scan.mode.map(|value| match value {
            ScanMode::Full => "full".to_string(),
            ScanMode::Incremental => "incremental".to_string(),
        }),
        started_at: scan.started_at,
        finished_at: scan.finished_at,
        outcome: scan.outcome.map(|value| match value {
            ScanOutcome::Success => "success".to_string(),
            ScanOutcome::Failure => "failure".to_string(),
        }),
        error: scan.error,
        next_scan_at: scan.next_scan_at,
    }
}

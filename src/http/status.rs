use super::transcript::{
    is_auxiliary_transcript_turn_id, thread_snapshot_from_events, thread_snapshot_is_complete,
    thread_snapshot_only_target_turn_is_incomplete,
};
use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::feature_flags::{
    FeatureFlagAvailability, FeatureFlagDefaults, FeatureFlagSnapshot, RuntimeFeatureFlagOverrides,
};
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, PersistedScanStatus,
    ProjectCatalogSummary, ReviewStateStore, RunHistoryEventRecord, RunHistoryKind,
    RunHistoryListQuery, RunHistoryRecord, ScanMode, ScanOutcome, ScanState,
    TranscriptBackfillState, merge_rewritten_turn_events,
};
use crate::transcript_backfill::{
    REVIEW_MISSING_CHILD_TURN_IDS_KEY, SessionHistoryBackfillSource,
    TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR, TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR,
    TranscriptBackfillSource,
};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::warn;
use uuid::Uuid;

pub use super::transcript::{ThreadItemSnapshot, ThreadSnapshot};

const TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR: &str =
    "matching Codex session history was not found";
const TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR: &str =
    "local session history remained incomplete after retry window";
const TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR: &str =
    "matching Codex session history was not found before retry window expired";
const TRANSCRIPT_BACKFILL_STALE_SOURCE_UNAVAILABLE_ERROR: &str =
    "local Codex session history directory remained unavailable before retry window expired";
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
    pub gitlab_discovery_mcp_configured: bool,
    pub max_concurrent: usize,
    pub schedule_cron: String,
    pub schedule_timezone: String,
    pub created_after: Option<String>,
    pub repo_targets: usize,
    pub repo_targets_all: bool,
    pub group_targets: usize,
    pub group_targets_all: bool,
    pub feature_flags: Vec<StatusFeatureFlagSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusFeatureFlagSnapshot {
    pub name: String,
    pub available: bool,
    pub default_enabled: bool,
    pub runtime_override: Option<bool>,
    pub effective_enabled: bool,
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
    feature_flag_csrf_token: String,
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
    gitlab_discovery_mcp_configured: bool,
    max_concurrent: usize,
    schedule_cron: String,
    schedule_timezone: String,
    repo_targets: usize,
    repo_targets_all: bool,
    group_targets: usize,
    group_targets_all: bool,
    feature_flag_defaults: FeatureFlagDefaults,
    feature_flag_availability: FeatureFlagAvailability,
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
        let feature_flag_availability = config.feature_flag_availability();
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
                gitlab_discovery_mcp_configured: config.codex.gitlab_discovery_mcp.enabled,
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
                feature_flag_defaults: config.feature_flags.clone(),
                feature_flag_availability,
            },
            state,
            feature_flag_csrf_token: Uuid::new_v4().to_string(),
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

    pub(crate) fn feature_flag_csrf_token(&self) -> &str {
        &self.feature_flag_csrf_token
    }

    pub async fn snapshot(&self) -> Result<StatusSnapshot> {
        let created_after = self.state.get_created_after().await?;
        let scan = self.state.get_scan_status().await?;
        let overrides = self.state.get_runtime_feature_flag_overrides().await?;
        Ok(StatusSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            config: StatusConfigSnapshot {
                gitlab_base_url: self.config.gitlab_base_url.clone(),
                bind_addr: self.config.bind_addr.clone(),
                run_once: self.config.run_once,
                dry_run: self.config.dry_run,
                mention_commands_enabled: self.config.mention_commands_enabled,
                browser_mcp_enabled: self.config.browser_mcp_enabled,
                gitlab_discovery_mcp_configured: self.config.gitlab_discovery_mcp_configured,
                max_concurrent: self.config.max_concurrent,
                schedule_cron: self.config.schedule_cron.clone(),
                schedule_timezone: self.config.schedule_timezone.clone(),
                created_after,
                repo_targets: self.config.repo_targets,
                repo_targets_all: self.config.repo_targets_all,
                group_targets: self.config.group_targets,
                group_targets_all: self.config.group_targets_all,
                feature_flags: self.feature_flag_snapshots(&overrides),
            },
            scan: scan_into_snapshot(scan),
            in_progress_reviews: self.state.list_in_progress_reviews().await?,
            in_progress_mentions: self.state.list_in_progress_mention_commands().await?,
            auth_limit_resets: self.state.list_auth_limit_reset_entries().await?,
            project_catalogs: self.state.list_project_catalog_summaries().await?,
        })
    }

    pub async fn update_runtime_feature_flag(
        &self,
        flag_name: &str,
        enabled: Option<bool>,
    ) -> Result<StatusFeatureFlagSnapshot> {
        match flag_name {
            "gitlab_discovery_mcp" => {
                if !self.config.feature_flag_availability.gitlab_discovery_mcp && enabled.is_some()
                {
                    bail!("invalid feature flag request: {flag_name} is unavailable");
                }
            }
            "composer_install" => {}
            "composer_safe_install" => {}
            other => bail!("invalid feature flag: {other}"),
        }

        let mut overrides = self.state.get_runtime_feature_flag_overrides().await?;
        match flag_name {
            "gitlab_discovery_mcp" => overrides.gitlab_discovery_mcp = enabled,
            "composer_install" => overrides.composer_install = enabled,
            "composer_safe_install" => overrides.composer_safe_install = enabled,
            _ => unreachable!("validated feature flag name"),
        }
        self.state
            .set_runtime_feature_flag_overrides(&overrides)
            .await?;
        self.feature_flag_snapshots(&overrides)
            .into_iter()
            .find(|flag| flag.name == flag_name)
            .ok_or_else(|| anyhow::anyhow!("missing feature flag after update: {flag_name}"))
    }

    fn feature_flag_snapshots(
        &self,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> Vec<StatusFeatureFlagSnapshot> {
        let effective = FeatureFlagSnapshot::resolve(
            &self.config.feature_flag_defaults,
            &self.config.feature_flag_availability,
            overrides,
        );
        vec![
            StatusFeatureFlagSnapshot {
                name: "gitlab_discovery_mcp".to_string(),
                available: self.config.feature_flag_availability.gitlab_discovery_mcp,
                default_enabled: self.config.feature_flag_defaults.gitlab_discovery_mcp,
                runtime_override: overrides.gitlab_discovery_mcp,
                effective_enabled: effective.gitlab_discovery_mcp,
            },
            StatusFeatureFlagSnapshot {
                name: "composer_install".to_string(),
                available: self.config.feature_flag_availability.composer_install,
                default_enabled: self.config.feature_flag_defaults.composer_install,
                runtime_override: overrides.composer_install,
                effective_enabled: effective.composer_install,
            },
            StatusFeatureFlagSnapshot {
                name: "composer_safe_install".to_string(),
                available: self.config.feature_flag_availability.composer_safe_install,
                default_enabled: self.config.feature_flag_defaults.composer_safe_install,
                runtime_override: overrides.composer_safe_install,
                effective_enabled: effective.composer_safe_install,
            },
        ]
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
        let should_retry_terminal_fallback = state == TranscriptBackfillState::Failed
            && error
                .as_deref()
                .is_some_and(|error| is_final_retry_window_attempt_pending(run, error));
        let cooldown_elapsed = self.backfill_retry_due(run.id).await;
        let backfill_is_active = {
            let active_backfills = self.active_backfills.lock().await;
            active_backfills.contains(&run.id)
        };
        if (matches!(
            state,
            TranscriptBackfillState::NotRequested | TranscriptBackfillState::InProgress
        ) || ((should_retry_missing_history || should_retry_terminal_fallback)
            && cooldown_elapsed))
            && has_transcript_backfill_source
            && (run.review_thread_id.is_some() || run.thread_id.is_some())
            && !backfill_is_active
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
        let retry_window_open_at_attempt_start =
            missing_history_retry_window_open(&run, Utc::now().timestamp());
        tokio::spawn(async move {
            let outcome = run_transcript_backfill(
                state.as_ref(),
                source.as_ref(),
                &run,
                retry_window_open_at_attempt_start,
            )
            .await;
            match outcome {
                Ok(()) => {
                    backfill_retry_after.lock().await.remove(&run.id);
                }
                Err(err) => {
                    let raw_error_text = err.to_string();
                    let should_retry = should_retry_transcript_backfill_failure(
                        &run,
                        &raw_error_text,
                        retry_window_open_at_attempt_start,
                    );
                    let error_text =
                        terminal_transcript_backfill_error_text(&raw_error_text, should_retry);
                    warn!(
                        run_id = run.id,
                        repo = %run.repo,
                        iid = run.iid,
                        error = %error_text,
                        "transcript backfill failed"
                    );
                    if should_retry {
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
    retry_window_open_at_attempt_start: bool,
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

    let allow_missing_review_child_history = !retry_window_open_at_attempt_start;
    let turn_scoped_events = match load_validated_transcript_backfill_events(
        source,
        run,
        thread_id,
        run.turn_id.as_deref(),
        allow_missing_review_child_history,
    )
    .await
    {
        Ok(events) => events,
        Err(err)
            if run.turn_id.is_some()
                && err.to_string() == TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR =>
        {
            None
        }
        Err(err) => return Err(err),
    };
    let review_wrapper_turn_events = turn_scoped_events
        .as_ref()
        .filter(|events| turn_events_include_review_wrapper_items(events))
        .cloned();
    let original_persisted_events = state.list_run_history_events(run.id).await?;
    let target_turn_missing_in_persisted = run.turn_id.as_deref().is_some_and(|turn_id| {
        !original_persisted_events
            .iter()
            .any(|event| event.turn_id.as_deref() == Some(turn_id))
    });
    let had_any_original_persisted_events = !original_persisted_events.is_empty();
    let persisted_events = sanitize_persisted_events_for_backfill(
        original_persisted_events,
        run.turn_id.as_deref(),
        review_wrapper_turn_events.as_deref(),
    );
    let mut candidate_events = initial_backfill_candidate_events(
        &persisted_events,
        run.turn_id.as_deref(),
        turn_scoped_events,
    )?;
    let mut rebuilt_thread = (!candidate_events.is_empty())
        .then(|| thread_snapshot_from_events(run, &ephemeral_run_history_events(&candidate_events)))
        .flatten();
    let persisted_turn_id_set = persisted_turn_ids(&persisted_events);
    let needs_review_wrapper_missing_target_recovery = review_wrapper_turn_events.is_some()
        && target_turn_missing_in_persisted
        && run.turn_id.is_some()
        && had_any_original_persisted_events;
    let only_target_turn_is_incomplete = run.turn_id.as_deref().is_some_and(|turn_id| {
        rebuilt_thread
            .as_ref()
            .is_some_and(|thread| thread_snapshot_only_target_turn_is_incomplete(thread, turn_id))
    });
    let needs_full_thread_rebuild = run.turn_id.as_deref().is_some()
        && (candidate_events.is_empty()
            || target_turn_missing_in_persisted
            || needs_review_wrapper_missing_target_recovery
            || (!rebuilt_thread
                .as_ref()
                .is_some_and(thread_snapshot_is_complete)
                && !only_target_turn_is_incomplete));
    if needs_full_thread_rebuild
        && let Some(full_thread_events) = source.load_events(thread_id, None).await?
    {
        let persisted_events_for_full_thread = sanitize_persisted_events_for_backfill(
            persisted_events.clone(),
            run.turn_id.as_deref(),
            Some(&full_thread_events),
        );
        let persisted_turn_ids_in_full_thread =
            persisted_turn_ids(&persisted_events_for_full_thread);
        let filtered_turn_ids = if persisted_turn_ids_in_full_thread.is_empty() {
            run.turn_id
                .as_deref()
                .map(|turn_id| HashSet::from([turn_id.to_string()]))
                .unwrap_or_else(|| turn_ids_from_new_events(&full_thread_events))
        } else if needs_review_wrapper_missing_target_recovery
            || (target_turn_missing_in_persisted && run.turn_id.is_some())
        {
            persisted_turn_ids_with_target_turn_id(
                &persisted_turn_ids_in_full_thread,
                run.turn_id.as_deref().expect("turn id checked above"),
            )
        } else {
            persisted_turn_ids_in_full_thread.clone()
        };
        let filtered_full_thread_events =
            if persisted_turn_id_set.is_empty() && run.turn_id.is_none() {
                full_thread_events.clone()
            } else {
                filter_events_to_turn_ids(&full_thread_events, &filtered_turn_ids)
            };
        let filtered_full_thread_has_missing_review_child_history =
            events_have_missing_review_child_history(&filtered_full_thread_events);
        let filtered_full_thread_can_fall_back =
            !filtered_full_thread_has_missing_review_child_history
                || missing_review_child_history_has_renderable_fallback(
                    &filtered_full_thread_events,
                );
        let allow_target_only_recovery_despite_unrelated_missing_child_history =
            target_turn_missing_in_persisted
                && run.turn_id.is_some()
                && filtered_full_thread_has_missing_review_child_history
                && (!allow_missing_review_child_history || !filtered_full_thread_can_fall_back);
        if filtered_full_thread_has_missing_review_child_history
            && !allow_missing_review_child_history
            && !allow_target_only_recovery_despite_unrelated_missing_child_history
        {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        if filtered_full_thread_has_missing_review_child_history
            && allow_missing_review_child_history
            && !filtered_full_thread_can_fall_back
            && !allow_target_only_recovery_despite_unrelated_missing_child_history
        {
            anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
        }
        let filtered_full_thread_events =
            strip_missing_review_child_history_markers(filtered_full_thread_events);
        let filtered_full_thread_events = preserve_auxiliary_persisted_events(
            &persisted_events_for_full_thread,
            filtered_full_thread_events,
        );
        let filtered_thread = thread_snapshot_from_events(
            run,
            &ephemeral_run_history_events(&filtered_full_thread_events),
        );
        let should_accept_filtered_full_thread = !(filtered_full_thread_events.is_empty()
            || (allow_target_only_recovery_despite_unrelated_missing_child_history
                && filtered_full_thread_has_missing_review_child_history));
        if should_accept_filtered_full_thread
            && persisted_turn_ids_are_covered(&filtered_turn_ids, &filtered_full_thread_events)
            && filtered_thread
                .as_ref()
                .is_some_and(thread_snapshot_is_complete)
        {
            rebuilt_thread = filtered_thread;
            candidate_events = filtered_full_thread_events;
        } else if target_turn_missing_in_persisted && run.turn_id.is_some() {
            let target_only_turn_ids = HashSet::from([run
                .turn_id
                .as_deref()
                .expect("turn id checked above")
                .to_string()]);
            let target_only_full_thread_events =
                filter_events_to_turn_ids(&full_thread_events, &target_only_turn_ids);
            let target_only_has_missing_review_child_history =
                events_have_missing_review_child_history(&target_only_full_thread_events);
            if target_only_has_missing_review_child_history && !allow_missing_review_child_history {
                anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
            }
            if target_only_has_missing_review_child_history
                && allow_missing_review_child_history
                && !missing_review_child_history_has_renderable_fallback(
                    &target_only_full_thread_events,
                )
            {
                anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
            }
            let target_only_full_thread_events =
                strip_missing_review_child_history_markers(target_only_full_thread_events);
            let target_only_thread = thread_snapshot_from_events(
                run,
                &ephemeral_run_history_events(&target_only_full_thread_events),
            );
            if !target_only_full_thread_events.is_empty()
                && persisted_turn_ids_are_covered(
                    &target_only_turn_ids,
                    &target_only_full_thread_events,
                )
                && target_only_thread
                    .as_ref()
                    .is_some_and(thread_snapshot_is_complete)
            {
                candidate_events = merge_recovered_target_turn_events(
                    persisted_events.clone(),
                    run.turn_id.as_deref().expect("turn id checked above"),
                    &target_only_full_thread_events,
                )?;
                rebuilt_thread = thread_snapshot_from_events(
                    run,
                    &ephemeral_run_history_events(&candidate_events),
                );
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

fn initial_backfill_candidate_events(
    persisted_events: &[RunHistoryEventRecord],
    turn_id: Option<&str>,
    turn_scoped_events: Option<Vec<crate::state::NewRunHistoryEvent>>,
) -> Result<Vec<crate::state::NewRunHistoryEvent>> {
    match (turn_id, turn_scoped_events) {
        (Some(turn_id), Some(events)) => {
            merge_rewritten_turn_events(persisted_events.to_vec(), turn_id, &events)
        }
        (Some(_), None) => Ok(Vec::new()),
        (None, Some(events)) => Ok(preserve_auxiliary_persisted_events(
            persisted_events,
            events,
        )),
        (None, None) => anyhow::bail!(TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR),
    }
}

async fn load_validated_transcript_backfill_events(
    source: &dyn TranscriptBackfillSource,
    run: &RunHistoryRecord,
    thread_id: &str,
    turn_id: Option<&str>,
    allow_missing_review_child_history: bool,
) -> Result<Option<Vec<crate::state::NewRunHistoryEvent>>> {
    let Some(events) = load_backfill_events(
        source,
        thread_id,
        turn_id,
        allow_missing_review_child_history,
    )
    .await?
    else {
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

async fn load_backfill_events(
    source: &dyn TranscriptBackfillSource,
    thread_id: &str,
    turn_id: Option<&str>,
    allow_missing_review_child_history: bool,
) -> Result<Option<Vec<crate::state::NewRunHistoryEvent>>> {
    let Some(events) = source.load_events(thread_id, turn_id).await? else {
        return Ok(None);
    };
    let has_missing_review_child_history = events_have_missing_review_child_history(&events);
    if has_missing_review_child_history && !allow_missing_review_child_history {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    if has_missing_review_child_history
        && allow_missing_review_child_history
        && !missing_review_child_history_has_renderable_fallback(&events)
    {
        anyhow::bail!(TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR);
    }
    Ok(Some(strip_missing_review_child_history_markers(events)))
}

fn events_have_missing_review_child_history(events: &[crate::state::NewRunHistoryEvent]) -> bool {
    events.iter().any(|event| {
        event.event_type == "item_completed"
            && event
                .payload
                .get(REVIEW_MISSING_CHILD_TURN_IDS_KEY)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|turn_ids| !turn_ids.is_empty())
    })
}

fn strip_missing_review_child_history_markers(
    mut events: Vec<crate::state::NewRunHistoryEvent>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    for event in &mut events {
        let Some(object) = event.payload.as_object_mut() else {
            continue;
        };
        object.remove(REVIEW_MISSING_CHILD_TURN_IDS_KEY);
    }
    events
}

fn missing_review_child_history_has_renderable_fallback(
    events: &[crate::state::NewRunHistoryEvent],
) -> bool {
    let marked_wrapper_items = events
        .iter()
        .filter(|event| event.event_type == "item_completed")
        .filter(|event| {
            event
                .payload
                .get(REVIEW_MISSING_CHILD_TURN_IDS_KEY)
                .and_then(serde_json::Value::as_array)
                .is_some_and(|turn_ids| !turn_ids.is_empty())
        })
        .collect::<Vec<_>>();

    let turns_with_missing_review_children = marked_wrapper_items
        .iter()
        .map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();

    !turns_with_missing_review_children.is_empty()
        && turns_with_missing_review_children.iter().all(|turn_id| {
            marked_wrapper_items.iter().any(|event| {
                event.turn_id == *turn_id
                    && review_wrapper_item_is_renderable_fallback(&event.payload)
            })
        })
}

fn renderable_review_value_present(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => false,
        serde_json::Value::String(text) => !text.is_empty(),
        serde_json::Value::Array(items) => !items.is_empty(),
        serde_json::Value::Object(items) => !items.is_empty(),
        _ => true,
    }
}

fn review_wrapper_item_is_renderable_fallback(payload: &serde_json::Value) -> bool {
    let Some(item_type) = payload.get("type").and_then(serde_json::Value::as_str) else {
        return false;
    };
    match item_type {
        "agentMessage" | "AgentMessage" => {
            payload.get("phase").is_none_or(serde_json::Value::is_null)
                && (payload
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|text| !text.is_empty())
                    || payload
                        .get("content")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|content| !content.is_empty()))
        }
        "exitedReviewMode" => payload
            .get("review")
            .is_some_and(renderable_review_value_present),
        _ => false,
    }
}

fn transcript_needs_backfill(run: &RunHistoryRecord, thread: Option<&ThreadSnapshot>) -> bool {
    !run.events_persisted_cleanly || !thread.is_some_and(thread_snapshot_is_complete)
}

fn should_retry_transcript_backfill_error(run: &RunHistoryRecord, error: &str) -> bool {
    if is_retry_window_backfill_error(error) {
        return missing_history_retry_window_open(run, Utc::now().timestamp());
    }
    is_retryable_transcript_backfill_error(error)
}

fn should_retry_transcript_backfill_failure(
    run: &RunHistoryRecord,
    error: &str,
    retry_window_open_at_attempt_start: bool,
) -> bool {
    should_retry_transcript_backfill_error(run, error)
        || (retry_window_open_at_attempt_start && is_retry_window_backfill_error(error))
}

fn is_final_retry_window_attempt_pending(run: &RunHistoryRecord, error: &str) -> bool {
    is_retry_window_backfill_error(error)
        && !missing_history_retry_window_open(run, Utc::now().timestamp())
}

fn is_retry_window_backfill_error(error: &str) -> bool {
    matches!(
        error,
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR
            | TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
            | TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR
    )
}

fn terminal_transcript_backfill_error_text(error: &str, should_retry: bool) -> String {
    if should_retry {
        return error.to_string();
    }
    match error {
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR.to_string()
        }
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR.to_string()
        }
        TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_SOURCE_UNAVAILABLE_ERROR.to_string()
        }
        _ => error.to_string(),
    }
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
        .collect::<HashSet<_>>()
}

fn persisted_turn_ids_with_target_turn_id(
    persisted_turn_ids: &HashSet<String>,
    target_turn_id: &str,
) -> HashSet<String> {
    let mut turn_ids = persisted_turn_ids.clone();
    turn_ids.insert(target_turn_id.to_string());
    turn_ids
}

fn sanitize_persisted_events_for_backfill(
    persisted_events: Vec<RunHistoryEventRecord>,
    target_turn_id: Option<&str>,
    review_wrapper_turn_events: Option<&[crate::state::NewRunHistoryEvent]>,
) -> Vec<RunHistoryEventRecord> {
    let Some(target_turn_id) = target_turn_id else {
        return persisted_events;
    };
    let review_child_turn_ids = review_wrapper_turn_events
        .map(review_wrapper_child_turn_ids)
        .unwrap_or_default();
    let drop_review_child_turns = !review_child_turn_ids.is_empty();
    let has_target_events = persisted_events
        .iter()
        .any(|event| event.turn_id.as_deref() == Some(target_turn_id));
    if drop_review_child_turns && !has_target_events {
        return persisted_events
            .into_iter()
            .filter(|event| {
                !event
                    .turn_id
                    .as_deref()
                    .is_some_and(|turn_id| review_child_turn_ids.contains(turn_id))
            })
            .collect();
    }
    if !has_target_events {
        return persisted_events;
    }
    let stale_turn_ids = persisted_events
        .iter()
        .filter_map(|event| event.turn_id.as_deref())
        .filter(|turn_id| *turn_id != target_turn_id)
        .collect::<HashSet<_>>()
        .into_iter()
        .filter(|turn_id| {
            let turn_events = persisted_events
                .iter()
                .filter(|event| event.turn_id.as_deref() == Some(*turn_id))
                .collect::<Vec<_>>();
            let turn_has_no_items = turn_events
                .iter()
                .all(|event| event.event_type != "item_completed");
            let turn_is_completed = turn_events
                .iter()
                .any(|event| event.event_type == "turn_completed");
            !turn_events.is_empty()
                && ((turn_has_no_items && turn_is_completed)
                    || (drop_review_child_turns && review_child_turn_ids.contains(*turn_id)))
        })
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>();
    persisted_events
        .into_iter()
        .filter(|event| {
            !event
                .turn_id
                .as_deref()
                .is_some_and(|turn_id| stale_turn_ids.contains(turn_id))
        })
        .collect()
}

fn turn_events_include_review_wrapper_items(events: &[crate::state::NewRunHistoryEvent]) -> bool {
    events.iter().any(|event| {
        event.event_type == "item_completed"
            && matches!(
                event
                    .payload
                    .get("type")
                    .and_then(serde_json::Value::as_str),
                Some("enteredReviewMode" | "exitedReviewMode")
            )
    })
}

fn review_wrapper_child_turn_ids(
    review_wrapper_turn_events: &[crate::state::NewRunHistoryEvent],
) -> HashSet<String> {
    review_wrapper_turn_events
        .iter()
        .filter_map(|event| event.payload.get("reviewChildTurnIds"))
        .filter_map(serde_json::Value::as_array)
        .flat_map(|turn_ids| turn_ids.iter())
        .filter_map(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<HashSet<_>>()
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
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .collect::<HashSet<_>>();
    persisted_turn_ids
        .iter()
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .all(|turn_id| full_thread_turn_ids.contains(turn_id.as_str()))
}

fn turn_ids_from_new_events(events: &[crate::state::NewRunHistoryEvent]) -> HashSet<String> {
    events
        .iter()
        .filter_map(|event| event.turn_id.clone())
        .filter(|turn_id| !is_auxiliary_transcript_turn_id(turn_id))
        .collect::<HashSet<_>>()
}

fn preserve_auxiliary_persisted_events(
    persisted_events: &[RunHistoryEventRecord],
    mut rewritten_events: Vec<crate::state::NewRunHistoryEvent>,
) -> Vec<crate::state::NewRunHistoryEvent> {
    if rewritten_events.iter().any(|event| {
        event
            .turn_id
            .as_deref()
            .is_some_and(is_auxiliary_transcript_turn_id)
    }) {
        return rewritten_events;
    }

    let mut auxiliary_events = persisted_events
        .iter()
        .filter(|event| {
            event
                .turn_id
                .as_deref()
                .is_some_and(is_auxiliary_transcript_turn_id)
        })
        .map(|event| crate::state::NewRunHistoryEvent {
            sequence: event.sequence,
            turn_id: event.turn_id.clone(),
            event_type: event.event_type.clone(),
            payload: event.payload.clone(),
        })
        .collect::<Vec<_>>();
    if auxiliary_events.is_empty() {
        return rewritten_events;
    }

    auxiliary_events.sort_by_key(|event| event.sequence);
    for event in &mut rewritten_events {
        event.sequence += auxiliary_events.len() as i64;
    }
    auxiliary_events.extend(rewritten_events);
    for (index, event) in auxiliary_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).expect("auxiliary preserved event index");
    }
    auxiliary_events
}

fn merge_recovered_target_turn_events(
    existing_events: Vec<RunHistoryEventRecord>,
    turn_id: &str,
    rewritten_events: &[crate::state::NewRunHistoryEvent],
) -> Result<Vec<crate::state::NewRunHistoryEvent>> {
    let existing_events = sanitize_persisted_events_for_backfill(
        existing_events,
        Some(turn_id),
        Some(rewritten_events),
    );
    if existing_events
        .iter()
        .any(|event| event.turn_id.as_deref() == Some(turn_id))
    {
        return merge_rewritten_turn_events(existing_events, turn_id, rewritten_events);
    }

    let mut existing_events = existing_events;
    existing_events.sort_by_key(|event| (event.sequence, event.id));

    let insertion_sequence = recovered_turn_insertion_sequence(&existing_events, rewritten_events)
        .unwrap_or_else(|| {
            existing_events
                .last()
                .map(|event| event.sequence + 1)
                .unwrap_or(1)
        });
    let delta = rewritten_events.len() as i64;

    let mut merged_events = Vec::new();
    for event in existing_events {
        let shifted_sequence = if event.sequence >= insertion_sequence {
            event.sequence + delta
        } else {
            event.sequence
        };
        merged_events.push(crate::state::NewRunHistoryEvent {
            sequence: shifted_sequence,
            turn_id: event.turn_id,
            event_type: event.event_type,
            payload: event.payload,
        });
    }

    merged_events.extend(
        rewritten_events
            .iter()
            .map(|event| crate::state::NewRunHistoryEvent {
                sequence: insertion_sequence + event.sequence - 1,
                turn_id: event.turn_id.clone(),
                event_type: event.event_type.clone(),
                payload: event.payload.clone(),
            }),
    );

    merged_events.sort_by_key(|event| event.sequence);
    for (index, event) in merged_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).expect("merged recovered event index");
    }
    Ok(merged_events)
}

fn recovered_turn_insertion_sequence(
    existing_events: &[RunHistoryEventRecord],
    rewritten_events: &[crate::state::NewRunHistoryEvent],
) -> Option<i64> {
    let recovered_last_timestamp = rewritten_events
        .iter()
        .filter_map(|event| history_event_timestamp(&event.payload))
        .max()?;
    let later_turn_ids = existing_events
        .iter()
        .filter(|event| {
            run_history_event_timestamp(event)
                .is_some_and(|timestamp| timestamp > recovered_last_timestamp)
        })
        .filter_map(|event| event.turn_id.clone())
        .collect::<HashSet<_>>();
    if !later_turn_ids.is_empty() {
        return existing_events
            .iter()
            .find(|event| {
                event
                    .turn_id
                    .as_ref()
                    .is_some_and(|turn_id| later_turn_ids.contains(turn_id))
            })
            .map(|event| event.sequence);
    }
    existing_events
        .iter()
        .find(|event| {
            run_history_event_timestamp(event)
                .is_some_and(|timestamp| timestamp > recovered_last_timestamp)
        })
        .map(|event| event.sequence)
}

fn run_history_event_timestamp(event: &RunHistoryEventRecord) -> Option<i64> {
    history_event_timestamp(&event.payload).or((event.created_at > 0).then_some(event.created_at))
}

fn history_event_timestamp(payload: &serde_json::Value) -> Option<i64> {
    let timestamp = payload
        .get("createdAt")
        .or_else(|| payload.get("timestamp"))?;
    match timestamp {
        serde_json::Value::Number(number) => number.as_i64().map(normalize_history_timestamp),
        serde_json::Value::String(text) => chrono::DateTime::parse_from_rfc3339(text)
            .ok()
            .map(|value| value.timestamp()),
        _ => None,
    }
}

fn normalize_history_timestamp(timestamp: i64) -> i64 {
    if timestamp.unsigned_abs() >= 1_000_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
    }
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
        StatusService, TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
        TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR,
        TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR, events_have_missing_review_child_history,
        fallback_session_history_path, initial_backfill_candidate_events,
        is_final_retry_window_attempt_pending, merge_recovered_target_turn_events,
        missing_history_retry_window_open, missing_review_child_history_has_renderable_fallback,
        persisted_turn_ids_are_covered, preserve_auxiliary_persisted_events,
        primary_session_history_path, sanitize_persisted_events_for_backfill,
        should_retry_transcript_backfill_error, should_retry_transcript_backfill_failure,
        strip_missing_review_child_history_markers, terminal_transcript_backfill_error_text,
        turn_ids_from_new_events,
    };
    use crate::config::{
        BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
        GitLabDiscoveryMcpConfig, GitLabTargets, McpServerOverridesConfig,
        ReasoningEffortOverridesConfig, ReasoningSummaryOverridesConfig, ReviewConfig,
        ReviewMentionCommandsConfig, ScheduleConfig, ServerConfig, TargetSelector,
    };
    use crate::feature_flags::{FeatureFlagDefaults, FeatureFlagSnapshot};
    use crate::state::{
        ReviewStateStore, RunHistoryEventRecord, RunHistoryKind, RunHistoryRecord,
        TranscriptBackfillState,
    };
    use crate::transcript_backfill::TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR;
    use serde_json::json;
    use std::sync::Arc;

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
    fn turn_id_helpers_ignore_auxiliary_startup_warning_turns() {
        let persisted_turn_ids = std::collections::HashSet::from([
            "gitlab-discovery-mcp-startup".to_string(),
            "turn-1".to_string(),
        ]);
        let full_thread_events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
        ];

        assert!(persisted_turn_ids_are_covered(
            &persisted_turn_ids,
            &full_thread_events
        ));
        assert_eq!(
            turn_ids_from_new_events(&full_thread_events),
            std::collections::HashSet::from(["turn-1".to_string()])
        );
    }

    #[test]
    fn preserve_auxiliary_persisted_events_reinjects_startup_warning_turn() {
        let persisted_events = vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "GitLab discovery MCP startup warning"
                }),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
        ];
        let rewritten_events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ];

        let merged = preserve_auxiliary_persisted_events(&persisted_events, rewritten_events);

        assert_eq!(merged.len(), 5);
        assert_eq!(
            merged
                .iter()
                .filter_map(|event| event.turn_id.as_deref())
                .collect::<Vec<_>>(),
            vec![
                "gitlab-discovery-mcp-startup",
                "gitlab-discovery-mcp-startup",
                "gitlab-discovery-mcp-startup",
                "turn-1",
                "turn-1",
            ]
        );
        assert_eq!(merged[0].sequence, 1);
        assert_eq!(merged[4].sequence, 5);
    }

    #[test]
    fn initial_backfill_candidate_events_preserves_auxiliary_turns_for_turnless_rewrite() {
        let persisted_events = vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
        ];
        let turn_scoped_events = Some(vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-1".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ]);

        let merged = initial_backfill_candidate_events(&persisted_events, None, turn_scoped_events)
            .expect("turn-less rewrite should keep auxiliary startup warning");

        assert_eq!(
            merged
                .iter()
                .filter_map(|event| event.turn_id.as_deref())
                .collect::<Vec<_>>(),
            vec![
                "gitlab-discovery-mcp-startup",
                "gitlab-discovery-mcp-startup",
                "turn-1",
                "turn-1",
            ]
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

    #[tokio::test]
    async fn status_snapshot_includes_feature_flag_state() -> anyhow::Result<()> {
        let store = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = StatusService::new(test_config(), store, false, None);

        let snapshot = service.snapshot().await?;

        assert_eq!(snapshot.config.feature_flags.len(), 3);
        assert_eq!(
            snapshot
                .config
                .feature_flags
                .iter()
                .map(|flag| flag.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "gitlab_discovery_mcp",
                "composer_install",
                "composer_safe_install",
            ]
        );
        assert!(
            snapshot
                .config
                .feature_flags
                .iter()
                .all(|flag| !flag.effective_enabled)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_runtime_feature_flag_persists_override() -> anyhow::Result<()> {
        let store = Arc::new(ReviewStateStore::new(":memory:").await?);
        let mut config = test_config();
        config.codex.gitlab_discovery_mcp.enabled = true;
        config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["group/source".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/target".to_string()],
            target_groups: Vec::new(),
        }];
        let service = StatusService::new(config, Arc::clone(&store), false, None);

        let updated = service
            .update_runtime_feature_flag("gitlab_discovery_mcp", Some(true))
            .await?;

        assert_eq!(updated.runtime_override, Some(true));
        assert!(updated.effective_enabled);
        assert_eq!(
            store
                .get_runtime_feature_flag_overrides()
                .await?
                .gitlab_discovery_mcp,
            Some(true)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_runtime_feature_flag_rejects_unavailable_flags() -> anyhow::Result<()> {
        let store = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

        let result = service
            .update_runtime_feature_flag("gitlab_discovery_mcp", Some(true))
            .await;

        assert!(result.is_err());
        assert_eq!(
            store
                .get_runtime_feature_flag_overrides()
                .await?
                .gitlab_discovery_mcp,
            None
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_runtime_feature_flag_persists_composer_overrides() -> anyhow::Result<()> {
        let store = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

        let updated = service
            .update_runtime_feature_flag("composer_install", Some(true))
            .await?;
        assert_eq!(updated.runtime_override, Some(true));
        assert!(updated.effective_enabled);

        let safe_updated = service
            .update_runtime_feature_flag("composer_safe_install", Some(true))
            .await?;
        assert_eq!(safe_updated.runtime_override, Some(true));
        assert!(safe_updated.effective_enabled);

        let stored = store.get_runtime_feature_flag_overrides().await?;
        assert_eq!(stored.composer_install, Some(true));
        assert_eq!(stored.composer_safe_install, Some(true));
        Ok(())
    }

    #[tokio::test]
    async fn update_runtime_feature_flag_allows_clearing_unavailable_override() -> anyhow::Result<()>
    {
        let store = Arc::new(ReviewStateStore::new(":memory:").await?);
        store
            .set_runtime_feature_flag_overrides(
                &crate::feature_flags::RuntimeFeatureFlagOverrides {
                    gitlab_discovery_mcp: Some(true),
                    composer_install: None,
                    composer_safe_install: None,
                },
            )
            .await?;
        let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

        let updated = service
            .update_runtime_feature_flag("gitlab_discovery_mcp", None)
            .await?;

        assert_eq!(updated.runtime_override, None);
        assert!(!updated.effective_enabled);
        assert_eq!(
            store
                .get_runtime_feature_flag_overrides()
                .await?
                .gitlab_discovery_mcp,
            None
        );
        Ok(())
    }

    #[test]
    fn missing_history_and_unavailable_source_retry_only_for_recent_runs() {
        let recent_run = sample_run_history_record(1_000);
        let stale_run = sample_run_history_record(0);

        assert!(missing_history_retry_window_open(&recent_run, 1_100));
        assert!(!missing_history_retry_window_open(&stale_run, 1_000));
    }

    #[test]
    fn incomplete_session_history_errors_retry_only_for_recent_runs() {
        let recent_run = sample_run_history_record(chrono::Utc::now().timestamp());
        let stale_run = sample_run_history_record(0);

        assert!(should_retry_transcript_backfill_error(
            &recent_run,
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
        ));
        assert!(!should_retry_transcript_backfill_error(
            &stale_run,
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
        ));
    }

    #[test]
    fn stale_incomplete_session_history_errors_are_reworded_for_terminal_state() {
        let stale_run = sample_run_history_record(0);
        let should_retry = should_retry_transcript_backfill_error(
            &stale_run,
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
        );
        assert!(!should_retry);
        assert_eq!(
            terminal_transcript_backfill_error_text(
                TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
                should_retry,
            ),
            TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR
        );
    }

    #[test]
    fn stale_missing_history_errors_are_reworded_for_terminal_state() {
        let stale_run = sample_run_history_record(0);
        let should_retry = should_retry_transcript_backfill_error(
            &stale_run,
            TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
        );
        assert!(!should_retry);
        assert_eq!(
            terminal_transcript_backfill_error_text(
                TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
                should_retry,
            ),
            TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR
        );
        assert!(is_final_retry_window_attempt_pending(
            &stale_run,
            TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
        ));
        assert!(!is_final_retry_window_attempt_pending(
            &stale_run,
            TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR,
        ));
    }

    #[test]
    fn retry_window_errors_get_one_more_retry_when_attempt_started_before_deadline() {
        let stale_run = sample_run_history_record(0);

        assert!(should_retry_transcript_backfill_failure(
            &stale_run,
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
            true,
        ));
        assert!(!should_retry_transcript_backfill_failure(
            &stale_run,
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
            false,
        ));
    }

    #[test]
    fn review_child_history_retry_marker_requires_retry_until_fallback_is_allowed() {
        let events = vec![crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        }];

        assert!(events_have_missing_review_child_history(&events));
        assert_eq!(
            strip_missing_review_child_history_markers(events.clone())[0]
                .payload
                .get("reviewMissingChildTurnIds"),
            None
        );
    }

    #[test]
    fn missing_review_child_history_fallback_requires_renderable_wrapper_output() {
        let wrapper_only_events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-child"]
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ];
        assert!(!missing_review_child_history_has_renderable_fallback(
            &wrapper_only_events
        ));

        let wrapper_fallback_events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-child"]
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Wrapper-only review message.",
                    "reviewMissingChildTurnIds": ["turn-child"]
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ];
        assert!(missing_review_child_history_has_renderable_fallback(
            &wrapper_fallback_events
        ));

        let unmarked_message_events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-child"]
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Later same-turn message"
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ];
        assert!(!missing_review_child_history_has_renderable_fallback(
            &unmarked_message_events
        ));
    }

    #[test]
    fn missing_review_child_history_fallback_must_be_on_the_same_turn() {
        let events = vec![
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-missing".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewMissingChildTurnIds": ["turn-child"]
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-other".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "Unrelated rendered output"
                }),
            },
        ];

        assert!(!missing_review_child_history_has_renderable_fallback(
            &events
        ));
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_preserves_started_only_non_target_turns() {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "renderable"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            None,
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[2].turn_id.as_deref(), Some("turn-stale-child"));
        assert_eq!(events[2].event_type, "turn_started");
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_preserves_target_turn_without_items() {
        let events = sanitize_persisted_events_for_backfill(
            vec![RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            }],
            Some("turn-target"),
            None,
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(events[0].event_type, "turn_started");
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_drops_empty_completed_non_target_turns() {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "renderable"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            None,
        );

        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
        );
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_drops_earlier_empty_non_target_turns() {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "renderable"}),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            None,
        );

        assert_eq!(events.len(), 2);
        assert!(
            events
                .iter()
                .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
        );
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_drops_non_target_turns_for_review_wrapper_rewrites() {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "stale child"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-stale-child".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            Some(&[crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "createdAt": "2026-03-11T21:32:37.160Z",
                    "reviewChildTurnIds": ["turn-stale-child"]
                }),
            }]),
        );

        assert!(events.is_empty());
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_preserves_timestamped_later_turn_when_parent_missing()
    {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-later".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-later".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "later turn",
                        "createdAt": "2026-03-11T21:40:01.000Z"
                    }),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-later".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({
                        "status": "completed",
                        "createdAt": "2026-03-11T21:40:02.000Z"
                    }),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            Some(&[crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "createdAt": "2026-03-11T21:32:37.160Z"
                }),
            }]),
        );

        assert_eq!(events.len(), 3);
        assert!(
            events
                .iter()
                .all(|event| event.turn_id.as_deref() == Some("turn-later"))
        );
    }

    #[test]
    fn sanitize_persisted_events_for_backfill_preserves_interleaved_non_child_turns() {
        let events = sanitize_persisted_events_for_backfill(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "parent start"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 3,
                    run_history_id: 1,
                    sequence: 3,
                    turn_id: Some("turn-other".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 4,
                    run_history_id: 1,
                    sequence: 4,
                    turn_id: Some("turn-other".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "other turn"}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 5,
                    run_history_id: 1,
                    sequence: 5,
                    turn_id: Some("turn-parent".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                    created_at: 0,
                },
            ],
            Some("turn-parent"),
            Some(&[crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "enteredReviewMode",
                    "reviewChildTurnIds": ["turn-stale-child"]
                }),
            }]),
        );

        assert_eq!(events.len(), 5);
        assert!(
            events
                .iter()
                .any(|event| event.turn_id.as_deref() == Some("turn-other"))
        );
    }

    #[test]
    fn merge_recovered_target_turn_events_appends_after_timestamp_less_existing_turns() {
        let merged = merge_recovered_target_turn_events(
            vec![RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "later turn"}),
                created_at: 0,
            }],
            "turn-target",
            &[
                crate::state::NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({"type": "agentMessage", "text": "target turn"}),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({"status": "completed"}),
                },
            ],
        )
        .expect("merged recovered target turn events");

        assert_eq!(merged[0].turn_id.as_deref(), Some("turn-later"));
        assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[3].turn_id.as_deref(), Some("turn-target"));
    }

    #[test]
    fn merge_recovered_target_turn_events_inserts_before_later_turn_start_without_timestamp() {
        let merged = merge_recovered_target_turn_events(
            vec![
                RunHistoryEventRecord {
                    id: 1,
                    run_history_id: 1,
                    sequence: 1,
                    turn_id: Some("turn-later".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({}),
                    created_at: 0,
                },
                RunHistoryEventRecord {
                    id: 2,
                    run_history_id: 1,
                    sequence: 2,
                    turn_id: Some("turn-later".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "later turn",
                        "createdAt": "2026-03-11T21:40:01.000Z"
                    }),
                    created_at: 0,
                },
            ],
            "turn-target",
            &[
                crate::state::NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({"createdAt": "2026-03-11T21:32:37.000Z"}),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "target turn",
                        "createdAt": "2026-03-11T21:32:38.000Z"
                    }),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({
                        "status": "completed",
                        "createdAt": "2026-03-11T21:32:39.000Z"
                    }),
                },
            ],
        )
        .expect("merged recovered target turn events before later turn start");

        assert_eq!(merged[0].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[3].turn_id.as_deref(), Some("turn-later"));
        assert_eq!(merged[3].event_type, "turn_started");
        assert_eq!(merged[4].turn_id.as_deref(), Some("turn-later"));
    }

    #[test]
    fn merge_recovered_target_turn_events_appends_when_target_is_newest_turn() {
        let merged = merge_recovered_target_turn_events(
            vec![RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-old".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "older turn",
                    "createdAt": "2026-03-11T21:20:00.000Z"
                }),
                created_at: 0,
            }],
            "turn-target",
            &[
                crate::state::NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({"createdAt": "2026-03-11T21:32:37.000Z"}),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "target turn",
                        "createdAt": "2026-03-11T21:32:38.000Z"
                    }),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({
                        "status": "completed",
                        "createdAt": "2026-03-11T21:32:39.000Z"
                    }),
                },
            ],
        )
        .expect("merged recovered target turn events after older turns");

        assert_eq!(merged[0].turn_id.as_deref(), Some("turn-old"));
        assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[3].turn_id.as_deref(), Some("turn-target"));
    }

    #[test]
    fn merge_recovered_target_turn_events_uses_row_created_at_when_payload_timestamps_are_missing()
    {
        let merged = merge_recovered_target_turn_events(
            vec![RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "later turn"}),
                created_at: 1_741_800_000,
            }],
            "turn-target",
            &[
                crate::state::NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: json!({"createdAt": "2025-03-11T21:32:37.000Z"}),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: json!({
                        "type": "agentMessage",
                        "text": "target turn",
                        "createdAt": "2025-03-11T21:32:38.000Z"
                    }),
                },
                crate::state::NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-target".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: json!({
                        "status": "completed",
                        "createdAt": "2025-03-11T21:32:39.000Z"
                    }),
                },
            ],
        )
        .expect("merged recovered target turn events using row created_at");

        assert_eq!(merged[0].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
        assert_eq!(merged[3].turn_id.as_deref(), Some("turn-later"));
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
            feature_flags: FeatureFlagSnapshot::default(),
            events_persisted_cleanly: false,
            transcript_backfill_state: TranscriptBackfillState::Failed,
            transcript_backfill_error: Some(
                "matching Codex session history was not found".to_string(),
            ),
        }
    }

    fn test_config() -> Config {
        Config {
            feature_flags: FeatureFlagDefaults::default(),
            gitlab: GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: String::new(),
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
                cron: "0 */10 * * * *".to_string(),
                timezone: Some("UTC".to_string()),
            },
            review: ReviewConfig {
                max_concurrent: 2,
                eyes_emoji: "eyes".to_string(),
                thumbs_emoji: "thumbsup".to_string(),
                comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
                stale_in_progress_minutes: 120,
                dry_run: true,
                additional_developer_instructions: None,
                mention_commands: ReviewMentionCommandsConfig {
                    enabled: false,
                    bot_username: None,
                    eyes_emoji: None,
                    additional_developer_instructions: None,
                },
            },
            codex: CodexConfig {
                image: "ghcr.io/openai/codex-universal:latest".to_string(),
                timeout_seconds: 1800,
                auth_host_path: "/tmp/codex".to_string(),
                auth_mount_path: "/root/.codex".to_string(),
                session_history_path: None,
                exec_sandbox: "danger-full-access".to_string(),
                fallback_auth_accounts: vec![],
                usage_limit_fallback_cooldown_seconds: 3600,
                deps: Default::default(),
                browser_mcp: BrowserMcpConfig::default(),
                gitlab_discovery_mcp: GitLabDiscoveryMcpConfig::default(),
                mcp_server_overrides: McpServerOverridesConfig::default(),
                reasoning_effort: ReasoningEffortOverridesConfig::default(),
                reasoning_summary: ReasoningSummaryOverridesConfig::default(),
            },
            docker: DockerConfig::default(),
            database: DatabaseConfig {
                path: ":memory:".to_string(),
            },
            server: ServerConfig {
                bind_addr: "127.0.0.1:0".to_string(),
                status_ui_enabled: true,
            },
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

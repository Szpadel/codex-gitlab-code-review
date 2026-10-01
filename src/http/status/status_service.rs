use super::backfill::BackfillService;
use super::models::scan_into_snapshot;
use super::{
    AdminService, HistoryQuery, HistoryRunListItem, HistoryRunRecord, HistorySnapshot,
    MrHistorySnapshot, RateLimitService, RunDetailSnapshot, SecurityContextPreview,
    StatusConfigSnapshot, StatusSnapshot, TokenUsageStatisticSnapshot,
};
use crate::config::Config;
use crate::review::{RunRetryStatus, RunRetryStatusProvider};
use crate::state::{
    ReviewStateStore, RunHistoryCursor, RunHistoryKind, RunHistoryListQuery, RunHistoryRecord,
    RunTokenUsageRollup,
};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone)]
pub struct StatusService {
    config: StatusConfig,
    state: Arc<ReviewStateStore>,
    admin: Arc<AdminService>,
    ratelimit: Arc<RateLimitService>,
    backfill: Arc<BackfillService>,
    retry_status_provider: Option<Arc<dyn RunRetryStatusProvider>>,
}

#[derive(Clone)]
struct StatusConfig {
    gitlab_base_url: String,
    database_path: String,
    bind_addr: String,
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
}

impl StatusService {
    pub fn new(
        config: &Config,
        state: Arc<ReviewStateStore>,
        run_once: bool,
        admin: Arc<AdminService>,
        ratelimit: Arc<RateLimitService>,
        backfill: Arc<BackfillService>,
        retry_status_provider: Option<Arc<dyn RunRetryStatusProvider>>,
    ) -> Self {
        Self {
            config: StatusConfig {
                gitlab_base_url: config.gitlab.base_url.clone(),
                database_path: config.database.path.clone(),
                bind_addr: config.server.bind_addr.clone(),
                run_once,
                dry_run: config.review.dry_run,
                mention_commands_enabled: config.review.mention_commands.enabled,
                browser_mcp_enabled: config.codex.browser_mcp.enabled,
                gitlab_discovery_mcp_configured: config.codex.gitlab_discovery_mcp.enabled,
                max_concurrent: config.review.max_concurrent,
                schedule_cron: config.schedule.cron.clone(),
                schedule_timezone: config
                    .schedule
                    .timezone
                    .clone()
                    .unwrap_or_else(|| "UTC".to_string()),
                repo_targets: config.gitlab.targets.repos.list().len(),
                repo_targets_all: config.gitlab.targets.repos.is_all(),
                group_targets: config.gitlab.targets.groups.list().len(),
                group_targets_all: config.gitlab.targets.groups.is_all(),
            },
            state,
            admin,
            ratelimit,
            backfill,
            retry_status_provider,
        }
    }

    #[must_use]
    pub fn gitlab_base_url(&self) -> &str {
        &self.config.gitlab_base_url
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn snapshot(&self) -> Result<StatusSnapshot> {
        let created_after = self.state.service_state.get_created_after().await?;
        let scan = self.state.service_state.get_scan_status().await?;
        let feature_flags = self.admin.feature_flag_snapshots().await?;
        let rate_limits = self.ratelimit.snapshot().await?;
        Ok(StatusSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            config: StatusConfigSnapshot {
                runtime_mode: self.admin.runtime_mode().to_string(),
                gitlab_base_url: self.config.gitlab_base_url.clone(),
                database_path: self.config.database_path.clone(),
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
                feature_flags,
            },
            scan: scan_into_snapshot(scan),
            in_progress_reviews: self.state.review_state.list_in_progress_reviews().await?,
            in_progress_mentions: self
                .state
                .mention_commands
                .list_in_progress_mention_commands()
                .await?,
            auth_limit_resets: self
                .state
                .service_state
                .list_auth_limit_reset_entries()
                .await?,
            project_catalogs: self
                .state
                .project_catalog
                .list_project_catalog_summaries()
                .await?,
            rate_limits,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn history_snapshot(&self, query: HistoryQuery) -> Result<HistorySnapshot> {
        let list_query = RunHistoryListQuery {
            repo: query.repo.clone(),
            iid: query.iid,
            kind: query.kind,
            result: query.result.clone(),
            search: query.search.clone(),
            limit: query.limit,
            after: query
                .after
                .as_deref()
                .map(|cursor| {
                    RunHistoryCursor::decode(cursor).context("invalid history after cursor")
                })
                .transpose()?,
            before: query
                .before
                .as_deref()
                .map(|cursor| {
                    RunHistoryCursor::decode(cursor).context("invalid history before cursor")
                })
                .transpose()?,
        };
        let limit = list_query.normalized_limit();
        let page = self.state.run_history.list_run_history(&list_query).await?;
        let statistics = self
            .state
            .run_history
            .token_usage_statistics(&list_query)
            .await?;
        let mut filters = query;
        filters.limit = limit;
        let runs = self.with_list_retry_statuses(page.runs).await?;
        Ok(HistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            filters,
            limit,
            has_previous: page.has_previous,
            has_next: page.has_next,
            previous_cursor: page.previous_cursor.map(RunHistoryCursor::encode),
            next_cursor: page.next_cursor.map(RunHistoryCursor::encode),
            token_statistics: token_usage_statistic_snapshots(statistics),
            runs,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn mr_history_snapshot(&self, repo: &str, iid: u64) -> Result<MrHistorySnapshot> {
        let runs = self
            .state
            .run_history
            .list_run_history_for_mr(repo, iid)
            .await?;
        let runs = self.with_record_retry_statuses(runs).await?;
        Ok(MrHistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            repo: repo.to_string(),
            iid,
            runs,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn run_detail_snapshot(&self, run_id: i64) -> Result<Option<RunDetailSnapshot>> {
        let Some(run) = self.state.run_history.get_run_history(run_id).await? else {
            return Ok(None);
        };
        let related_runs = self
            .state
            .run_history
            .related_runs(&run.repo, run.iid)
            .await?;
        let security_context_preview = self.resolve_security_context_preview(&run).await?;
        let events = self
            .state
            .run_history
            .list_run_history_events(run.id)
            .await?;
        let thread = crate::http::transcript::thread_snapshot_from_events(&run, &events);
        let transcript_backfill = self
            .backfill
            .resolve_transcript_backfill(&run, thread.as_ref())
            .await?;
        let run = self.with_record_retry_statuses(vec![run]).await?.remove(0);
        Ok(Some(RunDetailSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            run,
            related_runs,
            security_context_preview,
            thread,
            transcript_backfill,
        }))
    }

    async fn with_list_retry_statuses(
        &self,
        runs: Vec<crate::state::RunHistoryListItem>,
    ) -> Result<Vec<HistoryRunListItem>> {
        let run_ids = runs.iter().map(|run| run.id).collect::<Vec<_>>();
        let mut statuses = self.retry_statuses_for_run_ids(&run_ids);
        let mut usage = self
            .state
            .run_history
            .token_usage_for_runs(&run_ids)
            .await?;
        Ok(runs
            .into_iter()
            .map(|run| {
                let retry = statuses.remove(&run.id);
                let token_usage = usage.remove(&run.id);
                HistoryRunListItem::new(run, retry, token_usage)
            })
            .collect())
    }

    async fn with_record_retry_statuses(
        &self,
        runs: Vec<RunHistoryRecord>,
    ) -> Result<Vec<HistoryRunRecord>> {
        let run_ids = runs.iter().map(|run| run.id).collect::<Vec<_>>();
        let mut statuses = self.retry_statuses_for_run_ids(&run_ids);
        let mut usage = self
            .state
            .run_history
            .token_usage_for_runs(&run_ids)
            .await?;
        Ok(runs
            .into_iter()
            .map(|run| {
                let retry = statuses.remove(&run.id);
                let token_usage = usage.remove(&run.id);
                HistoryRunRecord::new(run, retry, token_usage)
            })
            .collect())
    }

    fn retry_statuses_for_run_ids(&self, run_ids: &[i64]) -> HashMap<i64, RunRetryStatus> {
        self.retry_status_provider
            .as_ref()
            .map(|provider| provider.retry_statuses_for_run_ids(run_ids))
            .unwrap_or_default()
    }

    async fn resolve_security_context_preview(
        &self,
        run: &RunHistoryRecord,
    ) -> Result<Option<SecurityContextPreview>> {
        if run.kind != RunHistoryKind::Security {
            return Ok(None);
        }
        let (Some(base_branch), Some(base_head_sha), Some(prompt_version)) = (
            run.security_context_base_branch.as_deref(),
            run.security_context_base_head_sha.as_deref(),
            run.security_context_prompt_version.as_deref(),
        ) else {
            return Ok(None);
        };
        if let Some(payload_json) = run.security_context_payload_json.as_ref() {
            return Ok(Some(SecurityContextPreview {
                base_branch: base_branch.to_string(),
                base_head_sha: base_head_sha.to_string(),
                prompt_version: prompt_version.to_string(),
                payload_json: payload_json.clone(),
                source_run_history_id: run.security_context_source_run_id,
                generated_at: run.security_context_generated_at.unwrap_or(run.started_at),
                expires_at: run
                    .security_context_expires_at
                    .unwrap_or(run.finished_at.unwrap_or(run.updated_at)),
            }));
        }
        let cache_entry = self
            .state
            .security_context_cache
            .find_security_review_context_cache(
                &run.repo,
                base_branch,
                base_head_sha,
                prompt_version,
            )
            .await?;
        let Some(entry) = cache_entry else {
            return Ok(None);
        };
        Ok(Some(SecurityContextPreview {
            base_branch: entry.base_branch,
            base_head_sha: entry.base_head_sha,
            prompt_version: entry.prompt_version,
            payload_json: entry.payload_json,
            source_run_history_id: (entry.source_run_history_id > 0)
                .then_some(entry.source_run_history_id),
            generated_at: entry.generated_at,
            expires_at: entry.expires_at,
        }))
    }
}

fn token_usage_statistic_snapshots(
    statistics: Vec<crate::state::RunTokenUsageStatistic>,
) -> Vec<TokenUsageStatisticSnapshot> {
    let mut by_kind = statistics
        .into_iter()
        .map(|statistic| (statistic.kind, statistic))
        .collect::<HashMap<_, _>>();
    let mut snapshots = Vec::new();
    let mut all = TokenUsageStatisticSnapshot {
        kind: None,
        recorded_runs: 0,
        usage: RunTokenUsageRollup::default(),
    };
    for kind in [
        RunHistoryKind::Review,
        RunHistoryKind::Security,
        RunHistoryKind::Mention,
    ] {
        let statistic = by_kind.remove(&kind);
        let snapshot = TokenUsageStatisticSnapshot {
            kind: Some(kind),
            recorded_runs: statistic.as_ref().map_or(0, |value| value.recorded_runs),
            usage: statistic.map_or_else(RunTokenUsageRollup::default, |value| value.usage),
        };
        all.recorded_runs += snapshot.recorded_runs;
        all.usage.response_count += snapshot.usage.response_count;
        all.usage.input_tokens += snapshot.usage.input_tokens;
        all.usage.cached_input_tokens += snapshot.usage.cached_input_tokens;
        all.usage.cache_write_input_tokens += snapshot.usage.cache_write_input_tokens;
        all.usage.output_tokens += snapshot.usage.output_tokens;
        all.usage.reasoning_output_tokens += snapshot.usage.reasoning_output_tokens;
        all.usage.total_tokens += snapshot.usage.total_tokens;
        snapshots.push(snapshot);
    }
    snapshots.push(all);
    snapshots
}

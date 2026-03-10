use crate::config::Config;
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, PersistedScanStatus,
    ProjectCatalogSummary, ReviewStateStore, ScanMode, ScanOutcome, ScanState,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::sync::Arc;

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
    pub fn new(config: Config, state: Arc<ReviewStateStore>, run_once: bool) -> Self {
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
        }
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

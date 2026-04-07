use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, PersistedScanStatus,
    ProjectCatalogSummary, ReviewRateLimitBucketSnapshot, ReviewRateLimitPendingEntry,
    ReviewRateLimitRule, RunHistoryKind, RunHistoryListItem, RunHistoryRecord, ScanMode,
    ScanOutcome, ScanState, TranscriptBackfillState,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StatusSnapshot {
    pub generated_at: String,
    pub config: StatusConfigSnapshot,
    pub scan: StatusScanSnapshot,
    pub in_progress_reviews: Vec<InProgressReview>,
    pub in_progress_mentions: Vec<InProgressMentionCommand>,
    pub auth_limit_resets: Vec<AuthLimitResetEntry>,
    pub project_catalogs: Vec<ProjectCatalogSummary>,
    pub rate_limits: StatusRateLimitSnapshot,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct StatusRateLimitSnapshot {
    pub rules: Vec<ReviewRateLimitRule>,
    pub active_buckets: Vec<ReviewRateLimitBucketSnapshot>,
    pub pending: Vec<ReviewRateLimitPendingEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusConfigSnapshot {
    pub runtime_mode: String,
    pub gitlab_base_url: String,
    pub database_path: String,
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

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct HistoryQuery {
    pub repo: Option<String>,
    pub iid: Option<u64>,
    pub kind: Option<RunHistoryKind>,
    pub result: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
    pub after: Option<String>,
    pub before: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistorySnapshot {
    pub generated_at: String,
    pub filters: HistoryQuery,
    pub limit: usize,
    pub has_previous: bool,
    pub has_next: bool,
    pub previous_cursor: Option<String>,
    pub next_cursor: Option<String>,
    pub runs: Vec<RunHistoryListItem>,
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
    pub security_context_preview: Option<SecurityContextPreview>,
    pub thread: Option<super::ThreadSnapshot>,
    pub transcript_backfill: Option<TranscriptBackfillSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecurityContextPreview {
    pub base_branch: String,
    pub base_head_sha: String,
    pub prompt_version: String,
    pub payload_json: String,
    pub source_run_history_id: Option<i64>,
    pub generated_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TranscriptBackfillSnapshot {
    pub state: TranscriptBackfillState,
    pub error: Option<String>,
}

pub(super) fn scan_into_snapshot(scan: PersistedScanStatus) -> StatusScanSnapshot {
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

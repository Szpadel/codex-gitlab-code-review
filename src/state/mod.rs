use crate::feature_flags::FeatureFlagSnapshot;
use crate::review_lane::ReviewLane;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::str::FromStr;

mod feature_flags_repository;
mod mention_commands_repository;
mod project_catalog_repository;
mod review_rate_limit_repository;
mod review_state_repository;
mod run_history_repository;
mod security_context_cache_repository;
mod security_review_debounce_repository;
mod service_state_repository;

pub use feature_flags_repository::FeatureFlagsRepository;
pub use mention_commands_repository::MentionCommandsRepository;
pub use project_catalog_repository::ProjectCatalogRepository;
pub use review_rate_limit_repository::ReviewRateLimitRepository;
pub use review_state_repository::ReviewStateRepository;
pub use run_history_repository::RunHistoryRepository;
pub(crate) use run_history_repository::merge_rewritten_turn_events;
pub use security_context_cache_repository::SecurityContextCacheRepository;
pub use security_review_debounce_repository::SecurityReviewDebounceRepository;
pub use service_state_repository::ServiceStateRepository;

pub(crate) const AUTH_LIMIT_RESET_KEY_PREFIX: &str = "codex_auth_limit_reset_at::";
pub(crate) const FEATURE_FLAG_OVERRIDES_KEY: &str = "feature_flag_overrides";
pub(crate) const SCAN_STATUS_KEY: &str = "scan_status";
pub(crate) const PROJECT_RATE_LIMIT_SUBJECT_IID: i64 = 0;

pub(crate) fn sqlite_i64_from_u64(value: u64, label: &'static str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("convert {label} to i64"))
}

pub(crate) fn sqlite_i64_from_usize(value: usize, label: &'static str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("convert {label} to i64"))
}

pub(crate) fn auth_limit_reset_key(account_name: &str) -> String {
    format!("{AUTH_LIMIT_RESET_KEY_PREFIX}{account_name}")
}

pub(crate) fn parse_review_lane(value: &str) -> Result<ReviewLane> {
    match value {
        "general" => Ok(ReviewLane::General),
        "security" => Ok(ReviewLane::Security),
        other => bail!("unknown review lane: {other}"),
    }
}

pub struct ReviewStateStore {
    pool: SqlitePool,
    pub review_state: ReviewStateRepository,
    pub run_history: RunHistoryRepository,
    pub project_catalog: ProjectCatalogRepository,
    pub feature_flags: FeatureFlagsRepository,
    pub mention_commands: MentionCommandsRepository,
    pub service_state: ServiceStateRepository,
    pub security_context_cache: SecurityContextCacheRepository,
    pub security_review_debounce: SecurityReviewDebounceRepository,
    pub review_rate_limit: ReviewRateLimitRepository,
}

pub struct ProjectCatalog {
    pub fetched_at: i64,
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunHistoryKind {
    Review,
    Security,
    Mention,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TranscriptBackfillState {
    NotRequested,
    InProgress,
    Complete,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewRunHistory {
    pub kind: RunHistoryKind,
    pub repo: String,
    pub iid: u64,
    pub head_sha: String,
    pub discussion_id: Option<String>,
    pub trigger_note_id: Option<u64>,
    pub trigger_note_author_name: Option<String>,
    pub trigger_note_body: Option<String>,
    pub command_repo: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunHistoryFinish {
    pub result: String,
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub review_thread_id: Option<String>,
    pub preview: Option<String>,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub auth_account_name: Option<String>,
    pub commit_sha: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunHistorySessionUpdate {
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub review_thread_id: Option<String>,
    pub auth_account_name: Option<String>,
    pub security_context_source_run_id: Option<i64>,
    pub security_context_base_branch: Option<String>,
    pub security_context_base_head_sha: Option<String>,
    pub security_context_prompt_version: Option<String>,
    pub security_context_payload_json: Option<String>,
    pub security_context_generated_at: Option<i64>,
    pub security_context_expires_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunHistoryRecord {
    pub id: i64,
    pub kind: RunHistoryKind,
    pub repo: String,
    pub iid: u64,
    pub head_sha: String,
    pub status: String,
    pub result: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub updated_at: i64,
    pub thread_id: Option<String>,
    pub turn_id: Option<String>,
    pub review_thread_id: Option<String>,
    pub security_context_source_run_id: Option<i64>,
    pub security_context_base_branch: Option<String>,
    pub security_context_base_head_sha: Option<String>,
    pub security_context_prompt_version: Option<String>,
    pub security_context_payload_json: Option<String>,
    pub security_context_generated_at: Option<i64>,
    pub security_context_expires_at: Option<i64>,
    pub preview: Option<String>,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub auth_account_name: Option<String>,
    pub discussion_id: Option<String>,
    pub trigger_note_id: Option<u64>,
    pub trigger_note_author_name: Option<String>,
    pub trigger_note_body: Option<String>,
    pub command_repo: Option<String>,
    pub commit_sha: Option<String>,
    pub feature_flags: FeatureFlagSnapshot,
    pub events_persisted_cleanly: bool,
    pub transcript_backfill_state: TranscriptBackfillState,
    pub transcript_backfill_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunHistoryListItem {
    pub id: i64,
    pub kind: RunHistoryKind,
    pub repo: String,
    pub iid: u64,
    pub status: String,
    pub result: Option<String>,
    pub started_at: i64,
    pub preview: Option<String>,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunHistoryCursor {
    pub started_at: i64,
    pub id: i64,
}

impl RunHistoryCursor {
    #[must_use]
    pub fn encode(self) -> String {
        let raw = format!("{}:{}", self.started_at, self.id);
        encode_hex(raw.as_bytes())
    }

    /// # Errors
    ///
    /// Returns an error if the cursor is not valid hex, UTF-8, or does not
    /// contain the expected `started_at:id` payload.
    pub fn decode(raw: &str) -> Result<Self> {
        let bytes = decode_hex(raw).context("decode run history cursor hex")?;
        let decoded = String::from_utf8(bytes).context("decode run history cursor utf-8")?;
        let (started_at, id) = decoded
            .split_once(':')
            .context("split run history cursor parts")?;
        Ok(Self {
            started_at: started_at
                .parse()
                .context("parse run history cursor started_at")?,
            id: id.parse().context("parse run history cursor id")?,
        })
    }
}

impl From<&RunHistoryListItem> for RunHistoryCursor {
    fn from(value: &RunHistoryListItem) -> Self {
        Self {
            started_at: value.started_at,
            id: value.id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunHistoryListQuery {
    pub repo: Option<String>,
    pub iid: Option<u64>,
    pub kind: Option<RunHistoryKind>,
    pub result: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
    pub after: Option<RunHistoryCursor>,
    pub before: Option<RunHistoryCursor>,
}

impl RunHistoryListQuery {
    #[must_use]
    pub fn normalized_limit(&self) -> usize {
        if self.limit == 0 {
            100
        } else {
            self.limit.min(500)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunHistoryListPage {
    pub runs: Vec<RunHistoryListItem>,
    pub has_previous: bool,
    pub has_next: bool,
    pub previous_cursor: Option<RunHistoryCursor>,
    pub next_cursor: Option<RunHistoryCursor>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct NewRunHistoryEvent {
    pub sequence: i64,
    pub turn_id: Option<String>,
    pub event_type: String,
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RunHistoryEventRecord {
    pub id: i64,
    pub run_history_id: i64,
    pub sequence: i64,
    pub turn_id: Option<String>,
    pub event_type: String,
    pub payload: Value,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InProgressReview {
    pub lane: ReviewLane,
    pub repo: String,
    pub iid: u64,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReviewContextCacheEntry {
    pub repo: String,
    pub base_branch: String,
    pub base_head_sha: String,
    pub prompt_version: String,
    pub payload_json: String,
    pub source_run_history_id: i64,
    pub generated_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitScope {
    Project,
    MergeRequest,
}

impl ReviewRateLimitScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::MergeRequest => "merge_request",
        }
    }

    pub(crate) fn subject_iid(self, iid: Option<u64>) -> i64 {
        match self {
            Self::Project => PROJECT_RATE_LIMIT_SUBJECT_IID,
            Self::MergeRequest => iid
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or(PROJECT_RATE_LIMIT_SUBJECT_IID),
        }
    }

    pub(crate) fn display_iid(self, subject_iid: i64) -> Option<u64> {
        match self {
            Self::Project => None,
            Self::MergeRequest if subject_iid <= 0 => None,
            Self::MergeRequest => u64::try_from(subject_iid).ok(),
        }
    }
}

impl FromStr for ReviewRateLimitScope {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "project" => Ok(Self::Project),
            "merge_request" => Ok(Self::MergeRequest),
            other => bail!("invalid review rate limit scope: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitTargetKind {
    Repo,
    Group,
}

impl ReviewRateLimitTargetKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Group => "group",
        }
    }
}

impl FromStr for ReviewRateLimitTargetKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "repo" => Ok(Self::Repo),
            "group" => Ok(Self::Group),
            other => bail!("invalid review rate limit target kind: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRateLimitTarget {
    pub kind: ReviewRateLimitTargetKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitBucketMode {
    Shared,
    Independent,
}

impl ReviewRateLimitBucketMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Independent => "independent",
        }
    }
}

impl FromStr for ReviewRateLimitBucketMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "shared" => Ok(Self::Shared),
            "independent" => Ok(Self::Independent),
            other => bail!("invalid review rate limit bucket mode: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewRateLimitRule {
    pub id: String,
    pub label: String,
    pub scope_repo: String,
    pub targets: Vec<ReviewRateLimitTarget>,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub scope_iid: Option<u64>,
    pub scope_subject: String,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub scope: ReviewRateLimitScope,
    pub capacity: u32,
    pub window_seconds: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRateLimitRuleUpsert {
    pub id: Option<String>,
    pub label: String,
    pub targets: Vec<ReviewRateLimitTarget>,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub scope_iid: Option<u64>,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub scope: ReviewRateLimitScope,
    pub capacity: u32,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReviewDebounceEntry {
    pub repo: String,
    pub iid: u64,
    pub last_started_at: i64,
    pub next_eligible_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewRateLimitBucketSnapshot {
    pub bucket_id: String,
    pub rule_id: String,
    pub rule_label: String,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub target_kind: ReviewRateLimitTargetKind,
    pub target_path: String,
    pub scope_repo: String,
    pub scope_iid: Option<u64>,
    pub scope_subject: String,
    pub scope: ReviewRateLimitScope,
    pub repo: String,
    pub iid: Option<u64>,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub available_slots: f64,
    pub capacity: u32,
    pub window_seconds: u64,
    pub updated_at: i64,
    pub next_slot_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewRateLimitPendingEntry {
    pub lane: ReviewLane,
    pub repo: String,
    pub iid: u64,
    pub first_blocked_at: i64,
    pub last_blocked_at: i64,
    pub last_seen_head_sha: String,
    pub next_retry_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewRateLimitAcquireOutcome {
    Unmatched,
    Acquired { bucket_ids: Vec<String> },
    Blocked { next_retry_at: i64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MentionCommandStateKey {
    pub repo: String,
    pub iid: u64,
    pub discussion_id: String,
    pub trigger_note_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct InProgressMentionCommand {
    pub key: MentionCommandStateKey,
    pub head_sha: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MentionCommandScanState {
    Ready,
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanState {
    Idle,
    Scanning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    Full,
    Incremental,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanOutcome {
    Success,
    Failure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedScanStatus {
    pub state: ScanState,
    pub mode: Option<ScanMode>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: Option<ScanOutcome>,
    pub error: Option<String>,
    pub next_scan_at: Option<String>,
}

impl Default for PersistedScanStatus {
    fn default() -> Self {
        Self {
            state: ScanState::Idle,
            mode: None,
            started_at: None,
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthLimitResetEntry {
    pub account_name: String,
    pub reset_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectCatalogSummary {
    pub cache_key: String,
    pub fetched_at: i64,
    pub project_count: usize,
}

impl ReviewStateStore {
    /// # Errors
    ///
    /// Returns an error if the `SQLite` database cannot be created, opened,
    /// migrated, or connected.
    pub async fn new(path: &str) -> Result<Self> {
        if path != ":memory:" {
            let path_obj = Path::new(path);
            if path_obj.is_dir() {
                bail!("database path is a directory: {}", path_obj.display());
            }
            if let Some(parent) = path_obj.parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create database directory {}", parent.display()))?;
            }
            if !path_obj.exists() {
                OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(path_obj)
                    .with_context(|| format!("create database file {}", path_obj.display()))?;
            }
        }
        let url = sqlite_url(path);
        let max_connections = if path == ":memory:" { 1 } else { 5 };
        let connect_options = sqlite_connect_options(path, &url)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(connect_options)
            .await
            .with_context(|| format!("connect sqlite database at {path}"))?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("run sqlite migrations")?;

        Ok(Self {
            review_state: ReviewStateRepository::new(pool.clone()),
            run_history: RunHistoryRepository::new(pool.clone()),
            project_catalog: ProjectCatalogRepository::new(pool.clone()),
            feature_flags: FeatureFlagsRepository::new(pool.clone()),
            mention_commands: MentionCommandsRepository::new(pool.clone()),
            service_state: ServiceStateRepository::new(pool.clone()),
            security_context_cache: SecurityContextCacheRepository::new(pool.clone()),
            security_review_debounce: SecurityReviewDebounceRepository::new(pool.clone()),
            review_rate_limit: ReviewRateLimitRepository::new(pool.clone()),
            pool,
        })
    }

    #[must_use]
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

fn sqlite_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else if path.starts_with('/') {
        format!("sqlite:///{}", path.trim_start_matches('/'))
    } else {
        format!("sqlite://{path}")
    }
}

fn sqlite_connect_options(path: &str, url: &str) -> Result<SqliteConnectOptions> {
    let mut options =
        SqliteConnectOptions::from_str(url).with_context(|| format!("parse sqlite url {url}"))?;
    if path != ":memory:" {
        options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }
    Ok(options)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut encoded, "{byte:02x}");
    }
    encoded
}

fn decode_hex(input: &str) -> Result<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        bail!("hex input must have an even length");
    }
    let mut bytes = Vec::with_capacity(input.len() / 2);
    for chunk in input.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(chunk[0]).context("decode high hex nibble")?;
        let low = decode_hex_nibble(chunk[1]).context("decode low hex nibble")?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("invalid hex nibble"),
    }
}

#[cfg(test)]
mod tests;

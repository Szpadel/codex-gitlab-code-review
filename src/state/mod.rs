use crate::config::FeatureFlagSnapshot;
use crate::review::ReviewLane;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Write as _;

mod feature_flags_repository;
mod mention_commands_repository;
mod mention_quota_pending_repository;
mod project_catalog_repository;
mod review_rate_limits;
mod review_state_repository;
mod run_history_repository;
mod security_context_cache_repository;
mod security_review_debounce_repository;
mod service_state_repository;
mod sqlite;

pub use feature_flags_repository::FeatureFlagsRepository;
pub use mention_commands_repository::MentionCommandsRepository;
pub use mention_quota_pending_repository::{
    MentionQuotaPendingEntry, MentionQuotaPendingRepository, MentionQuotaPendingUpsert,
};
pub use project_catalog_repository::ProjectCatalogRepository;
pub use review_rate_limits::{
    ReviewRateLimitAcquireOutcome, ReviewRateLimitBucketMode, ReviewRateLimitBucketSnapshot,
    ReviewRateLimitPendingEntry, ReviewRateLimitRepository, ReviewRateLimitRule,
    ReviewRateLimitRuleUpsert, ReviewRateLimitScope, ReviewRateLimitTarget,
    ReviewRateLimitTargetKind,
};
pub use review_state_repository::ReviewStateRepository;
pub use run_history_repository::RunHistoryRepository;
pub(crate) use run_history_repository::merge_rewritten_turn_events;
pub use security_context_cache_repository::SecurityContextCacheRepository;
pub use security_review_debounce_repository::SecurityReviewDebounceRepository;
pub use service_state_repository::ServiceStateRepository;
use sqlite::{SqliteCoordinator, ensure_sqlite_file};

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
    sqlite: SqliteCoordinator,
    pub review_state: ReviewStateRepository,
    pub run_history: RunHistoryRepository,
    pub project_catalog: ProjectCatalogRepository,
    pub feature_flags: FeatureFlagsRepository,
    pub mention_commands: MentionCommandsRepository,
    pub mention_quota_pending: MentionQuotaPendingRepository,
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
    pub error: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityReviewDebounceEntry {
    pub repo: String,
    pub iid: u64,
    pub last_started_at: i64,
    pub next_eligible_at: i64,
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
        ensure_sqlite_file(path)?;
        let sqlite = SqliteCoordinator::connect(path).await?;
        sqlx::migrate!()
            .run(sqlite.read_pool())
            .await
            .context("run sqlite migrations")?;

        Ok(Self {
            review_state: ReviewStateRepository::new(sqlite.clone()),
            run_history: RunHistoryRepository::new(sqlite.clone()),
            project_catalog: ProjectCatalogRepository::new(sqlite.clone()),
            feature_flags: FeatureFlagsRepository::new(sqlite.clone()),
            mention_commands: MentionCommandsRepository::new(sqlite.clone()),
            mention_quota_pending: MentionQuotaPendingRepository::new(sqlite.clone()),
            service_state: ServiceStateRepository::new(sqlite.clone()),
            security_context_cache: SecurityContextCacheRepository::new(sqlite.clone()),
            security_review_debounce: SecurityReviewDebounceRepository::new(sqlite.clone()),
            review_rate_limit: ReviewRateLimitRepository::new(sqlite.clone()),
            sqlite,
        })
    }

    /// # Errors
    ///
    /// Returns an error if an accepted background write failed.
    pub async fn flush_background_writes(&self) -> Result<()> {
        self.sqlite.flush_background_writes().await
    }

    #[cfg(test)]
    #[must_use]
    pub fn pool(&self) -> &sqlx::SqlitePool {
        self.sqlite.read_pool()
    }

    #[cfg(test)]
    pub async fn pause_background_writes_for_test(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.sqlite.pause_background_writes_for_test().await
    }
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

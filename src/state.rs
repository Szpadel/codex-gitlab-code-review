use crate::feature_flags::{FeatureFlagSnapshot, RuntimeFeatureFlagOverrides};
use crate::review_lane::ReviewLane;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{
    QueryBuilder, Row, Sqlite, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::path::Path;
use std::str::FromStr;
use tracing::warn;
use uuid::Uuid;

const AUTH_LIMIT_RESET_KEY_PREFIX: &str = "codex_auth_limit_reset_at::";
const FEATURE_FLAG_OVERRIDES_KEY: &str = "feature_flag_overrides";
const SCAN_STATUS_KEY: &str = "scan_status";

pub struct ReviewStateStore {
    pool: SqlitePool,
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
    pub fn encode(self) -> String {
        let raw = format!("{}:{}", self.started_at, self.id);
        encode_hex(raw.as_bytes())
    }

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
            .with_context(|| format!("connect sqlite database at {}", path))?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("run sqlite migrations")?;
        Ok(Self { pool })
    }

    pub async fn begin_review(&self, repo: &str, iid: u64, sha: &str) -> Result<bool> {
        self.begin_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    pub async fn begin_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
        let row =
            sqlx::query("SELECT status FROM review_state WHERE repo = ? AND iid = ? AND lane = ?")
                .bind(repo)
                .bind(iid as i64)
                .bind(lane.as_str())
                .fetch_optional(&mut *tx)
                .await
                .context("load existing review state")?;
        if let Some(existing) = row {
            let status: String = existing.try_get("status").context("read review status")?;
            if status == "in_progress" {
                tx.commit().await.context("commit sqlite transaction")?;
                return Ok(false);
            }
        }
        sqlx::query(
            r#"
            INSERT INTO review_state (repo, iid, lane, head_sha, status, started_at, updated_at)
            VALUES (?, ?, ?, ?, 'in_progress', ?, ?)
            ON CONFLICT(repo, iid, lane) DO UPDATE SET
                head_sha = excluded.head_sha,
                status = 'in_progress',
                started_at = excluded.started_at,
                updated_at = excluded.updated_at,
                result = NULL
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(lane.as_str())
        .bind(sha)
        .bind(now)
        .bind(now)
        .execute(&mut *tx)
        .await
        .context("insert review state")?;
        tx.commit().await.context("commit sqlite transaction")?;
        Ok(true)
    }

    pub async fn finish_review(&self, repo: &str, iid: u64, sha: &str, result: &str) -> Result<()> {
        self.finish_review_for_lane(repo, iid, sha, ReviewLane::General, result)
            .await
    }

    pub async fn finish_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
        result: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE review_state
            SET status = 'done', head_sha = ?, result = ?, updated_at = ?
            WHERE repo = ? AND iid = ? AND lane = ? AND head_sha = ? AND status = 'in_progress'
            "#,
        )
        .bind(sha)
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .bind(lane.as_str())
        .bind(sha)
        .execute(&self.pool)
        .await
        .context("update review state")?;
        Ok(())
    }

    pub async fn has_completed_inline_review(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
    ) -> Result<bool> {
        self.has_completed_inline_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    pub async fn has_completed_inline_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<bool> {
        let kind = if lane.is_security() {
            RunHistoryKind::Security
        } else {
            RunHistoryKind::Review
        };
        let row = sqlx::query(
            r#"
            SELECT 1
            FROM run_history
            WHERE kind = ?
              AND review_lane = ?
              AND repo = ?
              AND iid = ?
              AND head_sha = ?
              AND status = 'done'
              AND result = 'comment'
              AND feature_flags_json LIKE '%"gitlab_inline_review_comments":true%'
            LIMIT 1
            "#,
        )
        .bind(run_history_kind_label(kind))
        .bind(lane.as_str())
        .bind(repo)
        .bind(iid as i64)
        .bind(sha)
        .fetch_optional(&self.pool)
        .await;
        let row = match row {
            Ok(row) => row,
            Err(err) if err.to_string().contains("no such table: run_history") => return Ok(false),
            Err(err) => return Err(err).context("load completed inline review state"),
        };
        Ok(row.is_some())
    }

    pub async fn review_result(&self, repo: &str, iid: u64, sha: &str) -> Result<Option<String>> {
        self.review_result_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    pub async fn review_result_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            r#"
            SELECT result
            FROM review_state
            WHERE repo = ?
              AND iid = ?
              AND lane = ?
              AND head_sha = ?
              AND status = 'done'
            LIMIT 1
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(lane.as_str())
        .bind(sha)
        .fetch_optional(&self.pool)
        .await
        .context("load review result")?;
        Ok(row.map(|row| row.get::<String, _>(0)))
    }

    pub async fn list_in_progress_reviews(&self) -> Result<Vec<InProgressReview>> {
        let rows = sqlx::query(
            r#"
            SELECT repo, iid, lane, head_sha
            FROM review_state
            WHERE status = 'in_progress'
            ORDER BY repo, iid, lane
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("list in-progress reviews")?;

        rows.into_iter()
            .map(|row| {
                let repo: String = row.try_get("repo").context("read review repo")?;
                let iid_raw: i64 = row.try_get("iid").context("read review iid")?;
                let iid = u64::try_from(iid_raw).context("convert review iid to u64")?;
                let lane = parse_review_lane(
                    row.try_get::<String, _>("lane")
                        .context("read review lane")?
                        .as_str(),
                )?;
                let head_sha: String = row.try_get("head_sha").context("read review head sha")?;
                Ok(InProgressReview {
                    lane,
                    repo,
                    iid,
                    head_sha,
                })
            })
            .collect()
    }

    pub(crate) async fn has_in_progress_review(&self, repo: &str, iid: u64) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM review_state
                WHERE repo = ? AND iid = ? AND status = 'in_progress'
            )
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .fetch_one(&self.pool)
        .await
        .context("check in-progress review")?;
        Ok(exists != 0)
    }

    pub async fn clear_stale_in_progress(&self, max_age_minutes: u64) -> Result<()> {
        let cutoff = Utc::now().timestamp() - (max_age_minutes as i64 * 60);
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE review_state
            SET status = 'stale', updated_at = ?
            WHERE status = 'in_progress' AND updated_at < ?
            "#,
        )
        .bind(now)
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .context("mark stale reviews")?;
        Ok(())
    }

    pub async fn touch_in_progress_review(&self, repo: &str, iid: u64, sha: &str) -> Result<()> {
        self.touch_in_progress_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    pub async fn touch_in_progress_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE review_state
            SET updated_at = ?
            WHERE repo = ? AND iid = ? AND lane = ? AND head_sha = ? AND status = 'in_progress'
            "#,
        )
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .bind(lane.as_str())
        .bind(sha)
        .execute(&self.pool)
        .await
        .context("touch in-progress review")?;
        Ok(())
    }

    pub async fn get_security_review_context_cache(
        &self,
        repo: &str,
        base_branch: &str,
        base_head_sha: &str,
        prompt_version: &str,
        now: i64,
    ) -> Result<Option<SecurityReviewContextCacheEntry>> {
        self.delete_expired_security_review_context_cache(now)
            .await?;
        let row = sqlx::query(
            r#"
            SELECT repo, base_branch, base_head_sha, prompt_version, payload_json, source_run_history_id,
                   generated_at, expires_at
            FROM security_review_context_cache
            WHERE repo = ?
              AND base_branch = ?
              AND base_head_sha = ?
              AND prompt_version = ?
              AND expires_at > ?
            LIMIT 1
            "#,
        )
        .bind(repo)
        .bind(base_branch)
        .bind(base_head_sha)
        .bind(prompt_version)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("load security review context cache")?;
        row.map(map_security_review_context_cache_entry).transpose()
    }

    pub async fn upsert_security_review_context_cache(
        &self,
        entry: &SecurityReviewContextCacheEntry,
    ) -> Result<()> {
        self.delete_expired_security_review_context_cache(entry.generated_at)
            .await?;
        sqlx::query(
            r#"
            INSERT INTO security_review_context_cache (
                repo,
                base_branch,
                base_head_sha,
                prompt_version,
                payload_json,
                source_run_history_id,
                generated_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo, base_branch, base_head_sha, prompt_version) DO UPDATE SET
                payload_json = excluded.payload_json,
                source_run_history_id = excluded.source_run_history_id,
                generated_at = excluded.generated_at,
                expires_at = excluded.expires_at
            "#,
        )
        .bind(&entry.repo)
        .bind(&entry.base_branch)
        .bind(&entry.base_head_sha)
        .bind(&entry.prompt_version)
        .bind(&entry.payload_json)
        .bind(entry.source_run_history_id)
        .bind(entry.generated_at)
        .bind(entry.expires_at)
        .execute(&self.pool)
        .await
        .context("upsert security review context cache")?;
        Ok(())
    }

    async fn delete_expired_security_review_context_cache(&self, now: i64) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM security_review_context_cache
            WHERE expires_at <= ?
            "#,
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .context("delete expired security review context cache")?;
        Ok(())
    }

    pub async fn clear_stale_in_progress_mentions(&self, max_age_minutes: u64) -> Result<()> {
        let cutoff = Utc::now().timestamp() - (max_age_minutes as i64 * 60);
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE mention_command_state
            SET status = 'done', result = 'error', updated_at = ?
            WHERE status = 'in_progress' AND updated_at < ?
            "#,
        )
        .bind(now)
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .context("mark stale mention commands")?;
        Ok(())
    }

    pub async fn touch_in_progress_mention_command(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
        head_sha: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE mention_command_state
            SET updated_at = ?
            WHERE repo = ?
              AND iid = ?
              AND discussion_id = ?
              AND trigger_note_id = ?
              AND head_sha = ?
              AND status = 'in_progress'
            "#,
        )
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .bind(head_sha)
        .execute(&self.pool)
        .await
        .context("touch in-progress mention command")?;
        Ok(())
    }

    pub async fn reconcile_interrupted_run_history(&self, reason: &str) -> Result<u64> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            UPDATE run_history
            SET status = 'done',
                result = 'cancelled',
                finished_at = COALESCE(finished_at, ?),
                updated_at = ?,
                error = COALESCE(error, ?)
            WHERE status = 'in_progress'
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(reason)
        .execute(&self.pool)
        .await
        .context("reconcile interrupted run history")?;
        Ok(result.rows_affected())
    }

    pub async fn begin_mention_command(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
        head_sha: &str,
    ) -> Result<bool> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO mention_command_state (
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                head_sha,
                status,
                started_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?)
            ON CONFLICT(repo, iid, discussion_id, trigger_note_id) DO UPDATE
            SET head_sha = excluded.head_sha,
                status = 'in_progress',
                started_at = excluded.started_at,
                updated_at = excluded.updated_at,
                result = NULL
            WHERE mention_command_state.status != 'in_progress'
              AND (
                  mention_command_state.result = 'cancelled'
                  OR mention_command_state.result IS NULL
              )
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .bind(head_sha)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("insert mention command state")?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn finish_mention_command(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
        head_sha: &str,
        result: &str,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE mention_command_state
            SET status = 'done', result = ?, updated_at = ?
            WHERE repo = ?
              AND iid = ?
              AND discussion_id = ?
              AND trigger_note_id = ?
              AND head_sha = ?
              AND status = 'in_progress'
            "#,
        )
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .bind(head_sha)
        .execute(&self.pool)
        .await
        .context("update mention command state")?;
        Ok(())
    }

    pub async fn list_in_progress_mention_commands(&self) -> Result<Vec<InProgressMentionCommand>> {
        let rows = sqlx::query(
            r#"
            SELECT repo, iid, discussion_id, trigger_note_id, head_sha
            FROM mention_command_state
            WHERE status = 'in_progress'
            ORDER BY repo, iid, discussion_id, trigger_note_id
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("list in-progress mention commands")?;

        rows.into_iter()
            .map(|row| {
                let repo: String = row.try_get("repo").context("read mention command repo")?;
                let iid_raw: i64 = row.try_get("iid").context("read mention command iid")?;
                let iid = u64::try_from(iid_raw).context("convert mention command iid to u64")?;
                let discussion_id: String = row
                    .try_get("discussion_id")
                    .context("read mention command discussion id")?;
                let trigger_note_id_raw: i64 = row
                    .try_get("trigger_note_id")
                    .context("read mention command trigger note id")?;
                let trigger_note_id = u64::try_from(trigger_note_id_raw)
                    .context("convert mention command trigger note id to u64")?;
                let head_sha: String = row
                    .try_get("head_sha")
                    .context("read mention command head sha")?;
                Ok(InProgressMentionCommand {
                    key: MentionCommandStateKey {
                        repo,
                        iid,
                        discussion_id,
                        trigger_note_id,
                    },
                    head_sha,
                })
            })
            .collect()
    }

    pub(crate) async fn has_in_progress_mention_for_mr(
        &self,
        repo: &str,
        iid: u64,
    ) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT EXISTS(
                SELECT 1
                FROM mention_command_state
                WHERE repo = ? AND iid = ? AND status = 'in_progress'
            )
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .fetch_one(&self.pool)
        .await
        .context("check in-progress mention command")?;
        Ok(exists != 0)
    }

    pub(crate) async fn mr_has_in_progress_work(&self, repo: &str, iid: u64) -> Result<bool> {
        Ok(self.has_in_progress_review(repo, iid).await?
            || self.has_in_progress_mention_for_mr(repo, iid).await?)
    }

    pub(crate) async fn mention_command_scan_state(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) -> Result<MentionCommandScanState> {
        let row = sqlx::query(
            r#"
            SELECT status, result
            FROM mention_command_state
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .fetch_optional(&self.pool)
        .await
        .context("load mention command scan state")?;

        let Some(row) = row else {
            return Ok(MentionCommandScanState::Ready);
        };

        let status: String = row
            .try_get("status")
            .context("read mention command scan status")?;
        let result: Option<String> = row
            .try_get("result")
            .context("read mention command scan result")?;

        if status == "in_progress" {
            return Ok(MentionCommandScanState::InProgress);
        }
        if matches!(result.as_deref(), None | Some("cancelled")) {
            return Ok(MentionCommandScanState::Ready);
        }
        Ok(MentionCommandScanState::Completed)
    }

    pub async fn start_run_history(&self, new_run: NewRunHistory) -> Result<i64> {
        let review_lane = match new_run.kind {
            RunHistoryKind::Review => Some(ReviewLane::General),
            RunHistoryKind::Security => Some(ReviewLane::Security),
            RunHistoryKind::Mention => None,
        };
        self.start_run_history_for_lane(new_run, review_lane).await
    }

    pub async fn start_run_history_for_lane(
        &self,
        new_run: NewRunHistory,
        review_lane: Option<ReviewLane>,
    ) -> Result<i64> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO run_history (
                kind,
                review_lane,
                repo,
                iid,
                head_sha,
                status,
                started_at,
                updated_at,
                discussion_id,
                trigger_note_id,
                trigger_note_author_name,
                trigger_note_body,
                command_repo
            )
            VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(run_history_kind_label(new_run.kind))
        .bind(review_lane.map(ReviewLane::as_str))
        .bind(new_run.repo)
        .bind(new_run.iid as i64)
        .bind(new_run.head_sha)
        .bind(now)
        .bind(now)
        .bind(new_run.discussion_id)
        .bind(new_run.trigger_note_id.map(|value| value as i64))
        .bind(new_run.trigger_note_author_name)
        .bind(new_run.trigger_note_body)
        .bind(new_run.command_repo)
        .execute(&self.pool)
        .await
        .context("insert run history")?;
        Ok(result.last_insert_rowid())
    }

    pub async fn update_run_history_session(
        &self,
        run_id: i64,
        update: RunHistorySessionUpdate,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE run_history
            SET thread_id = COALESCE(?, thread_id),
                turn_id = COALESCE(?, turn_id),
                review_thread_id = COALESCE(?, review_thread_id),
                auth_account_name = COALESCE(?, auth_account_name),
                security_context_source_run_id = COALESCE(?, security_context_source_run_id),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(update.thread_id)
        .bind(update.turn_id)
        .bind(update.review_thread_id)
        .bind(update.auth_account_name)
        .bind(update.security_context_source_run_id)
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("update run history session metadata")?;
        Ok(())
    }

    pub async fn set_run_history_feature_flags(
        &self,
        run_id: i64,
        feature_flags: &FeatureFlagSnapshot,
    ) -> Result<()> {
        let feature_flags_json =
            serde_json::to_string(feature_flags).context("serialize feature flag snapshot")?;
        sqlx::query(
            r#"
            UPDATE run_history
            SET feature_flags_json = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(feature_flags_json)
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("update run history feature flags")?;
        Ok(())
    }

    pub async fn update_run_history_head_sha(&self, run_id: i64, head_sha: &str) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE run_history
            SET head_sha = ?, updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(head_sha)
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("update run history head sha")?;
        Ok(())
    }

    pub async fn finish_run_history(&self, run_id: i64, finish: RunHistoryFinish) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE run_history
            SET status = 'done',
                result = ?,
                finished_at = ?,
                updated_at = ?,
                thread_id = COALESCE(?, thread_id),
                turn_id = COALESCE(?, turn_id),
                review_thread_id = COALESCE(?, review_thread_id),
                preview = ?,
                summary = ?,
                error = ?,
                auth_account_name = COALESCE(?, auth_account_name),
                commit_sha = ?
            WHERE id = ?
            "#,
        )
        .bind(finish.result)
        .bind(now)
        .bind(now)
        .bind(finish.thread_id)
        .bind(finish.turn_id)
        .bind(finish.review_thread_id)
        .bind(finish.preview)
        .bind(finish.summary)
        .bind(finish.error)
        .bind(finish.auth_account_name)
        .bind(finish.commit_sha)
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("finish run history")?;
        Ok(())
    }

    pub async fn mark_run_history_events_incomplete(&self, run_id: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE run_history
            SET events_persisted_cleanly = 0,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("mark run history events incomplete")?;
        Ok(())
    }

    pub async fn append_run_history_events(
        &self,
        run_history_id: i64,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let created_at = Utc::now().timestamp();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction for run history events")?;
        let sequence_offset = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COALESCE(MAX(sequence), 0)
            FROM run_history_event
            WHERE run_history_id = ?
            "#,
        )
        .bind(run_history_id)
        .fetch_one(&mut *tx)
        .await
        .context("load current run history event sequence")?;
        for event in events {
            let payload_json =
                serde_json::to_string(&event.payload).context("serialize run history payload")?;
            sqlx::query(
                r#"
                INSERT INTO run_history_event (
                    run_history_id,
                    sequence,
                    turn_id,
                    event_type,
                    payload_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(run_history_id)
            .bind(sequence_offset + event.sequence)
            .bind(event.turn_id.as_deref())
            .bind(event.event_type.as_str())
            .bind(payload_json)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .context("insert run history event")?;
        }
        tx.commit()
            .await
            .context("commit sqlite transaction for run history events")?;
        Ok(())
    }

    pub async fn replace_run_history_events(
        &self,
        run_history_id: i64,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        let created_at = Utc::now().timestamp();
        let rewritten_events = events.to_vec();
        self.replace_run_history_events_inner(run_history_id, rewritten_events, created_at)
            .await
    }

    pub async fn replace_run_history_events_for_turn(
        &self,
        run_history_id: i64,
        turn_id: &str,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        let created_at = Utc::now().timestamp();
        let existing_events = self.list_run_history_events(run_history_id).await?;
        let rewritten_events = merge_rewritten_turn_events(existing_events, turn_id, events)
            .with_context(|| format!("merge rewritten run history events for turn {turn_id}"))?;
        self.replace_run_history_events_inner(run_history_id, rewritten_events, created_at)
            .await
    }

    async fn replace_run_history_events_inner(
        &self,
        run_history_id: i64,
        events: Vec<NewRunHistoryEvent>,
        created_at: i64,
    ) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction for run history event rewrite")?;
        sqlx::query("DELETE FROM run_history_event WHERE run_history_id = ?")
            .bind(run_history_id)
            .execute(&mut *tx)
            .await
            .context("delete previous run history events")?;
        for event in events {
            let payload_json =
                serde_json::to_string(&event.payload).context("serialize run history payload")?;
            sqlx::query(
                r#"
                INSERT INTO run_history_event (
                    run_history_id,
                    sequence,
                    turn_id,
                    event_type,
                    payload_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(run_history_id)
            .bind(event.sequence)
            .bind(event.turn_id.as_deref())
            .bind(event.event_type.as_str())
            .bind(payload_json)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .context("insert rewritten run history event")?;
        }
        sqlx::query("UPDATE run_history SET updated_at = ? WHERE id = ?")
            .bind(created_at)
            .bind(run_history_id)
            .execute(&mut *tx)
            .await
            .context("update run history timestamp after event rewrite")?;
        tx.commit()
            .await
            .context("commit sqlite transaction for run history event rewrite")?;
        Ok(())
    }

    pub async fn mark_run_history_transcript_backfill_complete(&self, run_id: i64) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE run_history
            SET events_persisted_cleanly = 1,
                transcript_backfill_state = ?,
                transcript_backfill_error = NULL,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(transcript_backfill_state_label(
            TranscriptBackfillState::Complete,
        ))
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("mark run history transcript backfill complete")?;
        Ok(())
    }

    pub async fn update_run_history_transcript_backfill(
        &self,
        run_id: i64,
        state: TranscriptBackfillState,
        error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE run_history
            SET transcript_backfill_state = ?,
                transcript_backfill_error = ?,
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(transcript_backfill_state_label(state))
        .bind(error)
        .bind(Utc::now().timestamp())
        .bind(run_id)
        .execute(&self.pool)
        .await
        .context("update run history transcript backfill state")?;
        Ok(())
    }

    pub async fn list_run_history_events(
        &self,
        run_history_id: i64,
    ) -> Result<Vec<RunHistoryEventRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, run_history_id, sequence, turn_id, event_type, payload_json, created_at
            FROM run_history_event
            WHERE run_history_id = ?
            ORDER BY sequence ASC, id ASC
            "#,
        )
        .bind(run_history_id)
        .fetch_all(&self.pool)
        .await
        .context("list run history events")?;
        rows.into_iter().map(map_run_history_event_row).collect()
    }

    pub async fn list_run_history_for_mr(
        &self,
        repo: &str,
        iid: u64,
    ) -> Result<Vec<RunHistoryRecord>> {
        let rows = sqlx::query(
            r#"
            SELECT id, kind, review_lane, repo, iid, head_sha, status, result, started_at, finished_at, updated_at,
                   thread_id, turn_id, review_thread_id, security_context_source_run_id,
                   preview, summary, error, auth_account_name,
                   discussion_id, trigger_note_id, trigger_note_author_name, trigger_note_body,
                   command_repo, commit_sha, feature_flags_json, events_persisted_cleanly,
                   transcript_backfill_state, transcript_backfill_error
            FROM run_history
            WHERE repo = ? AND iid = ?
            ORDER BY started_at DESC, id DESC
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .fetch_all(&self.pool)
        .await
        .context("list run history for MR")?;
        rows.into_iter().map(map_run_history_row).collect()
    }

    pub async fn get_run_history(&self, run_id: i64) -> Result<Option<RunHistoryRecord>> {
        let row = sqlx::query(
            r#"
            SELECT id, kind, review_lane, repo, iid, head_sha, status, result, started_at, finished_at, updated_at,
                   thread_id, turn_id, review_thread_id, security_context_source_run_id,
                   preview, summary, error, auth_account_name,
                   discussion_id, trigger_note_id, trigger_note_author_name, trigger_note_body,
                   command_repo, commit_sha, feature_flags_json, events_persisted_cleanly,
                   transcript_backfill_state, transcript_backfill_error
            FROM run_history
            WHERE id = ?
            "#,
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .context("get run history")?;
        row.map(map_run_history_row).transpose()
    }

    pub async fn list_run_history(
        &self,
        query: &RunHistoryListQuery,
    ) -> Result<RunHistoryListPage> {
        if query.after.is_some() && query.before.is_some() {
            bail!("run history query cannot include both after and before cursors");
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            r#"
            SELECT id, kind, review_lane, repo, iid, status, result, started_at, preview, summary
            FROM run_history
            "#,
        );
        let mut has_where = append_run_history_filters(&mut builder, query);

        let limit = query.normalized_limit();
        if let Some(cursor) = query.after {
            append_run_history_cursor_clause(
                &mut builder,
                &mut has_where,
                cursor,
                CursorDirection::After,
            );
        } else if let Some(cursor) = query.before {
            append_run_history_cursor_clause(
                &mut builder,
                &mut has_where,
                cursor,
                CursorDirection::Before,
            );
        }

        let ordered_before = query.before.is_some();
        if ordered_before {
            builder.push(" ORDER BY started_at ASC, id ASC");
        } else {
            builder.push(" ORDER BY started_at DESC, id DESC");
        }
        builder
            .push(" LIMIT ")
            .push_bind(i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX));

        let mut runs = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .context("list run history")?;
        let has_extra = runs.len() > limit;
        if has_extra {
            runs.pop();
        }

        let mut runs = runs
            .into_iter()
            .map(map_run_history_list_item_row)
            .collect::<Result<Vec<_>>>()?;
        if ordered_before {
            runs.reverse();
        }

        let has_previous = match (query.after, query.before) {
            (_, Some(_)) => has_extra,
            (Some(_), None) => !runs.is_empty(),
            (None, None) => false,
        };
        let has_next = match (query.after, query.before) {
            (Some(_), _) => has_extra,
            (None, Some(_)) => !runs.is_empty(),
            (None, None) => has_extra,
        };

        Ok(RunHistoryListPage {
            previous_cursor: if has_previous {
                runs.first().map(RunHistoryCursor::from)
            } else {
                None
            },
            next_cursor: if has_next {
                runs.last().map(RunHistoryCursor::from)
            } else {
                None
            },
            has_previous,
            has_next,
            runs,
        })
    }

    pub async fn get_project_last_mr_activity(&self, repo: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT last_activity_at FROM project_state WHERE repo = ?")
            .bind(repo)
            .fetch_optional(&self.pool)
            .await
            .context("load project last MR activity")?;
        match row {
            Some(row) => {
                let value: String = row
                    .try_get("last_activity_at")
                    .context("read project last MR activity")?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set_project_last_mr_activity(
        &self,
        repo: &str,
        last_activity_at: &str,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO project_state (repo, last_activity_at)
            VALUES (?, ?)
            ON CONFLICT(repo) DO UPDATE SET
                last_activity_at = excluded.last_activity_at
            "#,
        )
        .bind(repo)
        .bind(last_activity_at)
        .execute(&self.pool)
        .await
        .context("upsert project last MR activity")?;
        Ok(())
    }

    pub async fn load_project_catalog(&self, key: &str) -> Result<Option<ProjectCatalog>> {
        let row =
            sqlx::query("SELECT fetched_at, projects FROM project_catalog WHERE cache_key = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .context("load project catalog")?;
        match row {
            Some(row) => {
                let fetched_at: i64 = row.try_get("fetched_at").context("read fetched_at")?;
                let projects_json: String =
                    row.try_get("projects").context("read catalog projects")?;
                let projects: Vec<String> =
                    serde_json::from_str(&projects_json).context("deserialize catalog projects")?;
                Ok(Some(ProjectCatalog {
                    fetched_at,
                    projects,
                }))
            }
            None => Ok(None),
        }
    }

    pub async fn save_project_catalog(&self, key: &str, projects: &[String]) -> Result<()> {
        let now = Utc::now().timestamp();
        let projects_json =
            serde_json::to_string(projects).context("serialize catalog projects")?;
        sqlx::query(
            r#"
            INSERT INTO project_catalog (cache_key, fetched_at, projects, project_count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                fetched_at = excluded.fetched_at,
                projects = excluded.projects,
                project_count = excluded.project_count
            "#,
        )
        .bind(key)
        .bind(now)
        .bind(projects_json)
        .bind(projects.len() as i64)
        .execute(&self.pool)
        .await
        .context("upsert project catalog")?;
        Ok(())
    }

    pub async fn get_created_after(&self) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM service_state WHERE key = ?")
            .bind("created_after")
            .fetch_optional(&self.pool)
            .await
            .context("load created_after state")?;
        match row {
            Some(row) => {
                let value: String = row.try_get("value").context("read created_after state")?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set_created_after(&self, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO service_state (key, value)
            VALUES ('created_after', ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value
            "#,
        )
        .bind(value)
        .execute(&self.pool)
        .await
        .context("upsert created_after state")?;
        Ok(())
    }

    pub async fn get_or_create_review_owner_id(&self) -> Result<String> {
        let candidate = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO service_state (key, value)
            VALUES ('review_owner_id', ?)
            "#,
        )
        .bind(candidate)
        .execute(&self.pool)
        .await
        .context("insert review_owner_id state")?;

        let row = sqlx::query("SELECT value FROM service_state WHERE key = ?")
            .bind("review_owner_id")
            .fetch_one(&self.pool)
            .await
            .context("load review_owner_id state")?;
        let owner_id: String = row.try_get("value").context("read review_owner_id state")?;
        Ok(owner_id)
    }

    pub async fn get_auth_limit_reset_at(&self, account_name: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM service_state WHERE key = ?")
            .bind(auth_limit_reset_key(account_name))
            .fetch_optional(&self.pool)
            .await
            .with_context(|| {
                format!("load codex auth limit reset state for account {account_name}")
            })?;
        match row {
            Some(row) => {
                let value: String = row.try_get("value").with_context(|| {
                    format!("read codex auth limit reset state for account {account_name}")
                })?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set_auth_limit_reset_at(&self, account_name: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO service_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = CASE
                    WHEN julianday(service_state.value) IS NULL THEN excluded.value
                    WHEN julianday(excluded.value) IS NULL THEN service_state.value
                    WHEN julianday(excluded.value) > julianday(service_state.value) THEN excluded.value
                    ELSE service_state.value
                END
            "#,
        )
        .bind(auth_limit_reset_key(account_name))
        .bind(value)
        .execute(&self.pool)
        .await
        .with_context(|| {
            format!("upsert codex auth limit reset state for account {account_name}")
        })?;
        Ok(())
    }

    pub async fn clear_auth_limit_reset_at(&self, account_name: &str) -> Result<()> {
        sqlx::query("DELETE FROM service_state WHERE key = ?")
            .bind(auth_limit_reset_key(account_name))
            .execute(&self.pool)
            .await
            .with_context(|| {
                format!("delete codex auth limit reset state for account {account_name}")
            })?;
        Ok(())
    }

    pub async fn get_scan_status(&self) -> Result<PersistedScanStatus> {
        let raw = self.get_service_state_value(SCAN_STATUS_KEY).await?;
        match raw {
            Some(raw) => match serde_json::from_str(&raw) {
                Ok(scan) => Ok(scan),
                Err(err) => {
                    warn!(error = %err, "invalid persisted scan status; using default");
                    Ok(PersistedScanStatus::default())
                }
            },
            None => Ok(PersistedScanStatus::default()),
        }
    }

    pub async fn set_scan_status(&self, status: &PersistedScanStatus) -> Result<()> {
        let raw = serde_json::to_string(status).context("serialize scan status")?;
        self.set_service_state_value(SCAN_STATUS_KEY, &raw).await
    }

    pub async fn clear_next_scan_at(&self) -> Result<()> {
        let mut status = self.get_scan_status().await?;
        status.next_scan_at = None;
        self.set_scan_status(&status).await
    }

    pub async fn list_auth_limit_reset_entries(&self) -> Result<Vec<AuthLimitResetEntry>> {
        let rows =
            sqlx::query("SELECT key, value FROM service_state WHERE key LIKE ? ORDER BY key ASC")
                .bind(format!("{AUTH_LIMIT_RESET_KEY_PREFIX}%"))
                .fetch_all(&self.pool)
                .await
                .context("list auth limit reset entries")?;

        rows.into_iter()
            .map(|row| {
                let key: String = row.try_get("key").context("read auth limit reset key")?;
                let reset_at: String = row
                    .try_get("value")
                    .context("read auth limit reset timestamp")?;
                Ok(AuthLimitResetEntry {
                    account_name: key
                        .strip_prefix(AUTH_LIMIT_RESET_KEY_PREFIX)
                        .unwrap_or(key.as_str())
                        .to_string(),
                    reset_at,
                })
            })
            .collect()
    }

    pub async fn list_project_catalog_summaries(&self) -> Result<Vec<ProjectCatalogSummary>> {
        let rows = sqlx::query(
            r#"
            SELECT cache_key, fetched_at, project_count
            FROM project_catalog
            ORDER BY cache_key ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .context("list project catalogs")?;

        let mut summaries = Vec::with_capacity(rows.len());
        for row in rows {
            let cache_key: String = row.try_get("cache_key").context("read cache_key")?;
            let fetched_at: i64 = row.try_get("fetched_at").context("read fetched_at")?;
            let project_count_raw: Option<i64> =
                row.try_get("project_count").context("read project_count")?;
            let project_count = match project_count_raw {
                Some(project_count) => {
                    usize::try_from(project_count).context("convert project_count")?
                }
                None => self.load_legacy_project_catalog_count(&cache_key).await?,
            };
            summaries.push(ProjectCatalogSummary {
                cache_key,
                fetched_at,
                project_count,
            });
        }
        Ok(summaries)
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn get_runtime_feature_flag_overrides(&self) -> Result<RuntimeFeatureFlagOverrides> {
        let raw = self
            .get_service_state_value(FEATURE_FLAG_OVERRIDES_KEY)
            .await?;
        match raw {
            Some(raw) => serde_json::from_str(&raw).context("deserialize feature flag overrides"),
            None => Ok(RuntimeFeatureFlagOverrides::default()),
        }
    }

    pub async fn set_runtime_feature_flag_overrides(
        &self,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> Result<()> {
        let raw = serde_json::to_string(overrides).context("serialize feature flag overrides")?;
        self.set_service_state_value(FEATURE_FLAG_OVERRIDES_KEY, &raw)
            .await
    }

    async fn get_service_state_value(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM service_state WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .with_context(|| format!("load service_state value for key {key}"))?;
        row.map(|row| row.try_get("value").context("read service_state value"))
            .transpose()
    }

    async fn set_service_state_value(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO service_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value
            "#,
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .with_context(|| format!("upsert service_state value for key {key}"))?;
        Ok(())
    }

    async fn load_legacy_project_catalog_count(&self, key: &str) -> Result<usize> {
        let row = sqlx::query("SELECT projects FROM project_catalog WHERE cache_key = ?")
            .bind(key)
            .fetch_one(&self.pool)
            .await
            .with_context(|| format!("load legacy project catalog for key {key}"))?;
        let projects_json: String = row.try_get("projects").context("read projects")?;
        let projects: Vec<String> = serde_json::from_str(&projects_json)
            .context("deserialize catalog projects for legacy count")?;
        let project_count = projects.len();
        sqlx::query(
            "UPDATE project_catalog SET project_count = ? WHERE cache_key = ? AND project_count IS NULL",
        )
        .bind(project_count as i64)
        .bind(key)
        .execute(&self.pool)
        .await
        .with_context(|| format!("backfill legacy project count for key {key}"))?;
        Ok(project_count)
    }
}

fn auth_limit_reset_key(account_name: &str) -> String {
    format!("{AUTH_LIMIT_RESET_KEY_PREFIX}{account_name}")
}

fn run_history_kind_label(kind: RunHistoryKind) -> &'static str {
    match kind {
        RunHistoryKind::Review => "review",
        RunHistoryKind::Security => "security",
        RunHistoryKind::Mention => "mention",
    }
}

fn append_run_history_filters<'args>(
    builder: &mut QueryBuilder<'args, Sqlite>,
    query: &'args RunHistoryListQuery,
) -> bool {
    let mut has_where = false;
    let mut push_where = |builder: &mut QueryBuilder<'args, Sqlite>| {
        if !has_where {
            builder.push(" WHERE ");
            has_where = true;
        } else {
            builder.push(" AND ");
        }
    };

    if let Some(repo) = query.repo.as_deref() {
        push_where(builder);
        builder.push("repo = ").push_bind(repo);
    }
    if let Some(iid) = query.iid {
        push_where(builder);
        builder.push("iid = ").push_bind(iid as i64);
    }
    if let Some(kind) = query.kind {
        push_where(builder);
        builder
            .push("kind = ")
            .push_bind(run_history_kind_label(kind));
    }
    if let Some(result) = query.result.as_deref() {
        push_where(builder);
        builder.push("result = ").push_bind(result);
    }
    if let Some(search) = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let pattern = format!("%{search}%");
        push_where(builder);
        builder.push("(");
        builder.push("repo LIKE ").push_bind(pattern.clone());
        builder.push(" OR summary LIKE ").push_bind(pattern.clone());
        builder.push(" OR preview LIKE ").push_bind(pattern.clone());
        builder.push(" OR error LIKE ").push_bind(pattern.clone());
        builder
            .push(" OR trigger_note_body LIKE ")
            .push_bind(pattern);
        builder.push(")");
    }

    has_where
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorDirection {
    After,
    Before,
}

fn append_run_history_cursor_clause<'args>(
    builder: &mut QueryBuilder<'args, Sqlite>,
    has_where: &mut bool,
    cursor: RunHistoryCursor,
    direction: CursorDirection,
) {
    if !*has_where {
        builder.push(" WHERE ");
        *has_where = true;
    } else {
        builder.push(" AND ");
    }
    builder.push("(");
    match direction {
        CursorDirection::After => builder
            .push("started_at < ")
            .push_bind(cursor.started_at)
            .push(" OR (started_at = ")
            .push_bind(cursor.started_at)
            .push(" AND id < ")
            .push_bind(cursor.id)
            .push(")"),
        CursorDirection::Before => builder
            .push("started_at > ")
            .push_bind(cursor.started_at)
            .push(" OR (started_at = ")
            .push_bind(cursor.started_at)
            .push(" AND id > ")
            .push_bind(cursor.id)
            .push(")"),
    };
    builder.push(")");
}

fn parse_run_history_kind(value: &str) -> Result<RunHistoryKind> {
    match value {
        "review" => Ok(RunHistoryKind::Review),
        "security" => Ok(RunHistoryKind::Security),
        "mention" => Ok(RunHistoryKind::Mention),
        other => bail!("unknown run_history kind: {other}"),
    }
}

fn parse_review_lane(value: &str) -> Result<ReviewLane> {
    match value {
        "general" => Ok(ReviewLane::General),
        "security" => Ok(ReviewLane::Security),
        other => bail!("unknown review lane: {other}"),
    }
}

fn transcript_backfill_state_label(state: TranscriptBackfillState) -> &'static str {
    match state {
        TranscriptBackfillState::NotRequested => "not_requested",
        TranscriptBackfillState::InProgress => "in_progress",
        TranscriptBackfillState::Complete => "complete",
        TranscriptBackfillState::Failed => "failed",
    }
}

fn parse_transcript_backfill_state(value: &str) -> Result<TranscriptBackfillState> {
    match value {
        "not_requested" => Ok(TranscriptBackfillState::NotRequested),
        "in_progress" => Ok(TranscriptBackfillState::InProgress),
        "complete" => Ok(TranscriptBackfillState::Complete),
        "failed" => Ok(TranscriptBackfillState::Failed),
        other => bail!("unknown transcript_backfill state: {other}"),
    }
}

fn map_run_history_row(row: sqlx::sqlite::SqliteRow) -> Result<RunHistoryRecord> {
    let iid_raw: i64 = row.try_get("iid").context("read run history iid")?;
    let trigger_note_id_raw: Option<i64> = row
        .try_get("trigger_note_id")
        .context("read run history trigger note id")?;
    let feature_flags_json: String = row
        .try_get("feature_flags_json")
        .context("read run history feature_flags_json")?;
    Ok(RunHistoryRecord {
        id: row.try_get("id").context("read run history id")?,
        kind: parse_run_history_kind(
            row.try_get::<String, _>("kind")
                .context("read run history kind")?
                .as_str(),
        )?,
        repo: row.try_get("repo").context("read run history repo")?,
        iid: u64::try_from(iid_raw).context("convert run history iid to u64")?,
        head_sha: row
            .try_get("head_sha")
            .context("read run history head sha")?,
        status: row.try_get("status").context("read run history status")?,
        result: row.try_get("result").context("read run history result")?,
        started_at: row
            .try_get("started_at")
            .context("read run history started_at")?,
        finished_at: row
            .try_get("finished_at")
            .context("read run history finished_at")?,
        updated_at: row
            .try_get("updated_at")
            .context("read run history updated_at")?,
        thread_id: row
            .try_get("thread_id")
            .context("read run history thread_id")?,
        turn_id: row.try_get("turn_id").context("read run history turn_id")?,
        review_thread_id: row
            .try_get("review_thread_id")
            .context("read run history review_thread_id")?,
        security_context_source_run_id: row
            .try_get("security_context_source_run_id")
            .context("read run history security_context_source_run_id")?,
        preview: row.try_get("preview").context("read run history preview")?,
        summary: row.try_get("summary").context("read run history summary")?,
        error: row.try_get("error").context("read run history error")?,
        auth_account_name: row
            .try_get("auth_account_name")
            .context("read run history auth account")?,
        discussion_id: row
            .try_get("discussion_id")
            .context("read run history discussion id")?,
        trigger_note_id: trigger_note_id_raw
            .map(|value| u64::try_from(value).context("convert trigger_note_id to u64"))
            .transpose()?,
        trigger_note_author_name: row
            .try_get("trigger_note_author_name")
            .context("read run history trigger note author")?,
        trigger_note_body: row
            .try_get("trigger_note_body")
            .context("read run history trigger note body")?,
        command_repo: row
            .try_get("command_repo")
            .context("read run history command repo")?,
        commit_sha: row
            .try_get("commit_sha")
            .context("read run history commit sha")?,
        feature_flags: serde_json::from_str(&feature_flags_json)
            .context("deserialize run history feature flag snapshot")?,
        events_persisted_cleanly: row
            .try_get::<i64, _>("events_persisted_cleanly")
            .context("read run history events_persisted_cleanly")?
            != 0,
        transcript_backfill_state: parse_transcript_backfill_state(
            row.try_get::<String, _>("transcript_backfill_state")
                .context("read run history transcript_backfill_state")?
                .as_str(),
        )?,
        transcript_backfill_error: row
            .try_get("transcript_backfill_error")
            .context("read run history transcript_backfill_error")?,
    })
}

fn map_run_history_event_row(row: sqlx::sqlite::SqliteRow) -> Result<RunHistoryEventRecord> {
    let payload_json: String = row
        .try_get("payload_json")
        .context("read run history event payload_json")?;
    Ok(RunHistoryEventRecord {
        id: row.try_get("id").context("read run history event id")?,
        run_history_id: row
            .try_get("run_history_id")
            .context("read run history event run_history_id")?,
        sequence: row
            .try_get("sequence")
            .context("read run history event sequence")?,
        turn_id: row
            .try_get("turn_id")
            .context("read run history event turn_id")?,
        event_type: row
            .try_get("event_type")
            .context("read run history event event_type")?,
        payload: serde_json::from_str(&payload_json)
            .context("deserialize run history event payload_json")?,
        created_at: row
            .try_get("created_at")
            .context("read run history event created_at")?,
    })
}

fn map_run_history_list_item_row(row: sqlx::sqlite::SqliteRow) -> Result<RunHistoryListItem> {
    let iid_raw: i64 = row.try_get("iid").context("read run history list iid")?;
    Ok(RunHistoryListItem {
        id: row.try_get("id").context("read run history list id")?,
        kind: parse_run_history_kind(
            row.try_get::<String, _>("kind")
                .context("read run history list kind")?
                .as_str(),
        )?,
        repo: row.try_get("repo").context("read run history list repo")?,
        iid: u64::try_from(iid_raw).context("convert run history list iid to u64")?,
        status: row
            .try_get("status")
            .context("read run history list status")?,
        result: row
            .try_get("result")
            .context("read run history list result")?,
        started_at: row
            .try_get("started_at")
            .context("read run history list started_at")?,
        preview: row
            .try_get("preview")
            .context("read run history list preview")?,
        summary: row
            .try_get("summary")
            .context("read run history list summary")?,
    })
}

fn map_security_review_context_cache_entry(
    row: sqlx::sqlite::SqliteRow,
) -> Result<SecurityReviewContextCacheEntry> {
    Ok(SecurityReviewContextCacheEntry {
        repo: row
            .try_get("repo")
            .context("read security review cache repo")?,
        base_branch: row
            .try_get("base_branch")
            .context("read security review cache base_branch")?,
        base_head_sha: row
            .try_get("base_head_sha")
            .context("read security review cache base_head_sha")?,
        prompt_version: row
            .try_get("prompt_version")
            .context("read security review cache prompt_version")?,
        payload_json: row
            .try_get("payload_json")
            .context("read security review cache payload_json")?,
        source_run_history_id: row
            .try_get("source_run_history_id")
            .context("read security review cache source_run_history_id")?,
        generated_at: row
            .try_get("generated_at")
            .context("read security review cache generated_at")?,
        expires_at: row
            .try_get("expires_at")
            .context("read security review cache expires_at")?,
    })
}

fn sqlite_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else if path.starts_with('/') {
        format!("sqlite:///{}", path.trim_start_matches('/'))
    } else {
        format!("sqlite://{}", path)
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

pub(crate) fn merge_rewritten_turn_events(
    existing_events: Vec<RunHistoryEventRecord>,
    turn_id: &str,
    rewritten_events: &[NewRunHistoryEvent],
) -> Result<Vec<NewRunHistoryEvent>> {
    let mut existing_events = existing_events;
    existing_events.sort_by_key(|event| (event.sequence, event.id));

    let target_sequences = existing_events
        .iter()
        .filter(|event| event.turn_id.as_deref() == Some(turn_id))
        .map(|event| event.sequence)
        .collect::<Vec<_>>();

    let first_target_sequence = target_sequences.first().copied().unwrap_or_else(|| {
        existing_events
            .last()
            .map(|event| event.sequence + 1)
            .unwrap_or(1)
    });
    let last_target_sequence = target_sequences
        .last()
        .copied()
        .unwrap_or(first_target_sequence - 1);
    let delta = rewritten_events.len() as i64 - target_sequences.len() as i64;

    let mut merged_events = Vec::new();
    for event in existing_events {
        if event.turn_id.as_deref() == Some(turn_id) {
            continue;
        }
        let shifted_sequence = if event.sequence > last_target_sequence {
            event.sequence + delta
        } else {
            event.sequence
        };
        merged_events.push(NewRunHistoryEvent {
            sequence: shifted_sequence,
            turn_id: event.turn_id,
            event_type: event.event_type,
            payload: event.payload,
        });
    }

    merged_events.extend(rewritten_events.iter().map(|event| NewRunHistoryEvent {
        sequence: first_target_sequence + event.sequence - 1,
        turn_id: event.turn_id.clone(),
        event_type: event.event_type.clone(),
        payload: event.payload.clone(),
    }));

    merged_events.sort_by_key(|event| event.sequence);
    for (index, event) in merged_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).context("convert merged event index")?;
    }
    Ok(merged_events)
}

#[cfg(test)]
mod tests;

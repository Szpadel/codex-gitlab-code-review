use crate::feature_flags::{FeatureFlagSnapshot, RuntimeFeatureFlagOverrides};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool, sqlite::SqlitePoolOptions};
use std::fs::{self, OpenOptions};
use std::path::Path;
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

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunHistoryListQuery {
    pub repo: Option<String>,
    pub iid: Option<u64>,
    pub kind: Option<RunHistoryKind>,
    pub result: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
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
    pub repo: String,
    pub iid: u64,
    pub head_sha: String,
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
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect(&url)
            .await
            .with_context(|| format!("connect sqlite database at {}", path))?;
        sqlx::migrate!()
            .run(&pool)
            .await
            .context("run sqlite migrations")?;
        Ok(Self { pool })
    }

    pub async fn begin_review(&self, repo: &str, iid: u64, sha: &str) -> Result<bool> {
        let now = Utc::now().timestamp();
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
        let row = sqlx::query("SELECT status FROM review_state WHERE repo = ? AND iid = ?")
            .bind(repo)
            .bind(iid as i64)
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
            INSERT INTO review_state (repo, iid, head_sha, status, started_at, updated_at)
            VALUES (?, ?, ?, 'in_progress', ?, ?)
            ON CONFLICT(repo, iid) DO UPDATE SET
                head_sha = excluded.head_sha,
                status = 'in_progress',
                started_at = excluded.started_at,
                updated_at = excluded.updated_at,
                result = NULL
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
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
        let now = Utc::now().timestamp();
        sqlx::query(
            r#"
            UPDATE review_state
            SET status = 'done', head_sha = ?, result = ?, updated_at = ?
            WHERE repo = ? AND iid = ? AND head_sha = ? AND status = 'in_progress'
            "#,
        )
        .bind(sha)
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .bind(sha)
        .execute(&self.pool)
        .await
        .context("update review state")?;
        Ok(())
    }

    pub async fn list_in_progress_reviews(&self) -> Result<Vec<InProgressReview>> {
        let rows = sqlx::query(
            r#"
            SELECT repo, iid, head_sha
            FROM review_state
            WHERE status = 'in_progress'
            ORDER BY repo, iid
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
                let head_sha: String = row.try_get("head_sha").context("read review head sha")?;
                Ok(InProgressReview {
                    repo,
                    iid,
                    head_sha,
                })
            })
            .collect()
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

    pub async fn start_run_history(&self, new_run: NewRunHistory) -> Result<i64> {
        let now = Utc::now().timestamp();
        let result = sqlx::query(
            r#"
            INSERT INTO run_history (
                kind,
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
            VALUES (?, ?, ?, ?, 'in_progress', ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(run_history_kind_label(new_run.kind))
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
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(update.thread_id)
        .bind(update.turn_id)
        .bind(update.review_thread_id)
        .bind(update.auth_account_name)
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
            SELECT id, kind, repo, iid, head_sha, status, result, started_at, finished_at, updated_at,
                   thread_id, turn_id, review_thread_id, preview, summary, error, auth_account_name,
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
            SELECT id, kind, repo, iid, head_sha, status, result, started_at, finished_at, updated_at,
                   thread_id, turn_id, review_thread_id, preview, summary, error, auth_account_name,
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
    ) -> Result<Vec<RunHistoryRecord>> {
        let mut builder = QueryBuilder::<Sqlite>::new(
            r#"
            SELECT id, kind, repo, iid, head_sha, status, result, started_at, finished_at, updated_at,
                   thread_id, turn_id, review_thread_id, preview, summary, error, auth_account_name,
                   discussion_id, trigger_note_id, trigger_note_author_name, trigger_note_body,
                   command_repo, commit_sha, feature_flags_json, events_persisted_cleanly,
                   transcript_backfill_state, transcript_backfill_error
            FROM run_history
            "#,
        );

        let mut has_where = false;
        let mut push_where = |builder: &mut QueryBuilder<Sqlite>| {
            if !has_where {
                builder.push(" WHERE ");
                has_where = true;
            } else {
                builder.push(" AND ");
            }
        };

        if let Some(repo) = query.repo.as_deref() {
            push_where(&mut builder);
            builder.push("repo = ").push_bind(repo);
        }
        if let Some(iid) = query.iid {
            push_where(&mut builder);
            builder.push("iid = ").push_bind(iid as i64);
        }
        if let Some(kind) = query.kind {
            push_where(&mut builder);
            builder
                .push("kind = ")
                .push_bind(run_history_kind_label(kind));
        }
        if let Some(result) = query.result.as_deref() {
            push_where(&mut builder);
            builder.push("result = ").push_bind(result);
        }
        if let Some(search) = query
            .search
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let pattern = format!("%{search}%");
            push_where(&mut builder);
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

        let limit = if query.limit == 0 {
            50
        } else {
            query.limit.min(500)
        };
        builder
            .push(" ORDER BY started_at DESC, id DESC LIMIT ")
            .push_bind(limit as i64);

        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .context("list run history")?;
        rows.into_iter().map(map_run_history_row).collect()
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
        RunHistoryKind::Mention => "mention",
    }
}

fn parse_run_history_kind(value: &str) -> Result<RunHistoryKind> {
    match value {
        "review" => Ok(RunHistoryKind::Review),
        "mention" => Ok(RunHistoryKind::Mention),
        other => bail!("unknown run_history kind: {other}"),
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

fn sqlite_url(path: &str) -> String {
    if path == ":memory:" {
        "sqlite::memory:".to_string()
    } else if path.starts_with('/') {
        format!("sqlite:///{}", path.trim_start_matches('/'))
    } else {
        format!("sqlite://{}", path)
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
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::env;
    use std::fs;
    use uuid::Uuid;

    #[tokio::test]
    async fn begin_review_locks_in_progress() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let first = store.begin_review("group/repo", 1, "sha1").await?;
        let second = store.begin_review("group/repo", 1, "sha1").await?;
        assert_eq!(first, true);
        assert_eq!(second, false);

        store.finish_review("group/repo", 1, "sha1", "pass").await?;
        let third = store.begin_review("group/repo", 1, "sha2").await?;
        assert_eq!(third, true);
        Ok(())
    }

    #[tokio::test]
    async fn clear_stale_releases_lock() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store.begin_review("group/repo", 2, "sha1").await?;

        sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(2i64)
            .execute(store.pool())
            .await?;

        store.clear_stale_in_progress(1).await?;
        let again = store.begin_review("group/repo", 2, "sha2").await?;
        assert_eq!(again, true);
        Ok(())
    }

    #[tokio::test]
    async fn clear_stale_mentions_mark_error_and_block_replay() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";
        let iid = 11u64;
        let discussion_id = "discussion-1";
        let trigger_note_id = 22u64;
        store
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
            .await?;

        sqlx::query(
            r#"
            UPDATE mention_command_state
            SET updated_at = 0
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .execute(store.pool())
        .await?;

        store.clear_stale_in_progress_mentions(1).await?;
        let again = store
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
            .await?;

        assert_eq!(again, false);
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
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done".to_string());
        assert_eq!(result, Some("error".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn list_in_progress_reviews_returns_only_active_rows() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store.begin_review("group/repo-a", 1, "sha1").await?;
        store.begin_review("group/repo-b", 2, "sha2").await?;
        store
            .finish_review("group/repo-b", 2, "sha2", "pass")
            .await?;

        let in_progress = store.list_in_progress_reviews().await?;
        assert_eq!(
            in_progress,
            vec![InProgressReview {
                repo: "group/repo-a".to_string(),
                iid: 1,
                head_sha: "sha1".to_string(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn finish_review_is_noop_once_row_is_not_in_progress() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store.begin_review("group/repo", 3, "sha1").await?;

        store.finish_review("group/repo", 3, "sha1", "pass").await?;
        store
            .finish_review("group/repo", 3, "sha2", "error")
            .await?;

        let row = sqlx::query(
            "SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?",
        )
        .bind("group/repo")
        .bind(3i64)
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let head_sha: String = row.try_get("head_sha")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done".to_string());
        assert_eq!(head_sha, "sha1".to_string());
        assert_eq!(result, Some("pass".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn finish_review_ignores_outdated_sha_for_new_in_progress_review() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";
        let iid = 4u64;
        store.begin_review(repo, iid, "sha1").await?;

        sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
            .bind(repo)
            .bind(iid as i64)
            .execute(store.pool())
            .await?;
        store.clear_stale_in_progress(1).await?;

        let restarted = store.begin_review(repo, iid, "sha2").await?;
        assert_eq!(restarted, true);

        store.finish_review(repo, iid, "sha1", "error").await?;
        let row = sqlx::query(
            "SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?",
        )
        .bind(repo)
        .bind(iid as i64)
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let head_sha: String = row.try_get("head_sha")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "in_progress".to_string());
        assert_eq!(head_sha, "sha2".to_string());
        assert_eq!(result, None);

        store.finish_review(repo, iid, "sha2", "pass").await?;
        let row = sqlx::query(
            "SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?",
        )
        .bind(repo)
        .bind(iid as i64)
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let head_sha: String = row.try_get("head_sha")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done".to_string());
        assert_eq!(head_sha, "sha2".to_string());
        assert_eq!(result, Some("pass".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn begin_mention_command_is_idempotent() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";
        let iid = 11u64;
        let discussion_id = "discussion-1";
        let trigger_note_id = 22u64;

        let first = store
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
            .await?;
        let second = store
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
            .await?;
        assert_eq!(first, true);
        assert_eq!(second, false);

        let row = sqlx::query(
            r#"
            SELECT status, head_sha, result
            FROM mention_command_state
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let head_sha: String = row.try_get("head_sha")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "in_progress".to_string());
        assert_eq!(head_sha, "sha1".to_string());
        assert_eq!(result, None);
        Ok(())
    }

    #[tokio::test]
    async fn begin_mention_command_retries_after_cancelled_but_not_error() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";
        let iid = 12u64;
        let discussion_id = "discussion-2";
        let trigger_note_id = 23u64;

        assert!(
            store
                .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
                .await?
        );
        store
            .finish_mention_command(
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                "sha1",
                "cancelled",
            )
            .await?;
        assert!(
            store
                .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
                .await?
        );

        store
            .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2", "error")
            .await?;
        assert!(
            !store
                .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha3")
                .await?
        );

        let row = sqlx::query(
            r#"
            SELECT status, head_sha, result
            FROM mention_command_state
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            "#,
        )
        .bind(repo)
        .bind(iid as i64)
        .bind(discussion_id)
        .bind(trigger_note_id as i64)
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let head_sha: String = row.try_get("head_sha")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done".to_string());
        assert_eq!(head_sha, "sha2".to_string());
        assert_eq!(result, Some("error".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn finish_mention_command_transitions_only_in_progress_rows() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";
        let iid = 13u64;
        let discussion_id = "discussion-3";
        let trigger_note_id = 24u64;

        let started = store
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
            .await?;
        assert_eq!(started, true);

        store
            .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1", "pass")
            .await?;
        store
            .finish_mention_command(
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                "sha1",
                "overwritten",
            )
            .await?;

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
        .fetch_one(store.pool())
        .await?;
        let status: String = row.try_get("status")?;
        let result: Option<String> = row.try_get("result")?;
        assert_eq!(status, "done".to_string());
        assert_eq!(result, Some("pass".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn list_in_progress_mention_commands_returns_only_active_rows() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        store
            .begin_mention_command("group/repo-a", 1, "discussion-a", 101, "sha-a")
            .await?;
        store
            .begin_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b")
            .await?;
        store
            .finish_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b", "pass")
            .await?;

        let in_progress = store.list_in_progress_mention_commands().await?;
        assert_eq!(
            in_progress,
            vec![InProgressMentionCommand {
                key: MentionCommandStateKey {
                    repo: "group/repo-a".to_string(),
                    iid: 1,
                    discussion_id: "discussion-a".to_string(),
                    trigger_note_id: 101,
                },
                head_sha: "sha-a".to_string(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn creates_database_file_when_missing() -> Result<()> {
        let base = env::temp_dir().join(format!("codex-review-db-{}", Uuid::new_v4()));
        let path = base.join("nested").join("state.sqlite");
        if base.exists() {
            fs::remove_dir_all(&base).ok();
        }

        let store = ReviewStateStore::new(path.to_str().unwrap()).await?;
        assert!(path.exists());
        drop(store);
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[tokio::test]
    async fn fails_when_database_path_is_directory() -> Result<()> {
        let base = env::temp_dir().join(format!("codex-review-db-{}", Uuid::new_v4()));
        fs::create_dir_all(&base)?;
        let err = match ReviewStateStore::new(base.to_str().unwrap()).await {
            Ok(_) => panic!("expected error for database path that is a directory"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("database path is a directory"));
        assert!(msg.contains(base.to_str().unwrap()));
        let _ = fs::remove_dir_all(&base);
        Ok(())
    }

    #[tokio::test]
    async fn project_last_activity_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let repo = "group/repo";

        let missing = store.get_project_last_mr_activity(repo).await?;
        assert_eq!(missing, None);

        store
            .set_project_last_mr_activity(repo, "2025-01-01T00:00:00Z")
            .await?;
        let loaded = store.get_project_last_mr_activity(repo).await?;
        assert_eq!(loaded, Some("2025-01-01T00:00:00Z".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn project_catalog_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let key = "mode=all;repos=;groups=";
        let projects = vec!["group/repo".to_string(), "group/other".to_string()];

        let missing = store.load_project_catalog(key).await?;
        assert!(missing.is_none());

        store.save_project_catalog(key, &projects).await?;
        let loaded = store.load_project_catalog(key).await?.expect("catalog");
        assert_eq!(loaded.projects, projects);
        assert!(loaded.fetched_at > 0);
        Ok(())
    }

    #[tokio::test]
    async fn created_after_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let missing = store.get_created_after().await?;
        assert_eq!(missing, None);

        store.set_created_after("2025-01-02T03:04:05Z").await?;
        let loaded = store.get_created_after().await?;
        assert_eq!(loaded, Some("2025-01-02T03:04:05Z".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn review_owner_id_is_created_once_and_stable_across_calls() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let first = store.get_or_create_review_owner_id().await?;
        assert!(!first.is_empty());

        let second = store.get_or_create_review_owner_id().await?;
        assert_eq!(second, first);
        Ok(())
    }

    #[tokio::test]
    async fn auth_limit_reset_roundtrip_and_clear() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let account = "backup-1";

        let missing = store.get_auth_limit_reset_at(account).await?;
        assert_eq!(missing, None);

        store
            .set_auth_limit_reset_at(account, "2026-03-02T10:15:00Z")
            .await?;
        let loaded = store.get_auth_limit_reset_at(account).await?;
        assert_eq!(loaded, Some("2026-03-02T10:15:00Z".to_string()));

        store.clear_auth_limit_reset_at(account).await?;
        let cleared = store.get_auth_limit_reset_at(account).await?;
        assert_eq!(cleared, None);
        Ok(())
    }

    #[tokio::test]
    async fn auth_limit_reset_tracks_accounts_independently() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store
            .set_auth_limit_reset_at("primary", "2026-03-02T10:15:00Z")
            .await?;
        store
            .set_auth_limit_reset_at("backup-1", "2026-03-02T12:00:00Z")
            .await?;

        let primary = store.get_auth_limit_reset_at("primary").await?;
        let backup = store.get_auth_limit_reset_at("backup-1").await?;
        assert_eq!(primary, Some("2026-03-02T10:15:00Z".to_string()));
        assert_eq!(backup, Some("2026-03-02T12:00:00Z".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn auth_limit_reset_keeps_latest_timestamp_for_account() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let account = "backup-1";

        store
            .set_auth_limit_reset_at(account, "2026-03-02T12:00:00Z")
            .await?;
        store
            .set_auth_limit_reset_at(account, "2026-03-02T10:00:00Z")
            .await?;
        let after_older_write = store.get_auth_limit_reset_at(account).await?;
        assert_eq!(after_older_write, Some("2026-03-02T12:00:00Z".to_string()));

        store
            .set_auth_limit_reset_at(account, "2026-03-02T13:30:00Z")
            .await?;
        let after_newer_write = store.get_auth_limit_reset_at(account).await?;
        assert_eq!(after_newer_write, Some("2026-03-02T13:30:00Z".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn scan_status_roundtrip_and_clear_next_scan() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let initial = store.get_scan_status().await?;
        assert_eq!(initial.state, ScanState::Idle);
        assert_eq!(initial.mode, None);
        assert_eq!(initial.started_at, None);
        assert_eq!(initial.finished_at, None);
        assert_eq!(initial.outcome, None);
        assert_eq!(initial.error, None);
        assert_eq!(initial.next_scan_at, None);

        store
            .set_scan_status(&PersistedScanStatus {
                state: ScanState::Scanning,
                mode: Some(ScanMode::Full),
                started_at: Some("2026-03-10T10:00:00Z".to_string()),
                finished_at: None,
                outcome: None,
                error: None,
                next_scan_at: Some("2026-03-10T10:10:00Z".to_string()),
            })
            .await?;

        let running = store.get_scan_status().await?;
        assert_eq!(running.state, ScanState::Scanning);
        assert_eq!(running.mode, Some(ScanMode::Full));
        assert_eq!(running.started_at, Some("2026-03-10T10:00:00Z".to_string()));
        assert_eq!(running.finished_at, None);
        assert_eq!(running.outcome, None);
        assert_eq!(running.error, None);
        assert_eq!(
            running.next_scan_at,
            Some("2026-03-10T10:10:00Z".to_string())
        );

        store.clear_next_scan_at().await?;
        let cleared = store.get_scan_status().await?;
        assert_eq!(cleared.next_scan_at, None);
        Ok(())
    }

    #[tokio::test]
    async fn auth_limit_reset_listing_returns_sorted_accounts() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store
            .set_auth_limit_reset_at("backup-2", "2026-03-10T12:30:00Z")
            .await?;
        store
            .set_auth_limit_reset_at("primary", "2026-03-10T11:00:00Z")
            .await?;

        let entries = store.list_auth_limit_reset_entries().await?;
        assert_eq!(
            entries,
            vec![
                AuthLimitResetEntry {
                    account_name: "backup-2".to_string(),
                    reset_at: "2026-03-10T12:30:00Z".to_string(),
                },
                AuthLimitResetEntry {
                    account_name: "primary".to_string(),
                    reset_at: "2026-03-10T11:00:00Z".to_string(),
                },
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn project_catalog_summary_lists_project_counts() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store
            .save_project_catalog(
                "all",
                &[
                    "group/a".to_string(),
                    "group/b".to_string(),
                    "group/c".to_string(),
                ],
            )
            .await?;

        let summaries = store.list_project_catalog_summaries().await?;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].cache_key, "all".to_string());
        assert_eq!(summaries[0].project_count, 3);
        assert!(summaries[0].fetched_at > 0);
        Ok(())
    }

    #[tokio::test]
    async fn project_catalog_summary_falls_back_for_legacy_rows_without_count() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        sqlx::query(
            r#"
            INSERT INTO project_catalog (cache_key, fetched_at, projects, project_count)
            VALUES (?, ?, ?, NULL)
            "#,
        )
        .bind("legacy")
        .bind(123i64)
        .bind("[\"group/a\",\"group/b\"]")
        .execute(store.pool())
        .await?;

        let summaries = store.list_project_catalog_summaries().await?;
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].cache_key, "legacy".to_string());
        assert_eq!(summaries[0].project_count, 2);
        Ok(())
    }

    #[tokio::test]
    async fn run_history_is_append_only_for_same_mr() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let first_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 42,
                head_sha: "sha1".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                first_id,
                RunHistoryFinish {
                    result: "comment".to_string(),
                    thread_id: Some("thread-1".to_string()),
                    turn_id: Some("turn-1".to_string()),
                    review_thread_id: Some("thread-1".to_string()),
                    preview: Some("Review group/repo !42".to_string()),
                    summary: Some("needs fixes".to_string()),
                    error: None,
                    auth_account_name: Some("primary".to_string()),
                    commit_sha: None,
                },
            )
            .await?;

        let second_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 42,
                head_sha: "sha2".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;

        assert_ne!(first_id, second_id);

        let records = store.list_run_history_for_mr("group/repo", 42).await?;
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].id, second_id);
        assert_eq!(records[0].head_sha, "sha2".to_string());
        assert_eq!(records[1].id, first_id);
        assert_eq!(records[1].result.as_deref(), Some("comment"));
        Ok(())
    }

    #[tokio::test]
    async fn run_history_preserves_mention_trigger_metadata() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Mention,
                repo: "group/repo".to_string(),
                iid: 7,
                head_sha: "sha-mention".to_string(),
                discussion_id: Some("discussion-9".to_string()),
                trigger_note_id: Some(123),
                trigger_note_author_name: Some("Reviewer".to_string()),
                trigger_note_body: Some("@codex please rename this".to_string()),
                command_repo: Some("fork/repo".to_string()),
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "committed".to_string(),
                    thread_id: Some("thread-mention".to_string()),
                    turn_id: Some("turn-mention".to_string()),
                    review_thread_id: None,
                    preview: Some("note:123 author:reviewer".to_string()),
                    summary: Some("renamed method".to_string()),
                    error: None,
                    auth_account_name: Some("backup".to_string()),
                    commit_sha: Some("abc1234".to_string()),
                },
            )
            .await?;

        let record = store
            .get_run_history(run_id)
            .await?
            .expect("run history record should exist");
        assert_eq!(record.kind, RunHistoryKind::Mention);
        assert_eq!(record.discussion_id.as_deref(), Some("discussion-9"));
        assert_eq!(record.trigger_note_id, Some(123));
        assert_eq!(record.trigger_note_author_name.as_deref(), Some("Reviewer"));
        assert_eq!(
            record.trigger_note_body.as_deref(),
            Some("@codex please rename this")
        );
        assert_eq!(record.command_repo.as_deref(), Some("fork/repo"));
        assert_eq!(record.commit_sha.as_deref(), Some("abc1234"));
        assert_eq!(record.feature_flags, FeatureFlagSnapshot::default());
        Ok(())
    }

    #[tokio::test]
    async fn runtime_feature_flag_overrides_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        assert_eq!(
            store.get_runtime_feature_flag_overrides().await?,
            RuntimeFeatureFlagOverrides::default()
        );

        let overrides = RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
        };
        store.set_runtime_feature_flag_overrides(&overrides).await?;

        assert_eq!(store.get_runtime_feature_flag_overrides().await?, overrides);
        Ok(())
    }

    #[tokio::test]
    async fn run_history_feature_flags_snapshot_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 13,
                head_sha: "sha-flags".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;

        let feature_flags = FeatureFlagSnapshot {
            gitlab_discovery_mcp: true,
        };
        store
            .set_run_history_feature_flags(run_id, &feature_flags)
            .await?;

        let record = store
            .get_run_history(run_id)
            .await?
            .context("run history row should exist")?;
        assert_eq!(record.feature_flags, feature_flags);
        Ok(())
    }

    #[tokio::test]
    async fn run_history_filters_by_mr() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let first = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 11,
                head_sha: "sha-a".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        let _other = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/other".to_string(),
                iid: 11,
                head_sha: "sha-b".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                first,
                RunHistoryFinish {
                    result: "pass".to_string(),
                    thread_id: Some("thread-a".to_string()),
                    turn_id: Some("turn-a".to_string()),
                    review_thread_id: Some("thread-a".to_string()),
                    preview: Some("Review group/repo !11".to_string()),
                    summary: Some("looks good".to_string()),
                    error: None,
                    auth_account_name: Some("primary".to_string()),
                    commit_sha: None,
                },
            )
            .await?;

        let records = store.list_run_history_for_mr("group/repo", 11).await?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].repo, "group/repo".to_string());
        assert_eq!(records[0].iid, 11);
        Ok(())
    }

    #[tokio::test]
    async fn reconcile_interrupted_run_history_marks_in_progress_rows_cancelled() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let interrupted_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Mention,
                repo: "group/repo".to_string(),
                iid: 12,
                head_sha: "sha-interrupted".to_string(),
                discussion_id: Some("discussion-1".to_string()),
                trigger_note_id: Some(9),
                trigger_note_author_name: Some("reviewer".to_string()),
                trigger_note_body: Some("@codex fix this".to_string()),
                command_repo: Some("group/repo".to_string()),
            })
            .await?;
        let finished_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 12,
                head_sha: "sha-finished".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                finished_id,
                RunHistoryFinish {
                    result: "pass".to_string(),
                    preview: Some("Review group/repo !12".to_string()),
                    summary: Some("looks good".to_string()),
                    ..Default::default()
                },
            )
            .await?;

        let affected = store
            .reconcile_interrupted_run_history("run interrupted by service restart")
            .await?;
        assert_eq!(affected, 1);

        let interrupted = store
            .get_run_history(interrupted_id)
            .await?
            .expect("interrupted run should exist");
        assert_eq!(interrupted.status, "done".to_string());
        assert_eq!(interrupted.result.as_deref(), Some("cancelled"));
        assert_eq!(
            interrupted.error.as_deref(),
            Some("run interrupted by service restart")
        );
        assert!(interrupted.finished_at.is_some());

        let finished = store
            .get_run_history(finished_id)
            .await?
            .expect("finished run should exist");
        assert_eq!(finished.result.as_deref(), Some("pass"));
        Ok(())
    }

    #[tokio::test]
    async fn run_history_events_roundtrip_in_sequence_order() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 99,
                head_sha: "sha-seq".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-1".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: serde_json::json!({"type": "agentMessage", "text": "done"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-1".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    },
                ],
            )
            .await?;

        let events = store.list_run_history_events(run_id).await?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].event_type, "turn_started");
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[1].event_type, "item_completed");
        assert_eq!(events[1].payload["text"], "done");
        Ok(())
    }

    #[tokio::test]
    async fn run_history_events_offset_sequence_across_append_batches() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 100,
                head_sha: "sha-batches".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({}),
                }],
            )
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"status": "completed"}),
                    },
                ],
            )
            .await?;

        let events = store.list_run_history_events(run_id).await?;
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[1].turn_id.as_deref(), Some("turn-b"));
        assert_eq!(events[2].sequence, 3);
        assert_eq!(events[2].turn_id.as_deref(), Some("turn-b"));
        Ok(())
    }

    #[tokio::test]
    async fn mark_run_history_events_incomplete_updates_flag() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 101,
                head_sha: "sha-flag".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    ..Default::default()
                },
            )
            .await?;
        assert!(
            store
                .get_run_history(run_id)
                .await?
                .context("run history row")?
                .events_persisted_cleanly
        );

        store.mark_run_history_events_incomplete(run_id).await?;

        assert!(
            !store
                .get_run_history(run_id)
                .await?
                .context("run history row after mark")?
                .events_persisted_cleanly
        );
        Ok(())
    }

    #[tokio::test]
    async fn transcript_backfill_state_and_event_rewrite_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 102,
                head_sha: "sha-backfill".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    ..Default::default()
                },
            )
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: serde_json::json!({
                            "type": "reasoning",
                            "summary": [],
                            "content": []
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"status": "completed"}),
                    },
                ],
            )
            .await?;

        store
            .update_run_history_transcript_backfill(
                run_id,
                TranscriptBackfillState::InProgress,
                None,
            )
            .await?;
        let in_progress = store
            .get_run_history(run_id)
            .await?
            .context("run history row after in-progress update")?;
        assert_eq!(
            in_progress.transcript_backfill_state,
            TranscriptBackfillState::InProgress
        );
        assert_eq!(in_progress.transcript_backfill_error, None);

        store
            .replace_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: serde_json::json!({
                            "type": "reasoning",
                            "summary": [{"type": "summary_text", "text": "Recovered summary"}],
                            "content": [{"type": "reasoning_text", "text": "Recovered detail"}]
                        }),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"status": "completed"}),
                    },
                ],
            )
            .await?;
        store
            .mark_run_history_transcript_backfill_complete(run_id)
            .await?;

        let run = store
            .get_run_history(run_id)
            .await?
            .context("run history row after rewrite")?;
        assert_eq!(
            run.transcript_backfill_state,
            TranscriptBackfillState::Complete
        );
        assert_eq!(run.transcript_backfill_error, None);
        assert!(run.events_persisted_cleanly);

        let events = store.list_run_history_events(run_id).await?;
        assert_eq!(events.len(), 3);
        assert_eq!(
            events[1].payload["summary"][0]["text"],
            serde_json::json!("Recovered summary")
        );
        assert_eq!(
            events[1].payload["content"][0]["text"],
            serde_json::json!("Recovered detail")
        );
        Ok(())
    }

    #[tokio::test]
    async fn replace_run_history_events_for_turn_preserves_other_turns() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 103,
                head_sha: "sha-turn-rewrite".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    ..Default::default()
                },
            )
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({"label": "turn-a-start"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-a-end"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({"label": "turn-b-start"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-b-end"}),
                    },
                ],
            )
            .await?;

        store
            .update_run_history_transcript_backfill(
                run_id,
                TranscriptBackfillState::InProgress,
                None,
            )
            .await?;
        store
            .replace_run_history_events_for_turn(
                run_id,
                "turn-b",
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({"label": "turn-b-new-start"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "item_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-b-item"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-b-new-end"}),
                    },
                ],
            )
            .await?;

        let events = store.list_run_history_events(run_id).await?;
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(events[0].payload["label"], "turn-a-start");
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[1].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(events[1].payload["label"], "turn-a-end");
        assert_eq!(events[2].sequence, 3);
        assert_eq!(events[2].turn_id.as_deref(), Some("turn-b"));
        assert_eq!(events[2].payload["label"], "turn-b-new-start");
        assert_eq!(events[3].sequence, 4);
        assert_eq!(events[3].turn_id.as_deref(), Some("turn-b"));
        assert_eq!(events[3].payload["label"], "turn-b-item");
        assert_eq!(events[4].sequence, 5);
        assert_eq!(events[4].turn_id.as_deref(), Some("turn-b"));
        assert_eq!(events[4].payload["label"], "turn-b-new-end");
        Ok(())
    }

    #[tokio::test]
    async fn replace_run_history_events_for_turn_removes_turn_when_rewritten_empty() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 104,
                head_sha: "sha-turn-remove".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    ..Default::default()
                },
            )
            .await?;
        store
            .append_run_history_events(
                run_id,
                &[
                    NewRunHistoryEvent {
                        sequence: 1,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({"label": "turn-a-start"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 2,
                        turn_id: Some("turn-a".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-a-end"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 3,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_started".to_string(),
                        payload: serde_json::json!({"label": "turn-b-start"}),
                    },
                    NewRunHistoryEvent {
                        sequence: 4,
                        turn_id: Some("turn-b".to_string()),
                        event_type: "turn_completed".to_string(),
                        payload: serde_json::json!({"label": "turn-b-end"}),
                    },
                ],
            )
            .await?;

        store
            .replace_run_history_events_for_turn(run_id, "turn-b", &[])
            .await?;

        let events = store.list_run_history_events(run_id).await?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(events[0].payload["label"], "turn-a-start");
        assert_eq!(events[1].sequence, 2);
        assert_eq!(events[1].turn_id.as_deref(), Some("turn-a"));
        assert_eq!(events[1].payload["label"], "turn-a-end");
        Ok(())
    }
}

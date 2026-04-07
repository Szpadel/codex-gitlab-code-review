use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{Row, SqlitePool};

use super::{
    InProgressMentionCommand, MentionCommandScanState, MentionCommandStateKey, sqlite_i64_from_u64,
};

#[derive(Clone)]
pub struct MentionCommandsRepository {
    pool: SqlitePool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn begin_and_finish_mention_command_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        assert!(
            store
                .mention_commands
                .begin_mention_command("group/repo", 12, "discussion-1", 99, "sha-12")
                .await?
        );
        assert_eq!(
            store
                .mention_commands
                .mention_command_scan_state("group/repo", 12, "discussion-1", 99)
                .await?,
            MentionCommandScanState::InProgress
        );
        store
            .mention_commands
            .finish_mention_command("group/repo", 12, "discussion-1", 99, "sha-12", "done")
            .await?;
        assert_eq!(
            store
                .mention_commands
                .mention_command_scan_state("group/repo", 12, "discussion-1", 99)
                .await?,
            MentionCommandScanState::Completed
        );
        Ok(())
    }
}

impl MentionCommandsRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn clear_stale_in_progress_mentions(&self, max_age_minutes: u64) -> Result<()> {
        let cutoff = Utc::now().timestamp()
            - (sqlite_i64_from_u64(max_age_minutes, "max_age_minutes")? * 60);
        let now = Utc::now().timestamp();
        sqlx::query(
            r"
            UPDATE mention_command_state
            SET status = 'done', result = 'error', updated_at = ?
            WHERE status = 'in_progress' AND updated_at < ?
            ",
        )
        .bind(now)
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .context("mark stale mention commands")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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
            r"
            UPDATE mention_command_state
            SET updated_at = ?
            WHERE repo = ?
              AND iid = ?
              AND discussion_id = ?
              AND trigger_note_id = ?
              AND head_sha = ?
              AND status = 'in_progress'
            ",
        )
        .bind(now)
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(discussion_id)
        .bind(sqlite_i64_from_u64(trigger_note_id, "trigger_note_id")?)
        .bind(head_sha)
        .execute(&self.pool)
        .await
        .context("touch in-progress mention command")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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
            r"
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
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(discussion_id)
        .bind(sqlite_i64_from_u64(trigger_note_id, "trigger_note_id")?)
        .bind(head_sha)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .context("insert mention command state")?;
        Ok(result.rows_affected() > 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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
            r"
            UPDATE mention_command_state
            SET status = 'done', result = ?, updated_at = ?
            WHERE repo = ?
              AND iid = ?
              AND discussion_id = ?
              AND trigger_note_id = ?
              AND head_sha = ?
              AND status = 'in_progress'
            ",
        )
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(discussion_id)
        .bind(sqlite_i64_from_u64(trigger_note_id, "trigger_note_id")?)
        .bind(head_sha)
        .execute(&self.pool)
        .await
        .context("update mention command state")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_in_progress_mention_commands(&self) -> Result<Vec<InProgressMentionCommand>> {
        let rows = sqlx::query(
            r"
            SELECT repo, iid, discussion_id, trigger_note_id, head_sha
            FROM mention_command_state
            WHERE status = 'in_progress'
            ORDER BY repo, iid, discussion_id, trigger_note_id
            ",
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
            r"
            SELECT EXISTS(
                SELECT 1
                FROM mention_command_state
                WHERE repo = ? AND iid = ? AND status = 'in_progress'
            )
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .fetch_one(&self.pool)
        .await
        .context("check in-progress mention command")?;
        Ok(exists != 0)
    }

    pub(crate) async fn mention_command_scan_state(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) -> Result<MentionCommandScanState> {
        let row = sqlx::query(
            r"
            SELECT status, result
            FROM mention_command_state
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(discussion_id)
        .bind(sqlite_i64_from_u64(trigger_note_id, "trigger_note_id")?)
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
}

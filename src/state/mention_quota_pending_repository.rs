use crate::state::sqlite_i64_from_u64;
use anyhow::{Context, Result};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionQuotaPendingEntry {
    pub repo: String,
    pub iid: u64,
    pub discussion_id: String,
    pub trigger_note_id: u64,
    pub first_blocked_at: i64,
    pub last_blocked_at: i64,
    pub last_seen_head_sha: String,
    pub next_retry_at: i64,
}

#[derive(Debug, Clone, Copy)]
pub struct MentionQuotaPendingUpsert<'a> {
    pub repo: &'a str,
    pub iid: u64,
    pub discussion_id: &'a str,
    pub trigger_note_id: u64,
    pub head_sha: &'a str,
    pub blocked_at: i64,
    pub next_retry_at: i64,
}

#[derive(Clone)]
pub struct MentionQuotaPendingRepository {
    pool: SqlitePool,
}

impl MentionQuotaPendingRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn upsert_mention_quota_pending(
        &self,
        pending: MentionQuotaPendingUpsert<'_>,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO runtime_mention_quota_pending (
                repo,
                iid,
                discussion_id,
                trigger_note_id,
                first_blocked_at,
                last_blocked_at,
                last_seen_head_sha,
                next_retry_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(repo, iid, discussion_id, trigger_note_id) DO UPDATE SET
                first_blocked_at = MIN(runtime_mention_quota_pending.first_blocked_at, excluded.first_blocked_at),
                last_blocked_at = MAX(runtime_mention_quota_pending.last_blocked_at, excluded.last_blocked_at),
                last_seen_head_sha = excluded.last_seen_head_sha,
                next_retry_at = excluded.next_retry_at
            ",
        )
        .bind(pending.repo)
        .bind(sqlite_i64_from_u64(pending.iid, "iid")?)
        .bind(pending.discussion_id)
        .bind(sqlite_i64_from_u64(
            pending.trigger_note_id,
            "trigger_note_id",
        )?)
        .bind(pending.blocked_at)
        .bind(pending.blocked_at)
        .bind(pending.head_sha)
        .bind(pending.next_retry_at)
        .execute(&self.pool)
        .await
        .context("upsert runtime mention quota pending row")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn clear_mention_quota_pending(
        &self,
        repo: &str,
        iid: u64,
        discussion_id: &str,
        trigger_note_id: u64,
    ) -> Result<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM runtime_mention_quota_pending
            WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(discussion_id)
        .bind(sqlite_i64_from_u64(trigger_note_id, "trigger_note_id")?)
        .execute(&self.pool)
        .await
        .context("clear runtime mention quota pending row")?;
        Ok(result.rows_affected() > 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_mention_quota_pending(&self) -> Result<Vec<MentionQuotaPendingEntry>> {
        let rows = sqlx::query(
            r"
            SELECT repo, iid, discussion_id, trigger_note_id, first_blocked_at, last_blocked_at, last_seen_head_sha, next_retry_at
            FROM runtime_mention_quota_pending
            ORDER BY first_blocked_at ASC, repo ASC, iid ASC, discussion_id ASC, trigger_note_id ASC
            ",
        )
        .fetch_all(&self.pool)
        .await
        .context("list runtime mention quota pending rows")?;

        rows.into_iter()
            .map(|row| map_mention_quota_pending_row(&row))
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn earliest_mention_quota_pending_retry_at(&self) -> Result<Option<i64>> {
        let next_retry_at = sqlx::query_scalar::<_, Option<i64>>(
            r"
            SELECT MIN(next_retry_at)
            FROM runtime_mention_quota_pending
            ",
        )
        .fetch_one(&self.pool)
        .await
        .context("load earliest runtime mention quota pending retry time")?;
        Ok(next_retry_at)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn repo_has_due_mention_quota_pending(&self, repo: &str, now: i64) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r"
            SELECT EXISTS(
                SELECT 1
                FROM runtime_mention_quota_pending
                WHERE repo = ?
                  AND next_retry_at <= ?
            )
            ",
        )
        .bind(repo)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("check due runtime mention quota pending rows")?;
        Ok(exists != 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn sync_mention_quota_pending_rows(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<Vec<MentionQuotaPendingEntry>> {
        let deleted = self
            .list_mention_quota_pending_rows_for_prune(repo, open_iids)
            .await?;
        if deleted.is_empty() {
            return Ok(deleted);
        }

        if open_iids.is_empty() {
            sqlx::query("DELETE FROM runtime_mention_quota_pending WHERE repo = ?")
                .bind(repo)
                .execute(&self.pool)
                .await
                .context("clear runtime mention quota pending rows for closed repo")?;
            return Ok(deleted);
        }

        let mut builder =
            QueryBuilder::<Sqlite>::new("DELETE FROM runtime_mention_quota_pending WHERE repo = ");
        builder.push_bind(repo);
        builder.push(" AND iid NOT IN (");
        let mut separated = builder.separated(", ");
        for iid in open_iids {
            separated.push_bind(sqlite_i64_from_u64(*iid, "iid")?);
        }
        separated.push_unseparated(")");
        builder
            .build()
            .execute(&self.pool)
            .await
            .context("prune closed merge requests from runtime mention quota pending rows")?;
        Ok(deleted)
    }

    async fn list_mention_quota_pending_rows_for_prune(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<Vec<MentionQuotaPendingEntry>> {
        if open_iids.is_empty() {
            let rows = sqlx::query(
                r"
                SELECT repo, iid, discussion_id, trigger_note_id, first_blocked_at, last_blocked_at, last_seen_head_sha, next_retry_at
                FROM runtime_mention_quota_pending
                WHERE repo = ?
                ORDER BY first_blocked_at ASC, repo ASC, iid ASC, discussion_id ASC, trigger_note_id ASC
                ",
            )
            .bind(repo)
            .fetch_all(&self.pool)
            .await
            .context("list runtime mention quota pending rows for closed repo")?;
            return rows
                .into_iter()
                .map(|row| map_mention_quota_pending_row(&row))
                .collect();
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            r"
            SELECT repo, iid, discussion_id, trigger_note_id, first_blocked_at, last_blocked_at, last_seen_head_sha, next_retry_at
            FROM runtime_mention_quota_pending
            WHERE repo = ",
        );
        builder.push_bind(repo);
        builder.push(" AND iid NOT IN (");
        let mut separated = builder.separated(", ");
        for iid in open_iids {
            separated.push_bind(sqlite_i64_from_u64(*iid, "iid")?);
        }
        separated.push_unseparated(")");
        builder.push(" ORDER BY first_blocked_at ASC, repo ASC, iid ASC, discussion_id ASC, trigger_note_id ASC");
        let rows = builder
            .build()
            .fetch_all(&self.pool)
            .await
            .context("list runtime mention quota pending rows to prune")?;
        rows.into_iter()
            .map(|row| map_mention_quota_pending_row(&row))
            .collect()
    }
}

fn map_mention_quota_pending_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<MentionQuotaPendingEntry> {
    Ok(MentionQuotaPendingEntry {
        repo: row
            .try_get("repo")
            .context("read runtime mention quota pending repo")?,
        iid: u64::try_from(
            row.try_get::<i64, _>("iid")
                .context("read runtime mention quota pending iid")?,
        )
        .context("convert runtime mention quota pending iid to u64")?,
        discussion_id: row
            .try_get("discussion_id")
            .context("read runtime mention quota pending discussion_id")?,
        trigger_note_id: u64::try_from(
            row.try_get::<i64, _>("trigger_note_id")
                .context("read runtime mention quota pending trigger_note_id")?,
        )
        .context("convert runtime mention quota pending trigger_note_id to u64")?,
        first_blocked_at: row
            .try_get("first_blocked_at")
            .context("read runtime mention quota pending first_blocked_at")?,
        last_blocked_at: row
            .try_get("last_blocked_at")
            .context("read runtime mention quota pending last_blocked_at")?,
        last_seen_head_sha: row
            .try_get("last_seen_head_sha")
            .context("read runtime mention quota pending last_seen_head_sha")?,
        next_retry_at: row
            .try_get("next_retry_at")
            .context("read runtime mention quota pending next_retry_at")?,
    })
}

use super::ReviewRateLimitPendingEntry;
use crate::review::ReviewLane;
use crate::state::{parse_review_lane, sqlite_i64_from_u64};
use anyhow::{Context, Result};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

#[derive(Clone)]
pub(super) struct PendingRepository {
    pool: SqlitePool,
}

impl PendingRepository {
    pub(super) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn upsert_review_rate_limit_pending(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        head_sha: &str,
        blocked_at: i64,
        next_retry_at: i64,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO runtime_review_rate_limit_pending (
                lane,
                repo,
                iid,
                first_blocked_at,
                last_blocked_at,
                last_seen_head_sha,
                next_retry_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(lane, repo, iid) DO UPDATE SET
                first_blocked_at = MIN(runtime_review_rate_limit_pending.first_blocked_at, excluded.first_blocked_at),
                last_blocked_at = MAX(runtime_review_rate_limit_pending.last_blocked_at, excluded.last_blocked_at),
                last_seen_head_sha = excluded.last_seen_head_sha,
                next_retry_at = excluded.next_retry_at
            ",
        )
        .bind(lane.as_str())
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(blocked_at)
        .bind(blocked_at)
        .bind(head_sha)
        .bind(next_retry_at)
        .execute(&self.pool)
        .await
        .context("upsert runtime review rate limit pending row")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn clear_review_rate_limit_pending(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
    ) -> Result<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM runtime_review_rate_limit_pending
            WHERE lane = ? AND repo = ? AND iid = ?
            ",
        )
        .bind(lane.as_str())
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .execute(&self.pool)
        .await
        .context("clear runtime review rate limit pending row")?;
        Ok(result.rows_affected() > 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn list_review_rate_limit_pending(
        &self,
    ) -> Result<Vec<ReviewRateLimitPendingEntry>> {
        let rows = sqlx::query(
            r"
            SELECT lane, repo, iid, first_blocked_at, last_blocked_at, last_seen_head_sha, next_retry_at
            FROM runtime_review_rate_limit_pending
            ORDER BY first_blocked_at ASC, lane ASC, repo ASC, iid ASC
            ",
        )
        .fetch_all(&self.pool)
        .await
        .context("list runtime review rate limit pending rows")?;

        rows.into_iter()
            .map(|row| map_review_rate_limit_pending_row(&row))
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn earliest_review_rate_limit_pending_retry_at(&self) -> Result<Option<i64>> {
        let next_retry_at = sqlx::query_scalar::<_, Option<i64>>(
            r"
            SELECT MIN(next_retry_at)
            FROM runtime_review_rate_limit_pending
            ",
        )
        .fetch_one(&self.pool)
        .await
        .context("load earliest runtime review rate limit pending retry time")?;
        Ok(next_retry_at)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn repo_has_due_review_rate_limit_pending(
        &self,
        repo: &str,
        now: i64,
    ) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r"
            SELECT EXISTS(
                SELECT 1
                FROM runtime_review_rate_limit_pending
                WHERE repo = ?
                  AND next_retry_at <= ?
            )
            ",
        )
        .bind(repo)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("check due runtime review rate limit pending rows")?;
        Ok(exists != 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn sync_review_rate_limit_pending_rows(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        if open_iids.is_empty() {
            sqlx::query("DELETE FROM runtime_review_rate_limit_pending WHERE repo = ?")
                .bind(repo)
                .execute(&self.pool)
                .await
                .context("clear runtime review rate limit pending rows for closed repo")?;
            return Ok(());
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            "DELETE FROM runtime_review_rate_limit_pending WHERE repo = ",
        );
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
            .context("prune closed merge requests from runtime review rate limit pending rows")?;
        Ok(())
    }
}

fn map_review_rate_limit_pending_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ReviewRateLimitPendingEntry> {
    Ok(ReviewRateLimitPendingEntry {
        lane: parse_review_lane(
            row.try_get::<String, _>("lane")
                .context("read runtime review rate limit pending lane")?
                .as_str(),
        )?,
        repo: row
            .try_get("repo")
            .context("read runtime review rate limit pending repo")?,
        iid: u64::try_from(
            row.try_get::<i64, _>("iid")
                .context("read runtime review rate limit pending iid")?,
        )
        .context("convert runtime review rate limit pending iid to u64")?,
        first_blocked_at: row
            .try_get("first_blocked_at")
            .context("read runtime review rate limit pending first_blocked_at")?,
        last_blocked_at: row
            .try_get("last_blocked_at")
            .context("read runtime review rate limit pending last_blocked_at")?,
        last_seen_head_sha: row
            .try_get("last_seen_head_sha")
            .context("read runtime review rate limit pending last_seen_head_sha")?,
        next_retry_at: row
            .try_get("next_retry_at")
            .context("read runtime review rate limit pending next_retry_at")?,
    })
}

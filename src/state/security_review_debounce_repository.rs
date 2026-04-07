use anyhow::{Context, Result};
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};

use super::{SecurityReviewDebounceEntry, sqlite_i64_from_u64};

#[derive(Clone)]
pub struct SecurityReviewDebounceRepository {
    pool: SqlitePool,
}

impl SecurityReviewDebounceRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn upsert_security_review_debounce(
        &self,
        repo: &str,
        iid: u64,
        last_started_at: i64,
        next_eligible_at: i64,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO security_review_debounce_state (repo, iid, last_started_at, next_eligible_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(repo, iid) DO UPDATE SET
                last_started_at = excluded.last_started_at,
                next_eligible_at = excluded.next_eligible_at
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(last_started_at)
        .bind(next_eligible_at)
        .execute(&self.pool)
        .await
        .context("upsert security review debounce state")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn get_security_review_debounce(
        &self,
        repo: &str,
        iid: u64,
    ) -> Result<Option<SecurityReviewDebounceEntry>> {
        let row = sqlx::query(
            r"
            SELECT repo, iid, last_started_at, next_eligible_at
            FROM security_review_debounce_state
            WHERE repo = ? AND iid = ?
            LIMIT 1
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .fetch_optional(&self.pool)
        .await
        .context("load security review debounce state")?;
        row.map(|row| map_security_review_debounce_entry(&row))
            .transpose()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn repo_has_due_security_review_debounce(
        &self,
        repo: &str,
        now: i64,
    ) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r"
            SELECT EXISTS(
                SELECT 1
                FROM security_review_debounce_state debounce
                LEFT JOIN review_state review
                  ON review.repo = debounce.repo
                 AND review.iid = debounce.iid
                 AND review.lane = 'security'
                WHERE debounce.repo = ?
                  AND debounce.next_eligible_at <= ?
                  AND COALESCE(review.status, 'done') != 'in_progress'
            )
            ",
        )
        .bind(repo)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("check due security review debounce state")?;
        Ok(exists != 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn sync_security_review_debounce_rows(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        if open_iids.is_empty() {
            sqlx::query("DELETE FROM security_review_debounce_state WHERE repo = ?")
                .bind(repo)
                .execute(&self.pool)
                .await
                .context("clear security review debounce state for closed repo")?;
            return Ok(());
        }

        let mut builder =
            QueryBuilder::<Sqlite>::new("DELETE FROM security_review_debounce_state WHERE repo = ");
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
            .context("prune closed merge requests from security review debounce state")?;
        Ok(())
    }
}

fn map_security_review_debounce_entry(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SecurityReviewDebounceEntry> {
    Ok(SecurityReviewDebounceEntry {
        repo: row
            .try_get("repo")
            .context("read security review debounce repo")?,
        iid: u64::try_from(
            row.try_get::<i64, _>("iid")
                .context("read security review debounce iid")?,
        )
        .context("convert security review debounce iid to u64")?,
        last_started_at: row
            .try_get("last_started_at")
            .context("read security review debounce last_started_at")?,
        next_eligible_at: row
            .try_get("next_eligible_at")
            .context("read security review debounce next_eligible_at")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn debounce_state_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store
            .security_review_debounce
            .upsert_security_review_debounce("group/repo", 21, 100, 130)
            .await?;
        let entry = store
            .security_review_debounce
            .get_security_review_debounce("group/repo", 21)
            .await?
            .expect("debounce row should exist");
        assert_eq!(entry.next_eligible_at, 130);
        Ok(())
    }
}

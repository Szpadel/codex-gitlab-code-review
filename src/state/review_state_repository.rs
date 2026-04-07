use crate::review_lane::ReviewLane;
use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{Row, SqlitePool};

use super::{InProgressReview, sqlite_i64_from_u64};

#[derive(Clone)]
pub struct ReviewStateRepository {
    pool: SqlitePool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn begin_and_finish_general_review_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;

        assert!(
            store
                .review_state
                .begin_review("group/repo", 101, "sha-101")
                .await?
        );
        assert_eq!(
            store
                .review_state
                .review_result("group/repo", 101, "sha-101")
                .await?,
            None
        );

        store
            .review_state
            .finish_review("group/repo", 101, "sha-101", "pass")
            .await?;
        assert_eq!(
            store
                .review_state
                .review_result("group/repo", 101, "sha-101")
                .await?,
            Some("pass".to_string())
        );
        Ok(())
    }
}

impl ReviewStateRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the review state cannot be loaded or updated.
    pub async fn begin_review(&self, repo: &str, iid: u64, sha: &str) -> Result<bool> {
        self.begin_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the review state cannot be loaded or updated.
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
                .bind(i64::try_from(iid).context("convert review iid to i64")?)
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
            r"
            INSERT INTO review_state (repo, iid, lane, head_sha, status, started_at, updated_at)
            VALUES (?, ?, ?, ?, 'in_progress', ?, ?)
            ON CONFLICT(repo, iid, lane) DO UPDATE SET
                head_sha = excluded.head_sha,
                status = 'in_progress',
                started_at = excluded.started_at,
                updated_at = excluded.updated_at,
                result = NULL
            ",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
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

    /// # Errors
    ///
    /// Returns an error if the persisted review state cannot be updated.
    pub async fn finish_review(&self, repo: &str, iid: u64, sha: &str, result: &str) -> Result<()> {
        self.finish_review_for_lane(repo, iid, sha, ReviewLane::General, result)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the persisted review state cannot be updated.
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
            r"
            UPDATE review_state
            SET status = 'done', head_sha = ?, result = ?, updated_at = ?
            WHERE repo = ? AND iid = ? AND lane = ? AND head_sha = ? AND status = 'in_progress'
            ",
        )
        .bind(sha)
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(i64::try_from(iid).context("convert review iid to i64")?)
        .bind(lane.as_str())
        .bind(sha)
        .execute(&self.pool)
        .await
        .context("update review state")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the stored review result cannot be queried.
    pub async fn review_result(&self, repo: &str, iid: u64, sha: &str) -> Result<Option<String>> {
        self.review_result_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the stored review result cannot be queried.
    pub async fn review_result_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<Option<String>> {
        let row = sqlx::query(
            r"
            SELECT result
            FROM review_state
            WHERE repo = ?
              AND iid = ?
              AND lane = ?
              AND head_sha = ?
              AND status = 'done'
            LIMIT 1
            ",
        )
        .bind(repo)
        .bind(i64::try_from(iid).context("convert review iid to i64")?)
        .bind(lane.as_str())
        .bind(sha)
        .fetch_optional(&self.pool)
        .await
        .context("load review result")?;
        Ok(row.map(|row| row.get::<String, _>(0)))
    }

    /// # Errors
    ///
    /// Returns an error if in-progress review records cannot be loaded.
    pub async fn list_in_progress_reviews(&self) -> Result<Vec<InProgressReview>> {
        let rows = sqlx::query(
            r"
            SELECT repo, iid, lane, head_sha
            FROM review_state
            WHERE status = 'in_progress'
            ORDER BY repo, iid, lane
            ",
        )
        .fetch_all(&self.pool)
        .await
        .context("list in-progress reviews")?;

        rows.into_iter()
            .map(|row| {
                let repo: String = row.try_get("repo").context("read review repo")?;
                let iid_raw: i64 = row.try_get("iid").context("read review iid")?;
                let iid = u64::try_from(iid_raw).context("convert review iid to u64")?;
                let lane = super::parse_review_lane(
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
            r"
            SELECT EXISTS(
                SELECT 1
                FROM review_state
                WHERE repo = ? AND iid = ? AND status = 'in_progress'
            )
            ",
        )
        .bind(repo)
        .bind(i64::try_from(iid).context("convert review iid to i64")?)
        .fetch_one(&self.pool)
        .await
        .context("check in-progress review")?;
        Ok(exists != 0)
    }

    /// # Errors
    ///
    /// Returns an error if stale in-progress review rows cannot be marked.
    pub async fn clear_stale_in_progress(&self, max_age_minutes: u64) -> Result<()> {
        let cutoff = Utc::now().timestamp()
            - (super::sqlite_i64_from_u64(max_age_minutes, "max_age_minutes")? * 60);
        let now = Utc::now().timestamp();
        sqlx::query(
            r"
            UPDATE review_state
            SET status = 'stale', updated_at = ?
            WHERE status = 'in_progress' AND updated_at < ?
            ",
        )
        .bind(now)
        .bind(cutoff)
        .execute(&self.pool)
        .await
        .context("mark stale reviews")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the in-progress review heartbeat cannot be updated.
    pub async fn touch_in_progress_review(&self, repo: &str, iid: u64, sha: &str) -> Result<()> {
        self.touch_in_progress_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the in-progress review heartbeat cannot be updated.
    pub async fn touch_in_progress_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        sqlx::query(
            r"
            UPDATE review_state
            SET updated_at = ?
            WHERE repo = ? AND iid = ? AND lane = ? AND head_sha = ? AND status = 'in_progress'
            ",
        )
        .bind(now)
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(lane.as_str())
        .bind(sha)
        .execute(&self.pool)
        .await
        .context("touch in-progress review")?;
        Ok(())
    }
}

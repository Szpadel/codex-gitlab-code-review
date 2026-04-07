use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

use super::SecurityReviewContextCacheEntry;

#[derive(Clone)]
pub struct SecurityContextCacheRepository {
    pool: SqlitePool,
}

impl SecurityContextCacheRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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
            r"
            SELECT repo, base_branch, base_head_sha, prompt_version, payload_json, source_run_history_id,
                   generated_at, expires_at
            FROM security_review_context_cache
            WHERE repo = ?
              AND base_branch = ?
              AND base_head_sha = ?
              AND prompt_version = ?
              AND expires_at > ?
            LIMIT 1
            ",
        )
        .bind(repo)
        .bind(base_branch)
        .bind(base_head_sha)
        .bind(prompt_version)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("load security review context cache")?;
        row.map(|row| map_security_review_context_cache_entry(&row))
            .transpose()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn find_security_review_context_cache(
        &self,
        repo: &str,
        base_branch: &str,
        base_head_sha: &str,
        prompt_version: &str,
    ) -> Result<Option<SecurityReviewContextCacheEntry>> {
        let row = sqlx::query(
            r"
            SELECT repo, base_branch, base_head_sha, prompt_version, payload_json, source_run_history_id,
                   generated_at, expires_at
            FROM security_review_context_cache
            WHERE repo = ?
              AND base_branch = ?
              AND base_head_sha = ?
              AND prompt_version = ?
            LIMIT 1
            ",
        )
        .bind(repo)
        .bind(base_branch)
        .bind(base_head_sha)
        .bind(prompt_version)
        .fetch_optional(&self.pool)
        .await
        .context("find security review context cache")?;
        row.map(|row| map_security_review_context_cache_entry(&row))
            .transpose()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn get_latest_security_review_context_cache_for_branch(
        &self,
        repo: &str,
        base_branch: &str,
        prompt_version: &str,
        now: i64,
    ) -> Result<Option<SecurityReviewContextCacheEntry>> {
        self.delete_expired_security_review_context_cache(now)
            .await?;
        let row = sqlx::query(
            r"
            SELECT repo, base_branch, base_head_sha, prompt_version, payload_json, source_run_history_id,
                   generated_at, expires_at
            FROM security_review_context_cache
            WHERE repo = ?
              AND base_branch = ?
              AND prompt_version = ?
              AND expires_at > ?
            ORDER BY generated_at DESC, expires_at DESC, base_head_sha DESC
            LIMIT 1
            ",
        )
        .bind(repo)
        .bind(base_branch)
        .bind(prompt_version)
        .bind(now)
        .fetch_optional(&self.pool)
        .await
        .context("load latest security review context cache for branch")?;
        row.map(|row| map_security_review_context_cache_entry(&row))
            .transpose()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn upsert_security_review_context_cache(
        &self,
        entry: &SecurityReviewContextCacheEntry,
    ) -> Result<()> {
        self.delete_expired_security_review_context_cache(entry.generated_at)
            .await?;
        sqlx::query(
            r"
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
            ",
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
            r"
            DELETE FROM security_review_context_cache
            WHERE expires_at <= ?
            ",
        )
        .bind(now)
        .execute(&self.pool)
        .await
        .context("delete expired security review context cache")?;
        Ok(())
    }
}

fn map_security_review_context_cache_entry(
    row: &sqlx::sqlite::SqliteRow,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn security_context_cache_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let entry = SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "sha-main".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"threats\":[]}".to_string(),
            source_run_history_id: 77,
            generated_at: 100,
            expires_at: 200,
        };
        store
            .security_context_cache
            .upsert_security_review_context_cache(&entry)
            .await?;
        let loaded = store
            .security_context_cache
            .get_security_review_context_cache("group/repo", "main", "sha-main", "v1", 150)
            .await?
            .expect("cache entry should exist");
        assert_eq!(loaded.payload_json, entry.payload_json);
        Ok(())
    }
}

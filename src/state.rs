use anyhow::{bail, Context, Result};
use chrono::Utc;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::fs::{self, OpenOptions};
use std::path::Path;

pub struct ReviewStateStore {
    pool: SqlitePool,
}

pub struct ProjectCatalog {
    pub fetched_at: i64,
    pub projects: Vec<String>,
}

impl ReviewStateStore {
    pub async fn new(path: &str) -> Result<Self> {
        if path != ":memory:" {
            let path_obj = Path::new(path);
            if path_obj.is_dir() {
                bail!("database path is a directory: {}", path_obj.display());
            }
            if let Some(parent) = path_obj.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent).with_context(|| {
                        format!("create database directory {}", parent.display())
                    })?;
                }
            }
            if !path_obj.exists() {
                OpenOptions::new()
                    .write(true)
                    .create(true)
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
        let mut tx = self.pool.begin().await.context("start sqlite transaction")?;
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
            WHERE repo = ? AND iid = ?
            "#,
        )
        .bind(sha)
        .bind(result)
        .bind(now)
        .bind(repo)
        .bind(iid as i64)
        .execute(&self.pool)
        .await
        .context("update review state")?;
        Ok(())
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

    pub async fn get_project_last_activity(&self, repo: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT last_activity_at FROM project_state WHERE repo = ?")
            .bind(repo)
            .fetch_optional(&self.pool)
            .await
            .context("load project last activity")?;
        match row {
            Some(row) => {
                let value: String = row
                    .try_get("last_activity_at")
                    .context("read project last activity")?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    pub async fn set_project_last_activity(
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
        .context("upsert project last activity")?;
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
                let projects: Vec<String> = serde_json::from_str(&projects_json)
                    .context("deserialize catalog projects")?;
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
            INSERT INTO project_catalog (cache_key, fetched_at, projects)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                fetched_at = excluded.fetched_at,
                projects = excluded.projects
            "#,
        )
        .bind(key)
        .bind(now)
        .bind(projects_json)
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
                let value: String = row
                    .try_get("value")
                    .context("read created_after state")?;
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
        format!("sqlite://{}", path)
    }
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

        let missing = store.get_project_last_activity(repo).await?;
        assert_eq!(missing, None);

        store
            .set_project_last_activity(repo, "2025-01-01T00:00:00Z")
            .await?;
        let loaded = store.get_project_last_activity(repo).await?;
        assert_eq!(
            loaded,
            Some("2025-01-01T00:00:00Z".to_string())
        );
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

        store
            .set_created_after("2025-01-02T03:04:05Z")
            .await?;
        let loaded = store.get_created_after().await?;
        assert_eq!(loaded, Some("2025-01-02T03:04:05Z".to_string()));
        Ok(())
    }
}

use anyhow::{Context, Result, bail};
use chrono::Utc;
use sqlx::{Row, SqlitePool, sqlite::SqlitePoolOptions};
use std::fs::{self, OpenOptions};
use std::path::Path;
use uuid::Uuid;

pub struct ReviewStateStore {
    pool: SqlitePool,
}

pub struct ProjectCatalog {
    pub fetched_at: i64,
    pub projects: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InProgressReview {
    pub repo: String,
    pub iid: u64,
    pub head_sha: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MentionCommandStateKey {
    pub repo: String,
    pub iid: u64,
    pub discussion_id: String,
    pub trigger_note_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InProgressMentionCommand {
    pub key: MentionCommandStateKey,
    pub head_sha: String,
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
}

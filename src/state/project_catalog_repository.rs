use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::{Row, SqlitePool};

use super::{ProjectCatalog, ProjectCatalogSummary, sqlite_i64_from_usize};

#[derive(Clone)]
pub struct ProjectCatalogRepository {
    pool: SqlitePool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn save_and_load_catalog_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let projects = vec!["group/a".to_string(), "group/b".to_string()];
        store
            .project_catalog
            .save_project_catalog("all", &projects)
            .await?;
        let cached = store
            .project_catalog
            .load_project_catalog("all")
            .await?
            .expect("catalog should exist");
        assert_eq!(cached.projects, projects);
        Ok(())
    }
}

impl ProjectCatalogRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_project_last_mr_activity(
        &self,
        repo: &str,
        last_activity_at: &str,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO project_state (repo, last_activity_at)
            VALUES (?, ?)
            ON CONFLICT(repo) DO UPDATE SET
                last_activity_at = excluded.last_activity_at
            ",
        )
        .bind(repo)
        .bind(last_activity_at)
        .execute(&self.pool)
        .await
        .context("upsert project last MR activity")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn save_project_catalog(&self, key: &str, projects: &[String]) -> Result<()> {
        let now = Utc::now().timestamp();
        let projects_json =
            serde_json::to_string(projects).context("serialize catalog projects")?;
        sqlx::query(
            r"
            INSERT INTO project_catalog (cache_key, fetched_at, projects, project_count)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                fetched_at = excluded.fetched_at,
                projects = excluded.projects,
                project_count = excluded.project_count
            ",
        )
        .bind(key)
        .bind(now)
        .bind(projects_json)
        .bind(sqlite_i64_from_usize(projects.len(), "project_count")?)
        .execute(&self.pool)
        .await
        .context("upsert project catalog")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_project_catalog_summaries(&self) -> Result<Vec<ProjectCatalogSummary>> {
        let rows = sqlx::query(
            r"
            SELECT cache_key, fetched_at, project_count
            FROM project_catalog
            ORDER BY cache_key ASC
            ",
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
        .bind(sqlite_i64_from_usize(project_count, "project_count")?)
        .bind(key)
        .execute(&self.pool)
        .await
        .with_context(|| format!("backfill legacy project count for key {key}"))?;
        Ok(project_count)
    }
}

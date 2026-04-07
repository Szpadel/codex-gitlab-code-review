use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};
use tracing::warn;
use uuid::Uuid;

use super::{
    AUTH_LIMIT_RESET_KEY_PREFIX, AuthLimitResetEntry, PersistedScanStatus, SCAN_STATUS_KEY,
    auth_limit_reset_key,
};

#[derive(Clone)]
pub struct ServiceStateRepository {
    pool: SqlitePool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn created_after_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        store
            .service_state
            .set_created_after("2026-01-01T00:00:00Z")
            .await?;
        assert_eq!(
            store.service_state.get_created_after().await?,
            Some("2026-01-01T00:00:00Z".to_string())
        );
        Ok(())
    }
}

impl ServiceStateRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_created_after(&self, value: &str) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO service_state (key, value)
            VALUES ('created_after', ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value
            ",
        )
        .bind(value)
        .execute(&self.pool)
        .await
        .context("upsert created_after state")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn get_or_create_review_owner_id(&self) -> Result<String> {
        let candidate = Uuid::new_v4().to_string();
        sqlx::query(
            r"
            INSERT OR IGNORE INTO service_state (key, value)
            VALUES ('review_owner_id', ?)
            ",
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_auth_limit_reset_at(&self, account_name: &str, value: &str) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO service_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = CASE
                    WHEN julianday(service_state.value) IS NULL THEN excluded.value
                    WHEN julianday(excluded.value) IS NULL THEN service_state.value
                    WHEN julianday(excluded.value) > julianday(service_state.value) THEN excluded.value
                    ELSE service_state.value
                END
            ",
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_scan_status(&self, status: &PersistedScanStatus) -> Result<()> {
        let raw = serde_json::to_string(status).context("serialize scan status")?;
        self.set_service_state_value(SCAN_STATUS_KEY, &raw).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn clear_next_scan_at(&self) -> Result<()> {
        let mut status = self.get_scan_status().await?;
        status.next_scan_at = None;
        self.set_scan_status(&status).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
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

    pub(crate) async fn get_service_state_value(&self, key: &str) -> Result<Option<String>> {
        let row = sqlx::query("SELECT value FROM service_state WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await
            .with_context(|| format!("load service_state value for key {key}"))?;
        row.map(|row| row.try_get("value").context("read service_state value"))
            .transpose()
    }

    pub(crate) async fn set_service_state_value(&self, key: &str, value: &str) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO service_state (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value
            ",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .with_context(|| format!("upsert service_state value for key {key}"))?;
        Ok(())
    }
}

use anyhow::{Context, Result};
use sqlx::SqlitePool;

use crate::feature_flags::RuntimeFeatureFlagOverrides;

use super::{FEATURE_FLAG_OVERRIDES_KEY, ServiceStateRepository};

#[derive(Clone)]
pub struct FeatureFlagsRepository {
    service_state: ServiceStateRepository,
}

impl FeatureFlagsRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            service_state: ServiceStateRepository::new(pool),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn get_runtime_feature_flag_overrides(&self) -> Result<RuntimeFeatureFlagOverrides> {
        let raw = self
            .service_state
            .get_service_state_value(FEATURE_FLAG_OVERRIDES_KEY)
            .await?;
        match raw {
            Some(raw) => serde_json::from_str(&raw).context("deserialize feature flag overrides"),
            None => Ok(RuntimeFeatureFlagOverrides::default()),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_runtime_feature_flag_overrides(
        &self,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> Result<()> {
        let raw = serde_json::to_string(overrides).context("serialize feature flag overrides")?;
        self.service_state
            .set_service_state_value(FEATURE_FLAG_OVERRIDES_KEY, &raw)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn feature_flag_overrides_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let overrides = RuntimeFeatureFlagOverrides {
            security_review: Some(true),
            ..RuntimeFeatureFlagOverrides::default()
        };
        store
            .feature_flags
            .set_runtime_feature_flag_overrides(&overrides)
            .await?;
        assert_eq!(
            store
                .feature_flags
                .get_runtime_feature_flag_overrides()
                .await?,
            overrides
        );
        Ok(())
    }
}

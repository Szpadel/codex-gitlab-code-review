use super::{UsageAccountSnapshot, UsagePageSnapshot};
use crate::codex_runner::{
    CodexRunner, CodexUsageResetOutcome, ConfiguredAuthAccount, QUOTA_LAST_PROBE_AT_KEY,
    configured_auth_accounts,
};
use crate::config::Config;
use crate::service_error::ServiceError;
use crate::state::ReviewStateStore;
use anyhow::{Context, Result, anyhow};
use chrono::{SecondsFormat, Utc};
use futures::{StreamExt, TryStreamExt, stream};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct UsageService {
    accounts: Vec<ConfiguredAuthAccount>,
    state: Arc<ReviewStateStore>,
    runner: Option<Arc<dyn CodexRunner>>,
}

impl UsageService {
    #[must_use]
    pub fn new(
        config: &Config,
        state: Arc<ReviewStateStore>,
        runner: Option<Arc<dyn CodexRunner>>,
    ) -> Self {
        let accounts = configured_auth_accounts(&config.codex);
        Self {
            accounts,
            state,
            runner,
        }
    }

    /// # Errors
    ///
    /// Returns an error if reading local usage-limit marker state fails.
    pub async fn snapshot(&self) -> Result<UsagePageSnapshot, ServiceError> {
        let pending: Vec<_> = self
            .accounts
            .iter()
            .map(|account| async {
                let local_limit_reset_at = self
                    .state
                    .service_state
                    .get_auth_limit_reset_at(&account.state_key)
                    .await?;
                let usage = match &self.runner {
                    Some(runner) => runner
                        .read_usage_limits(&account.name)
                        .await
                        .map_err(|err| format!("{err:#}")),
                    None => Err("Codex runner is not available".to_string()),
                };
                Ok::<_, anyhow::Error>(UsageAccountSnapshot {
                    name: account.name.clone(),
                    auth_host_path: account.auth_host_path.clone(),
                    local_limit_reset_at,
                    usage,
                })
            })
            .collect();
        // Bound simultaneous container starts while preserving configured account order.
        let accounts = stream::iter(pending).buffered(4).try_collect().await?;
        Ok(UsagePageSnapshot {
            generated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
            accounts,
        })
    }

    /// # Errors
    ///
    /// Rejects unknown accounts, available weekly limits, or missing credits as
    /// invalid input. Reports RPC and state failures as internal errors.
    pub async fn consume_reset(
        &self,
        account_name: &str,
    ) -> Result<CodexUsageResetOutcome, ServiceError> {
        let account = self
            .accounts
            .iter()
            .find(|account| account.name == account_name)
            .ok_or_else(|| {
                ServiceError::InvalidInput(anyhow!(
                    "invalid usage reset request: unknown auth account"
                ))
            })?;
        let runner = self.runner.as_ref().ok_or_else(|| {
            ServiceError::Internal(anyhow!(
                "codex usage limits are unavailable: runner not configured"
            ))
        })?;
        let usage = runner
            .read_usage_limits(&account.name)
            .await
            .with_context(|| format!("read usage limits for account {}", account.name))?;
        if !usage.has_exhausted_weekly_limit() {
            return Err(ServiceError::InvalidInput(anyhow!(
                "invalid usage reset request: weekly usage limit is not exhausted"
            )));
        }
        if !usage
            .rate_limit_reset_credits
            .as_ref()
            .is_some_and(|credits| credits.available_count > 0)
        {
            return Err(ServiceError::InvalidInput(anyhow!(
                "invalid usage reset request: no usage reset credits available"
            )));
        }

        let outcome = runner
            .consume_usage_limit_reset(&account.name, &Uuid::new_v4().to_string())
            .await
            .with_context(|| format!("consume usage reset credit for account {}", account.name))?;
        if matches!(
            outcome,
            CodexUsageResetOutcome::Reset
                | CodexUsageResetOutcome::AlreadyRedeemed
                | CodexUsageResetOutcome::NothingToReset
        ) {
            self.state
                .service_state
                .clear_auth_limit_reset_at(&account.state_key)
                .await?;
            self.state
                .service_state
                .clear_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
                .await?;
        }
        Ok(outcome)
    }
}

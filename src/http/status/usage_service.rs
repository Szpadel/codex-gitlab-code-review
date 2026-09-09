use super::{UsageAccountSnapshot, UsagePageSnapshot};
use crate::codex_runner::{
    CodexRunner, CodexUsageResetOutcome, PRIMARY_AUTH_ACCOUNT_NAME, QUOTA_LAST_PROBE_AT_KEY,
    auth_account_state_key,
};
use crate::config::Config;
use crate::state::ReviewStateStore;
use anyhow::{Context, Result, anyhow, bail};
use chrono::{SecondsFormat, Utc};
use futures::{StreamExt, TryStreamExt, stream};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct UsageService {
    accounts: Vec<ConfiguredUsageAccount>,
    state: Arc<ReviewStateStore>,
    runner: Option<Arc<dyn CodexRunner>>,
}

#[derive(Clone)]
struct ConfiguredUsageAccount {
    name: String,
    auth_host_path: String,
    state_key: String,
}

impl UsageService {
    #[must_use]
    pub fn new(
        config: &Config,
        state: Arc<ReviewStateStore>,
        runner: Option<Arc<dyn CodexRunner>>,
    ) -> Self {
        let accounts = configured_usage_accounts(config);
        Self {
            accounts,
            state,
            runner,
        }
    }

    /// # Errors
    ///
    /// Returns an error if reading local usage-limit marker state fails.
    pub async fn snapshot(&self) -> Result<UsagePageSnapshot> {
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
    /// Returns an error if the account is unknown, the weekly limit is not
    /// exhausted, the Codex reset RPC fails, or local marker cleanup fails.
    pub async fn consume_reset(&self, account_name: &str) -> Result<CodexUsageResetOutcome> {
        let account = self
            .accounts
            .iter()
            .find(|account| account.name == account_name)
            .ok_or_else(|| anyhow!("invalid usage reset request: unknown auth account"))?;
        let runner = self
            .runner
            .as_ref()
            .ok_or_else(|| anyhow!("codex usage limits are unavailable: runner not configured"))?;
        let usage = runner
            .read_usage_limits(&account.name)
            .await
            .with_context(|| format!("read usage limits for account {}", account.name))?;
        if !usage.has_exhausted_weekly_limit() {
            bail!("invalid usage reset request: weekly usage limit is not exhausted");
        }
        if !usage
            .rate_limit_reset_credits
            .as_ref()
            .is_some_and(|credits| credits.available_count > 0)
        {
            bail!("invalid usage reset request: no usage reset credits available");
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

fn configured_usage_accounts(config: &Config) -> Vec<ConfiguredUsageAccount> {
    let mut accounts = vec![ConfiguredUsageAccount {
        name: PRIMARY_AUTH_ACCOUNT_NAME.to_string(),
        auth_host_path: config.codex.auth_host_path.clone(),
        state_key: auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, &config.codex.auth_host_path),
    }];
    accounts.extend(config.codex.fallback_auth_accounts.iter().map(|account| {
        ConfiguredUsageAccount {
            name: account.name.clone(),
            auth_host_path: account.auth_host_path.clone(),
            state_key: auth_account_state_key(&account.name, &account.auth_host_path),
        }
    }));
    accounts
}

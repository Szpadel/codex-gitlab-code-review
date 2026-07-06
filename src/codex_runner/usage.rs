use super::{DockerCodexRunner, Duration, Result, StartedAppServer, Value, anyhow, bail, json};
use anyhow::Context;
use serde::Deserialize;
use std::collections::BTreeMap;
use tokio::time::timeout;

const WEEKLY_WINDOW_MINS: i64 = 7 * 24 * 60;
const WINDOW_LABEL_TOLERANCE_PERCENT: f64 = 0.05;

#[derive(Debug, Clone, PartialEq)]
pub struct CodexUsageSnapshot {
    pub rate_limits_by_limit_id: BTreeMap<String, CodexUsageLimitSnapshot>,
    pub rate_limit_reset_credits: Option<CodexUsageResetCredits>,
}

impl CodexUsageSnapshot {
    #[must_use]
    pub fn has_exhausted_weekly_limit(&self) -> bool {
        self.rate_limits_by_limit_id
            .values()
            .any(CodexUsageLimitSnapshot::has_exhausted_weekly_window)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodexUsageLimitSnapshot {
    pub primary: Option<CodexUsageWindow>,
    pub secondary: Option<CodexUsageWindow>,
    pub credits: Option<Value>,
    pub individual_limit: Option<Value>,
    pub rate_limit_reached_type: Option<String>,
}

impl CodexUsageLimitSnapshot {
    #[must_use]
    pub fn has_exhausted_weekly_window(&self) -> bool {
        self.primary
            .as_ref()
            .is_some_and(CodexUsageWindow::is_exhausted_weekly)
            || self
                .secondary
                .as_ref()
                .is_some_and(CodexUsageWindow::is_exhausted_weekly)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct CodexUsageWindow {
    pub used_percent: f64,
    pub window_duration_mins: Option<i64>,
    pub resets_at: Option<i64>,
}

impl CodexUsageWindow {
    #[must_use]
    pub fn is_weekly(&self) -> bool {
        is_weekly_window_duration(self.window_duration_mins)
    }

    #[must_use]
    pub fn is_exhausted_weekly(&self) -> bool {
        self.is_weekly() && self.used_percent >= 100.0
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CodexUsageResetCredits {
    pub available_count: i64,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CodexUsageResetOutcome {
    Reset,
    NothingToReset,
    NoCredit,
    AlreadyRedeemed,
}

impl CodexUsageResetOutcome {
    #[must_use]
    pub fn as_query_value(self) -> &'static str {
        match self {
            Self::Reset => "reset",
            Self::NothingToReset => "nothingToReset",
            Self::NoCredit => "noCredit",
            Self::AlreadyRedeemed => "alreadyRedeemed",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConsumeResetResponse {
    outcome: CodexUsageResetOutcome,
}

impl DockerCodexRunner {
    pub(crate) async fn read_usage_limits_with_account(
        &self,
        account_name: &str,
    ) -> Result<CodexUsageSnapshot> {
        let account = self
            .auth_account_by_name(account_name)
            .ok_or_else(|| anyhow!("unknown codex auth account: {account_name}"))?;
        let response = self
            .run_usage_app_server_request(
                account.auth_host_path.as_str(),
                "account/rateLimits/read",
                json!({}),
                "codex usage limits read timed out",
            )
            .await?;
        parse_usage_snapshot(response)
    }

    pub(crate) async fn consume_usage_limit_reset_with_account(
        &self,
        account_name: &str,
        idempotency_key: &str,
    ) -> Result<CodexUsageResetOutcome> {
        if idempotency_key.trim().is_empty() {
            bail!("invalid usage reset request: idempotency key must not be empty");
        }
        let account = self
            .auth_account_by_name(account_name)
            .ok_or_else(|| anyhow!("unknown codex auth account: {account_name}"))?;
        let response = self
            .run_usage_app_server_request(
                account.auth_host_path.as_str(),
                "account/rateLimitResetCredit/consume",
                json!({ "idempotencyKey": idempotency_key }),
                "codex usage reset timed out",
            )
            .await?;
        let parsed: ConsumeResetResponse = serde_json::from_value(response)
            .context("decode codex usage reset consume response")?;
        Ok(parsed.outcome)
    }

    async fn run_usage_app_server_request(
        &self,
        auth_host_path: &str,
        method: &str,
        params: Value,
        timeout_error: &'static str,
    ) -> Result<Value> {
        let StartedAppServer {
            container_id,
            browser_container_id,
            mut client,
        } = self
            .start_app_server_container(
                Self::build_history_reader_script(&self.codex.auth_mount_path),
                auth_host_path,
                Vec::new(),
                Vec::new(),
                None,
                Vec::new(),
            )
            .await?;

        let result = timeout(Duration::from_secs(self.codex.timeout_seconds), async {
            client.initialize().await?;
            client.initialized().await?;
            client.request(method, params).await
        })
        .await;

        let result = match result {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(err)) => Err(self
                .enrich_app_server_io_error_if_needed(err, &container_id)
                .await),
            Err(_) => Err(anyhow!(timeout_error)),
        };

        self.cleanup_app_server_containers(&container_id, browser_container_id.as_deref())
            .await;

        result
    }
}

#[must_use]
pub fn is_weekly_window_duration(window_duration_mins: Option<i64>) -> bool {
    let Some(window_duration_mins) = window_duration_mins else {
        return false;
    };
    let tolerance = (WEEKLY_WINDOW_MINS as f64 * WINDOW_LABEL_TOLERANCE_PERCENT).ceil() as i64;
    (window_duration_mins - WEEKLY_WINDOW_MINS).abs() <= tolerance
}

fn parse_usage_snapshot(response: Value) -> Result<CodexUsageSnapshot> {
    let rate_limit_reset_credits = match response.get("rateLimitResetCredits") {
        Some(Value::Null) | None => None,
        Some(raw) => {
            Some(serde_json::from_value(raw.clone()).context("decode codex usage reset credits")?)
        }
    };

    let mut rate_limits_by_limit_id =
        if let Some(rate_limits_by_limit_id) = response.get("rateLimitsByLimitId") {
            if rate_limits_by_limit_id.is_null() {
                BTreeMap::new()
            } else {
                serde_json::from_value::<BTreeMap<String, CodexUsageLimitSnapshot>>(
                    rate_limits_by_limit_id.clone(),
                )
                .context("decode codex usage rateLimitsByLimitId")?
            }
        } else {
            BTreeMap::new()
        };

    if rate_limits_by_limit_id.is_empty()
        && let Some(rate_limits) = response.get("rateLimits")
    {
        let limit_id = rate_limits
            .get("limitId")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("codex")
            .to_string();
        let snapshot = serde_json::from_value::<CodexUsageLimitSnapshot>(rate_limits.clone())
            .context("decode codex usage rateLimits")?;
        rate_limits_by_limit_id.insert(limit_id, snapshot);
    }

    Ok(CodexUsageSnapshot {
        rate_limits_by_limit_id,
        rate_limit_reset_credits,
    })
}

use super::{
    ChronoDuration, CodexConfig, DateTime, DockerCodexRunner, PRIMARY_AUTH_ACCOUNT_NAME, Result,
    Utc, warn,
};
use crate::duration::{
    parse_duration_seconds_from_text, safe_cooldown_duration, safe_duration_from_seconds,
};

#[derive(Debug, Clone)]
pub(crate) struct AuthAccount {
    pub(crate) name: String,
    pub(crate) auth_host_path: String,
    pub(crate) state_key: String,
    pub(crate) is_primary: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthFailureKind {
    UsageLimited { reset_at: DateTime<Utc> },
    AuthUnavailable,
    Other,
}

impl DockerCodexRunner {
    pub(crate) fn build_auth_accounts(codex: &CodexConfig) -> Vec<AuthAccount> {
        let mut accounts = vec![AuthAccount {
            name: PRIMARY_AUTH_ACCOUNT_NAME.to_string(),
            auth_host_path: codex.auth_host_path.clone(),
            state_key: auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, &codex.auth_host_path),
            is_primary: true,
        }];
        accounts.extend(
            codex
                .fallback_auth_accounts
                .iter()
                .map(|account| AuthAccount {
                    name: account.name.clone(),
                    auth_host_path: account.auth_host_path.clone(),
                    state_key: auth_account_state_key(&account.name, &account.auth_host_path),
                    is_primary: false,
                }),
        );
        accounts
    }

    pub(crate) async fn account_is_temporarily_blocked(
        &self,
        account: &AuthAccount,
        now: DateTime<Utc>,
    ) -> Result<bool> {
        let Some(raw_reset_at) = self
            .state
            .get_auth_limit_reset_at(&account.state_key)
            .await?
        else {
            return Ok(false);
        };
        match DateTime::parse_from_rfc3339(&raw_reset_at) {
            Ok(parsed) => Ok(parsed.with_timezone(&Utc) > now),
            Err(err) => {
                warn!(
                    account = account.name.as_str(),
                    raw_reset_at = raw_reset_at.as_str(),
                    error = %err,
                    "invalid account reset timestamp in state; clearing stale entry"
                );
                self.state
                    .clear_auth_limit_reset_at(&account.state_key)
                    .await?;
                Ok(false)
            }
        }
    }

    pub(crate) async fn available_auth_accounts(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Vec<AuthAccount>> {
        let mut available = Vec::new();
        for account in &self.auth_accounts {
            if self.account_is_temporarily_blocked(account, now).await? {
                continue;
            }
            available.push(account.clone());
        }
        Ok(available)
    }

    pub(crate) async fn clear_limit_reset_if_stale(
        &self,
        account: &AuthAccount,
        attempt_started_at: DateTime<Utc>,
    ) -> Result<()> {
        let Some(raw_reset_at) = self
            .state
            .get_auth_limit_reset_at(&account.state_key)
            .await?
        else {
            return Ok(());
        };
        match DateTime::parse_from_rfc3339(&raw_reset_at) {
            Ok(parsed) => {
                let reset_at = parsed.with_timezone(&Utc);
                if should_clear_limit_reset(reset_at, attempt_started_at) {
                    self.state
                        .clear_auth_limit_reset_at(&account.state_key)
                        .await?;
                }
            }
            Err(_) => {
                self.state
                    .clear_auth_limit_reset_at(&account.state_key)
                    .await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn mark_limit_reset_at(
        &self,
        account: &AuthAccount,
        reset_at: DateTime<Utc>,
    ) -> Result<()> {
        self.state
            .set_auth_limit_reset_at(&account.state_key, &reset_at.to_rfc3339())
            .await
    }
}

pub(crate) fn classify_auth_failure(
    err: &anyhow::Error,
    now: DateTime<Utc>,
    fallback_cooldown_seconds: u64,
) -> AuthFailureKind {
    let chain = format!("{err:#}");
    let chain_lower = chain.to_ascii_lowercase();
    if is_usage_limit_error(&chain_lower) {
        let reset_at = parse_usage_limit_reset_at(&chain, now)
            .unwrap_or_else(|| safe_reset_at_from_cooldown(now, fallback_cooldown_seconds));
        return AuthFailureKind::UsageLimited { reset_at };
    }
    if is_auth_unavailable_error(&chain_lower) {
        return AuthFailureKind::AuthUnavailable;
    }
    AuthFailureKind::Other
}

pub(crate) fn classify_auth_failure_for_account(
    base: AuthFailureKind,
    err: &anyhow::Error,
    account: &AuthAccount,
) -> AuthFailureKind {
    if base != AuthFailureKind::Other {
        return base;
    }
    let chain_lower = format!("{err:#}").to_ascii_lowercase();
    if is_account_startup_failure(&chain_lower, &account.auth_host_path) {
        AuthFailureKind::AuthUnavailable
    } else {
        AuthFailureKind::Other
    }
}

pub(crate) fn is_usage_limit_error(error_text_lower: &str) -> bool {
    let explicit = [
        "rate_limit_exceeded",
        "insufficient_quota",
        "x-ratelimit",
        "usage limit exceeded",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle));
    let reached_with_retry_hint = error_text_lower.contains("rate limit reached")
        && error_text_lower.contains("try again in");
    explicit || reached_with_retry_hint
}

pub(crate) fn is_auth_unavailable_error(error_text_lower: &str) -> bool {
    [
        "not authenticated",
        "authentication required",
        "invalid credentials",
        "invalid api key",
        "auth.json",
        "please run codex auth login",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle))
}

pub(crate) fn is_account_startup_failure(error_text_lower: &str, auth_host_path: &str) -> bool {
    let path_lower = auth_host_path.to_ascii_lowercase();
    if path_lower.is_empty() || !error_text_lower.contains(path_lower.as_str()) {
        return false;
    }
    [
        "invalid mount config",
        "bind source path does not exist",
        "no such file or directory",
        "mount",
    ]
    .iter()
    .any(|needle| error_text_lower.contains(needle))
}

pub(crate) fn parse_usage_limit_reset_at(text: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let absolute = parse_rfc3339_reset_timestamp(text, now);
    let relative = parse_relative_reset_timestamp(text, now);
    match (absolute, relative) {
        (Some(abs), Some(rel)) => Some(abs.min(rel)),
        (Some(abs), None) => Some(abs),
        (None, Some(rel)) => Some(rel),
        (None, None) => None,
    }
}

pub(crate) fn parse_rfc3339_reset_timestamp(
    text: &str,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let mut candidates = Vec::new();
    for token in text.split_whitespace() {
        let cleaned = token.trim_matches(|ch: char| {
            matches!(
                ch,
                ',' | ';' | '.' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
            )
        });
        if cleaned.is_empty() {
            continue;
        }
        if let Ok(parsed) = DateTime::parse_from_rfc3339(cleaned) {
            let utc = parsed.with_timezone(&Utc);
            if utc > now {
                candidates.push(utc);
            }
        }
    }
    candidates.into_iter().min()
}

pub(crate) fn parse_relative_reset_timestamp(
    text: &str,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    let lower = text.to_ascii_lowercase();
    for anchor in ["try again in", "resets in", "retry in"] {
        if let Some(idx) = lower.find(anchor) {
            let slice = &lower[idx + anchor.len()..];
            if let Some(seconds) = parse_duration_seconds_from_text(slice) {
                let duration = safe_duration_from_seconds(seconds);
                return now.checked_add_signed(duration);
            }
        }
    }
    None
}

pub(crate) fn safe_reset_at_from_cooldown(
    now: DateTime<Utc>,
    cooldown_seconds: u64,
) -> DateTime<Utc> {
    let cooldown = safe_cooldown_duration(cooldown_seconds);
    if let Some(reset_at) = now.checked_add_signed(cooldown) {
        return reset_at;
    }
    now.checked_add_signed(ChronoDuration::days(3650))
        .unwrap_or(now)
}

pub(crate) fn should_clear_limit_reset(
    existing_reset_at: DateTime<Utc>,
    attempt_started_at: DateTime<Utc>,
) -> bool {
    existing_reset_at <= attempt_started_at
}

pub(crate) fn auth_account_state_key(name: &str, auth_host_path: &str) -> String {
    format!("{name}::{auth_host_path}")
}

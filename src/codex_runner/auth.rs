use super::*;

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

pub(crate) fn parse_duration_seconds_from_text(text: &str) -> Option<i64> {
    let tokens = text
        .split_whitespace()
        .map(|raw_token| {
            raw_token.trim_matches(|ch: char| {
                matches!(
                    ch,
                    ',' | ';' | '.' | '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>'
                )
            })
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();

    let mut total = 0i64;
    let mut consumed = false;
    let mut idx = 0usize;
    while idx < tokens.len() {
        if let Some(seconds) = parse_duration_token_seconds(tokens[idx]) {
            total = total.saturating_add(seconds);
            consumed = true;
            idx += 1;
            continue;
        }

        if let Ok(value) = tokens[idx].parse::<f64>()
            && let Some(unit_token) = tokens.get(idx + 1)
            && let Some(unit_seconds) = duration_unit_seconds(unit_token)
        {
            total = total.saturating_add(seconds_from_numeric_value(value, unit_seconds));
            consumed = true;
            idx += 2;
            continue;
        }

        if consumed && matches!(tokens[idx], "and" | "then") {
            idx += 1;
            continue;
        }

        if consumed {
            break;
        }
        idx += 1;
    }

    if consumed && total > 0i64 {
        Some(total)
    } else {
        None
    }
}

pub(crate) fn parse_duration_token_seconds(token: &str) -> Option<i64> {
    let mut numeric_end = 0usize;
    let mut seen_digit = false;
    let mut seen_dot = false;
    for (idx, ch) in token.char_indices() {
        if ch.is_ascii_digit() {
            seen_digit = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        if ch == '.' && seen_digit && !seen_dot {
            seen_dot = true;
            numeric_end = idx + ch.len_utf8();
            continue;
        }
        break;
    }
    if !seen_digit || numeric_end == 0 || numeric_end >= token.len() {
        return None;
    }
    let value = token[..numeric_end].parse::<f64>().ok()?;
    let unit = &token[numeric_end..];
    duration_unit_seconds(unit).map(|seconds| seconds_from_numeric_value(value, seconds))
}

pub(crate) fn duration_unit_seconds(unit: &str) -> Option<i64> {
    match unit {
        "d" | "day" | "days" => Some(86_400),
        "h" | "hr" | "hrs" | "hour" | "hours" => Some(3_600),
        "m" | "min" | "mins" | "minute" | "minutes" => Some(60),
        "s" | "sec" | "secs" | "second" | "seconds" => Some(1),
        _ => None,
    }
}

pub(crate) fn seconds_from_numeric_value(value: f64, unit_seconds: i64) -> i64 {
    if !value.is_finite() || value <= 0.0 {
        return 0;
    }
    let total = value * unit_seconds as f64;
    if total >= i64::MAX as f64 {
        i64::MAX
    } else {
        total.ceil() as i64
    }
}

pub(crate) fn safe_cooldown_duration(cooldown_seconds: u64) -> ChronoDuration {
    let seconds = i64::try_from(cooldown_seconds).ok().unwrap_or(i64::MAX);
    safe_duration_from_seconds(seconds)
}

pub(crate) fn safe_duration_from_seconds(seconds: i64) -> ChronoDuration {
    const MAX_CHRONO_SECONDS: i64 = i64::MAX / 1000;
    let clamped = seconds.clamp(0, MAX_CHRONO_SECONDS);
    ChronoDuration::seconds(clamped)
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

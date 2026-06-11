use super::{
    ChronoDuration, CodexConfig, DateTime, DockerCodexRunner, PRIMARY_AUTH_ACCOUNT_NAME,
    QuotaBlock, Result, Utc, bail, info, warn,
};
use crate::codex_runner::duration::{
    parse_duration_seconds_from_text, safe_cooldown_duration, safe_duration_from_seconds,
};
use anyhow::Context as _;
use std::fmt;

pub(crate) const QUOTA_LAST_PROBE_AT_KEY: &str = "codex_quota_last_probe_at";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexQuotaExhausted {
    pub reset_at: DateTime<Utc>,
    pub retry_at: DateTime<Utc>,
}

impl fmt::Display for CodexQuotaExhausted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "codex quota exhausted until {}; retry after {}",
            self.reset_at, self.retry_at
        )
    }
}

impl std::error::Error for CodexQuotaExhausted {}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthFallbackAction {
    Review,
    MentionCommand,
}

impl AuthFallbackAction {
    fn action_label(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::MentionCommand => "mention command",
        }
    }

    fn no_available_accounts_message(self) -> &'static str {
        match self {
            Self::Review => {
                "no available codex auth accounts (all accounts are waiting for usage-limit reset)"
            }
            Self::MentionCommand => {
                "no available codex auth accounts (all accounts are waiting for usage-limit reset)"
            }
        }
    }

    fn all_accounts_failed_message(self, combined_errors: String) -> String {
        match self {
            Self::Review => {
                format!(
                    "all codex auth accounts failed with usage-limit/auth errors: {combined_errors}"
                )
            }
            Self::MentionCommand => {
                format!(
                    "all codex auth accounts failed with usage-limit/auth errors for mention command: {combined_errors}"
                )
            }
        }
    }

    fn usage_limited_log_message(self) -> &'static str {
        match self {
            Self::Review => "codex auth account usage-limited; trying next account",
            Self::MentionCommand => {
                "codex auth account usage-limited for mention command; trying next account"
            }
        }
    }

    fn auth_unavailable_log_message(self) -> &'static str {
        match self {
            Self::Review => "codex auth account unavailable; trying next account",
            Self::MentionCommand => {
                "codex auth account unavailable for mention command; trying next account"
            }
        }
    }

    fn usage_limited_error_message(
        self,
        account_name: &str,
        reset_at: DateTime<Utc>,
        err: &anyhow::Error,
    ) -> String {
        match self {
            Self::Review => {
                format!("account '{account_name}' usage-limited until {reset_at}: {err}")
            }
            Self::MentionCommand => {
                format!("account '{account_name}' usage-limited until {reset_at}: {err}")
            }
        }
    }

    fn auth_unavailable_error_message(self, account_name: &str, err: &anyhow::Error) -> String {
        match self {
            Self::Review => format!("account '{account_name}' unavailable: {err}"),
            Self::MentionCommand => format!("account '{account_name}' unavailable: {err}"),
        }
    }

    fn unexpected_failure_context(self, account_name: &str, err: &anyhow::Error) -> String {
        let cause = error_chain_summary(err);
        match self {
            Self::Review => format!("codex review failed for account '{account_name}': {cause}"),
            Self::MentionCommand => {
                format!("mention command failed for account '{account_name}': {cause}")
            }
        }
    }
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
        Ok(self.stored_limit_reset_at(account, now).await?.is_some())
    }

    pub(crate) async fn stored_limit_reset_at(
        &self,
        account: &AuthAccount,
        now: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        let Some(raw_reset_at) = self
            .state
            .service_state
            .get_auth_limit_reset_at(&account.state_key)
            .await?
        else {
            return Ok(None);
        };
        match DateTime::parse_from_rfc3339(&raw_reset_at) {
            Ok(parsed) => {
                let reset_at = parsed.with_timezone(&Utc);
                Ok((reset_at > now).then_some(reset_at))
            }
            Err(err) => {
                warn!(
                    account = account.name.as_str(),
                    raw_reset_at = raw_reset_at.as_str(),
                    error = %err,
                    "invalid account reset timestamp in state; clearing stale entry"
                );
                self.state
                    .service_state
                    .clear_auth_limit_reset_at(&account.state_key)
                    .await?;
                Ok(None)
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
            .service_state
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
                        .service_state
                        .clear_auth_limit_reset_at(&account.state_key)
                        .await?;
                }
            }
            Err(_) => {
                self.state
                    .service_state
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
            .service_state
            .set_auth_limit_reset_at(&account.state_key, &reset_at.to_rfc3339())
            .await
    }

    pub(crate) async fn run_with_auth_fallback<R, F, Fut>(
        &self,
        action: AuthFallbackAction,
        mut execute: F,
    ) -> Result<R>
    where
        F: FnMut(AuthAccount) -> Fut,
        Fut: std::future::Future<Output = Result<R>>,
    {
        let now = Utc::now();
        let mut available_accounts = self.available_auth_accounts(now).await?;
        let mut probe_started = false;
        if available_accounts.is_empty() {
            if self.auth_accounts.is_empty() {
                bail!(action.no_available_accounts_message());
            }
            probe_started = true;
            self.state
                .service_state
                .set_service_state_value(QUOTA_LAST_PROBE_AT_KEY, &now.to_rfc3339())
                .await?;
            let mut blocked_accounts = Vec::new();
            for account in &self.auth_accounts {
                blocked_accounts.push((self.stored_limit_reset_at(account, now).await?, account));
            }
            blocked_accounts.sort_by(|(left_reset, left_account), (right_reset, right_account)| {
                left_reset
                    .cmp(right_reset)
                    .then_with(|| left_account.name.cmp(&right_account.name))
            });
            available_accounts = blocked_accounts
                .into_iter()
                .map(|(_, account)| account.clone())
                .collect();
            info!(
                action = action.action_label(),
                accounts = ?available_accounts
                    .iter()
                    .map(|account| account.name.as_str())
                    .collect::<Vec<_>>(),
                "all codex auth accounts have usage-limit markers; probing blocked accounts"
            );
        }

        let mut auth_fallback_errors = Vec::new();
        let mut saw_auth_unavailable = false;
        for account in available_accounts {
            let attempt_started_at = Utc::now();
            let had_future_reset_at_attempt = self
                .stored_limit_reset_at(&account, attempt_started_at)
                .await?
                .is_some();
            info!(
                account = account.name.as_str(),
                is_primary = account.is_primary,
                action = action.action_label(),
                "running codex action with auth account"
            );
            match execute(account.clone()).await {
                Ok(output) => {
                    if had_future_reset_at_attempt {
                        self.state
                            .service_state
                            .clear_auth_limit_reset_at(&account.state_key)
                            .await?;
                    } else {
                        self.clear_limit_reset_if_stale(&account, attempt_started_at)
                            .await?;
                    }
                    return Ok(output);
                }
                Err(err) => {
                    let kind = classify_auth_failure(
                        &err,
                        Utc::now(),
                        self.codex.usage_limit_fallback_cooldown_seconds,
                    );
                    let kind = classify_auth_failure_for_account(kind, &err, &account);
                    match kind {
                        AuthFailureKind::UsageLimited { reset_at } => {
                            self.mark_limit_reset_at(&account, reset_at).await?;
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                reset_at = %reset_at,
                                error = %err,
                                action = action.action_label(),
                                "{}",
                                action.usage_limited_log_message()
                            );
                            auth_fallback_errors.push(action.usage_limited_error_message(
                                account.name.as_str(),
                                reset_at,
                                &err,
                            ));
                        }
                        AuthFailureKind::AuthUnavailable => {
                            saw_auth_unavailable = true;
                            warn!(
                                account = account.name.as_str(),
                                is_primary = account.is_primary,
                                error = %err,
                                action = action.action_label(),
                                "{}",
                                action.auth_unavailable_log_message()
                            );
                            auth_fallback_errors.push(
                                action.auth_unavailable_error_message(account.name.as_str(), &err),
                            );
                        }
                        AuthFailureKind::Other => {
                            let context =
                                action.unexpected_failure_context(account.name.as_str(), &err);
                            if probe_started {
                                self.state
                                    .service_state
                                    .clear_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
                                    .await?;
                            }
                            return Err(err).with_context(|| context);
                        }
                    }
                }
            }
        }

        if saw_auth_unavailable {
            if probe_started {
                self.state
                    .service_state
                    .clear_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
                    .await?;
            }
            bail!(
                "{}",
                action.all_accounts_failed_message(auth_fallback_errors.join(" | "))
            );
        }
        let quota_reset_at = self
            .earliest_stored_limit_reset_at(now)
            .await?
            .unwrap_or_else(|| {
                safe_reset_at_from_cooldown(now, self.codex.usage_limit_fallback_cooldown_seconds)
            });
        let retry_at = quota_retry_at(now, quota_reset_at, self.codex.usage_limit_recheck_seconds);
        self.state
            .service_state
            .set_service_state_value(QUOTA_LAST_PROBE_AT_KEY, &Utc::now().to_rfc3339())
            .await?;
        Err(anyhow::Error::new(CodexQuotaExhausted {
            reset_at: quota_reset_at,
            retry_at,
        }))
    }

    async fn earliest_stored_limit_reset_at(
        &self,
        now: DateTime<Utc>,
    ) -> Result<Option<DateTime<Utc>>> {
        let mut earliest = None;
        for account in &self.auth_accounts {
            if let Some(reset_at) = self.stored_limit_reset_at(account, now).await? {
                earliest =
                    Some(earliest.map_or(reset_at, |current: DateTime<Utc>| current.min(reset_at)));
            }
        }
        Ok(earliest)
    }

    pub(crate) async fn quota_block_at(&self, now: DateTime<Utc>) -> Result<Option<QuotaBlock>> {
        if self.auth_accounts.is_empty() {
            return Ok(None);
        }

        let mut earliest_reset_at = None;
        for account in &self.auth_accounts {
            let Some(reset_at) = self.stored_limit_reset_at(account, now).await? else {
                return Ok(None);
            };
            earliest_reset_at = Some(
                earliest_reset_at.map_or(reset_at, |current: DateTime<Utc>| current.min(reset_at)),
            );
        }
        let Some(reset_at) = earliest_reset_at else {
            return Ok(None);
        };

        let Some(raw_last_probe_at) = self
            .state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await?
        else {
            return Ok(None);
        };
        let Ok(last_probe_at) = DateTime::parse_from_rfc3339(&raw_last_probe_at) else {
            return Ok(None);
        };
        let probe_due_at = last_probe_at
            .with_timezone(&Utc)
            .checked_add_signed(safe_cooldown_duration(
                self.codex.usage_limit_recheck_seconds,
            ))
            .unwrap_or(reset_at);
        if now >= probe_due_at {
            return Ok(None);
        }

        Ok(Some(QuotaBlock {
            reset_at,
            retry_at: reset_at.min(probe_due_at),
        }))
    }
}

fn quota_retry_at(
    now: DateTime<Utc>,
    reset_at: DateTime<Utc>,
    recheck_seconds: u64,
) -> DateTime<Utc> {
    let recheck_at = now
        .checked_add_signed(safe_cooldown_duration(recheck_seconds))
        .unwrap_or(reset_at);
    reset_at.min(recheck_at)
}

fn error_chain_summary(err: &anyhow::Error) -> String {
    err.chain()
        .map(ToString::to_string)
        .filter(|cause| !cause.trim().is_empty())
        .collect::<Vec<_>>()
        .join(": ")
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

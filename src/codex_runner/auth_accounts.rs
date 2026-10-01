//! Configured accounts in the order used by reviews and Usage requests.

use crate::config::CodexConfig;

pub(crate) const PRIMARY_AUTH_ACCOUNT_NAME: &str = "primary";

/// Identifies the host credentials and their persisted quota marker.
#[derive(Debug, Clone)]
pub(crate) struct ConfiguredAuthAccount {
    pub(crate) name: String,
    pub(crate) auth_host_path: String,
    pub(crate) state_key: String,
}

/// Returns the primary account first, then fallbacks in configuration order.
pub(crate) fn configured_auth_accounts(codex: &CodexConfig) -> Vec<ConfiguredAuthAccount> {
    let mut accounts = vec![ConfiguredAuthAccount {
        name: PRIMARY_AUTH_ACCOUNT_NAME.to_string(),
        auth_host_path: codex.auth_host_path.clone(),
        state_key: auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, &codex.auth_host_path),
    }];
    accounts.extend(
        codex
            .fallback_auth_accounts
            .iter()
            .map(|account| ConfiguredAuthAccount {
                name: account.name.clone(),
                auth_host_path: account.auth_host_path.clone(),
                state_key: auth_account_state_key(&account.name, &account.auth_host_path),
            }),
    );
    accounts
}

/// Keeps quota markers separate when an account's host credentials change.
pub(crate) fn auth_account_state_key(name: &str, auth_host_path: &str) -> String {
    format!("{name}::{auth_host_path}")
}

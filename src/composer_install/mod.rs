mod auth;
#[cfg(test)]
mod auth_lookup_tests;
#[cfg(test)]
mod auth_prepare_tests;
mod command;
mod output;

use crate::feature_flags::FeatureFlagSnapshot;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub use auth::{
    ComposerAuthLookup, ComposerAuthLookupAttempt, PreparedComposerAuth, composer_debug_lines,
    prepare_composer_auth, resolve_composer_auth,
};
pub use command::composer_install_exec_command;
pub use output::{
    ComposerInstallExecOutput, composer_install_result_from_exec_output,
    redact_composer_related_output,
};

pub const COMPOSER_AUTH_VARIABLE_KEY: &str = "COMPOSER_AUTH";
pub const COMPOSER_SKIP_MARKER: &str = "CODEX_COMPOSER_SKIP";
pub const COMPOSER_INSTALL_TURN_ID: &str = "composer-install";
pub const DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS: u64 = 300;
pub(crate) const COMPOSER_SKIP_EXIT_CODE: i64 = 86;
pub(crate) const COMPOSER_SKIP_REASON_MISSING_JSON: &str = "missing-composer-json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ComposerInstallMode {
    Full,
    Safe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ComposerInstallResult {
    pub attempted: bool,
    pub success: bool,
    pub mode: ComposerInstallMode,
    #[serde(default)]
    pub auth_source: Option<String>,
    #[serde(default)]
    pub log_excerpt: Option<String>,
}

impl ComposerInstallMode {
    #[must_use]
    pub fn for_flags(flags: &FeatureFlagSnapshot) -> Option<Self> {
        if !flags.composer_install {
            return None;
        }

        Some(if flags.composer_safe_install {
            Self::Safe
        } else {
            Self::Full
        })
    }

    #[must_use]
    pub fn command_label(self) -> &'static str {
        match self {
            Self::Full => "composer install --no-interaction --no-progress --ignore-platform-reqs",
            Self::Safe => {
                "composer install --no-dev --no-scripts --no-plugins --prefer-dist --no-interaction --no-progress --ignore-platform-reqs"
            }
        }
    }
}

impl ComposerInstallResult {
    #[must_use]
    pub fn skipped(mode: ComposerInstallMode, auth_source: Option<String>) -> Self {
        Self {
            attempted: false,
            success: true,
            mode,
            auth_source,
            log_excerpt: None,
        }
    }

    #[must_use]
    pub fn succeeded(
        mode: ComposerInstallMode,
        auth_source: Option<String>,
        log_excerpt: Option<String>,
    ) -> Self {
        Self {
            attempted: true,
            success: true,
            mode,
            auth_source,
            log_excerpt,
        }
    }

    #[must_use]
    pub fn failed(
        mode: ComposerInstallMode,
        auth_source: Option<String>,
        log_excerpt: String,
    ) -> Self {
        Self {
            attempted: true,
            success: false,
            mode,
            auth_source,
            log_excerpt: Some(log_excerpt),
        }
    }
}

#[must_use]
pub fn composer_install_timeout_seconds(remaining: Duration) -> Option<u64> {
    if remaining.is_zero() {
        return None;
    }

    let rounded_up = remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() > 0));
    Some(rounded_up.min(DEFAULT_COMPOSER_INSTALL_TIMEOUT_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::feature_flags::FeatureFlagSnapshot;
    use std::time::Duration;

    #[test]
    fn mode_defaults_to_full_when_safe_flag_is_disabled() {
        assert_eq!(
            ComposerInstallMode::for_flags(&FeatureFlagSnapshot {
                composer_install: true,
                composer_safe_install: false,
                ..FeatureFlagSnapshot::default()
            }),
            Some(ComposerInstallMode::Full)
        );
    }

    #[test]
    fn mode_uses_safe_install_when_safe_flag_is_enabled() {
        assert_eq!(
            ComposerInstallMode::for_flags(&FeatureFlagSnapshot {
                composer_install: true,
                composer_safe_install: true,
                ..FeatureFlagSnapshot::default()
            }),
            Some(ComposerInstallMode::Safe)
        );
    }

    #[test]
    fn composer_install_timeout_seconds_rounds_up_subsecond_budget() {
        assert_eq!(
            composer_install_timeout_seconds(Duration::from_millis(1)),
            Some(1)
        );
        assert_eq!(
            composer_install_timeout_seconds(Duration::from_millis(1500)),
            Some(2)
        );
        assert_eq!(composer_install_timeout_seconds(Duration::ZERO), None);
    }
}

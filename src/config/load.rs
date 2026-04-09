use super::defaults::{
    default_security_context_session_override, default_security_review_session_override,
};
use super::{Config, SessionModeOverrideConfig};
use anyhow::{Context, Result};
use serde::Deserialize;
use serde::de::Deserializer;
use std::env;

/// # Errors
///
/// Returns an error if configuration files or environment overrides cannot be
/// loaded or parsed.
pub fn load_raw_config() -> Result<Config> {
    let path = env::var("CONFIG_PATH").unwrap_or_else(|_| "config.yaml".to_string());
    let builder = config::Config::builder()
        .add_source(config::File::with_name(&path))
        .add_source(config::Environment::with_prefix("CODEX_REVIEW").separator("__"));
    let cfg = builder
        .build()
        .with_context(|| format!("load config from {path}"))?;

    if legacy_proxy_config_present(&cfg) {
        tracing::warn!(
            "legacy proxy config detected but ignored; built-in proxy support has been removed"
        );
    }
    validate_no_legacy_reasoning_effort_config(&cfg)?;

    cfg.try_deserialize().context("deserialize config")
}

pub(crate) fn empty_string_as_none<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<String>::deserialize(deserializer)?;
    Ok(value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }))
}

pub(crate) fn legacy_proxy_config_present(cfg: &config::Config) -> bool {
    cfg.get_table("proxy").is_ok_and(|table| !table.is_empty())
}

fn validate_no_legacy_reasoning_effort_config(cfg: &config::Config) -> Result<()> {
    anyhow::ensure!(
        !cfg.get_table("codex.reasoning_effort")
            .is_ok_and(|table| !table.is_empty()),
        "codex.reasoning_effort has been replaced by codex.session_overrides.<mode>.reasoning_effort"
    );
    Ok(())
}

#[derive(Deserialize)]
struct RawSessionModeOverrideConfig {
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    reasoning_effort: Option<Option<String>>,
}

fn deserialize_session_override_with_default<'de, D>(
    deserializer: D,
    default: SessionModeOverrideConfig,
) -> std::result::Result<SessionModeOverrideConfig, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = Option::<RawSessionModeOverrideConfig>::deserialize(deserializer)?;
    let Some(raw) = raw else {
        return Ok(default);
    };

    Ok(SessionModeOverrideConfig {
        model: raw.model.or(default.model),
        reasoning_effort: match raw.reasoning_effort {
            Some(reasoning_effort) => reasoning_effort,
            None => default.reasoning_effort,
        },
    })
}

pub(crate) fn deserialize_security_context_session_override<'de, D>(
    deserializer: D,
) -> std::result::Result<SessionModeOverrideConfig, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_session_override_with_default(
        deserializer,
        default_security_context_session_override(),
    )
}

pub(crate) fn deserialize_security_review_session_override<'de, D>(
    deserializer: D,
) -> std::result::Result<SessionModeOverrideConfig, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_session_override_with_default(
        deserializer,
        default_security_review_session_override(),
    )
}

use super::defaults::default_docker_host;
use super::{BROWSER_MCP_REMOTE_DEBUGGING_PORT, CodexConfig, Config, SessionModeOverrideConfig};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::env;
use std::ops::Deref;
use url::Url;

const SUPPORTED_REASONING_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh"];
const SUPPORTED_REASONING_SUMMARIES: &[&str] = &["none", "auto", "detailed"];
const MIB_BYTES: u64 = 1024 * 1024;
const MAX_WORK_TMPFS_SIZE_MIB: u64 = i64::MAX as u64 / MIB_BYTES;

#[derive(Clone, Debug)]
pub struct ValidatedConfig(Config);

impl ValidatedConfig {
    pub fn into_inner(self) -> Config {
        self.0
    }
}

impl AsRef<Config> for ValidatedConfig {
    fn as_ref(&self) -> &Config {
        &self.0
    }
}

impl Deref for ValidatedConfig {
    type Target = Config;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// # Errors
///
/// Returns an error if loaded configuration is semantically invalid.
pub fn validate_config(mut config: Config) -> Result<ValidatedConfig> {
    if config.codex.auth_host_path.is_empty() {
        config.codex.auth_host_path = config.codex.auth_mount_path.clone();
    }
    if config.docker.host.trim().is_empty() {
        config.docker.host = default_docker_host();
    }

    apply_gitlab_discovery_mcp_runtime_defaults(&mut config)?;
    validate_codex_auth_accounts(&config.codex)?;
    validate_work_tmpfs(&config.codex)?;
    validate_browser_mcp(&config.codex)?;
    validate_gitlab_discovery_mcp(&config.codex)?;
    validate_unique_injected_mcp_server_names(&config.codex)?;
    validate_distinct_http_and_gitlab_discovery_bind_addrs(&config)?;
    validate_mcp_server_overrides(&config.codex)?;
    validate_session_overrides(&config.codex)?;
    validate_reasoning_summary_overrides(&config.codex)?;

    Ok(ValidatedConfig(config))
}

pub(crate) fn apply_gitlab_discovery_mcp_runtime_defaults(config: &mut Config) -> Result<()> {
    if !config.codex.gitlab_discovery_mcp.enabled
        || !config
            .codex
            .gitlab_discovery_mcp
            .advertise_url
            .trim()
            .is_empty()
    {
        return Ok(());
    }

    let (bind_host, port) = parse_bind_addr(
        "codex.gitlab_discovery_mcp.bind_addr",
        &config.codex.gitlab_discovery_mcp.bind_addr,
    )?;
    let pod_ip = env::var("POD_IP")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    if let Some(pod_ip) = pod_ip {
        anyhow::ensure!(
            is_wildcard_host(&bind_host),
            "codex.gitlab_discovery_mcp.advertise_url cannot default from POD_IP when codex.gitlab_discovery_mcp.bind_addr listens on {bind_host}; use a wildcard bind_addr or set advertise_url explicitly"
        );
        let pod_ip = pod_ip
            .parse::<std::net::IpAddr>()
            .context("parse POD_IP for gitlab discovery MCP advertise_url default")?;
        if bind_host_supports_ip(&bind_host, pod_ip) {
            let host = match pod_ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };
            config.codex.gitlab_discovery_mcp.advertise_url = format!("http://{host}:{port}/mcp");
        } else {
            config.codex.gitlab_discovery_mcp.advertise_url =
                format!("http://host.docker.internal:{port}/mcp");
        }
    } else {
        anyhow::ensure!(
            is_wildcard_host(&bind_host),
            "codex.gitlab_discovery_mcp.advertise_url cannot default to host.docker.internal when codex.gitlab_discovery_mcp.bind_addr listens on {bind_host}; use a wildcard bind_addr or set advertise_url explicitly"
        );
        config.codex.gitlab_discovery_mcp.advertise_url =
            format!("http://host.docker.internal:{port}/mcp");
    }

    Ok(())
}

#[must_use]
pub fn gitlab_discovery_mcp_uses_cluster_service_advertise_url(codex: &CodexConfig) -> bool {
    if !codex.gitlab_discovery_mcp.enabled {
        return false;
    }

    let Ok(advertise_url) = Url::parse(&codex.gitlab_discovery_mcp.advertise_url) else {
        return false;
    };
    let Some(host) = advertise_url.host_str() else {
        return false;
    };

    host.ends_with(".svc.cluster.local") || host.ends_with(".cluster.local")
}

fn validate_work_tmpfs(codex: &CodexConfig) -> Result<()> {
    if let Some(size_mib) = codex.work_tmpfs.size_mib {
        anyhow::ensure!(
            size_mib > 0,
            "codex.work_tmpfs.size_mib must be greater than 0 when set"
        );
        anyhow::ensure!(
            size_mib <= MAX_WORK_TMPFS_SIZE_MIB,
            "codex.work_tmpfs.size_mib must be at most {MAX_WORK_TMPFS_SIZE_MIB}"
        );
    }
    Ok(())
}

fn validate_codex_auth_accounts(codex: &CodexConfig) -> Result<()> {
    anyhow::ensure!(
        !codex.auth_host_path.trim().is_empty(),
        "codex.auth_host_path must not be empty"
    );

    let mut names = HashSet::new();
    let mut host_paths = HashSet::new();
    host_paths.insert(codex.auth_host_path.as_str());

    for account in &codex.fallback_auth_accounts {
        anyhow::ensure!(
            !account.name.trim().is_empty(),
            "codex.fallback_auth_accounts[].name must not be empty"
        );
        anyhow::ensure!(
            account.name != "primary",
            "codex.fallback_auth_accounts[].name 'primary' is reserved"
        );
        anyhow::ensure!(
            !account.auth_host_path.trim().is_empty(),
            "codex.fallback_auth_accounts[].auth_host_path must not be empty"
        );
        anyhow::ensure!(
            names.insert(account.name.as_str()),
            "duplicate codex fallback account name: {}",
            account.name
        );
        anyhow::ensure!(
            host_paths.insert(account.auth_host_path.as_str()),
            "duplicate codex auth_host_path across primary/fallback accounts: {}",
            account.auth_host_path
        );
    }

    Ok(())
}

fn validate_mcp_server_overrides(codex: &CodexConfig) -> Result<()> {
    for server in codex
        .mcp_server_overrides
        .review
        .keys()
        .chain(codex.mcp_server_overrides.mention.keys())
    {
        anyhow::ensure!(
            !server.trim().is_empty(),
            "codex.mcp_server_overrides keys must not be empty"
        );
        anyhow::ensure!(
            is_valid_mcp_server_name(server),
            "codex.mcp_server_overrides keys must match ^[a-zA-Z0-9_-]+$"
        );
    }

    Ok(())
}

fn validate_browser_mcp(codex: &CodexConfig) -> Result<()> {
    if !codex.browser_mcp.enabled {
        return Ok(());
    }

    anyhow::ensure!(
        !codex.browser_mcp.server_name.trim().is_empty(),
        "codex.browser_mcp.server_name must not be empty"
    );
    anyhow::ensure!(
        codex
            .browser_mcp
            .server_name
            .chars()
            .all(|ch| !ch.is_control()),
        "codex.browser_mcp.server_name must not contain control characters"
    );
    anyhow::ensure!(
        is_valid_mcp_server_name(&codex.browser_mcp.server_name),
        "codex.browser_mcp.server_name must match ^[a-zA-Z0-9_-]+$"
    );
    anyhow::ensure!(
        !codex.browser_mcp.browser_image.trim().is_empty(),
        "codex.browser_mcp.browser_image must not be empty"
    );
    anyhow::ensure!(
        !codex.browser_mcp.mcp_command.trim().is_empty(),
        "codex.browser_mcp.mcp_command must not be empty"
    );
    anyhow::ensure!(
        codex.browser_mcp.remote_debugging_port == BROWSER_MCP_REMOTE_DEBUGGING_PORT,
        "codex.browser_mcp.remote_debugging_port must be {BROWSER_MCP_REMOTE_DEBUGGING_PORT}"
    );

    for arg in &codex.browser_mcp.browser_args {
        let trimmed = arg.trim();
        anyhow::ensure!(
            trimmed != "--remote-debugging-port"
                && !trimmed.starts_with("--remote-debugging-port="),
            "codex.browser_mcp.browser_args must not override --remote-debugging-port"
        );
        anyhow::ensure!(
            trimmed != "--remote-debugging-address"
                && !trimmed.starts_with("--remote-debugging-address="),
            "codex.browser_mcp.browser_args must not override --remote-debugging-address"
        );
    }

    Ok(())
}

fn validate_gitlab_discovery_mcp(codex: &CodexConfig) -> Result<()> {
    if !codex.gitlab_discovery_mcp.enabled {
        return Ok(());
    }

    let mcp = &codex.gitlab_discovery_mcp;
    anyhow::ensure!(
        !mcp.server_name.trim().is_empty(),
        "codex.gitlab_discovery_mcp.server_name must not be empty"
    );
    anyhow::ensure!(
        mcp.server_name.chars().all(|ch| !ch.is_control()),
        "codex.gitlab_discovery_mcp.server_name must not contain control characters"
    );
    anyhow::ensure!(
        is_valid_mcp_server_name(&mcp.server_name),
        "codex.gitlab_discovery_mcp.server_name must match ^[a-zA-Z0-9_-]+$"
    );
    anyhow::ensure!(
        !mcp.bind_addr.trim().is_empty(),
        "codex.gitlab_discovery_mcp.bind_addr must not be empty"
    );

    let bind_addr = Url::parse(&format!("tcp://{}", mcp.bind_addr))
        .context("parse codex.gitlab_discovery_mcp.bind_addr")?;
    anyhow::ensure!(
        bind_addr.port().is_some_and(|port| port != 0),
        "codex.gitlab_discovery_mcp.bind_addr must include a non-zero port"
    );
    anyhow::ensure!(
        !mcp.advertise_url.trim().is_empty(),
        "codex.gitlab_discovery_mcp.advertise_url must not be empty"
    );

    let advertise_url =
        Url::parse(&mcp.advertise_url).context("parse codex.gitlab_discovery_mcp.advertise_url")?;
    anyhow::ensure!(
        matches!(advertise_url.scheme(), "http" | "https"),
        "codex.gitlab_discovery_mcp.advertise_url must use http or https"
    );
    advertise_url
        .host_str()
        .context("parse codex.gitlab_discovery_mcp.advertise_url host")?;

    anyhow::ensure!(
        !mcp.clone_root.trim().is_empty(),
        "codex.gitlab_discovery_mcp.clone_root must not be empty"
    );
    anyhow::ensure!(
        mcp.clone_root.starts_with('/'),
        "codex.gitlab_discovery_mcp.clone_root must be an absolute path"
    );

    for (index, rule) in mcp.allow.iter().enumerate() {
        let rule_name = format!("codex.gitlab_discovery_mcp.allow[{index}]");
        anyhow::ensure!(
            !(rule.source_repos.is_empty() && rule.source_group_prefixes.is_empty()),
            "{rule_name} must include at least one source_repos or source_group_prefixes entry"
        );
        anyhow::ensure!(
            !(rule.target_repos.is_empty() && rule.target_groups.is_empty()),
            "{rule_name} must include at least one target_repos or target_groups entry"
        );

        for (field, values) in [
            ("source_repos", &rule.source_repos),
            ("source_group_prefixes", &rule.source_group_prefixes),
            ("target_repos", &rule.target_repos),
            ("target_groups", &rule.target_groups),
        ] {
            for value in values {
                anyhow::ensure!(
                    !value.trim().is_empty(),
                    "{rule_name}.{field} values must not be empty"
                );
                anyhow::ensure!(
                    value.chars().all(|ch| !ch.is_control()),
                    "{rule_name}.{field} values must not contain control characters"
                );
            }
        }
    }

    Ok(())
}

fn validate_unique_injected_mcp_server_names(codex: &CodexConfig) -> Result<()> {
    if codex.browser_mcp.enabled
        && codex.gitlab_discovery_mcp.enabled
        && codex.browser_mcp.server_name == codex.gitlab_discovery_mcp.server_name
    {
        anyhow::bail!(
            "codex.browser_mcp.server_name and codex.gitlab_discovery_mcp.server_name must be distinct when both MCP injectors are enabled"
        );
    }

    Ok(())
}

fn validate_distinct_http_and_gitlab_discovery_bind_addrs(config: &Config) -> Result<()> {
    if !config.codex.gitlab_discovery_mcp.enabled {
        return Ok(());
    }

    let (http_host, http_port) = parse_bind_addr("server.bind_addr", &config.server.bind_addr)?;
    let (mcp_host, mcp_port) = parse_bind_addr(
        "codex.gitlab_discovery_mcp.bind_addr",
        &config.codex.gitlab_discovery_mcp.bind_addr,
    )?;

    if http_port == mcp_port
        && (http_host == mcp_host || is_wildcard_host(&http_host) || is_wildcard_host(&mcp_host))
    {
        anyhow::bail!(
            "server.bind_addr and codex.gitlab_discovery_mcp.bind_addr must not target the same listener socket"
        );
    }

    Ok(())
}

fn parse_bind_addr(field: &str, value: &str) -> Result<(String, u16)> {
    let url = Url::parse(&format!("tcp://{value}")).with_context(|| format!("parse {field}"))?;
    let host = url
        .host_str()
        .map(ToOwned::to_owned)
        .with_context(|| format!("{field} must include a host"))?;
    let port = url
        .port()
        .with_context(|| format!("{field} must include a port"))?;

    Ok((host, port))
}

fn is_wildcard_host(host: &str) -> bool {
    matches!(host, "0.0.0.0" | "::" | "[::]" | "0:0:0:0:0:0:0:0")
}

fn bind_host_supports_ip(bind_host: &str, ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => bind_host == "0.0.0.0",
        std::net::IpAddr::V6(_) => matches!(bind_host, "::" | "[::]" | "0:0:0:0:0:0:0:0"),
    }
}

fn validate_session_mode_override(
    field: &str,
    override_config: &SessionModeOverrideConfig,
) -> Result<()> {
    if let Some(model) = override_config.model.as_deref() {
        anyhow::ensure!(
            !model.trim().is_empty(),
            "codex.session_overrides.{field}.model must not be empty"
        );
        anyhow::ensure!(
            model.chars().all(|ch| !ch.is_control()),
            "codex.session_overrides.{field}.model must not contain control characters"
        );
    }

    let Some(reasoning_effort) = override_config.reasoning_effort.as_deref() else {
        return Ok(());
    };
    anyhow::ensure!(
        !reasoning_effort.trim().is_empty(),
        "codex.session_overrides.{field}.reasoning_effort must not be empty"
    );
    anyhow::ensure!(
        reasoning_effort.chars().all(|ch| !ch.is_control()),
        "codex.session_overrides.{field}.reasoning_effort must not contain control characters"
    );
    anyhow::ensure!(
        SUPPORTED_REASONING_EFFORTS.contains(&reasoning_effort),
        "codex.session_overrides.{field}.reasoning_effort must be one of: {}",
        SUPPORTED_REASONING_EFFORTS.join(", ")
    );

    Ok(())
}

fn validate_session_overrides(codex: &CodexConfig) -> Result<()> {
    for (field, override_config) in [
        ("review", &codex.session_overrides.review),
        ("mention", &codex.session_overrides.mention),
        (
            "security_context",
            &codex.session_overrides.security_context,
        ),
        ("security_review", &codex.session_overrides.security_review),
    ] {
        validate_session_mode_override(field, override_config)?;
    }

    Ok(())
}

fn validate_reasoning_summary_overrides(codex: &CodexConfig) -> Result<()> {
    for (field, value) in [
        ("review", codex.reasoning_summary.review.as_deref()),
        ("mention", codex.reasoning_summary.mention.as_deref()),
    ] {
        let Some(value) = value else {
            continue;
        };
        anyhow::ensure!(
            !value.trim().is_empty(),
            "codex.reasoning_summary.{field} must not be empty"
        );
        anyhow::ensure!(
            value.chars().all(|ch| !ch.is_control()),
            "codex.reasoning_summary.{field} must not contain control characters"
        );
        anyhow::ensure!(
            SUPPORTED_REASONING_SUMMARIES.contains(&value),
            "codex.reasoning_summary.{field} must be one of: {}",
            SUPPORTED_REASONING_SUMMARIES.join(", ")
        );
    }

    Ok(())
}

fn is_valid_mcp_server_name(name: &str) -> bool {
    // Codex CLI `-c key=value` overrides split nested config paths on `.`, so
    // names that require quoted TOML dotted-key segments cannot be targeted by
    // our runtime override path. Codex itself also rejects MCP server names
    // outside this upstream pattern during MCP startup.
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
}

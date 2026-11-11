//! Validates the chart's OIDC configuration through the runtime config parser.

use codex_gitlab_code_review::config::{Config, validate_config};
use serde::Deserialize;
use std::{collections::BTreeMap, process::Command};

#[derive(Deserialize)]
struct ConfigMap {
    data: BTreeMap<String, String>,
}

#[test]
fn chart_oidc_config_loads_with_a_secret_override() -> anyhow::Result<()> {
    let output = Command::new("helm")
        .args([
            "template",
            "oidc-test",
            "charts/codex-gitlab-review",
            "--show-only",
            "templates/configmap.yaml",
            "--set",
            "config.server.statusUiEnabled=true",
            "--set",
            "config.server.oidc.enabled=true",
            "--set",
            "config.server.oidc.issuerUrl=https://auth.example.com/application/o/review/",
            "--set",
            "config.server.oidc.clientId=review",
            "--set",
            "config.server.oidc.redirectUrl=https://review.example.com/auth/callback",
            "--set",
            "config.server.oidc.clientSecret.existingSecret=review-oidc",
        ])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "helm template failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout)?;
    let configmap: ConfigMap = config::Config::builder()
        .add_source(config::File::from_str(&rendered, config::FileFormat::Yaml))
        .build()?
        .try_deserialize()?;
    let yaml = &configmap.data["config.yaml"];
    let config: Config = config::Config::builder()
        .add_source(config::File::from_str(yaml, config::FileFormat::Yaml))
        .set_override("server.oidc.client_secret", "test-secret-from-kubernetes")?
        .build()?
        .try_deserialize()?;
    validate_config(config)?;
    Ok(())
}

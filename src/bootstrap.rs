use anyhow::Result;
use async_trait::async_trait;
use std::time::Duration;
use tracing::info;

use crate::codex_runner::docker::wait_for_docker_ready;
use crate::config::{DockerConfig, ValidatedConfig, load_validated_config};
use crate::service_factory::{
    RuntimeMode, ServiceBundle, ServiceFactoryOptions, build_service_bundle,
};

const STARTUP_DOCKER_READY_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_DOCKER_READY_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy)]
pub struct BootstrapOptions {
    pub run_once: bool,
    pub force_dry_run: bool,
    pub log_all_json: bool,
    pub dev_mode: bool,
}

pub type BootstrappedRuntime = ServiceBundle;

#[async_trait]
trait DockerReadinessProbe: Send + Sync {
    async fn wait_for_startup_docker(&self, docker_cfg: &DockerConfig) -> Result<()>;
}

struct RealDockerReadinessProbe;

#[async_trait]
impl DockerReadinessProbe for RealDockerReadinessProbe {
    async fn wait_for_startup_docker(&self, docker_cfg: &DockerConfig) -> Result<()> {
        info!(
            docker_host = docker_cfg.host.as_str(),
            timeout_secs = STARTUP_DOCKER_READY_TIMEOUT.as_secs(),
            "waiting for docker daemon readiness"
        );
        wait_for_docker_ready(
            docker_cfg,
            STARTUP_DOCKER_READY_TIMEOUT,
            STARTUP_DOCKER_READY_POLL_INTERVAL,
        )
        .await?;
        info!(
            docker_host = docker_cfg.host.as_str(),
            "docker daemon is ready"
        );
        Ok(())
    }
}

pub async fn bootstrap_runtime(options: BootstrapOptions) -> Result<BootstrappedRuntime> {
    let config = load_validated_config(options.dev_mode)?;
    let readiness_probe = RealDockerReadinessProbe;
    bootstrap_runtime_from_config_with_probe(config, options, &readiness_probe).await
}

pub async fn bootstrap_runtime_from_config(
    config: ValidatedConfig,
    options: BootstrapOptions,
) -> Result<BootstrappedRuntime> {
    let readiness_probe = RealDockerReadinessProbe;
    bootstrap_runtime_from_config_with_probe(config, options, &readiness_probe).await
}

async fn bootstrap_runtime_from_config_with_probe(
    config: ValidatedConfig,
    options: BootstrapOptions,
    readiness_probe: &dyn DockerReadinessProbe,
) -> Result<BootstrappedRuntime> {
    wait_for_startup_docker_if_needed(config.as_ref(), options, readiness_probe).await?;
    build_service_bundle(
        config,
        ServiceFactoryOptions {
            run_once: options.run_once,
            force_dry_run: options.force_dry_run,
            log_all_json: options.log_all_json,
            runtime_mode: if options.dev_mode {
                RuntimeMode::Development
            } else {
                RuntimeMode::Normal
            },
        },
    )
    .await
}

async fn wait_for_startup_docker_if_needed(
    config: &crate::config::Config,
    options: BootstrapOptions,
    readiness_probe: &dyn DockerReadinessProbe,
) -> Result<()> {
    if options.dev_mode {
        Ok(())
    } else {
        readiness_probe
            .wait_for_startup_docker(&config.docker)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, test_builder::ConfigBuilder};
    use std::sync::Mutex;

    struct RecordingDockerReadinessProbe {
        hosts: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DockerReadinessProbe for RecordingDockerReadinessProbe {
        async fn wait_for_startup_docker(&self, docker_cfg: &DockerConfig) -> Result<()> {
            self.hosts
                .lock()
                .expect("readiness hosts lock")
                .push(docker_cfg.host.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn startup_docker_readiness_waits_in_normal_mode() -> Result<()> {
        let config = test_config();
        let probe = RecordingDockerReadinessProbe {
            hosts: Mutex::new(Vec::new()),
        };

        wait_for_startup_docker_if_needed(&config, test_options(false), &probe).await?;

        assert_eq!(
            *probe.hosts.lock().expect("readiness hosts lock"),
            vec![config.docker.host]
        );
        Ok(())
    }

    #[tokio::test]
    async fn startup_docker_readiness_skips_dev_mode() -> Result<()> {
        let config = test_config();
        let probe = RecordingDockerReadinessProbe {
            hosts: Mutex::new(Vec::new()),
        };

        wait_for_startup_docker_if_needed(&config, test_options(true), &probe).await?;

        assert!(probe.hosts.lock().expect("readiness hosts lock").is_empty());
        Ok(())
    }

    fn test_options(dev_mode: bool) -> BootstrapOptions {
        BootstrapOptions {
            run_once: true,
            force_dry_run: false,
            log_all_json: false,
            dev_mode,
        }
    }

    fn test_config() -> Config {
        ConfigBuilder::for_service_factory_tests().build()
    }
}

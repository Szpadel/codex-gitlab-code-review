use anyhow::Result;

use crate::config::ValidatedConfig;
use crate::service_factory::{
    RuntimeMode, ServiceBundle, ServiceFactoryOptions, build_service_bundle,
    load_config as load_config_inner,
};

#[derive(Debug, Clone, Copy)]
pub(crate) struct BootstrapOptions {
    pub(crate) run_once: bool,
    pub(crate) force_dry_run: bool,
    pub(crate) log_all_json: bool,
    pub(crate) dev_mode: bool,
}

pub(crate) type BootstrappedRuntime = ServiceBundle;

pub(crate) async fn bootstrap_runtime(
    config: ValidatedConfig,
    options: BootstrapOptions,
) -> Result<BootstrappedRuntime> {
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

pub(crate) fn load_config(dev_mode: bool) -> Result<ValidatedConfig> {
    load_config_inner(dev_mode)
}

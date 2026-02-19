use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::gitlab::GitLabApi;
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;

pub(crate) mod mention;
pub(crate) mod review;

#[derive(Clone)]
pub(crate) struct FlowShared {
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) state: Arc<ReviewStateStore>,
    pub(crate) codex: Arc<dyn CodexRunner>,
    pub(crate) bot_user_id: u64,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) shutdown: Arc<AtomicBool>,
}

impl FlowShared {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: Config,
        gitlab: Arc<dyn GitLabApi>,
        state: Arc<ReviewStateStore>,
        codex: Arc<dyn CodexRunner>,
        bot_user_id: u64,
        semaphore: Arc<Semaphore>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config,
            gitlab,
            state,
            codex,
            bot_user_id,
            semaphore,
            shutdown,
        }
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

#[async_trait]
pub(crate) trait MergeRequestFlow: Send + Sync {
    fn flow_name(&self) -> &'static str;

    async fn clear_stale_in_progress(&self) -> Result<()>;

    async fn recover_in_progress(&self) -> Result<()>;
}

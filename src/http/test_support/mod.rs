pub(crate) mod config;
pub(crate) mod run_history;
pub(crate) mod server;
pub(crate) mod skills_fs;
pub(crate) mod transcript_fakes;

use super::{HttpServices, TranscriptBackfillSource, app_router, app_router_with_dev_tools};
use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::dev_mode::DevToolsService;
use crate::state::ReviewStateStore;
use anyhow::Result;
use std::sync::Arc;

pub(crate) use config::test_config;
pub(crate) use run_history::{
    RunFixture, agent_message_event, agent_message_event_at, empty_reasoning_event,
    insert_run_history, insert_run_history_events, reasoning_event, run_event,
    turn_completed_event, turn_completed_event_at, turn_started_event, turn_started_event_at,
};
pub(crate) use server::{test_client, test_client_builder, test_get};
pub(crate) use skills_fs::{TestAuthDir, build_skill_zip, write_skill};
pub(crate) use transcript_fakes::{
    CapturingTranscriptBackfillSource, CountingThreadReaderRunner,
    ErroringTranscriptBackfillSource, SequencedTranscriptBackfillSource,
    StaticTranscriptBackfillSource, ThreadReaderRunner, TurnScopedFallbackTranscriptBackfillSource,
};

pub(crate) struct HttpTestServer {
    pub state: Arc<ReviewStateStore>,
    pub services: Arc<HttpServices>,
    pub address: String,
}

pub(crate) struct HttpTestServerBuilder {
    config: Config,
    runtime_mode: Option<String>,
    transcript_backfill_source: Option<Arc<dyn TranscriptBackfillSource>>,
    runner: Option<Arc<dyn CodexRunner>>,
    dev_tools_enabled: bool,
}

impl HttpTestServerBuilder {
    pub(crate) fn new() -> Self {
        Self {
            config: test_config(),
            runtime_mode: None,
            transcript_backfill_source: None,
            runner: None,
            dev_tools_enabled: false,
        }
    }

    pub(crate) fn with_config(mut self, config: Config) -> Self {
        self.config = config;
        self
    }

    pub(crate) fn with_runtime_mode(mut self, runtime_mode: impl Into<String>) -> Self {
        self.runtime_mode = Some(runtime_mode.into());
        self
    }

    pub(crate) fn with_transcript_backfill_source(
        mut self,
        transcript_backfill_source: Arc<dyn TranscriptBackfillSource>,
    ) -> Self {
        self.transcript_backfill_source = Some(transcript_backfill_source);
        self
    }

    pub(crate) fn with_runner(mut self, runner: Arc<dyn CodexRunner>) -> Self {
        self.runner = Some(runner);
        self
    }

    pub(crate) fn with_dev_tools(mut self) -> Self {
        self.dev_tools_enabled = true;
        self
    }

    pub(crate) async fn spawn(self) -> Result<HttpTestServer> {
        crate::gitlab::tls::ensure_reqwest_rustls_provider();
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let dev_tools = self
            .dev_tools_enabled
            .then(|| Arc::new(DevToolsService::new(&self.config.database.path)));
        let mut services = HttpServices::new(self.config, Arc::clone(&state), false, self.runner);
        if let Some(runtime_mode) = self.runtime_mode {
            services = services.with_runtime_mode(&runtime_mode);
        }
        if let Some(transcript_backfill_source) = self.transcript_backfill_source {
            services = services.with_transcript_backfill_source(transcript_backfill_source);
        }
        let services = Arc::new(services);
        let app = match dev_tools {
            Some(dev_tools) => app_router_with_dev_tools(Arc::clone(&services), Some(dev_tools)),
            None => app_router(Arc::clone(&services)),
        };
        let address = server::spawn_test_server(app).await?.to_string();
        Ok(HttpTestServer {
            state,
            services,
            address,
        })
    }
}

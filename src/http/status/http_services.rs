use super::{
    AdminService, BackfillService, RateLimitService, SkillsService, StatusService,
    TranscriptBackfillSource, UsageService,
};
use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::retry::RunRetryStatusProvider;
use crate::skills::SkillsManager;
use crate::state::ReviewStateStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct HttpServices {
    pub status: Arc<StatusService>,
    pub admin: Arc<AdminService>,
    pub skills: Arc<SkillsService>,
    pub ratelimit: Arc<RateLimitService>,
    pub usage: Arc<UsageService>,
    pub backfill: Arc<BackfillService>,
    config: Config,
    state: Arc<ReviewStateStore>,
    runner: Option<Arc<dyn CodexRunner>>,
    run_once: bool,
    runtime_mode: String,
    transcript_backfill_source_override: Option<Arc<dyn TranscriptBackfillSource>>,
    retry_status_provider: Option<Arc<dyn RunRetryStatusProvider>>,
}

impl HttpServices {
    #[must_use]
    pub fn new(
        config: Config,
        state: Arc<ReviewStateStore>,
        run_once: bool,
        // Status-page reads stay on persisted events plus local session history.
        // The usage page is the only status UI path that performs live Codex
        // app-server reads because reset eligibility depends on current usage.
        runner: Option<Arc<dyn CodexRunner>>,
    ) -> Self {
        Self::build(
            config,
            state,
            runner,
            run_once,
            "normal".to_string(),
            None,
            None,
        )
    }

    #[must_use]
    pub fn with_runtime_mode(mut self, runtime_mode: &str) -> Self {
        self.runtime_mode = runtime_mode.to_string();
        self.rebuild_services();
        self
    }

    #[must_use]
    pub fn with_retry_status_provider(
        mut self,
        retry_status_provider: Arc<dyn RunRetryStatusProvider>,
    ) -> Self {
        self.retry_status_provider = Some(retry_status_provider);
        self.rebuild_services();
        self
    }

    #[must_use]
    pub fn with_transcript_backfill_source(
        mut self,
        transcript_backfill_source: Arc<dyn TranscriptBackfillSource>,
    ) -> Self {
        self.transcript_backfill_source_override = Some(transcript_backfill_source);
        self.rebuild_services();
        self
    }

    fn build(
        config: Config,
        state: Arc<ReviewStateStore>,
        runner: Option<Arc<dyn CodexRunner>>,
        run_once: bool,
        runtime_mode: String,
        transcript_backfill_source_override: Option<Arc<dyn TranscriptBackfillSource>>,
        retry_status_provider: Option<Arc<dyn RunRetryStatusProvider>>,
    ) -> Self {
        let feature_flag_availability = config.feature_flag_availability();
        let admin = Arc::new(AdminService::new(
            Arc::clone(&state),
            runtime_mode.clone(),
            config.server.status_ui_enabled,
            config.feature_flags.clone(),
            feature_flag_availability,
        ));
        let skills = Arc::new(SkillsService::new(SkillsManager::new(&config)));
        let ratelimit = Arc::new(RateLimitService::new(
            Arc::clone(&state),
            config.gitlab.targets.repos.list().to_vec(),
            config.gitlab.targets.groups.list().to_vec(),
        ));
        let usage = Arc::new(UsageService::new(
            &config,
            Arc::clone(&state),
            runner.clone(),
        ));
        let mut backfill_service = BackfillService::new(&config, Arc::clone(&state));
        if let Some(source) = transcript_backfill_source_override.clone() {
            backfill_service = backfill_service.with_transcript_backfill_source(source);
        }
        let backfill = Arc::new(backfill_service);
        let status = Arc::new(StatusService::new(
            &config,
            Arc::clone(&state),
            run_once,
            Arc::clone(&admin),
            Arc::clone(&ratelimit),
            Arc::clone(&backfill),
            retry_status_provider.clone(),
        ));

        Self {
            status,
            admin,
            skills,
            ratelimit,
            usage,
            backfill,
            config,
            state,
            runner,
            run_once,
            runtime_mode,
            transcript_backfill_source_override,
            retry_status_provider,
        }
    }

    fn rebuild_services(&mut self) {
        let rebuilt = Self::build(
            self.config.clone(),
            Arc::clone(&self.state),
            self.runner.clone(),
            self.run_once,
            self.runtime_mode.clone(),
            self.transcript_backfill_source_override.clone(),
            self.retry_status_provider.clone(),
        );
        self.status = rebuilt.status;
        self.admin = rebuilt.admin;
        self.skills = rebuilt.skills;
        self.ratelimit = rebuilt.ratelimit;
        self.usage = rebuilt.usage;
        self.backfill = rebuilt.backfill;
    }
}

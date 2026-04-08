use crate::codex_runner::CodexRunner;
use crate::flow::mention::MentionFlow;
use crate::flow::review::ReviewFlow;
use crate::flow::{ActiveTaskRegistry, MergeRequestFlow};
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::{debug, warn};

#[async_trait]
pub(crate) trait ScanCoordinator: Send + Sync {
    async fn recover_in_progress(&self) -> Result<()>;

    async fn clear_stale_flow_state(&self) -> Result<()>;
}

pub(crate) struct DefaultScanCoordinator {
    state: Arc<ReviewStateStore>,
    active_tasks: Arc<ActiveTaskRegistry>,
    codex: Arc<dyn CodexRunner>,
    general_review_flow: Arc<ReviewFlow>,
    security_review_flow: Arc<ReviewFlow>,
    mention_flow: Arc<MentionFlow>,
}

impl DefaultScanCoordinator {
    pub(crate) fn new(
        state: Arc<ReviewStateStore>,
        active_tasks: Arc<ActiveTaskRegistry>,
        codex: Arc<dyn CodexRunner>,
        general_review_flow: Arc<ReviewFlow>,
        security_review_flow: Arc<ReviewFlow>,
        mention_flow: Arc<MentionFlow>,
    ) -> Self {
        Self {
            state,
            active_tasks,
            codex,
            general_review_flow,
            security_review_flow,
            mention_flow,
        }
    }

    fn flows(&self) -> [&dyn MergeRequestFlow; 3] {
        [
            self.general_review_flow.as_ref(),
            self.security_review_flow.as_ref(),
            self.mention_flow.as_ref(),
        ]
    }

    async fn refresh_active_flow_state(&self) -> Result<()> {
        for review in self.active_tasks.active_reviews() {
            self.state
                .review_state
                .touch_in_progress_review_for_lane(
                    &review.repo,
                    review.iid,
                    &review.head_sha,
                    review.lane,
                )
                .await?;
        }
        for mention in self.active_tasks.active_mentions() {
            self.state
                .mention_commands
                .touch_in_progress_mention_command(
                    &mention.repo,
                    mention.iid,
                    &mention.discussion_id,
                    mention.trigger_note_id,
                    &mention.head_sha,
                )
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl ScanCoordinator for DefaultScanCoordinator {
    async fn recover_in_progress(&self) -> Result<()> {
        if let Err(err) = self.codex.stop_active_reviews().await {
            warn!(error = %err, "failed to stop active codex review containers");
        }
        for flow in self.flows() {
            debug!(flow = flow.flow_name(), "recover in-progress flow state");
            flow.recover_in_progress().await?;
        }
        Ok(())
    }

    async fn clear_stale_flow_state(&self) -> Result<()> {
        self.refresh_active_flow_state().await?;
        for flow in self.flows() {
            flow.clear_stale_in_progress().await?;
        }
        Ok(())
    }
}

//! Startup recovery and stale-state maintenance for merge-request flows.

use crate::codex_runner::CodexRunner;
use crate::flow::mention::MentionFlow;
use crate::flow::review::ReviewFlow;
use crate::flow::{ActiveTaskRegistry, MergeRequestFlow};
use crate::state::ReviewStateStore;
use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, warn};

/// Coordinates recovery across review and mention flows.
pub(crate) struct ScanCoordinator {
    state: Arc<ReviewStateStore>,
    active_tasks: Arc<ActiveTaskRegistry>,
    codex: Arc<dyn CodexRunner>,
    general_review_flow: Arc<ReviewFlow>,
    security_review_flow: Arc<ReviewFlow>,
    mention_flow: Arc<MentionFlow>,
}

impl ScanCoordinator {
    /// Shares the active flows and state used during recovery.
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

    /// Attempts to stop leftover containers before recovering each flow's persisted work.
    pub(crate) async fn recover_in_progress(&self) -> Result<()> {
        if let Err(err) = self.codex.stop_active_reviews().await {
            warn!(error = %err, "failed to stop active codex review containers");
        }
        for flow in self.flows() {
            debug!(flow = flow.flow_name(), "recover in-progress flow state");
            flow.recover_in_progress().await?;
        }
        Ok(())
    }

    /// Refreshes active claims before clearing stale flow state.
    pub(crate) async fn clear_stale_flow_state(&self) -> Result<()> {
        self.refresh_active_flow_state().await?;
        // The review sweep covers both lanes in one database operation.
        let maintenance_flows: [&dyn MergeRequestFlow; 2] = [
            self.general_review_flow.as_ref(),
            self.mention_flow.as_ref(),
        ];
        for flow in maintenance_flows {
            flow.clear_stale_in_progress().await?;
        }
        Ok(())
    }
}

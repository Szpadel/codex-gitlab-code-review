use super::transcript::build_mock_review_transcript;
use crate::codex_runner::{CodexResult, CodexRunner, ReviewComment, ReviewContext};
use crate::state::{ReviewStateStore, RunHistorySessionUpdate};
use anyhow::Result;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use std::sync::Arc;

pub struct MockCodexRunner {
    state: Arc<ReviewStateStore>,
}

impl MockCodexRunner {
    #[must_use]
    pub fn new(state: Arc<ReviewStateStore>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl CodexRunner for MockCodexRunner {
    async fn run_review(&self, ctx: ReviewContext) -> Result<CodexResult> {
        // Keep synthetic transcript events in the recent past so completed
        // runs never render future relative timestamps in the UI.
        let started_at = Utc::now() - Duration::seconds(6);
        let transcript = build_mock_review_transcript(
            ctx.lane,
            &ctx.repo,
            ctx.mr.iid,
            &ctx.head_sha,
            ctx.mr.title.as_deref(),
            started_at,
        );
        if let Some(run_history_id) = ctx.run_history_id {
            self.state
                .update_run_history_session(
                    run_history_id,
                    RunHistorySessionUpdate {
                        thread_id: Some(transcript.thread_id.clone()),
                        turn_id: Some(transcript.primary_turn_id.clone()),
                        review_thread_id: Some(transcript.thread_id.clone()),
                        auth_account_name: Some("dev-mode".to_string()),
                        ..RunHistorySessionUpdate::default()
                    },
                )
                .await?;
            self.state
                .append_run_history_events(run_history_id, &transcript.events)
                .await?;
        }
        Ok(CodexResult::Comment(ReviewComment {
            summary: transcript.summary.clone(),
            overall_explanation: Some(transcript.summary.clone()),
            overall_confidence_score: None,
            findings: Vec::new(),
            body: transcript.body,
        }))
    }
}

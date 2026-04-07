mod execution;
mod retry;
mod rewrite;
mod sources;

use self::execution::transcript_needs_backfill;
use self::sources::build_account_transcript_backfill_sources;
use crate::config::Config;
use crate::state::{ReviewStateStore, RunHistoryRecord, TranscriptBackfillState};
use crate::transcript_backfill::{SessionHistoryBackfillSource, TranscriptBackfillSource};
use anyhow::Result;
use chrono::Utc;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tracing::warn;

#[derive(Clone)]
pub struct BackfillService {
    state: Arc<ReviewStateStore>,
    default_transcript_backfill_source: Option<Arc<dyn TranscriptBackfillSource>>,
    account_transcript_backfill_sources: HashMap<String, Arc<dyn TranscriptBackfillSource>>,
    active_backfills: Arc<Mutex<HashSet<i64>>>,
    backfill_retry_after: Arc<Mutex<HashMap<i64, Instant>>>,
}

impl BackfillService {
    pub fn new(config: &Config, state: Arc<ReviewStateStore>) -> Self {
        let default_transcript_backfill_source = Arc::new(SessionHistoryBackfillSource::new(
            sources::primary_session_history_path(
                &config.codex.auth_host_path,
                &config.codex.auth_mount_path,
                config.codex.session_history_path.as_deref(),
            ),
        )) as Arc<dyn TranscriptBackfillSource>;
        let account_transcript_backfill_sources = build_account_transcript_backfill_sources(
            config,
            Arc::clone(&default_transcript_backfill_source),
        );

        Self {
            state,
            default_transcript_backfill_source: Some(default_transcript_backfill_source),
            account_transcript_backfill_sources,
            active_backfills: Arc::new(Mutex::new(HashSet::new())),
            backfill_retry_after: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    pub fn with_transcript_backfill_source(
        mut self,
        transcript_backfill_source: Arc<dyn TranscriptBackfillSource>,
    ) -> Self {
        self.account_transcript_backfill_sources.insert(
            "primary".to_string(),
            Arc::clone(&transcript_backfill_source),
        );
        self.default_transcript_backfill_source = Some(transcript_backfill_source);
        self
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn resolve_transcript_backfill(
        &self,
        run: &RunHistoryRecord,
        thread: Option<&super::ThreadSnapshot>,
    ) -> Result<Option<super::TranscriptBackfillSnapshot>> {
        if run.status != "done" {
            return Ok(None);
        }
        if !transcript_needs_backfill(run, thread) {
            return Ok(None);
        }

        let mut state = run.transcript_backfill_state;
        let mut error = run.transcript_backfill_error.clone();
        let has_transcript_backfill_source = self.transcript_backfill_source_for_run(run).is_some();
        let should_retry_missing_history = state == TranscriptBackfillState::Failed
            && error
                .as_deref()
                .is_some_and(|error| retry::should_retry_transcript_backfill_error(run, error));
        let should_retry_terminal_fallback = state == TranscriptBackfillState::Failed
            && error
                .as_deref()
                .is_some_and(|error| retry::is_final_retry_window_attempt_pending(run, error));
        let cooldown_elapsed = self.backfill_retry_due(run.id).await;
        let backfill_is_active = {
            let active_backfills = self.active_backfills.lock().await;
            active_backfills.contains(&run.id)
        };
        if (matches!(
            state,
            TranscriptBackfillState::NotRequested | TranscriptBackfillState::InProgress
        ) || ((should_retry_missing_history || should_retry_terminal_fallback)
            && cooldown_elapsed))
            && has_transcript_backfill_source
            && (run.review_thread_id.is_some() || run.thread_id.is_some())
            && !backfill_is_active
        {
            self.schedule_transcript_backfill(run.clone()).await?;
            state = TranscriptBackfillState::InProgress;
            error = None;
        }

        Ok(Some(super::TranscriptBackfillSnapshot { state, error }))
    }

    async fn schedule_transcript_backfill(&self, run: RunHistoryRecord) -> Result<()> {
        let Some(source) = self.transcript_backfill_source_for_run(&run) else {
            return Ok(());
        };

        {
            let mut active = self.active_backfills.lock().await;
            if !active.insert(run.id) {
                return Ok(());
            }
        }
        self.backfill_retry_after.lock().await.remove(&run.id);

        if let Err(err) = self
            .state
            .run_history
            .update_run_history_transcript_backfill(
                run.id,
                TranscriptBackfillState::InProgress,
                None,
            )
            .await
        {
            self.active_backfills.lock().await.remove(&run.id);
            return Err(err);
        }

        let state = Arc::clone(&self.state);
        let active_backfills = Arc::clone(&self.active_backfills);
        let backfill_retry_after = Arc::clone(&self.backfill_retry_after);
        let retry_window_open_at_attempt_start =
            retry::missing_history_retry_window_open(&run, Utc::now().timestamp());
        tokio::spawn(async move {
            let outcome = execution::run_transcript_backfill(
                state.as_ref(),
                source.as_ref(),
                &run,
                retry_window_open_at_attempt_start,
            )
            .await;
            match outcome {
                Ok(()) => {
                    backfill_retry_after.lock().await.remove(&run.id);
                }
                Err(err) => {
                    let raw_error_text = err.to_string();
                    let should_retry = retry::should_retry_transcript_backfill_failure(
                        &run,
                        &raw_error_text,
                        retry_window_open_at_attempt_start,
                    );
                    let error_text = retry::terminal_transcript_backfill_error_text(
                        &raw_error_text,
                        should_retry,
                    );
                    warn!(
                        run_id = run.id,
                        repo = %run.repo,
                        iid = run.iid,
                        error = %error_text,
                        "transcript backfill failed"
                    );
                    if should_retry {
                        backfill_retry_after.lock().await.insert(
                            run.id,
                            Instant::now() + retry::TRANSCRIPT_BACKFILL_RETRY_COOLDOWN,
                        );
                    } else {
                        backfill_retry_after.lock().await.remove(&run.id);
                    }
                    if let Err(update_err) = state
                        .run_history
                        .update_run_history_transcript_backfill(
                            run.id,
                            TranscriptBackfillState::Failed,
                            Some(error_text.as_str()),
                        )
                        .await
                    {
                        warn!(
                            run_id = run.id,
                            error = %update_err,
                            "failed to persist transcript backfill error"
                        );
                    }
                }
            }
            active_backfills.lock().await.remove(&run.id);
        });

        Ok(())
    }

    fn transcript_backfill_source_for_run(
        &self,
        run: &RunHistoryRecord,
    ) -> Option<Arc<dyn TranscriptBackfillSource>> {
        run.auth_account_name
            .as_deref()
            .and_then(|account_name| {
                self.account_transcript_backfill_sources
                    .get(account_name)
                    .cloned()
            })
            .or_else(|| self.default_transcript_backfill_source.clone())
    }

    async fn backfill_retry_due(&self, run_id: i64) -> bool {
        let mut retry_after = self.backfill_retry_after.lock().await;
        match retry_after.get(&run_id).copied() {
            Some(deadline) if Instant::now() < deadline => false,
            Some(_) => {
                retry_after.remove(&run_id);
                true
            }
            None => true,
        }
    }
}

#[cfg(test)]
pub(crate) use execution::{
    events_have_missing_review_child_history, initial_backfill_candidate_events,
    missing_review_child_history_has_renderable_fallback, run_transcript_backfill,
    strip_missing_review_child_history_markers,
};
#[cfg(test)]
pub(crate) use retry::{
    TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR, TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR,
    TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR, is_final_retry_window_attempt_pending,
    missing_history_retry_window_open, should_retry_transcript_backfill_error,
    should_retry_transcript_backfill_failure, terminal_transcript_backfill_error_text,
};
#[cfg(test)]
pub(crate) use rewrite::{
    merge_recovered_target_turn_events, persisted_turn_ids_are_covered,
    preserve_auxiliary_persisted_events, sanitize_persisted_events_for_backfill,
    turn_ids_from_new_events,
};
#[cfg(test)]
pub(crate) use sources::{fallback_session_history_path, primary_session_history_path};

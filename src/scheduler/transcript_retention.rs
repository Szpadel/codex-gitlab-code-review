//! Removes old transcript events without delaying the scan loop.

use crate::background_tasks::BackgroundTasks;
use crate::state::ReviewStateStore;
use crate::state::TranscriptPruneResult;
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Interval, MissedTickBehavior};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

const TRANSCRIPT_RETENTION_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
// Delay maintenance to reduce contention with initial scan writes.
const TRANSCRIPT_RETENTION_STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Starts cancellable daily maintenance under the runtime task owner.
pub(super) fn spawn(
    state: Arc<ReviewStateStore>,
    days: u32,
    background_tasks: &BackgroundTasks,
) -> JoinHandle<()> {
    let cancellation = background_tasks.cancellation();
    let interval = tokio::time::interval_at(
        Instant::now() + TRANSCRIPT_RETENTION_STARTUP_DELAY,
        TRANSCRIPT_RETENTION_INTERVAL,
    );
    background_tasks.spawn(maintain_transcripts(state, days, cancellation, interval))
}

async fn maintain_transcripts(
    state: Arc<ReviewStateStore>,
    retention_days: u32,
    cancellation: CancellationToken,
    mut interval: Interval,
) {
    // Do not repeat missed daily passes after a long database operation.
    interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            _ = interval.tick() => {}
        }
        let cutoff = Utc::now().timestamp()
            - chrono::Duration::days(i64::from(retention_days)).num_seconds();
        let result = tokio::select! {
            biased;
            () = cancellation.cancelled() => return,
            result = prune_transcript_pass(&state, cutoff) => result,
        };
        match result {
            Ok(counts) => info!(
                pruned_runs = counts.runs,
                pruned_events = counts.events,
                retention_days,
                "Transcript retention pass complete"
            ),
            Err(error) => warn!(error = %error, retention_days, "Transcript retention pass failed"),
        }
    }
}

/// Commits small batches until no eligible runs remain. A failed batch propagates its error.
async fn prune_transcript_pass(
    state: &ReviewStateStore,
    cutoff: i64,
) -> Result<TranscriptPruneResult> {
    let mut total = TranscriptPruneResult::default();
    loop {
        let pruned = state
            .run_history
            .prune_transcripts_batch(cutoff, total.last_run_id)
            .await?;
        total.runs += pruned.runs;
        total.events += pruned.events;
        if pruned.last_run_id.is_none() {
            return Ok(total);
        }
        total.last_run_id = pruned.last_run_id;
        // Let pending scan and transcript writes acquire the released coordinator.
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    async fn insert_old_run(state: &ReviewStateStore, id: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO run_history (id, kind, repo, iid, head_sha, status, started_at, updated_at)
             VALUES (?, 'review', 'group/repo', 1, 'sha', 'done', 0, 0)",
        ).bind(id).execute(state.pool()).await?;
        Ok(())
    }

    async fn wait_for_expiration(state: &ReviewStateStore, id: i64) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let run = state.run_history.get_run_history(id).await?.unwrap();
                if run.transcript_backfill_state == crate::state::TranscriptBackfillState::Expired {
                    return Ok::<_, anyhow::Error>(());
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await??;
        Ok(())
    }

    #[tokio::test]
    async fn transcript_retention_timer_runs_startup_and_repeat_passes() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        insert_old_run(&state, 1).await?;
        let owner = state.background_tasks();
        let task = owner.spawn(maintain_transcripts(
            Arc::clone(&state),
            90,
            owner.cancellation(),
            tokio::time::interval(Duration::from_millis(10)),
        ));
        wait_for_expiration(&state, 1).await?;
        insert_old_run(&state, 2).await?;
        wait_for_expiration(&state, 2).await?;
        owner.shutdown().await;
        task.await?;
        Ok(())
    }

    #[tokio::test]
    async fn transcript_retention_stops_when_cancelled_during_a_database_wait() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        insert_old_run(&state, 1).await?;
        let transaction = state.pool().begin().await?;
        let owner = state.background_tasks();
        let task = owner.spawn(maintain_transcripts(
            Arc::clone(&state),
            90,
            owner.cancellation(),
            tokio::time::interval(Duration::from_millis(10)),
        ));
        tokio::time::sleep(Duration::from_millis(20)).await;
        owner.cancellation().cancel();
        tokio::time::timeout(Duration::from_secs(1), task).await??;
        transaction.rollback().await?;
        let run = state.run_history.get_run_history(1).await?.unwrap();
        assert_ne!(
            run.transcript_backfill_state,
            crate::state::TranscriptBackfillState::Expired
        );
        owner.shutdown().await;
        Ok(())
    }

    #[tokio::test]
    async fn transcript_retention_owner_cancels_the_startup_delay() -> Result<()> {
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        insert_old_run(&state, 1).await?;
        let owner = state.background_tasks();
        let task = spawn(Arc::clone(&state), 90, &owner);
        tokio::time::timeout(Duration::from_secs(1), owner.shutdown()).await?;
        task.await?;
        let run = state.run_history.get_run_history(1).await?.unwrap();
        assert_ne!(
            run.transcript_backfill_state,
            crate::state::TranscriptBackfillState::Expired
        );
        Ok(())
    }
}

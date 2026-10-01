use crate::config::FeatureFlagSnapshot;
use crate::review_lane::ReviewLane;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use sqlx::{AssertSqlSafe, QueryBuilder, Row, Sqlite, SqlitePool};
use std::collections::HashMap;

use super::{
    NewRunHistory, NewRunHistoryEvent, NewRunTokenUsage, RunHistoryCursor, RunHistoryEventRecord,
    RunHistoryFinish, RunHistoryListItem, RunHistoryListPage, RunHistoryListQuery,
    RunHistoryRecord, RunHistorySessionUpdate, RunTokenUsageRollup, RunTokenUsageStatistic,
    TranscriptBackfillState, sqlite::SqliteCoordinator, sqlite_i64_from_u64,
};
use crate::run_history_kind::RunHistoryKind;

const MISSING_ERROR_DETAILS: &str =
    "Run finished with result error, but no failure details were recorded.";
// Release the write coordinator between small batches so scans can persist results.
const TRANSCRIPT_PRUNE_BATCH_RUNS: i64 = 10;
const RECONCILE_INTERRUPTED_RUN_HISTORY_SQL: &str = r"
    UPDATE run_history
    SET status = 'done',
        result = 'cancelled',
        finished_at = COALESCE(finished_at, ?),
        updated_at = ?,
        error = COALESCE(error, ?)
    WHERE status = 'in_progress'
    ";
const UPSERT_RUN_TOKEN_USAGE_SQL: &str = r"
    INSERT INTO run_history_token_usage (
        run_history_id, response_id, thread_id, turn_id, input_tokens,
        cached_input_tokens, cache_write_input_tokens, output_tokens,
        reasoning_output_tokens, total_tokens, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(run_history_id, response_id) DO UPDATE SET
        thread_id = excluded.thread_id,
        turn_id = excluded.turn_id,
        input_tokens = excluded.input_tokens,
        cached_input_tokens = excluded.cached_input_tokens,
        cache_write_input_tokens = excluded.cache_write_input_tokens,
        output_tokens = excluded.output_tokens,
        reasoning_output_tokens = excluded.reasoning_output_tokens,
        total_tokens = excluded.total_tokens
    ";
/// Column list consumed by `map_run_history_row`; keep the two in sync.
const RUN_HISTORY_COLUMNS: &str = "id, kind, repo, iid, head_sha, status, result, \
    started_at, finished_at, updated_at, thread_id, turn_id, review_thread_id, \
    security_context_source_run_id, security_context_base_branch, security_context_base_head_sha, \
    security_context_prompt_version, security_context_payload_json, security_context_generated_at, \
    security_context_expires_at, preview, summary, error, auth_account_name, discussion_id, \
    trigger_note_id, trigger_note_author_name, trigger_note_body, command_repo, commit_sha, \
    feature_flags_json, events_persisted_cleanly, transcript_backfill_state, transcript_backfill_error";

#[derive(Clone)]
pub struct RunHistoryRepository {
    sqlite: SqliteCoordinator,
}

/// Metadata for navigation between runs. Transcript and request bodies are excluded.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RelatedRun {
    pub id: i64,
    pub kind: RunHistoryKind,
    pub status: String,
    pub result: Option<String>,
    pub started_at: i64,
}

/// Counts expired runs and deleted events. Run metadata and token usage remain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TranscriptPruneResult {
    pub(crate) runs: u64,
    pub(crate) events: u64,
    /// Resume the same pass after this ID to avoid repeated scans of expired runs.
    pub(crate) last_run_id: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorDirection {
    After,
    Before,
}

impl RunHistoryRepository {
    pub(crate) fn new(sqlite: SqliteCoordinator) -> Self {
        Self { sqlite }
    }

    /// Expires one small batch of done runs started before the Unix-second cutoff.
    /// Resume with the previous batch's last ID. Use `None` for a new pass.
    /// Returns committed deletion counts. SQLite failures propagate.
    pub(crate) async fn prune_transcripts_batch(
        &self,
        cutoff: i64,
        after_run_id: Option<i64>,
    ) -> Result<TranscriptPruneResult> {
        // Read candidates without the write gate. Old metadata can require a long scan.
        let mut query = QueryBuilder::<Sqlite>::new(
            "SELECT id FROM run_history NOT INDEXED WHERE status = 'done' AND started_at < ",
        );
        query
            .push_bind(cutoff)
            .push(" AND transcript_backfill_state != 'expired'");
        // Walk primary keys once per pass, not the growing prefix of expired runs.
        if let Some(after_run_id) = after_run_id {
            query.push(" AND id > ").push_bind(after_run_id);
        }
        query
            .push(" ORDER BY id LIMIT ")
            .push_bind(TRANSCRIPT_PRUNE_BATCH_RUNS);
        let runs = query
            .build_query_scalar::<i64>()
            .fetch_all(self.sqlite.read_pool())
            .await
            .context("select expired transcripts")?;

        self.sqlite
            .write_foreground("prune expired transcripts", move |pool| {
                let runs = runs.clone();
                async move {
                    let mut transaction = pool
                        .begin()
                        .await
                        .context("start transcript retention transaction")?;

                    // Only transcript events expire. Usage and its trigger-maintained totals stay intact.
                    let mut counts = TranscriptPruneResult::default();
                    for run_id in runs {
                        counts.last_run_id = Some(run_id);
                        // Recheck eligibility because another write can follow candidate selection.
                        let marked = sqlx::query(
                            "UPDATE run_history SET transcript_backfill_state = 'expired',
                             transcript_backfill_error = NULL, updated_at = ? WHERE id = ?
                             AND status = 'done' AND started_at < ? AND transcript_backfill_state != 'expired'",
                        )
                        .bind(Utc::now().timestamp())
                        .bind(run_id)
                        .bind(cutoff)
                        .execute(&mut *transaction)
                        .await
                        .context("mark transcript expired")?
                        .rows_affected();
                        if marked == 0 {
                            continue;
                        }
                        counts.runs += marked;
                        counts.events +=
                            sqlx::query("DELETE FROM run_history_event WHERE run_history_id = ?")
                                .bind(run_id)
                                .execute(&mut *transaction)
                                .await
                                .context("delete expired transcript events")?
                                .rows_affected();
                    }
                    transaction
                        .commit()
                        .await
                        .context("commit transcript retention transaction")?;
                    Ok(counts)
                }
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if review history cannot be queried.
    pub async fn has_completed_inline_review(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
    ) -> Result<bool> {
        self.has_completed_inline_review_for_lane(repo, iid, sha, ReviewLane::General)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if review history cannot be queried.
    pub async fn has_completed_inline_review_for_lane(
        &self,
        repo: &str,
        iid: u64,
        sha: &str,
        lane: ReviewLane,
    ) -> Result<bool> {
        let kind = if lane.is_security() {
            RunHistoryKind::Security
        } else {
            RunHistoryKind::Review
        };
        let row = sqlx::query(
            r#"
            SELECT 1
            FROM run_history
            WHERE kind = ?
              AND review_lane = ?
              AND repo = ?
              AND iid = ?
              AND head_sha = ?
              AND status = 'done'
              AND result = 'comment'
              AND feature_flags_json LIKE '%"gitlab_inline_review_comments":true%'
            LIMIT 1
            "#,
        )
        .bind(run_history_kind_label(kind))
        .bind(lane.as_str())
        .bind(repo)
        .bind(i64::try_from(iid).context("convert review iid to i64")?)
        .bind(sha)
        .fetch_optional(self.sqlite.read_pool())
        .await;
        let row = match row {
            Ok(row) => row,
            Err(err) if err.to_string().contains("no such table: run_history") => return Ok(false),
            Err(err) => return Err(err).context("load completed inline review state"),
        };
        Ok(row.is_some())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn reconcile_interrupted_run_history(&self, reason: &str) -> Result<u64> {
        let now = Utc::now().timestamp();
        self.sqlite
            .write_foreground("reconcile interrupted run history", |pool| async move {
                let result = sqlx::query(RECONCILE_INTERRUPTED_RUN_HISTORY_SQL)
                    .bind(now)
                    .bind(now)
                    .bind(reason)
                    .execute(&pool)
                    .await
                    .context("reconcile interrupted run history")?;
                Ok(result.rows_affected())
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn start_run_history(&self, new_run: NewRunHistory) -> Result<i64> {
        let review_lane = match new_run.kind {
            RunHistoryKind::Review => Some(ReviewLane::General),
            RunHistoryKind::Security => Some(ReviewLane::Security),
            RunHistoryKind::Mention => None,
        };
        self.start_run_history_for_lane(new_run, review_lane).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn start_run_history_for_lane(
        &self,
        new_run: NewRunHistory,
        review_lane: Option<ReviewLane>,
    ) -> Result<i64> {
        let now = Utc::now().timestamp();
        self.sqlite
            .write_foreground("start run history", move |pool| {
                let new_run = new_run.clone();
                async move {
                    let result = sqlx::query(
                        r"
                        INSERT INTO run_history (
                            kind,
                            review_lane,
                            repo,
                            iid,
                            head_sha,
                            status,
                            started_at,
                            updated_at,
                            discussion_id,
                            trigger_note_id,
                            trigger_note_author_name,
                            trigger_note_body,
                            command_repo
                        )
                        VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?, ?, ?, ?, ?, ?)
                        ",
                    )
                    .bind(run_history_kind_label(new_run.kind))
                    .bind(review_lane.map(ReviewLane::as_str))
                    .bind(new_run.repo)
                    .bind(sqlite_i64_from_u64(new_run.iid, "iid")?)
                    .bind(new_run.head_sha)
                    .bind(now)
                    .bind(now)
                    .bind(new_run.discussion_id)
                    .bind(
                        new_run
                            .trigger_note_id
                            .map(|value| sqlite_i64_from_u64(value, "trigger_note_id"))
                            .transpose()?,
                    )
                    .bind(new_run.trigger_note_author_name)
                    .bind(new_run.trigger_note_body)
                    .bind(new_run.command_repo)
                    .execute(&pool)
                    .await
                    .context("insert run history")?;
                    Ok(result.last_insert_rowid())
                }
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn update_run_history_session(
        &self,
        run_id: i64,
        update: RunHistorySessionUpdate,
    ) -> Result<()> {
        self.sqlite
            .write_foreground("update run history session", move |pool| {
                let update = update.clone();
                async move {
                    sqlx::query(
                        r"
                        UPDATE run_history
                        SET thread_id = COALESCE(?, thread_id),
                            turn_id = COALESCE(?, turn_id),
                            review_thread_id = COALESCE(?, review_thread_id),
                            auth_account_name = COALESCE(?, auth_account_name),
                            security_context_source_run_id = COALESCE(?, security_context_source_run_id),
                            security_context_base_branch = COALESCE(?, security_context_base_branch),
                            security_context_base_head_sha = COALESCE(?, security_context_base_head_sha),
                            security_context_prompt_version = COALESCE(?, security_context_prompt_version),
                            security_context_payload_json = COALESCE(?, security_context_payload_json),
                            security_context_generated_at = COALESCE(?, security_context_generated_at),
                            security_context_expires_at = COALESCE(?, security_context_expires_at),
                            updated_at = ?
                        WHERE id = ?
                        ",
                    )
                    .bind(update.thread_id)
                    .bind(update.turn_id)
                    .bind(update.review_thread_id)
                    .bind(update.auth_account_name)
                    .bind(update.security_context_source_run_id)
                    .bind(update.security_context_base_branch)
                    .bind(update.security_context_base_head_sha)
                    .bind(update.security_context_prompt_version)
                    .bind(update.security_context_payload_json)
                    .bind(update.security_context_generated_at)
                    .bind(update.security_context_expires_at)
                    .bind(Utc::now().timestamp())
                    .bind(run_id)
                    .execute(&pool)
                    .await
                    .context("update run history session metadata")?;
                    Ok(())
                }
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn set_run_history_feature_flags(
        &self,
        run_id: i64,
        feature_flags: &FeatureFlagSnapshot,
    ) -> Result<()> {
        self.sqlite
            .write_foreground("set run history feature flags", |pool| async move {
                let feature_flags_json = serde_json::to_string(feature_flags)
                    .context("serialize feature flag snapshot")?;
                sqlx::query(
                    r"
                    UPDATE run_history
                    SET feature_flags_json = ?,
                        updated_at = ?
                    WHERE id = ?
                    ",
                )
                .bind(feature_flags_json)
                .bind(Utc::now().timestamp())
                .bind(run_id)
                .execute(&pool)
                .await
                .context("update run history feature flags")?;
                Ok(())
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn update_run_history_head_sha(&self, run_id: i64, head_sha: &str) -> Result<()> {
        self.sqlite
            .write_foreground("update run history head sha", |pool| async move {
                sqlx::query(
                    r"
                    UPDATE run_history
                    SET head_sha = ?, updated_at = ?
                    WHERE id = ?
                    ",
                )
                .bind(head_sha)
                .bind(Utc::now().timestamp())
                .bind(run_id)
                .execute(&pool)
                .await
                .context("update run history head sha")?;
                Ok(())
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn finish_run_history(&self, run_id: i64, finish: RunHistoryFinish) -> Result<()> {
        let now = Utc::now().timestamp();
        self.sqlite
            .write_foreground("finish run history", move |pool| {
                let finish = finish.clone();
                async move {
                    let error =
                        normalized_run_history_finish_error(&finish.result, finish.error.clone());
                    sqlx::query(
                        r"
                        UPDATE run_history
                        SET status = 'done',
                            result = ?,
                            finished_at = ?,
                            updated_at = ?,
                            thread_id = COALESCE(?, thread_id),
                            turn_id = COALESCE(?, turn_id),
                            review_thread_id = COALESCE(?, review_thread_id),
                            preview = ?,
                            summary = ?,
                            error = ?,
                            auth_account_name = COALESCE(?, auth_account_name),
                            commit_sha = ?
                        WHERE id = ?
                        ",
                    )
                    .bind(finish.result)
                    .bind(now)
                    .bind(now)
                    .bind(finish.thread_id)
                    .bind(finish.turn_id)
                    .bind(finish.review_thread_id)
                    .bind(finish.preview)
                    .bind(finish.summary)
                    .bind(error)
                    .bind(finish.auth_account_name)
                    .bind(finish.commit_sha)
                    .bind(run_id)
                    .execute(&pool)
                    .await
                    .context("finish run history")?;
                    Ok(())
                }
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn mark_run_history_events_incomplete(&self, run_id: i64) -> Result<()> {
        self.sqlite
            .write_foreground("mark run history events incomplete", |pool| async move {
                mark_run_history_events_incomplete_on_pool(pool, run_id).await
            })
            .await
    }

    /// Expired runs ignore transcript writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn append_run_history_events(
        &self,
        run_history_id: i64,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        let created_at = Utc::now().timestamp();
        self.sqlite
            .write_foreground("append run history events", |pool| async move {
                append_run_history_events_on_pool(pool, run_history_id, events, created_at).await
            })
            .await
    }

    /// Expired runs ignore transcript writes when the queued job executes.
    ///
    /// # Errors
    ///
    /// Returns an error if the background write cannot be accepted.
    pub async fn append_run_history_events_bg(
        &self,
        run_history_id: i64,
        events: Vec<NewRunHistoryEvent>,
    ) -> Result<()> {
        if events.is_empty() {
            return Ok(());
        }
        self.sqlite
            .enqueue_background_with_failure(
                "append run history events",
                move |pool| {
                    let events = events.clone();
                    Box::pin(async move {
                        let created_at = Utc::now().timestamp();
                        append_run_history_events_on_pool(pool, run_history_id, &events, created_at)
                            .await
                    })
                },
                move |pool, _error| {
                    Box::pin(async move {
                        mark_run_history_events_incomplete_on_pool(pool, run_history_id).await
                    })
                },
            )
            .await
    }

    /// Expired runs ignore transcript writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn replace_run_history_events(
        &self,
        run_history_id: i64,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        let created_at = Utc::now().timestamp();
        let rewritten_events = events.to_vec();
        self.sqlite
            .write_foreground("replace run history events", move |pool| {
                let rewritten_events = rewritten_events.clone();
                async move {
                    replace_run_history_events_on_pool(
                        pool,
                        run_history_id,
                        rewritten_events,
                        created_at,
                    )
                    .await
                }
            })
            .await
    }

    /// Expired runs ignore transcript writes.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn replace_run_history_events_for_turn(
        &self,
        run_history_id: i64,
        turn_id: &str,
        events: &[NewRunHistoryEvent],
    ) -> Result<()> {
        let created_at = Utc::now().timestamp();
        self.sqlite
            .write_foreground("replace run history events for turn", |pool| async move {
                if events.is_empty()
                    && !run_history_turn_exists(&pool, run_history_id, turn_id).await?
                {
                    return Ok(());
                }
                let existing_events =
                    list_run_history_events_on_pool(pool.clone(), run_history_id).await?;
                let rewritten_events =
                    merge_rewritten_turn_events(existing_events, turn_id, events).with_context(
                        || format!("merge rewritten run history events for turn {turn_id}"),
                    )?;
                replace_run_history_events_on_pool(
                    pool,
                    run_history_id,
                    rewritten_events,
                    created_at,
                )
                .await
            })
            .await
    }

    /// Expired runs ignore transcript writes when the queued job executes.
    ///
    /// # Errors
    ///
    /// Returns an error if the background write cannot be accepted.
    pub async fn replace_run_history_events_for_turn_bg(
        &self,
        run_history_id: i64,
        turn_id: String,
        events: Vec<NewRunHistoryEvent>,
    ) -> Result<()> {
        self.sqlite
            .enqueue_background_with_failure(
                "replace run history events for turn",
                move |pool| {
                    let turn_id = turn_id.clone();
                    let events = events.clone();
                    Box::pin(async move {
                        let created_at = Utc::now().timestamp();
                        if events.is_empty()
                            && !run_history_turn_exists(&pool, run_history_id, &turn_id).await?
                        {
                            return Ok(());
                        }
                        let existing_events =
                            list_run_history_events_on_pool(pool.clone(), run_history_id).await?;
                        let rewritten_events =
                            merge_rewritten_turn_events(existing_events, &turn_id, &events)
                                .with_context(|| {
                                    format!("merge rewritten run history events for turn {turn_id}")
                                })?;
                        replace_run_history_events_on_pool(
                            pool,
                            run_history_id,
                            rewritten_events,
                            created_at,
                        )
                        .await
                    })
                },
                move |pool, _error| {
                    Box::pin(async move {
                        mark_run_history_events_incomplete_on_pool(pool, run_history_id).await
                    })
                },
            )
            .await
    }

    /// Expiration is terminal. Expired runs remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn mark_run_history_transcript_backfill_complete(&self, run_id: i64) -> Result<()> {
        self.sqlite
            .write_foreground(
                "mark run history transcript backfill complete",
                |pool| async move {
                    mark_run_history_transcript_backfill_complete_on_pool(pool, run_id).await
                },
            )
            .await
    }

    /// Expiration is terminal. Expired runs remain unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the background write cannot be accepted.
    pub async fn mark_run_history_transcript_backfill_complete_bg(
        &self,
        run_id: i64,
    ) -> Result<()> {
        self.sqlite
            .enqueue_background(
                "mark run history transcript backfill complete",
                move |pool| {
                    Box::pin(async move {
                        mark_run_history_transcript_backfill_complete_on_pool(pool, run_id).await
                    })
                },
            )
            .await
    }

    /// Expired runs ignore transcript writes and remain expired.
    ///
    /// # Errors
    ///
    /// Returns an error if the background write cannot be accepted.
    pub async fn complete_run_history_transcript_backfill_bg(
        &self,
        run_history_id: i64,
        events: Vec<NewRunHistoryEvent>,
    ) -> Result<()> {
        self.sqlite
            .enqueue_background_with_failure(
                "complete run history transcript backfill",
                move |pool| {
                    let events = events.clone();
                    Box::pin(async move {
                        let created_at = Utc::now().timestamp();
                        replace_run_history_events_on_pool(
                            pool.clone(),
                            run_history_id,
                            events,
                            created_at,
                        )
                        .await?;
                        mark_run_history_transcript_backfill_complete_on_pool(pool, run_history_id)
                            .await
                    })
                },
                move |pool, _error| {
                    Box::pin(async move {
                        mark_run_history_events_incomplete_on_pool(pool, run_history_id).await
                    })
                },
            )
            .await
    }

    /// Returns `false` for an absent or expired run. Expiration is terminal.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn update_run_history_transcript_backfill(
        &self,
        run_id: i64,
        state: TranscriptBackfillState,
        error: Option<&str>,
    ) -> Result<bool> {
        self.sqlite
            .write_foreground(
                "update run history transcript backfill",
                |pool| async move {
                    let result = sqlx::query(
                        r"
                    UPDATE run_history
                    SET transcript_backfill_state = ?,
                        transcript_backfill_error = ?,
                        updated_at = ?
                    WHERE id = ? AND transcript_backfill_state != 'expired'
                    ",
                    )
                    .bind(transcript_backfill_state_label(state))
                    .bind(error)
                    .bind(Utc::now().timestamp())
                    .bind(run_id)
                    .execute(&pool)
                    .await
                    .context("update run history transcript backfill state")?;
                    Ok(result.rows_affected() > 0)
                },
            )
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_run_history_events(
        &self,
        run_history_id: i64,
    ) -> Result<Vec<RunHistoryEventRecord>> {
        list_run_history_events_on_pool(self.sqlite.read_pool().clone(), run_history_id).await
    }

    /// Loads one event only when it belongs to the requested run.
    /// Returns `None` for an absent event. Propagates SQLite and payload parse errors.
    pub(crate) async fn get_run_history_event(
        &self,
        run_history_id: i64,
        event_id: i64,
    ) -> Result<Option<RunHistoryEventRecord>> {
        let row = sqlx::query(
            "SELECT id, run_history_id, sequence, turn_id, event_type, payload_json, created_at \
             FROM run_history_event WHERE id = ? AND run_history_id = ?",
        )
        .bind(event_id)
        .bind(run_history_id)
        .fetch_optional(self.sqlite.read_pool())
        .await
        .context("get run history event")?;
        row.as_ref().map(map_run_history_event_row).transpose()
    }

    /// Records exact usage for one upstream model response.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails or a count is negative.
    pub async fn record_run_token_usage(
        &self,
        run_history_id: i64,
        usage: &NewRunTokenUsage,
    ) -> Result<()> {
        validate_token_usage(usage)?;
        self.sqlite
            .write_foreground("record run token usage", |pool| async move {
                let created_at = Utc::now().timestamp();
                upsert_run_token_usage(&pool, run_history_id, usage, created_at).await
            })
            .await
    }

    /// Returns token usage totals keyed by run id. Runs without captured usage are omitted.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn token_usage_for_runs(
        &self,
        run_ids: &[i64],
    ) -> Result<HashMap<i64, RunTokenUsageRollup>> {
        let mut usage = HashMap::new();
        for run_ids in run_ids.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(
                "SELECT run_history_id, response_count, input_tokens, cached_input_tokens, \
                 cache_write_input_tokens, output_tokens, reasoning_output_tokens, total_tokens \
                 FROM run_history_token_usage_rollup WHERE run_history_id IN (",
            );
            let mut separated = builder.separated(", ");
            for run_id in run_ids {
                separated.push_bind(*run_id);
            }
            separated.push_unseparated(")");
            let rows = builder
                .build()
                .fetch_all(self.sqlite.read_pool())
                .await
                .context("load run token usage totals")?;
            for row in rows {
                let run_id = row
                    .try_get("run_history_id")
                    .context("read token usage run_history_id")?;
                usage.insert(run_id, map_token_usage_rollup(&row)?);
            }
        }
        Ok(usage)
    }

    /// Returns usage totals grouped by run kind for all runs matching the supplied filters.
    /// Pagination cursors and limits are intentionally ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn token_usage_statistics(
        &self,
        query: &RunHistoryListQuery,
    ) -> Result<Vec<RunTokenUsageStatistic>> {
        let mut builder = token_usage_statistics_query(query)?;
        let rows = builder
            .build()
            .fetch_all(self.sqlite.read_pool())
            .await
            .context("load run token usage statistics")?;
        rows.into_iter()
            .map(|row| {
                Ok(RunTokenUsageStatistic {
                    kind: parse_run_history_kind(
                        row.try_get::<String, _>("kind")
                            .context("read token usage statistic kind")?
                            .as_str(),
                    )?,
                    recorded_runs: row
                        .try_get("recorded_runs")
                        .context("read token usage statistic recorded_runs")?,
                    usage: map_token_usage_rollup(&row)?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_run_history_for_mr(
        &self,
        repo: &str,
        iid: u64,
    ) -> Result<Vec<RunHistoryRecord>> {
        let sql = format!(
            r"
            SELECT {RUN_HISTORY_COLUMNS}
            FROM run_history
            WHERE repo = ? AND iid = ?
            ORDER BY started_at DESC, id DESC
            "
        );
        let rows = sqlx::query(AssertSqlSafe(sql))
            .bind(repo)
            .bind(sqlite_i64_from_u64(iid, "iid")?)
            .fetch_all(self.sqlite.read_pool())
            .await
            .context("list run history for MR")?;
        rows.into_iter()
            .map(|row| map_run_history_row(&row))
            .collect()
    }

    /// Returns the 50 most recent sessions for run-detail navigation, newest first.
    ///
    /// # Errors
    /// Returns an error if the database query fails or the IID does not fit in SQLite.
    pub async fn related_runs(&self, repo: &str, iid: u64) -> Result<Vec<RelatedRun>> {
        let rows = sqlx::query(
            "SELECT id, kind, status, result, started_at FROM run_history
             WHERE repo = ? AND iid = ? ORDER BY started_at DESC, id DESC LIMIT 50",
        )
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .fetch_all(self.sqlite.read_pool())
        .await
        .context("load related runs")?;
        rows.into_iter()
            .map(|row| {
                Ok(RelatedRun {
                    id: row.try_get("id")?,
                    kind: parse_run_history_kind(row.try_get::<String, _>("kind")?.as_str())?,
                    status: row.try_get("status")?,
                    result: row.try_get("result")?,
                    started_at: row.try_get("started_at")?,
                })
            })
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn get_run_history(&self, run_id: i64) -> Result<Option<RunHistoryRecord>> {
        let sql = format!(
            r"
            SELECT {RUN_HISTORY_COLUMNS}
            FROM run_history
            WHERE id = ?
            "
        );
        let row = sqlx::query(AssertSqlSafe(sql))
            .bind(run_id)
            .fetch_optional(self.sqlite.read_pool())
            .await
            .context("get run history")?;
        row.map(|row| map_run_history_row(&row)).transpose()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_run_history(
        &self,
        query: &RunHistoryListQuery,
    ) -> Result<RunHistoryListPage> {
        if query.after.is_some() && query.before.is_some() {
            bail!("run history query cannot include both after and before cursors");
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            r"
            SELECT id, kind, review_lane, repo, iid, status, result, started_at, preview, summary, error
            FROM run_history
            ",
        );
        let mut has_where = append_run_history_filters(&mut builder, query)?;

        let limit = query.normalized_limit();
        if let Some(cursor) = query.after {
            append_run_history_cursor_clause(
                &mut builder,
                &mut has_where,
                cursor,
                CursorDirection::After,
            );
        } else if let Some(cursor) = query.before {
            append_run_history_cursor_clause(
                &mut builder,
                &mut has_where,
                cursor,
                CursorDirection::Before,
            );
        }

        let ordered_before = query.before.is_some();
        if ordered_before {
            builder.push(" ORDER BY started_at ASC, id ASC");
        } else {
            builder.push(" ORDER BY started_at DESC, id DESC");
        }
        builder
            .push(" LIMIT ")
            .push_bind(i64::try_from(limit.saturating_add(1)).unwrap_or(i64::MAX));

        let mut runs = builder
            .build()
            .fetch_all(self.sqlite.read_pool())
            .await
            .context("list run history")?;
        let has_extra = runs.len() > limit;
        if has_extra {
            runs.pop();
        }

        let mut runs = runs
            .into_iter()
            .map(|row| map_run_history_list_item_row(&row))
            .collect::<Result<Vec<_>>>()?;
        if ordered_before {
            runs.reverse();
        }

        let has_previous = match (query.after, query.before) {
            (_, Some(_)) => has_extra,
            (Some(_), None) => !runs.is_empty(),
            (None, None) => false,
        };
        let has_next = match (query.after, query.before) {
            (None, Some(_)) => !runs.is_empty(),
            (Some(_), _) | (None, None) => has_extra,
        };

        Ok(RunHistoryListPage {
            previous_cursor: if has_previous {
                runs.first().map(RunHistoryCursor::from)
            } else {
                None
            },
            next_cursor: if has_next {
                runs.last().map(RunHistoryCursor::from)
            } else {
                None
            },
            has_previous,
            has_next,
            runs,
        })
    }
}

async fn mark_run_history_events_incomplete_on_pool(pool: SqlitePool, run_id: i64) -> Result<()> {
    sqlx::query(
        r"
        UPDATE run_history
        SET events_persisted_cleanly = 0,
            updated_at = ?
        WHERE id = ?
        ",
    )
    .bind(Utc::now().timestamp())
    .bind(run_id)
    .execute(&pool)
    .await
    .context("mark run history events incomplete")?;
    Ok(())
}

async fn run_history_turn_exists(pool: &SqlitePool, run_id: i64, turn_id: &str) -> Result<bool> {
    let exists = sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM run_history_event WHERE run_history_id = ? AND turn_id = ? LIMIT 1",
    )
    .bind(run_id)
    .bind(turn_id)
    .fetch_optional(pool)
    .await
    .context("check run history turn events")?;
    Ok(exists.is_some())
}

async fn append_run_history_events_on_pool(
    pool: SqlitePool,
    run_history_id: i64,
    events: &[NewRunHistoryEvent],
    created_at: i64,
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("start sqlite transaction for run history events")?;
    // A queued capture or backfill must not restore an expired transcript.
    if transcript_is_expired(&mut tx, run_history_id).await? {
        tx.rollback()
            .await
            .context("close expired transcript append")?;
        return Ok(());
    }
    let sequence_offset = sqlx::query_scalar::<_, i64>(
        r"
        SELECT COALESCE(MAX(sequence), 0)
        FROM run_history_event
        WHERE run_history_id = ?
        ",
    )
    .bind(run_history_id)
    .fetch_one(&mut *tx)
    .await
    .context("load current run history event sequence")?;
    for event in events {
        let payload_json =
            serde_json::to_string(&event.payload).context("serialize run history payload")?;
        sqlx::query(
            r"
            INSERT INTO run_history_event (
                run_history_id,
                sequence,
                turn_id,
                event_type,
                payload_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(run_history_id)
        .bind(sequence_offset + event.sequence)
        .bind(event.turn_id.as_deref())
        .bind(event.event_type.as_str())
        .bind(payload_json)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .context("insert run history event")?;
        if let Some(usage) = token_usage_from_event(event)? {
            upsert_run_token_usage_in_transaction(&mut tx, run_history_id, &usage, created_at)
                .await?;
        }
    }
    tx.commit()
        .await
        .context("commit sqlite transaction for run history events")?;
    Ok(())
}

async fn list_run_history_events_on_pool(
    pool: SqlitePool,
    run_history_id: i64,
) -> Result<Vec<RunHistoryEventRecord>> {
    let rows = sqlx::query(
        r"
        SELECT id, run_history_id, sequence, turn_id, event_type, payload_json, created_at
        FROM run_history_event
        WHERE run_history_id = ?
        ORDER BY sequence ASC, id ASC
        ",
    )
    .bind(run_history_id)
    .fetch_all(&pool)
    .await
    .context("list run history events")?;
    rows.into_iter()
        .map(|row| map_run_history_event_row(&row))
        .collect()
}

async fn replace_run_history_events_on_pool(
    pool: SqlitePool,
    run_history_id: i64,
    events: Vec<NewRunHistoryEvent>,
    created_at: i64,
) -> Result<()> {
    let mut tx = pool
        .begin()
        .await
        .context("start sqlite transaction for run history event rewrite")?;
    // Backfill can finish after retention commits. Expiration is terminal.
    if transcript_is_expired(&mut tx, run_history_id).await? {
        tx.rollback()
            .await
            .context("close expired transcript rewrite")?;
        return Ok(());
    }
    sqlx::query("DELETE FROM run_history_event WHERE run_history_id = ?")
        .bind(run_history_id)
        .execute(&mut *tx)
        .await
        .context("delete previous run history events")?;
    for event in events {
        let payload_json =
            serde_json::to_string(&event.payload).context("serialize run history payload")?;
        sqlx::query(
            r"
            INSERT INTO run_history_event (
                run_history_id,
                sequence,
                turn_id,
                event_type,
                payload_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(run_history_id)
        .bind(event.sequence)
        .bind(event.turn_id.as_deref())
        .bind(event.event_type.as_str())
        .bind(payload_json)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .context("insert rewritten run history event")?;
        // Usage is an independent audit record: transcript rewrites never delete observations,
        // but any exact raw-response records present in recovered history are still upserted.
        if let Some(usage) = token_usage_from_event(&event)? {
            upsert_run_token_usage_in_transaction(&mut tx, run_history_id, &usage, created_at)
                .await?;
        }
    }
    sqlx::query("UPDATE run_history SET updated_at = ? WHERE id = ?")
        .bind(created_at)
        .bind(run_history_id)
        .execute(&mut *tx)
        .await
        .context("update run history timestamp after event rewrite")?;
    tx.commit()
        .await
        .context("commit sqlite transaction for run history event rewrite")?;
    Ok(())
}

/// Checks the terminal retention state in the same transaction as event writes.
async fn transcript_is_expired(
    transaction: &mut sqlx::Transaction<'_, Sqlite>,
    run_id: i64,
) -> Result<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM run_history WHERE id = ? AND transcript_backfill_state = 'expired')",
    )
    .bind(run_id)
    .fetch_one(&mut **transaction)
    .await
    .context("check transcript expiration")
}

async fn mark_run_history_transcript_backfill_complete_on_pool(
    pool: SqlitePool,
    run_id: i64,
) -> Result<()> {
    sqlx::query(
        r"
        UPDATE run_history
        SET events_persisted_cleanly = 1,
            transcript_backfill_state = ?,
            transcript_backfill_error = NULL,
            updated_at = ?
        WHERE id = ? AND transcript_backfill_state != 'expired'
        ",
    )
    .bind(transcript_backfill_state_label(
        TranscriptBackfillState::Complete,
    ))
    .bind(Utc::now().timestamp())
    .bind(run_id)
    .execute(&pool)
    .await
    .context("mark run history transcript backfill complete")?;
    Ok(())
}

pub(crate) fn merge_rewritten_turn_events(
    existing_events: Vec<RunHistoryEventRecord>,
    turn_id: &str,
    rewritten_events: &[NewRunHistoryEvent],
) -> Result<Vec<NewRunHistoryEvent>> {
    let mut existing_events = existing_events;
    existing_events.sort_by_key(|event| (event.sequence, event.id));

    let target_sequences = existing_events
        .iter()
        .filter(|event| event.turn_id.as_deref() == Some(turn_id))
        .map(|event| event.sequence)
        .collect::<Vec<_>>();

    let first_target_sequence = target_sequences
        .first()
        .copied()
        .unwrap_or_else(|| existing_events.last().map_or(1, |event| event.sequence + 1));
    let last_target_sequence = target_sequences
        .last()
        .copied()
        .unwrap_or(first_target_sequence - 1);
    let rewritten_len = i64::try_from(rewritten_events.len()).unwrap_or(i64::MAX);
    let target_len = i64::try_from(target_sequences.len()).unwrap_or(i64::MAX);
    let delta = rewritten_len.saturating_sub(target_len);

    let mut merged_events = Vec::new();
    for event in existing_events {
        if event.turn_id.as_deref() == Some(turn_id) {
            continue;
        }
        let shifted_sequence = if event.sequence > last_target_sequence {
            event.sequence + delta
        } else {
            event.sequence
        };
        merged_events.push(NewRunHistoryEvent {
            sequence: shifted_sequence,
            turn_id: event.turn_id,
            event_type: event.event_type,
            payload: event.payload,
        });
    }

    merged_events.extend(rewritten_events.iter().map(|event| NewRunHistoryEvent {
        sequence: first_target_sequence + event.sequence - 1,
        turn_id: event.turn_id.clone(),
        event_type: event.event_type.clone(),
        payload: event.payload.clone(),
    }));

    merged_events.sort_by_key(|event| event.sequence);
    for (index, event) in merged_events.iter_mut().enumerate() {
        event.sequence = i64::try_from(index + 1).context("convert merged event index")?;
    }
    Ok(merged_events)
}

fn token_usage_from_event(event: &NewRunHistoryEvent) -> Result<Option<NewRunTokenUsage>> {
    if event.event_type != "raw_response_completed" {
        return Ok(None);
    }
    let Some(usage) = event.payload.get("usage").filter(|usage| !usage.is_null()) else {
        return Ok(None);
    };
    let required_i64 = |name: &str| {
        usage
            .get(name)
            .and_then(serde_json::Value::as_i64)
            .with_context(|| format!("read raw response usage {name}"))
    };
    Ok(Some(NewRunTokenUsage {
        response_id: event
            .payload
            .get("responseId")
            .and_then(serde_json::Value::as_str)
            .context("read raw response responseId")?
            .to_string(),
        thread_id: event
            .payload
            .get("threadId")
            .and_then(serde_json::Value::as_str)
            .context("read raw response threadId")?
            .to_string(),
        turn_id: event
            .payload
            .get("turnId")
            .and_then(serde_json::Value::as_str)
            .or(event.turn_id.as_deref())
            .context("read raw response turnId")?
            .to_string(),
        input_tokens: required_i64("inputTokens")?,
        cached_input_tokens: required_i64("cachedInputTokens")?,
        cache_write_input_tokens: usage
            .get("cacheWriteInputTokens")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0),
        output_tokens: required_i64("outputTokens")?,
        reasoning_output_tokens: required_i64("reasoningOutputTokens")?,
        total_tokens: required_i64("totalTokens")?,
    }))
}

fn validate_token_usage(usage: &NewRunTokenUsage) -> Result<()> {
    if usage.response_id.trim().is_empty()
        || usage.thread_id.trim().is_empty()
        || usage.turn_id.trim().is_empty()
    {
        bail!("token usage response, thread, and turn ids must not be empty");
    }
    if [
        usage.input_tokens,
        usage.cached_input_tokens,
        usage.cache_write_input_tokens,
        usage.output_tokens,
        usage.reasoning_output_tokens,
        usage.total_tokens,
    ]
    .into_iter()
    .any(|value| value < 0)
    {
        bail!("token usage counts must not be negative");
    }
    Ok(())
}

async fn upsert_run_token_usage(
    pool: &SqlitePool,
    run_history_id: i64,
    usage: &NewRunTokenUsage,
    created_at: i64,
) -> Result<()> {
    sqlx::query(UPSERT_RUN_TOKEN_USAGE_SQL)
        .bind(run_history_id)
        .bind(&usage.response_id)
        .bind(&usage.thread_id)
        .bind(&usage.turn_id)
        .bind(usage.input_tokens)
        .bind(usage.cached_input_tokens)
        .bind(usage.cache_write_input_tokens)
        .bind(usage.output_tokens)
        .bind(usage.reasoning_output_tokens)
        .bind(usage.total_tokens)
        .bind(created_at)
        .execute(pool)
        .await
        .context("upsert run token usage")?;
    Ok(())
}

async fn upsert_run_token_usage_in_transaction(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    run_history_id: i64,
    usage: &NewRunTokenUsage,
    created_at: i64,
) -> Result<()> {
    validate_token_usage(usage)?;
    sqlx::query(UPSERT_RUN_TOKEN_USAGE_SQL)
        .bind(run_history_id)
        .bind(&usage.response_id)
        .bind(&usage.thread_id)
        .bind(&usage.turn_id)
        .bind(usage.input_tokens)
        .bind(usage.cached_input_tokens)
        .bind(usage.cache_write_input_tokens)
        .bind(usage.output_tokens)
        .bind(usage.reasoning_output_tokens)
        .bind(usage.total_tokens)
        .bind(created_at)
        .execute(&mut **tx)
        .await
        .context("upsert captured run token usage")?;
    Ok(())
}

fn map_token_usage_rollup(row: &sqlx::sqlite::SqliteRow) -> Result<RunTokenUsageRollup> {
    Ok(RunTokenUsageRollup {
        response_count: row
            .try_get("response_count")
            .context("read token usage response_count")?,
        input_tokens: row
            .try_get("input_tokens")
            .context("read token usage input_tokens")?,
        cached_input_tokens: row
            .try_get("cached_input_tokens")
            .context("read token usage cached_input_tokens")?,
        cache_write_input_tokens: row
            .try_get("cache_write_input_tokens")
            .context("read token usage cache_write_input_tokens")?,
        output_tokens: row
            .try_get("output_tokens")
            .context("read token usage output_tokens")?,
        reasoning_output_tokens: row
            .try_get("reasoning_output_tokens")
            .context("read token usage reasoning_output_tokens")?,
        total_tokens: row
            .try_get("total_tokens")
            .context("read token usage total_tokens")?,
    })
}

fn run_history_kind_label(kind: RunHistoryKind) -> &'static str {
    match kind {
        RunHistoryKind::Review => "review",
        RunHistoryKind::Security => "security",
        RunHistoryKind::Mention => "mention",
    }
}

/// Builds aggregate SQL without pagination. Filter conversion errors propagate.
fn token_usage_statistics_query(query: &RunHistoryListQuery) -> Result<QueryBuilder<Sqlite>> {
    let mut builder = QueryBuilder::<Sqlite>::new(
        "SELECT filtered.kind, COUNT(*) AS recorded_runs, \
         SUM(usage.response_count) AS response_count, SUM(usage.input_tokens) AS input_tokens, \
         SUM(usage.cached_input_tokens) AS cached_input_tokens, \
         SUM(usage.cache_write_input_tokens) AS cache_write_input_tokens, \
         SUM(usage.output_tokens) AS output_tokens, \
         SUM(usage.reasoning_output_tokens) AS reasoning_output_tokens, \
         SUM(usage.total_tokens) AS total_tokens \
         FROM (SELECT id, kind FROM run_history",
    );
    append_run_history_filters(&mut builder, query)?;
    builder.push(
        ") AS filtered JOIN run_history_token_usage_rollup AS usage \
         ON usage.run_history_id = filtered.id GROUP BY filtered.kind ORDER BY filtered.kind",
    );
    Ok(builder)
}

fn append_run_history_filters(
    builder: &mut QueryBuilder<Sqlite>,
    query: &RunHistoryListQuery,
) -> Result<bool> {
    let mut has_where = false;
    let mut push_where = |builder: &mut QueryBuilder<Sqlite>| {
        if has_where {
            builder.push(" AND ");
        } else {
            builder.push(" WHERE ");
            has_where = true;
        }
    };

    if let Some(repo) = query.repo.as_deref() {
        push_where(builder);
        builder.push("repo = ").push_bind(repo);
    }
    if let Some(iid) = query.iid {
        push_where(builder);
        builder
            .push("iid = ")
            .push_bind(sqlite_i64_from_u64(iid, "iid")?);
    }
    if let Some(kind) = query.kind {
        push_where(builder);
        builder
            .push("kind = ")
            .push_bind(run_history_kind_label(kind));
    }
    if let Some(result) = query.result.as_deref() {
        push_where(builder);
        builder.push("result = ").push_bind(result);
    }
    if let Some(search) = query
        .search
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let pattern = format!("%{search}%");
        push_where(builder);
        builder.push("(");
        builder.push("repo LIKE ").push_bind(pattern.clone());
        builder.push(" OR summary LIKE ").push_bind(pattern.clone());
        builder.push(" OR preview LIKE ").push_bind(pattern.clone());
        builder.push(" OR error LIKE ").push_bind(pattern.clone());
        builder
            .push(" OR trigger_note_body LIKE ")
            .push_bind(pattern);
        builder.push(")");
    }

    Ok(has_where)
}

fn append_run_history_cursor_clause(
    builder: &mut QueryBuilder<Sqlite>,
    has_where: &mut bool,
    cursor: RunHistoryCursor,
    direction: CursorDirection,
) {
    if *has_where {
        builder.push(" AND ");
    } else {
        builder.push(" WHERE ");
        *has_where = true;
    }
    builder.push("(");
    match direction {
        CursorDirection::After => builder
            .push("started_at < ")
            .push_bind(cursor.started_at)
            .push(" OR (started_at = ")
            .push_bind(cursor.started_at)
            .push(" AND id < ")
            .push_bind(cursor.id)
            .push(")"),
        CursorDirection::Before => builder
            .push("started_at > ")
            .push_bind(cursor.started_at)
            .push(" OR (started_at = ")
            .push_bind(cursor.started_at)
            .push(" AND id > ")
            .push_bind(cursor.id)
            .push(")"),
    };
    builder.push(")");
}

fn parse_run_history_kind(value: &str) -> Result<RunHistoryKind> {
    match value {
        "review" => Ok(RunHistoryKind::Review),
        "security" => Ok(RunHistoryKind::Security),
        "mention" => Ok(RunHistoryKind::Mention),
        other => bail!("unknown run_history kind: {other}"),
    }
}

fn transcript_backfill_state_label(state: TranscriptBackfillState) -> &'static str {
    match state {
        TranscriptBackfillState::NotRequested => "not_requested",
        TranscriptBackfillState::InProgress => "in_progress",
        TranscriptBackfillState::Complete => "complete",
        TranscriptBackfillState::Failed => "failed",
        TranscriptBackfillState::Expired => "expired",
    }
}

fn parse_transcript_backfill_state(value: &str) -> Result<TranscriptBackfillState> {
    match value {
        "not_requested" => Ok(TranscriptBackfillState::NotRequested),
        "in_progress" => Ok(TranscriptBackfillState::InProgress),
        "complete" => Ok(TranscriptBackfillState::Complete),
        "failed" => Ok(TranscriptBackfillState::Failed),
        "expired" => Ok(TranscriptBackfillState::Expired),
        other => bail!("unknown transcript_backfill state: {other}"),
    }
}

fn map_run_history_row(row: &sqlx::sqlite::SqliteRow) -> Result<RunHistoryRecord> {
    let iid_raw: i64 = row.try_get("iid").context("read run history iid")?;
    let trigger_note_id_raw: Option<i64> = row
        .try_get("trigger_note_id")
        .context("read run history trigger note id")?;
    let feature_flags_json: String = row
        .try_get("feature_flags_json")
        .context("read run history feature_flags_json")?;
    Ok(RunHistoryRecord {
        id: row.try_get("id").context("read run history id")?,
        kind: parse_run_history_kind(
            row.try_get::<String, _>("kind")
                .context("read run history kind")?
                .as_str(),
        )?,
        repo: row.try_get("repo").context("read run history repo")?,
        iid: u64::try_from(iid_raw).context("convert run history iid to u64")?,
        head_sha: row
            .try_get("head_sha")
            .context("read run history head sha")?,
        status: row.try_get("status").context("read run history status")?,
        result: row.try_get("result").context("read run history result")?,
        started_at: row
            .try_get("started_at")
            .context("read run history started_at")?,
        finished_at: row
            .try_get("finished_at")
            .context("read run history finished_at")?,
        updated_at: row
            .try_get("updated_at")
            .context("read run history updated_at")?,
        thread_id: row
            .try_get("thread_id")
            .context("read run history thread_id")?,
        turn_id: row.try_get("turn_id").context("read run history turn_id")?,
        review_thread_id: row
            .try_get("review_thread_id")
            .context("read run history review_thread_id")?,
        security_context_source_run_id: row
            .try_get("security_context_source_run_id")
            .context("read run history security_context_source_run_id")?,
        security_context_base_branch: row
            .try_get("security_context_base_branch")
            .context("read run history security_context_base_branch")?,
        security_context_base_head_sha: row
            .try_get("security_context_base_head_sha")
            .context("read run history security_context_base_head_sha")?,
        security_context_prompt_version: row
            .try_get("security_context_prompt_version")
            .context("read run history security_context_prompt_version")?,
        security_context_payload_json: row
            .try_get("security_context_payload_json")
            .context("read run history security_context_payload_json")?,
        security_context_generated_at: row
            .try_get("security_context_generated_at")
            .context("read run history security_context_generated_at")?,
        security_context_expires_at: row
            .try_get("security_context_expires_at")
            .context("read run history security_context_expires_at")?,
        preview: row.try_get("preview").context("read run history preview")?,
        summary: row.try_get("summary").context("read run history summary")?,
        error: row.try_get("error").context("read run history error")?,
        auth_account_name: row
            .try_get("auth_account_name")
            .context("read run history auth account")?,
        discussion_id: row
            .try_get("discussion_id")
            .context("read run history discussion id")?,
        trigger_note_id: trigger_note_id_raw
            .map(|value| u64::try_from(value).context("convert trigger_note_id to u64"))
            .transpose()?,
        trigger_note_author_name: row
            .try_get("trigger_note_author_name")
            .context("read run history trigger note author")?,
        trigger_note_body: row
            .try_get("trigger_note_body")
            .context("read run history trigger note body")?,
        command_repo: row
            .try_get("command_repo")
            .context("read run history command repo")?,
        commit_sha: row
            .try_get("commit_sha")
            .context("read run history commit sha")?,
        feature_flags: serde_json::from_str(&feature_flags_json)
            .context("deserialize run history feature flag snapshot")?,
        events_persisted_cleanly: row
            .try_get::<i64, _>("events_persisted_cleanly")
            .context("read run history events_persisted_cleanly")?
            != 0,
        transcript_backfill_state: parse_transcript_backfill_state(
            row.try_get::<String, _>("transcript_backfill_state")
                .context("read run history transcript_backfill_state")?
                .as_str(),
        )?,
        transcript_backfill_error: row
            .try_get("transcript_backfill_error")
            .context("read run history transcript_backfill_error")?,
    })
}

fn map_run_history_event_row(row: &sqlx::sqlite::SqliteRow) -> Result<RunHistoryEventRecord> {
    let payload_json: String = row
        .try_get("payload_json")
        .context("read run history event payload_json")?;
    Ok(RunHistoryEventRecord {
        id: row.try_get("id").context("read run history event id")?,
        run_history_id: row
            .try_get("run_history_id")
            .context("read run history event run_history_id")?,
        sequence: row
            .try_get("sequence")
            .context("read run history event sequence")?,
        turn_id: row
            .try_get("turn_id")
            .context("read run history event turn_id")?,
        event_type: row
            .try_get("event_type")
            .context("read run history event event_type")?,
        payload: serde_json::from_str(&payload_json)
            .context("deserialize run history event payload_json")?,
        created_at: row
            .try_get("created_at")
            .context("read run history event created_at")?,
    })
}

fn map_run_history_list_item_row(row: &sqlx::sqlite::SqliteRow) -> Result<RunHistoryListItem> {
    let iid_raw: i64 = row.try_get("iid").context("read run history list iid")?;
    let result: Option<String> = row
        .try_get("result")
        .context("read run history list result")?;
    let error: Option<String> = row
        .try_get("error")
        .context("read run history list error")?;
    let expose_error = matches!(result.as_deref(), Some("error" | "flagged"));
    Ok(RunHistoryListItem {
        id: row.try_get("id").context("read run history list id")?,
        kind: parse_run_history_kind(
            row.try_get::<String, _>("kind")
                .context("read run history list kind")?
                .as_str(),
        )?,
        repo: row.try_get("repo").context("read run history list repo")?,
        iid: u64::try_from(iid_raw).context("convert run history list iid to u64")?,
        status: row
            .try_get("status")
            .context("read run history list status")?,
        result,
        started_at: row
            .try_get("started_at")
            .context("read run history list started_at")?,
        preview: row
            .try_get("preview")
            .context("read run history list preview")?,
        summary: row
            .try_get("summary")
            .context("read run history list summary")?,
        error: if expose_error { error } else { None },
    })
}

fn normalized_run_history_finish_error(result: &str, error: Option<String>) -> Option<String> {
    if result == "error" && error.as_deref().is_none_or(|value| value.trim().is_empty()) {
        Some(MISSING_ERROR_DETAILS.to_string())
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn history_statistics_plan_uses_kind_covering_index() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let query = token_usage_statistics_query(&RunHistoryListQuery::default())?;
        let sql = format!("EXPLAIN QUERY PLAN {}", query.sql().as_str());
        let rows = sqlx::query(AssertSqlSafe(sql))
            .fetch_all(store.pool())
            .await?;
        let details = rows
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            details.contains("SCAN run_history USING COVERING INDEX idx_run_history_kind"),
            "{details}"
        );
        assert!(!details.contains("TEMP B-TREE FOR GROUP BY"), "{details}");
        Ok(())
    }

    #[tokio::test]
    async fn history_reconcile_plan_uses_in_progress_index() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let sql = format!("EXPLAIN QUERY PLAN {RECONCILE_INTERRUPTED_RUN_HISTORY_SQL}");
        let rows = sqlx::query(AssertSqlSafe(sql))
            .bind(0_i64)
            .bind(0_i64)
            .bind("restart")
            .fetch_all(store.pool())
            .await?;
        let details = rows
            .iter()
            .map(|row| row.get::<String, _>("detail"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            details.contains("SEARCH run_history USING INDEX idx_run_history_in_progress"),
            "{details}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn start_and_finish_run_history_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let run_id = store
            .run_history
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid: 11,
                head_sha: "sha-11".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;

        store
            .run_history
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "comment".to_string(),
                    ..RunHistoryFinish::default()
                },
            )
            .await?;

        let run = store
            .run_history
            .get_run_history(run_id)
            .await?
            .expect("run should exist");
        assert_eq!(run.result.as_deref(), Some("comment"));
        Ok(())
    }
}

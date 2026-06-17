use super::bucket_rows::{
    load_review_rate_limit_rule_bucket_rows, map_review_rate_limit_rule_bucket_row,
    materialize_rate_limit_available_slots, materialize_review_rate_limit_bucket_row,
    next_rate_limit_slot_at,
};
use super::{
    REVIEW_RATE_LIMIT_EPSILON, ReviewRateLimitAcquireOutcome, ReviewRateLimitBucketSnapshot,
    unique_review_rate_limit_rule_ids,
};
use crate::review::ReviewLane;
use crate::state::sqlite::SqliteCoordinator;
use anyhow::{Context, Result};
use sqlx::{Row, SqlitePool};

#[derive(Clone)]
pub(super) struct BucketRepository {
    sqlite: SqliteCoordinator,
}

impl BucketRepository {
    pub(super) fn new(sqlite: SqliteCoordinator) -> Self {
        Self { sqlite }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn list_active_review_rate_limit_buckets(
        &self,
        now: i64,
    ) -> Result<Vec<ReviewRateLimitBucketSnapshot>> {
        self.sqlite
            .write_foreground("list active review rate limit buckets", |pool| async move {
                let mut tx = pool.begin().await.context("start sqlite transaction")?;
                let rows = sqlx::query(
                    r"
                    SELECT r.id, r.label, r.applies_to_review, r.applies_to_security, r.scope,
                           r.capacity, r.window_seconds, r.created_at,
                           r.updated_at AS rule_updated_at, r.bucket_mode, b.bucket_id, b.target_kind,
                           b.target_path, b.scope_repo, b.scope_subject_iid, b.available_slots,
                           b.updated_at AS bucket_updated_at
                    FROM runtime_review_rate_limit_rule r
                    JOIN runtime_review_rate_limit_bucket b ON b.rule_id = r.id
                    ORDER BY r.created_at ASC, r.id ASC
                    ",
                )
                .fetch_all(tx.as_mut())
                .await
                .context("list active runtime review rate limit buckets")?;

                let mut active = Vec::with_capacity(rows.len());
                for row in rows {
                    let raw = map_review_rate_limit_rule_bucket_row(&row)?;
                    let materialized = materialize_review_rate_limit_bucket_row(&raw, now);
                    if materialized.is_full {
                        sqlx::query(
                            "DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?",
                        )
                        .bind(materialized.snapshot.bucket_id.as_str())
                        .execute(tx.as_mut())
                        .await
                        .context("delete full runtime review rate limit bucket")?;
                    } else {
                        active.push(materialized.snapshot);
                    }
                }
                tx.commit().await.context("commit sqlite transaction")?;
                Ok(active)
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn try_consume_review_rate_limits(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        now: i64,
    ) -> Result<ReviewRateLimitAcquireOutcome> {
        self.sqlite
            .write_foreground("consume review rate limits", |pool| async move {
                let mut tx = pool.begin().await.context("start sqlite transaction")?;
                let rows = load_review_rate_limit_rule_bucket_rows(&mut tx, lane, repo, iid)
                    .await
                    .context("load matching runtime review rate limit buckets")?;
                if rows.is_empty() {
                    tx.commit().await.context("commit sqlite transaction")?;
                    return Ok(ReviewRateLimitAcquireOutcome::Unmatched);
                }

                let mut materialized = Vec::with_capacity(rows.len());
                let mut blocked_next_retry_at: Option<i64> = None;
                for row in rows {
                    let state = materialize_review_rate_limit_bucket_row(&row, now);
                    if state.is_full {
                        sqlx::query(
                            "DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?",
                        )
                        .bind(state.snapshot.bucket_id.as_str())
                        .execute(tx.as_mut())
                        .await
                        .context("delete full runtime review rate limit bucket")?;
                    }
                    if state.current_available + REVIEW_RATE_LIMIT_EPSILON < 1.0 {
                        let next_retry_at = next_rate_limit_slot_at(
                            now,
                            state.current_available,
                            state.capacity,
                            state.window_seconds,
                            1.0,
                        );
                        blocked_next_retry_at = Some(match blocked_next_retry_at {
                            Some(existing) => existing.max(next_retry_at),
                            None => next_retry_at,
                        });
                    }
                    materialized.push(state);
                }

                if let Some(next_retry_at) = blocked_next_retry_at {
                    tx.commit().await.context("commit sqlite transaction")?;
                    return Ok(ReviewRateLimitAcquireOutcome::Blocked { next_retry_at });
                }

                let mut acquired_bucket_ids = Vec::with_capacity(materialized.len());
                for state in materialized {
                    let new_available = (state.current_available - 1.0).max(0.0);
                    if state.had_bucket_row {
                        if new_available + REVIEW_RATE_LIMIT_EPSILON >= f64::from(state.capacity) {
                            sqlx::query(
                                "DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?",
                            )
                            .bind(state.snapshot.bucket_id.as_str())
                            .execute(tx.as_mut())
                            .await
                            .context(
                                "delete full runtime review rate limit bucket after consume",
                            )?;
                        } else {
                            sqlx::query(
                                r"
                                UPDATE runtime_review_rate_limit_bucket
                                SET available_slots = ?, updated_at = ?
                                WHERE bucket_id = ?
                                ",
                            )
                            .bind(new_available)
                            .bind(now)
                            .bind(state.snapshot.bucket_id.as_str())
                            .execute(tx.as_mut())
                            .await
                            .context("update runtime review rate limit bucket after consume")?;
                        }
                    } else {
                        sqlx::query(
                            r"
                            INSERT INTO runtime_review_rate_limit_bucket (
                                bucket_id,
                                rule_id,
                                target_kind,
                                target_path,
                                scope_repo,
                                scope_subject_iid,
                                available_slots,
                                updated_at
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ",
                        )
                        .bind(state.snapshot.bucket_id.as_str())
                        .bind(state.snapshot.rule_id.as_str())
                        .bind(state.snapshot.target_kind.as_str())
                        .bind(state.snapshot.target_path.as_str())
                        .bind(state.snapshot.scope_repo.as_str())
                        .bind(state.snapshot.scope.subject_iid(state.snapshot.scope_iid))
                        .bind(new_available)
                        .bind(now)
                        .execute(tx.as_mut())
                        .await
                        .context("insert runtime review rate limit bucket after consume")?;
                    }
                    acquired_bucket_ids.push(state.snapshot.bucket_id);
                }

                tx.commit().await.context("commit sqlite transaction")?;
                Ok(ReviewRateLimitAcquireOutcome::Acquired {
                    bucket_ids: acquired_bucket_ids,
                })
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn refund_review_rate_limit_buckets(
        &self,
        bucket_ids: &[String],
        now: i64,
    ) -> Result<()> {
        if bucket_ids.is_empty() {
            return Ok(());
        }

        self.sqlite
            .write_foreground("refund review rate limit buckets", |pool| async move {
                refund_review_rate_limit_buckets_on_pool(pool, bucket_ids, now).await
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn refund_review_rate_limit_rule(
        &self,
        rule_id: &str,
        now: i64,
    ) -> Result<()> {
        self.sqlite
            .write_foreground("refund review rate limit rule", |pool| async move {
                let bucket_ids = sqlx::query_scalar::<_, String>(
                    r"
                    SELECT bucket_id
                    FROM runtime_review_rate_limit_bucket
                    WHERE rule_id = ?
                    ORDER BY bucket_id ASC
                    ",
                )
                .bind(rule_id)
                .fetch_all(&pool)
                .await
                .context("list runtime review rate limit buckets for rule refund")?;
                refund_review_rate_limit_buckets_on_pool(pool, &bucket_ids, now).await
            })
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub(super) async fn refund_review_rate_limit_bucket(
        &self,
        bucket_id: &str,
        now: i64,
    ) -> Result<()> {
        self.refund_review_rate_limit_buckets(&[bucket_id.to_string()], now)
            .await
    }
}

async fn refund_review_rate_limit_buckets_on_pool(
    pool: SqlitePool,
    bucket_ids: &[String],
    now: i64,
) -> Result<()> {
    let unique_bucket_ids = unique_review_rate_limit_rule_ids(bucket_ids)?;
    let mut tx = pool.begin().await.context("start sqlite transaction")?;
    for bucket_id in unique_bucket_ids {
        let row = sqlx::query(
            r"
            SELECT r.capacity, r.window_seconds, b.available_slots, b.updated_at
            FROM runtime_review_rate_limit_rule r
            LEFT JOIN runtime_review_rate_limit_bucket b ON b.rule_id = r.id
            WHERE b.bucket_id = ?
            ",
        )
        .bind(bucket_id.as_str())
        .fetch_optional(tx.as_mut())
        .await
        .context("load runtime review rate limit bucket for refund")?;
        let Some(row) = row else {
            continue;
        };

        let capacity_raw: i64 = row.try_get("capacity").context("read rule capacity")?;
        let capacity = u32::try_from(capacity_raw).context("convert rule capacity")?;
        let window_seconds: i64 = row
            .try_get("window_seconds")
            .context("read rule window seconds")?;
        let Some(available_slots_raw) = row
            .try_get::<Option<f64>, _>("available_slots")
            .context("read bucket available slots")?
        else {
            continue;
        };
        let Some(bucket_updated_at) = row
            .try_get::<Option<i64>, _>("updated_at")
            .context("read bucket updated_at")?
        else {
            continue;
        };

        let current_available = materialize_rate_limit_available_slots(
            Some(available_slots_raw),
            Some(bucket_updated_at),
            capacity,
            u64::try_from(window_seconds).context("convert rule window seconds")?,
            now,
        );
        let new_available = (current_available + 1.0).min(f64::from(capacity));
        if new_available + REVIEW_RATE_LIMIT_EPSILON >= f64::from(capacity) {
            sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?")
                .bind(bucket_id.as_str())
                .execute(tx.as_mut())
                .await
                .context("delete full runtime review rate limit bucket after refund")?;
        } else {
            sqlx::query(
                r"
                UPDATE runtime_review_rate_limit_bucket
                SET available_slots = ?, updated_at = ?
                WHERE bucket_id = ?
                ",
            )
            .bind(new_available)
            .bind(now)
            .bind(bucket_id.as_str())
            .execute(tx.as_mut())
            .await
            .context("update runtime review rate limit bucket after refund")?;
        }
    }
    tx.commit().await.context("commit sqlite transaction")?;
    Ok(())
}

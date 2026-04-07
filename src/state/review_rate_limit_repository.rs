use crate::review_lane::ReviewLane;
use anyhow::{Context, Result, bail};
use chrono::Utc;
use sqlx::{QueryBuilder, Row, Sqlite, SqlitePool};
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;
use uuid::Uuid;

use super::{
    ReviewRateLimitAcquireOutcome, ReviewRateLimitBucketMode, ReviewRateLimitBucketSnapshot,
    ReviewRateLimitPendingEntry, ReviewRateLimitRule, ReviewRateLimitRuleUpsert,
    ReviewRateLimitScope, ReviewRateLimitTarget, ReviewRateLimitTargetKind, parse_review_lane,
    sqlite_i64_from_u64,
};

#[derive(Clone)]
pub struct ReviewRateLimitRepository {
    pool: SqlitePool,
}

impl ReviewRateLimitRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
    async fn load_review_rate_limit_targets_by_rule_id(
        &self,
    ) -> Result<Vec<(String, ReviewRateLimitTarget)>> {
        load_review_rate_limit_targets_by_rule_id_from_executor(&self.pool).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_review_rate_limit_rules(&self) -> Result<Vec<ReviewRateLimitRule>> {
        let rows = sqlx::query(
            r"
            SELECT id, label, scope_repo, scope_subject_iid, applies_to_review, applies_to_security,
                   scope, capacity, window_seconds, created_at, updated_at, bucket_mode
            FROM runtime_review_rate_limit_rule
            ORDER BY created_at ASC, id ASC
            ",
        )
        .fetch_all(&self.pool)
        .await
        .context("list runtime review rate limit rules")?;

        let targets_by_rule_id = review_rate_limit_targets_by_rule_id(
            self.load_review_rate_limit_targets_by_rule_id().await?,
        );
        rows.into_iter()
            .map(|row| map_review_rate_limit_rule_row(&row, &targets_by_rule_id))
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn create_review_rate_limit_rule(
        &self,
        rule: &ReviewRateLimitRuleUpsert,
    ) -> Result<String> {
        validate_review_rate_limit_rule_upsert(rule)?;
        let id = rule
            .id
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let now = Utc::now().timestamp();
        let primary_target = rule_primary_target(rule)?;
        let bucket_mode =
            effective_review_rate_limit_bucket_mode(rule.scope, &rule.targets, rule.bucket_mode);
        let scope_repo = if is_global_review_rate_limit_target(&primary_target) {
            ""
        } else {
            primary_target.path.as_str()
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
        sqlx::query(
            r"
            INSERT INTO runtime_review_rate_limit_rule (
                id,
                label,
                scope_repo,
                scope_subject_iid,
                applies_to_review,
                applies_to_security,
                scope,
                capacity,
                window_seconds,
                bucket_mode,
                created_at,
                updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ",
        )
        .bind(&id)
        .bind(&rule.label)
        .bind(scope_repo)
        .bind(rule.scope.subject_iid(rule.scope_iid))
        .bind(rule.applies_to_review)
        .bind(rule.applies_to_security)
        .bind(rule.scope.as_str())
        .bind(i64::from(rule.capacity))
        .bind(i64::try_from(rule.window_seconds).context("convert rule window seconds to i64")?)
        .bind(bucket_mode.as_str())
        .bind(now)
        .bind(now)
        .execute(tx.as_mut())
        .await
        .context("insert runtime review rate limit rule")?;
        insert_review_rate_limit_rule_targets(tx.as_mut(), &id, &rule.targets, now).await?;
        tx.commit().await.context("commit sqlite transaction")?;
        Ok(id)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn update_review_rate_limit_rule(
        &self,
        rule: &ReviewRateLimitRuleUpsert,
    ) -> Result<()> {
        validate_review_rate_limit_rule_upsert(rule)?;
        let Some(id) = rule.id.as_deref() else {
            bail!("runtime review rate limit rule id is required for update");
        };
        let now = Utc::now().timestamp();
        let primary_target = rule_primary_target(rule)?;
        let bucket_mode =
            effective_review_rate_limit_bucket_mode(rule.scope, &rule.targets, rule.bucket_mode);
        let scope_repo = if is_global_review_rate_limit_target(&primary_target) {
            ""
        } else {
            primary_target.path.as_str()
        };
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
        let existing_row = sqlx::query(
            r"
            SELECT id, label, scope_repo, scope_subject_iid, applies_to_review, applies_to_security,
                   scope, capacity, window_seconds, created_at, updated_at, bucket_mode
            FROM runtime_review_rate_limit_rule
            WHERE id = ?
            ",
        )
        .bind(id)
        .fetch_optional(tx.as_mut())
        .await
        .context("load runtime review rate limit rule before update")?;
        let Some(existing_row) = existing_row else {
            tx.rollback().await.context("rollback sqlite transaction")?;
            bail!("runtime review rate limit rule not found: {id}");
        };
        let existing_targets_by_rule_id = review_rate_limit_targets_by_rule_id(
            load_review_rate_limit_targets_by_rule_id_from_executor(tx.as_mut())
                .await
                .context("load runtime review rate limit rule targets before update")?,
        );
        let existing_rule =
            map_review_rate_limit_rule_row(&existing_row, &existing_targets_by_rule_id)
                .context("map runtime review rate limit rule before update")?;
        let invalidate_buckets =
            review_rate_limit_rule_update_invalidates_buckets(&existing_rule, rule)?;
        let result = sqlx::query(
            r"
            UPDATE runtime_review_rate_limit_rule
            SET label = ?,
                scope_repo = ?,
                scope_subject_iid = ?,
                applies_to_review = ?,
                applies_to_security = ?,
                scope = ?,
                capacity = ?,
                window_seconds = ?,
                bucket_mode = ?,
                updated_at = ?
            WHERE id = ?
            ",
        )
        .bind(&rule.label)
        .bind(scope_repo)
        .bind(rule.scope.subject_iid(rule.scope_iid))
        .bind(rule.applies_to_review)
        .bind(rule.applies_to_security)
        .bind(rule.scope.as_str())
        .bind(i64::from(rule.capacity))
        .bind(i64::try_from(rule.window_seconds).context("convert rule window seconds to i64")?)
        .bind(bucket_mode.as_str())
        .bind(now)
        .bind(id)
        .execute(tx.as_mut())
        .await
        .context("update runtime review rate limit rule")?;
        if result.rows_affected() == 0 {
            tx.rollback().await.context("rollback sqlite transaction")?;
            bail!("runtime review rate limit rule not found: {id}");
        }
        sqlx::query("DELETE FROM runtime_review_rate_limit_rule_target WHERE rule_id = ?")
            .bind(id)
            .execute(tx.as_mut())
            .await
            .context("delete runtime review rate limit rule targets")?;
        insert_review_rate_limit_rule_targets(tx.as_mut(), id, &rule.targets, now).await?;
        if invalidate_buckets {
            sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE rule_id = ?")
                .bind(id)
                .execute(tx.as_mut())
                .await
                .context("delete invalidated runtime review rate limit buckets")?;
        }
        tx.commit().await.context("commit sqlite transaction")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn delete_review_rate_limit_rule(&self, id: &str) -> Result<()> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
        sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE rule_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("delete runtime review rate limit buckets")?;
        sqlx::query("DELETE FROM runtime_review_rate_limit_rule_target WHERE rule_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("delete runtime review rate limit targets")?;
        let result = sqlx::query("DELETE FROM runtime_review_rate_limit_rule WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .context("delete runtime review rate limit rule")?;
        if result.rows_affected() == 0 {
            tx.rollback().await.context("rollback sqlite transaction")?;
            bail!("runtime review rate limit rule not found: {id}");
        }
        tx.commit().await.context("commit sqlite transaction")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_active_review_rate_limit_buckets(
        &self,
        now: i64,
    ) -> Result<Vec<ReviewRateLimitBucketSnapshot>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
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
                sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?")
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
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn try_consume_review_rate_limits(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        now: i64,
    ) -> Result<ReviewRateLimitAcquireOutcome> {
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
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
                sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?")
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
                    sqlx::query("DELETE FROM runtime_review_rate_limit_bucket WHERE bucket_id = ?")
                        .bind(state.snapshot.bucket_id.as_str())
                        .execute(tx.as_mut())
                        .await
                        .context("delete full runtime review rate limit bucket after consume")?;
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
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_buckets(
        &self,
        bucket_ids: &[String],
        now: i64,
    ) -> Result<()> {
        if bucket_ids.is_empty() {
            return Ok(());
        }

        let unique_bucket_ids = unique_review_rate_limit_rule_ids(bucket_ids)?;
        let mut tx = self
            .pool
            .begin()
            .await
            .context("start sqlite transaction")?;
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

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_rule(&self, rule_id: &str, now: i64) -> Result<()> {
        let bucket_ids = sqlx::query_scalar::<_, String>(
            r"
            SELECT bucket_id
            FROM runtime_review_rate_limit_bucket
            WHERE rule_id = ?
            ORDER BY bucket_id ASC
            ",
        )
        .bind(rule_id)
        .fetch_all(&self.pool)
        .await
        .context("list runtime review rate limit buckets for rule refund")?;
        self.refund_review_rate_limit_buckets(&bucket_ids, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_bucket(&self, bucket_id: &str, now: i64) -> Result<()> {
        self.refund_review_rate_limit_buckets(&[bucket_id.to_string()], now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn upsert_review_rate_limit_pending(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        head_sha: &str,
        blocked_at: i64,
        next_retry_at: i64,
    ) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO runtime_review_rate_limit_pending (
                lane,
                repo,
                iid,
                first_blocked_at,
                last_blocked_at,
                last_seen_head_sha,
                next_retry_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(lane, repo, iid) DO UPDATE SET
                first_blocked_at = MIN(runtime_review_rate_limit_pending.first_blocked_at, excluded.first_blocked_at),
                last_blocked_at = MAX(runtime_review_rate_limit_pending.last_blocked_at, excluded.last_blocked_at),
                last_seen_head_sha = excluded.last_seen_head_sha,
                next_retry_at = excluded.next_retry_at
            ",
        )
        .bind(lane.as_str())
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .bind(blocked_at)
        .bind(blocked_at)
        .bind(head_sha)
        .bind(next_retry_at)
        .execute(&self.pool)
        .await
        .context("upsert runtime review rate limit pending row")?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn clear_review_rate_limit_pending(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
    ) -> Result<bool> {
        let result = sqlx::query(
            r"
            DELETE FROM runtime_review_rate_limit_pending
            WHERE lane = ? AND repo = ? AND iid = ?
            ",
        )
        .bind(lane.as_str())
        .bind(repo)
        .bind(sqlite_i64_from_u64(iid, "iid")?)
        .execute(&self.pool)
        .await
        .context("clear runtime review rate limit pending row")?;
        Ok(result.rows_affected() > 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_review_rate_limit_pending(&self) -> Result<Vec<ReviewRateLimitPendingEntry>> {
        let rows = sqlx::query(
            r"
            SELECT lane, repo, iid, first_blocked_at, last_blocked_at, last_seen_head_sha, next_retry_at
            FROM runtime_review_rate_limit_pending
            ORDER BY first_blocked_at ASC, lane ASC, repo ASC, iid ASC
            ",
        )
        .fetch_all(&self.pool)
        .await
        .context("list runtime review rate limit pending rows")?;

        rows.into_iter()
            .map(|row| map_review_rate_limit_pending_row(&row))
            .collect()
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn earliest_review_rate_limit_pending_retry_at(&self) -> Result<Option<i64>> {
        let next_retry_at = sqlx::query_scalar::<_, Option<i64>>(
            r"
            SELECT MIN(next_retry_at)
            FROM runtime_review_rate_limit_pending
            ",
        )
        .fetch_one(&self.pool)
        .await
        .context("load earliest runtime review rate limit pending retry time")?;
        Ok(next_retry_at)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn repo_has_due_review_rate_limit_pending(
        &self,
        repo: &str,
        now: i64,
    ) -> Result<bool> {
        let exists = sqlx::query_scalar::<_, i64>(
            r"
            SELECT EXISTS(
                SELECT 1
                FROM runtime_review_rate_limit_pending
                WHERE repo = ?
                  AND next_retry_at <= ?
            )
            ",
        )
        .bind(repo)
        .bind(now)
        .fetch_one(&self.pool)
        .await
        .context("check due runtime review rate limit pending rows")?;
        Ok(exists != 0)
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn sync_review_rate_limit_pending_rows(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        if open_iids.is_empty() {
            sqlx::query("DELETE FROM runtime_review_rate_limit_pending WHERE repo = ?")
                .bind(repo)
                .execute(&self.pool)
                .await
                .context("clear runtime review rate limit pending rows for closed repo")?;
            return Ok(());
        }

        let mut builder = QueryBuilder::<Sqlite>::new(
            "DELETE FROM runtime_review_rate_limit_pending WHERE repo = ",
        );
        builder.push_bind(repo);
        builder.push(" AND iid NOT IN (");
        let mut separated = builder.separated(", ");
        for iid in open_iids {
            separated.push_bind(sqlite_i64_from_u64(*iid, "iid")?);
        }
        separated.push_unseparated(")");
        builder
            .build()
            .execute(&self.pool)
            .await
            .context("prune closed merge requests from runtime review rate limit pending rows")?;
        Ok(())
    }
}

const REVIEW_RATE_LIMIT_EPSILON: f64 = 1e-9;
const GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH: &str = "*";

#[derive(Debug, Clone)]
struct ReviewRateLimitRuleBucketRow {
    bucket_id: String,
    rule_id: String,
    label: String,
    bucket_mode: ReviewRateLimitBucketMode,
    target_kind: ReviewRateLimitTargetKind,
    target_path: String,
    scope_repo: String,
    scope_subject_iid: i64,
    applies_to_review: bool,
    applies_to_security: bool,
    scope: ReviewRateLimitScope,
    capacity: u32,
    window_seconds: u64,
    available_slots: Option<f64>,
    bucket_updated_at: Option<i64>,
}

#[derive(Debug, Clone)]
struct MaterializedReviewRateLimitBucketRow {
    snapshot: ReviewRateLimitBucketSnapshot,
    current_available: f64,
    capacity: u32,
    window_seconds: u64,
    had_bucket_row: bool,
    is_full: bool,
}

fn validate_review_rate_limit_rule_upsert(rule: &ReviewRateLimitRuleUpsert) -> Result<()> {
    if rule.label.trim().is_empty() {
        bail!("runtime review rate limit rule label must not be empty");
    }
    let mut unique_targets = BTreeSet::new();
    for target in &rule.targets {
        let normalized = normalize_review_rate_limit_target(target)?;
        if !unique_targets.insert((normalized.kind, normalized.path)) {
            bail!("runtime review rate limit rule targets must be unique");
        }
    }
    if !rule.applies_to_review && !rule.applies_to_security {
        bail!("runtime review rate limit rule must cover at least one lane");
    }
    if rule.capacity == 0 {
        bail!("runtime review rate limit rule capacity must be greater than zero");
    }
    if rule.window_seconds == 0 {
        bail!("runtime review rate limit rule window_seconds must be greater than zero");
    }
    match rule.scope {
        ReviewRateLimitScope::Project if rule.scope_iid.is_some() => {
            bail!("project-scoped runtime review rate limit rules cannot set scope_iid")
        }
        ReviewRateLimitScope::MergeRequest if rule.scope_iid.is_some() => {
            bail!("merge-request-scoped runtime review rate limit rules cannot set scope_iid")
        }
        _ => Ok(()),
    }
}

fn unique_review_rate_limit_rule_ids(rule_ids: &[String]) -> Result<Vec<String>> {
    let mut unique = BTreeSet::new();
    for rule_id in rule_ids {
        let rule_id = rule_id.trim();
        if rule_id.is_empty() {
            bail!("runtime review rate limit rule id must not be empty");
        }
        unique.insert(rule_id.to_string());
    }
    Ok(unique.into_iter().collect())
}

fn normalize_review_rate_limit_target(
    target: &ReviewRateLimitTarget,
) -> Result<ReviewRateLimitTarget> {
    let path = target.path.trim().trim_matches('/').to_string();
    if path.is_empty() {
        bail!("runtime review rate limit rule target path must not be empty");
    }
    Ok(ReviewRateLimitTarget {
        kind: target.kind,
        path,
    })
}

fn normalize_review_rate_limit_targets(
    targets: &[ReviewRateLimitTarget],
) -> Result<Vec<ReviewRateLimitTarget>> {
    let mut normalized = Vec::with_capacity(targets.len());
    for target in targets {
        normalized.push(normalize_review_rate_limit_target(target)?);
    }
    Ok(normalized)
}

fn global_review_rate_limit_target() -> ReviewRateLimitTarget {
    ReviewRateLimitTarget {
        kind: ReviewRateLimitTargetKind::Repo,
        path: GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH.to_string(),
    }
}

fn is_global_review_rate_limit_target(target: &ReviewRateLimitTarget) -> bool {
    target.kind == ReviewRateLimitTargetKind::Repo
        && target.path == GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH
}

fn effective_review_rate_limit_bucket_mode(
    scope: ReviewRateLimitScope,
    targets: &[ReviewRateLimitTarget],
    bucket_mode: ReviewRateLimitBucketMode,
) -> ReviewRateLimitBucketMode {
    if scope == ReviewRateLimitScope::Project || targets.is_empty() {
        ReviewRateLimitBucketMode::Shared
    } else {
        bucket_mode
    }
}

fn effective_review_rate_limit_bucket_mode_for_bucket_row(
    scope: ReviewRateLimitScope,
    target_path: &str,
    bucket_mode: ReviewRateLimitBucketMode,
) -> ReviewRateLimitBucketMode {
    if scope == ReviewRateLimitScope::Project || target_path == GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH
    {
        ReviewRateLimitBucketMode::Shared
    } else {
        bucket_mode
    }
}

fn rule_primary_target(rule: &ReviewRateLimitRuleUpsert) -> Result<ReviewRateLimitTarget> {
    rule.targets
        .first()
        .map(normalize_review_rate_limit_target)
        .transpose()?
        .map_or_else(|| Ok(global_review_rate_limit_target()), Ok)
}

fn rule_primary_target_from_rule(rule: &ReviewRateLimitRule) -> Result<ReviewRateLimitTarget> {
    rule.targets.first().cloned().map_or_else(
        || {
            if rule.scope_repo.trim().is_empty() {
                Ok(global_review_rate_limit_target())
            } else {
                Ok(ReviewRateLimitTarget {
                    kind: ReviewRateLimitTargetKind::Repo,
                    path: rule.scope_repo.clone(),
                })
            }
        },
        Ok,
    )
}

fn review_rate_limit_rule_update_invalidates_buckets(
    existing: &ReviewRateLimitRule,
    updated: &ReviewRateLimitRuleUpsert,
) -> Result<bool> {
    let normalized_targets = normalize_review_rate_limit_targets(&updated.targets)?;
    Ok(existing.scope != updated.scope
        || existing.scope_iid != updated.scope_iid
        || existing.targets != normalized_targets
        || existing.bucket_mode
            != effective_review_rate_limit_bucket_mode(
                updated.scope,
                normalized_targets.as_slice(),
                updated.bucket_mode,
            )
        || existing.capacity != updated.capacity
        || existing.window_seconds != updated.window_seconds)
}

fn scope_subject_display(
    scope: ReviewRateLimitScope,
    repo: &str,
    scope_iid: Option<u64>,
) -> String {
    match scope {
        ReviewRateLimitScope::Project if repo.trim().is_empty() => "Global".to_string(),
        ReviewRateLimitScope::Project => repo.to_string(),
        ReviewRateLimitScope::MergeRequest if repo.trim().is_empty() => {
            "All merge requests".to_string()
        }
        ReviewRateLimitScope::MergeRequest => match scope_iid {
            Some(iid) => format!("{repo} !{iid}"),
            None => format!("{repo} !unknown"),
        },
    }
}

fn rule_targets_display(targets: &[ReviewRateLimitTarget]) -> String {
    match targets {
        [] => "Global".to_string(),
        [target] => target.path.clone(),
        _ => format!("{} targets", targets.len()),
    }
}

fn target_matches_repo(target: &ReviewRateLimitTarget, repo: &str) -> bool {
    if is_global_review_rate_limit_target(target) {
        return true;
    }
    match target.kind {
        ReviewRateLimitTargetKind::Repo => target.path == repo,
        ReviewRateLimitTargetKind::Group => {
            repo == target.path || repo.starts_with(&format!("{}/", target.path))
        }
    }
}

fn rate_limit_bucket_id(
    rule_id: &str,
    scope: ReviewRateLimitScope,
    scope_repo: &str,
    scope_iid: Option<u64>,
    bucket_mode: ReviewRateLimitBucketMode,
    target: &ReviewRateLimitTarget,
) -> String {
    match (scope, bucket_mode) {
        (ReviewRateLimitScope::Project, _) => format!("{rule_id}:repo:{scope_repo}"),
        (ReviewRateLimitScope::MergeRequest, ReviewRateLimitBucketMode::Shared) => {
            let iid = scope_iid.unwrap_or_default();
            format!("{rule_id}:mr:{scope_repo}:{iid}")
        }
        (ReviewRateLimitScope::MergeRequest, ReviewRateLimitBucketMode::Independent) => {
            let iid = scope_iid.unwrap_or_default();
            format!(
                "{rule_id}:mr:{scope_repo}:{iid}:{}:{}",
                target.kind.as_str(),
                target.path
            )
        }
    }
}

async fn insert_review_rate_limit_rule_targets(
    executor: &mut sqlx::SqliteConnection,
    rule_id: &str,
    targets: &[ReviewRateLimitTarget],
    now: i64,
) -> Result<()> {
    for (sort_order, target) in normalize_review_rate_limit_targets(targets)?
        .into_iter()
        .enumerate()
    {
        sqlx::query(
            r"
            INSERT INTO runtime_review_rate_limit_rule_target (
                rule_id,
                sort_order,
                target_kind,
                target_path,
                created_at
            )
            VALUES (?, ?, ?, ?, ?)
            ",
        )
        .bind(rule_id)
        .bind(
            i64::try_from(sort_order)
                .context("convert runtime review rate limit target sort order")?,
        )
        .bind(target.kind.as_str())
        .bind(target.path)
        .bind(now)
        .execute(&mut *executor)
        .await
        .context("insert runtime review rate limit rule target")?;
    }
    Ok(())
}

async fn load_review_rate_limit_targets_by_rule_id_from_executor<'a, E>(
    executor: E,
) -> Result<Vec<(String, ReviewRateLimitTarget)>>
where
    E: sqlx::Executor<'a, Database = Sqlite>,
{
    let rows = sqlx::query(
        r"
        SELECT rule_id, target_kind, target_path
        FROM runtime_review_rate_limit_rule_target
        ORDER BY rule_id ASC, sort_order ASC, created_at ASC, target_kind ASC, target_path ASC
        ",
    )
    .fetch_all(executor)
    .await
    .context("list runtime review rate limit rule targets")?;

    rows.into_iter()
        .map(|row| {
            Ok((
                row.try_get("rule_id")
                    .context("read runtime review rate limit rule target rule_id")?,
                ReviewRateLimitTarget {
                    kind: ReviewRateLimitTargetKind::from_str(
                        row.try_get::<String, _>("target_kind")
                            .context("read runtime review rate limit rule target kind")?
                            .as_str(),
                    )?,
                    path: row
                        .try_get("target_path")
                        .context("read runtime review rate limit rule target path")?,
                },
            ))
        })
        .collect()
}

async fn load_review_rate_limit_rule_bucket_rows(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    lane: ReviewLane,
    repo: &str,
    iid: u64,
) -> Result<Vec<ReviewRateLimitRuleBucketRow>> {
    let rule_rows = sqlx::query(
        r"
        SELECT id, label, scope_repo, scope_subject_iid, applies_to_review,
               applies_to_security, scope, capacity, window_seconds, bucket_mode,
               created_at, updated_at
        FROM runtime_review_rate_limit_rule
        WHERE (
            (? = 'general' AND applies_to_review = 1)
            OR (? = 'security' AND applies_to_security = 1)
        )
        ORDER BY created_at ASC, id ASC
        ",
    )
    .bind(lane.as_str())
    .bind(lane.as_str())
    .fetch_all(tx.as_mut())
    .await
    .context("load runtime review rate limit rules for bucket evaluation")?;
    let targets_by_rule_id = review_rate_limit_targets_by_rule_id(
        load_review_rate_limit_targets_by_rule_id_from_executor(tx.as_mut()).await?,
    );

    let mut rows = Vec::new();
    for row in rule_rows {
        let rule = map_review_rate_limit_rule_row(&row, &targets_by_rule_id)?;
        let matched_targets = if rule.targets.is_empty() {
            vec![global_review_rate_limit_target()]
        } else {
            rule.targets
                .iter()
                .filter(|target| target_matches_repo(target, repo))
                .cloned()
                .collect::<Vec<_>>()
        };
        if matched_targets.is_empty() {
            continue;
        }
        let bucket_mode =
            effective_review_rate_limit_bucket_mode(rule.scope, &rule.targets, rule.bucket_mode);
        let materialized_targets = match rule.scope {
            ReviewRateLimitScope::Project => vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: repo.to_string(),
            }],
            ReviewRateLimitScope::MergeRequest => match bucket_mode {
                ReviewRateLimitBucketMode::Shared => vec![rule_primary_target_from_rule(&rule)?],
                ReviewRateLimitBucketMode::Independent => matched_targets,
            },
        };
        for target in materialized_targets {
            let scope_repo = repo.to_string();
            let scope_iid = match rule.scope {
                ReviewRateLimitScope::Project => None,
                ReviewRateLimitScope::MergeRequest => Some(iid),
            };
            let bucket_id = rate_limit_bucket_id(
                &rule.id,
                rule.scope,
                scope_repo.as_str(),
                scope_iid,
                bucket_mode,
                &target,
            );
            rows.push(ReviewRateLimitRuleBucketRow {
                bucket_id: bucket_id.clone(),
                rule_id: rule.id.clone(),
                label: rule.label.clone(),
                bucket_mode,
                target_kind: target.kind,
                target_path: target.path.clone(),
                scope_repo,
                scope_subject_iid: rule.scope.subject_iid(scope_iid),
                applies_to_review: rule.applies_to_review,
                applies_to_security: rule.applies_to_security,
                scope: rule.scope,
                capacity: rule.capacity,
                window_seconds: rule.window_seconds,
                available_slots: None,
                bucket_updated_at: None,
            });
        }
    }

    let bucket_states = load_review_rate_limit_bucket_states_by_id(
        tx,
        rows.iter().map(|row| row.bucket_id.as_str()),
    )
    .await?;
    for row in &mut rows {
        if let Some((available_slots, updated_at)) = bucket_states.get(row.bucket_id.as_str()) {
            row.available_slots = Some(*available_slots);
            row.bucket_updated_at = Some(*updated_at);
        }
    }
    Ok(rows)
}

fn review_rate_limit_targets_by_rule_id(
    targets: Vec<(String, ReviewRateLimitTarget)>,
) -> HashMap<String, Vec<ReviewRateLimitTarget>> {
    let mut targets_by_rule_id = HashMap::new();
    for (rule_id, target) in targets {
        targets_by_rule_id
            .entry(rule_id)
            .or_insert_with(Vec::new)
            .push(target);
    }
    targets_by_rule_id
}

async fn load_review_rate_limit_bucket_states_by_id<I>(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    bucket_ids: I,
) -> Result<HashMap<String, (f64, i64)>>
where
    I: IntoIterator,
    I::Item: AsRef<str>,
{
    const SQLITE_BUCKET_ID_CHUNK_SIZE: usize = 900;

    let bucket_ids = bucket_ids
        .into_iter()
        .map(|bucket_id| bucket_id.as_ref().to_string())
        .collect::<Vec<_>>();
    if bucket_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let mut bucket_states = HashMap::with_capacity(bucket_ids.len());
    for bucket_id_chunk in bucket_ids.chunks(SQLITE_BUCKET_ID_CHUNK_SIZE) {
        let mut query_builder = QueryBuilder::<Sqlite>::new(
            "SELECT bucket_id, available_slots, updated_at FROM runtime_review_rate_limit_bucket WHERE bucket_id IN (",
        );
        {
            let mut separated = query_builder.separated(", ");
            for bucket_id in bucket_id_chunk {
                separated.push_bind(bucket_id.as_str());
            }
        }
        query_builder.push(")");
        let rows = query_builder
            .build()
            .fetch_all(tx.as_mut())
            .await
            .context("load runtime review rate limit buckets for evaluation")?;
        for row in rows {
            bucket_states.insert(
                row.try_get("bucket_id")
                    .context("read runtime review rate limit bucket bucket_id")?,
                (
                    row.try_get("available_slots")
                        .context("read runtime review rate limit bucket available_slots")?,
                    row.try_get("updated_at")
                        .context("read runtime review rate limit bucket updated_at")?,
                ),
            );
        }
    }

    Ok(bucket_states)
}

fn map_review_rate_limit_rule_row(
    row: &sqlx::sqlite::SqliteRow,
    targets_by_rule_id: &HashMap<String, Vec<ReviewRateLimitTarget>>,
) -> Result<ReviewRateLimitRule> {
    let scope = ReviewRateLimitScope::from_str(
        row.try_get::<String, _>("scope")
            .context("read runtime review rate limit rule scope")?
            .as_str(),
    )?;
    let scope_repo: String = row
        .try_get("scope_repo")
        .context("read runtime review rate limit rule scope_repo")?;
    let scope_subject_iid = row
        .try_get::<i64, _>("scope_subject_iid")
        .context("read runtime review rate limit rule scope_subject_iid")?;
    let scope_iid = scope.display_iid(scope_subject_iid);
    let id: String = row
        .try_get("id")
        .context("read runtime review rate limit rule id")?;
    let rule_targets = targets_by_rule_id.get(&id).cloned().unwrap_or_default();
    let scope_subject = if rule_targets.is_empty() {
        scope_subject_display(scope, scope_repo.as_str(), scope_iid)
    } else {
        let target_label = rule_targets_display(&rule_targets);
        scope_subject_display(scope, target_label.as_str(), scope_iid)
    };
    let bucket_mode = effective_review_rate_limit_bucket_mode(
        scope,
        rule_targets.as_slice(),
        ReviewRateLimitBucketMode::from_str(
            row.try_get::<String, _>("bucket_mode")
                .context("read runtime review rate limit rule bucket_mode")?
                .as_str(),
        )?,
    );
    Ok(ReviewRateLimitRule {
        id,
        label: row
            .try_get("label")
            .context("read runtime review rate limit rule label")?,
        scope_repo: scope_repo.clone(),
        targets: rule_targets.clone(),
        bucket_mode,
        scope_iid,
        scope_subject,
        applies_to_review: row
            .try_get::<i64, _>("applies_to_review")
            .context("read runtime review rate limit rule applies_to_review")?
            != 0,
        applies_to_security: row
            .try_get::<i64, _>("applies_to_security")
            .context("read runtime review rate limit rule applies_to_security")?
            != 0,
        scope,
        capacity: u32::try_from(
            row.try_get::<i64, _>("capacity")
                .context("read runtime review rate limit rule capacity")?,
        )
        .context("convert runtime review rate limit rule capacity to u32")?,
        window_seconds: u64::try_from(
            row.try_get::<i64, _>("window_seconds")
                .context("read runtime review rate limit rule window_seconds")?,
        )
        .context("convert runtime review rate limit rule window_seconds to u64")?,
        created_at: row
            .try_get("created_at")
            .context("read runtime review rate limit rule created_at")?,
        updated_at: row
            .try_get("updated_at")
            .context("read runtime review rate limit rule updated_at")?,
    })
}

fn map_review_rate_limit_pending_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ReviewRateLimitPendingEntry> {
    Ok(ReviewRateLimitPendingEntry {
        lane: parse_review_lane(
            row.try_get::<String, _>("lane")
                .context("read runtime review rate limit pending lane")?
                .as_str(),
        )?,
        repo: row
            .try_get("repo")
            .context("read runtime review rate limit pending repo")?,
        iid: u64::try_from(
            row.try_get::<i64, _>("iid")
                .context("read runtime review rate limit pending iid")?,
        )
        .context("convert runtime review rate limit pending iid to u64")?,
        first_blocked_at: row
            .try_get("first_blocked_at")
            .context("read runtime review rate limit pending first_blocked_at")?,
        last_blocked_at: row
            .try_get("last_blocked_at")
            .context("read runtime review rate limit pending last_blocked_at")?,
        last_seen_head_sha: row
            .try_get("last_seen_head_sha")
            .context("read runtime review rate limit pending last_seen_head_sha")?,
        next_retry_at: row
            .try_get("next_retry_at")
            .context("read runtime review rate limit pending next_retry_at")?,
    })
}

fn map_review_rate_limit_rule_bucket_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ReviewRateLimitRuleBucketRow> {
    let scope = ReviewRateLimitScope::from_str(
        row.try_get::<String, _>("scope")
            .context("read runtime review rate limit rule scope")?
            .as_str(),
    )?;
    let target_path: String = row
        .try_get("target_path")
        .context("read runtime review rate limit target path")?;
    let requested_bucket_mode = ReviewRateLimitBucketMode::from_str(
        row.try_get::<String, _>("bucket_mode")
            .context("read runtime review rate limit bucket mode")?
            .as_str(),
    )?;
    let bucket_mode = effective_review_rate_limit_bucket_mode_for_bucket_row(
        scope,
        &target_path,
        requested_bucket_mode,
    );
    Ok(ReviewRateLimitRuleBucketRow {
        bucket_id: row
            .try_get("bucket_id")
            .context("read runtime review rate limit bucket id")?,
        rule_id: row
            .try_get("id")
            .context("read runtime review rate limit rule id")?,
        label: row
            .try_get("label")
            .context("read runtime review rate limit rule label")?,
        bucket_mode,
        target_kind: ReviewRateLimitTargetKind::from_str(
            row.try_get::<String, _>("target_kind")
                .context("read runtime review rate limit target kind")?
                .as_str(),
        )?,
        target_path,
        scope_repo: row
            .try_get("scope_repo")
            .context("read runtime review rate limit rule scope_repo")?,
        scope_subject_iid: row
            .try_get("scope_subject_iid")
            .context("read runtime review rate limit rule scope_subject_iid")?,
        applies_to_review: row
            .try_get::<i64, _>("applies_to_review")
            .context("read runtime review rate limit rule applies_to_review")?
            != 0,
        applies_to_security: row
            .try_get::<i64, _>("applies_to_security")
            .context("read runtime review rate limit rule applies_to_security")?
            != 0,
        scope,
        capacity: u32::try_from(
            row.try_get::<i64, _>("capacity")
                .context("read runtime review rate limit rule capacity")?,
        )
        .context("convert runtime review rate limit rule capacity to u32")?,
        window_seconds: u64::try_from(
            row.try_get::<i64, _>("window_seconds")
                .context("read runtime review rate limit rule window_seconds")?,
        )
        .context("convert runtime review rate limit rule window_seconds to u64")?,
        available_slots: row
            .try_get("available_slots")
            .context("read runtime review rate limit bucket available_slots")?,
        bucket_updated_at: row
            .try_get("bucket_updated_at")
            .context("read runtime review rate limit bucket updated_at")?,
    })
}

fn materialize_review_rate_limit_bucket_row(
    raw: &ReviewRateLimitRuleBucketRow,
    now: i64,
) -> MaterializedReviewRateLimitBucketRow {
    let current_available = materialize_rate_limit_available_slots(
        raw.available_slots,
        raw.bucket_updated_at,
        raw.capacity,
        raw.window_seconds,
        now,
    );
    let snapshot = ReviewRateLimitBucketSnapshot {
        bucket_id: raw.bucket_id.clone(),
        rule_id: raw.rule_id.clone(),
        rule_label: raw.label.clone(),
        bucket_mode: raw.bucket_mode,
        target_kind: raw.target_kind,
        target_path: raw.target_path.clone(),
        scope_repo: raw.scope_repo.clone(),
        scope_iid: raw.scope.display_iid(raw.scope_subject_iid),
        scope_subject: scope_subject_display(
            raw.scope,
            raw.scope_repo.as_str(),
            raw.scope.display_iid(raw.scope_subject_iid),
        ),
        scope: raw.scope,
        repo: raw.scope_repo.clone(),
        iid: raw.scope.display_iid(raw.scope_subject_iid),
        applies_to_review: raw.applies_to_review,
        applies_to_security: raw.applies_to_security,
        available_slots: current_available,
        capacity: raw.capacity,
        window_seconds: raw.window_seconds,
        updated_at: raw.bucket_updated_at.unwrap_or(now),
        next_slot_at: Some(next_rate_limit_slot_at(
            now,
            current_available,
            raw.capacity,
            raw.window_seconds,
            next_rate_limit_ui_target(current_available, raw.capacity),
        )),
    };
    MaterializedReviewRateLimitBucketRow {
        is_full: current_available + REVIEW_RATE_LIMIT_EPSILON >= f64::from(raw.capacity),
        had_bucket_row: raw.available_slots.is_some(),
        capacity: raw.capacity,
        window_seconds: raw.window_seconds,
        current_available,
        snapshot,
    }
}

fn materialize_rate_limit_available_slots(
    available_slots: Option<f64>,
    bucket_updated_at: Option<i64>,
    capacity: u32,
    window_seconds: u64,
    now: i64,
) -> f64 {
    let Some(available_slots) = available_slots else {
        return f64::from(capacity);
    };
    let Some(bucket_updated_at) = bucket_updated_at else {
        return available_slots.min(f64::from(capacity));
    };
    let elapsed = u32::try_from(now.saturating_sub(bucket_updated_at).max(0)).unwrap_or(u32::MAX);
    let window_seconds = u32::try_from(window_seconds).unwrap_or(u32::MAX);
    let refill_rate = f64::from(capacity) / f64::from(window_seconds);
    let refilled = available_slots + (f64::from(elapsed) * refill_rate);
    refilled.min(f64::from(capacity))
}

fn next_rate_limit_ui_target(current_available: f64, capacity: u32) -> f64 {
    let capacity = f64::from(capacity);
    if current_available + REVIEW_RATE_LIMIT_EPSILON >= capacity {
        capacity
    } else if current_available < 1.0 {
        1.0
    } else {
        let next_whole = current_available.floor() + 1.0;
        next_whole.min(capacity)
    }
}

fn next_rate_limit_slot_at(
    now: i64,
    current_available: f64,
    capacity: u32,
    window_seconds: u64,
    target_available: f64,
) -> i64 {
    if target_available <= current_available + REVIEW_RATE_LIMIT_EPSILON {
        return now;
    }
    let window_seconds = u32::try_from(window_seconds).unwrap_or(u32::MAX);
    let refill_rate = f64::from(capacity) / f64::from(window_seconds);
    let delta = (target_available - current_available) / refill_rate;
    let delta = std::time::Duration::from_secs_f64(delta.max(0.0).ceil());
    let delta = i64::try_from(delta.as_secs()).unwrap_or(i64::MAX);
    now.saturating_add(delta)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ReviewStateStore;

    #[tokio::test]
    async fn create_and_delete_rate_limit_rule_roundtrip() -> Result<()> {
        let store = ReviewStateStore::new(":memory:").await?;
        let id = store
            .review_rate_limit
            .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
                id: None,
                label: "test-rule".to_string(),
                targets: Vec::new(),
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                scope: ReviewRateLimitScope::Project,
                capacity: 1,
                window_seconds: 60,
            })
            .await?;
        assert_eq!(
            store
                .review_rate_limit
                .list_review_rate_limit_rules()
                .await?
                .len(),
            1
        );
        store
            .review_rate_limit
            .delete_review_rate_limit_rule(&id)
            .await?;
        assert!(
            store
                .review_rate_limit
                .list_review_rate_limit_rules()
                .await?
                .is_empty()
        );
        Ok(())
    }
}

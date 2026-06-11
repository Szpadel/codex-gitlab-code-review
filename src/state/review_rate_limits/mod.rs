use anyhow::{Result, bail};
use sqlx::SqlitePool;
use std::collections::BTreeSet;

mod bucket_rows;
mod buckets;
mod pending;
mod rules;
mod types;

use buckets::BucketRepository;
use pending::PendingRepository;
use rules::RuleRepository;

pub use types::{
    ReviewRateLimitAcquireOutcome, ReviewRateLimitBucketMode, ReviewRateLimitBucketSnapshot,
    ReviewRateLimitPendingEntry, ReviewRateLimitRule, ReviewRateLimitRuleUpsert,
    ReviewRateLimitScope, ReviewRateLimitTarget, ReviewRateLimitTargetKind,
};

#[derive(Clone)]
pub struct ReviewRateLimitRepository {
    rules: RuleRepository,
    buckets: BucketRepository,
    pending: PendingRepository,
}

impl ReviewRateLimitRepository {
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            rules: RuleRepository::new(pool.clone()),
            buckets: BucketRepository::new(pool.clone()),
            pending: PendingRepository::new(pool),
        }
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_review_rate_limit_rules(&self) -> Result<Vec<ReviewRateLimitRule>> {
        self.rules.list_review_rate_limit_rules().await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn create_review_rate_limit_rule(
        &self,
        rule: &ReviewRateLimitRuleUpsert,
    ) -> Result<String> {
        self.rules.create_review_rate_limit_rule(rule).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn update_review_rate_limit_rule(
        &self,
        rule: &ReviewRateLimitRuleUpsert,
    ) -> Result<()> {
        self.rules.update_review_rate_limit_rule(rule).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn delete_review_rate_limit_rule(&self, id: &str) -> Result<()> {
        self.rules.delete_review_rate_limit_rule(id).await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_active_review_rate_limit_buckets(
        &self,
        now: i64,
    ) -> Result<Vec<ReviewRateLimitBucketSnapshot>> {
        self.buckets
            .list_active_review_rate_limit_buckets(now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn try_consume_review_rate_limits(
        &self,
        lane: crate::review::ReviewLane,
        repo: &str,
        iid: u64,
        now: i64,
    ) -> Result<ReviewRateLimitAcquireOutcome> {
        self.buckets
            .try_consume_review_rate_limits(lane, repo, iid, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_buckets(
        &self,
        bucket_ids: &[String],
        now: i64,
    ) -> Result<()> {
        self.buckets
            .refund_review_rate_limit_buckets(bucket_ids, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_rule(&self, rule_id: &str, now: i64) -> Result<()> {
        self.buckets
            .refund_review_rate_limit_rule(rule_id, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn refund_review_rate_limit_bucket(&self, bucket_id: &str, now: i64) -> Result<()> {
        self.buckets
            .refund_review_rate_limit_bucket(bucket_id, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn upsert_review_rate_limit_pending(
        &self,
        lane: crate::review::ReviewLane,
        repo: &str,
        iid: u64,
        head_sha: &str,
        blocked_at: i64,
        next_retry_at: i64,
    ) -> Result<()> {
        self.pending
            .upsert_review_rate_limit_pending(lane, repo, iid, head_sha, blocked_at, next_retry_at)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn clear_review_rate_limit_pending(
        &self,
        lane: crate::review::ReviewLane,
        repo: &str,
        iid: u64,
    ) -> Result<bool> {
        self.pending
            .clear_review_rate_limit_pending(lane, repo, iid)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn list_review_rate_limit_pending(&self) -> Result<Vec<ReviewRateLimitPendingEntry>> {
        self.pending.list_review_rate_limit_pending().await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn earliest_review_rate_limit_pending_retry_at(&self) -> Result<Option<i64>> {
        self.pending
            .earliest_review_rate_limit_pending_retry_at()
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn repo_has_due_review_rate_limit_pending(
        &self,
        repo: &str,
        now: i64,
    ) -> Result<bool> {
        self.pending
            .repo_has_due_review_rate_limit_pending(repo, now)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the `SQLite` state operation fails.
    pub async fn sync_review_rate_limit_pending_rows(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Result<()> {
        self.pending
            .sync_review_rate_limit_pending_rows(repo, open_iids)
            .await
    }
}

pub(super) const REVIEW_RATE_LIMIT_EPSILON: f64 = 1e-9;
pub(super) const GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH: &str = "*";

pub(super) fn unique_review_rate_limit_rule_ids(rule_ids: &[String]) -> Result<Vec<String>> {
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

pub(super) fn normalize_review_rate_limit_target(
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

pub(super) fn normalize_review_rate_limit_targets(
    targets: &[ReviewRateLimitTarget],
) -> Result<Vec<ReviewRateLimitTarget>> {
    let mut normalized = Vec::with_capacity(targets.len());
    for target in targets {
        normalized.push(normalize_review_rate_limit_target(target)?);
    }
    Ok(normalized)
}

pub(super) fn global_review_rate_limit_target() -> ReviewRateLimitTarget {
    ReviewRateLimitTarget {
        kind: ReviewRateLimitTargetKind::Repo,
        path: GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH.to_string(),
    }
}

pub(super) fn is_global_review_rate_limit_target(target: &ReviewRateLimitTarget) -> bool {
    target.kind == ReviewRateLimitTargetKind::Repo
        && target.path == GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH
}

pub(super) fn effective_review_rate_limit_bucket_mode(
    scope: ReviewRateLimitScope,
    has_independent_bucket_target: bool,
    bucket_mode: ReviewRateLimitBucketMode,
) -> ReviewRateLimitBucketMode {
    if scope == ReviewRateLimitScope::Project || !has_independent_bucket_target {
        ReviewRateLimitBucketMode::Shared
    } else {
        bucket_mode
    }
}

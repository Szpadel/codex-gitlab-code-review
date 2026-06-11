use super::rules::{
    load_review_rate_limit_targets_by_rule_id_from_executor, map_review_rate_limit_rule_row,
    review_rate_limit_targets_by_rule_id, rule_primary_target_from_rule, scope_subject_display,
};
use super::{
    GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH, REVIEW_RATE_LIMIT_EPSILON, ReviewRateLimitBucketMode,
    ReviewRateLimitBucketSnapshot, ReviewRateLimitScope, ReviewRateLimitTarget,
    ReviewRateLimitTargetKind, effective_review_rate_limit_bucket_mode,
    global_review_rate_limit_target, is_global_review_rate_limit_target,
};
use crate::review::ReviewLane;
use anyhow::{Context, Result};
use sqlx::{QueryBuilder, Row, Sqlite};
use std::collections::HashMap;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub(super) struct ReviewRateLimitRuleBucketRow {
    pub(super) bucket_id: String,
    pub(super) rule_id: String,
    pub(super) label: String,
    pub(super) bucket_mode: ReviewRateLimitBucketMode,
    pub(super) target_kind: ReviewRateLimitTargetKind,
    pub(super) target_path: String,
    pub(super) scope_repo: String,
    pub(super) scope_subject_iid: i64,
    pub(super) applies_to_review: bool,
    pub(super) applies_to_security: bool,
    pub(super) scope: ReviewRateLimitScope,
    pub(super) capacity: u32,
    pub(super) window_seconds: u64,
    pub(super) available_slots: Option<f64>,
    pub(super) bucket_updated_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct MaterializedReviewRateLimitBucketRow {
    pub(super) snapshot: ReviewRateLimitBucketSnapshot,
    pub(super) current_available: f64,
    pub(super) capacity: u32,
    pub(super) window_seconds: u64,
    pub(super) had_bucket_row: bool,
    pub(super) is_full: bool,
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

pub(super) async fn load_review_rate_limit_rule_bucket_rows(
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
        let bucket_mode = effective_review_rate_limit_bucket_mode(
            rule.scope,
            !rule.targets.is_empty(),
            rule.bucket_mode,
        );
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

pub(super) fn map_review_rate_limit_rule_bucket_row(
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
    let bucket_mode = effective_review_rate_limit_bucket_mode(
        scope,
        target_path != GLOBAL_REVIEW_RATE_LIMIT_TARGET_PATH,
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

pub(super) fn materialize_review_rate_limit_bucket_row(
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

pub(super) fn materialize_rate_limit_available_slots(
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

pub(super) fn next_rate_limit_slot_at(
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

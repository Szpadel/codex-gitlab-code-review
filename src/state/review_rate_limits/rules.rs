use super::{
    ReviewRateLimitBucketMode, ReviewRateLimitRule, ReviewRateLimitRuleUpsert,
    ReviewRateLimitScope, ReviewRateLimitTarget, ReviewRateLimitTargetKind,
    effective_review_rate_limit_bucket_mode, global_review_rate_limit_target,
    is_global_review_rate_limit_target, normalize_review_rate_limit_target,
    normalize_review_rate_limit_targets,
};
use anyhow::{Context, Result, bail};
use chrono::Utc;
use sqlx::{Row, Sqlite, SqlitePool};
use std::collections::{BTreeSet, HashMap};
use std::str::FromStr;
use uuid::Uuid;

#[derive(Clone)]
pub(super) struct RuleRepository {
    pool: SqlitePool,
}

impl RuleRepository {
    pub(super) fn new(pool: SqlitePool) -> Self {
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
    pub(super) async fn list_review_rate_limit_rules(&self) -> Result<Vec<ReviewRateLimitRule>> {
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
    pub(super) async fn create_review_rate_limit_rule(
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
        let bucket_mode = effective_review_rate_limit_bucket_mode(
            rule.scope,
            !rule.targets.is_empty(),
            rule.bucket_mode,
        );
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
    pub(super) async fn update_review_rate_limit_rule(
        &self,
        rule: &ReviewRateLimitRuleUpsert,
    ) -> Result<()> {
        validate_review_rate_limit_rule_upsert(rule)?;
        let Some(id) = rule.id.as_deref() else {
            bail!("runtime review rate limit rule id is required for update");
        };
        let now = Utc::now().timestamp();
        let primary_target = rule_primary_target(rule)?;
        let bucket_mode = effective_review_rate_limit_bucket_mode(
            rule.scope,
            !rule.targets.is_empty(),
            rule.bucket_mode,
        );
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
    pub(super) async fn delete_review_rate_limit_rule(&self, id: &str) -> Result<()> {
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

fn rule_primary_target(rule: &ReviewRateLimitRuleUpsert) -> Result<ReviewRateLimitTarget> {
    rule.targets
        .first()
        .map(normalize_review_rate_limit_target)
        .transpose()?
        .map_or_else(|| Ok(global_review_rate_limit_target()), Ok)
}

pub(super) fn rule_primary_target_from_rule(
    rule: &ReviewRateLimitRule,
) -> Result<ReviewRateLimitTarget> {
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
                !normalized_targets.is_empty(),
                updated.bucket_mode,
            )
        || existing.capacity != updated.capacity
        || existing.window_seconds != updated.window_seconds)
}

pub(super) fn scope_subject_display(
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

pub(super) async fn load_review_rate_limit_targets_by_rule_id_from_executor<'a, E>(
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

pub(super) fn review_rate_limit_targets_by_rule_id(
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

pub(super) fn map_review_rate_limit_rule_row(
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
        !rule_targets.is_empty(),
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

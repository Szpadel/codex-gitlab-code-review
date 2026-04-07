use super::StatusRateLimitSnapshot;
use crate::state::{
    ReviewRateLimitRuleUpsert, ReviewRateLimitTarget, ReviewRateLimitTargetKind, ReviewStateStore,
};
use anyhow::Result;
use chrono::Utc;
use std::sync::Arc;

#[derive(Clone)]
pub struct RateLimitService {
    state: Arc<ReviewStateStore>,
    repo_target_paths: Vec<String>,
    group_target_paths: Vec<String>,
}

impl RateLimitService {
    pub fn new(
        state: Arc<ReviewStateStore>,
        repo_target_paths: Vec<String>,
        group_target_paths: Vec<String>,
    ) -> Self {
        Self {
            state,
            repo_target_paths,
            group_target_paths,
        }
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn snapshot(&self) -> Result<StatusRateLimitSnapshot> {
        let now = Utc::now().timestamp();
        Ok(StatusRateLimitSnapshot {
            rules: self
                .state
                .review_rate_limit
                .list_review_rate_limit_rules()
                .await?,
            active_buckets: self
                .state
                .review_rate_limit
                .list_active_review_rate_limit_buckets(now)
                .await?,
            pending: self
                .state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?,
        })
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn target_suggestions(&self) -> Result<Vec<ReviewRateLimitTarget>> {
        let mut suggestions = Vec::new();
        for path in &self.repo_target_paths {
            suggestions.push(ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: path.clone(),
            });
        }
        for path in &self.group_target_paths {
            suggestions.push(ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Group,
                path: path.clone(),
            });
        }
        for rule in self
            .state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?
        {
            suggestions.extend(rule.targets);
        }

        let mut deduped = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for suggestion in suggestions {
            if seen.insert((suggestion.kind, suggestion.path.clone())) {
                deduped.push(suggestion);
            }
        }
        Ok(deduped)
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn create_rule(&self, rule: &ReviewRateLimitRuleUpsert) -> Result<String> {
        self.state
            .review_rate_limit
            .create_review_rate_limit_rule(rule)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn update_rule(&self, rule: &ReviewRateLimitRuleUpsert) -> Result<()> {
        self.state
            .review_rate_limit
            .update_review_rate_limit_rule(rule)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn delete_rule(&self, rule_id: &str) -> Result<()> {
        self.state
            .review_rate_limit
            .delete_review_rate_limit_rule(rule_id)
            .await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn refund_one_bucket_slot(&self, bucket_id: &str) -> Result<()> {
        self.state
            .review_rate_limit
            .refund_review_rate_limit_bucket(bucket_id, Utc::now().timestamp())
            .await
    }
}

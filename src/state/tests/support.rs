use super::*;

pub(super) fn review_rate_limit_rule(
    id: &str,
    label: &str,
    spec: ReviewRateLimitRuleSpec,
) -> ReviewRateLimitRuleUpsert {
    ReviewRateLimitRuleUpsert {
        id: Some(id.to_string()),
        label: label.to_string(),
        targets: spec.targets,
        bucket_mode: spec.bucket_mode,
        scope_iid: spec.scope_iid,
        applies_to_review: spec.applies_to_review,
        applies_to_security: spec.applies_to_security,
        scope: spec.scope,
        capacity: spec.capacity,
        window_seconds: spec.window_seconds,
    }
}

pub(super) struct ReviewRateLimitRuleSpec {
    pub(super) scope: ReviewRateLimitScope,
    pub(super) targets: Vec<ReviewRateLimitTarget>,
    pub(super) bucket_mode: ReviewRateLimitBucketMode,
    pub(super) scope_iid: Option<u64>,
    pub(super) applies_to_review: bool,
    pub(super) applies_to_security: bool,
    pub(super) capacity: u32,
    pub(super) window_seconds: u64,
}

pub(super) fn repo_target(path: &str) -> ReviewRateLimitTarget {
    ReviewRateLimitTarget {
        kind: ReviewRateLimitTargetKind::Repo,
        path: path.to_string(),
    }
}

pub(super) fn group_target(path: &str) -> ReviewRateLimitTarget {
    ReviewRateLimitTarget {
        kind: ReviewRateLimitTargetKind::Group,
        path: path.to_string(),
    }
}

pub(super) fn assert_approx_eq(actual: f64, expected: f64) {
    assert!(
        (actual - expected).abs() < 1e-6,
        "expected {expected}, got {actual}"
    );
}

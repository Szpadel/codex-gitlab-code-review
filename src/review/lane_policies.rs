use crate::config::{Config, FeatureFlagSnapshot};
use crate::state::RunHistoryKind;

pub(crate) trait ReviewLanePolicy: Send + Sync {
    fn flow_name(&self) -> &'static str;

    fn is_enabled(&self, feature_flags: &FeatureFlagSnapshot) -> bool;

    fn uses_awards(&self) -> bool;

    fn comment_marker_prefix<'a>(&self, config: &'a Config) -> &'a str;

    fn finding_marker_prefix<'a>(&self, config: &'a Config) -> &'a str;

    fn run_history_kind(&self) -> RunHistoryKind;

    fn skips_completed_review_result(&self) -> bool;

    fn resolves_review_project_path(&self) -> bool;

    fn additional_developer_instructions(&self, config: &Config) -> Option<String>;

    fn min_confidence_score(&self, config: &Config) -> Option<f32>;

    fn context_ttl_seconds(&self, config: &Config) -> Option<u64>;
}

pub(crate) struct GeneralLanePolicy;

impl ReviewLanePolicy for GeneralLanePolicy {
    fn flow_name(&self) -> &'static str {
        "review"
    }

    fn is_enabled(&self, _feature_flags: &FeatureFlagSnapshot) -> bool {
        true
    }

    fn uses_awards(&self) -> bool {
        true
    }

    fn comment_marker_prefix<'a>(&self, config: &'a Config) -> &'a str {
        &config.review.comment_marker_prefix
    }

    fn finding_marker_prefix<'a>(&self, _config: &'a Config) -> &'a str {
        "<!-- codex-review-finding:sha="
    }

    fn run_history_kind(&self) -> RunHistoryKind {
        RunHistoryKind::Review
    }

    fn skips_completed_review_result(&self) -> bool {
        false
    }

    fn resolves_review_project_path(&self) -> bool {
        true
    }

    fn additional_developer_instructions(&self, _config: &Config) -> Option<String> {
        None
    }

    fn min_confidence_score(&self, _config: &Config) -> Option<f32> {
        None
    }

    fn context_ttl_seconds(&self, _config: &Config) -> Option<u64> {
        None
    }
}

pub(crate) struct SecurityLanePolicy;

impl ReviewLanePolicy for SecurityLanePolicy {
    fn flow_name(&self) -> &'static str {
        "security_review"
    }

    fn is_enabled(&self, feature_flags: &FeatureFlagSnapshot) -> bool {
        feature_flags.security_review
    }

    fn uses_awards(&self) -> bool {
        false
    }

    fn comment_marker_prefix<'a>(&self, config: &'a Config) -> &'a str {
        &config.review.security.comment_marker_prefix
    }

    fn finding_marker_prefix<'a>(&self, config: &'a Config) -> &'a str {
        &config.review.security.finding_marker_prefix
    }

    fn run_history_kind(&self) -> RunHistoryKind {
        RunHistoryKind::Security
    }

    fn skips_completed_review_result(&self) -> bool {
        true
    }

    fn resolves_review_project_path(&self) -> bool {
        false
    }

    fn additional_developer_instructions(&self, config: &Config) -> Option<String> {
        config
            .review
            .security
            .additional_developer_instructions
            .clone()
    }

    fn min_confidence_score(&self, config: &Config) -> Option<f32> {
        Some(config.review.security.min_confidence_score)
    }

    fn context_ttl_seconds(&self, config: &Config) -> Option<u64> {
        Some(config.review.security.context_ttl_seconds)
    }
}

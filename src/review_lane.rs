//! Review lane identity and its fixed workflow behavior.

use crate::config::{Config, FeatureFlagSnapshot};
use crate::run_history_kind::RunHistoryKind;
use serde::{Deserialize, Serialize};

/// Selects general or security review behavior and its persisted lane name.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewLane {
    #[default]
    General,
    Security,
}

impl ReviewLane {
    /// Returns the stable lane name used in persisted state.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::General => "general",
            Self::Security => "security",
        }
    }

    /// Reports whether this is the security review lane.
    #[must_use]
    pub const fn is_security(self) -> bool {
        matches!(self, Self::Security)
    }

    /// Returns the human-readable label used in run history.
    #[must_use]
    pub const fn review_label(self) -> &'static str {
        match self {
            Self::General => "Review",
            Self::Security => "Security review",
        }
    }

    /// Returns the flow name used in recovery logs.
    pub(crate) const fn flow_name(self) -> &'static str {
        match self {
            Self::General => "review",
            Self::Security => "security_review",
        }
    }

    /// Checks the runtime feature gate; general reviews are always enabled.
    pub(crate) fn is_enabled(self, feature_flags: &FeatureFlagSnapshot) -> bool {
        match self {
            Self::General => true,
            Self::Security => feature_flags.security_review,
        }
    }

    /// Controls review awards; security reviews do not publish them.
    pub(crate) const fn uses_awards(self) -> bool {
        matches!(self, Self::General)
    }

    /// Selects the marker identifying this lane's summary comments.
    pub(crate) fn comment_marker_prefix(self, config: &Config) -> &str {
        match self {
            Self::General => &config.review.comment_marker_prefix,
            Self::Security => &config.review.security.comment_marker_prefix,
        }
    }

    /// Selects the marker identifying this lane's inline findings.
    pub(crate) fn finding_marker_prefix(self, config: &Config) -> &str {
        match self {
            Self::General => "<!-- codex-review-finding:sha=",
            Self::Security => &config.review.security.finding_marker_prefix,
        }
    }

    /// Selects the persisted run kind for this lane.
    pub(crate) const fn run_history_kind(self) -> RunHistoryKind {
        match self {
            Self::General => RunHistoryKind::Review,
            Self::Security => RunHistoryKind::Security,
        }
    }

    /// Uses any completed state to deduplicate security reviews, which may finish silently.
    /// General reviews count only a stored pass. Their comments count through GitLab markers.
    pub(crate) const fn skips_completed_review_result(self) -> bool {
        matches!(self, Self::Security)
    }

    /// Resolves fork source paths for general reviews; security uses the canonical project.
    pub(crate) const fn resolves_review_project_path(self) -> bool {
        matches!(self, Self::General)
    }

    /// Supplies lane-specific instructions; the runner applies the shared fallback.
    pub(crate) fn additional_developer_instructions(self, config: &Config) -> Option<String> {
        match self {
            Self::General => None,
            Self::Security => config
                .review
                .security
                .additional_developer_instructions
                .clone(),
        }
    }

    /// Applies the configured confidence threshold only to security findings.
    pub(crate) fn min_confidence_score(self, config: &Config) -> Option<f32> {
        match self {
            Self::General => None,
            Self::Security => Some(config.review.security.min_confidence_score),
        }
    }

    /// Applies security-context expiration only to security reviews.
    pub(crate) fn context_ttl_seconds(self, config: &Config) -> Option<u64> {
        match self {
            Self::General => None,
            Self::Security => Some(config.review.security.context_ttl_seconds),
        }
    }
}

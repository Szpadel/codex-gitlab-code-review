use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagSnapshot {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
    #[serde(default)]
    pub gitlab_inline_review_comments: bool,
    #[serde(default)]
    pub security_review: bool,
    #[serde(default)]
    pub composer_install: bool,
    #[serde(default)]
    pub composer_auto_repositories: bool,
    #[serde(default)]
    pub composer_safe_install: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFeatureFlagOverrides {
    #[serde(default)]
    pub gitlab_discovery_mcp: Option<bool>,
    #[serde(default)]
    pub gitlab_inline_review_comments: Option<bool>,
    #[serde(default)]
    pub security_review: Option<bool>,
    #[serde(default)]
    pub composer_install: Option<bool>,
    #[serde(default)]
    pub composer_auto_repositories: Option<bool>,
    #[serde(default)]
    pub composer_safe_install: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagDefaults {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
    #[serde(default)]
    pub gitlab_inline_review_comments: bool,
    #[serde(default)]
    pub security_review: bool,
    #[serde(default)]
    pub composer_install: bool,
    #[serde(default)]
    pub composer_auto_repositories: bool,
    #[serde(default)]
    pub composer_safe_install: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlagAvailability {
    pub gitlab_discovery_mcp: bool,
    pub gitlab_inline_review_comments: bool,
    pub security_review: bool,
    pub composer_install: bool,
    pub composer_auto_repositories: bool,
    pub composer_safe_install: bool,
}

impl FeatureFlagSnapshot {
    pub fn resolve(
        defaults: &FeatureFlagDefaults,
        availability: &FeatureFlagAvailability,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> Self {
        Self {
            gitlab_discovery_mcp: resolve_flag(
                defaults.gitlab_discovery_mcp,
                availability.gitlab_discovery_mcp,
                overrides.gitlab_discovery_mcp,
            ),
            gitlab_inline_review_comments: resolve_flag(
                defaults.gitlab_inline_review_comments,
                availability.gitlab_inline_review_comments,
                overrides.gitlab_inline_review_comments,
            ),
            security_review: resolve_flag(
                defaults.security_review,
                availability.security_review,
                overrides.security_review,
            ),
            composer_install: resolve_flag(
                defaults.composer_install,
                availability.composer_install,
                overrides.composer_install,
            ),
            composer_auto_repositories: resolve_flag(
                defaults.composer_auto_repositories,
                availability.composer_auto_repositories,
                overrides.composer_auto_repositories,
            ),
            composer_safe_install: resolve_flag(
                defaults.composer_safe_install,
                availability.composer_safe_install,
                overrides.composer_safe_install,
            ),
        }
    }
}

fn resolve_flag(default_enabled: bool, available: bool, runtime_override: Option<bool>) -> bool {
    if !available {
        return false;
    }

    runtime_override.unwrap_or(default_enabled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_override_can_enable_available_flag() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: false,
                security_review: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: true,
                gitlab_inline_review_comments: true,
                security_review: true,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                gitlab_inline_review_comments: None,
                security_review: None,
                composer_install: None,
                composer_auto_repositories: None,
                composer_safe_install: None,
            },
        );

        assert!(snapshot.gitlab_discovery_mcp);
    }

    #[test]
    fn unavailable_flag_stays_disabled_even_with_override() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: true,
                gitlab_inline_review_comments: true,
                security_review: true,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: false,
                security_review: false,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                gitlab_inline_review_comments: Some(true),
                security_review: Some(true),
                composer_install: None,
                composer_auto_repositories: None,
                composer_safe_install: None,
            },
        );

        assert!(!snapshot.gitlab_discovery_mcp);
        assert!(!snapshot.gitlab_inline_review_comments);
        assert!(!snapshot.security_review);
    }

    #[test]
    fn composer_flags_resolve_independently() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: false,
                security_review: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: true,
                security_review: true,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: None,
                gitlab_inline_review_comments: Some(true),
                security_review: Some(true),
                composer_install: Some(true),
                composer_auto_repositories: Some(true),
                composer_safe_install: Some(true),
            },
        );

        assert!(snapshot.gitlab_inline_review_comments);
        assert!(snapshot.security_review);
        assert!(snapshot.composer_install);
        assert!(snapshot.composer_auto_repositories);
        assert!(snapshot.composer_safe_install);
    }
}

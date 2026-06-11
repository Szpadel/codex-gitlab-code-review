use serde::{Deserialize, Serialize};

macro_rules! define_feature_flags {
    ($($flag:ident),+ $(,)?) => {
        #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct FeatureFlagSnapshot {
            $(
                #[serde(default)]
                pub $flag: bool,
            )+
        }

        #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct RuntimeFeatureFlagOverrides {
            $(
                #[serde(default)]
                pub $flag: Option<bool>,
            )+
        }

        #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
        pub struct FeatureFlagDefaults {
            $(
                #[serde(default)]
                pub $flag: bool,
            )+
        }

        #[derive(Clone, Debug, Default, PartialEq, Eq)]
        pub struct FeatureFlagAvailability {
            $(
                pub $flag: bool,
            )+
        }

        impl FeatureFlagSnapshot {
            #[must_use]
            pub fn resolve(
                defaults: &FeatureFlagDefaults,
                availability: &FeatureFlagAvailability,
                overrides: &RuntimeFeatureFlagOverrides,
            ) -> Self {
                Self {
                    $(
                        $flag: resolve_flag(
                            defaults.$flag,
                            availability.$flag,
                            overrides.$flag,
                        ),
                    )+
                }
            }
        }
    };
}

define_feature_flags! {
    gitlab_discovery_mcp,
    gitlab_inline_review_comments,
    security_review,
    security_context_ignore_base_head,
    composer_install,
    composer_auto_repositories,
    composer_safe_install,
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
                security_context_ignore_base_head: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: true,
                gitlab_inline_review_comments: true,
                security_review: true,
                security_context_ignore_base_head: true,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                gitlab_inline_review_comments: None,
                security_review: None,
                security_context_ignore_base_head: None,
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
                security_context_ignore_base_head: true,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: false,
                security_review: false,
                security_context_ignore_base_head: false,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                gitlab_inline_review_comments: Some(true),
                security_review: Some(true),
                security_context_ignore_base_head: Some(true),
                composer_install: None,
                composer_auto_repositories: None,
                composer_safe_install: None,
            },
        );

        assert!(!snapshot.gitlab_discovery_mcp);
        assert!(!snapshot.gitlab_inline_review_comments);
        assert!(!snapshot.security_review);
        assert!(!snapshot.security_context_ignore_base_head);
    }

    #[test]
    fn composer_flags_resolve_independently() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: false,
                security_review: false,
                security_context_ignore_base_head: false,
                composer_install: false,
                composer_auto_repositories: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                gitlab_inline_review_comments: true,
                security_review: true,
                security_context_ignore_base_head: true,
                composer_install: true,
                composer_auto_repositories: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: None,
                gitlab_inline_review_comments: Some(true),
                security_review: Some(true),
                security_context_ignore_base_head: Some(true),
                composer_install: Some(true),
                composer_auto_repositories: Some(true),
                composer_safe_install: Some(true),
            },
        );

        assert!(snapshot.gitlab_inline_review_comments);
        assert!(snapshot.security_review);
        assert!(snapshot.security_context_ignore_base_head);
        assert!(snapshot.composer_install);
        assert!(snapshot.composer_auto_repositories);
        assert!(snapshot.composer_safe_install);
    }

    #[test]
    fn flag_struct_literals_keep_update_syntax_available() {
        let _snapshot = FeatureFlagSnapshot {
            composer_safe_install: true,
            ..Default::default()
        };
        let _overrides = RuntimeFeatureFlagOverrides {
            composer_auto_repositories: Some(true),
            ..Default::default()
        };
        let _defaults = FeatureFlagDefaults {
            gitlab_inline_review_comments: true,
            ..Default::default()
        };
        let _availability = FeatureFlagAvailability {
            security_context_ignore_base_head: true,
            ..Default::default()
        };
    }
}

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagSnapshot {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
    #[serde(default)]
    pub composer_install: bool,
    #[serde(default)]
    pub composer_safe_install: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFeatureFlagOverrides {
    #[serde(default)]
    pub gitlab_discovery_mcp: Option<bool>,
    #[serde(default)]
    pub composer_install: Option<bool>,
    #[serde(default)]
    pub composer_safe_install: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagDefaults {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
    #[serde(default)]
    pub composer_install: bool,
    #[serde(default)]
    pub composer_safe_install: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlagAvailability {
    pub gitlab_discovery_mcp: bool,
    pub composer_install: bool,
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
            composer_install: resolve_flag(
                defaults.composer_install,
                availability.composer_install,
                overrides.composer_install,
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
                composer_install: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: true,
                composer_install: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                composer_install: None,
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
                composer_install: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                composer_install: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
                composer_install: None,
                composer_safe_install: None,
            },
        );

        assert!(!snapshot.gitlab_discovery_mcp);
    }

    #[test]
    fn composer_flags_resolve_independently() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: false,
                composer_install: false,
                composer_safe_install: false,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
                composer_install: true,
                composer_safe_install: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: None,
                composer_install: Some(true),
                composer_safe_install: Some(true),
            },
        );

        assert!(snapshot.composer_install);
        assert!(snapshot.composer_safe_install);
    }
}

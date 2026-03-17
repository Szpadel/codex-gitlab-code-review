use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagSnapshot {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFeatureFlagOverrides {
    #[serde(default)]
    pub gitlab_discovery_mcp: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureFlagDefaults {
    #[serde(default)]
    pub gitlab_discovery_mcp: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FeatureFlagAvailability {
    pub gitlab_discovery_mcp: bool,
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
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: true,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
            },
        );

        assert!(snapshot.gitlab_discovery_mcp);
    }

    #[test]
    fn unavailable_flag_stays_disabled_even_with_override() {
        let snapshot = FeatureFlagSnapshot::resolve(
            &FeatureFlagDefaults {
                gitlab_discovery_mcp: true,
            },
            &FeatureFlagAvailability {
                gitlab_discovery_mcp: false,
            },
            &RuntimeFeatureFlagOverrides {
                gitlab_discovery_mcp: Some(true),
            },
        );

        assert!(!snapshot.gitlab_discovery_mcp);
    }
}

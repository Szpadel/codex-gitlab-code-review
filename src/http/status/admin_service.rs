use super::StatusFeatureFlagSnapshot;
use crate::feature_flags::{
    FeatureFlagAvailability, FeatureFlagDefaults, FeatureFlagSnapshot, RuntimeFeatureFlagOverrides,
};
use crate::state::{ReviewStateStore, ScanMode, ScanOutcome, ScanState};
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone)]
pub struct AdminService {
    config: AdminConfig,
    state: Arc<ReviewStateStore>,
    csrf_token: String,
}

#[derive(Clone)]
struct AdminConfig {
    runtime_mode: String,
    status_ui_enabled: bool,
    feature_flag_defaults: FeatureFlagDefaults,
    feature_flag_availability: FeatureFlagAvailability,
}

impl AdminService {
    pub fn new(
        state: Arc<ReviewStateStore>,
        runtime_mode: String,
        status_ui_enabled: bool,
        feature_flag_defaults: FeatureFlagDefaults,
        feature_flag_availability: FeatureFlagAvailability,
    ) -> Self {
        Self {
            config: AdminConfig {
                runtime_mode,
                status_ui_enabled,
                feature_flag_defaults,
                feature_flag_availability,
            },
            state,
            csrf_token: Uuid::new_v4().to_string(),
        }
    }

    #[must_use]
    pub fn runtime_mode(&self) -> &str {
        &self.config.runtime_mode
    }

    pub(crate) fn status_ui_enabled(&self) -> bool {
        self.config.status_ui_enabled
    }

    pub(crate) fn feature_flag_csrf_token(&self) -> &str {
        &self.csrf_token
    }

    pub(crate) fn admin_csrf_token(&self) -> &str {
        &self.csrf_token
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn feature_flag_snapshots(&self) -> Result<Vec<StatusFeatureFlagSnapshot>> {
        let overrides = self
            .state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?;
        Ok(self.build_feature_flag_snapshots(&overrides))
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn update_runtime_feature_flag(
        &self,
        flag_name: &str,
        enabled: Option<bool>,
    ) -> Result<StatusFeatureFlagSnapshot> {
        match flag_name {
            "gitlab_discovery_mcp" => {
                if !self.config.feature_flag_availability.gitlab_discovery_mcp && enabled.is_some()
                {
                    bail!("invalid feature flag request: {flag_name} is unavailable");
                }
            }
            "gitlab_inline_review_comments"
            | "security_review"
            | "security_context_ignore_base_head"
            | "composer_install"
            | "composer_auto_repositories"
            | "composer_safe_install" => {}
            other => bail!("invalid feature flag: {other}"),
        }

        let mut overrides = self
            .state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?;
        match flag_name {
            "gitlab_discovery_mcp" => overrides.gitlab_discovery_mcp = enabled,
            "gitlab_inline_review_comments" => overrides.gitlab_inline_review_comments = enabled,
            "security_review" => overrides.security_review = enabled,
            "security_context_ignore_base_head" => {
                overrides.security_context_ignore_base_head = enabled;
            }
            "composer_install" => overrides.composer_install = enabled,
            "composer_auto_repositories" => overrides.composer_auto_repositories = enabled,
            "composer_safe_install" => overrides.composer_safe_install = enabled,
            _ => unreachable!("validated feature flag name"),
        }

        self.state
            .feature_flags
            .set_runtime_feature_flag_overrides(&overrides)
            .await?;
        self.build_feature_flag_snapshots(&overrides)
            .into_iter()
            .find(|flag| flag.name == flag_name)
            .ok_or_else(|| anyhow::anyhow!("missing feature flag after update: {flag_name}"))
    }

    fn build_feature_flag_snapshots(
        &self,
        overrides: &RuntimeFeatureFlagOverrides,
    ) -> Vec<StatusFeatureFlagSnapshot> {
        let effective = FeatureFlagSnapshot::resolve(
            &self.config.feature_flag_defaults,
            &self.config.feature_flag_availability,
            overrides,
        );
        vec![
            StatusFeatureFlagSnapshot {
                name: "gitlab_discovery_mcp".to_string(),
                available: self.config.feature_flag_availability.gitlab_discovery_mcp,
                default_enabled: self.config.feature_flag_defaults.gitlab_discovery_mcp,
                runtime_override: overrides.gitlab_discovery_mcp,
                effective_enabled: effective.gitlab_discovery_mcp,
            },
            StatusFeatureFlagSnapshot {
                name: "gitlab_inline_review_comments".to_string(),
                available: self
                    .config
                    .feature_flag_availability
                    .gitlab_inline_review_comments,
                default_enabled: self
                    .config
                    .feature_flag_defaults
                    .gitlab_inline_review_comments,
                runtime_override: overrides.gitlab_inline_review_comments,
                effective_enabled: effective.gitlab_inline_review_comments,
            },
            StatusFeatureFlagSnapshot {
                name: "security_review".to_string(),
                available: self.config.feature_flag_availability.security_review,
                default_enabled: self.config.feature_flag_defaults.security_review,
                runtime_override: overrides.security_review,
                effective_enabled: effective.security_review,
            },
            StatusFeatureFlagSnapshot {
                name: "security_context_ignore_base_head".to_string(),
                available: self
                    .config
                    .feature_flag_availability
                    .security_context_ignore_base_head,
                default_enabled: self
                    .config
                    .feature_flag_defaults
                    .security_context_ignore_base_head,
                runtime_override: overrides.security_context_ignore_base_head,
                effective_enabled: effective.security_context_ignore_base_head,
            },
            StatusFeatureFlagSnapshot {
                name: "composer_install".to_string(),
                available: self.config.feature_flag_availability.composer_install,
                default_enabled: self.config.feature_flag_defaults.composer_install,
                runtime_override: overrides.composer_install,
                effective_enabled: effective.composer_install,
            },
            StatusFeatureFlagSnapshot {
                name: "composer_auto_repositories".to_string(),
                available: self
                    .config
                    .feature_flag_availability
                    .composer_auto_repositories,
                default_enabled: self.config.feature_flag_defaults.composer_auto_repositories,
                runtime_override: overrides.composer_auto_repositories,
                effective_enabled: effective.composer_auto_repositories,
            },
            StatusFeatureFlagSnapshot {
                name: "composer_safe_install".to_string(),
                available: self.config.feature_flag_availability.composer_safe_install,
                default_enabled: self.config.feature_flag_defaults.composer_safe_install,
                runtime_override: overrides.composer_safe_install,
                effective_enabled: effective.composer_safe_install,
            },
        ]
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn mark_scan_started(&self, mode: ScanMode) -> Result<()> {
        let mut scan = self.state.service_state.get_scan_status().await?;
        scan.state = ScanState::Scanning;
        scan.mode = Some(mode);
        scan.started_at = Some(Utc::now().to_rfc3339());
        scan.finished_at = None;
        scan.outcome = None;
        scan.error = None;
        scan.next_scan_at = None;
        self.state.service_state.set_scan_status(&scan).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn mark_scan_finished(
        &self,
        mode: ScanMode,
        outcome: ScanOutcome,
        error: Option<String>,
    ) -> Result<()> {
        let mut scan = self.state.service_state.get_scan_status().await?;
        scan.state = ScanState::Idle;
        scan.mode = Some(mode);
        if scan.started_at.is_none() {
            scan.started_at = Some(Utc::now().to_rfc3339());
        }
        scan.finished_at = Some(Utc::now().to_rfc3339());
        scan.outcome = Some(outcome);
        scan.error = error;
        self.state.service_state.set_scan_status(&scan).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn set_next_scan_at(&self, next_scan_at: Option<DateTime<Utc>>) -> Result<()> {
        let mut scan = self.state.service_state.get_scan_status().await?;
        scan.next_scan_at = next_scan_at.map(|value| value.to_rfc3339());
        self.state.service_state.set_scan_status(&scan).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn clear_next_scan_at(&self) -> Result<()> {
        self.state.service_state.clear_next_scan_at().await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn recover_startup_status(&self) -> Result<()> {
        self.reconcile_interrupted_run_history().await?;
        let mut scan = self.state.service_state.get_scan_status().await?;
        scan.next_scan_at = None;
        if scan.state == ScanState::Scanning {
            scan.state = ScanState::Idle;
            scan.outcome = Some(ScanOutcome::Failure);
            scan.finished_at = Some(Utc::now().to_rfc3339());
            scan.error = Some("scan interrupted by service restart".to_string());
        }
        self.state.service_state.set_scan_status(&scan).await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn reconcile_interrupted_run_history(&self) -> Result<()> {
        self.state
            .run_history
            .reconcile_interrupted_run_history("run interrupted by service restart")
            .await?;
        Ok(())
    }
}

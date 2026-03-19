use super::*;
use crate::composer_install::{
    COMPOSER_INSTALL_TURN_ID, ComposerAuthLookup, ComposerInstallMode, ComposerInstallResult,
    composer_install_exec_command, composer_install_result_from_exec_output, prepare_composer_auth,
    redact_composer_related_output, resolve_composer_auth,
};
use crate::gitlab::GitLabClient;

impl DockerCodexRunner {
    pub(crate) async fn run_composer_install_step(
        &self,
        container_id: &str,
        repo_path: &str,
        project_path: &str,
        feature_flags: &FeatureFlagSnapshot,
        timeout_seconds: u64,
        run_history_id: Option<i64>,
    ) -> Option<ComposerInstallResult> {
        let mode = ComposerInstallMode::for_flags(feature_flags)?;
        let auth_lookup = self.resolve_composer_auth_lookup(project_path).await;
        let composer_auth = auth_lookup.value.clone();
        let prepared_auth = prepare_composer_auth(
            composer_auth.as_deref(),
            feature_flags.composer_auto_repositories,
        );
        let env = prepared_auth
            .env_value
            .as_ref()
            .map(|value| vec![format!("COMPOSER_AUTH={value}")]);
        let command = composer_install_exec_command(
            mode,
            timeout_seconds,
            prepared_auth.repository_config_json.as_deref(),
        );
        let command_label = mode.command_label();

        let result = match self
            .exec_container_command_with_env_allow_failure(
                container_id,
                command,
                Some(repo_path),
                env,
            )
            .await
        {
            Ok(output) => composer_install_result_from_exec_output(
                mode,
                auth_lookup.source,
                output.exit_code,
                &output.stdout,
                &output.stderr,
                Some(&self.gitlab_token),
                composer_auth.as_deref(),
            ),
            Err(err) => ComposerInstallResult::failed(
                mode,
                auth_lookup.source,
                redact_composer_related_output(
                    &err.to_string(),
                    Some(&self.gitlab_token),
                    composer_auth.as_deref(),
                ),
            ),
        };

        if result.attempted {
            if !result.success {
                warn!(
                    container_id,
                    repo_path,
                    project_path,
                    command = command_label,
                    auth_source = result.auth_source.as_deref().unwrap_or("none"),
                    "composer install failed; continuing run"
                );
            }
            self.append_composer_install_result(run_history_id, command_label, &result)
                .await;
        }

        Some(result)
    }

    async fn resolve_composer_auth_lookup(&self, project_path: &str) -> ComposerAuthLookup {
        match GitLabClient::new(self.git_base.as_str(), &self.gitlab_token) {
            Ok(gitlab) => resolve_composer_auth(&gitlab, project_path).await,
            Err(err) => {
                warn!(
                    project_path,
                    error = %err,
                    "failed to initialize gitlab client for COMPOSER_AUTH lookup; continuing without auth"
                );
                ComposerAuthLookup {
                    value: None,
                    source: None,
                }
            }
        }
    }

    async fn append_composer_install_result(
        &self,
        run_history_id: Option<i64>,
        command: &str,
        result: &ComposerInstallResult,
    ) {
        let events = composer_install_events(command, result);
        self.append_run_history_events(run_history_id, &events)
            .await;
    }
}

pub(crate) fn composer_install_events(
    command: &str,
    result: &ComposerInstallResult,
) -> Vec<NewRunHistoryEvent> {
    let turn_id = Some(COMPOSER_INSTALL_TURN_ID.to_string());
    let mut item = json!({
        "type": "commandExecution",
        "command": command,
        "status": if result.success { "completed" } else { "failed" },
    });
    if let Some(log_excerpt) = result.log_excerpt.as_deref() {
        item["aggregatedOutput"] = json!(log_excerpt);
    }
    if let Some(auth_source) = result.auth_source.as_deref() {
        item["metadata"] = json!({
            "authSource": auth_source,
            "mode": result.mode,
            "success": result.success,
        });
    } else {
        item["metadata"] = json!({
            "mode": result.mode,
            "success": result.success,
        });
    }
    vec![
        NewRunHistoryEvent {
            sequence: 1,
            turn_id: turn_id.clone(),
            event_type: "turn_started".to_string(),
            payload: annotate_event_payload(json!({})),
        },
        NewRunHistoryEvent {
            sequence: 2,
            turn_id: turn_id.clone(),
            event_type: "item_completed".to_string(),
            payload: annotate_event_payload(item),
        },
        NewRunHistoryEvent {
            sequence: 3,
            turn_id,
            event_type: "turn_completed".to_string(),
            payload: annotate_event_payload(json!({
                "status": "completed"
            })),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composer_install::ComposerInstallMode;

    #[test]
    fn composer_install_failure_events_create_completed_command_turn() {
        let result = ComposerInstallResult::failed(
            ComposerInstallMode::Safe,
            Some("group:team/platform".to_string()),
            "COMPOSER_AUTH detected from group team/platform\ninstall failed".to_string(),
        );

        let events = composer_install_events(
            "composer install --no-dev --no-scripts --no-plugins --prefer-dist --no-interaction --no-progress --ignore-platform-reqs",
            &result,
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[0].event_type, "turn_started");
        assert_eq!(events[1].event_type, "item_completed");
        assert_eq!(events[1].payload["type"], "commandExecution");
        assert_eq!(events[1].payload["status"], "failed");
        assert_eq!(
            events[1].payload["aggregatedOutput"],
            "COMPOSER_AUTH detected from group team/platform\ninstall failed"
        );
        assert_eq!(
            events[1].payload["metadata"]["authSource"],
            "group:team/platform"
        );
        assert_eq!(events[2].event_type, "turn_completed");
        assert_eq!(events[2].payload["status"], "completed");
    }

    #[test]
    fn composer_install_success_events_create_completed_command_turn() {
        let result = ComposerInstallResult::succeeded(
            ComposerInstallMode::Full,
            Some("project:group/repo".to_string()),
            Some(
                "COMPOSER_AUTH detected from repository group/repo\nInstalling dependencies from lock file"
                    .to_string(),
            ),
        );

        let events = composer_install_events(
            "composer install --no-interaction --no-progress --ignore-platform-reqs",
            &result,
        );

        assert_eq!(events.len(), 3);
        assert_eq!(events[1].payload["type"], "commandExecution");
        assert_eq!(events[1].payload["status"], "completed");
        assert_eq!(
            events[1].payload["aggregatedOutput"],
            "COMPOSER_AUTH detected from repository group/repo\nInstalling dependencies from lock file"
        );
        assert_eq!(events[1].payload["metadata"]["success"], true);
        assert_eq!(
            events[1].payload["metadata"]["authSource"],
            "project:group/repo"
        );
    }
}

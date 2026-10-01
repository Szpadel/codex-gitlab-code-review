use super::{
    DockerCodexRunner, FeatureFlagSnapshot, NewRunHistoryEvent, annotate_event_payload, json, warn,
};
use crate::composer_install::{
    COMPOSER_INSTALL_TURN_ID, ComposerCommandOutput, ComposerInstallMode, ComposerInstallPlan,
    ComposerInstallResult,
};

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
        let presence = self
            .exec_container_command_with_env_allow_failure(
                container_id,
                vec![
                    "test".to_string(),
                    "-f".to_string(),
                    "composer.json".to_string(),
                ],
                Some(repo_path),
                None,
            )
            .await;
        let preflight_error = match presence {
            Ok(output) if output.exit_code == 0 => None,
            Ok(output) if output.exit_code == 1 => {
                return Some(ComposerInstallResult::skipped(mode, None));
            }
            Ok(output) => Some(format!(
                "Check composer.json failed with exit code {}: {}",
                output.exit_code, output.stderr
            )),
            Err(err) => Some(format!("Check composer.json failed: {err:#}")),
        };
        if let Some(error) = preflight_error {
            warn!(
                container_id,
                repo_path, error, "Composer file check failed. Continue without installation"
            );
            let result = ComposerInstallResult::failed(mode, None, error);
            self.append_composer_install_result(run_history_id, mode.command_label(), &result)
                .await;
            return Some(result);
        }
        let plan = ComposerInstallPlan::prepare(
            self.gitlab.as_ref(),
            project_path,
            mode,
            feature_flags.composer_auto_repositories,
            timeout_seconds,
        )
        .await;
        let command_label = mode.command_label();

        let result = plan
            .execute(Some(&self.gitlab_token), |command, env| async move {
                self.exec_container_command_with_env_allow_failure(
                    container_id,
                    command,
                    Some(repo_path),
                    env,
                )
                .await
                .map(|output| ComposerCommandOutput {
                    exit_code: output.exit_code,
                    stdout: output.stdout,
                    stderr: output.stderr,
                })
            })
            .await;

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
    use crate::composer_install::{ComposerInstallMode, composer_install_exec_command};

    #[tokio::test]
    async fn composer_auth_uses_the_shared_gitlab_client() -> anyhow::Result<()> {
        use super::super::container::ContainerExecOutput;
        use super::super::test_support::{ExecContainerCommandRequest, FakeRunnerHarness};
        use std::sync::Arc;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/variables/COMPOSER_AUTH",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"key": "COMPOSER_AUTH", "value": "{}", "environment_scope": "*"}),
            ))
            .expect(2)
            .mount(&server)
            .await;
        let harness = Arc::new(FakeRunnerHarness::default());
        let runner = DockerCodexRunner::new_with_test_runtime(
            crate::config::test_builder::ConfigBuilder::for_review_tests()
                .build()
                .codex,
            url::Url::parse(&server.uri())?,
            Arc::new(crate::gitlab::GitLabClient::new(&server.uri(), "token")?),
            Arc::new(crate::state::ReviewStateStore::new(":memory:").await?),
            None,
            super::super::RunnerRuntimeOptions {
                gitlab_token: "token".to_string(),
                log_all_json: false,
                owner_id: "composer-test".to_string(),
                mention_commands_active: false,
                review_additional_developer_instructions: None,
            },
            harness.clone(),
        );

        for success in [true, false] {
            harness.push_exec_output(
                ExecContainerCommandRequest {
                    container_id: "app-1".to_string(),
                    command: vec![
                        "test".to_string(),
                        "-f".to_string(),
                        "composer.json".to_string(),
                    ],
                    cwd: Some("/work/repo".to_string()),
                    env: None,
                },
                ContainerExecOutput {
                    exit_code: 0,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            );
            let install_request = ExecContainerCommandRequest {
                container_id: "app-1".to_string(),
                command: composer_install_exec_command(ComposerInstallMode::Safe, 42, None),
                cwd: Some("/work/repo".to_string()),
                env: Some(vec!["COMPOSER_AUTH={}".to_string()]),
            };
            if success {
                harness.push_exec_output(
                    install_request,
                    ContainerExecOutput {
                        exit_code: 0,
                        stdout: "installed with token".to_string(),
                        stderr: String::new(),
                    },
                );
            } else {
                harness.push_exec_error(install_request, "installation failed with token");
            }
            let result = runner
                .run_composer_install_step(
                    "app-1",
                    "/work/repo",
                    "group/repo",
                    &FeatureFlagSnapshot {
                        composer_install: true,
                        composer_safe_install: true,
                        ..FeatureFlagSnapshot::default()
                    },
                    42,
                    None,
                )
                .await
                .expect("install result");
            assert_eq!(result.auth_source.as_deref(), Some("project:group/repo"));
            assert!(result.attempted);
            assert_eq!(result.success, success);
            assert!(
                result
                    .log_excerpt
                    .as_deref()
                    .expect("excerpt")
                    .contains(if success {
                        "installed with [REDACTED_GITLAB_TOKEN]"
                    } else {
                        "installation failed with [REDACTED_GITLAB_TOKEN]"
                    })
            );
        }
        server.verify().await;
        Ok(())
    }

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

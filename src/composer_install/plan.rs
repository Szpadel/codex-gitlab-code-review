//! Prepares one Composer command and converts its output into a redacted result.

use super::{
    ComposerInstallExecOutput, ComposerInstallMode, ComposerInstallResult, composer_debug_lines,
    composer_install_exec_command, composer_install_result_from_exec_output, prepare_composer_auth,
    resolve_composer_auth,
};
use crate::gitlab::GitLabApi;
use anyhow::Result;
use std::future::Future;

/// Keeps the command, credentials, and output diagnostics under one owner.
pub(crate) struct ComposerInstallPlan {
    mode: ComposerInstallMode,
    command: Vec<String>,
    env: Option<Vec<String>>,
    auth_source: Option<String>,
    composer_auth: Option<String>,
    debug_lines: Vec<String>,
}

/// Raw executor output. The plan redacts secrets before returning the result.
pub(crate) struct ComposerCommandOutput {
    pub(crate) exit_code: i64,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl ComposerInstallPlan {
    /// Resolves credentials through the supplied client and builds a bounded install command.
    /// Missing credentials do not prevent installation.
    pub(crate) async fn prepare(
        gitlab: &dyn GitLabApi,
        project_path: &str,
        mode: ComposerInstallMode,
        auto_repositories: bool,
        timeout_seconds: u64,
    ) -> Self {
        let auth_lookup = resolve_composer_auth(gitlab, project_path).await;
        let prepared_auth = prepare_composer_auth(auth_lookup.value.as_deref(), auto_repositories);
        let debug_lines = composer_debug_lines(&auth_lookup, &prepared_auth, auto_repositories);
        let command = composer_install_exec_command(
            mode,
            timeout_seconds,
            prepared_auth.repository_config_json.as_deref(),
        );
        let env = prepared_auth
            .env_value
            .map(|value| vec![format!("COMPOSER_AUTH={value}")]);
        Self {
            mode,
            command,
            env,
            auth_source: auth_lookup.source,
            composer_auth: auth_lookup.value,
            debug_lines,
        }
    }

    /// Runs the supplied executor once. Executor errors become redacted failed installs.
    pub(crate) async fn execute<F, Fut>(
        self,
        gitlab_token: Option<&str>,
        executor: F,
    ) -> ComposerInstallResult
    where
        F: FnOnce(Vec<String>, Option<Vec<String>>) -> Fut,
        Fut: Future<Output = Result<ComposerCommandOutput>>,
    {
        let output = match executor(self.command, self.env).await {
            Ok(output) => output,
            Err(error) => ComposerCommandOutput {
                exit_code: 1,
                stdout: String::new(),
                stderr: error.to_string(),
            },
        };
        composer_install_result_from_exec_output(ComposerInstallExecOutput {
            mode: self.mode,
            auth_source: self.auth_source,
            exit_code: output.exit_code,
            stdout: &output.stdout,
            stderr: &output.stderr,
            gitlab_token,
            composer_auth: self.composer_auth.as_deref(),
            debug_lines: &self.debug_lines,
        })
    }
}

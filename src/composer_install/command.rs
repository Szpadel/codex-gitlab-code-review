use super::{
    COMPOSER_SKIP_EXIT_CODE, COMPOSER_SKIP_MARKER, COMPOSER_SKIP_REASON_MISSING_JSON,
    ComposerInstallMode,
};
use crate::placeholders::render_placeholders;

const COMPOSER_INSTALL_SCRIPT_TEMPLATE: &str = include_str!("assets/install.sh");

#[must_use]
pub fn composer_install_exec_command(
    mode: ComposerInstallMode,
    timeout_seconds: u64,
    repository_config_json: Option<&str>,
) -> Vec<String> {
    let composer_command = format!("COMPOSER_ALLOW_SUPERUSER=1 {}", mode.command_label());
    let skip_line = composer_skip_line();
    let skip_exit_code = COMPOSER_SKIP_EXIT_CODE.to_string();
    let timeout_seconds_text = timeout_seconds.to_string();
    let composer_home_setup = repository_config_json
        .map(|config| {
            let config_q = shell_quote(config);
            format!(
                "composer_home=\"$(mktemp -d /tmp/codex-composer-home.XXXXXX)\" || {{\n\
  echo \"failed to create temporary COMPOSER_HOME\" >&2\n\
  exit 1\n\
}}\n\
printf '%s' {config_q} >\"$composer_home/config.json\" || {{\n\
  echo \"failed to write temporary Composer config\" >&2\n\
  exit 1\n\
}}\n\
export COMPOSER_HOME=\"$composer_home\"\n"
            )
        })
        .unwrap_or_default();
    let script = render_placeholders(
        COMPOSER_INSTALL_SCRIPT_TEMPLATE,
        &[
            ("SKIP_LINE", &skip_line),
            ("SKIP_EXIT_CODE", &skip_exit_code),
            ("COMPOSER_HOME_SETUP", &composer_home_setup),
            ("COMPOSER_COMMAND", &composer_command),
            ("TIMEOUT_SECONDS", &timeout_seconds_text),
        ],
    )
    .expect("composer install script template placeholders are valid");
    vec!["bash".to_string(), "-lc".to_string(), script]
}

pub(super) fn composer_skip_line() -> String {
    format!("{COMPOSER_SKIP_MARKER}:{COMPOSER_SKIP_REASON_MISSING_JSON}")
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn composer_install_exec_command_cleans_up_temporary_log_file() {
        let command = composer_install_exec_command(ComposerInstallMode::Full, 42, None);
        let script = command.last().expect("bash script");

        assert!(script.contains("mktemp /tmp/codex-composer-install."));
        assert!(script.contains("mktemp /tmp/codex-composer-timeout."));
        assert!(script.contains("trap cleanup EXIT"));
        assert!(script.contains("rm -f \"$log_file\""));
        assert!(script.contains("rm -f \"$timeout_marker\""));
        assert!(!script.contains("mktemp -d /tmp/codex-composer-home."));
        assert!(script.contains("composer install timed out after 42s"));
        let run_pid_pos = script.find("run_pid=\"$!\"").expect("run pid assignment");
        let watchdog_pos = script
            .find("watchdog_pid=\"$!\"")
            .expect("watchdog assignment");
        assert!(run_pid_pos < watchdog_pos);
    }

    #[test]
    fn composer_install_exec_command_configures_temporary_composer_home_when_requested() {
        let command = composer_install_exec_command(
            ComposerInstallMode::Full,
            42,
            Some(r#"{"repositories":[{"type":"composer","url":"https://example.com"}]}"#),
        );
        let script = command.last().expect("bash script");

        assert!(script.contains("composer_home=\"$(mktemp -d /tmp/codex-composer-home."));
        assert!(script.contains("failed to create temporary COMPOSER_HOME"));
        assert!(script.contains("failed to write temporary Composer config"));
        assert!(script.contains("export COMPOSER_HOME=\"$composer_home\""));
        assert!(script.contains("config.json"));
        assert!(script.contains("rm -rf \"$composer_home\""));
    }

    #[test]
    fn composer_install_exec_command_renders_snapshot_without_placeholders() {
        let command = composer_install_exec_command(
            ComposerInstallMode::Safe,
            42,
            Some(r#"{"repositories":[{"type":"composer","url":"https://example.com"}]}"#),
        );
        let script = command.last().expect("bash script");

        assert!(!script.contains("@@"), "{script}");
        insta::assert_snapshot!("composer_install_script", script);
    }
}

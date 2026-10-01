use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_grace_period_covers_review_and_optional_deduplication() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    for (inline_comments, expected_grace) in [("false", 157), ("true", 194)] {
        let feature_flag =
            format!("config.featureFlags.gitlabInlineReviewComments={inline_comments}");
        let output = Command::new("helm")
            .args([
                "template",
                "codex-gitlab-review",
                chart.to_str().expect("chart path"),
                "--set",
                "config.codex.timeoutSeconds=37",
                "--set",
                &feature_flag,
            ])
            .output()
            .expect("run helm template");
        assert!(
            output.status.success(),
            "helm template failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(
            rendered.contains(&format!("terminationGracePeriodSeconds: {expected_grace}")),
            "inline comments={inline_comments} must allow {expected_grace} seconds"
        );
    }
}

#[test]
fn chart_renders_graceful_restart_lifecycle() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let deployment =
        fs::read_to_string(templates.join("deployment.yaml")).expect("read deployment template");

    assert!(
        deployment.contains(
            "terminationGracePeriodSeconds: {{ add (int .Values.config.codex.timeoutSeconds) 120 }}"
        ),
        "deployment should derive termination grace from Codex timeout"
    );
    assert!(
        deployment.contains("kill -USR1 1"),
        "deployment preStop hook should request graceful drain via SIGUSR1"
    );
    assert!(
        deployment.contains("while kill -0 1 2>/dev/null; do"),
        "deployment preStop hook should wait for the main process to exit"
    );
    if let Ok(output) = Command::new("helm")
        .args([
            "template",
            "codex-gitlab-review",
            chart.to_str().expect("chart path"),
        ])
        .output()
    {
        assert!(
            output.status.success(),
            "helm template failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(rendered.contains("terminationGracePeriodSeconds: 1920"));
        assert!(rendered.contains("kill -USR1 1"));
    }
}

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_renders_graceful_restart_lifecycle() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let deployment =
        fs::read_to_string(templates.join("deployment.yaml")).expect("read deployment template");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("read values");

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
    assert!(
        values.contains("graceful restarts can wait for one started Codex run to finish"),
        "values should document why timeoutSeconds influences graceful shutdown"
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

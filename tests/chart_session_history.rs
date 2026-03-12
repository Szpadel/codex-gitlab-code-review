use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_mounts_custom_session_history_path() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let deployment =
        fs::read_to_string(templates.join("deployment.yaml")).expect("read deployment template");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("read values");

    assert!(
        deployment.contains("mkdir -p \"${auth_dir}/sessions\""),
        "deployment init container should create the sessions subtree"
    );
    assert!(
        deployment.contains("mountPath: {{ $sessionHistoryPath }}"),
        "deployment should expose a dedicated custom session-history mount when needed"
    );
    assert!(
        deployment.contains("subPath: {{ printf \"%s/sessions\" $primaryAuthSubPath }}"),
        "custom session-history mount should point at the primary auth sessions subtree"
    );
    assert!(
        values.contains("sessionHistoryPath: \"\""),
        "values should expose the optional session-history override"
    );

    if let Ok(output) = Command::new("helm")
        .args([
            "template",
            "codex-gitlab-review",
            chart.to_str().expect("chart path"),
            "--set",
            "config.codex.sessionHistoryPath=/var/lib/codex-sessions",
        ])
        .output()
    {
        assert!(
            output.status.success(),
            "helm template failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(rendered.contains("mountPath: /var/lib/codex-sessions"));
        assert!(rendered.contains("subPath: codex-auth/sessions"));
    }
}

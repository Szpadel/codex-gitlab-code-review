use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_exposes_work_tmpfs_settings() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("read values");
    let configmap =
        fs::read_to_string(templates.join("configmap.yaml")).expect("read configmap template");

    assert!(
        values.contains("\n    workTmpfs:\n"),
        "values.yaml should expose workTmpfs settings under config.codex"
    );
    assert!(
        values.contains("enabled: true"),
        "workTmpfs should be enabled by default in Helm values"
    );
    assert!(
        values.contains("sizeMiB: null"),
        "workTmpfs should expose an optional size cap in Helm values"
    );
    assert!(
        configmap.contains("work_tmpfs:"),
        "configmap template should render codex.work_tmpfs settings"
    );
    assert!(
        configmap.contains("size_mib: null"),
        "configmap template should render null when sizeMiB is not set"
    );

    if let Ok(output) = Command::new("helm")
        .args([
            "template",
            "codex-gitlab-review",
            chart.to_str().expect("chart path"),
            "--set",
            "config.codex.workTmpfs.enabled=false",
            "--set",
            "config.codex.workTmpfs.sizeMiB=256",
        ])
        .output()
    {
        assert!(
            output.status.success(),
            "helm template failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(rendered.contains("work_tmpfs:"));
        assert!(rendered.contains("enabled: false"));
        assert!(rendered.contains("size_mib: 256"));
    }
}

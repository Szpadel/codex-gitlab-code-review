use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_ships_opt_in_ingress_support() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("read values");
    let ingress = fs::read_to_string(templates.join("ingress.yaml")).expect("read ingress");
    let notes = fs::read_to_string(templates.join("NOTES.txt")).expect("read notes");

    assert!(
        values.contains("\ningress:\n"),
        "values.yaml should expose ingress settings"
    );
    assert!(
        values.contains("enabled: false"),
        "ingress should stay opt-in by default"
    );
    assert!(
        values.contains("statusUiEnabled: false"),
        "status UI should remain disabled by default"
    );
    assert!(
        ingress.contains("kind: Ingress"),
        "chart should ship an ingress template"
    );
    assert!(
        ingress.contains("networking.k8s.io/v1"),
        "ingress template should use networking.k8s.io/v1"
    );
    assert!(
        ingress.contains("{{- if .Values.ingress.enabled }}"),
        "ingress template should be guarded by ingress.enabled"
    );
    assert!(
        notes.contains("It does not enable the status UI/API"),
        "chart notes should document ingress and status UI decoupling"
    );

    if let Ok(output) = Command::new("helm")
        .args([
            "template",
            "codex-gitlab-review",
            chart.to_str().expect("chart path"),
            "--set",
            "ingress.enabled=true",
            "--set",
            "ingress.className=nginx",
            "--set",
            "ingress.hosts[0].host=review.example.com",
            "--set",
            "ingress.hosts[0].paths[0].path=/",
            "--set",
            "ingress.hosts[0].paths[0].pathType=Prefix",
        ])
        .output()
    {
        assert!(
            output.status.success(),
            "helm template failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let rendered = String::from_utf8_lossy(&output.stdout);
        assert!(rendered.contains("kind: Ingress"));
        assert!(rendered.contains("ingressClassName: \"nginx\""));
        assert!(rendered.contains("host: \"review.example.com\""));
        assert!(rendered.contains("path: \"/\""));
        assert!(rendered.contains("pathType: \"Prefix\""));
        assert!(rendered.contains("number: 8080"));
    }
}

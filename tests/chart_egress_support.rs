use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn chart_does_not_ship_proxy_or_network_firewall_support() {
    let chart = Path::new(env!("CARGO_MANIFEST_DIR")).join("charts/codex-gitlab-review");
    let templates = chart.join("templates");
    let values = fs::read_to_string(chart.join("values.yaml")).expect("read values");
    let deployment =
        fs::read_to_string(templates.join("deployment.yaml")).expect("read deployment template");
    let configmap =
        fs::read_to_string(templates.join("configmap.yaml")).expect("read configmap template");
    let notes = fs::read_to_string(templates.join("NOTES.txt")).expect("read notes template");

    assert!(
        !values.contains("\nproxy:\n"),
        "values.yaml should not expose proxy settings"
    );
    assert!(
        !values.contains("\nnetworkPolicy:\n"),
        "values.yaml should not expose networkPolicy settings"
    );
    assert!(
        !templates.join("proxy-configmap.yaml").exists(),
        "proxy configmap template should be removed"
    );
    assert!(
        !templates.join("networkpolicy.yaml").exists(),
        "network policy template should be removed"
    );
    assert!(
        notes.contains("proxy and egress-firewall chart support has been removed"),
        "chart notes should warn about removed egress controls"
    );
    assert!(
        !deployment.contains("egress-proxy"),
        "deployment should not add a proxy sidecar"
    );
    assert!(
        !deployment.contains("proxy-config"),
        "deployment should not mount proxy config"
    );
    assert!(
        !configmap.contains("http_proxy"),
        "rendered app config should not inject proxy env settings"
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
        for forbidden in [
            "kind: NetworkPolicy",
            "egress-proxy",
            "proxy-config",
            "http_proxy:",
            "https_proxy:",
            "no_proxy:",
        ] {
            assert!(
                !rendered.contains(forbidden),
                "rendered chart should not contain {forbidden}"
            );
        }
    }
}

use super::*;

#[tokio::test]
async fn sequential_session_image_checks_reuse_the_warmup_pull() -> Result<()> {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, query_param},
    };

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(query_param(
            "fromImage",
            "ghcr.io/openai/codex-universal:latest",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("{\"status\":\"Downloaded\"}\n"),
        )
        .expect(1)
        .mount(&server)
        .await;
    let runner = DockerCodexRunner::new(
        &DockerConfig { host: server.uri() },
        test_codex_config(),
        Url::parse("http://127.0.0.1:9")?,
        Arc::new(crate::gitlab::GitLabClient::new("http://127.0.0.1:9", "")?),
        Arc::new(ReviewStateStore::new(":memory:").await?),
        None,
        RunnerRuntimeOptions {
            gitlab_token: String::new(),
            log_all_json: false,
            owner_id: "image-test".to_string(),
            mention_commands_active: false,
            review_additional_developer_instructions: None,
        },
    )?;

    runner.warm_up_images().await?;
    runner
        .ensure_image_available("ghcr.io/openai/codex-universal")
        .await?;
    runner
        .ensure_image_available("ghcr.io/openai/codex-universal:latest")
        .await?;

    server.verify().await;
    Ok(())
}
#[test]
fn normalize_image_reference_appends_latest_when_missing_tag() {
    let image = "ghcr.io/openai/codex-universal";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal:latest"
    );
}

#[test]
fn normalize_image_reference_preserves_tag() {
    let image = "ghcr.io/openai/codex-universal:v1.2.3";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal:v1.2.3"
    );
}

#[test]
fn normalize_image_reference_preserves_digest() {
    let image = "ghcr.io/openai/codex-universal@sha256:deadbeef";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "ghcr.io/openai/codex-universal@sha256:deadbeef"
    );
}

#[test]
fn normalize_image_reference_handles_registry_port() {
    let image = "localhost:5000/codex-universal";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "localhost:5000/codex-universal:latest"
    );
}

#[test]
fn normalize_image_reference_keeps_tag_with_registry_port() {
    let image = "localhost:5000/codex-universal:canary";
    assert_eq!(
        DockerCodexRunner::normalize_image_reference(image),
        "localhost:5000/codex-universal:canary"
    );
}

#[test]
fn warm_up_image_refs_only_include_codex_image_when_browser_mcp_disabled() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: false,
            ..BrowserMcpConfig::default()
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_include_browser_image_when_any_mode_keeps_browser_enabled() {
    let runner = test_runner_with_codex_and_mentions(
        CodexConfig {
            image: "ghcr.io/openai/codex-universal".to_string(),
            browser_mcp: BrowserMcpConfig {
                enabled: true,
                server_name: "chrome-devtools".to_string(),
                browser_image: "chromedp/headless-shell".to_string(),
                ..BrowserMcpConfig::default()
            },
            mcp_server_overrides: McpServerOverridesConfig {
                review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
                mention: BTreeMap::new(),
            },
            ..test_codex_config()
        },
        true,
    );

    assert_eq!(
        runner.warm_up_image_refs(),
        vec![
            "ghcr.io/openai/codex-universal:latest".to_string(),
            "chromedp/headless-shell:latest".to_string()
        ]
    );
}

#[test]
fn warm_up_image_refs_skip_browser_image_when_mentions_are_disabled() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell".to_string(),
            ..BrowserMcpConfig::default()
        },
        mcp_server_overrides: McpServerOverridesConfig {
            review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
            mention: BTreeMap::new(),
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_skip_browser_image_when_all_modes_disable_browser() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "chromedp/headless-shell".to_string(),
            ..BrowserMcpConfig::default()
        },
        mcp_server_overrides: McpServerOverridesConfig {
            review: BTreeMap::from([("chrome-devtools".to_string(), false)]),
            mention: BTreeMap::from([("chrome-devtools".to_string(), false)]),
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

#[test]
fn warm_up_image_refs_deduplicate_identical_codex_and_browser_images() {
    let runner = test_runner_with_codex(CodexConfig {
        image: "ghcr.io/openai/codex-universal".to_string(),
        browser_mcp: BrowserMcpConfig {
            enabled: true,
            server_name: "chrome-devtools".to_string(),
            browser_image: "ghcr.io/openai/codex-universal:latest".to_string(),
            ..BrowserMcpConfig::default()
        },
        ..test_codex_config()
    });

    assert_eq!(
        runner.warm_up_image_refs(),
        vec!["ghcr.io/openai/codex-universal:latest".to_string()]
    );
}

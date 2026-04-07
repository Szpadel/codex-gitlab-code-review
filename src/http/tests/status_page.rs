use super::*;
#[tokio::test]
async fn api_status_returns_scan_and_in_progress_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/repo", 7, "abcdef")
        .await?;
    state
        .mention_commands
        .begin_mention_command("group/repo", 7, "discussion-1", 99, "abcdef")
        .await?;
    state
        .service_state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Idle,
            mode: Some(ScanMode::Incremental),
            started_at: Some("2026-03-10T11:00:00Z".to_string()),
            finished_at: Some("2026-03-10T11:00:05Z".to_string()),
            outcome: Some(ScanOutcome::Success),
            error: None,
            next_scan_at: Some("2026-03-10T11:10:00Z".to_string()),
        })
        .await?;

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/api/status")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("\"scan_state\":\"idle\""));
    assert!(body.contains("\"mode\":\"incremental\""));
    assert!(body.contains("\"repo\":\"group/repo\""));
    assert!(body.contains("\"trigger_note_id\":99"));
    Ok(())
}

#[tokio::test]
async fn status_page_renders_sections_and_escapes_dynamic_content() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review("group/<repo>", 42, "abcdef")
        .await?;
    state
        .service_state
        .set_auth_limit_reset_at("primary<script>", "2026-03-10T12:00:00Z")
        .await?;
    state
        .service_state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Scanning,
            mode: Some(ScanMode::Full),
            started_at: Some("2026-03-10T11:59:00Z".to_string()),
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: None,
        })
        .await?;

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/status")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Service status"));
    assert!(body.contains("In-progress reviews"));
    assert!(body.contains("Auth fallback cooldowns"));
    assert!(body.contains("group/&lt;repo&gt;"));
    assert!(body.contains("primary&lt;script&gt;"));
    assert!(body.contains("class=\"localized-timestamp\""));
    assert!(body.contains("datetime=\"2026-03-10T11:59:00Z\""));
    assert!(body.contains("datetime=\"2026-03-10T12:00:00Z\""));
    assert!(body.contains("Mar 10, 2026, 11:59 AM UTC"));
    assert!(body.contains("Mar 10, 2026, 12:00 PM UTC"));
    assert!(body.contains("name=\"codex-status-csrf\""));
    assert!(body.contains("function resolveAppBasePath(pathname)"));
    assert!(!body.contains("primary<script>"));
    Ok(())
}

#[tokio::test]
async fn development_page_renders_when_dev_tools_are_enabled() -> Result<()> {
    let mut config = test_config();
    config.database.path = "/tmp/codex-gitlab-code-review-dev-test.sqlite".to_string();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(config.clone(), state, false, None));
    let dev_tools = Arc::new(DevToolsService::new(&config.database.path));
    let address = spawn_test_server(app_router_with_dev_tools(
        Arc::clone(&status_service),
        Some(dev_tools),
    ))
    .await?;

    let response = test_get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Development tools"));
    assert!(body.contains("demo/group/service-a"));
    assert!(body.contains("demo/group/service-b"));
    assert!(body.contains("demo/group/service-c"));
    assert!(body.contains("/tmp/codex-gitlab-code-review-dev-test.sqlite"));
    assert!(body.contains("<a class=\"nav-link active\" href=\"/development\""));
    assert!(body.contains("No active synthetic MR."));
    Ok(())
}

#[tokio::test]
async fn development_page_is_not_mounted_without_dev_tools() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(test_config(), state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let status_response = reqwest::get(format!("http://{address}/status")).await?;
    assert_eq!(status_response.status(), StatusCode::OK);
    let status_body = status_response.text().await?;
    assert!(!status_body.contains("href=\"/development\""));

    let response = reqwest::get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn development_repo_actions_require_csrf_and_update_snapshot() -> Result<()> {
    let mut config = test_config();
    config.database.path = "/tmp/codex-gitlab-code-review-dev-test.sqlite".to_string();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(config.clone(), state, false, None));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let dev_tools = Arc::new(DevToolsService::new(&config.database.path));
    let address = spawn_test_server(app_router_with_dev_tools(
        Arc::clone(&status_service),
        Some(dev_tools),
    ))
    .await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/development/repos/create"))
        .form(&[
            ("csrf_token", "wrong"),
            ("repo_path", "demo/group/service-z"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let created = client
        .post(format!("http://{address}/development/repos/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("repo_path", "demo/group/service-z"),
        ])
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);

    let repo_key = super::view::encode_repo_key("demo/group/service-z");
    let simulated_mr = client
        .post(format!(
            "http://{address}/development/repos/{repo_key}/simulate-mr"
        ))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(simulated_mr.status(), StatusCode::SEE_OTHER);

    let simulated_commit = client
        .post(format!(
            "http://{address}/development/repos/{repo_key}/simulate-commit"
        ))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(simulated_commit.status(), StatusCode::SEE_OTHER);

    let response = test_get(format!("http://{address}/development")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("demo/group/service-z"));
    assert!(body.contains("Active MR !1"));
    assert!(body.contains("Revision 2"));
    Ok(())
}

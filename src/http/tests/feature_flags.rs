use super::*;
#[tokio::test]
async fn feature_flag_update_endpoint_persists_runtime_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/source".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/target".to_string()],
        target_groups: Vec::new(),
    }];
    let status_service = Arc::new(HttpServices::new(config, Arc::clone(&state), false, None));
    let csrf_token = status_service.admin.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client();

    let response = client
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("\"runtime_override\":true"));
    assert!(body.contains("\"effective_enabled\":true"));

    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_requires_csrf_header() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.gitlab_discovery_mcp.enabled = true;
    let status_service = Arc::new(HttpServices::new(config, Arc::clone(&state), false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_rejects_unavailable_flags() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_clears_unavailable_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .feature_flags
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/gitlab_discovery_mcp"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": null }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_persists_composer_install_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/composer_install"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .composer_install,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn feature_flag_update_endpoint_persists_composer_auto_repositories_override() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.feature_flag_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client()
        .post(format!(
            "http://{address}/api/feature-flags/composer_auto_repositories"
        ))
        .header("x-codex-status-csrf", csrf_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .composer_auto_repositories,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn status_service_snapshot_exposes_project_catalog_summary() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .project_catalog
        .save_project_catalog("all", &["group/a".to_string(), "group/b".to_string()])
        .await?;
    state
        .service_state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Idle,
            mode: Some(ScanMode::Full),
            started_at: Some("2026-03-10T09:00:00Z".to_string()),
            finished_at: Some("2026-03-10T09:00:02Z".to_string()),
            outcome: Some(ScanOutcome::Failure),
            error: Some("boom".to_string()),
            next_scan_at: Some("2026-03-10T09:10:00Z".to_string()),
        })
        .await?;

    let status_service = HttpServices::new(test_config(), state, false, None);
    let snapshot = status_service.status.snapshot().await?;
    assert_eq!(snapshot.project_catalogs.len(), 1);
    assert_eq!(snapshot.project_catalogs[0].cache_key, "all".to_string());
    assert_eq!(snapshot.project_catalogs[0].project_count, 2);
    assert_eq!(snapshot.scan.scan_state, "idle".to_string());
    assert_eq!(snapshot.scan.outcome, Some("failure".to_string()));
    assert_eq!(snapshot.scan.error, Some("boom".to_string()));
    Ok(())
}

#[tokio::test]
async fn status_service_snapshot_tolerates_malformed_scan_status() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("INSERT INTO service_state (key, value) VALUES ('scan_status', 'not-json')")
        .execute(state.pool())
        .await?;

    let status_service = HttpServices::new(test_config(), state, false, None);
    let snapshot = status_service.status.snapshot().await?;

    assert_eq!(snapshot.scan.scan_state, "idle".to_string());
    assert_eq!(snapshot.scan.mode, None);
    Ok(())
}

#[tokio::test]
async fn status_service_scan_updates_roundtrip() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = HttpServices::new(test_config(), Arc::clone(&state), false, None);

    status_service
        .admin
        .set_next_scan_at(Some(
            DateTime::parse_from_rfc3339("2026-03-10T12:10:00Z")?.with_timezone(&Utc),
        ))
        .await?;
    status_service
        .admin
        .mark_scan_started(ScanMode::Full)
        .await?;
    status_service
        .admin
        .mark_scan_finished(ScanMode::Full, ScanOutcome::Success, None)
        .await?;

    let persisted = state.service_state.get_scan_status().await?;
    assert_eq!(persisted.state, ScanState::Idle);
    assert_eq!(persisted.mode, Some(ScanMode::Full));
    assert!(persisted.started_at.is_some());
    assert!(persisted.finished_at.is_some());
    assert_eq!(persisted.outcome, Some(ScanOutcome::Success));
    assert_eq!(persisted.error, None);
    assert_eq!(persisted.next_scan_at, None);
    Ok(())
}

#[tokio::test]
async fn status_routes_are_not_registered_when_ui_disabled() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.server.status_ui_enabled = false;
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let status_response = reqwest::get(format!("http://{address}/status")).await?;
    assert_eq!(status_response.status(), StatusCode::NOT_FOUND);

    let health_response = reqwest::get(format!("http://{address}/healthz")).await?;
    assert_eq!(health_response.status(), StatusCode::OK);
    Ok(())
}

#[tokio::test]
async fn startup_recovery_clears_stale_scanning_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc123".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish::default(),
    )
    .await?;
    sqlx::query("UPDATE run_history SET status = 'in_progress', result = NULL, finished_at = NULL WHERE id = ?")
        .bind(run_id)
        .execute(state.pool())
        .await?;
    state
        .service_state
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Scanning,
            mode: Some(ScanMode::Incremental),
            started_at: Some("2026-03-10T10:00:00Z".to_string()),
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: Some("2026-03-10T10:10:00Z".to_string()),
        })
        .await?;
    let status_service = HttpServices::new(test_config(), Arc::clone(&state), false, None);

    status_service.admin.recover_startup_status().await?;

    let persisted = state.service_state.get_scan_status().await?;
    assert_eq!(persisted.state, ScanState::Idle);
    assert_eq!(persisted.mode, Some(ScanMode::Incremental));
    assert_eq!(persisted.outcome, Some(ScanOutcome::Failure));
    assert_eq!(
        persisted.error,
        Some("scan interrupted by service restart".to_string())
    );
    assert!(persisted.finished_at.is_some());
    assert_eq!(persisted.next_scan_at, None);
    let recovered_run = state
        .run_history
        .get_run_history(run_id)
        .await?
        .expect("recovered run should exist");
    assert_eq!(recovered_run.status, "done".to_string());
    assert_eq!(recovered_run.result.as_deref(), Some("cancelled"));
    assert_eq!(
        recovered_run.error.as_deref(),
        Some("run interrupted by service restart")
    );
    Ok(())
}

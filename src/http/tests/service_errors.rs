use super::*;

#[tokio::test]
async fn rate_limit_capacity_zero_returns_bad_request() -> Result<()> {
    let server = HttpTestServerBuilder::new().spawn().await?;
    let rule_id = server
        .services
        .ratelimit
        .create_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Valid rule".to_string(),
            targets: Vec::new(),
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 1,
            window_seconds: 60,
        })
        .await?;
    let client = test_client();
    for path in [
        "/rate-limits/create".to_string(),
        format!("/rate-limits/{rule_id}/update"),
    ] {
        let response = client
            .post(format!("http://{}{path}", server.address))
            .form(&[
                ("csrf_token", server.services.admin.admin_csrf_token()),
                ("label", "Zero capacity"),
                ("scope", "project"),
                ("targets_json", "[]"),
                ("bucket_mode", "shared"),
                ("applies_to_review", "true"),
                ("capacity", "0"),
                ("window_text", "1m"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(
            response.text().await?,
            "status endpoint error: runtime review rate limit rule capacity must be greater than zero"
        );
    }
    let rules = server
        .state
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].capacity, 1);
    Ok(())
}

#[tokio::test]
async fn unknown_flag_with_not_found_in_name_returns_bad_request() -> Result<()> {
    let server = HttpTestServerBuilder::new().spawn().await?;
    let response = test_client()
        .post(format!(
            "http://{}/api/feature-flags/not%20found",
            server.address
        ))
        .header(
            "x-codex-status-csrf",
            server.services.admin.feature_flag_csrf_token(),
        )
        .json(&json!({ "enabled": true }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.text().await?,
        "status endpoint error: invalid feature flag: not found"
    );
    Ok(())
}

#[tokio::test]
async fn missing_run_returns_not_found() -> Result<()> {
    let server = HttpTestServerBuilder::new().spawn().await?;
    for path in ["/api/history/42", "/history/42"] {
        let response = test_get(format!("http://{}{path}", server.address)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response.text().await?,
            "status endpoint error: run not found"
        );
    }
    Ok(())
}

#[tokio::test]
async fn missing_rate_limit_rule_returns_not_found() -> Result<()> {
    let server = HttpTestServerBuilder::new().spawn().await?;
    for action in ["update", "delete"] {
        let response = test_client()
            .post(format!(
                "http://{}/rate-limits/missing/{action}",
                server.address
            ))
            .form(&[
                ("csrf_token", server.services.admin.admin_csrf_token()),
                ("label", "Valid rule"),
                ("scope", "project"),
                ("targets_json", "[]"),
                ("bucket_mode", "shared"),
                ("applies_to_review", "true"),
                ("capacity", "1"),
                ("window_text", "1m"),
            ])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{action}");
        assert_eq!(
            response.text().await?,
            "status endpoint error: runtime review rate limit rule not found: missing"
        );
    }
    Ok(())
}

#[tokio::test]
async fn duplicate_skill_returns_conflict() -> Result<()> {
    let auth_home = TestAuthDir::new("http-error-duplicate-skill");
    write_skill(
        auth_home.path(),
        "duplicate",
        "---\nname: duplicate\n---\n",
        &[],
    )?;
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let server = HttpTestServerBuilder::new()
        .with_config(config)
        .spawn()
        .await?;
    let response = test_client()
        .post(format!("http://{}/skills/upload", server.address))
        .multipart(
            multipart::Form::new()
                .text(
                    "csrf_token",
                    server.services.admin.admin_csrf_token().to_string(),
                )
                .part(
                    "archive",
                    multipart::Part::bytes(build_skill_zip(&[(
                        "SKILL.md",
                        b"---\nname: duplicate\n---\n",
                    )]))
                    .file_name("duplicate.zip"),
                ),
        )
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(
        response.text().await?,
        "status endpoint error: skill already exists: duplicate"
    );
    Ok(())
}

#[tokio::test]
async fn filesystem_error_with_not_found_in_path_returns_internal_error() -> Result<()> {
    let auth_home = TestAuthDir::new("http-error-not found");
    let skills_path = auth_home.path().join("skills");
    std::fs::write(&skills_path, "not a directory")?;
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let server = HttpTestServerBuilder::new()
        .with_config(config)
        .spawn()
        .await?;
    let response = test_get(format!("http://{}/skills", server.address)).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        response.text().await?,
        format!("status endpoint error: read {}", skills_path.display())
    );
    Ok(())
}

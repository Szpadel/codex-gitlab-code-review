use super::*;
#[tokio::test]
async fn skills_page_renders_upload_form_and_installed_skill_list() -> Result<()> {
    let auth_home = TestAuthDir::new("http-skills-page");
    write_skill(
        auth_home.path(),
        "web-skill",
        "---\nname: web-skill\ndescription: Web skill\n---\n",
        &[("scripts/run.sh", b"echo web")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/skills")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Upload skill archive"));
    assert!(body.contains("name=\"archive\""));
    assert!(body.contains("web-skill"));
    assert!(body.contains("/skills/web-skill"));
    Ok(())
}

#[tokio::test]
async fn skill_preview_page_renders_account_status_and_delete_form() -> Result<()> {
    let primary = TestAuthDir::new("http-skill-preview-primary");
    let backup = TestAuthDir::new("http-skill-preview-backup");
    write_skill(
        primary.path(),
        "preview-skill",
        "---\nname: preview-skill\ndescription: Preview me\n---\n",
        &[("scripts/run.sh", b"echo primary")],
    )?;
    write_skill(
        backup.path(),
        "preview-skill",
        "---\nname: preview-skill\ndescription: Preview me\n---\n",
        &[("scripts/run.sh", b"echo primary")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = primary.path().display().to_string();
    config.codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: backup.path().display().to_string(),
    }];
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!("http://{address}/skills/preview-skill")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Skill preview"));
    assert!(body.contains("preview-skill"));
    assert!(body.contains("primary"));
    assert!(body.contains("backup"));
    assert!(body.contains("/skills/preview-skill/delete"));
    Ok(())
}

#[tokio::test]
async fn upload_skill_endpoint_installs_into_primary_and_fallback_auth_homes() -> Result<()> {
    let primary = TestAuthDir::new("http-upload-primary");
    let backup = TestAuthDir::new("http-upload-backup");
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = primary.path().display().to_string();
    config.codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: backup.path().display().to_string(),
    }];
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(Arc::clone(&status_service))).await?;
    let archive = build_skill_zip(&[
        (
            "wrapped/web-skill/SKILL.md",
            b"---\nname: web-skill\ndescription: Upload me\n---\n",
        ),
        ("wrapped/web-skill/scripts/run.sh", b"echo upload\n"),
    ]);

    let client = test_client();
    let response = client
        .post(format!("http://{address}/skills/upload"))
        .multipart(multipart::Form::new().text("csrf_token", csrf_token).part(
            "archive",
            multipart::Part::bytes(archive).file_name("web-skill.zip"),
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(primary.path().join("skills/web-skill/SKILL.md").is_file());
    assert!(
        backup
            .path()
            .join("skills/web-skill/scripts/run.sh")
            .is_file()
    );
    Ok(())
}

#[tokio::test]
async fn upload_skill_endpoint_rejects_unsupported_archive_type() -> Result<()> {
    let auth_home = TestAuthDir::new("http-upload-invalid");
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client();

    let response = client
        .post(format!("http://{address}/skills/upload"))
        .multipart(multipart::Form::new().text("csrf_token", csrf_token).part(
            "archive",
            multipart::Part::bytes(b"not-an-archive".to_vec()).file_name("bad.rar"),
        ))
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn delete_skill_endpoint_requires_csrf_and_removes_skill() -> Result<()> {
    let auth_home = TestAuthDir::new("http-delete-primary");
    write_skill(
        auth_home.path(),
        "delete-skill",
        "---\nname: delete-skill\n---\n",
        &[("scripts/run.sh", b"echo delete")],
    )?;
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.auth_host_path = auth_home.path().display().to_string();
    let status_service = Arc::new(HttpServices::new(config, state, false, None));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(Arc::clone(&status_service))).await?;
    let client = test_client();

    let forbidden = client
        .post(format!("http://{address}/skills/delete-skill/delete"))
        .form(&[("csrf_token", "wrong")])
        .send()
        .await?;
    assert_eq!(forbidden.status(), StatusCode::BAD_REQUEST);
    assert!(auth_home.path().join("skills/delete-skill").exists());

    let deleted = client
        .post(format!("http://{address}/skills/delete-skill/delete"))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(deleted.status(), StatusCode::OK);
    assert!(!auth_home.path().join("skills/delete-skill").exists());
    Ok(())
}

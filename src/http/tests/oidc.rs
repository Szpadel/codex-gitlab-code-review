//! Exercises access control through the same router used by the HTTP server.

use super::*;
use crate::config::OidcConfig;

#[tokio::test]
async fn oidc_protects_ui_api_and_mutations_but_keeps_health_public() -> Result<()> {
    let mut config = test_config();
    config.server.oidc = Some(OidcConfig {
        issuer_url: "https://auth.example.com/application/o/review/".into(),
        client_id: "review".into(),
        client_secret: "secret".into(),
        redirect_url: "https://review.example.com/auth/callback".into(),
    });
    let server = HttpTestServerBuilder::new()
        .with_config(config)
        .with_dev_tools()
        .spawn()
        .await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    for path in [
        "/",
        "/status",
        "/history",
        "/skills",
        "/usage",
        "/rate-limits",
        "/development",
    ] {
        let response = client
            .get(format!("http://{}{path}", server.address))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{path}");
        assert!(
            response.headers()["location"]
                .to_str()?
                .starts_with("/auth/login?")
        );
    }
    for path in [
        "/api/status",
        "/api/history",
        "/api/history/1",
        "/api/history/1/entries/1/body",
        "/api/mr/61/1/history",
    ] {
        let response = client
            .get(format!("http://{}{path}", server.address))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    for path in [
        "/skills/upload",
        "/skills/example/delete",
        "/usage/reset",
        "/rate-limits/create",
        "/api/feature-flags/security_review",
        "/development/repos/create",
    ] {
        let response = client
            .post(format!("http://{}{path}", server.address))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
    }
    let response = client
        .get(format!("http://{}/healthz", server.address))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text().await?, "OK");
    Ok(())
}

use super::oidc_provider::OidcFixture;

#[tokio::test]
async fn oidc_login_grants_access_rotates_session_and_logout_revokes_it() -> Result<()> {
    let fixture = OidcFixture::new().await?;
    let attempt = fixture.login("/history?page=2").await?;
    fixture.token(&attempt, None).await?;
    let response = fixture.callback(&attempt).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/history?page=2");
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_ne!(cookie, attempt.cookie);
    fixture.assert_token_exchange(&attempt).await?;
    let response = fixture
        .client
        .get(fixture.url("/api/status"))
        .header("cookie", &cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = fixture
        .client
        .get(fixture.url("/api/status"))
        .header("cookie", &attempt.cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = fixture
        .client
        .get(fixture.url("/status"))
        .header("cookie", &cookie)
        .send()
        .await?;
    let html = response.text().await?;
    assert!(html.contains("href=\"/auth/logout\""));
    let csrf = html
        .split("name=\"codex-status-csrf\" content=\"")
        .nth(1)
        .context("admin CSRF token")?
        .split('"')
        .next()
        .unwrap();
    let response = fixture
        .client
        .post(fixture.url("/api/feature-flags/security_review"))
        .header("cookie", &cookie)
        .header("x-codex-status-csrf", csrf)
        .json(&json!({"enabled": true}))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        fixture
            .server
            .state
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?
            .security_review
            .unwrap()
    );
    let response = fixture
        .client
        .post(fixture.url("/api/feature-flags/security_review"))
        .header("cookie", &cookie)
        .json(&json!({"enabled": true}))
        .send()
        .await?;
    assert_eq!(
        response.status(),
        StatusCode::BAD_REQUEST,
        "authenticated writes still require CSRF"
    );
    let response = fixture
        .client
        .get(fixture.url("/auth/logout"))
        .header("cookie", &cookie)
        .send()
        .await?;
    let html = response.text().await?;
    let csrf = html
        .split("name=\"csrf_token\" value=\"")
        .nth(1)
        .context("logout token")?
        .split('"')
        .next()
        .unwrap();
    let response = fixture
        .client
        .post(fixture.url("/auth/logout"))
        .header("cookie", &cookie)
        .form(&[("csrf_token", "wrong")])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .client
        .post(fixture.url("/auth/logout"))
        .header("cookie", &cookie)
        .form(&[("csrf_token", csrf)])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let response = fixture
        .client
        .get(fixture.url("/api/status"))
        .header("cookie", &cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn oidc_rejects_invalid_tokens_and_consumes_the_login_attempt() -> Result<()> {
    for invalid in [
        "issuer",
        "audience",
        "expiration",
        "nonce",
        "missing nonce",
        "signature",
        "access token hash",
        "missing ID token",
    ] {
        let fixture = OidcFixture::new().await?;
        let attempt = fixture.login("/").await?;
        fixture.token(&attempt, Some(invalid)).await?;
        let response = fixture.callback(&attempt).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "{invalid}: {}",
            response.text().await?
        );
        let response = fixture.callback(&attempt).await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "replayed {invalid}"
        );
        assert_eq!(fixture.token_request_count().await, 1, "replayed {invalid}");
        let response = fixture
            .client
            .get(fixture.url("/api/status"))
            .header("cookie", &attempt.cookie)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{invalid}");
    }
    Ok(())
}

#[tokio::test]
async fn oidc_rejects_wrong_state_missing_cookie_and_provider_denial() -> Result<()> {
    let fixture = OidcFixture::new().await?;
    let attempt = fixture.login("/").await?;
    let response = fixture
        .client
        .get(fixture.url("/auth/callback"))
        .query(&[("state", &attempt.state), ("code", &"code".into())])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = fixture
        .client
        .get(fixture.url("/auth/callback?state=wrong&code=code"))
        .header("cookie", &attempt.cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let attempt = fixture.login("/").await?;
    let response = fixture
        .client
        .get(fixture.url("/auth/callback"))
        .query(&[
            ("state", attempt.state.as_str()),
            ("error", "access_denied"),
        ])
        .header("cookie", &attempt.cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.token_request_count().await, 0);
    Ok(())
}

#[tokio::test]
async fn oidc_does_not_register_login_routes_when_ui_is_disabled() -> Result<()> {
    let mut config = test_config();
    config.server.status_ui_enabled = false;
    config.server.oidc = Some(OidcConfig {
        issuer_url: "https://auth.example.com/".into(),
        client_id: "review".into(),
        client_secret: "secret".into(),
        redirect_url: "https://review.example.com/auth/callback".into(),
    });
    let server = HttpTestServerBuilder::new()
        .with_config(config)
        .spawn()
        .await?;
    for path in [
        "/",
        "/api/status",
        "/auth/login",
        "/auth/callback",
        "/auth/logout",
    ] {
        let response = test_get(format!("http://{}{path}", server.address)).await?;
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
    Ok(())
}

#[tokio::test]
async fn oidc_sessions_expire_with_the_id_token() -> Result<()> {
    let fixture = OidcFixture::new().await?;
    let attempt = fixture.login("/").await?;
    let expires_at = fixture.token(&attempt, Some("short expiration")).await?;
    let response = fixture.callback(&attempt).await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response.headers()["set-cookie"]
        .to_str()?
        .split(';')
        .next()
        .unwrap()
        .to_string();
    // Wait for the signed claim's deadline, including time spent completing login.
    let remaining = (expires_at - Utc::now()).to_std().unwrap_or_default();
    tokio::time::sleep(remaining + std::time::Duration::from_millis(100)).await;
    let response = fixture
        .client
        .get(fixture.url("/api/status"))
        .header("cookie", cookie)
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    Ok(())
}

#[tokio::test]
async fn oidc_https_callback_uses_host_only_secure_cookies() -> Result<()> {
    let fixture = OidcFixture::with_redirect("HTTPS://review.example.com/auth/callback").await?;
    let response = fixture
        .client
        .get(fixture.url("/auth/login"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookie = response.headers()["set-cookie"].to_str()?;
    assert!(cookie.starts_with("__Host-codex-ui="));
    assert!(cookie.contains("Secure"));
    assert!(cookie.contains("Path=/"));
    assert!(!cookie.contains("Domain="));
    Ok(())
}

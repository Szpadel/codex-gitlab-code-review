//! Validates the external OIDC configuration before the HTTP listener starts.

use super::OidcConfig;
use anyhow::{Context, Result, ensure};
use url::Url;

pub(super) fn validate(config: &OidcConfig) -> Result<()> {
    validate_url(&config.issuer_url, "server.oidc.issuer_url")?;
    let redirect = validate_url(&config.redirect_url, "server.oidc.redirect_url")?;
    ensure!(
        redirect.path() == "/auth/callback",
        "server.oidc.redirect_url must use the path /auth/callback"
    );
    ensure!(
        !config.client_id.trim().is_empty(),
        "server.oidc.client_id must not be empty"
    );
    ensure!(
        !config.client_secret.trim().is_empty(),
        "server.oidc.client_secret must not be empty"
    );
    Ok(())
}

fn validate_url(value: &str, name: &str) -> Result<Url> {
    let url = Url::parse(value).with_context(|| format!("parse {name}"))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "{name} must use HTTPS (HTTP is allowed only on loopback)"
    );
    ensure!(
        url.has_host()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "{name} must have a host and no credentials, query, or fragment"
    );
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{test_builder::ConfigBuilder, validate_config};

    #[test]
    fn oidc_configuration_requires_credentials_and_a_secure_external_callback() {
        let oidc = OidcConfig {
            issuer_url: "https://auth.example.com/application/o/review/".into(),
            client_id: "review".into(),
            client_secret: "secret".into(),
            redirect_url: "https://review.example.com/auth/callback".into(),
        };
        let mut config = ConfigBuilder::for_service_factory_tests().build();
        config.server.oidc = Some(oidc.clone());
        assert!(validate_config(config.clone()).is_ok());
        for redirect in [
            "http://review.example.com/auth/callback",
            "https://review.example.com/other",
            "https://review.example.com/auth/callback?query=1",
            "https://user@review.example.com/auth/callback",
            "https://review.example.com/auth/callback#fragment",
        ] {
            config.server.oidc.as_mut().unwrap().redirect_url = redirect.into();
            assert!(validate_config(config.clone()).is_err(), "{redirect}");
        }
        config.server.oidc = Some(oidc);
        for redirect in [
            "http://localhost:8080/auth/callback",
            "http://127.0.0.1:8080/auth/callback",
            "http://[::1]:8080/auth/callback",
        ] {
            config.server.oidc.as_mut().unwrap().redirect_url = redirect.into();
            assert!(validate_config(config.clone()).is_ok(), "{redirect}");
        }
        config.server.oidc.as_mut().unwrap().client_secret.clear();
        assert!(validate_config(config.clone()).is_err());
        config.server.oidc.as_mut().unwrap().client_secret = "secret".into();
        config.server.oidc.as_mut().unwrap().client_id.clear();
        assert!(validate_config(config).is_err());
    }
}

//! A network-boundary OIDC provider for real HTTP router tests.

use super::*;
use crate::config::OidcConfig;
use crate::http::test_support::HttpTestServer;
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, IssuerUrl, JsonWebKeyId, Nonce,
    PrivateSigningKey, StandardClaims, SubjectIdentifier,
    core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    },
};
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{method, path},
};

pub(super) struct OidcFixture {
    pub(super) server: HttpTestServer,
    pub(super) client: reqwest::Client,
    provider: MockServer,
    key: CoreRsaPrivateSigningKey,
}

pub(super) struct LoginAttempt {
    pub(super) cookie: String,
    pub(super) state: String,
    pub(super) nonce: String,
    pub(super) challenge: String,
}

impl OidcFixture {
    pub(super) async fn new() -> Result<Self> {
        Self::with_redirect("http://localhost/auth/callback").await
    }

    pub(super) async fn with_redirect(redirect_url: &str) -> Result<Self> {
        let provider = MockServer::start().await;
        // This key is a test fixture with no authority outside this mock provider.
        let key = CoreRsaPrivateSigningKey::from_pem(
            include_str!("oidc-test-key.pem"),
            Some(JsonWebKeyId::new("test".into())),
        )
        .map_err(anyhow::Error::msg)?;
        let metadata = json!({
            "issuer": provider.uri(),
            "authorization_endpoint": format!("{}/authorize", provider.uri()),
            "token_endpoint": format!("{}/token", provider.uri()),
            "jwks_uri": format!("{}/jwks", provider.uri()),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"]
        });
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
            .mount(&provider)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(CoreJsonWebKeySet::new(vec![key.as_verification_key()])),
            )
            .mount(&provider)
            .await;
        let mut config = test_config();
        config.server.oidc = Some(OidcConfig {
            issuer_url: provider.uri(),
            client_id: "review".into(),
            client_secret: "secret".into(),
            redirect_url: redirect_url.into(),
        });
        let server = HttpTestServerBuilder::new()
            .with_config(config)
            .spawn()
            .await?;
        let client = test_client_builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            server,
            client,
            provider,
            key,
        })
    }

    pub(super) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.server.address)
    }

    pub(super) async fn login(&self, return_to: &str) -> Result<LoginAttempt> {
        let response = self
            .client
            .get(self.url("/auth/login"))
            .query(&[("return_to", return_to)])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let authorization = url::Url::parse(response.headers()["location"].to_str()?)?;
        let params = authorization
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["scope"], "openid");
        assert_eq!(params["client_id"], "review");
        assert_eq!(params["code_challenge_method"], "S256");
        let cookie = response.headers()["set-cookie"].to_str()?;
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
        Ok(LoginAttempt {
            cookie: cookie.split(';').next().unwrap().to_string(),
            state: params["state"].to_string(),
            nonce: params["nonce"].to_string(),
            challenge: params["code_challenge"].to_string(),
        })
    }

    pub(super) async fn token(
        &self,
        attempt: &LoginAttempt,
        invalid: Option<&str>,
    ) -> Result<DateTime<Utc>> {
        let now = Utc::now();
        let mut claims = CoreIdTokenClaims::new(
            IssuerUrl::new(self.provider.uri())?,
            vec![Audience::new("review".into())],
            now + chrono::Duration::seconds(300),
            now,
            StandardClaims::new(SubjectIdentifier::new("admin".into())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(Nonce::new(attempt.nonce.clone())));
        match invalid {
            Some("issuer") => {
                claims = claims.set_issuer(IssuerUrl::new("https://other.example".into())?)
            }
            Some("audience") => {
                claims = claims.set_audiences(vec![Audience::new("another-client".into())])
            }
            Some("short expiration") => {
                claims = claims.set_expiration(now + chrono::Duration::seconds(10))
            }
            Some("expiration") => {
                claims = claims.set_expiration(now - chrono::Duration::seconds(1))
            }
            Some("nonce") => claims = claims.set_nonce(Some(Nonce::new("wrong-nonce".into()))),
            Some("missing nonce") => claims = claims.set_nonce(None),
            _ => {}
        }
        let expires_at = claims.expiration();
        let token = CoreIdToken::new(
            claims,
            &self.key,
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            Some(&AccessToken::new("access".into())),
            None,
        )?;
        let mut token = token.to_string();
        if invalid == Some("signature") {
            // Keep valid JWT syntax but replace the signature with unrelated bytes.
            let signature = token.rfind('.').unwrap() + 1;
            token.truncate(signature);
            token.push_str(&"A".repeat(342));
        }
        let mut body = json!({"access_token": "access", "token_type": "Bearer", "id_token": token});
        if invalid == Some("access token hash") {
            body["access_token"] = json!("substituted");
        }
        if invalid == Some("missing ID token") {
            body.as_object_mut().unwrap().remove("id_token");
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&self.provider)
            .await;
        Ok(expires_at)
    }

    pub(super) async fn callback(&self, attempt: &LoginAttempt) -> Result<reqwest::Response> {
        Ok(self
            .client
            .get(self.url("/auth/callback"))
            .query(&[
                ("state", attempt.state.as_str()),
                ("code", "authorization-code"),
            ])
            .header("cookie", &attempt.cookie)
            .send()
            .await?)
    }

    pub(super) async fn assert_token_exchange(&self, attempt: &LoginAttempt) -> Result<()> {
        let requests = self.provider.received_requests().await.unwrap();
        let request = requests
            .iter()
            .find(|r| r.url.path() == "/token")
            .context("token request")?;
        let form =
            url::form_urlencoded::parse(&request.body).collect::<std::collections::HashMap<_, _>>();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "authorization-code");
        assert_eq!(form["redirect_uri"], "http://localhost/auth/callback");
        let challenge = openidconnect::PkceCodeChallenge::from_code_verifier_sha256(
            &openidconnect::PkceCodeVerifier::new(form["code_verifier"].to_string()),
        );
        assert_eq!(challenge.as_str(), attempt.challenge);
        assert_eq!(
            request.headers["authorization"],
            "Basic cmV2aWV3OnNlY3JldA=="
        );
        Ok(())
    }

    pub(super) async fn token_request_count(&self) -> usize {
        self.provider
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.url.path() == "/token")
            .count()
    }
}

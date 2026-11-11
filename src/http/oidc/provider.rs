//! Adapts the application's HTTP client to the standard OIDC implementation.

use super::{AuthError, OidcAuth, PendingLogin};
use anyhow::Context;
use openidconnect::{
    AccessTokenHash, AsyncHttpClient, AuthorizationCode, ClientId, ClientSecret, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeVerifier, RedirectUrl, TokenResponse,
    core::{CoreClient, CoreProviderMetadata},
};

type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

impl OidcAuth {
    /// Discovers current provider keys for each login step, including key rotation.
    pub(super) async fn provider(&self) -> Result<DiscoveredClient, AuthError> {
        let issuer = IssuerUrl::new(self.config.issuer_url.clone()).context("parse OIDC issuer")?;
        let http = http_client()?;
        let metadata = CoreProviderMetadata::discover_async(issuer, &http)
            .await
            .context("discover OIDC provider")?;
        Ok(CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.config.client_id.clone()),
            Some(ClientSecret::new(self.config.client_secret.clone())),
        )
        .set_redirect_uri(
            RedirectUrl::new(self.config.redirect_url.clone())
                .context("parse OIDC callback URL")?,
        ))
    }

    /// Returns the verified ID token's expiration time as Unix seconds.
    pub(super) async fn verify_code(
        &self,
        code: String,
        pending: &PendingLogin,
    ) -> Result<i64, AuthError> {
        let client = self.provider().await?;
        let http = http_client()?;
        let tokens = client
            .exchange_code(AuthorizationCode::new(code))
            .context("prepare OIDC token exchange")?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier.clone()))
            .request_async(&http)
            .await
            .context("exchange OIDC authorization code")?;
        let id_token = tokens.id_token().ok_or(AuthError::Rejected(
            "The provider did not return an ID token",
        ))?;
        let verifier = client.id_token_verifier();
        let claims = id_token
            .claims(&verifier, &Nonce::new(pending.nonce.clone()))
            .map_err(|_| AuthError::Rejected("Invalid ID token"))?;
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                tokens.access_token(),
                id_token
                    .signing_alg()
                    .context("read ID token signing algorithm")?,
                id_token
                    .signing_key(&verifier)
                    .context("read ID token signing key")?,
            )
            .context("verify access token hash")?;
            if actual != *expected {
                return Err(AuthError::Rejected("Invalid access token hash"));
            }
        }
        Ok(claims.expiration().timestamp())
    }
}

fn http_client() -> anyhow::Result<OidcHttpClient> {
    crate::gitlab::tls::ensure_reqwest_rustls_provider();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map(OidcHttpClient)
        .context("create OIDC HTTP client")
}

async fn send(
    client: &reqwest::Client,
    request: HttpRequest,
) -> Result<HttpResponse, reqwest::Error> {
    let (parts, body) = request.into_parts();
    let response = client
        .request(parts.method, parts.uri.to_string())
        .headers(parts.headers)
        .body(body)
        .send()
        .await?;
    let mut result = HttpResponse::new(Vec::new());
    *result.status_mut() = response.status();
    *result.headers_mut() = response.headers().clone();
    *result.body_mut() = response.bytes().await?.to_vec();
    Ok(result)
}

// oauth2 5 uses reqwest 0.12. Adapt our reqwest 0.13 client without a second
// HTTP stack. The boxed future supplies the Send guarantee axum handlers need.
struct OidcHttpClient(reqwest::Client);

impl<'c> AsyncHttpClient<'c> for OidcHttpClient {
    type Error = reqwest::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<HttpResponse, Self::Error>> + Send + 'c>,
    >;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(send(&self.0, request))
    }
}

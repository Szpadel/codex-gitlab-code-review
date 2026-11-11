//! Protects the complete UI with OIDC. Authentik application policies own admission.
//! Sessions expire with the ID token, at most eight hours after login. They are
//! held in a bounded process-local store, so a restart requires a new login.

mod provider;
mod store;

use crate::config::OidcConfig;
use anyhow::Context;
use axum::{
    Form, Router,
    extract::{Query, Request, State},
    http::{Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
};
use openidconnect::{CsrfToken, Nonce, PkceCodeChallenge};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use store::OidcSessionStore;
use tower_sessions::{
    Expiry, Session, SessionManagerLayer,
    cookie::{
        SameSite,
        time::{Duration, OffsetDateTime},
    },
};

const PENDING_LOGIN: &str = "oidc_pending_login";
const AUTHENTICATED_UNTIL: &str = "oidc_authenticated_until";
const LOGOUT_CSRF: &str = "oidc_logout_csrf";
const LOGIN_TIMEOUT: Duration = Duration::minutes(10);
const MAX_SESSION_AGE: Duration = Duration::hours(8);
const SESSION_CAPACITY: u64 = 10_000;

/// Owns provider configuration. No provider tokens are stored in the browser.
struct OidcAuth {
    config: OidcConfig,
}

#[derive(Deserialize, Serialize)]
struct PendingLogin {
    state: String,
    nonce: String,
    pkce_verifier: String,
    return_to: String,
}

#[derive(Default, Deserialize)]
struct LoginQuery {
    return_to: Option<String>,
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct LogoutForm {
    csrf_token: String,
}

/// Protects all supplied routes, then adds the public login and callback routes.
/// The caller must keep health checks outside this router.
pub(super) fn protect<S>(router: Router<S>, config: OidcConfig) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let secure = url::Url::parse(&config.redirect_url)
        .expect("validated OIDC redirect URL")
        .scheme()
        == "https";
    let auth = Arc::new(OidcAuth { config });
    let sessions = SessionManagerLayer::new(OidcSessionStore::new(SESSION_CAPACITY))
        .with_name(if secure {
            "__Host-codex-ui"
        } else {
            "codex-ui"
        })
        .with_secure(secure)
        .with_http_only(true)
        .with_same_site(SameSite::Lax)
        .with_expiry(Expiry::OnInactivity(LOGIN_TIMEOUT));
    let auth_routes = Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .route("/auth/logout", get(logout_page).post(logout))
        .with_state(auth);
    router
        .route_layer(middleware::from_fn(require_login))
        .merge(auth_routes)
        .layer(middleware::from_fn(private_response))
        .layer(sessions)
}

async fn require_login(
    session: Session,
    request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let expires_at: Option<i64> = session
        .get(AUTHENTICATED_UNTIL)
        .await
        .context("read UI session")?;
    if expires_at.is_some_and(|expiry| expiry > OffsetDateTime::now_utc().unix_timestamp()) {
        return Ok(next.run(request).await);
    }
    if request.method() != Method::GET || request.uri().path().starts_with("/api/") {
        return Ok((StatusCode::UNAUTHORIZED, "Login required").into_response());
    }
    let return_to = request
        .uri()
        .path_and_query()
        .map_or("/", |uri| uri.as_str());
    Ok(Redirect::to(&format!(
        "/auth/login?return_to={}",
        urlencoding::encode(return_to)
    ))
    .into_response())
}

async fn private_response(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    response
}

async fn login(
    State(auth): State<Arc<OidcAuth>>,
    session: Session,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AuthError> {
    let return_to = local_return_to(query.return_to.as_deref()).to_string();
    let client = auth.provider().await?;
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(
            openidconnect::core::CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge)
        .url();
    session.flush().await.context("replace UI login session")?;
    session.set_expiry(Some(Expiry::AtDateTime(
        OffsetDateTime::now_utc() + LOGIN_TIMEOUT,
    )));
    session
        .insert(
            PENDING_LOGIN,
            PendingLogin {
                state: state.secret().clone(),
                nonce: nonce.secret().clone(),
                pkce_verifier: verifier.secret().clone(),
                return_to,
            },
        )
        .await
        .context("save pending OIDC login")?;
    Ok(Redirect::to(url.as_str()).into_response())
}

async fn callback(
    State(auth): State<Arc<OidcAuth>>,
    session: Session,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AuthError> {
    let pending: PendingLogin = session
        .remove(PENDING_LOGIN)
        .await
        .context("read pending OIDC login")?
        .ok_or(AuthError::Rejected("Login expired or was already used"))?;
    // Consume the attempt before network I/O, including provider or validation failures.
    session.save().await.context("consume pending OIDC login")?;
    if CsrfToken::new(query.state) != CsrfToken::new(pending.state.clone()) {
        return Err(AuthError::Rejected("Invalid login state"));
    }
    if query.error.is_some() {
        return Err(AuthError::Rejected("The identity provider denied login"));
    }
    let code = query
        .code
        .ok_or(AuthError::Rejected("Missing authorization code"))?;
    let token_expiry = auth.verify_code(code, &pending).await?;
    let now = OffsetDateTime::now_utc();
    let expires_at = token_expiry.min((now + MAX_SESSION_AGE).unix_timestamp());
    session.cycle_id().await.context("rotate UI session ID")?;
    session.set_expiry(Some(Expiry::AtDateTime(
        OffsetDateTime::from_unix_timestamp(expires_at).context("read ID token expiry")?,
    )));
    session
        .insert(AUTHENTICATED_UNTIL, expires_at)
        .await
        .context("save UI login")?;
    session
        .insert(LOGOUT_CSRF, CsrfToken::new_random().secret())
        .await
        .context("save logout token")?;
    Ok(Redirect::to(&pending.return_to).into_response())
}

fn local_return_to(value: Option<&str>) -> &str {
    // URL parsers treat backslashes as slashes. Keep the redirect on this origin.
    value
        .filter(|value| {
            value.starts_with('/')
                && !value.starts_with("//")
                && !value.contains('\\')
                && !value.chars().any(char::is_control)
                && !value.starts_with("/auth/")
        })
        .unwrap_or("/")
}

async fn logout_page(session: Session) -> Result<Response, AuthError> {
    let csrf_token: Option<String> = session
        .get(LOGOUT_CSRF)
        .await
        .context("read logout token")?;
    let Some(csrf_token) = csrf_token else {
        return Ok(Redirect::to("/auth/login").into_response());
    };
    Ok(Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Sign out</title><style>{}</style></head>\
         <body><main class=\"content\"><h1>Sign out</h1><p>This ends your session in Codex GitLab Review.</p>\
         <form method=\"post\" action=\"/auth/logout\"><input type=\"hidden\" name=\"csrf_token\" value=\"{}\"><button type=\"submit\">Sign out</button></form><a href=\"/\">Cancel</a></main></body></html>",
        include_str!("assets/page.css"), super::view::escape_html(&csrf_token),
    )).into_response())
}

async fn logout(session: Session, Form(form): Form<LogoutForm>) -> Result<Response, AuthError> {
    let expected: Option<String> = session
        .get(LOGOUT_CSRF)
        .await
        .context("read logout token")?;
    if expected.as_deref() != Some(&form.csrf_token) {
        return Err(AuthError::Rejected("Invalid logout token"));
    }
    session.flush().await.context("end UI session")?;
    Ok(Html("<!DOCTYPE html><html lang=\"en\"><title>Signed out</title><p>You are signed out of Codex GitLab Review.</p><a href=\"/auth/login\">Sign in</a></html>").into_response())
}

/// Separates invalid external login responses from internal failures.
enum AuthError {
    Rejected(&'static str),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for AuthError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        match self {
            Self::Rejected(message) => (StatusCode::FORBIDDEN, message).into_response(),
            Self::Internal(error) => {
                // Display only our operation context. Provider errors can contain tokens.
                tracing::warn!(operation = %error, "OIDC login failed");
                (
                    StatusCode::BAD_GATEWAY,
                    "Login failed. Try again or contact the administrator.",
                )
                    .into_response()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_returns_only_to_local_ui_paths() {
        assert_eq!(local_return_to(Some("/history?page=2")), "/history?page=2");
        for value in [
            "https://evil.example",
            "//evil.example",
            "/\\evil.example",
            "/\nevil.example",
            "/auth/login",
        ] {
            assert_eq!(local_return_to(Some(value)), "/");
        }
    }
}

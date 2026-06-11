use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

#[derive(Debug)]
pub(crate) struct StatusHandlerError(pub(crate) anyhow::Error);

impl From<anyhow::Error> for StatusHandlerError {
    fn from(error: anyhow::Error) -> Self {
        Self(error)
    }
}

impl IntoResponse for StatusHandlerError {
    fn into_response(self) -> Response {
        let message = self.0.to_string();
        let status = if message.contains("not found") {
            StatusCode::NOT_FOUND
        } else if message.contains("already exists") {
            StatusCode::CONFLICT
        } else if message.contains("unsupported archive type") || message.contains("invalid") {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, format!("status endpoint error: {}", self.0)).into_response()
    }
}

pub(crate) fn require_feature_flag_csrf_header(
    headers: &HeaderMap,
    expected_token: &str,
) -> anyhow::Result<()> {
    let matches_expected = headers
        .get("x-codex-status-csrf")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        anyhow::bail!("invalid feature flag csrf token")
    }
}

pub(crate) fn require_admin_csrf_form_token(
    actual_token: Option<&str>,
    expected_token: &str,
) -> anyhow::Result<()> {
    let matches_expected = actual_token.is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        anyhow::bail!("invalid csrf token")
    }
}

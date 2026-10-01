//! Maps service failure categories to status endpoint responses.

use crate::service_error::ServiceError;
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

/// Preserves diagnostics and selects the HTTP status from the service failure.
#[derive(Debug)]
pub(crate) struct StatusHandlerError(pub(crate) ServiceError);

impl From<ServiceError> for StatusHandlerError {
    fn from(error: ServiceError) -> Self {
        Self(error)
    }
}

impl IntoResponse for StatusHandlerError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            ServiceError::InvalidInput(_) => StatusCode::BAD_REQUEST,
            ServiceError::NotFound(_) => StatusCode::NOT_FOUND,
            ServiceError::Conflict(_) => StatusCode::CONFLICT,
            ServiceError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, format!("status endpoint error: {}", self.0)).into_response()
    }
}

/// Requires `x-codex-status-csrf` to equal the expected token.
/// Rejects missing or incorrect tokens as invalid input.
pub(crate) fn require_feature_flag_csrf_header(
    headers: &HeaderMap,
    expected_token: &str,
) -> Result<(), ServiceError> {
    let matches_expected = headers
        .get("x-codex-status-csrf")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidInput(anyhow::anyhow!(
            "invalid feature flag csrf token"
        )))
    }
}

/// Rejects a missing or incorrect form token as invalid input.
pub(crate) fn require_admin_csrf_form_token(
    actual_token: Option<&str>,
    expected_token: &str,
) -> Result<(), ServiceError> {
    let matches_expected = actual_token.is_some_and(|value| value == expected_token);
    if matches_expected {
        Ok(())
    } else {
        Err(ServiceError::InvalidInput(anyhow::anyhow!(
            "invalid csrf token"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn response_status_depends_only_on_service_category() {
        let diagnostic = "invalid resource not found or already exists";
        for (error, status) in [
            (
                ServiceError::InvalidInput(anyhow::anyhow!(diagnostic)),
                StatusCode::BAD_REQUEST,
            ),
            (
                ServiceError::NotFound(anyhow::anyhow!(diagnostic)),
                StatusCode::NOT_FOUND,
            ),
            (
                ServiceError::Conflict(anyhow::anyhow!(diagnostic)),
                StatusCode::CONFLICT,
            ),
            (
                ServiceError::Internal(anyhow::anyhow!(diagnostic)),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
        ] {
            let response = StatusHandlerError::from(error).into_response();
            assert_eq!(response.status(), status);
            let body = axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap();
            assert_eq!(body, format!("status endpoint error: {diagnostic}"));
        }
    }
}

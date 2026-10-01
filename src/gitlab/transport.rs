use crate::text::truncate_with_marker;
use anyhow::{Context, Result, anyhow};
use reqwest::{Response, StatusCode, header};
use serde::Deserialize;

const GITLAB_ERROR_BODY_LIMIT: usize = 512;
const RETRYABLE_GITLAB_STATUSES: &[StatusCode] = &[
    StatusCode::REQUEST_TIMEOUT,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
    StatusCode::GATEWAY_TIMEOUT,
];

/// Keeps the response status separate from the diagnostic text.
#[derive(Debug, thiserror::Error)]
#[error("gitlab {method} {url} response: status={status} content_type={content_type} body={body}")]
pub(crate) struct GitLabHttpError {
    status: StatusCode,
    method: String,
    url: String,
    content_type: String,
    body: String,
}

impl GitLabHttpError {
    /// Sanitizes and truncates the body for logs and stored diagnostics.
    pub(crate) fn new(
        method: &str,
        url: &str,
        status: StatusCode,
        content_type: Option<&str>,
        body: &str,
    ) -> Self {
        Self {
            status,
            method: method.to_string(),
            url: url.to_string(),
            content_type: content_type.unwrap_or("<unknown>").to_string(),
            body: format_gitlab_error_body(body),
        }
    }
}

pub(crate) async fn ensure_success<T: for<'de> Deserialize<'de>>(
    response: Response,
    method: &str,
    url: &str,
) -> Result<T> {
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let content_type = content_type.map(str::to_owned);
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(
            GitLabHttpError::new(method, url, status, content_type.as_deref(), &text).into(),
        );
    }
    let body = response
        .bytes()
        .await
        .with_context(|| format!("gitlab {method} {url} response body"))?;
    serde_json::from_slice::<T>(&body).map_err(|err| {
        anyhow!(format_gitlab_decode_error(
            method,
            url,
            status,
            content_type.as_deref(),
            &body,
            &err
        ))
    })
}

pub(crate) async fn ensure_success_empty(
    response: Response,
    method: &str,
    url: &str,
) -> Result<()> {
    let status = response.status();
    if !status.is_success() {
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let content_type = content_type.map(str::to_owned);
        let text = response.text().await.unwrap_or_default();
        return Err(
            GitLabHttpError::new(method, url, status, content_type.as_deref(), &text).into(),
        );
    }
    Ok(())
}

pub(crate) async fn ensure_success_bytes(
    response: Response,
    method: &str,
    url: &str,
) -> Result<Vec<u8>> {
    let status = response.status();
    if !status.is_success() {
        let content_type = response
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok());
        let content_type = content_type.map(str::to_owned);
        let text = response.text().await.unwrap_or_default();
        return Err(
            GitLabHttpError::new(method, url, status, content_type.as_deref(), &text).into(),
        );
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("gitlab {method} {url} response bytes"))?;
    Ok(bytes.to_vec())
}

fn format_gitlab_decode_error(
    method: &str,
    url: &str,
    status: reqwest::StatusCode,
    content_type: Option<&str>,
    body: &[u8],
    err: &serde_json::Error,
) -> String {
    let content_type = content_type.unwrap_or("<unknown>");
    format!(
        "gitlab {method} {url} response: status={status} content_type={content_type} body={} decode_error={err}",
        format_gitlab_error_body_bytes(body),
    )
}

fn format_gitlab_error_body(body: &str) -> String {
    if body.is_empty() {
        return "<empty>".to_string();
    }
    let sanitized = body.replace(char::is_whitespace, " ");
    let sanitized = sanitized.trim();
    if sanitized.is_empty() {
        return "<whitespace>".to_string();
    }
    truncate_with_marker(sanitized, GITLAB_ERROR_BODY_LIMIT, "...")
}

fn format_gitlab_error_body_bytes(body: &[u8]) -> String {
    format_gitlab_error_body(&String::from_utf8_lossy(body))
}

/// Matches only non-success GitLab responses, including errors with added context.
pub(crate) fn gitlab_error_has_status(err: &anyhow::Error, statuses: &[u16]) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<GitLabHttpError>())
        .any(|response| statuses.contains(&response.status.as_u16()))
}

pub(crate) fn is_retryable_gitlab_status(status: StatusCode) -> bool {
    RETRYABLE_GITLAB_STATUSES.contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(status: StatusCode, body: &str) -> Response {
        axum::http::Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .unwrap()
            .into()
    }

    async fn response_errors(status: StatusCode, body: &str) -> Vec<anyhow::Error> {
        vec![
            ensure_success::<serde_json::Value>(response(status, body), "GET", "url")
                .await
                .unwrap_err(),
            ensure_success_empty(response(status, body), "DELETE", "url")
                .await
                .unwrap_err(),
            ensure_success_bytes(response(status, body), "GET", "url")
                .await
                .unwrap_err(),
        ]
    }

    #[tokio::test]
    async fn non_success_errors_preserve_status_and_diagnostics() {
        for error in response_errors(StatusCode::NOT_FOUND, "\n not\tfound \n").await {
            assert!(gitlab_error_has_status(&error, &[404]));
            assert!(!gitlab_error_has_status(&error, &[503]));
            assert!(error.to_string().ends_with(
                "url response: status=404 Not Found content_type=application/json body=not found"
            ));
            assert!(gitlab_error_has_status(
                &error.context("lookup failed"),
                &[404]
            ));
        }
    }

    #[tokio::test]
    async fn non_success_errors_ignore_status_text_in_body_and_context() {
        for error in response_errors(StatusCode::SERVICE_UNAVAILABLE, "status=404").await {
            let error = error.context("lookup failed: status=403");
            assert!(!gitlab_error_has_status(&error, &[404, 403]));
            assert!(gitlab_error_has_status(&error, &[503]));
        }
    }

    #[test]
    fn unrelated_errors_are_not_gitlab_http_responses() {
        assert!(!gitlab_error_has_status(&anyhow!("status=404"), &[404]));
    }

    #[tokio::test]
    async fn non_success_errors_preserve_body_truncation_and_placeholders() {
        for (body, expected) in [
            (String::new(), "<empty>".to_string()),
            ("\n\t ".to_string(), "<whitespace>".to_string()),
            ("x".repeat(600), format!("{}...", "x".repeat(512))),
        ] {
            let error = ensure_success_empty(
                axum::http::Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(body)
                    .unwrap()
                    .into(),
                "DELETE",
                "url",
            )
            .await
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "gitlab DELETE url response: status=404 Not Found content_type=<unknown> body={expected}"
                )
            );
        }
    }
}

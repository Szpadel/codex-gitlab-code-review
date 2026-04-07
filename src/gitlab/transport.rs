use anyhow::{Context, Result, anyhow};
use reqwest::{Response, header};
use serde::Deserialize;

const GITLAB_ERROR_BODY_LIMIT: usize = 512;

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
        return Err(anyhow!(format_gitlab_http_error(
            method,
            url,
            status,
            content_type.as_deref(),
            &text
        )));
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
        return Err(anyhow!(format_gitlab_http_error(
            method,
            url,
            status,
            content_type.as_deref(),
            &text
        )));
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
        return Err(anyhow!(format_gitlab_http_error(
            method,
            url,
            status,
            content_type.as_deref(),
            &text
        )));
    }
    let bytes = response
        .bytes()
        .await
        .with_context(|| format!("gitlab {method} {url} response bytes"))?;
    Ok(bytes.to_vec())
}

fn format_gitlab_http_error(
    method: &str,
    url: &str,
    status: reqwest::StatusCode,
    content_type: Option<&str>,
    body: &str,
) -> String {
    let content_type = content_type.unwrap_or("<unknown>");
    format!(
        "gitlab {method} {url} response: status={status} content_type={content_type} body={}",
        format_gitlab_error_body(body),
    )
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
    if sanitized.chars().count() <= GITLAB_ERROR_BODY_LIMIT {
        return sanitized.to_string();
    }
    let truncated: String = sanitized.chars().take(GITLAB_ERROR_BODY_LIMIT).collect();
    format!("{truncated}...")
}

fn format_gitlab_error_body_bytes(body: &[u8]) -> String {
    format_gitlab_error_body(&String::from_utf8_lossy(body))
}

pub(crate) fn gitlab_error_has_status(err: &anyhow::Error, statuses: &[u16]) -> bool {
    let text = format!("{err:#}");
    statuses
        .iter()
        .any(|status| text.contains(&format!("status={status}")))
}

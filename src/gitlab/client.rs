use super::pagination;
use super::transport::{
    ensure_success, ensure_success_bytes, ensure_success_empty, is_retryable_gitlab_status,
};
use super::types::{MergeRequestDiscussion, Note};
use crate::tls::ensure_reqwest_rustls_provider;
use anyhow::{Context, Result};
use reqwest::{Client, RequestBuilder, Response, header};
use serde::Deserialize;
use std::future::Future;
use std::time::Duration;
use tracing::warn;
use url::Url;

const DEFAULT_GITLAB_RETRY_MAX_ATTEMPTS: u32 = 10;
const DEFAULT_GITLAB_RETRY_INITIAL_DELAY: Duration = Duration::from_millis(250);
const DEFAULT_GITLAB_RETRY_MAX_DELAY: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug)]
pub(crate) struct GitLabRetryPolicy {
    max_attempts: u32,
    initial_delay: Duration,
    max_delay: Duration,
}

impl Default for GitLabRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_GITLAB_RETRY_MAX_ATTEMPTS,
            initial_delay: DEFAULT_GITLAB_RETRY_INITIAL_DELAY,
            max_delay: DEFAULT_GITLAB_RETRY_MAX_DELAY,
        }
    }
}

impl GitLabRetryPolicy {
    pub(crate) fn max_attempts(self) -> u32 {
        self.max_attempts.max(1)
    }

    fn delay_after_attempt(self, attempt: u32) -> Duration {
        if self.initial_delay.is_zero() || self.max_delay.is_zero() {
            return Duration::ZERO;
        }
        let exponent = attempt.saturating_sub(1).min(30);
        let multiplier = 1u128 << exponent;
        let delay_millis = self
            .initial_delay
            .as_millis()
            .saturating_mul(multiplier)
            .min(self.max_delay.as_millis())
            .min(u128::from(u64::MAX));
        Duration::from_millis(delay_millis as u64)
    }

    #[cfg(test)]
    pub(crate) fn without_delay(max_attempts: u32) -> Self {
        Self {
            max_attempts,
            initial_delay: Duration::ZERO,
            max_delay: Duration::ZERO,
        }
    }
}

#[derive(Clone)]
pub struct GitLabClient {
    api_base: String,
    token: String,
    client: Client,
    retry_policy: GitLabRetryPolicy,
}

enum RetrySendOutcome {
    Response(Response),
    Confirmed,
}

pub(crate) enum GitLabWriteConfirmation {
    MergeRequest {
        notes_url: String,
        body: String,
    },
    Discussion {
        discussions_url: String,
        discussion_id: String,
        body: String,
    },
    AnyDiscussion {
        discussions_url: String,
        body: String,
    },
}

impl GitLabClient {
    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
        ensure_reqwest_rustls_provider();
        let api_base = normalize_api_base(base_url)?;
        let mut headers = header::HeaderMap::new();
        if !token.is_empty() {
            headers.insert(
                "PRIVATE-TOKEN",
                header::HeaderValue::from_str(token)
                    .with_context(|| "build gitlab token header")?,
            );
        }
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("codex-gitlab-review"),
        );
        let client = Client::builder()
            .default_headers(headers)
            .build()
            .context("build gitlab http client")?;
        Ok(Self {
            api_base,
            token: token.to_string(),
            client,
            retry_policy: GitLabRetryPolicy::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_retry_policy(mut self, retry_policy: GitLabRetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }

    #[must_use]
    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    pub(crate) fn project_path(&self, project: &str) -> String {
        let encoded = urlencoding::encode(project);
        format!("{}/projects/{}", self.api_base, encoded)
    }

    pub(crate) fn group_path(&self, group: &str) -> String {
        let encoded = urlencoding::encode(group);
        format!("{}/groups/{}", self.api_base, encoded)
    }

    pub(crate) fn discussion_note_award_base_url(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> String {
        let encoded_discussion_id = urlencoding::encode(discussion_id);
        format!(
            "{}/merge_requests/{}/discussions/{}/notes/{}/award_emoji",
            self.project_path(project),
            iid,
            encoded_discussion_id,
            note_id
        )
    }

    pub(crate) fn merge_request_note_award_base_url(
        &self,
        project: &str,
        iid: u64,
        note_id: u64,
    ) -> String {
        format!(
            "{}/merge_requests/{}/notes/{}/award_emoji",
            self.project_path(project),
            iid,
            note_id
        )
    }

    pub(crate) async fn get_json<T: for<'de> Deserialize<'de> + Send>(
        &self,
        url: &str,
    ) -> Result<T> {
        self.send_read_with_retry(
            "GET",
            url,
            || self.client.get(url),
            |response| ensure_success(response, "GET", url),
        )
        .await
    }

    pub(crate) async fn post_empty(&self, url: &str) -> Result<()> {
        match self
            .send_with_retry("POST", url, || self.client.post(url), None)
            .await?
        {
            RetrySendOutcome::Response(response) => {
                ensure_success_empty(response, "POST", url).await
            }
            RetrySendOutcome::Confirmed => Ok(()),
        }
    }

    pub(crate) async fn delete_empty(&self, url: &str) -> Result<()> {
        match self
            .send_with_retry("DELETE", url, || self.client.delete(url), None)
            .await?
        {
            RetrySendOutcome::Response(response) => {
                ensure_success_empty(response, "DELETE", url).await
            }
            RetrySendOutcome::Confirmed => Ok(()),
        }
    }

    pub(crate) async fn post_note(
        &self,
        url: &str,
        body: &str,
        confirmation: GitLabWriteConfirmation,
    ) -> Result<()> {
        match self
            .send_with_retry(
                "POST",
                url,
                || {
                    self.client
                        .post(url)
                        .json(&serde_json::json!({ "body": body }))
                },
                Some(&confirmation),
            )
            .await?
        {
            RetrySendOutcome::Response(response) => {
                self.ensure_write_json_success(response, "POST", url, &confirmation)
                    .await
            }
            RetrySendOutcome::Confirmed => Ok(()),
        }
    }

    pub(crate) async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        confirmation: GitLabWriteConfirmation,
    ) -> Result<()> {
        match self
            .send_with_retry(
                "POST",
                url,
                || self.client.post(url).form(form),
                Some(&confirmation),
            )
            .await?
        {
            RetrySendOutcome::Response(response) => {
                self.ensure_write_json_success(response, "POST", url, &confirmation)
                    .await
            }
            RetrySendOutcome::Confirmed => Ok(()),
        }
    }

    pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de> + Send>(
        &self,
        base_url: &str,
    ) -> Result<Vec<T>> {
        pagination::get_paginated(self, base_url).await
    }

    pub(crate) async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        self.send_read_with_retry(
            "GET",
            url,
            || self.client.get(url),
            |response| ensure_success_bytes(response, "GET", url),
        )
        .await
    }

    pub(crate) async fn get_paginated_page<T: for<'de> Deserialize<'de> + Send>(
        &self,
        url: &str,
    ) -> Result<(Vec<T>, Option<String>)> {
        self.send_read_with_retry(
            "GET",
            url,
            || self.client.get(url),
            |response| async move {
                let next_page = response
                    .headers()
                    .get("X-Next-Page")
                    .and_then(|val| val.to_str().ok())
                    .and_then(|val| {
                        if val.is_empty() {
                            None
                        } else {
                            Some(val.to_string())
                        }
                    });
                let page_items = ensure_success(response, "GET", url).await?;
                Ok((page_items, next_page))
            },
        )
        .await
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub fn git_base_url(&self) -> Result<Url> {
        let mut url = Url::parse(&self.api_base)?;
        let path = url.path().trim_end_matches('/').to_string();
        let stripped = path.strip_suffix("/api/v4").unwrap_or(&path);
        url.set_path(stripped);
        Ok(url)
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    async fn send_with_retry(
        &self,
        method: &str,
        url: &str,
        build_request: impl Fn() -> RequestBuilder,
        confirmation: Option<&GitLabWriteConfirmation>,
    ) -> Result<RetrySendOutcome> {
        let max_attempts = self.retry_policy.max_attempts();
        let mut attempt = 1;

        loop {
            match build_request().send().await {
                Ok(response) => {
                    let status = response.status();
                    if !is_retryable_gitlab_status(status) {
                        return Ok(RetrySendOutcome::Response(response));
                    }
                    if Box::pin(self.confirm_write_published(method, url, confirmation)).await? {
                        return Ok(RetrySendOutcome::Confirmed);
                    }
                    if attempt >= max_attempts {
                        return Ok(RetrySendOutcome::Response(response));
                    }
                    self.sleep_before_retry(method, url, attempt, max_attempts, Some(status), None)
                        .await;
                }
                Err(err) => {
                    if !is_retryable_reqwest_error(&err) {
                        return Err(err).with_context(|| format!("gitlab {method} {url}"));
                    }
                    if Box::pin(self.confirm_write_published(method, url, confirmation)).await? {
                        return Ok(RetrySendOutcome::Confirmed);
                    }
                    if attempt >= max_attempts {
                        return Err(err).with_context(|| format!("gitlab {method} {url}"));
                    }
                    let error = err.to_string();
                    self.sleep_before_retry(
                        method,
                        url,
                        attempt,
                        max_attempts,
                        None,
                        Some(error.as_str()),
                    )
                    .await;
                }
            }
            attempt += 1;
        }
    }

    async fn send_read_with_retry<T, F, Fut>(
        &self,
        method: &str,
        url: &str,
        build_request: impl Fn() -> RequestBuilder,
        mut read_response: F,
    ) -> Result<T>
    where
        F: FnMut(Response) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let max_attempts = self.retry_policy.max_attempts();
        let mut attempt = 1;

        loop {
            match build_request().send().await {
                Ok(response) => {
                    let status = response.status();
                    if is_retryable_gitlab_status(status) {
                        if attempt >= max_attempts {
                            return read_response(response).await;
                        }
                        self.sleep_before_retry(
                            method,
                            url,
                            attempt,
                            max_attempts,
                            Some(status),
                            None,
                        )
                        .await;
                    } else {
                        match read_response(response).await {
                            Ok(value) => return Ok(value),
                            Err(err) if is_retryable_anyhow_read_error(&err) => {
                                if attempt >= max_attempts {
                                    return Err(err);
                                }
                                let error = err.to_string();
                                self.sleep_before_retry(
                                    method,
                                    url,
                                    attempt,
                                    max_attempts,
                                    None,
                                    Some(error.as_str()),
                                )
                                .await;
                            }
                            Err(err) => return Err(err),
                        }
                    }
                }
                Err(err) => {
                    if !is_retryable_reqwest_error(&err) {
                        return Err(err).with_context(|| format!("gitlab {method} {url}"));
                    }
                    if attempt >= max_attempts {
                        return Err(err).with_context(|| format!("gitlab {method} {url}"));
                    }
                    let error = err.to_string();
                    self.sleep_before_retry(
                        method,
                        url,
                        attempt,
                        max_attempts,
                        None,
                        Some(error.as_str()),
                    )
                    .await;
                }
            }
            attempt += 1;
        }
    }

    async fn ensure_write_json_success(
        &self,
        response: Response,
        method: &str,
        url: &str,
        confirmation: &GitLabWriteConfirmation,
    ) -> Result<()> {
        match ensure_success::<serde_json::Value>(response, method, url).await {
            Ok(_) => Ok(()),
            Err(err) if is_retryable_anyhow_read_error(&err) => {
                if self
                    .confirm_write_published(method, url, Some(confirmation))
                    .await?
                {
                    Ok(())
                } else {
                    Err(err)
                }
            }
            Err(err) => Err(err),
        }
    }

    async fn sleep_before_retry(
        &self,
        method: &str,
        url: &str,
        attempt: u32,
        max_attempts: u32,
        status: Option<reqwest::StatusCode>,
        error: Option<&str>,
    ) {
        let delay = self.retry_policy.delay_after_attempt(attempt);
        warn!(
            method,
            url,
            attempt,
            max_attempts,
            retry_delay_ms = delay.as_millis(),
            status = status.map(|status| status.as_u16()).unwrap_or_default(),
            error = error.unwrap_or_default(),
            "gitlab request failed with retryable error; retrying"
        );
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    async fn confirm_write_published(
        &self,
        method: &str,
        url: &str,
        confirmation: Option<&GitLabWriteConfirmation>,
    ) -> Result<bool> {
        let Some(confirmation) = confirmation else {
            return Ok(false);
        };
        let published = match confirmation {
            GitLabWriteConfirmation::MergeRequest { notes_url, body } => self
                .boxed_note_body_exists(notes_url, body)
                .await
                .with_context(|| format!("confirm gitlab {method} {url} note publication"))?,
            GitLabWriteConfirmation::Discussion {
                discussions_url,
                discussion_id,
                body,
            } => self
                .boxed_discussion_note_body_exists(discussions_url, Some(discussion_id), body)
                .await
                .with_context(|| {
                    format!("confirm gitlab {method} {url} discussion note publication")
                })?,
            GitLabWriteConfirmation::AnyDiscussion {
                discussions_url,
                body,
            } => self
                .boxed_discussion_note_body_exists(discussions_url, None, body)
                .await
                .with_context(|| {
                    format!("confirm gitlab {method} {url} discussion note publication")
                })?,
        };
        if published {
            warn!(
                method,
                url, "gitlab write was already published after retryable error"
            );
        }
        Ok(published)
    }

    async fn note_body_exists(&self, notes_url: &str, body: &str) -> Result<bool> {
        let notes: Vec<Note> = self.get_paginated(notes_url).await?;
        Ok(notes.iter().any(|note| note.body == body))
    }

    fn boxed_note_body_exists<'a>(
        &'a self,
        notes_url: &'a str,
        body: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(self.note_body_exists(notes_url, body))
    }

    async fn discussion_note_body_exists(
        &self,
        discussions_url: &str,
        discussion_id: Option<&str>,
        body: &str,
    ) -> Result<bool> {
        let discussions: Vec<MergeRequestDiscussion> = self.get_paginated(discussions_url).await?;
        Ok(discussions
            .iter()
            .filter(|discussion| discussion_id.is_none_or(|id| discussion.id == id))
            .flat_map(|discussion| &discussion.notes)
            .any(|note| note.body == body))
    }

    fn boxed_discussion_note_body_exists<'a>(
        &'a self,
        discussions_url: &'a str,
        discussion_id: Option<&'a str>,
        body: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(self.discussion_note_body_exists(discussions_url, discussion_id, body))
    }
}

pub(crate) fn normalize_api_base(base_url: &str) -> Result<String> {
    let mut url =
        Url::parse(base_url).with_context(|| format!("parse gitlab base url {base_url}"))?;
    let path = url.path().trim_end_matches('/');
    let new_path = if path.ends_with("/api/v4") {
        path.to_string()
    } else if path.is_empty() {
        "/api/v4".to_string()
    } else {
        format!("{path}/api/v4")
    };
    url.set_path(&new_path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

fn is_retryable_reqwest_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

fn is_retryable_anyhow_read_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<reqwest::Error>()
            .is_some_and(|err| is_retryable_reqwest_error(err) || err.is_body())
    })
}

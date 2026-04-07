use super::pagination;
use super::transport::{ensure_success, ensure_success_bytes, ensure_success_empty};
use crate::tls::ensure_reqwest_rustls_provider;
use anyhow::{Context, Result};
use reqwest::{Client, header};
use serde::Deserialize;
use url::Url;

#[derive(Clone)]
pub struct GitLabClient {
    api_base: String,
    token: String,
    client: Client,
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
        })
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

    pub(crate) async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("gitlab GET {url}"))?;
        ensure_success(response, "GET", url).await
    }

    pub(crate) async fn post_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .send()
            .await
            .with_context(|| format!("gitlab POST {url}"))?;
        ensure_success_empty(response, "POST", url).await
    }

    pub(crate) async fn delete_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .with_context(|| format!("gitlab DELETE {url}"))?;
        ensure_success_empty(response, "DELETE", url).await
    }

    pub(crate) async fn post_note(&self, url: &str, body: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .await
            .with_context(|| format!("gitlab POST {url}"))?;
        ensure_success::<serde_json::Value>(response, "POST", url).await?;
        Ok(())
    }

    pub(crate) async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<()> {
        let response = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .with_context(|| format!("gitlab POST {url}"))?;
        ensure_success::<serde_json::Value>(response, "POST", url).await?;
        Ok(())
    }

    pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de>>(
        &self,
        base_url: &str,
    ) -> Result<Vec<T>> {
        pagination::get_paginated(&self.client, base_url).await
    }

    pub(crate) async fn get_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("gitlab GET {url}"))?;
        ensure_success_bytes(response, "GET", url).await
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

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use reqwest::{Client, Response, header};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabUser {
    pub id: u64,
    pub username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeRequest {
    pub iid: u64,
    pub title: Option<String>,
    pub web_url: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub sha: Option<String>,
    pub source_branch: Option<String>,
    pub target_branch: Option<String>,
    pub diff_refs: Option<DiffRefs>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabProject {
    pub last_activity_at: Option<String>,
}

impl MergeRequest {
    pub fn head_sha(&self) -> Option<String> {
        self.diff_refs
            .as_ref()
            .and_then(|diff| diff.head_sha.clone())
            .or_else(|| self.sha.clone())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiffRefs {
    pub head_sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabProjectSummary {
    pub path_with_namespace: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AwardEmoji {
    pub id: u64,
    pub name: String,
    pub user: GitLabUser,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Note {
    pub id: u64,
    pub body: String,
    pub author: GitLabUser,
}

#[async_trait]
pub trait GitLabApi: Send + Sync {
    async fn current_user(&self) -> Result<GitLabUser>;
    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>>;
    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>>;
    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest>;
    async fn get_project(&self, project: &str) -> Result<GitLabProject>;
    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>>;
    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()>;
    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()>;
    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>>;
    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct GitLabClient {
    api_base: String,
    token: String,
    client: Client,
}

impl GitLabClient {
    pub fn new(base_url: &str, token: &str) -> Result<Self> {
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

    pub fn api_base(&self) -> &str {
        &self.api_base
    }

    fn project_path(&self, project: &str) -> String {
        let encoded = urlencoding::encode(project);
        format!("{}/projects/{}", self.api_base, encoded)
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("gitlab GET {}", url))?;
        ensure_success(response)
            .await
            .with_context(|| format!("gitlab GET {} response", url))
    }

    async fn post_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .send()
            .await
            .with_context(|| format!("gitlab POST {}", url))?;
        ensure_success_empty(response)
            .await
            .with_context(|| format!("gitlab POST {} response", url))
    }

    async fn delete_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .with_context(|| format!("gitlab DELETE {}", url))?;
        ensure_success_empty(response)
            .await
            .with_context(|| format!("gitlab DELETE {} response", url))
    }

    async fn post_note(&self, url: &str, body: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .await
            .with_context(|| format!("gitlab POST {}", url))?;
        ensure_success::<serde_json::Value>(response)
            .await
            .with_context(|| format!("gitlab POST {} response", url))?;
        Ok(())
    }

    async fn get_paginated<T: for<'de> Deserialize<'de>>(&self, base_url: &str) -> Result<Vec<T>> {
        let base = Url::parse(base_url)?;
        let mut items = Vec::new();
        let mut page = 1u32;
        loop {
            let mut url = base.clone();
            {
                let mut pairs = url.query_pairs_mut();
                pairs.append_pair("per_page", "100");
                pairs.append_pair("page", &page.to_string());
            }
            let response = self
                .client
                .get(url.clone())
                .send()
                .await
                .with_context(|| format!("gitlab GET {}", url.as_str()))?;
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
            let mut page_items: Vec<T> = ensure_success(response)
                .await
                .with_context(|| format!("gitlab GET {} response", url.as_str()))?;
            items.append(&mut page_items);
            match next_page {
                Some(next) => {
                    page = next.parse::<u32>().unwrap_or(page + 1);
                }
                None => break,
            }
        }
        Ok(items)
    }

    pub fn git_base_url(&self) -> Result<Url> {
        let mut url = Url::parse(&self.api_base)?;
        let path = url.path().trim_end_matches('/').to_string();
        let stripped = path.strip_suffix("/api/v4").unwrap_or(&path);
        url.set_path(stripped);
        Ok(url)
    }

    pub fn token(&self) -> &str {
        &self.token
    }
}

#[async_trait]
impl GitLabApi for GitLabClient {
    async fn current_user(&self) -> Result<GitLabUser> {
        let url = format!("{}/user", self.api_base);
        self.get_json(&url).await
    }

    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
        let url = format!("{}/projects?simple=true", self.api_base);
        self.get_paginated(&url).await
    }

    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/projects?include_subgroups=true&simple=true",
            self.api_base, encoded
        );
        self.get_paginated(&url).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        let url = format!(
            "{}/merge_requests?state=opened&scope=all",
            self.project_path(project)
        );
        self.get_paginated(&url).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        let url = format!(
            "{}/merge_requests?state=opened&scope=all&order_by=updated_at&sort=desc&per_page=1",
            self.project_path(project)
        );
        let mut mrs: Vec<MergeRequest> = self.get_json(&url).await?;
        Ok(mrs.pop())
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        let url = format!("{}/merge_requests/{}", self.project_path(project), iid);
        self.get_json(&url).await
    }

    async fn get_project(&self, project: &str) -> Result<GitLabProject> {
        let url = self.project_path(project);
        self.get_json(&url).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji?name={}",
            self.project_path(project),
            iid,
            name
        );
        self.post_empty(&url).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji/{}",
            self.project_path(project),
            iid,
            award_id
        );
        self.delete_empty(&url).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        let url = format!(
            "{}/merge_requests/{}/notes",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/notes",
            self.project_path(project),
            iid
        );
        self.post_note(&url, body).await
    }
}

async fn ensure_success<T: for<'de> Deserialize<'de>>(response: Response) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "gitlab api error: status={} body={} ",
            status,
            text
        ));
    }
    let value = response.json::<T>().await?;
    Ok(value)
}

async fn ensure_success_empty(response: Response) -> Result<()> {
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "gitlab api error: status={} body={} ",
            status,
            text
        ));
    }
    Ok(())
}

fn normalize_api_base(base_url: &str) -> Result<String> {
    let mut url =
        Url::parse(base_url).with_context(|| format!("parse gitlab base url {}", base_url))?;
    let path = url.path().trim_end_matches('/');
    let new_path = if path.ends_with("/api/v4") {
        path.to_string()
    } else if path.is_empty() {
        "/api/v4".to_string()
    } else {
        format!("{}/api/v4", path)
    };
    url.set_path(&new_path);
    Ok(url.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{header_exists, method, path, query_param},
    };

    #[tokio::test]
    async fn list_open_mrs_paginates() -> Result<()> {
        let server = MockServer::start().await;
        let page1 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "2")
            .set_body_json(vec![serde_json::json!({
                "iid": 1,
                "sha": "abc"
            })]);
        let page2 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "iid": 2,
                "sha": "def"
            })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
            .and(query_param("state", "opened"))
            .and(query_param("scope", "all"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
            .and(query_param("state", "opened"))
            .and(query_param("scope", "all"))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "100"))
            .respond_with(page2)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let mrs = client.list_open_mrs("group/repo").await?;
        assert_eq!(mrs.len(), 2);
        assert_eq!(mrs[0].iid, 1);
        assert_eq!(mrs[1].iid, 2);
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_open_mr_activity_fetches_latest_update() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
            "iid": 7,
            "updated_at": "2025-01-05T12:34:56Z"
        })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
            .and(query_param("state", "opened"))
            .and(query_param("scope", "all"))
            .and(query_param("order_by", "updated_at"))
            .and(query_param("sort", "desc"))
            .and(query_param("per_page", "1"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let mr = client
            .get_latest_open_mr_activity("group/repo")
            .await?
            .expect("latest MR");
        assert_eq!(mr.iid, 7);
        assert_eq!(
            mr.updated_at,
            Some(DateTime::parse_from_rfc3339("2025-01-05T12:34:56Z")?.with_timezone(&Utc))
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_projects_paginates() -> Result<()> {
        let server = MockServer::start().await;
        let page1 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "2")
            .set_body_json(vec![serde_json::json!({
                "path_with_namespace": "group/repo"
            })]);
        let page2 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "path_with_namespace": "group/other"
            })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v4/projects"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "100"))
            .respond_with(page2)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let projects = client.list_projects().await?;
        assert_eq!(projects.len(), 2);
        assert_eq!(projects[0].path_with_namespace, "group/repo");
        assert_eq!(projects[1].path_with_namespace, "group/other");
        Ok(())
    }

    #[tokio::test]
    async fn list_group_projects_includes_subgroups() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
            "path_with_namespace": "group/sub/repo"
        })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/groups/group%2Fsub/projects"))
            .and(query_param("include_subgroups", "true"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let projects = client.list_group_projects("group/sub").await?;
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].path_with_namespace, "group/sub/repo");
        Ok(())
    }

    #[test]
    fn normalize_api_base_appends_api_path() -> Result<()> {
        let base = normalize_api_base("https://gitlab.example.com")?;
        assert_eq!(base, "https://gitlab.example.com/api/v4");
        Ok(())
    }

    #[tokio::test]
    async fn delete_award_accepts_no_content() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(204);
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/1/award_emoji/42",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        client.delete_award("group/repo", 1, 42).await?;
        Ok(())
    }

    #[tokio::test]
    async fn get_project_reads_last_activity() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "last_activity_at": "2025-01-01T00:00:00Z"
        }));
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let project = client.get_project("group/repo").await?;
        assert_eq!(
            project.last_activity_at,
            Some("2025-01-01T00:00:00Z".to_string())
        );
        Ok(())
    }
}

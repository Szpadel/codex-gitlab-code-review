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
    #[serde(default)]
    pub author: Option<GitLabUser>,
    #[serde(default)]
    pub source_project_id: Option<u64>,
    #[serde(default)]
    pub target_project_id: Option<u64>,
    pub diff_refs: Option<DiffRefs>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabProject {
    #[serde(default)]
    pub path_with_namespace: Option<String>,
    #[serde(default)]
    pub web_url: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
    #[serde(default)]
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GitLabRepositoryRef {
    name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabGroup {
    pub full_path: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub marked_for_deletion_on: Option<String>,
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
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub start_sha: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MergeRequestDiffVersion {
    pub id: u64,
    pub head_commit_sha: String,
    pub base_commit_sha: String,
    pub start_commit_sha: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MergeRequestDiff {
    pub old_path: String,
    pub new_path: String,
    pub diff: String,
    #[serde(default)]
    pub new_file: bool,
    #[serde(default)]
    pub deleted_file: bool,
    #[serde(default)]
    pub renamed_file: bool,
    #[serde(default)]
    pub collapsed: bool,
    #[serde(default)]
    pub too_large: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabProjectSummary {
    pub path_with_namespace: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub marked_for_deletion_on: Option<String>,
    #[serde(default)]
    pub marked_for_deletion_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabGroupSummary {
    pub full_path: String,
    #[serde(default)]
    pub archived: bool,
    #[serde(default)]
    pub marked_for_deletion_on: Option<String>,
}

impl GitLabProjectSummary {
    fn is_active(&self) -> bool {
        !self.archived
            && self.marked_for_deletion_on.is_none()
            && self.marked_for_deletion_at.is_none()
    }
}

impl GitLabGroupSummary {
    fn is_active(&self) -> bool {
        !self.archived && self.marked_for_deletion_on.is_none()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct GitLabCiVariable {
    pub key: String,
    pub value: String,
    pub environment_scope: String,
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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MergeRequestDiscussion {
    pub id: String,
    #[serde(default)]
    pub notes: Vec<DiscussionNote>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiscussionNote {
    pub id: u64,
    pub body: String,
    pub author: GitLabUser,
    #[serde(default)]
    pub system: bool,
    #[serde(default)]
    pub in_reply_to_id: Option<u64>,
    #[serde(default)]
    pub created_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabUserDetail {
    pub id: u64,
    pub username: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub public_email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeRequestDiffDiscussion {
    pub body: String,
    pub position: DiffDiscussionPosition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDiscussionPosition {
    pub base_sha: String,
    pub head_sha: String,
    pub start_sha: String,
    pub old_path: String,
    pub new_path: String,
    pub old_line: Option<usize>,
    pub new_line: Option<usize>,
    pub line_range: Option<DiffDiscussionLineRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDiscussionLineRange {
    pub start: DiffDiscussionLineEndpoint,
    pub end: DiffDiscussionLineEndpoint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffDiscussionLineEndpoint {
    pub line_code: String,
    pub line_type: DiffDiscussionLineType,
    pub old_line: Option<usize>,
    pub new_line: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffDiscussionLineType {
    Old,
    New,
}

#[async_trait]
pub trait GitLabApi: Send + Sync {
    async fn current_user(&self) -> Result<GitLabUser>;
    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_direct_group_projects(&self, _group: &str) -> Result<Vec<GitLabProjectSummary>> {
        Ok(Vec::new())
    }
    async fn list_group_subgroups(&self, _group: &str) -> Result<Vec<GitLabGroupSummary>> {
        Ok(Vec::new())
    }
    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>>;
    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>>;
    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest>;
    async fn list_mr_diff_versions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        Ok(Vec::new())
    }
    async fn list_mr_diffs(&self, _project: &str, _iid: u64) -> Result<Vec<MergeRequestDiff>> {
        Ok(Vec::new())
    }
    async fn get_project(&self, project: &str) -> Result<GitLabProject>;
    async fn list_repository_branches(&self, _project: &str) -> Result<Vec<String>> {
        Err(anyhow!(
            "list_repository_branches not implemented for this gitlab client"
        ))
    }
    async fn list_repository_tags(&self, _project: &str) -> Result<Vec<String>> {
        Err(anyhow!(
            "list_repository_tags not implemented for this gitlab client"
        ))
    }
    async fn get_group(&self, group: &str) -> Result<GitLabGroup> {
        Err(anyhow!(
            "get_group not implemented for this gitlab client (group={group})"
        ))
    }
    async fn list_project_variables(&self, _project: &str) -> Result<Vec<GitLabCiVariable>> {
        Err(anyhow!(
            "list_project_variables not implemented for this gitlab client"
        ))
    }
    async fn get_project_variable(&self, _project: &str, _key: &str) -> Result<GitLabCiVariable> {
        Err(anyhow!(
            "get_project_variable not implemented for this gitlab client"
        ))
    }
    async fn list_group_variables(&self, _group: &str) -> Result<Vec<GitLabCiVariable>> {
        Err(anyhow!(
            "list_group_variables not implemented for this gitlab client"
        ))
    }
    async fn get_group_variable(&self, _group: &str, _key: &str) -> Result<GitLabCiVariable> {
        Err(anyhow!(
            "get_group_variable not implemented for this gitlab client"
        ))
    }
    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>>;
    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()>;
    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()>;
    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>>;
    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()>;
    async fn create_diff_discussion(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        self.create_note(project, iid, &request.body).await
    }
    async fn list_discussions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        Ok(Vec::new())
    }
    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        _discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        self.create_note(project, iid, body).await
    }
    async fn list_discussion_note_awards(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        Ok(Vec::new())
    }
    async fn add_discussion_note_award(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
        _name: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn delete_discussion_note_award(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
        _award_id: u64,
    ) -> Result<()> {
        Ok(())
    }
    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        Err(anyhow!(
            "get_user not implemented for this gitlab client (user_id={user_id})"
        ))
    }
    async fn download_project_upload(
        &self,
        _project: &str,
        _secret: &str,
        _filename: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow!(
            "download_project_upload not implemented for this gitlab client"
        ))
    }
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

    fn group_path(&self, group: &str) -> String {
        let encoded = urlencoding::encode(group);
        format!("{}/groups/{}", self.api_base, encoded)
    }

    fn discussion_note_award_base_url(
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

    fn merge_request_note_award_base_url(&self, project: &str, iid: u64, note_id: u64) -> String {
        format!(
            "{}/merge_requests/{}/notes/{}/award_emoji",
            self.project_path(project),
            iid,
            note_id
        )
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, url: &str) -> Result<T> {
        let response = self
            .client
            .get(url)
            .send()
            .await
            .with_context(|| format!("gitlab GET {}", url))?;
        ensure_success(response, "GET", url).await
    }

    async fn post_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .send()
            .await
            .with_context(|| format!("gitlab POST {}", url))?;
        ensure_success_empty(response, "POST", url).await
    }

    async fn delete_empty(&self, url: &str) -> Result<()> {
        let response = self
            .client
            .delete(url)
            .send()
            .await
            .with_context(|| format!("gitlab DELETE {}", url))?;
        ensure_success_empty(response, "DELETE", url).await
    }

    async fn post_note(&self, url: &str, body: &str) -> Result<()> {
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({ "body": body }))
            .send()
            .await
            .with_context(|| format!("gitlab POST {}", url))?;
        ensure_success::<serde_json::Value>(response, "POST", url).await?;
        Ok(())
    }

    async fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<()> {
        let response = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .with_context(|| format!("gitlab POST {}", url))?;
        ensure_success::<serde_json::Value>(response, "POST", url).await?;
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
            let mut page_items: Vec<T> = ensure_success(response, "GET", url.as_str()).await?;
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

    async fn list_repository_refs(&self, project: &str, ref_kind: &str) -> Result<Vec<String>> {
        let url = format!("{}/repository/{}", self.project_path(project), ref_kind);
        let refs = self.get_paginated::<GitLabRepositoryRef>(&url).await?;
        Ok(sorted_unique(refs.into_iter().map(|item| item.name)))
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

impl DiffDiscussionLineType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::New => "new",
        }
    }
}

fn append_line_range_form_fields(
    form: &mut Vec<(String, String)>,
    endpoint_name: &str,
    endpoint: &DiffDiscussionLineEndpoint,
) {
    let prefix = format!("position[line_range][{endpoint_name}]");
    form.push((format!("{prefix}[line_code]"), endpoint.line_code.clone()));
    form.push((
        format!("{prefix}[type]"),
        endpoint.line_type.as_str().to_string(),
    ));
    if let Some(old_line) = endpoint.old_line {
        form.push((format!("{prefix}[old_line]"), old_line.to_string()));
    }
    if let Some(new_line) = endpoint.new_line {
        form.push((format!("{prefix}[new_line]"), new_line.to_string()));
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
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/projects?include_subgroups=true&simple=true",
            self.api_base, encoded
        );
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    async fn list_direct_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/projects?include_subgroups=false&simple=true",
            self.api_base, encoded
        );
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    async fn list_group_subgroups(&self, group: &str) -> Result<Vec<GitLabGroupSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!("{}/groups/{}/subgroups?simple=true", self.api_base, encoded);
        Ok(self
            .get_paginated::<GitLabGroupSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabGroupSummary::is_active)
            .collect())
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

    async fn list_mr_diff_versions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        let url = format!(
            "{}/merge_requests/{}/versions",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    async fn list_mr_diffs(&self, project: &str, iid: u64) -> Result<Vec<MergeRequestDiff>> {
        let url = format!(
            "{}/merge_requests/{}/diffs",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    async fn get_project(&self, project: &str) -> Result<GitLabProject> {
        let url = self.project_path(project);
        self.get_json(&url).await
    }

    async fn list_repository_branches(&self, project: &str) -> Result<Vec<String>> {
        self.list_repository_refs(project, "branches").await
    }

    async fn list_repository_tags(&self, project: &str) -> Result<Vec<String>> {
        self.list_repository_refs(project, "tags").await
    }

    async fn get_group(&self, group: &str) -> Result<GitLabGroup> {
        let url = self.group_path(group);
        self.get_json(&url).await
    }

    async fn list_project_variables(&self, project: &str) -> Result<Vec<GitLabCiVariable>> {
        let url = format!("{}/variables", self.project_path(project));
        self.get_paginated(&url).await
    }

    async fn get_project_variable(&self, project: &str, key: &str) -> Result<GitLabCiVariable> {
        let encoded_key = urlencoding::encode(key);
        let mut url = Url::parse(&format!(
            "{}/variables/{}",
            self.project_path(project),
            encoded_key
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("filter[environment_scope]", "*");
        }
        self.get_json(url.as_str()).await
    }

    async fn list_group_variables(&self, group: &str) -> Result<Vec<GitLabCiVariable>> {
        let url = format!("{}/variables", self.group_path(group));
        self.get_paginated(&url).await
    }

    async fn get_group_variable(&self, group: &str, key: &str) -> Result<GitLabCiVariable> {
        let encoded_key = urlencoding::encode(key);
        let mut url = Url::parse(&format!(
            "{}/variables/{}",
            self.group_path(group),
            encoded_key
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("filter[environment_scope]", "*");
        }
        self.get_json(url.as_str()).await
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

    async fn create_diff_discussion(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/discussions",
            self.project_path(project),
            iid
        );
        let mut form = vec![
            ("body".to_string(), request.body.clone()),
            ("position[position_type]".to_string(), "text".to_string()),
            (
                "position[base_sha]".to_string(),
                request.position.base_sha.clone(),
            ),
            (
                "position[head_sha]".to_string(),
                request.position.head_sha.clone(),
            ),
            (
                "position[start_sha]".to_string(),
                request.position.start_sha.clone(),
            ),
            (
                "position[old_path]".to_string(),
                request.position.old_path.clone(),
            ),
            (
                "position[new_path]".to_string(),
                request.position.new_path.clone(),
            ),
        ];
        if let Some(old_line) = request.position.old_line {
            form.push(("position[old_line]".to_string(), old_line.to_string()));
        }
        if let Some(new_line) = request.position.new_line {
            form.push(("position[new_line]".to_string(), new_line.to_string()));
        }
        if let Some(line_range) = &request.position.line_range {
            append_line_range_form_fields(&mut form, "start", &line_range.start);
            append_line_range_form_fields(&mut form, "end", &line_range.end);
        }
        self.post_form(&url, &form).await
    }

    async fn list_discussions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        let url = format!(
            "{}/merge_requests/{}/discussions",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        let encoded_discussion_id = urlencoding::encode(discussion_id);
        let url = format!(
            "{}/merge_requests/{}/discussions/{}/notes",
            self.project_path(project),
            iid,
            encoded_discussion_id
        );
        self.post_note(&url, body).await
    }

    async fn list_discussion_note_awards(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        let discussion_url =
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id);
        match self.get_paginated(&discussion_url).await {
            Ok(awards) => Ok(awards),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = self.merge_request_note_award_base_url(project, iid, note_id);
                self.get_paginated(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }

    async fn add_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        let discussion_url = format!(
            "{}?name={}",
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id),
            name
        );
        match self.post_empty(&discussion_url).await {
            Ok(()) => Ok(()),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = format!(
                    "{}?name={}",
                    self.merge_request_note_award_base_url(project, iid, note_id),
                    name
                );
                self.post_empty(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }

    async fn delete_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        let discussion_url = format!(
            "{}/{}",
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id),
            award_id
        );
        match self.delete_empty(&discussion_url).await {
            Ok(()) => Ok(()),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = format!(
                    "{}/{}",
                    self.merge_request_note_award_base_url(project, iid, note_id),
                    award_id
                );
                self.delete_empty(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        let url = format!("{}/users/{}", self.api_base, user_id);
        self.get_json(&url).await
    }

    async fn download_project_upload(
        &self,
        project: &str,
        secret: &str,
        filename: &str,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}/uploads/{}/{}",
            self.project_path(project),
            urlencoding::encode(secret),
            urlencoding::encode(filename)
        );
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("gitlab GET {}", url))?;
        ensure_success_bytes(response, "GET", &url).await
    }
}

const GITLAB_ERROR_BODY_LIMIT: usize = 512;

async fn ensure_success<T: for<'de> Deserialize<'de>>(
    response: Response,
    method: &str,
    url: &str,
) -> Result<T> {
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(format_gitlab_http_error(
            method, url, status, &text
        )));
    }
    let value = response
        .json::<T>()
        .await
        .with_context(|| format!("gitlab {method} {url} response"))?;
    Ok(value)
}

async fn ensure_success_empty(response: Response, method: &str, url: &str) -> Result<()> {
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(format_gitlab_http_error(
            method, url, status, &text
        )));
    }
    Ok(())
}

async fn ensure_success_bytes(response: Response, method: &str, url: &str) -> Result<Vec<u8>> {
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        return Err(anyhow!(format_gitlab_http_error(
            method, url, status, &text
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
    body: &str,
) -> String {
    format!(
        "gitlab {method} {url} response: status={status} body={}",
        format_gitlab_error_body(body)
    )
}

fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
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

fn should_fallback_to_merge_request_note_awards(err: &anyhow::Error) -> bool {
    gitlab_error_has_status(err, &[404, 405, 400, 422])
}

pub(crate) fn gitlab_error_has_status(err: &anyhow::Error, statuses: &[u16]) -> bool {
    let text = format!("{err:#}");
    statuses
        .iter()
        .any(|status| text.contains(&format!("status={status}")))
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
        matchers::{body_string_contains, header_exists, method, path, query_param},
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
    async fn get_latest_open_mr_activity_error_is_self_contained() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
            .and(query_param("state", "opened"))
            .and(query_param("scope", "all"))
            .and(query_param("order_by", "updated_at"))
            .and(query_param("sort", "desc"))
            .and(query_param("per_page", "1"))
            .respond_with(
                ResponseTemplate::new(502)
                    .insert_header("content-type", "text/plain")
                    .set_body_string("upstream proxy failure"),
            )
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let err = client
            .get_latest_open_mr_activity("group/repo")
            .await
            .expect_err("request should fail");
        let message = err.to_string();
        assert!(message.contains("gitlab GET"));
        assert!(message.contains("/projects/group%2Frepo/merge_requests?state=opened"));
        assert!(message.contains("status=502 Bad Gateway"));
        assert!(message.contains("body=upstream proxy failure"));
        Ok(())
    }

    #[tokio::test]
    async fn get_latest_open_mr_activity_json_decode_error_keeps_request_context() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
            .and(query_param("state", "opened"))
            .and(query_param("scope", "all"))
            .and(query_param("order_by", "updated_at"))
            .and(query_param("sort", "desc"))
            .and(query_param("per_page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_string("<html>proxy splash</html>"),
            )
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let err = client
            .get_latest_open_mr_activity("group/repo")
            .await
            .expect_err("request should fail");
        let message = err.to_string();
        assert!(message.contains("gitlab GET"));
        assert!(message.contains("/projects/group%2Frepo/merge_requests?state=opened"));
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
    async fn list_projects_excludes_inactive_entries() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![
            serde_json::json!({
                "path_with_namespace": "group/active",
                "archived": false,
                "marked_for_deletion_on": null
            }),
            serde_json::json!({
                "path_with_namespace": "group/archived",
                "archived": true,
                "marked_for_deletion_on": null
            }),
            serde_json::json!({
                "path_with_namespace": "group/deleting",
                "archived": false,
                "marked_for_deletion_on": "2026-03-18"
            }),
        ]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let projects = client.list_projects().await?;
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].path_with_namespace, "group/active");
        Ok(())
    }

    #[tokio::test]
    async fn create_note_error_is_self_contained() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests/7/notes"))
            .respond_with(
                ResponseTemplate::new(403)
                    .insert_header("content-type", "application/json")
                    .set_body_string(r#"{"message":"forbidden"}"#),
            )
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let err = client
            .create_note("group/repo", 7, "hello")
            .await
            .expect_err("request should fail");
        let message = err.to_string();
        assert!(message.contains("gitlab POST"));
        assert!(message.contains("/projects/group%2Frepo/merge_requests/7/notes"));
        assert!(message.contains("status=403 Forbidden"));
        assert!(message.contains(r#"body={"message":"forbidden"}"#));
        Ok(())
    }

    #[tokio::test]
    async fn download_project_upload_fetches_bytes_from_gitlab() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/uploads/hash/screenshot%20final.png",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/png")
                    .set_body_bytes(b"png-bytes".to_vec()),
            )
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        assert_eq!(
            client
                .download_project_upload("group/repo", "hash", "screenshot final.png")
                .await?,
            b"png-bytes".to_vec()
        );
        Ok(())
    }

    #[tokio::test]
    async fn download_project_upload_error_is_self_contained() -> Result<()> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/uploads/hash/missing.png",
            ))
            .respond_with(
                ResponseTemplate::new(404)
                    .insert_header("content-type", "application/json")
                    .set_body_string(r#"{"message":"404 Upload Not Found"}"#),
            )
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let err = client
            .download_project_upload("group/repo", "hash", "missing.png")
            .await
            .expect_err("request should fail");
        let message = err.to_string();
        assert!(message.contains("gitlab GET"));
        assert!(message.contains("/projects/group%2Frepo/uploads/hash/missing.png"));
        assert!(message.contains("status=404 Not Found"));
        assert!(message.contains(r#"body={"message":"404 Upload Not Found"}"#));
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

    #[tokio::test]
    async fn list_group_projects_excludes_inactive_entries() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![
            serde_json::json!({
                "path_with_namespace": "group/sub/active",
                "archived": false,
                "marked_for_deletion_at": null
            }),
            serde_json::json!({
                "path_with_namespace": "group/sub/archived",
                "archived": true,
                "marked_for_deletion_at": null
            }),
            serde_json::json!({
                "path_with_namespace": "group/sub/deleting",
                "archived": false,
                "marked_for_deletion_at": "2026-03-18"
            }),
        ]);

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
        assert_eq!(projects[0].path_with_namespace, "group/sub/active");
        Ok(())
    }

    #[tokio::test]
    async fn list_direct_group_projects_excludes_subgroups() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
            "path_with_namespace": "group/sub/repo"
        })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/groups/group%2Fsub/projects"))
            .and(query_param("include_subgroups", "false"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let projects = client.list_direct_group_projects("group/sub").await?;
        assert_eq!(projects.len(), 1);
        assert_eq!(projects[0].path_with_namespace, "group/sub/repo");
        Ok(())
    }

    #[tokio::test]
    async fn list_group_subgroups_returns_full_paths() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
            "full_path": "group/sub/child"
        })]);

        Mock::given(method("GET"))
            .and(path("/api/v4/groups/group%2Fsub/subgroups"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let groups = client.list_group_subgroups("group/sub").await?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].full_path, "group/sub/child");
        Ok(())
    }

    #[tokio::test]
    async fn list_group_subgroups_excludes_inactive_entries() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![
            serde_json::json!({
                "full_path": "group/sub/active",
                "archived": false,
                "marked_for_deletion_on": null
            }),
            serde_json::json!({
                "full_path": "group/sub/archived",
                "archived": true,
                "marked_for_deletion_on": null
            }),
            serde_json::json!({
                "full_path": "group/sub/deleting",
                "archived": false,
                "marked_for_deletion_on": "2026-03-18"
            }),
        ]);

        Mock::given(method("GET"))
            .and(path("/api/v4/groups/group%2Fsub/subgroups"))
            .and(query_param("simple", "true"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let groups = client.list_group_subgroups("group/sub").await?;
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].full_path, "group/sub/active");
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
            "web_url": "https://gitlab.example.com/group/repo",
            "default_branch": "main",
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
            project.web_url,
            Some("https://gitlab.example.com/group/repo".to_string())
        );
        assert_eq!(project.default_branch, Some("main".to_string()));
        assert_eq!(
            project.last_activity_at,
            Some("2025-01-01T00:00:00Z".to_string())
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_repository_branches_paginates_and_sorts_names() -> Result<()> {
        let server = MockServer::start().await;
        let page1 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "2")
            .set_body_json(vec![
                serde_json::json!({ "name": "release" }),
                serde_json::json!({ "name": "main" }),
            ]);
        let page2 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![
                serde_json::json!({ "name": "develop" }),
                serde_json::json!({ "name": "main" }),
            ]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/repository/branches"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/repository/branches"))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page2)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let branches = client.list_repository_branches("group/repo").await?;

        assert_eq!(branches, vec!["develop", "main", "release"]);
        Ok(())
    }

    #[tokio::test]
    async fn list_repository_tags_paginates_and_sorts_names() -> Result<()> {
        let server = MockServer::start().await;
        let page1 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "2")
            .set_body_json(vec![
                serde_json::json!({ "name": "v2.0.0" }),
                serde_json::json!({ "name": "v1.0.0" }),
            ]);
        let page2 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![
                serde_json::json!({ "name": "v1.5.0" }),
                serde_json::json!({ "name": "v1.0.0" }),
            ]);

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/repository/tags"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/repository/tags"))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page2)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let tags = client.list_repository_tags("group/repo").await?;

        assert_eq!(tags, vec!["v1.0.0", "v1.5.0", "v2.0.0"]);
        Ok(())
    }

    #[tokio::test]
    async fn get_project_variable_requests_global_scope_filter() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key": "COMPOSER_AUTH",
            "value": "{\"http-basic\":{}}",
            "environment_scope": "*",
            "variable_type": "env_var",
            "protected": false,
            "masked": true,
            "hidden": false,
            "raw": false,
            "description": null
        }));
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/variables/COMPOSER_AUTH",
            ))
            .and(query_param("filter[environment_scope]", "*"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let variable = client
            .get_project_variable("group/repo", "COMPOSER_AUTH")
            .await?;
        assert_eq!(variable.value, "{\"http-basic\":{}}");
        assert_eq!(variable.environment_scope, "*");
        Ok(())
    }

    #[tokio::test]
    async fn get_group_variable_requests_global_scope_filter() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key": "COMPOSER_AUTH",
            "value": "{\"http-basic\":{}}",
            "environment_scope": "*",
            "variable_type": "env_var",
            "protected": false,
            "masked": true,
            "hidden": false,
            "raw": false,
            "description": null
        }));
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/groups/group%2Fsubgroup/variables/COMPOSER_AUTH",
            ))
            .and(query_param("filter[environment_scope]", "*"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let variable = client
            .get_group_variable("group/subgroup", "COMPOSER_AUTH")
            .await?;
        assert_eq!(variable.value, "{\"http-basic\":{}}");
        assert_eq!(variable.environment_scope, "*");
        Ok(())
    }

    #[tokio::test]
    async fn list_discussions_reads_thread_notes() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
            "id": "discussion-1",
            "notes": [
                {
                    "id": 101,
                    "body": "root",
                    "system": false,
                    "author": { "id": 1, "username": "alice", "name": "Alice" }
                },
                {
                    "id": 102,
                    "body": "@botuser please fix",
                    "system": false,
                    "in_reply_to_id": 101,
                    "author": { "id": 2, "username": "bob", "name": "Bob" }
                }
            ]
        })]);
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/9/discussions",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let discussions = client.list_discussions("group/repo", 9).await?;
        assert_eq!(discussions.len(), 1);
        assert_eq!(discussions[0].id, "discussion-1");
        assert_eq!(discussions[0].notes.len(), 2);
        assert_eq!(discussions[0].notes[1].in_reply_to_id, Some(101));
        Ok(())
    }

    #[tokio::test]
    async fn list_mr_diff_versions_reads_latest_version_metadata() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "id": 110,
                "head_commit_sha": "head-1",
                "base_commit_sha": "base-1",
                "start_commit_sha": "start-1"
            })]);
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/versions",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let versions = client.list_mr_diff_versions("group/repo", 3).await?;
        assert_eq!(
            versions,
            vec![MergeRequestDiffVersion {
                id: 110,
                head_commit_sha: "head-1".to_string(),
                base_commit_sha: "base-1".to_string(),
                start_commit_sha: "start-1".to_string(),
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_mr_diffs_reads_all_pages() -> Result<()> {
        let server = MockServer::start().await;
        let page1 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "2")
            .set_body_json(vec![serde_json::json!({
                "old_path": "src/old.rs",
                "new_path": "src/new.rs",
                "diff": "@@ -1 +1 @@\n-old\n+new\n",
                "renamed_file": true,
                "new_file": false,
                "deleted_file": false,
                "collapsed": false,
                "too_large": false
            })]);
        let page2 = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "old_path": "src/lib.rs",
                "new_path": "src/lib.rs",
                "diff": "@@ -4 +4 @@\n-old\n+new\n",
                "renamed_file": false,
                "new_file": false,
                "deleted_file": false,
                "collapsed": false,
                "too_large": false
            })]);
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests/8/diffs"))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Frepo/merge_requests/8/diffs"))
            .and(query_param("page", "2"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(page2)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let diffs = client.list_mr_diffs("group/repo", 8).await?;
        assert_eq!(diffs.len(), 2);
        assert_eq!(diffs[0].new_path, "src/new.rs");
        assert!(diffs[0].renamed_file);
        assert_eq!(diffs[1].new_path, "src/lib.rs");
        Ok(())
    }

    #[tokio::test]
    async fn create_diff_discussion_posts_position_form_fields() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": "discussion-77"
        }));
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/4/discussions",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .and(body_string_contains("body=inline+review"))
            .and(body_string_contains("position%5Bposition_type%5D=text"))
            .and(body_string_contains("position%5Bbase_sha%5D=base"))
            .and(body_string_contains("position%5Bhead_sha%5D=head"))
            .and(body_string_contains("position%5Bstart_sha%5D=start"))
            .and(body_string_contains("position%5Bold_path%5D=src%2Flib.rs"))
            .and(body_string_contains("position%5Bnew_path%5D=src%2Flib.rs"))
            .and(body_string_contains("position%5Bnew_line%5D=14"))
            .and(body_string_contains(
                "position%5Bline_range%5D%5Bstart%5D%5Bline_code%5D=hash_14_14",
            ))
            .and(body_string_contains(
                "position%5Bline_range%5D%5Bend%5D%5Bline_code%5D=hash_16_16",
            ))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        client
            .create_diff_discussion(
                "group/repo",
                4,
                &MergeRequestDiffDiscussion {
                    body: "inline review".to_string(),
                    position: DiffDiscussionPosition {
                        base_sha: "base".to_string(),
                        head_sha: "head".to_string(),
                        start_sha: "start".to_string(),
                        old_path: "src/lib.rs".to_string(),
                        new_path: "src/lib.rs".to_string(),
                        old_line: Some(14),
                        new_line: Some(14),
                        line_range: Some(DiffDiscussionLineRange {
                            start: DiffDiscussionLineEndpoint {
                                line_code: "hash_14_14".to_string(),
                                line_type: DiffDiscussionLineType::New,
                                old_line: Some(14),
                                new_line: Some(14),
                            },
                            end: DiffDiscussionLineEndpoint {
                                line_code: "hash_16_16".to_string(),
                                line_type: DiffDiscussionLineType::New,
                                old_line: Some(16),
                                new_line: Some(16),
                            },
                        }),
                    },
                },
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn create_discussion_note_posts_to_discussion_endpoint() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 777
        }));
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        client
            .create_discussion_note("group/repo", 3, "discussion-123", "working on it")
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn discussion_note_award_endpoints_use_discussion_note_path() -> Result<()> {
        let server = MockServer::start().await;
        let list_response = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "id": 501,
                "name": "eyes",
                "user": { "id": 1, "username": "botuser", "name": "Bot User" }
            })]);
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(list_response)
            .mount(&server)
            .await;

        let add_response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 777
        }));
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("name", "eyes"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(add_response)
            .mount(&server)
            .await;

        let delete_response = ResponseTemplate::new(204);
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji/501",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(delete_response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let awards = client
            .list_discussion_note_awards("group/repo", 3, "discussion-123", 777)
            .await?;
        assert_eq!(awards.len(), 1);
        client
            .add_discussion_note_award("group/repo", 3, "discussion-123", 777, "eyes")
            .await?;
        client
            .delete_discussion_note_award("group/repo", 3, "discussion-123", 777, 501)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn discussion_note_award_endpoints_fallback_to_merge_request_note_path() -> Result<()> {
        let server = MockServer::start().await;

        let not_found = ResponseTemplate::new(404).set_body_string("not found");
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .respond_with(not_found.clone())
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("name", "eyes"))
            .respond_with(not_found.clone())
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji/501",
            ))
            .respond_with(not_found)
            .mount(&server)
            .await;

        let list_fallback_response = ResponseTemplate::new(200)
            .append_header("X-Next-Page", "")
            .set_body_json(vec![serde_json::json!({
                "id": 501,
                "name": "eyes",
                "user": { "id": 1, "username": "botuser", "name": "Bot User" }
            })]);
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .respond_with(list_fallback_response)
            .mount(&server)
            .await;
        let add_fallback_response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "id": 777
        }));
        Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji",
            ))
            .and(query_param("name", "eyes"))
            .respond_with(add_fallback_response)
            .mount(&server)
            .await;
        let delete_fallback_response = ResponseTemplate::new(204);
        Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji/501",
            ))
            .respond_with(delete_fallback_response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let awards = client
            .list_discussion_note_awards("group/repo", 3, "discussion-123", 777)
            .await?;
        assert_eq!(awards.len(), 1);
        client
            .add_discussion_note_award("group/repo", 3, "discussion-123", 777, "eyes")
            .await?;
        client
            .delete_discussion_note_award("group/repo", 3, "discussion-123", 777, 501)
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn get_user_reads_public_email() -> Result<()> {
        let server = MockServer::start().await;
        let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": 44,
            "username": "dev-user",
            "name": "Dev User",
            "public_email": "dev@example.com"
        }));
        Mock::given(method("GET"))
            .and(path("/api/v4/users/44"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(response)
            .mount(&server)
            .await;

        let client = GitLabClient::new(&server.uri(), "token")?;
        let user = client.get_user(44).await?;
        assert_eq!(user.id, 44);
        assert_eq!(user.username.as_deref(), Some("dev-user"));
        assert_eq!(user.public_email.as_deref(), Some("dev@example.com"));
        Ok(())
    }
}

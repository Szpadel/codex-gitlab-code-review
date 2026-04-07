use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GitLabUser {
    pub id: u64,
    pub username: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(from = "RawMergeRequest")]
pub struct MergeRequest {
    pub iid: u64,
    pub title: Option<String>,
    pub web_url: Option<String>,
    pub draft: bool,
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

#[derive(Debug, Clone, Deserialize)]
struct RawMergeRequest {
    pub iid: u64,
    pub title: Option<String>,
    pub web_url: Option<String>,
    #[serde(default)]
    pub draft: Option<bool>,
    #[serde(default)]
    pub work_in_progress: Option<bool>,
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

impl From<RawMergeRequest> for MergeRequest {
    fn from(raw: RawMergeRequest) -> Self {
        Self {
            iid: raw.iid,
            title: raw.title,
            web_url: raw.web_url,
            draft: raw
                .draft
                .unwrap_or_else(|| raw.work_in_progress.unwrap_or(false)),
            created_at: raw.created_at,
            updated_at: raw.updated_at,
            sha: raw.sha,
            source_branch: raw.source_branch,
            target_branch: raw.target_branch,
            author: raw.author,
            source_project_id: raw.source_project_id,
            target_project_id: raw.target_project_id,
            diff_refs: raw.diff_refs,
        }
    }
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
pub(crate) struct GitLabRepositoryRef {
    pub(crate) name: String,
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
    #[must_use]
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
    pub(crate) fn is_active(&self) -> bool {
        !self.archived
            && self.marked_for_deletion_on.is_none()
            && self.marked_for_deletion_at.is_none()
    }
}

impl GitLabGroupSummary {
    pub(crate) fn is_active(&self) -> bool {
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

impl DiffDiscussionLineType {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Old => "old",
            Self::New => "new",
        }
    }
}

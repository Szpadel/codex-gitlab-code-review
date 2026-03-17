mod registry;
mod server;
mod service;

pub use registry::{
    GitLabDiscoverySessionBinding, GitLabDiscoverySessionRegistry,
    ResolvedGitLabDiscoveryAllowList, generate_bearer_token, resolve_allow_list,
};
pub use service::GitLabDiscoveryMcpService;

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct GitLabDiscoveryPathEntry {
    #[serde(rename = "type")]
    pub kind: GitLabDiscoveryPathEntryKind,
    pub path: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum GitLabDiscoveryPathEntryKind {
    Group,
    Repo,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListGitLabPathsRequest {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListGitLabPathsResponse {
    pub current_path: Option<String>,
    pub entries: Vec<GitLabDiscoveryPathEntry>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CloneGitLabRepoRequest {
    pub repo_path: String,
    #[serde(default)]
    pub checkout_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct CloneGitLabRepoResponse {
    pub path: String,
    pub head_sha: String,
    pub default_branch: String,
    pub checked_out_ref: String,
    pub checked_out_kind: GitLabCheckoutKind,
    pub branches: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GitLabCheckoutKind {
    Branch,
    Tag,
}

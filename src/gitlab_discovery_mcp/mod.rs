mod registry;
mod server;
mod service;

use crate::composer_install::ComposerInstallResult;
pub use registry::{
    GitLabDiscoverySessionBinding, GitLabDiscoverySessionRegistry, GitLabPathListing,
    ResolvedGitLabDiscoveryAllowList, resolve_allow_list,
};
pub use service::GitLabDiscoveryMcpService;

use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct ListGitLabPathsRequest {
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub struct ListGitLabPathsResponse {
    pub current_path: Option<String>,
    pub subgroups: Vec<String>,
    pub repositories: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, JsonSchema)]
pub struct CloneGitLabRepoRequest {
    pub repo_path: String,
    #[serde(default)]
    pub checkout_ref: Option<String>,
    #[serde(default)]
    pub commit_sha: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composer_install: Option<ComposerInstallResult>,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitLabCheckoutKind {
    Branch,
    Tag,
    Commit,
}

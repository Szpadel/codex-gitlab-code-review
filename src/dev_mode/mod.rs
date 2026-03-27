mod runner;
mod transcript;

use crate::gitlab::{
    AwardEmoji, GitLabApi, GitLabProject, GitLabProjectSummary, GitLabUser, GitLabUserDetail,
    MergeRequest, Note,
};
use crate::review::DynamicRepoSource;
use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use std::collections::{BTreeMap, hash_map::DefaultHasher};
use std::fmt::Write as _;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::RwLock;

pub use runner::MockCodexRunner;

pub const DEV_MODE_BASE_URL: &str = "https://dev-mode.invalid";
const DEFAULT_REPOS: &[&str] = &[
    "demo/group/service-a",
    "demo/group/service-b",
    "demo/group/service-c",
];
const BOT_USER_ID: u64 = 1;
const BOT_USERNAME: &str = "codex-dev";
const BOT_DISPLAY_NAME: &str = "Codex Dev";

#[derive(Clone)]
pub struct DevToolsService {
    database_path: String,
    state: Arc<RwLock<DevToolsState>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DevelopmentSnapshot {
    pub database_path: String,
    pub repos: Vec<DevelopmentRepoSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct DevelopmentRepoSnapshot {
    pub repo_path: String,
    pub active_mr_iid: Option<u64>,
    pub active_revision: Option<u64>,
    pub active_head_sha: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Default)]
struct DevToolsState {
    next_project_id: u64,
    next_note_id: u64,
    next_award_id: u64,
    repos: BTreeMap<String, DevRepository>,
}

#[derive(Debug, Clone)]
struct DevRepository {
    project_id: u64,
    next_iid: u64,
    active_mr: Option<DevMergeRequest>,
    notes: Vec<Note>,
    awards: Vec<AwardEmoji>,
}

#[derive(Debug, Clone)]
struct DevMergeRequest {
    iid: u64,
    title: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    head_sha: String,
    revision: u64,
    source_branch: String,
    target_branch: String,
    author: GitLabUser,
}

impl DevToolsService {
    #[must_use]
    pub fn new(database_path: &str) -> Self {
        let mut state = DevToolsState::default();
        for repo_path in DEFAULT_REPOS {
            state.insert_repo(repo_path);
        }
        Self {
            database_path: database_path.to_string(),
            state: Arc::new(RwLock::new(state)),
        }
    }

    #[must_use]
    pub fn database_path(&self) -> &str {
        &self.database_path
    }

    #[must_use]
    pub fn gitlab_api(&self) -> Arc<dyn GitLabApi> {
        Arc::new(DevGitLabApi {
            state: Arc::clone(&self.state),
        })
    }

    pub async fn snapshot(&self) -> DevelopmentSnapshot {
        let state = self.state.read().await;
        let repos = state
            .repos
            .iter()
            .map(|(repo_path, repo)| DevelopmentRepoSnapshot {
                repo_path: repo_path.clone(),
                active_mr_iid: repo.active_mr.as_ref().map(|mr| mr.iid),
                active_revision: repo.active_mr.as_ref().map(|mr| mr.revision),
                active_head_sha: repo.active_mr.as_ref().map(|mr| mr.head_sha.clone()),
                updated_at: repo.active_mr.as_ref().map(|mr| mr.updated_at.to_rfc3339()),
            })
            .collect();
        DevelopmentSnapshot {
            database_path: self.database_path.clone(),
            repos,
        }
    }

    /// # Errors
    ///
    /// Returns an error if the synthetic repository catalog cannot be updated.
    pub async fn create_repo(&self, repo_path: &str) -> Result<()> {
        let normalized = normalize_repo_path(repo_path)?;
        let mut state = self.state.write().await;
        if !state.repos.contains_key(&normalized) {
            state.insert_repo(&normalized);
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the synthetic repository cannot be renamed or the
    /// backing state cannot be updated.
    pub async fn update_repo(&self, existing_repo_path: &str, repo_path: &str) -> Result<()> {
        let existing = normalize_repo_path(existing_repo_path)?;
        let replacement = normalize_repo_path(repo_path)?;
        let mut state = self.state.write().await;
        let mut repo = state
            .repos
            .remove(&existing)
            .ok_or_else(|| anyhow!("repo not found: {existing}"))?;
        if existing != replacement && state.repos.contains_key(&replacement) {
            state.repos.insert(existing, repo);
            bail!("repo already exists: {replacement}");
        }
        if let Some(active_mr) = repo.active_mr.as_mut() {
            active_mr.title = format!("Synthetic review for {replacement}");
        }
        state.repos.insert(replacement, repo);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the synthetic repository cannot be removed from the
    /// backing state.
    pub async fn delete_repo(&self, repo_path: &str) -> Result<()> {
        let normalized = normalize_repo_path(repo_path)?;
        let removed = self.state.write().await.repos.remove(&normalized);
        if removed.is_none() {
            bail!("repo not found: {normalized}");
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the synthetic merge request cannot be created or
    /// persisted.
    pub async fn simulate_new_mr(&self, repo_path: &str) -> Result<()> {
        let normalized = normalize_repo_path(repo_path)?;
        let mut state = self.state.write().await;
        let repo = state
            .repos
            .get_mut(&normalized)
            .ok_or_else(|| anyhow!("repo not found: {normalized}"))?;
        let iid = repo.next_iid;
        repo.next_iid += 1;
        let now = Utc::now();
        repo.active_mr = Some(DevMergeRequest {
            iid,
            title: format!("Synthetic review for {normalized}"),
            created_at: now,
            updated_at: now,
            head_sha: synthetic_sha(&normalized, iid, 1),
            revision: 1,
            source_branch: format!("dev/synthetic-{iid}"),
            target_branch: "main".to_string(),
            author: synthetic_author(),
        });
        repo.notes.clear();
        repo.awards.clear();
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the synthetic repository state cannot be advanced or
    /// persisted.
    pub async fn simulate_new_commit(&self, repo_path: &str) -> Result<()> {
        let normalized = normalize_repo_path(repo_path)?;
        let mut state = self.state.write().await;
        let repo = state
            .repos
            .get_mut(&normalized)
            .ok_or_else(|| anyhow!("repo not found: {normalized}"))?;
        let active_mr = repo
            .active_mr
            .as_mut()
            .ok_or_else(|| anyhow!("invalid repo action: no active synthetic MR"))?;
        active_mr.revision += 1;
        active_mr.updated_at = Utc::now();
        active_mr.head_sha = synthetic_sha(&normalized, active_mr.iid, active_mr.revision);
        Ok(())
    }
}

#[async_trait]
impl DynamicRepoSource for DevToolsService {
    async fn list_repos(&self) -> Result<Vec<String>> {
        let state = self.state.read().await;
        Ok(state.repos.keys().cloned().collect())
    }
}

impl DevToolsState {
    fn insert_repo(&mut self, repo_path: &str) {
        self.next_project_id += 1;
        self.repos.insert(
            repo_path.to_string(),
            DevRepository {
                project_id: self.next_project_id,
                next_iid: 1,
                active_mr: None,
                notes: Vec::new(),
                awards: Vec::new(),
            },
        );
    }
}

struct DevGitLabApi {
    state: Arc<RwLock<DevToolsState>>,
}

#[async_trait]
impl GitLabApi for DevGitLabApi {
    async fn current_user(&self) -> Result<GitLabUser> {
        Ok(bot_user())
    }

    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
        let state = self.state.read().await;
        Ok(state
            .repos
            .keys()
            .cloned()
            .map(|path_with_namespace| GitLabProjectSummary {
                path_with_namespace,
                archived: false,
                marked_for_deletion_on: None,
                marked_for_deletion_at: None,
            })
            .collect())
    }

    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        let state = self.state.read().await;
        let prefix = format!("{}/", group.trim_matches('/'));
        Ok(state
            .repos
            .keys()
            .filter(|repo_path| repo_path.starts_with(&prefix))
            .cloned()
            .map(|path_with_namespace| GitLabProjectSummary {
                path_with_namespace,
                archived: false,
                marked_for_deletion_on: None,
                marked_for_deletion_at: None,
            })
            .collect())
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        let state = self.state.read().await;
        let repo = load_repo(&state, project)?;
        Ok(repo
            .active_mr
            .as_ref()
            .map(|mr| mr.as_merge_request(project, repo.project_id))
            .into_iter()
            .collect())
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        let state = self.state.read().await;
        let repo = load_repo(&state, project)?;
        Ok(repo
            .active_mr
            .as_ref()
            .map(|mr| mr.as_merge_request(project, repo.project_id)))
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        let state = self.state.read().await;
        let repo = load_repo(&state, project)?;
        let active_mr = repo
            .active_mr
            .as_ref()
            .filter(|mr| mr.iid == iid)
            .ok_or_else(|| anyhow!("mr not found"))?;
        Ok(active_mr.as_merge_request(project, repo.project_id))
    }

    async fn get_project(&self, project: &str) -> Result<GitLabProject> {
        let state = self.state.read().await;
        let (path_with_namespace, repo) = find_repo(&state, project)?;
        Ok(GitLabProject {
            path_with_namespace: Some(path_with_namespace.to_string()),
            web_url: Some(project_web_url(path_with_namespace)),
            default_branch: Some("main".to_string()),
            last_activity_at: repo.active_mr.as_ref().map(|mr| mr.updated_at.to_rfc3339()),
        })
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        let state = self.state.read().await;
        let repo = load_repo(&state, project)?;
        ensure_active_mr(repo, iid)?;
        Ok(repo.awards.clone())
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        let mut state = self.state.write().await;
        let next_award_id = state.next_award_id + 1;
        state.next_award_id = next_award_id;
        let repo = load_repo_mut(&mut state, project)?;
        ensure_active_mr(repo, iid)?;
        repo.awards.push(AwardEmoji {
            id: next_award_id,
            name: name.to_string(),
            user: bot_user(),
        });
        Ok(())
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        let mut state = self.state.write().await;
        let repo = load_repo_mut(&mut state, project)?;
        ensure_active_mr(repo, iid)?;
        repo.awards.retain(|award| award.id != award_id);
        Ok(())
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        let state = self.state.read().await;
        let repo = load_repo(&state, project)?;
        ensure_active_mr(repo, iid)?;
        Ok(repo.notes.clone())
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        let mut state = self.state.write().await;
        let next_note_id = state.next_note_id + 1;
        state.next_note_id = next_note_id;
        let repo = load_repo_mut(&mut state, project)?;
        ensure_active_mr(repo, iid)?;
        repo.notes.push(Note {
            id: next_note_id,
            body: body.to_string(),
            author: bot_user(),
        });
        Ok(())
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        Ok(GitLabUserDetail {
            id: user_id,
            username: Some(BOT_USERNAME.to_string()),
            name: Some(BOT_DISPLAY_NAME.to_string()),
            public_email: Some("codex-dev@example.invalid".to_string()),
        })
    }
}

impl DevMergeRequest {
    fn as_merge_request(&self, repo_path: &str, project_id: u64) -> MergeRequest {
        MergeRequest {
            iid: self.iid,
            title: Some(self.title.clone()),
            web_url: Some(format!(
                "{}/-/merge_requests/{}",
                project_web_url(repo_path),
                self.iid
            )),
            draft: false,
            created_at: Some(self.created_at),
            updated_at: Some(self.updated_at),
            sha: Some(self.head_sha.clone()),
            source_branch: Some(self.source_branch.clone()),
            target_branch: Some(self.target_branch.clone()),
            author: Some(self.author.clone()),
            source_project_id: Some(project_id),
            target_project_id: Some(project_id),
            diff_refs: None,
        }
    }
}

fn normalize_repo_path(repo_path: &str) -> Result<String> {
    let normalized = repo_path.trim().trim_matches('/').to_string();
    if normalized.is_empty() {
        bail!("invalid repo path: must not be empty");
    }
    Ok(normalized)
}

fn synthetic_sha(repo_path: &str, iid: u64, revision: u64) -> String {
    let mut hex = String::new();
    for salt in 0_u64..5 {
        let mut hasher = DefaultHasher::new();
        repo_path.hash(&mut hasher);
        iid.hash(&mut hasher);
        revision.hash(&mut hasher);
        salt.hash(&mut hasher);
        let _ = write!(hex, "{:016x}", hasher.finish());
    }
    hex.truncate(40);
    hex
}

fn project_web_url(repo_path: &str) -> String {
    format!("{DEV_MODE_BASE_URL}/{repo_path}")
}

fn bot_user() -> GitLabUser {
    GitLabUser {
        id: BOT_USER_ID,
        username: Some(BOT_USERNAME.to_string()),
        name: Some(BOT_DISPLAY_NAME.to_string()),
    }
}

fn synthetic_author() -> GitLabUser {
    GitLabUser {
        id: 2,
        username: Some("synthetic-author".to_string()),
        name: Some("Synthetic Author".to_string()),
    }
}

fn find_repo<'a>(
    state: &'a DevToolsState,
    project: &'a str,
) -> Result<(&'a str, &'a DevRepository)> {
    if let Some(repo) = state.repos.get(project) {
        return Ok((project, repo));
    }

    let project_id = project.parse::<u64>().ok();
    state
        .repos
        .iter()
        .find(|(_, repo)| Some(repo.project_id) == project_id)
        .map(|(repo_path, repo)| (repo_path.as_str(), repo))
        .ok_or_else(|| anyhow!("project not found: {project}"))
}

fn load_repo<'a>(state: &'a DevToolsState, project: &'a str) -> Result<&'a DevRepository> {
    find_repo(state, project).map(|(_, repo)| repo)
}

fn load_repo_mut<'a>(state: &'a mut DevToolsState, project: &str) -> Result<&'a mut DevRepository> {
    if state.repos.contains_key(project) {
        return state
            .repos
            .get_mut(project)
            .context("repo lookup unexpectedly failed");
    }

    let project_id = project
        .parse::<u64>()
        .ok()
        .ok_or_else(|| anyhow!("project not found: {project}"))?;
    let repo_path = state
        .repos
        .iter()
        .find(|(_, repo)| repo.project_id == project_id)
        .map(|(repo_path, _)| repo_path.clone())
        .ok_or_else(|| anyhow!("project not found: {project}"))?;
    state
        .repos
        .get_mut(&repo_path)
        .context("repo lookup unexpectedly failed")
}

fn ensure_active_mr(repo: &DevRepository, iid: u64) -> Result<()> {
    if repo.active_mr.as_ref().is_some_and(|mr| mr.iid == iid) {
        Ok(())
    } else {
        bail!("mr not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_starts_with_default_repositories() {
        let service = DevToolsService::new("/tmp/dev.sqlite");

        let snapshot = service.snapshot().await;

        assert_eq!(snapshot.database_path, "/tmp/dev.sqlite");
        assert_eq!(
            snapshot
                .repos
                .iter()
                .map(|repo| repo.repo_path.as_str())
                .collect::<Vec<_>>(),
            DEFAULT_REPOS
        );
    }

    #[tokio::test]
    async fn simulate_actions_create_and_advance_active_merge_request() -> Result<()> {
        let service = DevToolsService::new("/tmp/dev.sqlite");

        service.create_repo("demo/group/service-z").await?;
        service.simulate_new_mr("demo/group/service-z").await?;
        service.simulate_new_commit("demo/group/service-z").await?;

        let snapshot = service.snapshot().await;
        let repo = snapshot
            .repos
            .into_iter()
            .find(|repo| repo.repo_path == "demo/group/service-z")
            .expect("repo snapshot");
        assert_eq!(repo.active_mr_iid, Some(1));
        assert_eq!(repo.active_revision, Some(2));
        assert!(repo.active_head_sha.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn dynamic_repo_source_reads_runtime_repo_list() -> Result<()> {
        let service = DevToolsService::new("/tmp/dev.sqlite");
        service.create_repo("demo/group/service-z").await?;
        service.delete_repo("demo/group/service-b").await?;

        let repos = DynamicRepoSource::list_repos(&service).await?;

        assert!(repos.contains(&"demo/group/service-a".to_string()));
        assert!(repos.contains(&"demo/group/service-z".to_string()));
        assert!(!repos.contains(&"demo/group/service-b".to_string()));
        Ok(())
    }
}

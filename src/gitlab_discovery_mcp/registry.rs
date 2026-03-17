use super::{GitLabDiscoveryPathEntry, GitLabDiscoveryPathEntryKind};
use crate::config::GitLabDiscoveryAllowRule;
use crate::feature_flags::FeatureFlagSnapshot;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashMap};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLabDiscoverySessionBinding {
    pub run_history_id: i64,
    pub container_id: String,
    pub source_repo: String,
    pub clone_root: String,
    pub feature_flags: FeatureFlagSnapshot,
    pub allow: ResolvedGitLabDiscoveryAllowList,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedGitLabDiscoveryAllowList {
    pub target_repos: BTreeSet<String>,
    pub target_groups: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct RegistryState {
    bindings_by_token: HashMap<String, GitLabDiscoverySessionBinding>,
    tokens_by_session: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct GitLabDiscoverySessionRegistry {
    state: RwLock<RegistryState>,
}

impl GitLabDiscoverySessionRegistry {
    pub async fn register_token(&self, token: String, binding: GitLabDiscoverySessionBinding) {
        self.state
            .write()
            .await
            .bindings_by_token
            .insert(token, binding);
    }

    pub async fn bind_session(&self, token: &str, session_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        if !state.bindings_by_token.contains_key(token) {
            bail!("cannot bind MCP session to unknown token");
        }
        state
            .tokens_by_session
            .insert(session_id.to_string(), token.to_string());
        Ok(())
    }

    pub async fn remove_token(&self, token: &str) {
        let mut state = self.state.write().await;
        state.bindings_by_token.remove(token);
        state
            .tokens_by_session
            .retain(|_, current| current != token);
    }

    pub async fn binding_for_request(
        &self,
        token: &str,
        session_id: Option<&str>,
    ) -> Option<GitLabDiscoverySessionBinding> {
        let state = self.state.read().await;
        let binding = state.bindings_by_token.get(token)?;
        if let Some(session_id) = session_id {
            let bound_token = state.tokens_by_session.get(session_id)?;
            if bound_token != token {
                return None;
            }
        }
        Some(binding.clone())
    }
}

impl ResolvedGitLabDiscoveryAllowList {
    pub fn is_repo_allowed(&self, repo_path: &str) -> bool {
        self.target_repos.contains(repo_path)
            || self
                .target_groups
                .iter()
                .any(|group| repo_within_group(repo_path, group))
    }

    pub fn can_browse_group(&self, group_path: &str) -> bool {
        self.target_groups
            .iter()
            .any(|group| group == group_path || repo_belongs_to_group(group_path, group))
            || self
                .target_repos
                .iter()
                .any(|repo| repo_belongs_to_group(repo, group_path))
    }

    pub fn has_repo_within_group(&self, group_path: &str) -> bool {
        self.target_repos
            .iter()
            .any(|repo| repo_belongs_to_group(repo, group_path))
            || self
                .target_groups
                .iter()
                .any(|group| repo_belongs_to_group(group, group_path))
    }

    pub fn root_entries(&self) -> Vec<GitLabDiscoveryPathEntry> {
        let mut entries = self
            .target_groups
            .iter()
            .map(|path| GitLabDiscoveryPathEntry {
                kind: GitLabDiscoveryPathEntryKind::Group,
                path: path.clone(),
            })
            .chain(
                self.target_repos
                    .iter()
                    .map(|path| GitLabDiscoveryPathEntry {
                        kind: GitLabDiscoveryPathEntryKind::Repo,
                        path: path.clone(),
                    }),
            )
            .collect::<Vec<_>>();
        for repo in &self.target_repos {
            if self
                .target_groups
                .iter()
                .any(|group| repo_belongs_to_group(repo, group))
            {
                continue;
            }
            let Some((top_group, _)) = repo.split_once('/') else {
                continue;
            };
            entries.push(GitLabDiscoveryPathEntry {
                kind: GitLabDiscoveryPathEntryKind::Group,
                path: top_group.to_string(),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path).then(left.kind.cmp(&right.kind)));
        entries.dedup_by(|left, right| left.kind == right.kind && left.path == right.path);
        entries
    }
}

pub fn resolve_allow_list(
    source_repo: &str,
    rules: &[GitLabDiscoveryAllowRule],
) -> ResolvedGitLabDiscoveryAllowList {
    let mut resolved = ResolvedGitLabDiscoveryAllowList::default();
    for rule in rules {
        let repo_match = rule.source_repos.iter().any(|repo| repo == source_repo);
        let group_match = rule
            .source_group_prefixes
            .iter()
            .any(|group| repo_belongs_to_group(source_repo, group));
        if !(repo_match || group_match) {
            continue;
        }
        resolved
            .target_repos
            .extend(rule.target_repos.iter().cloned());
        resolved
            .target_groups
            .extend(rule.target_groups.iter().cloned());
    }
    resolved
}

pub fn generate_bearer_token() -> String {
    Uuid::new_v4().to_string()
}

fn repo_belongs_to_group(path: &str, group: &str) -> bool {
    path == group || path.starts_with(&format!("{group}/"))
}

fn repo_within_group(path: &str, group: &str) -> bool {
    path.starts_with(&format!("{group}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_allow_list_unions_repo_and_group_matches() {
        let resolved = resolve_allow_list(
            "source/group/repo",
            &[
                GitLabDiscoveryAllowRule {
                    source_group_prefixes: vec!["source/group".to_string()],
                    target_groups: vec!["target/root".to_string()],
                    ..Default::default()
                },
                GitLabDiscoveryAllowRule {
                    source_repos: vec!["source/group/repo".to_string()],
                    target_repos: vec!["target/root/app".to_string()],
                    ..Default::default()
                },
            ],
        );

        assert!(resolved.target_groups.contains("target/root"));
        assert!(resolved.target_repos.contains("target/root/app"));
    }

    #[test]
    fn repo_only_allow_rules_still_allow_parent_group_browsing() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from(["company/shared/contracts".to_string()]),
            target_groups: BTreeSet::new(),
        };

        assert!(allow.can_browse_group("company"));
        assert!(allow.can_browse_group("company/shared"));
        assert!(!allow.can_browse_group("company/other"));
        assert_eq!(
            allow.root_entries(),
            vec![
                GitLabDiscoveryPathEntry {
                    kind: GitLabDiscoveryPathEntryKind::Group,
                    path: "company".to_string(),
                },
                GitLabDiscoveryPathEntry {
                    kind: GitLabDiscoveryPathEntryKind::Repo,
                    path: "company/shared/contracts".to_string(),
                },
            ]
        );
    }

    #[test]
    fn group_allow_rules_do_not_treat_group_paths_as_cloneable_repositories() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::new(),
            target_groups: BTreeSet::from(["company/platform".to_string()]),
        };

        assert!(allow.can_browse_group("company/platform"));
        assert!(allow.is_repo_allowed("company/platform/service"));
        assert!(!allow.is_repo_allowed("company/platform"));
    }

    #[tokio::test]
    async fn registry_binds_sessions_to_tokens() -> anyhow::Result<()> {
        let registry = GitLabDiscoverySessionRegistry::default();
        registry
            .register_token(
                "token-1".to_string(),
                GitLabDiscoverySessionBinding {
                    run_history_id: 1,
                    container_id: "container".to_string(),
                    source_repo: "group/repo".to_string(),
                    clone_root: "/work/mcp".to_string(),
                    feature_flags: FeatureFlagSnapshot {
                        gitlab_discovery_mcp: true,
                    },
                    allow: ResolvedGitLabDiscoveryAllowList::default(),
                    created_at: Utc::now(),
                },
            )
            .await;

        assert!(
            registry
                .binding_for_request("token-1", None)
                .await
                .is_some()
        );
        assert!(
            registry
                .binding_for_request("token-1", Some("session-1"))
                .await
                .is_none()
        );

        registry.bind_session("token-1", "session-1").await?;
        assert!(
            registry
                .binding_for_request("token-1", Some("session-1"))
                .await
                .is_some()
        );
        assert!(
            registry
                .binding_for_request("other", Some("session-1"))
                .await
                .is_none()
        );
        Ok(())
    }
}

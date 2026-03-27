use crate::config::GitLabDiscoveryAllowRule;
use crate::feature_flags::FeatureFlagSnapshot;
use anyhow::{Result, bail};
use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashMap};
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLabDiscoverySessionBinding {
    pub run_history_id: i64,
    pub container_id: String,
    pub network_container_id: String,
    pub peer_ips: BTreeSet<String>,
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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GitLabPathListing {
    pub subgroups: Vec<String>,
    pub repositories: Vec<String>,
}

#[derive(Debug, Default)]
struct RegistryState {
    bindings_by_network_container: HashMap<String, GitLabDiscoverySessionBinding>,
    network_containers_by_peer_ip: HashMap<String, String>,
    network_containers_by_session: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct GitLabDiscoverySessionRegistry {
    state: RwLock<RegistryState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLabDiscoveryRegistrySnapshot {
    pub network_container_ids: Vec<String>,
    pub peer_ips: Vec<String>,
    pub session_ids: Vec<String>,
}

impl GitLabDiscoverySessionRegistry {
    pub async fn register_binding(&self, binding: GitLabDiscoverySessionBinding) {
        let mut state = self.state.write().await;
        remove_binding_locked(&mut state, &binding.network_container_id);
        for peer_ip in &binding.peer_ips {
            state
                .network_containers_by_peer_ip
                .insert(peer_ip.clone(), binding.network_container_id.clone());
        }
        state
            .bindings_by_network_container
            .insert(binding.network_container_id.clone(), binding);
    }

    /// # Errors
    ///
    /// Returns an error if the underlying operation fails.
    pub async fn bind_session(&self, network_container_id: &str, session_id: &str) -> Result<()> {
        let mut state = self.state.write().await;
        if !state
            .bindings_by_network_container
            .contains_key(network_container_id)
        {
            bail!("cannot bind MCP session to unknown network container");
        }
        state
            .network_containers_by_session
            .insert(session_id.to_string(), network_container_id.to_string());
        Ok(())
    }

    pub async fn remove_binding(&self, network_container_id: &str) {
        let mut state = self.state.write().await;
        remove_binding_locked(&mut state, network_container_id);
    }

    pub async fn binding_for_peer(&self, peer_ip: &str) -> Option<GitLabDiscoverySessionBinding> {
        let state = self.state.read().await;
        let network_container_id = state.network_containers_by_peer_ip.get(peer_ip)?;
        let binding = state
            .bindings_by_network_container
            .get(network_container_id)?;
        Some(binding.clone())
    }

    pub async fn binding_for_session_and_peer(
        &self,
        session_id: &str,
        peer_ip: &str,
    ) -> Option<GitLabDiscoverySessionBinding> {
        let state = self.state.read().await;
        let network_container_id = state.network_containers_by_session.get(session_id)?;
        let peer_binding = state.network_containers_by_peer_ip.get(peer_ip)?;
        if peer_binding != network_container_id {
            return None;
        }
        let binding = state
            .bindings_by_network_container
            .get(network_container_id)?;
        Some(binding.clone())
    }

    pub async fn snapshot(&self) -> GitLabDiscoveryRegistrySnapshot {
        let state = self.state.read().await;
        let mut network_container_ids = state
            .bindings_by_network_container
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        network_container_ids.sort();
        let mut peer_ips = state
            .network_containers_by_peer_ip
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        peer_ips.sort();
        let mut session_ids = state
            .network_containers_by_session
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        session_ids.sort();
        GitLabDiscoveryRegistrySnapshot {
            network_container_ids,
            peer_ips,
            session_ids,
        }
    }
}

fn remove_binding_locked(state: &mut RegistryState, network_container_id: &str) {
    let Some(binding) = state
        .bindings_by_network_container
        .remove(network_container_id)
    else {
        state
            .network_containers_by_session
            .retain(|_, current| current != network_container_id);
        return;
    };
    for peer_ip in binding.peer_ips {
        if state
            .network_containers_by_peer_ip
            .get(&peer_ip)
            .map(String::as_str)
            == Some(network_container_id)
        {
            state.network_containers_by_peer_ip.remove(&peer_ip);
        }
    }
    state
        .network_containers_by_session
        .retain(|_, current| current != network_container_id);
}

impl ResolvedGitLabDiscoveryAllowList {
    #[must_use]
    pub fn is_repo_allowed(&self, repo_path: &str) -> bool {
        self.target_repos.contains(repo_path)
            || self
                .target_groups
                .iter()
                .any(|group| repo_within_group(repo_path, group))
    }

    #[must_use]
    pub fn can_browse_group(&self, group_path: &str) -> bool {
        self.target_groups.iter().any(|group| {
            group == group_path
                || repo_belongs_to_group(group_path, group)
                || repo_belongs_to_group(group, group_path)
        }) || self
            .target_repos
            .iter()
            .any(|repo| repo_belongs_to_group(repo, group_path))
    }

    #[must_use]
    pub fn has_repo_within_group(&self, group_path: &str) -> bool {
        self.target_repos
            .iter()
            .any(|repo| repo_belongs_to_group(repo, group_path))
            || self
                .target_groups
                .iter()
                .any(|group| repo_belongs_to_group(group, group_path))
    }

    pub fn listing_for_path(&self, path: Option<&str>) -> Option<GitLabPathListing> {
        let current_path = path.map(str::trim).filter(|value| !value.is_empty());
        match current_path {
            None => Some(self.projected_children(None)),
            Some(path) if self.target_repos.contains(path) => Some(GitLabPathListing::default()),
            Some(path) if self.can_browse_group(path) => Some(self.projected_children(Some(path))),
            Some(_) => None,
        }
    }

    fn projected_children(&self, current_path: Option<&str>) -> GitLabPathListing {
        let mut subgroups = BTreeSet::new();
        let mut repositories = BTreeSet::new();

        for group in &self.target_groups {
            match current_path {
                None => {
                    subgroups.insert(group.clone());
                }
                Some(_) => {
                    if let Some(child) = immediate_child_path(current_path, group) {
                        subgroups.insert(child);
                    }
                }
            }
        }

        for repo in &self.target_repos {
            if self
                .target_groups
                .iter()
                .any(|group| repo_within_group(repo, group))
            {
                continue;
            }
            let Some(child) = immediate_child_path(current_path, repo) else {
                continue;
            };
            if child == *repo {
                repositories.insert(child);
            } else {
                subgroups.insert(child);
            }
        }

        GitLabPathListing::new(subgroups, repositories)
    }
}

impl GitLabPathListing {
    pub fn new(
        subgroups: impl IntoIterator<Item = String>,
        repositories: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut subgroups = subgroups.into_iter().collect::<Vec<_>>();
        subgroups.sort();
        subgroups.dedup();

        let mut repositories = repositories.into_iter().collect::<Vec<_>>();
        repositories.sort();
        repositories.dedup();

        Self {
            subgroups,
            repositories,
        }
    }
}

#[must_use]
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

fn repo_belongs_to_group(path: &str, group: &str) -> bool {
    path == group || path.starts_with(&format!("{group}/"))
}

fn repo_within_group(path: &str, group: &str) -> bool {
    path.starts_with(&format!("{group}/"))
}

fn immediate_child_path(current_path: Option<&str>, target_path: &str) -> Option<String> {
    match current_path {
        None => target_path
            .split_once('/')
            .map(|(segment, _)| segment.to_string())
            .or_else(|| Some(target_path.to_string())),
        Some(path) => {
            if target_path == path || !repo_within_group(target_path, path) {
                return None;
            }
            let remainder = target_path.strip_prefix(&format!("{path}/"))?;
            let next_segment = remainder.split('/').next()?;
            Some(format!("{path}/{next_segment}"))
        }
    }
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
            allow.listing_for_path(None),
            Some(GitLabPathListing {
                subgroups: vec!["company".to_string()],
                repositories: Vec::new(),
            })
        );
        assert_eq!(
            allow.listing_for_path(Some("company")),
            Some(GitLabPathListing {
                subgroups: vec!["company/shared".to_string()],
                repositories: Vec::new(),
            })
        );
        assert_eq!(
            allow.listing_for_path(Some("company/shared")),
            GitLabPathListing {
                subgroups: Vec::new(),
                repositories: vec!["company/shared/contracts".to_string()],
            }
            .into()
        );
    }

    #[test]
    fn group_allow_rules_do_not_treat_group_paths_as_cloneable_repositories() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::new(),
            target_groups: BTreeSet::from(["company/platform".to_string()]),
        };

        assert!(allow.can_browse_group("company"));
        assert!(allow.can_browse_group("company/platform"));
        assert!(allow.is_repo_allowed("company/platform/service"));
        assert!(!allow.is_repo_allowed("company/platform"));
        assert_eq!(
            allow.listing_for_path(None),
            GitLabPathListing {
                subgroups: vec!["company/platform".to_string()],
                repositories: Vec::new(),
            }
            .into()
        );
    }

    #[test]
    fn root_listing_collapses_nested_groups_to_immediate_children() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from([
                "company/apps/console".to_string(),
                "company/shared/contracts".to_string(),
            ]),
            target_groups: BTreeSet::from([
                "company/platform".to_string(),
                "vendor/security".to_string(),
            ]),
        };

        assert_eq!(
            allow.listing_for_path(None),
            GitLabPathListing {
                subgroups: vec![
                    "company".to_string(),
                    "company/platform".to_string(),
                    "vendor/security".to_string(),
                ],
                repositories: Vec::new(),
            }
            .into()
        );
        assert_eq!(
            allow.listing_for_path(Some("company")),
            Some(GitLabPathListing {
                subgroups: vec![
                    "company/apps".to_string(),
                    "company/platform".to_string(),
                    "company/shared".to_string(),
                ],
                repositories: Vec::new(),
            })
        );
    }

    #[test]
    fn target_group_descendants_do_not_leak_repo_leaves_into_root_projection() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from([
                "example-org/placeholder-service-a".to_string(),
                "example-org/placeholder-service-b".to_string(),
            ]),
            target_groups: BTreeSet::from(["example-org".to_string()]),
        };

        assert_eq!(
            allow.listing_for_path(None),
            Some(GitLabPathListing {
                subgroups: vec!["example-org".to_string()],
                repositories: Vec::new(),
            })
        );
        assert_eq!(
            allow.listing_for_path(Some("example-org")),
            Some(GitLabPathListing::default())
        );
    }

    #[tokio::test]
    async fn registry_binds_sessions_to_network_container_and_peer_ip() -> anyhow::Result<()> {
        let registry = GitLabDiscoverySessionRegistry::default();
        registry
            .register_binding(GitLabDiscoverySessionBinding {
                run_history_id: 1,
                container_id: "container".to_string(),
                network_container_id: "network-container".to_string(),
                peer_ips: BTreeSet::from(["172.17.0.2".to_string()]),
                source_repo: "group/repo".to_string(),
                clone_root: "/work/mcp".to_string(),
                feature_flags: FeatureFlagSnapshot {
                    gitlab_discovery_mcp: true,
                    gitlab_inline_review_comments: false,
                    composer_install: false,
                    composer_auto_repositories: false,
                    composer_safe_install: false,
                    security_review: false,
                    security_context_ignore_base_head: false,
                },
                allow: ResolvedGitLabDiscoveryAllowList::default(),
                created_at: Utc::now(),
            })
            .await;

        assert!(registry.binding_for_peer("172.17.0.2").await.is_some());
        assert!(
            registry
                .binding_for_session_and_peer("session-1", "172.17.0.2")
                .await
                .is_none()
        );

        registry
            .bind_session("network-container", "session-1")
            .await?;
        assert!(
            registry
                .binding_for_session_and_peer("session-1", "172.17.0.2")
                .await
                .is_some()
        );
        assert!(
            registry
                .binding_for_session_and_peer("session-1", "172.17.0.3")
                .await
                .is_none()
        );
        registry.remove_binding("network-container").await;
        assert!(registry.binding_for_peer("172.17.0.2").await.is_none());
        Ok(())
    }
}

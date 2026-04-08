use super::{DynamicRepoSource, ScanMode};
use crate::config::Config;
use crate::gitlab::GitLabApi;
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{debug, warn};

#[async_trait]
pub(crate) trait TargetResolver: Send + Sync {
    fn set_dynamic_repo_source(&mut self, dynamic_repo_source: Arc<dyn DynamicRepoSource>);

    async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>>;
}

pub(crate) struct DefaultTargetResolver {
    config: Config,
    gitlab: Arc<dyn GitLabApi>,
    state: Arc<ReviewStateStore>,
    dynamic_repo_source: Option<Arc<dyn DynamicRepoSource>>,
}

impl DefaultTargetResolver {
    pub(crate) fn new(
        config: Config,
        gitlab: Arc<dyn GitLabApi>,
        state: Arc<ReviewStateStore>,
    ) -> Self {
        Self {
            config,
            gitlab,
            state,
            dynamic_repo_source: None,
        }
    }

    async fn resolve_all_targets(&self, mode: ScanMode) -> Result<Vec<String>> {
        let cache_key = self.config.gitlab.targets.cache_key_for_all();
        self.resolve_discovered_targets(
            mode,
            || async {
                let projects = self.gitlab.list_projects().await?;
                Ok(projects
                    .into_iter()
                    .map(|project| project.path_with_namespace)
                    .collect())
            },
            cache_key,
        )
        .await
    }

    async fn resolve_group_targets(&self, mode: ScanMode) -> Result<Vec<String>> {
        let groups = &self.config.gitlab.targets.groups;
        if groups.list().is_empty() {
            return Ok(Vec::new());
        }
        let cache_key = self.config.gitlab.targets.cache_key_for_groups();
        self.resolve_discovered_targets(
            mode,
            || async {
                let mut deduped = HashSet::new();
                for group in groups.list() {
                    let projects = self.gitlab.list_group_projects(group).await?;
                    for project in projects {
                        deduped.insert(project.path_with_namespace);
                    }
                }
                Ok(deduped.into_iter().collect())
            },
            cache_key,
        )
        .await
    }

    async fn resolve_discovered_targets<F, Fut>(
        &self,
        mode: ScanMode,
        fetch: F,
        cache_key: String,
    ) -> Result<Vec<String>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<String>>>,
    {
        let cached = self
            .state
            .project_catalog
            .load_project_catalog(&cache_key)
            .await?;
        let force_refresh = matches!(mode, ScanMode::Full);
        if let Some(cache) = cached.as_ref() {
            let refresh_seconds = self.config.gitlab.targets.refresh_seconds;
            if !force_refresh
                && refresh_seconds > 0
                && Utc::now().timestamp() - cache.fetched_at < refresh_seconds as i64
            {
                debug!(
                    cache_key = cache_key.as_str(),
                    count = cache.projects.len(),
                    "using cached project catalog"
                );
                return Ok(cache.projects.clone());
            }
        }
        match fetch().await {
            Ok(mut projects) => {
                projects.sort();
                projects.dedup();
                self.state
                    .project_catalog
                    .save_project_catalog(&cache_key, &projects)
                    .await?;
                Ok(projects)
            }
            Err(err) => {
                if let Some(cache) = cached {
                    warn!(
                        cache_key = cache_key.as_str(),
                        error = %err,
                        "failed to refresh project catalog; using cached list"
                    );
                    Ok(cache.projects)
                } else {
                    Err(err)
                }
            }
        }
    }
}

#[async_trait]
impl TargetResolver for DefaultTargetResolver {
    fn set_dynamic_repo_source(&mut self, dynamic_repo_source: Arc<dyn DynamicRepoSource>) {
        self.dynamic_repo_source = Some(dynamic_repo_source);
    }

    async fn resolve_repos(&self, mode: ScanMode) -> Result<Vec<String>> {
        if let Some(dynamic_repo_source) = self.dynamic_repo_source.as_ref() {
            let mut repos = dynamic_repo_source.list_repos().await?;
            repos.sort();
            repos.dedup();
            return Ok(repos);
        }

        let targets = &self.config.gitlab.targets;
        let include_all = targets.repos.is_all() || targets.groups.is_all();
        let mut included = HashSet::new();
        if include_all {
            for repo in self.resolve_all_targets(mode).await? {
                included.insert(repo);
            }
        } else {
            for repo in targets.repos.list() {
                included.insert(repo.clone());
            }
            if !targets.groups.list().is_empty() {
                for repo in self.resolve_group_targets(mode).await? {
                    included.insert(repo);
                }
            }
        }

        if included.is_empty() {
            return Ok(Vec::new());
        }

        let exclude_repos: HashSet<&str> =
            targets.exclude_repos.iter().map(String::as_str).collect();
        let exclude_group_prefixes: Vec<String> = targets
            .exclude_groups
            .iter()
            .map(|group| group.trim_end_matches('/'))
            .filter(|group| !group.is_empty())
            .map(|group| format!("{group}/"))
            .collect();

        let mut repos: Vec<String> = included
            .into_iter()
            .filter(|repo| {
                if exclude_repos.contains(repo.as_str()) {
                    return false;
                }
                if exclude_group_prefixes
                    .iter()
                    .any(|prefix| repo.starts_with(prefix))
                {
                    return false;
                }
                true
            })
            .collect();
        repos.sort();
        Ok(repos)
    }
}

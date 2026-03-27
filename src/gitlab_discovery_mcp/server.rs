use super::service::mcp_internal_error;
use super::{
    CloneGitLabRepoRequest, CloneGitLabRepoResponse, GitLabDiscoveryMcpService,
    GitLabDiscoverySessionBinding, GitLabPathListing, InspectGitLabRepoRequest,
    InspectGitLabRepoResponse, ListGitLabPathsRequest, ListGitLabPathsResponse,
    ResolvedGitLabDiscoveryAllowList,
};
use crate::gitlab::{GitLabApi, gitlab_error_has_status};
use anyhow::Result;
use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use rmcp::handler::server::{router::tool::ToolRouter, tool::Extension, wrapper::Parameters};
use rmcp::model::{ServerCapabilities, ServerInfo};
use rmcp::transport::streamable_http_server::{
    StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
};
use rmcp::{
    ErrorData as McpError, Json as McpJson, ServerHandler, tool, tool_handler, tool_router,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tracing::warn;

#[derive(Clone)]
struct GitLabDiscoveryMcpServer {
    tool_router: ToolRouter<Self>,
    service: Arc<GitLabDiscoveryMcpService>,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for GitLabDiscoveryMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build()).with_instructions(
            "Browse allowed GitLab paths. Call list_gitlab_paths without a path first to see top-level accessible groups, then call it again with a returned subgroup path to navigate deeper. Each response separates subgroup paths from repository paths. Use inspect_gitlab_repo to inspect an allowed repository and list its branches and tags without cloning. Use clone_gitlab_repo to clone an allowed repository into the current Codex container. Pass checkout_ref for branch or tag checkout, or commit_sha for a detached commit checkout.",
        )
    }
}

#[tool_router]
impl GitLabDiscoveryMcpServer {
    #[tool(
        name = "list_gitlab_paths",
        description = "List the immediate child subgroups and repositories visible from the requested GitLab path. Omit path to list top-level accessible groups. The response returns separate subgroup and repository arrays."
    )]
    async fn list_gitlab_paths(
        &self,
        Parameters(request): Parameters<ListGitLabPathsRequest>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<McpJson<ListGitLabPathsResponse>, McpError> {
        let binding = Self::binding_from_parts(&parts)?;
        let current_path = request
            .path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let listing =
            browse_listing_for_path(&self.service.gitlab, &binding.allow, current_path).await?;

        Ok(McpJson(ListGitLabPathsResponse {
            current_path: current_path.map(ToOwned::to_owned),
            subgroups: listing.subgroups,
            repositories: listing.repositories,
        }))
    }

    #[tool(
        name = "inspect_gitlab_repo",
        description = "Inspect an allowed GitLab repository without cloning it. Returns repository metadata plus all branch and tag names visible from GitLab."
    )]
    async fn inspect_gitlab_repo(
        &self,
        Parameters(request): Parameters<InspectGitLabRepoRequest>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<McpJson<InspectGitLabRepoResponse>, McpError> {
        let binding = Self::binding_from_parts(&parts)?;
        let repo_path = validated_repo_path(&request.repo_path)?;
        let response =
            inspect_repo_for_path(&self.service.gitlab, &binding.allow, repo_path).await?;

        Ok(McpJson(response))
    }

    #[tool(
        name = "clone_gitlab_repo",
        description = "Clone an allowed GitLab repository into the current Codex container and return the local path plus available branches and tags. Use checkout_ref for a branch or tag, or commit_sha for a detached checkout by commit SHA."
    )]
    async fn clone_gitlab_repo(
        &self,
        Parameters(request): Parameters<CloneGitLabRepoRequest>,
        Extension(parts): Extension<axum::http::request::Parts>,
    ) -> Result<McpJson<CloneGitLabRepoResponse>, McpError> {
        let binding = Self::binding_from_parts(&parts)?;
        let repo_path = validated_repo_path(&request.repo_path)?;
        ensure_allowed_repo_path(&binding.allow, repo_path)?;

        let path = self
            .service
            .clone_repository(&binding, repo_path)
            .await
            .map_err(mcp_internal_error)?;
        let branches = self
            .service
            .list_remote_branches(&binding.container_id, &path)
            .await
            .map_err(mcp_internal_error)?;
        let tags = self
            .service
            .list_tags(&binding.container_id, &path)
            .await
            .map_err(mcp_internal_error)?;
        let default_branch = self
            .service
            .default_branch(&binding.container_id, &path)
            .await
            .map_err(mcp_internal_error)?;
        let checkout_ref = request
            .checkout_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let commit_sha = request
            .commit_sha
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let (checked_out_ref, checked_out_kind) = if checkout_ref.is_none() && commit_sha.is_none()
        {
            (default_branch.clone(), super::GitLabCheckoutKind::Branch)
        } else {
            self.service
                .checkout_target(
                    &binding.container_id,
                    super::service::CheckoutTargetRequest {
                        repo_path: &path,
                        gitlab_repo_path: repo_path,
                        checkout_ref,
                        commit_sha,
                        branches: &branches,
                        tags: &tags,
                    },
                )
                .await
                .map_err(mcp_internal_error)?
        };
        let composer_install = self
            .service
            .run_composer_install(&binding, &path, repo_path)
            .await;
        let head_sha = self
            .service
            .head_sha(&binding.container_id, &path)
            .await
            .map_err(mcp_internal_error)?;

        Ok(McpJson(CloneGitLabRepoResponse {
            path,
            head_sha,
            default_branch,
            checked_out_ref,
            checked_out_kind,
            branches,
            tags,
            composer_install,
        }))
    }
}

fn validated_repo_path(repo_path: &str) -> Result<&str, McpError> {
    let repo_path = repo_path.trim();
    if repo_path.is_empty() {
        return Err(McpError::invalid_params(
            "repo_path must not be empty",
            None,
        ));
    }
    Ok(repo_path)
}

fn ensure_allowed_repo_path(
    allow: &ResolvedGitLabDiscoveryAllowList,
    repo_path: &str,
) -> Result<(), McpError> {
    if allow.is_repo_allowed(repo_path) {
        Ok(())
    } else {
        Err(McpError::resource_not_found(
            format!("GitLab repo is not allowed for this run: {repo_path}"),
            None,
        ))
    }
}

async fn inspect_repo_for_path(
    gitlab: &impl GitLabApi,
    allow: &ResolvedGitLabDiscoveryAllowList,
    repo_path: &str,
) -> Result<InspectGitLabRepoResponse, McpError> {
    ensure_allowed_repo_path(allow, repo_path)?;

    let project = gitlab
        .get_project(repo_path)
        .await
        .map_err(|err| map_repo_lookup_error(repo_path, err))?;
    let branches = gitlab
        .list_repository_branches(repo_path)
        .await
        .map(sorted_unique_names)
        .map_err(|err| map_repo_lookup_error(repo_path, err))?;
    let tags = gitlab
        .list_repository_tags(repo_path)
        .await
        .map(sorted_unique_names)
        .map_err(|err| map_repo_lookup_error(repo_path, err))?;

    Ok(InspectGitLabRepoResponse {
        repo_path: project
            .path_with_namespace
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| repo_path.to_string()),
        web_url: project.web_url,
        default_branch: project.default_branch,
        branches,
        tags,
    })
}

async fn browse_listing_for_path(
    gitlab: &impl GitLabApi,
    allow: &ResolvedGitLabDiscoveryAllowList,
    current_path: Option<&str>,
) -> Result<GitLabPathListing, McpError> {
    let Some(projected) = allow.listing_for_path(current_path) else {
        let path = current_path.unwrap_or_default();
        return Err(McpError::resource_not_found(
            format!("GitLab path is not allowed for this run: {path}"),
            None,
        ));
    };

    let Some(path) = current_path else {
        return Ok(projected);
    };

    let group = match gitlab.get_group(path).await {
        Ok(group) => group,
        Err(err) => {
            if gitlab_error_has_status(&err, &[404]) {
                return Ok(projected);
            }
            return Err(mcp_internal_error(err));
        }
    };
    if group.archived || group.marked_for_deletion_on.is_some() {
        return Ok(GitLabPathListing::default());
    }

    let mut subgroups = Vec::new();
    for subgroup in gitlab
        .list_group_subgroups(path)
        .await
        .map_err(mcp_internal_error)?
    {
        if allow.can_browse_group(&subgroup.full_path)
            || allow.has_repo_within_group(&subgroup.full_path)
        {
            subgroups.push(subgroup.full_path);
        }
    }

    let mut repositories = Vec::new();
    for project in gitlab
        .list_direct_group_projects(path)
        .await
        .map_err(mcp_internal_error)?
    {
        if allow.is_repo_allowed(&project.path_with_namespace) {
            repositories.push(project.path_with_namespace);
        }
    }

    Ok(GitLabPathListing::new(subgroups, repositories))
}

fn sorted_unique_names(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn map_repo_lookup_error(repo_path: &str, err: anyhow::Error) -> McpError {
    if gitlab_error_has_status(&err, &[404]) {
        McpError::resource_not_found(format!("GitLab repo not found: {repo_path}"), None)
    } else {
        mcp_internal_error(err)
    }
}

impl GitLabDiscoveryMcpServer {
    fn binding_from_parts(
        parts: &axum::http::request::Parts,
    ) -> Result<GitLabDiscoverySessionBinding, McpError> {
        parts
            .extensions
            .get::<GitLabDiscoverySessionBinding>()
            .cloned()
            .ok_or_else(|| McpError::resource_not_found("MCP session binding not found", None))
    }
}

pub(crate) fn build_router(service: &Arc<GitLabDiscoveryMcpService>) -> Router {
    let server = GitLabDiscoveryMcpServer {
        tool_router: GitLabDiscoveryMcpServer::tool_router(),
        service: Arc::clone(&service),
    };
    let rmcp_service: StreamableHttpService<GitLabDiscoveryMcpServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            StreamableHttpServerConfig::default(),
        );

    let protected_mcp =
        Router::new()
            .fallback_service(rmcp_service)
            .layer(middleware::from_fn_with_state(
                service.registry(),
                authenticate_mcp_request,
            ));

    Router::new()
        .route("/healthz", get(|| async { "OK" }))
        .nest("/mcp", protected_mcp)
}

async fn authenticate_mcp_request(
    State(registry): State<Arc<super::GitLabDiscoverySessionRegistry>>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let peer_ip = canonical_peer_ip(peer_addr.ip());
    let incoming_session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let binding = if let Some(session_id) = incoming_session_id.as_deref() {
        registry
            .binding_for_session_and_peer(session_id, &peer_ip)
            .await
    } else {
        registry.binding_for_peer(&peer_ip).await
    };
    let Some(binding) = binding else {
        let snapshot = registry.snapshot().await;
        warn!(
            peer_ip,
            session_id = incoming_session_id.as_deref().unwrap_or("<none>"),
            registered_peer_ips = snapshot.peer_ips.join(","),
            registered_network_containers = snapshot.network_container_ids.join(","),
            "gitlab discovery MCP request did not match any registered session"
        );
        let status = if incoming_session_id.is_some() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        return (status, "MCP session is not authorized").into_response();
    };

    request.extensions_mut().insert(binding.clone());

    let response = next.run(request).await;
    if incoming_session_id.is_none()
        && let Some(session_id) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        && let Err(err) = registry
            .bind_session(&binding.network_container_id, session_id)
            .await
    {
        warn!(
            error = %err,
            session_id,
            peer_ip,
            network_container_id = binding.network_container_id.as_str(),
            "failed to bind MCP session to gitlab discovery peer identity"
        );
    }
    response
}

fn canonical_peer_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| v6.to_string(), |mapped| mapped.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GitLabDiscoveryMcpServer, browse_listing_for_path, build_router, inspect_repo_for_path,
    };
    use crate::config::{DockerConfig, GitLabConfig, GitLabDiscoveryMcpConfig, GitLabTargets};
    use crate::gitlab::{
        AwardEmoji, GitLabApi, GitLabGroup, GitLabGroupSummary, GitLabProject,
        GitLabProjectSummary, GitLabUser, MergeRequest, Note,
    };
    use crate::gitlab_discovery_mcp::{
        InspectGitLabRepoResponse, ResolvedGitLabDiscoveryAllowList,
    };
    use anyhow::Result;
    use async_trait::async_trait;
    use rmcp::model::ErrorCode;
    use std::collections::{BTreeMap, BTreeSet};
    use std::sync::Arc;

    #[test]
    fn build_router_does_not_panic() {
        let service = crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig::default(),
            &GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: None,
                created_after: None,
                targets: GitLabTargets::default(),
            },
            GitLabDiscoveryMcpConfig::default(),
        )
        .expect("service");
        let service = Arc::new(service);
        let _router = build_router(&service);
    }

    #[test]
    fn tool_router_includes_inspect_gitlab_repo() {
        let tools = GitLabDiscoveryMcpServer::tool_router().list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();

        assert!(names.contains(&"inspect_gitlab_repo"));
    }

    #[derive(Default)]
    struct FakeGitLab {
        groups: BTreeSet<String>,
        subgroups: BTreeMap<String, Vec<GitLabGroupSummary>>,
        projects: BTreeMap<String, Vec<GitLabProjectSummary>>,
        project_details: BTreeMap<String, GitLabProject>,
        branches: BTreeMap<String, Vec<String>>,
        tags: BTreeMap<String, Vec<String>>,
    }

    #[async_trait]
    impl GitLabApi for FakeGitLab {
        async fn current_user(&self) -> Result<GitLabUser> {
            unimplemented!()
        }

        async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
            unimplemented!()
        }

        async fn list_group_projects(&self, _group: &str) -> Result<Vec<GitLabProjectSummary>> {
            unimplemented!()
        }

        async fn list_direct_group_projects(
            &self,
            group: &str,
        ) -> Result<Vec<GitLabProjectSummary>> {
            Ok(self.projects.get(group).cloned().unwrap_or_default())
        }

        async fn list_group_subgroups(&self, group: &str) -> Result<Vec<GitLabGroupSummary>> {
            Ok(self.subgroups.get(group).cloned().unwrap_or_default())
        }

        async fn list_open_mrs(&self, _project: &str) -> Result<Vec<MergeRequest>> {
            unimplemented!()
        }

        async fn get_latest_open_mr_activity(
            &self,
            _project: &str,
        ) -> Result<Option<MergeRequest>> {
            unimplemented!()
        }

        async fn get_mr(&self, _project: &str, _iid: u64) -> Result<MergeRequest> {
            unimplemented!()
        }

        async fn get_project(&self, project: &str) -> Result<GitLabProject> {
            if self.groups.contains(project) {
                anyhow::bail!("gitlab GET fake response: status=404 Not Found body=not found");
            }
            Ok(self
                .project_details
                .get(project)
                .cloned()
                .unwrap_or(GitLabProject {
                    path_with_namespace: Some(project.to_string()),
                    web_url: None,
                    default_branch: None,
                    last_activity_at: None,
                }))
        }

        async fn get_group(&self, group: &str) -> Result<GitLabGroup> {
            if !self.groups.contains(group) {
                anyhow::bail!("gitlab GET fake response: status=404 Not Found body=not found");
            }
            Ok(GitLabGroup {
                full_path: group.to_string(),
                archived: false,
                marked_for_deletion_on: None,
            })
        }

        async fn list_awards(&self, _project: &str, _iid: u64) -> Result<Vec<AwardEmoji>> {
            unimplemented!()
        }

        async fn add_award(&self, _project: &str, _iid: u64, _name: &str) -> Result<()> {
            unimplemented!()
        }

        async fn delete_award(&self, _project: &str, _iid: u64, _award_id: u64) -> Result<()> {
            unimplemented!()
        }

        async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<Note>> {
            unimplemented!()
        }

        async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
            unimplemented!()
        }

        async fn list_repository_branches(&self, project: &str) -> Result<Vec<String>> {
            Ok(self.branches.get(project).cloned().unwrap_or_default())
        }

        async fn list_repository_tags(&self, project: &str) -> Result<Vec<String>> {
            Ok(self.tags.get(project).cloned().unwrap_or_default())
        }
    }

    #[tokio::test]
    async fn browse_listing_returns_live_children_for_group_descendants() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::new(),
            target_groups: BTreeSet::from(["example-org".to_string()]),
        };
        let gitlab = FakeGitLab {
            groups: BTreeSet::from([
                "example-org".to_string(),
                "example-org/platform".to_string(),
            ]),
            projects: BTreeMap::from([(
                "example-org/platform".to_string(),
                vec![GitLabProjectSummary {
                    path_with_namespace: "example-org/platform/placeholder-service".to_string(),
                    archived: false,
                    marked_for_deletion_on: None,
                    marked_for_deletion_at: None,
                }],
            )]),
            ..Default::default()
        };

        let listing = browse_listing_for_path(&gitlab, &allow, Some("example-org/platform"))
            .await
            .expect("listing");

        assert_eq!(
            listing,
            crate::gitlab_discovery_mcp::GitLabPathListing {
                subgroups: Vec::new(),
                repositories: vec!["example-org/platform/placeholder-service".to_string()],
            }
        );
    }

    #[tokio::test]
    async fn browse_listing_keeps_projected_children_when_parent_group_lookup_is_missing() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from(["alice/tooling".to_string()]),
            target_groups: BTreeSet::new(),
        };
        let gitlab = FakeGitLab::default();

        let listing = browse_listing_for_path(&gitlab, &allow, Some("alice"))
            .await
            .expect("listing");

        assert_eq!(
            listing,
            crate::gitlab_discovery_mcp::GitLabPathListing {
                subgroups: Vec::new(),
                repositories: vec!["alice/tooling".to_string()],
            }
        );
    }

    #[tokio::test]
    async fn inspect_repo_returns_metadata_and_refs_for_allowed_repo() {
        let allow = ResolvedGitLabDiscoveryAllowList {
            target_repos: BTreeSet::from(["example-org/platform/placeholder-service".to_string()]),
            target_groups: BTreeSet::new(),
        };
        let gitlab = FakeGitLab {
            project_details: BTreeMap::from([(
                "example-org/platform/placeholder-service".to_string(),
                GitLabProject {
                    path_with_namespace: Some(
                        "example-org/platform/placeholder-service".to_string(),
                    ),
                    web_url: Some(
                        "https://gitlab.example.com/example-org/platform/placeholder-service"
                            .to_string(),
                    ),
                    default_branch: Some("main".to_string()),
                    last_activity_at: Some("2025-01-01T00:00:00Z".to_string()),
                },
            )]),
            branches: BTreeMap::from([(
                "example-org/platform/placeholder-service".to_string(),
                vec![
                    "release".to_string(),
                    "main".to_string(),
                    "main".to_string(),
                ],
            )]),
            tags: BTreeMap::from([(
                "example-org/platform/placeholder-service".to_string(),
                vec!["v2.0.0".to_string(), "v1.0.0".to_string()],
            )]),
            ..Default::default()
        };

        let inspection =
            inspect_repo_for_path(&gitlab, &allow, "example-org/platform/placeholder-service")
                .await
                .expect("inspection");

        assert_eq!(
            inspection,
            InspectGitLabRepoResponse {
                repo_path: "example-org/platform/placeholder-service".to_string(),
                web_url: Some(
                    "https://gitlab.example.com/example-org/platform/placeholder-service"
                        .to_string(),
                ),
                default_branch: Some("main".to_string()),
                branches: vec!["main".to_string(), "release".to_string()],
                tags: vec!["v1.0.0".to_string(), "v2.0.0".to_string()],
            }
        );
    }

    #[tokio::test]
    async fn inspect_repo_rejects_disallowed_repo() {
        let allow = ResolvedGitLabDiscoveryAllowList::default();
        let gitlab = FakeGitLab::default();

        let err = inspect_repo_for_path(&gitlab, &allow, "example-org/private")
            .await
            .expect_err("disallowed repo must fail");

        assert_eq!(err.code, ErrorCode::RESOURCE_NOT_FOUND);
    }
}

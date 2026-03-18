use super::service::mcp_internal_error;
use super::{
    CloneGitLabRepoRequest, CloneGitLabRepoResponse, GitLabDiscoveryMcpService,
    GitLabDiscoverySessionBinding, GitLabPathListing, ListGitLabPathsRequest,
    ListGitLabPathsResponse,
};
use crate::gitlab::GitLabApi;
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
            "Browse allowed GitLab paths. Call list_gitlab_paths without a path first to see top-level accessible groups, then call it again with a returned subgroup path to navigate deeper. Each response separates subgroup paths from repository paths. Use clone_gitlab_repo to clone an allowed repository into the current Codex container. Pass checkout_ref for branch or tag checkout, or commit_sha for a detached commit checkout.",
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
        let binding = self.binding_from_parts(&parts).await?;
        let current_path = request
            .path
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());

        let listing = match current_path {
            None => binding.allow.root_listing(),
            Some(path) => {
                if binding.allow.is_repo_allowed(path) {
                    GitLabPathListing::default()
                } else if binding.allow.can_browse_group(path) {
                    let mut subgroups = Vec::new();
                    for group in self
                        .service
                        .gitlab
                        .list_group_subgroups(path)
                        .await
                        .map_err(mcp_internal_error)?
                    {
                        if binding.allow.can_browse_group(&group.full_path)
                            || binding.allow.has_repo_within_group(&group.full_path)
                        {
                            subgroups.push(group.full_path);
                        }
                    }
                    let mut repositories = Vec::new();
                    for project in self
                        .service
                        .gitlab
                        .list_direct_group_projects(path)
                        .await
                        .map_err(mcp_internal_error)?
                    {
                        if binding.allow.is_repo_allowed(&project.path_with_namespace) {
                            repositories.push(project.path_with_namespace);
                        }
                    }
                    GitLabPathListing::new(subgroups, repositories)
                } else {
                    return Err(McpError::resource_not_found(
                        format!("GitLab path is not allowed for this run: {path}"),
                        None,
                    ));
                }
            }
        };

        Ok(McpJson(ListGitLabPathsResponse {
            current_path: current_path.map(ToOwned::to_owned),
            subgroups: listing.subgroups,
            repositories: listing.repositories,
        }))
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
        let binding = self.binding_from_parts(&parts).await?;
        let repo_path = request.repo_path.trim();
        if repo_path.is_empty() {
            return Err(McpError::invalid_params(
                "repo_path must not be empty",
                None,
            ));
        }
        if !binding.allow.is_repo_allowed(repo_path) {
            return Err(McpError::resource_not_found(
                format!("GitLab repo is not allowed for this run: {repo_path}"),
                None,
            ));
        }

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
        }))
    }
}

impl GitLabDiscoveryMcpServer {
    async fn binding_from_parts(
        &self,
        parts: &axum::http::request::Parts,
    ) -> Result<GitLabDiscoverySessionBinding, McpError> {
        parts
            .extensions
            .get::<GitLabDiscoverySessionBinding>()
            .cloned()
            .ok_or_else(|| McpError::resource_not_found("MCP session binding not found", None))
    }
}

pub(crate) fn build_router(service: Arc<GitLabDiscoveryMcpService>) -> Router {
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
            .map(|mapped| mapped.to_string())
            .unwrap_or_else(|| v6.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::build_router;
    use crate::config::{DockerConfig, GitLabConfig, GitLabDiscoveryMcpConfig, GitLabTargets};
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
        let _router = build_router(Arc::new(service));
    }
}

use super::service::mcp_internal_error;
use super::{
    CloneGitLabRepoRequest, CloneGitLabRepoResponse, GitLabDiscoveryMcpService,
    GitLabDiscoveryPathEntry, GitLabDiscoveryPathEntryKind, GitLabDiscoverySessionBinding,
    ListGitLabPathsRequest, ListGitLabPathsResponse,
};
use crate::gitlab::GitLabApi;
use anyhow::Result;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
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
            "Browse allowed GitLab groups and clone allowed repositories into the current Codex container without exposing GitLab credentials to the agent.",
        )
    }
}

#[tool_router]
impl GitLabDiscoveryMcpServer {
    #[tool(
        name = "list_gitlab_paths",
        description = "List allowed GitLab groups and repositories for the current review context."
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

        let entries = match current_path {
            None => binding.allow.root_entries(),
            Some(path) => {
                if binding.allow.is_repo_allowed(path) {
                    Vec::new()
                } else if binding.allow.can_browse_group(path) {
                    let mut entries = Vec::new();
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
                            entries.push(GitLabDiscoveryPathEntry {
                                kind: GitLabDiscoveryPathEntryKind::Group,
                                path: group.full_path,
                            });
                        }
                    }
                    for project in self
                        .service
                        .gitlab
                        .list_direct_group_projects(path)
                        .await
                        .map_err(mcp_internal_error)?
                    {
                        if binding.allow.is_repo_allowed(&project.path_with_namespace) {
                            entries.push(GitLabDiscoveryPathEntry {
                                kind: GitLabDiscoveryPathEntryKind::Repo,
                                path: project.path_with_namespace,
                            });
                        }
                    }
                    entries.sort_by(|left, right| {
                        left.path.cmp(&right.path).then(left.kind.cmp(&right.kind))
                    });
                    entries
                        .dedup_by(|left, right| left.kind == right.kind && left.path == right.path);
                    entries
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
            entries,
        }))
    }

    #[tool(
        name = "clone_gitlab_repo",
        description = "Clone an allowed GitLab repository into the current Codex container and return the local path plus available branches and tags."
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
        let (checked_out_ref, checked_out_kind) = match request
            .checkout_ref
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            Some(checkout_ref) => self
                .service
                .checkout_ref(&binding.container_id, &path, checkout_ref, &branches, &tags)
                .await
                .map_err(mcp_internal_error)?,
            None => (default_branch.clone(), super::GitLabCheckoutKind::Branch),
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
        let token = extract_bearer_token(&parts.headers)
            .ok_or_else(|| McpError::invalid_params("missing bearer token", None))?;
        let session_id = parts
            .headers
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| McpError::invalid_params("missing mcp-session-id header", None))?;
        self.service
            .registry()
            .binding_for_request(&token, Some(session_id))
            .await
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
            .nest_service("/", rmcp_service)
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
    request: Request<Body>,
    next: Next,
) -> Response {
    let incoming_session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    let Some(token) = extract_bearer_token(request.headers()) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };
    if registry
        .binding_for_request(&token, incoming_session_id.as_deref())
        .await
        .is_none()
    {
        let status = if incoming_session_id.is_some() {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::UNAUTHORIZED
        };
        return (status, "MCP session is not authorized").into_response();
    }

    let response = next.run(request).await;
    if incoming_session_id.is_none() {
        if let Some(session_id) = response
            .headers()
            .get("mcp-session-id")
            .and_then(|value| value.to_str().ok())
        {
            if let Err(err) = registry.bind_session(&token, session_id).await {
                warn!(error = %err, session_id, "failed to bind MCP session to bearer token");
            }
        }
    }
    response
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(ToOwned::to_owned)
}

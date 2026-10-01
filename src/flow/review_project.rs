//! Resolves checkout identity and publication links before a review starts.

use crate::config::Config;
use crate::gitlab::links::gitlab_web_base;
use crate::gitlab::{GitLabApi, MergeRequest};
use crate::review_lane::ReviewLane;
use tracing::warn;

/// Carries the lane's checkout path and the source base for finding links.
pub(crate) struct ResolvedReviewProject {
    /// An empty path disables GitLab discovery when the fork cannot be resolved.
    pub(crate) project_path: String,
    pub(crate) source_web_base: String,
}

/// Looks up a fork once. Security reviews retain the canonical checkout path.
/// If source lookup fails, links use the target base from the merge request.
pub(crate) async fn resolve_review_project(
    config: &Config,
    gitlab: &dyn GitLabApi,
    lane: ReviewLane,
    repo: &str,
    mr: &MergeRequest,
) -> ResolvedReviewProject {
    let mut resolved = ResolvedReviewProject {
        project_path: repo.to_string(),
        source_web_base: target_project_web_base(config, repo, mr),
    };
    let Some(source_project_id) = mr
        .source_project_id
        .filter(|source_id| mr.target_project_id != Some(*source_id))
    else {
        return resolved;
    };

    match gitlab.get_project(&source_project_id.to_string()).await {
        Ok(project) => {
            if let Some(path) = &project.path_with_namespace
                && mr.target_project_id.is_some()
            {
                resolved.source_web_base =
                    format!("{}/{}", gitlab_web_base(&config.gitlab.base_url), path);
            }
            if lane.resolves_review_project_path() {
                resolved.project_path = match project
                    .path_with_namespace
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    Some(path) => path.to_string(),
                    None => {
                        warn!(
                            repo,
                            iid = mr.iid,
                            source_project_id,
                            "source project path missing for fork MR; disabling GitLab discovery for this run"
                        );
                        String::new()
                    }
                };
            }
        }
        Err(err) => {
            if lane.resolves_review_project_path() {
                warn!(
                    repo,
                    iid = mr.iid,
                    source_project_id,
                    error = %err,
                    "failed to resolve source project path for fork MR; disabling GitLab discovery for this run"
                );
                resolved.project_path.clear();
            }
        }
    }
    resolved
}

fn target_project_web_base(config: &Config, repo: &str, mr: &MergeRequest) -> String {
    if let Some(web_url) = &mr.web_url
        && let Some((base, _)) = web_url.split_once("/-/merge_requests/")
    {
        return base.to_string();
    }
    format!("{}/{}", gitlab_web_base(&config.gitlab.base_url), repo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use serde_json::json;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    #[tokio::test]
    async fn resolved_forks_keep_lane_checkout_policy_and_source_links() -> Result<()> {
        for lane in [ReviewLane::General, ReviewLane::Security] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v4/projects/123"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "path_with_namespace": "fork/source"
                })))
                .expect(1)
                .mount(&server)
                .await;
            let gitlab = crate::gitlab::GitLabClient::new(&server.uri(), "token")?;
            let mut config = crate::config::test_builder::ConfigBuilder::for_review_tests().build();
            config.gitlab.base_url = "https://gitlab.example.com/api/v4".to_string();
            let mr = serde_json::from_value(json!({
                "iid": 50, "source_project_id": 123, "target_project_id": 456
            }))?;
            let project = resolve_review_project(&config, &gitlab, lane, "target/repo", &mr).await;
            assert_eq!(
                project.project_path,
                if lane.is_security() {
                    "target/repo"
                } else {
                    "fork/source"
                }
            );
            assert_eq!(
                project.source_web_base,
                "https://gitlab.example.com/fork/source"
            );
            server.verify().await;
        }
        Ok(())
    }

    #[tokio::test]
    async fn unresolved_forks_keep_target_links_and_disable_general_discovery() -> Result<()> {
        for lane in [ReviewLane::General, ReviewLane::Security] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/api/v4/projects/123"))
                .respond_with(ResponseTemplate::new(404))
                .expect(1)
                .mount(&server)
                .await;
            let gitlab = crate::gitlab::GitLabClient::new(&server.uri(), "token")?;
            let config = crate::config::test_builder::ConfigBuilder::for_review_tests().build();
            let mr = serde_json::from_value(json!({
                "iid": 50, "source_project_id": 123, "target_project_id": 456,
                "web_url": "https://gitlab.example.com/target/repo/-/merge_requests/50"
            }))?;
            let project = resolve_review_project(&config, &gitlab, lane, "target/repo", &mr).await;
            assert_eq!(
                project.project_path,
                if lane.is_security() {
                    "target/repo"
                } else {
                    ""
                }
            );
            assert_eq!(
                project.source_web_base,
                "https://gitlab.example.com/target/repo"
            );
            server.verify().await;
        }
        Ok(())
    }
}

use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use codex_gitlab_code_review::codex_runner::DockerCodexRunner;
use codex_gitlab_code_review::config::{
    CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig, GitLabTargets, ProxyConfig,
    ReviewConfig, ScheduleConfig, ServerConfig, TargetSelector,
};
use codex_gitlab_code_review::gitlab::{GitLabApi, GitLabClient};
use codex_gitlab_code_review::review::ReviewService;
use codex_gitlab_code_review::state::ReviewStateStore;
use std::env;
use std::sync::Arc;

#[tokio::test]
async fn e2e_live_dry_run() -> Result<()> {
    if env::var("E2E_LIVE").ok().as_deref() != Some("1") {
        return Ok(());
    }

    let base_url = env_required("E2E_GITLAB_BASE_URL")?;
    let repo = env_required("E2E_GITLAB_REPO")?;
    let token = env::var("E2E_GITLAB_TOKEN")
        .map_err(|_| anyhow!("E2E_GITLAB_TOKEN is required for live GitLab API access"))?;
    let mr_iid = env::var("E2E_GITLAB_MR_IID")
        .ok()
        .and_then(|value| value.parse::<u64>().ok());
    let auth_host_path = env::var("E2E_CODEX_AUTH_HOST_PATH")
        .or_else(|_| env::var("HOME").map(|home| format!("{}/.codex", home)))
        .unwrap_or_else(|_| "/root/.codex".to_string());
    let docker_host =
        env::var("E2E_DOCKER_HOST").unwrap_or_else(|_| "unix:///var/run/docker.sock".to_string());
    let created_after = Utc::now() - Duration::days(3650);

    let config = Config {
        gitlab: GitLabConfig {
            base_url: base_url.clone(),
            token: token.clone(),
            bot_user_id: None,
            created_after: Some(created_after),
            targets: GitLabTargets {
                repos: TargetSelector::List(vec![repo.clone()]),
                ..Default::default()
            },
        },
        schedule: ScheduleConfig {
            cron: "* * * * *".to_string(),
            timezone: None,
        },
        review: ReviewConfig {
            max_concurrent: 1,
            eyes_emoji: "eyes".to_string(),
            thumbs_emoji: "thumbsup".to_string(),
            comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
            stale_in_progress_minutes: 60,
            dry_run: true,
        },
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 1800,
            auth_host_path,
            auth_mount_path: "/root/.codex".to_string(),
            exec_sandbox: "danger-full-access".to_string(),
            deps: codex_gitlab_code_review::config::DepsConfig { enabled: false },
        },
        docker: DockerConfig { host: docker_host },
        database: DatabaseConfig {
            path: ":memory:".to_string(),
        },
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
        },
        proxy: ProxyConfig {
            http_proxy: None,
            https_proxy: None,
            no_proxy: None,
        },
    };

    let gitlab_client = GitLabClient::new(&config.gitlab.base_url, &config.gitlab.token)?;
    let bot_user_id = if config.gitlab.token.is_empty() {
        0
    } else {
        gitlab_client.current_user().await?.id
    };
    let git_base = gitlab_client.git_base_url()?;
    let iid = match mr_iid {
        Some(value) => value,
        None => {
            let mrs = gitlab_client.list_open_mrs(&repo).await?;
            let first = mrs.first().ok_or_else(|| anyhow!("no open MRs found"))?;
            first.iid
        }
    };

    let state = Arc::new(ReviewStateStore::new(&config.database.path).await?);
    let runner = DockerCodexRunner::new(
        config.docker.clone(),
        config.codex.clone(),
        config.proxy.clone(),
        git_base,
        config.gitlab.token.clone(),
        false,
    )?;
    let service = ReviewService::new(
        config.clone(),
        Arc::new(gitlab_client),
        state,
        Arc::new(runner),
        bot_user_id,
        created_after,
    );

    service.review_mr(&repo, iid).await?;
    Ok(())
}

fn env_required(name: &str) -> Result<String> {
    env::var(name).map_err(|_| anyhow!("missing env var {}", name))
}

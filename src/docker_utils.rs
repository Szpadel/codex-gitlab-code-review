use crate::config::DockerConfig;
use anyhow::{Context, Result, anyhow};
use bollard::errors::Error as BollardError;
use bollard::query_parameters::CreateImageOptionsBuilder;
use bollard::{API_DEFAULT_VERSION, Docker};
use futures::StreamExt;
use std::future::Future;
use std::time::{Duration, Instant};
use tokio::time::{sleep, timeout as tokio_timeout};
use tracing::warn;

pub fn connect_docker(docker_cfg: &DockerConfig) -> Result<Docker> {
    let host = docker_cfg.host.as_str();
    if host.starts_with("unix://") || host.ends_with(".sock") {
        Docker::connect_with_unix(host, 120, API_DEFAULT_VERSION)
            .with_context(|| format!("connect to docker unix socket {host}"))
    } else {
        Docker::connect_with_http(host, 120, API_DEFAULT_VERSION)
            .with_context(|| format!("connect to docker host {host}"))
    }
}

pub async fn wait_for_docker_ready(
    docker_cfg: &DockerConfig,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<()> {
    let docker = match connect_docker(docker_cfg) {
        Ok(docker) => Some(docker),
        Err(err) if is_missing_unix_socket_error(&err) => None,
        Err(err) => return Err(err),
    };

    let docker_cfg = docker_cfg.clone();
    let host = docker_cfg.host.clone();
    let probe_result = if let Some(docker) = docker {
        wait_for_ready(timeout, poll_interval, || {
            let host = host.clone();
            let docker = docker.clone();
            async move {
                docker
                    .ping()
                    .await
                    .with_context(|| format!("ping docker host {host}"))?;
                Ok(())
            }
        })
        .await
    } else {
        wait_for_ready(timeout, poll_interval, || {
            let docker_cfg = docker_cfg.clone();
            let host = host.clone();
            async move {
                let docker = connect_docker(&docker_cfg)?;
                docker
                    .ping()
                    .await
                    .with_context(|| format!("ping docker host {host}"))?;
                Ok(())
            }
        })
        .await
    };

    probe_result.with_context(|| {
        format!(
            "wait {} for docker host {} to become ready",
            format_duration(timeout),
            docker_cfg.host
        )
    })
}

pub fn normalize_image_reference(image: &str) -> String {
    let trimmed = image.trim();
    if trimmed.is_empty() {
        return trimmed.to_string();
    }
    if trimmed.contains('@') {
        return trimmed.to_string();
    }
    let last_slash = trimmed.rfind('/');
    let last_colon = trimmed.rfind(':');
    let needs_latest = match (last_colon, last_slash) {
        (None, _) => true,
        (Some(colon), Some(slash)) => colon < slash,
        (Some(_), None) => false,
    };
    if needs_latest {
        format!("{trimmed}:latest")
    } else {
        trimmed.to_string()
    }
}

pub async fn ensure_image(docker: &Docker, image: &str) -> Result<()> {
    let options = CreateImageOptionsBuilder::new().from_image(image).build();
    let mut stream = docker.create_image(Some(options), None, None);
    while let Some(next) = stream.next().await {
        match next {
            Ok(_) => {}
            Err(err) => {
                if image_exists(docker, image).await? {
                    warn!(
                        image = image,
                        error = %err,
                        "failed to pull docker image; using local copy"
                    );
                    return Ok(());
                }
                return Err(anyhow!(err).context(format!("pull docker image {image}")));
            }
        }
    }
    Ok(())
}

async fn image_exists(docker: &Docker, image: &str) -> Result<bool> {
    match docker.inspect_image(image).await {
        Ok(_) => Ok(true),
        Err(BollardError::DockerResponseServerError {
            status_code: 404, ..
        }) => Ok(false),
        Err(err) => Err(anyhow!(err).context(format!("inspect docker image {image}"))),
    }
}

async fn wait_for_ready<F, Fut>(
    timeout: Duration,
    poll_interval: Duration,
    mut probe: F,
) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let deadline = Instant::now() + timeout;
    let mut last_err = None;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(last_err.unwrap_or_else(|| anyhow!("readiness probe timed out")));
        }
        let remaining = deadline.saturating_duration_since(now);

        let err = match tokio_timeout(remaining, probe()).await {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(err)) => err,
            Err(_) => return Err(anyhow!("readiness probe timed out")),
        };
        last_err = Some(err);

        let now = Instant::now();
        if now >= deadline {
            return Err(last_err.unwrap_or_else(|| anyhow!("readiness probe timed out")));
        }

        sleep(poll_interval.min(deadline.saturating_duration_since(now))).await;
    }
}

fn format_duration(duration: Duration) -> String {
    if duration.subsec_nanos() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn is_missing_unix_socket_error(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<BollardError>())
        .any(|cause| matches!(cause, BollardError::SocketNotFoundError(_)))
}

#[cfg(test)]
mod tests {
    use super::{wait_for_docker_ready, wait_for_ready};
    use crate::config::DockerConfig;
    use anyhow::{Result, anyhow};
    use bollard::errors::Error as BollardError;
    use std::path::PathBuf;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[tokio::test]
    async fn wait_for_ready_returns_without_retry_when_probe_succeeds() -> Result<()> {
        let attempts = Arc::new(AtomicUsize::new(0));
        wait_for_ready(Duration::from_millis(10), Duration::from_millis(1), {
            let attempts = Arc::clone(&attempts);
            move || {
                let attempts = Arc::clone(&attempts);
                async move {
                    attempts.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            }
        })
        .await?;

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_ready_retries_until_probe_succeeds() -> Result<()> {
        let attempts = Arc::new(AtomicUsize::new(0));
        wait_for_ready(Duration::from_millis(50), Duration::from_millis(1), {
            let attempts = Arc::clone(&attempts);
            move || {
                let attempts = Arc::clone(&attempts);
                async move {
                    let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                    if attempt < 2 {
                        Err(anyhow!("not ready yet"))
                    } else {
                        Ok(())
                    }
                }
            }
        })
        .await?;

        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_ready_returns_last_probe_error_after_timeout() {
        let err = wait_for_ready(
            Duration::from_millis(5),
            Duration::from_millis(1),
            || async { Err(anyhow!("docker unavailable")) },
        )
        .await
        .expect_err("probe should time out");

        assert!(err.to_string().contains("docker unavailable"));
    }

    #[tokio::test]
    async fn wait_for_ready_rejects_probe_success_after_timeout() {
        let err = wait_for_ready(
            Duration::from_millis(5),
            Duration::from_millis(1),
            || async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok(())
            },
        )
        .await
        .expect_err("probe should time out before late success");

        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn wait_for_docker_ready_retries_missing_unix_socket_until_timeout() {
        let missing_socket = missing_socket_path();
        let docker_cfg = DockerConfig {
            host: format!("unix://{}", missing_socket.display()),
        };

        let started_at = Instant::now();
        let err = wait_for_docker_ready(
            &docker_cfg,
            Duration::from_millis(25),
            Duration::from_millis(5),
        )
        .await
        .expect_err("missing socket should time out after retries");

        assert!(
            started_at.elapsed() >= Duration::from_millis(20),
            "expected retries before timeout, got {:?}",
            started_at.elapsed()
        );
        assert!(err.to_string().contains("wait 25ms for docker host"));
        assert!(err.to_string().contains(&docker_cfg.host));
    }

    #[test]
    fn is_missing_unix_socket_error_only_matches_socket_not_found() {
        let missing_socket_err = anyhow!(BollardError::SocketNotFoundError(
            "/var/run/docker.sock".to_string()
        ));
        let other_err = anyhow!(BollardError::RequestTimeoutError);

        assert!(super::is_missing_unix_socket_error(&missing_socket_err));
        assert!(!super::is_missing_unix_socket_error(&other_err));
    }

    fn missing_socket_path() -> PathBuf {
        let nanos_since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let unique = format!(
            "codex-gitlab-code-review-missing-{}-{}.sock",
            std::process::id(),
            nanos_since_epoch
        );
        std::env::temp_dir().join(unique)
    }
}

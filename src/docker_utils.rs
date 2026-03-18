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
    let docker = connect_docker(docker_cfg)?;
    let host = docker_cfg.host.clone();
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
    .with_context(|| {
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

#[cfg(test)]
mod tests {
    use super::wait_for_ready;
    use anyhow::{Result, anyhow};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

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
}

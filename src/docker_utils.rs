use crate::config::DockerConfig;
use anyhow::{Context, Result, anyhow};
use bollard::errors::Error as BollardError;
use bollard::query_parameters::CreateImageOptionsBuilder;
use bollard::{API_DEFAULT_VERSION, Docker};
use futures::StreamExt;
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

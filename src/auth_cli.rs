use crate::config::{CodexConfig, DockerConfig, ProxyConfig};
use crate::docker_utils::{connect_docker, ensure_image, normalize_image_reference};
use anyhow::{Context, Result, anyhow, bail};
use bollard::Docker;
use bollard::container::LogOutput;
use bollard::models::{ContainerCreateBody, HostConfig};
use bollard::query_parameters::{
    AttachContainerOptionsBuilder, CreateContainerOptionsBuilder, RemoveContainerOptionsBuilder,
    StartContainerOptionsBuilder, WaitContainerOptionsBuilder,
};
use futures::StreamExt;
use std::io::Write;
use std::pin::Pin;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub enum AuthAction {
    Login,
    Status,
}

pub struct AuthRunner {
    docker: Docker,
    codex: CodexConfig,
    proxy: ProxyConfig,
}

impl AuthRunner {
    pub fn new(docker_cfg: DockerConfig, codex: CodexConfig, proxy: ProxyConfig) -> Result<Self> {
        let docker = connect_docker(&docker_cfg)?;
        Ok(Self {
            docker,
            codex,
            proxy,
        })
    }

    pub async fn run(&self, action: AuthAction, debug: bool) -> Result<()> {
        let image_ref = normalize_image_reference(&self.codex.image);
        ensure_image(&self.docker, &image_ref).await?;

        let name = format!("codex-auth-{}", Uuid::new_v4());
        let script = build_auth_script(&self.codex.auth_mount_path, action);
        let config = ContainerCreateBody {
            image: Some(image_ref.clone()),
            cmd: Some(vec!["-lc".to_string(), script]),
            env: Some(self.env_vars(debug)),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            attach_stdin: Some(false),
            open_stdin: Some(false),
            tty: Some(false),
            host_config: Some(HostConfig {
                binds: Some(vec![format!(
                    "{}:{}:rw",
                    self.codex.auth_host_path, self.codex.auth_mount_path
                )]),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                config,
            )
            .await
            .with_context(|| format!("create docker container {name} with image {image_ref}"))?;

        let id = create.id;
        let start_result = self
            .docker
            .start_container(&id, Some(StartContainerOptionsBuilder::new().build()))
            .await
            .with_context(|| format!("start docker container {id}"));
        if let Err(err) = start_result {
            self.remove_container_best_effort(&id).await;
            return Err(err);
        }

        let attach = match self
            .docker
            .attach_container(
                &id,
                Some(
                    AttachContainerOptionsBuilder::new()
                        .stdout(true)
                        .stderr(true)
                        .stream(true)
                        .logs(true)
                        .build(),
                ),
            )
            .await
            .with_context(|| format!("attach docker container {id}"))
        {
            Ok(attach) => attach,
            Err(err) => {
                self.remove_container_best_effort(&id).await;
                return Err(err);
            }
        };

        let output_task = tokio::spawn(stream_output(attach.output));
        let mut wait_stream = self
            .docker
            .wait_container(&id, Some(WaitContainerOptionsBuilder::new().build()));

        let exit_status_result = wait_stream.next().await.transpose();
        let output_result = output_task
            .await
            .map_err(|err| anyhow!("auth output task failed: {err}"))?;

        self.remove_container_best_effort(&id).await;
        output_result?;

        let exit_status = exit_status_result?;
        match exit_status {
            Some(result) if result.status_code == 0 => Ok(()),
            Some(result) => {
                let message = result
                    .error
                    .as_ref()
                    .and_then(|err| err.message.clone())
                    .unwrap_or_else(|| "unknown error".to_string());
                bail!(
                    "auth command failed with status {}: {}",
                    result.status_code,
                    message
                );
            }
            None => bail!("auth container exited without status"),
        }
    }

    fn env_vars(&self, debug: bool) -> Vec<String> {
        let mut env = vec![
            format!("CODEX_HOME={}", self.codex.auth_mount_path),
            "HOME=/root".to_string(),
        ];
        if let Some(value) = &self.proxy.http_proxy {
            env.push(format!("HTTP_PROXY={value}"));
        }
        if let Some(value) = &self.proxy.https_proxy {
            env.push(format!("HTTPS_PROXY={value}"));
        }
        if let Some(value) = &self.proxy.no_proxy {
            env.push(format!("NO_PROXY={value}"));
        }
        if debug {
            env.push("CODEX_RUNNER_DEBUG=1".to_string());
        }
        env
    }

    async fn remove_container_best_effort(&self, id: &str) {
        let _ = self
            .docker
            .remove_container(
                id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
    }
}

fn build_auth_script(auth_mount_path: &str, action: AuthAction) -> String {
    let action_args = match action {
        AuthAction::Login => "login --device-auth",
        AuthAction::Status => "login status",
    };
    format!(
        r#"set -eu
mkdir -p "{auth_mount_path}"
export CODEX_HOME="{auth_mount_path}"
# Ensure Codex CLI is available for auth flows.
if ! command -v codex >/dev/null 2>&1; then
  echo "codex-auth: codex not found, installing"
  if command -v npm >/dev/null 2>&1; then
    if [ "${{CODEX_RUNNER_DEBUG:-}}" = "1" ]; then
      npm install -g @openai/codex
    else
      if ! npm install -g @openai/codex >/tmp/codex-auth-install.log 2>&1; then
        echo "codex-auth-error: codex install failed"
        tail -n 50 /tmp/codex-auth-install.log | sed 's/^/codex-auth-error: /'
        exit 1
      fi
    fi
  else
    echo "codex-auth-error: npm not found; provide a base image with node/npm or preinstall codex"
    exit 1
  fi
fi
exec codex -c cli_auth_credentials_store="file" {action_args}
"#,
        auth_mount_path = auth_mount_path,
        action_args = action_args,
    )
}

async fn stream_output(
    mut output: Pin<
        Box<dyn futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>,
    >,
) -> Result<()> {
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    while let Some(next) = output.next().await {
        match next? {
            LogOutput::StdOut { message }
            | LogOutput::Console { message }
            | LogOutput::StdIn { message } => {
                out.write_all(&message)?;
                out.flush()?;
            }
            LogOutput::StdErr { message } => {
                err.write_all(&message)?;
                err.flush()?;
            }
        }
    }
    Ok(())
}

use super::*;

#[derive(Clone)]
pub(crate) struct InFlightImagePull {
    pub(crate) id: u64,
    pub(crate) future: Shared<BoxFuture<'static, std::result::Result<(), Arc<String>>>>,
}

#[derive(Debug)]
pub(crate) struct ContainerExecOutput {
    pub(crate) exit_code: i64,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

impl DockerCodexRunner {
    pub(crate) fn warm_up_image_refs(&self) -> Vec<String> {
        let mut images = vec![Self::normalize_image_reference(&self.codex.image)];
        if self.browser_mcp_enabled_for_any_mode() {
            let browser_image =
                Self::normalize_image_reference(&self.codex.browser_mcp.browser_image);
            if !images.contains(&browser_image) {
                images.push(browser_image);
            }
        }
        images
    }

    pub(crate) fn browser_mcp_enabled_for_any_mode(&self) -> bool {
        effective_browser_mcp(self.browser_mcp(), &self.codex.mcp_server_overrides.review).is_some()
            || (self.mention_commands_active
                && effective_browser_mcp(
                    self.browser_mcp(),
                    &self.codex.mcp_server_overrides.mention,
                )
                .is_some())
    }

    pub(crate) async fn ensure_image_available(&self, image: &str) -> Result<()> {
        let image = Self::normalize_image_reference(image);
        let in_flight = {
            let mut image_pulls = self
                .image_pulls
                .lock()
                .expect("image pull map lock poisoned");
            if let Some(in_flight) = image_pulls.get(&image) {
                in_flight.clone()
            } else {
                let pull_id = self.next_image_pull_id.fetch_add(1, Ordering::Relaxed);
                let docker = self.docker.clone();
                let image_for_pull = image.clone();
                let future = async move {
                    ensure_image(&docker, &image_for_pull)
                        .await
                        .map_err(|err| Arc::new(format!("{err:#}")))
                }
                .boxed()
                .shared();
                let in_flight = InFlightImagePull {
                    id: pull_id,
                    future,
                };
                image_pulls.insert(image.clone(), in_flight.clone());
                in_flight
            }
        };

        let result = in_flight.future.await;
        {
            let mut image_pulls = self
                .image_pulls
                .lock()
                .expect("image pull map lock poisoned");
            if image_pulls
                .get(&image)
                .is_some_and(|current| current.id == in_flight.id)
            {
                image_pulls.remove(&image);
            }
        }
        if let Err(err) = result {
            return Err(anyhow!(err.as_ref().clone()));
        }

        Ok(())
    }

    pub(crate) fn normalize_image_reference(image: &str) -> String {
        normalize_image_reference(image)
    }

    pub(crate) async fn remove_container_best_effort(&self, id: &str) {
        let _ = self
            .docker
            .remove_container(
                id,
                Some(RemoveContainerOptionsBuilder::new().force(true).build()),
            )
            .await;
    }

    pub(crate) async fn cleanup_app_server_containers(
        &self,
        container_id: &str,
        browser_container_id: Option<&str>,
    ) {
        self.remove_container_best_effort(container_id).await;
        if let Some(browser_container_id) = browser_container_id {
            self.remove_container_best_effort(browser_container_id)
                .await;
        }
    }

    pub(crate) async fn exec_container_command(
        &self,
        container_id: &str,
        command: Vec<String>,
        cwd: Option<&str>,
    ) -> Result<ContainerExecOutput> {
        self.exec_container_command_with_env(container_id, command, cwd, None)
            .await
    }

    pub(crate) async fn exec_container_command_with_env(
        &self,
        container_id: &str,
        command: Vec<String>,
        cwd: Option<&str>,
        env: Option<Vec<String>>,
    ) -> Result<ContainerExecOutput> {
        let command_display = format_command_for_log(&command);
        let cwd_display = cwd.unwrap_or("<default>");
        info!(
            container_id,
            command = command_display.as_str(),
            cwd = cwd_display,
            "running docker exec command"
        );

        // Deliberately bypass app-server command RPC and its sandbox semantics for
        // mention auxiliary git operations.
        let exec = self
            .docker
            .create_exec(
                container_id,
                ExecConfig {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    cmd: Some(command.clone()),
                    working_dir: cwd.map(|value| value.to_string()),
                    env,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| {
                format!(
                    "create docker exec command '{}' in container {}",
                    command_display, container_id
                )
            })?;

        let start_result = self
            .docker
            .start_exec(&exec.id, None::<StartExecOptions>)
            .await
            .with_context(|| {
                format!(
                    "start docker exec command '{}' in container {}",
                    command_display, container_id
                )
            })?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                while let Some(message) = output.next().await {
                    match message.with_context(|| {
                        format!(
                            "read docker exec output for command '{}' in container {}",
                            command_display, container_id
                        )
                    })? {
                        LogOutput::StdOut { message } | LogOutput::Console { message } => {
                            stdout.push_str(String::from_utf8_lossy(&message).as_ref());
                        }
                        LogOutput::StdErr { message } => {
                            stderr.push_str(String::from_utf8_lossy(&message).as_ref());
                        }
                        LogOutput::StdIn { .. } => {}
                    }
                }
            }
            StartExecResults::Detached => {
                bail!(
                    "docker exec command '{}' unexpectedly detached in container {}",
                    command_display,
                    container_id
                );
            }
        }

        let inspect = self.docker.inspect_exec(&exec.id).await.with_context(|| {
            format!(
                "inspect docker exec command '{}' in container {}",
                command_display, container_id
            )
        })?;
        let output = validate_container_exec_result(
            &command,
            cwd,
            ContainerExecOutput {
                exit_code: inspect.exit_code.unwrap_or(-1),
                stdout,
                stderr,
            },
        )?;

        info!(
            container_id,
            command = command_display.as_str(),
            cwd = cwd_display,
            exit_code = output.exit_code,
            "docker exec command completed"
        );

        Ok(output)
    }

    pub(crate) async fn exec_container_git_command(
        &self,
        container_id: &str,
        git_args: &[String],
        cwd: Option<&str>,
    ) -> Result<ContainerExecOutput> {
        self.exec_container_command(container_id, auxiliary_git_exec_command(git_args), cwd)
            .await
    }

    pub(crate) fn is_managed_container_name(name: &str) -> bool {
        let name = name.trim_start_matches('/');
        name.starts_with(REVIEW_CONTAINER_NAME_PREFIX)
            || name.starts_with(BROWSER_CONTAINER_NAME_PREFIX)
    }

    pub(crate) fn review_container_labels(owner_id: &str) -> HashMap<String, String> {
        HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), owner_id.to_string())])
    }

    pub(crate) fn review_container_filters(owner_id: &str) -> HashMap<String, Vec<String>> {
        HashMap::from([
            (
                "name".to_string(),
                vec![
                    REVIEW_CONTAINER_NAME_PREFIX.to_string(),
                    BROWSER_CONTAINER_NAME_PREFIX.to_string(),
                ],
            ),
            (
                "label".to_string(),
                vec![format!("{REVIEW_OWNER_LABEL_KEY}={owner_id}")],
            ),
        ])
    }

    pub(crate) fn has_review_owner_label(
        labels: Option<&HashMap<String, String>>,
        owner_id: &str,
    ) -> bool {
        labels
            .and_then(|labels| labels.get(REVIEW_OWNER_LABEL_KEY))
            .map(|value| value == owner_id)
            .unwrap_or(false)
    }

    pub(crate) async fn stop_active_review_containers_best_effort(&self) {
        let filters = Self::review_container_filters(&self.owner_id);
        let options = ListContainersOptionsBuilder::new()
            .all(true)
            .filters(&filters)
            .build();

        let containers = match self.docker.list_containers(Some(options)).await {
            Ok(containers) => containers,
            Err(err) => {
                warn!(
                    error = %err,
                    "failed to list docker containers while stopping active codex reviews"
                );
                return;
            }
        };

        for container in containers {
            let names = container.names.unwrap_or_default();
            if !names
                .iter()
                .any(|name| Self::is_managed_container_name(name))
            {
                continue;
            }
            if !Self::has_review_owner_label(container.labels.as_ref(), &self.owner_id) {
                continue;
            }

            let Some(id) = container.id.as_deref() else {
                let names_value = if names.is_empty() {
                    "<unknown>".to_string()
                } else {
                    names.join(",")
                };
                warn!(
                    container_names = names_value.as_str(),
                    "skipping managed codex container without id"
                );
                continue;
            };

            if let Err(err) = self
                .docker
                .remove_container(
                    id,
                    Some(RemoveContainerOptionsBuilder::new().force(true).build()),
                )
                .await
            {
                let container_name = names
                    .iter()
                    .find(|name| Self::is_managed_container_name(name))
                    .map(|name| name.trim_start_matches('/'))
                    .unwrap_or("<unknown>");
                warn!(
                    container_id = id,
                    container_name,
                    error = %err,
                    "failed to remove managed codex container"
                );
            }
        }
    }

    pub(crate) async fn start_app_server_container(
        &self,
        script: String,
        auth_host_path: &str,
        extra_binds: Vec<String>,
        extra_env: Vec<String>,
        browser_mcp: Option<&BrowserMcpConfig>,
        extra_hosts: Vec<String>,
    ) -> Result<StartedAppServer> {
        let image_ref = Self::normalize_image_reference(&self.codex.image);
        self.ensure_image_available(&image_ref).await?;
        let browser_container_id = if let Some(browser_mcp) = browser_mcp {
            Some(
                self.start_browser_container(browser_mcp, extra_hosts.clone())
                    .await?,
            )
        } else {
            None
        };
        let name = format!("{}{}", REVIEW_CONTAINER_NAME_PREFIX, Uuid::new_v4());
        let mut binds = vec![format!(
            "{}:{}:rw",
            auth_host_path, self.codex.auth_mount_path
        )];
        binds.extend(extra_binds);
        let config = ContainerCreateBody {
            image: Some(image_ref.clone()),
            cmd: Some(Self::app_server_cmd(script)),
            env: Some(self.env_vars(&extra_env)),
            labels: Some(Self::review_container_labels(&self.owner_id)),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            attach_stdin: Some(true),
            open_stdin: Some(true),
            tty: Some(false),
            host_config: Some(HostConfig {
                binds: Some(binds),
                extra_hosts: (browser_container_id.is_none() && !extra_hosts.is_empty())
                    .then_some(extra_hosts),
                network_mode: browser_container_id
                    .as_ref()
                    .map(|id| format!("container:{id}")),
                auto_remove: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let create = match self
            .docker
            .create_container(
                Some(CreateContainerOptionsBuilder::new().name(&name).build()),
                config,
            )
            .await
            .with_context(|| format!("create docker container {} with image {}", name, image_ref))
        {
            Ok(create) => create,
            Err(err) => {
                if let Some(browser_id) = browser_container_id.as_deref() {
                    self.remove_container_best_effort(browser_id).await;
                }
                return Err(err);
            }
        };
        let id = create.id;
        let start_result = self
            .docker
            .start_container(&id, Some(StartContainerOptionsBuilder::new().build()))
            .await
            .with_context(|| format!("start docker container {}", id));
        if let Err(err) = start_result {
            self.remove_container_best_effort(&id).await;
            if let Some(browser_id) = browser_container_id.as_deref() {
                self.remove_container_best_effort(browser_id).await;
            }
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
                        .stdin(true)
                        .stream(true)
                        .logs(true)
                        .build(),
                ),
            )
            .await
            .with_context(|| format!("attach docker container {}", id))
        {
            Ok(attach) => attach,
            Err(err) => {
                self.remove_container_best_effort(&id).await;
                if let Some(browser_id) = browser_container_id.as_deref() {
                    self.remove_container_best_effort(browser_id).await;
                }
                return Err(err);
            }
        };

        Ok(StartedAppServer {
            container_id: id,
            browser_container_id,
            client: AppServerClient::new(attach, self.log_all_json),
        })
    }
}

pub(crate) fn validate_container_exec_result(
    command: &[String],
    cwd: Option<&str>,
    output: ContainerExecOutput,
) -> Result<ContainerExecOutput> {
    if output.exit_code == 0 {
        return Ok(output);
    }

    let command_display = format_command_for_log(command);
    let cwd_display = cwd.unwrap_or("<default>");
    let stderr = output.stderr.trim();
    if stderr.is_empty() {
        bail!(
            "docker exec command failed with exit code {} (command: {}, cwd: {})",
            output.exit_code,
            command_display,
            cwd_display
        );
    }

    bail!(
        "docker exec command failed with exit code {} (command: {}, cwd: {}): {}",
        output.exit_code,
        command_display,
        cwd_display,
        stderr
    );
}

pub(crate) fn format_command_for_log(command: &[String]) -> String {
    command
        .iter()
        .map(|value| shell_quote(value))
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn auxiliary_git_exec_command(git_args: &[String]) -> Vec<String> {
    let git_command = std::iter::once("git".to_string())
        .chain(git_args.iter().cloned())
        .map(|value| shell_quote(&value))
        .collect::<Vec<_>>()
        .join(" ");
    vec!["bash".to_string(), "-lc".to_string(), git_command]
}

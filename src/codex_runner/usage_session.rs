//! Per-account Usage workers own connections independently of HTTP request lifetimes.

use super::container::AppServerContainerExtras;
use super::session_runner::RunSessionConfig;
use super::{DockerCodexRunner, RunnerRuntime, StartedAppServer};
use anyhow::{Context, Result, anyhow, bail};
use bollard::Docker;
use bollard::errors::Error as DockerError;
use bollard::query_parameters::RemoveContainerOptionsBuilder;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Weak;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::warn;

/// Owns the bounded account workers. Drop requests cleanup without retaining the runner.
#[derive(Default)]
pub(super) struct UsageSessions {
    workers: HashMap<String, UsageWorker>,
    shutdown: CancellationToken,
}

impl Drop for UsageSessions {
    fn drop(&mut self) {
        // Workers own cleanup. Closing the owner also wakes workers with idle connections.
        self.shutdown.cancel();
    }
}

struct UsageWorker {
    requests: mpsc::Sender<UsageRequest>,
    task: JoinHandle<Result<()>>,
}

struct UsageRequest {
    method: &'static str,
    params: Value,
    timeout_error: &'static str,
    response: oneshot::Sender<Result<Value>>,
}

// A worker must still remove its container after the last runner reference disappears.
enum UsageContainerRemoval {
    Docker(Docker),
    #[cfg(test)]
    Fake(std::sync::Arc<dyn super::test_support::RunnerHarness>),
}

impl UsageContainerRemoval {
    /// Clears the connection only after removal succeeds. An absent container counts as removed.
    /// Errors retain the connection so the worker can retry cleanup without starting another.
    async fn remove(&self, session: &mut Option<StartedAppServer>) -> Result<()> {
        let Some(container_id) = session
            .as_ref()
            .map(|started| started.container_id.as_str())
        else {
            return Ok(());
        };
        match self {
            Self::Docker(docker) => {
                match docker
                    .remove_container(
                        container_id,
                        Some(RemoveContainerOptionsBuilder::new().force(true).build()),
                    )
                    .await
                {
                    Ok(())
                    | Err(DockerError::DockerResponseServerError {
                        status_code: 404, ..
                    }) => {}
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("remove Usage container {container_id}"));
                    }
                }
            }
            #[cfg(test)]
            Self::Fake(harness) => {
                harness.remove_usage_container(container_id).await?;
            }
        }
        *session = None;
        Ok(())
    }
}

impl DockerCodexRunner {
    /// Queues a fresh RPC for a configured account. Accepted requests survive caller cancellation.
    /// Shutdown, worker failure, startup failure, and RPC errors are returned to the caller.
    pub(super) async fn request_usage(
        &self,
        account_name: &str,
        method: &'static str,
        params: Value,
        timeout_error: &'static str,
    ) -> Result<Value> {
        let account = self
            .auth_account_by_name(account_name)
            .ok_or_else(|| anyhow!("unknown codex auth account: {account_name}"))?;
        let requests = {
            let mut sessions = self
                .usage_sessions
                .lock()
                .expect("Usage sessions lock poisoned");
            if sessions.shutdown.is_cancelled() {
                bail!("Usage sessions are shut down");
            }
            if !sessions.workers.contains_key(account_name) {
                // One queued request per account prevents an unbounded internal backlog.
                let (requests, receiver) = mpsc::channel(1);
                let removal = match &self.runtime {
                    RunnerRuntime::Docker { docker, .. } => {
                        UsageContainerRemoval::Docker(docker.clone())
                    }
                    #[cfg(test)]
                    RunnerRuntime::Fake(harness) => UsageContainerRemoval::Fake(harness.clone()),
                };
                let task = tokio::spawn(run_usage_worker(
                    self.self_weak.clone(),
                    account.auth_host_path.clone(),
                    receiver,
                    sessions.shutdown.clone(),
                    removal,
                ));
                sessions
                    .workers
                    .insert(account_name.to_string(), UsageWorker { requests, task });
            }
            sessions.workers[account_name].requests.clone()
        };
        let (response, receiver) = oneshot::channel();
        requests
            .send(UsageRequest {
                method,
                params,
                timeout_error,
                response,
            })
            .await
            .with_context(|| format!("send Usage request to worker for account {account_name}"))?;
        receiver.await.with_context(|| {
            format!("receive Usage response from worker for account {account_name}")
        })?
    }

    /// Rejects new requests and waits for all workers to remove their containers.
    pub(super) async fn stop_usage_sessions(&self) -> Result<()> {
        let workers = {
            let mut sessions = self
                .usage_sessions
                .lock()
                .expect("Usage sessions lock poisoned");
            sessions.shutdown.cancel();
            std::mem::take(&mut sessions.workers)
        };
        let mut result = Ok(());
        for (account, worker) in workers {
            drop(worker.requests);
            let stopped = worker
                .task
                .await
                .context("join Usage account worker")
                .and_then(|value| value);
            if let Err(error) = stopped {
                warn!(account, error = %error, "Usage worker shutdown failed");
                result = Err(error);
            }
        }
        result
    }
}

async fn run_usage_worker(
    runner: Weak<DockerCodexRunner>,
    auth_host_path: String,
    mut requests: mpsc::Receiver<UsageRequest>,
    shutdown: CancellationToken,
    removal: UsageContainerRemoval,
) -> Result<()> {
    let mut session = None;
    let mut needs_removal = false;
    loop {
        let request = tokio::select! {
            biased;
            () = shutdown.cancelled() => break,
            request = requests.recv() => match request {
                Some(request) => request,
                None => break,
            },
        };
        let Some(runner) = runner.upgrade() else {
            break;
        };
        if needs_removal {
            if let Err(error) = removal.remove(&mut session).await {
                let _ = request.response.send(Err(error));
                continue;
            }
            needs_removal = false;
        }
        let initialize = session.is_none();
        if initialize {
            // Do not cancel startup: the worker must receive the container ID for cleanup.
            match runner
                .start_app_server_container(
                    DockerCodexRunner::build_history_reader_script(&runner.codex.auth_mount_path),
                    &auth_host_path,
                    AppServerContainerExtras::default(),
                    None,
                    Vec::new(),
                )
                .await
            {
                Ok(started) => session = Some(started),
                Err(error) => {
                    let _ = request.response.send(Err(error));
                    continue;
                }
            }
        }
        let started = session.as_mut().expect("Usage session started");
        let mut request_result = tokio::select! {
            biased;
            () = shutdown.cancelled() => Err(anyhow!("Usage sessions are shutting down")),
            result = runner.run_session_with_timeout(
                RunSessionConfig {
                    app_server_container_id: started.container_id.clone(),
                    browser_container_id: None,
                    browser_mcp: None,
                    timeout_duration: Duration::from_secs(runner.codex.timeout_seconds),
                    timeout_error: request.timeout_error,
                },
                async {
                    if initialize {
                        started.client.initialize().await?;
                        started.client.initialized().await?;
                    }
                    started.client.request(request.method, request.params).await
                },
            ) => result,
        };
        // Usage RPCs do not consume notifications. Do not retain them between requests.
        started.client.pending_notifications.clear();
        if request_result.is_err()
            && let Err(error) = removal.remove(&mut session).await
        {
            // Do not start a new container until the failed container is removed.
            needs_removal = true;
            request_result =
                request_result.context(format!("Usage container cleanup failed: {error:#}"));
        }
        // A disconnected caller does not cancel an accepted request or its cleanup.
        let _ = request.response.send(request_result);
    }
    let cleanup = removal.remove(&mut session).await;
    if let Err(error) = &cleanup {
        warn!(auth_host_path, error = %error, "Failed to remove Usage container");
    }
    cleanup
}

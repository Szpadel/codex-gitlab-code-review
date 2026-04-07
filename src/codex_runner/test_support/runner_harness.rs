use super::models::{
    AppServerStartRecord, BrowserStartRecord, ExecContainerCommandRequest, ManagedContainerSummary,
    ScriptedAppServer, StartAppServerContainerRequest,
};
use super::scripted_app_server::build_scripted_app_client;
use super::*;
use crate::codex_runner::browser_mcp::{
    BrowserContainerDiagnostics, BrowserContainerStateSnapshot, BrowserLaunchConfig, BrowserLogTail,
};
use crate::codex_runner::container::ContainerExecOutput;
use std::collections::BTreeSet;

#[derive(Debug)]
struct ExpectedExec {
    request: ExecContainerCommandRequest,
    result: std::result::Result<ContainerExecOutput, String>,
}

#[async_trait]
pub(crate) trait RunnerHarness: Send + Sync {
    async fn ensure_image_available(&self, image: &str) -> Result<()>;
    async fn remove_container_best_effort(&self, id: &str);
    async fn start_app_server_container(
        &self,
        request: StartAppServerContainerRequest,
    ) -> Result<StartedAppServer>;
    async fn exec_container_command_with_env_allow_failure(
        &self,
        request: ExecContainerCommandRequest,
    ) -> Result<ContainerExecOutput>;
    async fn list_managed_containers(&self, owner_id: &str)
    -> Result<Vec<ManagedContainerSummary>>;
    async fn collect_browser_container_diagnostics(
        &self,
        browser_container_id: &str,
        launch: &BrowserLaunchConfig,
    ) -> BrowserContainerDiagnostics;
    async fn collect_container_peer_ips(&self, container_id: &str) -> Result<BTreeSet<String>>;
}

#[derive(Default)]
pub(crate) struct FakeRunnerHarness {
    state: Mutex<FakeRunnerHarnessState>,
    app_protocol_requests: Arc<Mutex<Vec<Value>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
}

#[derive(Default)]
struct FakeRunnerHarnessState {
    next_app_container_id: u64,
    next_browser_container_id: u64,
    ensured_images: Vec<String>,
    removed_containers: Vec<String>,
    scripted_app_servers: VecDeque<ScriptedAppServer>,
    app_server_starts: Vec<AppServerStartRecord>,
    browser_starts: Vec<BrowserStartRecord>,
    exec_requests: Vec<ExecContainerCommandRequest>,
    expected_execs: VecDeque<ExpectedExec>,
    managed_containers: Vec<ManagedContainerSummary>,
    browser_diagnostics: HashMap<String, VecDeque<BrowserContainerDiagnostics>>,
    peer_ips: HashMap<String, BTreeSet<String>>,
}

impl FakeRunnerHarness {
    pub(crate) fn push_app_server(&self, scripted: ScriptedAppServer) {
        self.state
            .lock()
            .unwrap()
            .scripted_app_servers
            .push_back(scripted);
    }

    pub(crate) fn push_exec_output(
        &self,
        request: ExecContainerCommandRequest,
        output: ContainerExecOutput,
    ) {
        self.state
            .lock()
            .unwrap()
            .expected_execs
            .push_back(ExpectedExec {
                request,
                result: Ok(output),
            });
    }

    pub(crate) fn push_exec_error(&self, request: ExecContainerCommandRequest, error: &str) {
        self.state
            .lock()
            .unwrap()
            .expected_execs
            .push_back(ExpectedExec {
                request,
                result: Err(error.to_string()),
            });
    }

    pub(crate) fn set_managed_containers(&self, containers: Vec<ManagedContainerSummary>) {
        self.state.lock().unwrap().managed_containers = containers;
    }

    pub(crate) fn set_browser_diagnostics(
        &self,
        container_id: &str,
        diagnostics: Vec<BrowserContainerDiagnostics>,
    ) {
        self.state
            .lock()
            .unwrap()
            .browser_diagnostics
            .insert(container_id.to_string(), diagnostics.into());
    }

    pub(crate) fn set_peer_ips(&self, container_id: &str, peer_ips: BTreeSet<String>) {
        self.state
            .lock()
            .unwrap()
            .peer_ips
            .insert(container_id.to_string(), peer_ips);
    }

    pub(crate) fn ensured_images(&self) -> Vec<String> {
        self.state.lock().unwrap().ensured_images.clone()
    }

    pub(crate) fn removed_containers(&self) -> Vec<String> {
        self.state.lock().unwrap().removed_containers.clone()
    }

    pub(crate) fn app_server_starts(&self) -> Vec<AppServerStartRecord> {
        self.state.lock().unwrap().app_server_starts.clone()
    }

    pub(crate) fn browser_starts(&self) -> Vec<BrowserStartRecord> {
        self.state.lock().unwrap().browser_starts.clone()
    }

    pub(crate) fn exec_requests(&self) -> Vec<ExecContainerCommandRequest> {
        self.state.lock().unwrap().exec_requests.clone()
    }

    pub(crate) fn app_protocol_requests(&self) -> Vec<Value> {
        self.app_protocol_requests.lock().unwrap().clone()
    }

    pub(crate) fn operation_log(&self) -> Vec<String> {
        self.operation_log.lock().unwrap().clone()
    }
}

#[async_trait]
impl RunnerHarness for FakeRunnerHarness {
    async fn ensure_image_available(&self, image: &str) -> Result<()> {
        self.state
            .lock()
            .unwrap()
            .ensured_images
            .push(image.to_string());
        Ok(())
    }

    async fn remove_container_best_effort(&self, id: &str) {
        self.state
            .lock()
            .unwrap()
            .removed_containers
            .push(id.to_string());
    }

    async fn start_app_server_container(
        &self,
        request: StartAppServerContainerRequest,
    ) -> Result<StartedAppServer> {
        let (container_id, browser_container_id, scripted) = {
            let mut state = self.state.lock().unwrap();
            state.next_app_container_id += 1;
            let container_id = format!("app-{}", state.next_app_container_id);
            let browser_container_id = request.browser_mcp.as_ref().map(|browser_mcp| {
                state.next_browser_container_id += 1;
                let browser_container_id = format!("browser-{}", state.next_browser_container_id);
                state.browser_starts.push(BrowserStartRecord {
                    container_id: browser_container_id.clone(),
                    launch: BrowserLaunchConfig::from_browser_mcp(browser_mcp),
                    extra_hosts: request.extra_hosts.clone(),
                });
                browser_container_id
            });
            let network_mode = browser_container_id
                .as_ref()
                .map(|id| format!("container:{id}"));
            state.app_server_starts.push(AppServerStartRecord {
                container_id: container_id.clone(),
                browser_container_id: browser_container_id.clone(),
                request: request.clone(),
                network_mode,
            });
            let scripted = state
                .scripted_app_servers
                .pop_front()
                .ok_or_else(|| anyhow!("no scripted app-server session queued"))?;
            (container_id, browser_container_id, scripted)
        };

        let client = build_scripted_app_client(
            scripted,
            Arc::clone(&self.app_protocol_requests),
            Arc::clone(&self.operation_log),
            request.log_all_json,
        );

        Ok(StartedAppServer {
            container_id,
            browser_container_id,
            client,
        })
    }

    async fn exec_container_command_with_env_allow_failure(
        &self,
        request: ExecContainerCommandRequest,
    ) -> Result<ContainerExecOutput> {
        let expected = {
            let mut state = self.state.lock().unwrap();
            state.exec_requests.push(request.clone());
            state.expected_execs.pop_front()
        }
        .ok_or_else(|| anyhow!("unexpected fake exec request: {:?}", request))?;

        self.operation_log
            .lock()
            .unwrap()
            .push(format!("exec:{}", format_command_for_log(&request.command)));

        anyhow::ensure!(
            expected.request == request,
            "fake exec request mismatch\nexpected: {:?}\nactual: {:?}",
            expected.request,
            request
        );

        match expected.result {
            Ok(output) => Ok(output),
            Err(error) => Err(anyhow!(error)),
        }
    }

    async fn list_managed_containers(
        &self,
        _owner_id: &str,
    ) -> Result<Vec<ManagedContainerSummary>> {
        Ok(self.state.lock().unwrap().managed_containers.clone())
    }

    async fn collect_browser_container_diagnostics(
        &self,
        browser_container_id: &str,
        launch: &BrowserLaunchConfig,
    ) -> BrowserContainerDiagnostics {
        let mut state = self.state.lock().unwrap();
        if let Some(queue) = state.browser_diagnostics.get_mut(browser_container_id)
            && let Some(diagnostics) = queue.pop_front()
        {
            if queue.is_empty() {
                queue.push_back(diagnostics.clone());
            }
            return diagnostics;
        }

        BrowserContainerDiagnostics {
            container_id: browser_container_id.to_string(),
            launch: launch.clone(),
            state: Some(BrowserContainerStateSnapshot {
                status: Some("running".to_string()),
                running: Some(true),
                exit_code: Some(0),
                oom_killed: Some(false),
                error: None,
                started_at: Some("2026-03-18T10:00:00Z".to_string()),
                finished_at: None,
            }),
            state_collection_error: None,
            log_tail: BrowserLogTail {
                stdout: Vec::new(),
                stderr: vec![format!(
                    "DevTools listening on ws://127.0.0.1:{}/devtools/browser/fake",
                    BROWSER_MCP_REMOTE_DEBUGGING_PORT
                )],
            },
            log_collection_error: None,
        }
    }

    async fn collect_container_peer_ips(&self, container_id: &str) -> Result<BTreeSet<String>> {
        self.state
            .lock()
            .unwrap()
            .peer_ips
            .get(container_id)
            .cloned()
            .ok_or_else(|| anyhow!("no fake peer IPs registered for container {container_id}"))
    }
}

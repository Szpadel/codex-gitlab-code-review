use super::*;
use crate::codex_runner::browser_mcp::{
    BrowserContainerDiagnostics, BrowserContainerStateSnapshot, BrowserLaunchConfig, BrowserLogTail,
};
use crate::codex_runner::container::ContainerExecOutput;
use crate::gitlab_discovery_mcp::GitLabDiscoverySessionBinding;
use bollard::errors::Error as BollardError;
use futures::StreamExt;
use serde_json::json;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, duplex};
use tokio::time::{Duration, sleep};
use tokio_util::io::ReaderStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StartAppServerContainerRequest {
    pub(crate) image: String,
    pub(crate) cmd: Vec<String>,
    pub(crate) env: Vec<String>,
    pub(crate) binds: Vec<String>,
    pub(crate) labels: HashMap<String, String>,
    pub(crate) extra_hosts: Vec<String>,
    pub(crate) browser_mcp: Option<BrowserMcpConfig>,
    pub(crate) log_all_json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserStartRecord {
    pub(crate) container_id: String,
    pub(crate) launch: BrowserLaunchConfig,
    pub(crate) extra_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AppServerStartRecord {
    pub(crate) container_id: String,
    pub(crate) browser_container_id: Option<String>,
    pub(crate) request: StartAppServerContainerRequest,
    pub(crate) network_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecContainerCommandRequest {
    pub(crate) container_id: String,
    pub(crate) command: Vec<String>,
    pub(crate) cwd: Option<String>,
    pub(crate) env: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManagedContainerSummary {
    pub(crate) id: Option<String>,
    pub(crate) names: Vec<String>,
    pub(crate) labels: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub(crate) enum ScriptedAppChunk {
    Json(Value),
    Line(String),
    SleepMillis(u64),
}

#[derive(Debug, Clone)]
pub(crate) struct ScriptedAppRequest {
    pub(crate) method: String,
    pub(crate) result: Option<Value>,
    pub(crate) error: Option<Value>,
    pub(crate) after_response: Vec<ScriptedAppChunk>,
    pub(crate) close_output_after: bool,
}

impl ScriptedAppRequest {
    pub(crate) fn result(method: &str, result: Value) -> Self {
        Self {
            method: method.to_string(),
            result: Some(result),
            error: None,
            after_response: Vec::new(),
            close_output_after: false,
        }
    }

    pub(crate) fn with_after_response(mut self, after_response: Vec<ScriptedAppChunk>) -> Self {
        self.after_response = after_response;
        self
    }

    pub(crate) fn close_output_after(mut self) -> Self {
        self.close_output_after = true;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ScriptedAppServer {
    requests: VecDeque<ScriptedAppRequest>,
}

impl ScriptedAppServer {
    pub(crate) fn from_requests(requests: Vec<ScriptedAppRequest>) -> Self {
        Self {
            requests: requests.into(),
        }
    }
}

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

pub(crate) struct FakeGitLabDiscoveryHandle {
    server_name: String,
    advertise_url: String,
    clone_root: String,
    allow_by_repo: Mutex<HashMap<String, ResolvedGitLabDiscoveryAllowList>>,
    registered_bindings: Mutex<Vec<GitLabDiscoverySessionBinding>>,
    removed_bindings: Mutex<Vec<String>>,
}

impl FakeGitLabDiscoveryHandle {
    pub(crate) fn new(server_name: &str, advertise_url: &str, clone_root: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            advertise_url: advertise_url.to_string(),
            clone_root: clone_root.to_string(),
            allow_by_repo: Mutex::new(HashMap::new()),
            registered_bindings: Mutex::new(Vec::new()),
            removed_bindings: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn set_allow_list(
        &self,
        source_repo: &str,
        allow: ResolvedGitLabDiscoveryAllowList,
    ) {
        self.allow_by_repo
            .lock()
            .unwrap()
            .insert(source_repo.to_string(), allow);
    }

    pub(crate) fn registered_bindings(&self) -> Vec<GitLabDiscoverySessionBinding> {
        self.registered_bindings.lock().unwrap().clone()
    }

    pub(crate) fn removed_bindings(&self) -> Vec<String> {
        self.removed_bindings.lock().unwrap().clone()
    }
}

#[async_trait]
impl GitLabDiscoveryHandle for FakeGitLabDiscoveryHandle {
    fn server_name(&self) -> &str {
        self.server_name.as_str()
    }

    fn advertise_url(&self) -> &str {
        self.advertise_url.as_str()
    }

    fn clone_root(&self) -> &str {
        self.clone_root.as_str()
    }

    fn resolve_allow_list(&self, source_repo: &str) -> ResolvedGitLabDiscoveryAllowList {
        self.allow_by_repo
            .lock()
            .unwrap()
            .get(source_repo)
            .cloned()
            .unwrap_or_default()
    }

    async fn register_binding(&self, binding: GitLabDiscoverySessionBinding) {
        self.registered_bindings.lock().unwrap().push(binding);
    }

    async fn remove_binding(&self, network_container_id: &str) {
        self.removed_bindings
            .lock()
            .unwrap()
            .push(network_container_id.to_string());
    }
}

fn build_scripted_app_client(
    scripted: ScriptedAppServer,
    protocol_requests: Arc<Mutex<Vec<Value>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
    log_all_json: bool,
) -> AppServerClient {
    let (client_input, server_input) = duplex(16 * 1024);
    let (server_output, client_output) = duplex(16 * 1024);
    tokio::spawn(async move {
        serve_scripted_app_server(
            scripted,
            protocol_requests,
            operation_log,
            server_input,
            server_output,
        )
        .await;
    });
    let output = ReaderStream::new(client_output).map(|chunk| match chunk {
        Ok(bytes) => Ok(LogOutput::StdOut { message: bytes }),
        Err(err) => Err(BollardError::IOError { err }),
    });
    AppServerClient {
        input: Box::pin(client_input),
        output: Box::pin(output),
        buffer: Vec::new(),
        pending_notifications: VecDeque::new(),
        reasoning_buffers: HashMap::new(),
        agent_message_buffers: HashMap::new(),
        command_output_buffers: HashMap::new(),
        recent_runner_errors: VecDeque::new(),
        log_all_json,
    }
}

async fn serve_scripted_app_server(
    scripted: ScriptedAppServer,
    protocol_requests: Arc<Mutex<Vec<Value>>>,
    operation_log: Arc<Mutex<Vec<String>>>,
    server_input: tokio::io::DuplexStream,
    mut server_output: tokio::io::DuplexStream,
) {
    let mut requests = scripted.requests;
    let mut lines = BufReader::new(server_input).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Ok(message) = serde_json::from_str::<Value>(trimmed) else {
            continue;
        };
        protocol_requests.lock().unwrap().push(message.clone());
        let method = message
            .get("method")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        operation_log.lock().unwrap().push(format!("app:{method}"));
        let Some(id) = message.get("id").cloned() else {
            if method == "initialized" {
                continue;
            }
            continue;
        };

        let Some(expected) = requests.pop_front() else {
            let _ = write_json_line(
                &mut server_output,
                &json!({ "id": id, "error": { "message": format!("unexpected request method {method}") } }),
            )
            .await;
            return;
        };

        if expected.method != method {
            let _ = write_json_line(
                &mut server_output,
                &json!({ "id": id, "error": { "message": format!("expected request method {}, got {}", expected.method, method) } }),
            )
            .await;
            return;
        }

        let response = match (expected.result, expected.error) {
            (_, Some(error)) => json!({ "id": id, "error": error }),
            (Some(result), None) => json!({ "id": id, "result": result }),
            (None, None) => json!({ "id": id, "result": {} }),
        };
        if write_json_line(&mut server_output, &response)
            .await
            .is_err()
        {
            return;
        }
        for chunk in expected.after_response {
            let write_result = match chunk {
                ScriptedAppChunk::Json(value) => write_json_line(&mut server_output, &value).await,
                ScriptedAppChunk::Line(line) => write_text_line(&mut server_output, &line).await,
                ScriptedAppChunk::SleepMillis(millis) => {
                    sleep(Duration::from_millis(millis)).await;
                    Ok(())
                }
            };
            if write_result.is_err() {
                return;
            }
        }
        if expected.close_output_after {
            return;
        }
    }
    if !requests.is_empty() {
        let remaining_methods = requests
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        let _ = write_text_line(
            &mut server_output,
            &format!(
                "codex-runner-error: scripted app-server ended with pending requests: {}",
                remaining_methods
            ),
        )
        .await;
    }
}

async fn write_json_line(
    output: &mut tokio::io::DuplexStream,
    value: &Value,
) -> std::io::Result<()> {
    let line = serde_json::to_string(value).expect("serialize scripted app-server response");
    write_text_line(output, &line).await
}

async fn write_text_line(output: &mut tokio::io::DuplexStream, line: &str) -> std::io::Result<()> {
    output.write_all(line.as_bytes()).await?;
    output.write_all(b"\n").await?;
    output.flush().await
}

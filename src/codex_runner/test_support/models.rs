use super::*;
use crate::codex_runner::browser_mcp::BrowserLaunchConfig;
use bollard::models::Mount;

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StartAppServerContainerRequest {
    pub(crate) image: String,
    pub(crate) cmd: Vec<String>,
    pub(crate) env: Vec<String>,
    pub(crate) binds: Vec<String>,
    pub(crate) mounts: Option<Vec<Mount>>,
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

#[derive(Debug, Clone, PartialEq)]
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
    pub(super) requests: VecDeque<ScriptedAppRequest>,
}

impl ScriptedAppServer {
    pub(crate) fn from_requests(requests: Vec<ScriptedAppRequest>) -> Self {
        Self {
            requests: requests.into(),
        }
    }
}

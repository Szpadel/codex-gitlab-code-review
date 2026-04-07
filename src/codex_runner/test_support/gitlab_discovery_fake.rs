use super::*;
use crate::gitlab_discovery_mcp::GitLabDiscoverySessionBinding;

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

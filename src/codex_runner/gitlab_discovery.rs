use super::{
    BTreeMap, ContainerInspectResponse, Context, DockerCodexRunner, FeatureFlagSnapshot,
    GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID, GitLabDiscoveryMcpService, NewRunHistoryEvent,
    ResolvedGitLabDiscoveryAllowList, Result, RunnerRuntime, Url, Utc, annotate_event_payload,
    async_trait, debug, json, shell_quote, warn,
};
use crate::gitlab_discovery_mcp::GitLabDiscoverySessionBinding;
use std::collections::BTreeSet;

#[async_trait]
pub(crate) trait GitLabDiscoveryHandle: Send + Sync {
    fn server_name(&self) -> &str;
    fn advertise_url(&self) -> &str;
    fn clone_root(&self) -> &str;
    fn resolve_allow_list(&self, source_repo: &str) -> ResolvedGitLabDiscoveryAllowList;
    async fn register_binding(&self, binding: GitLabDiscoverySessionBinding);
    async fn remove_binding(&self, network_container_id: &str);
}

#[async_trait]
impl GitLabDiscoveryHandle for GitLabDiscoveryMcpService {
    fn server_name(&self) -> &str {
        self.server_name()
    }

    fn advertise_url(&self) -> &str {
        self.advertise_url()
    }

    fn clone_root(&self) -> &str {
        self.clone_root()
    }

    fn resolve_allow_list(&self, source_repo: &str) -> ResolvedGitLabDiscoveryAllowList {
        self.resolve_allow_list(source_repo)
    }

    async fn register_binding(&self, binding: GitLabDiscoverySessionBinding) {
        self.registry().register_binding(binding).await;
    }

    async fn remove_binding(&self, network_container_id: &str) {
        self.registry().remove_binding(network_container_id).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitLabDiscoveryMcpRuntimeConfig {
    pub(crate) server_name: String,
    pub(crate) advertise_url: String,
    pub(crate) clone_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedGitLabDiscoveryMcp {
    pub(crate) source_repo: String,
    pub(crate) feature_flags: FeatureFlagSnapshot,
    pub(crate) allow: ResolvedGitLabDiscoveryAllowList,
    pub(crate) runtime_config: GitLabDiscoveryMcpRuntimeConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RegisteredGitLabDiscoverySession {
    pub(crate) network_container_id: String,
    pub(crate) peer_ips: BTreeSet<String>,
}

impl DockerCodexRunner {
    pub(crate) fn prepare_gitlab_discovery_mcp(
        &self,
        source_repo: &str,
        feature_flags: &FeatureFlagSnapshot,
        mcp_server_overrides: &BTreeMap<String, bool>,
    ) -> Option<PreparedGitLabDiscoveryMcp> {
        if !feature_flags.gitlab_discovery_mcp {
            return None;
        }
        if source_repo.trim().is_empty() {
            return None;
        }
        let service = self.gitlab_discovery_mcp.as_ref()?;
        if matches!(mcp_server_overrides.get(service.server_name()), Some(false)) {
            return None;
        }
        let allow = service.resolve_allow_list(source_repo);
        if allow.target_repos.is_empty() && allow.target_groups.is_empty() {
            return None;
        }
        Some(PreparedGitLabDiscoveryMcp {
            source_repo: source_repo.to_string(),
            feature_flags: feature_flags.clone(),
            allow,
            runtime_config: GitLabDiscoveryMcpRuntimeConfig {
                server_name: service.server_name().to_string(),
                advertise_url: service.advertise_url().to_string(),
                clone_root: service.clone_root().to_string(),
            },
        })
    }

    pub(crate) fn effective_feature_flags(
        requested: &FeatureFlagSnapshot,
        gitlab_discovery_enabled: bool,
    ) -> FeatureFlagSnapshot {
        FeatureFlagSnapshot {
            gitlab_discovery_mcp: requested.gitlab_discovery_mcp && gitlab_discovery_enabled,
            gitlab_inline_review_comments: requested.gitlab_inline_review_comments,
            security_review: requested.security_review,
            security_context_ignore_base_head: requested.security_context_ignore_base_head,
            composer_install: requested.composer_install,
            composer_auto_repositories: requested.composer_auto_repositories,
            composer_safe_install: requested.composer_safe_install,
        }
    }

    pub(crate) async fn sync_effective_feature_flags(
        &self,
        run_history_id: Option<i64>,
        requested: &FeatureFlagSnapshot,
        gitlab_discovery_enabled: bool,
    ) {
        let Some(run_history_id) = run_history_id else {
            return;
        };
        let effective = Self::effective_feature_flags(requested, gitlab_discovery_enabled);
        if let Err(err) = self
            .state
            .set_run_history_feature_flags(run_history_id, &effective)
            .await
        {
            warn!(
                run_history_id,
                error = %err,
                "failed to persist effective feature flags for run"
            );
        }
    }

    pub(crate) fn gitlab_discovery_extra_hosts(
        &self,
        runtime_config: &GitLabDiscoveryMcpRuntimeConfig,
    ) -> Vec<String> {
        let Ok(advertise_url) = Url::parse(&runtime_config.advertise_url) else {
            return Vec::new();
        };
        match advertise_url.host_str() {
            Some("host.docker.internal") => vec!["host.docker.internal:host-gateway".to_string()],
            _ => Vec::new(),
        }
    }

    pub(crate) async fn register_gitlab_discovery_session(
        &self,
        prepared: Option<&PreparedGitLabDiscoveryMcp>,
        container_id: &str,
        network_container_id: &str,
        run_history_id: Option<i64>,
    ) -> Result<Option<RegisteredGitLabDiscoverySession>> {
        let (Some(service), Some(prepared)) = (self.gitlab_discovery_mcp.as_ref(), prepared) else {
            return Ok(None);
        };
        let peer_ips = self
            .collect_container_peer_ips(network_container_id)
            .await?;
        service
            .register_binding(GitLabDiscoverySessionBinding {
                run_history_id: run_history_id.unwrap_or_default(),
                container_id: container_id.to_string(),
                network_container_id: network_container_id.to_string(),
                peer_ips: peer_ips.clone(),
                source_repo: prepared.source_repo.clone(),
                clone_root: prepared.runtime_config.clone_root.clone(),
                feature_flags: prepared.feature_flags.clone(),
                allow: prepared.allow.clone(),
                created_at: Utc::now(),
            })
            .await;
        Ok(Some(RegisteredGitLabDiscoverySession {
            network_container_id: network_container_id.to_string(),
            peer_ips,
        }))
    }

    pub(crate) async fn probe_gitlab_discovery_mcp_endpoint(
        &self,
        prepared: Option<&PreparedGitLabDiscoveryMcp>,
        container_id: &str,
        registered: Option<&RegisteredGitLabDiscoverySession>,
        run_history_id: Option<i64>,
    ) {
        let Some(prepared) = prepared else {
            return;
        };
        let Some(command) = gitlab_discovery_mcp_probe_exec_command(&prepared.runtime_config)
        else {
            let detail = "unsupported advertise_url scheme for startup probe";
            warn!(
                container_id,
                url = prepared.runtime_config.advertise_url.as_str(),
                detail,
                "skipping gitlab discovery MCP reachability probe for unsupported advertise_url"
            );
            self.append_gitlab_discovery_mcp_startup_failure(
                run_history_id,
                prepared.runtime_config.advertise_url.as_str(),
                detail,
            )
            .await;
            return;
        };

        match self
            .exec_container_command(container_id, command, None)
            .await
        {
            Ok(output) => {
                let first_line = output
                    .stdout
                    .lines()
                    .map(str::trim)
                    .find(|line| {
                        matches!(
                            line.split_whitespace().next(),
                            Some("OK" | "ERROR" | "SKIP")
                        )
                    })
                    .or_else(|| {
                        output
                            .stdout
                            .lines()
                            .map(str::trim)
                            .find(|line| !line.is_empty())
                    })
                    .unwrap_or("");
                if first_line.starts_with("OK ") {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                    debug!(
                        container_id,
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
                        stdout = output.stdout.trim(),
                        stderr = output.stderr.trim(),
                        "gitlab discovery MCP endpoint passed startup probe"
                    );
                } else if first_line.starts_with("SKIP ") {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                    warn!(
                        container_id,
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
                        stdout = output.stdout.trim(),
                        stderr = output.stderr.trim(),
                        "gitlab discovery MCP reachability probe skipped inside review container"
                    );
                } else {
                    warn!(
                        container_id,
                        network_container_id =
                            registered.map_or("<unregistered>", |binding| binding
                                .network_container_id
                                .as_str()),
                        peer_ips = registered
                            .map(|binding| binding
                                .peer_ips
                                .iter()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(","))
                            .unwrap_or_default(),
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
                        stdout = output.stdout.trim(),
                        stderr = output.stderr.trim(),
                        "gitlab discovery MCP endpoint failed startup probe"
                    );
                    if first_line.is_empty() {
                        self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                            .await;
                        warn!(
                            container_id,
                            url = prepared.runtime_config.advertise_url.as_str(),
                            "gitlab discovery MCP startup probe returned no diagnostic output"
                        );
                    } else {
                        self.append_gitlab_discovery_mcp_startup_failure(
                            run_history_id,
                            prepared.runtime_config.advertise_url.as_str(),
                            first_line,
                        )
                        .await;
                    }
                }
            }
            Err(err) => {
                self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                    .await;
                warn!(
                    container_id,
                    url = prepared.runtime_config.advertise_url.as_str(),
                    network_container_id = registered
                        .map_or("<unregistered>", |binding| binding.network_container_id.as_str()),
                    peer_ips = registered
                        .map(|binding| binding.peer_ips.iter().cloned().collect::<Vec<_>>().join(","))
                        .unwrap_or_default(),
                    error = %err,
                    "gitlab discovery MCP startup probe could not run inside the review container"
                );
            }
        }
    }

    pub(crate) async fn append_gitlab_discovery_mcp_startup_failure(
        &self,
        run_history_id: Option<i64>,
        advertise_url: &str,
        detail: &str,
    ) {
        let message = format!(
            "GitLab discovery MCP startup warning: endpoint {advertise_url} {detail}. MCP tools may be unavailable in this run."
        );
        let events = gitlab_discovery_mcp_startup_failure_events(&message);
        self.replace_run_history_events_for_turn(
            run_history_id,
            GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID,
            &events,
        )
        .await;
    }

    pub(crate) async fn clear_gitlab_discovery_mcp_startup_failure(
        &self,
        run_history_id: Option<i64>,
    ) {
        self.replace_run_history_events_for_turn(
            run_history_id,
            GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID,
            &[],
        )
        .await;
    }

    pub(crate) async fn unregister_gitlab_discovery_session(
        &self,
        registered: Option<&RegisteredGitLabDiscoverySession>,
    ) {
        let (Some(service), Some(registered)) = (self.gitlab_discovery_mcp.as_ref(), registered)
        else {
            return;
        };
        service
            .remove_binding(&registered.network_container_id)
            .await;
    }
}

impl DockerCodexRunner {
    async fn collect_container_peer_ips(&self, container_id: &str) -> Result<BTreeSet<String>> {
        #[cfg(test)]
        if let RunnerRuntime::Fake(harness) = &self.runtime {
            return harness.collect_container_peer_ips(container_id).await;
        }

        #[cfg(test)]
        let docker = match &self.runtime {
            RunnerRuntime::Docker { docker, .. } => docker,
            RunnerRuntime::Fake(_) => unreachable!("fake runtime handled above"),
        };
        #[cfg(not(test))]
        let RunnerRuntime::Docker { docker, .. } = &self.runtime;
        let inspect = docker
            .inspect_container(
                container_id,
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .with_context(|| format!("inspect docker container {container_id} for MCP peer IPs"))?;
        let peer_ips = container_peer_ips(&inspect);
        anyhow::ensure!(
            !peer_ips.is_empty(),
            "container {container_id} has no registered IP addresses for GitLab discovery MCP"
        );
        Ok(peer_ips)
    }
}

fn container_peer_ips(inspect: &ContainerInspectResponse) -> BTreeSet<String> {
    let mut peer_ips = BTreeSet::new();
    if let Some(settings) = inspect.network_settings.as_ref()
        && let Some(networks) = settings.networks.as_ref()
    {
        for network in networks.values() {
            if let Some(ip_address) = network.ip_address.as_deref().map(str::trim)
                && !ip_address.is_empty()
            {
                peer_ips.insert(ip_address.to_string());
            }
            if let Some(ip_address) = network.global_ipv6_address.as_deref().map(str::trim)
                && !ip_address.is_empty()
            {
                peer_ips.insert(ip_address.to_string());
            }
        }
    }
    peer_ips
}

pub(crate) fn gitlab_discovery_mcp_startup_failure_events(
    message: &str,
) -> Vec<NewRunHistoryEvent> {
    let turn_id = Some(GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID.to_string());
    vec![
        NewRunHistoryEvent {
            sequence: 1,
            turn_id: turn_id.clone(),
            event_type: "turn_started".to_string(),
            payload: annotate_event_payload(json!({})),
        },
        NewRunHistoryEvent {
            sequence: 2,
            turn_id: turn_id.clone(),
            event_type: "item_completed".to_string(),
            payload: annotate_event_payload(json!({
                "type": "agentMessage",
                "phase": "system",
                "text": message,
            })),
        },
        NewRunHistoryEvent {
            sequence: 3,
            turn_id,
            event_type: "turn_completed".to_string(),
            payload: annotate_event_payload(json!({
                "status": "completed"
            })),
        },
    ]
}

pub(crate) fn gitlab_discovery_mcp_probe_exec_command(
    runtime_config: &GitLabDiscoveryMcpRuntimeConfig,
) -> Option<Vec<String>> {
    let parsed = Url::parse(&runtime_config.advertise_url).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return None;
    }

    let url_q = shell_quote(&runtime_config.advertise_url);
    let mut health_url = parsed.clone();
    let advertise_path = parsed.path();
    let health_path = advertise_path.strip_suffix("/mcp").map_or_else(
        || "/healthz".to_string(),
        |prefix| {
            if prefix.is_empty() {
                "/healthz".to_string()
            } else {
                format!("{prefix}/healthz")
            }
        },
    );
    health_url.set_path(&health_path);
    health_url.set_query(None);
    health_url.set_fragment(None);
    let health_url_q = shell_quote(health_url.as_str());
    let script = format!(
        r#"set -u
url={url_q}
health_url={health_url_q}
init_payload='{{"jsonrpc":"2.0","id":"probe-init","method":"initialize","params":{{"protocolVersion":"2025-03-26","capabilities":{{}},"clientInfo":{{"name":"codex-gitlab-review-probe","version":"0.0.0"}}}}}}'
initialized_payload='{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}'
tools_payload='{{"jsonrpc":"2.0","id":"probe-tools","method":"tools/list","params":{{}}}}'
log_info() {{
  printf 'INFO %s\n' "$1"
}}
hosts_line="$(grep -E '[[:space:]]host\.docker\.internal([[:space:]]|$)' /etc/hosts 2>/dev/null | tail -n 1 || true)"
if [ -n "$hosts_line" ]; then
  log_info "hosts $hosts_line"
fi
if command -v ip >/dev/null 2>&1; then
  default_route="$(ip route show default 2>/dev/null | head -n 1 || true)"
  if [ -n "$default_route" ]; then
    log_info "default-route $default_route"
  fi
fi
if command -v curl >/dev/null 2>&1; then
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  tools_body_file="$(mktemp)"
  health_body_file="$(mktemp)"
  curl_err_file="$(mktemp)"
  cleanup() {{
    rm -f "$headers_file" "$body_file" "$tools_body_file" "$health_body_file" "$curl_err_file"
  }}
  trap cleanup EXIT
  health_status="$(
    curl -sS -o "$health_body_file" --max-time 5 -w '%{{http_code}}' \
      "$health_url" 2>"$curl_err_file"
  )"
  health_curl_status=$?
  if [ "$health_curl_status" -ne 0 ]; then
    last_line="$(tail -n 1 "$curl_err_file" | tr -d '\r')"
    log_info "healthz skipped: $last_line"
  else
    health_body="$(tr -d '\r' <"$health_body_file")"
    if [ "$health_status" != "200" ] || [ "$health_body" != "OK" ]; then
      log_info "healthz unavailable: http $health_status body=${{health_body:-<empty>}}"
    else
      log_info "healthz ok"
    fi
  fi
  status="$(
    curl -sS -o "$body_file" -D "$headers_file" --max-time 5 -w '%{{http_code}}' \
      -X POST \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      --data "$init_payload" \
      "$url" 2>"$curl_err_file"
  )"
  curl_status=$?
  if [ "$curl_status" -eq 0 ]; then
    session_id="$(awk 'tolower($1)=="mcp-session-id:"{{print $2}}' "$headers_file" | tr -d '\r' | tail -n 1)"
    if [ -z "$session_id" ]; then
      printf 'ERROR initialize response missing mcp-session-id header (http %s)\n' "$status"
      exit 0
    fi
    close_session() {{
      curl -sS -o /dev/null --max-time 5 \
        -X DELETE \
        -H "MCP-Session-Id: $session_id" \
        "$url" >/dev/null 2>&1 || true
    }}
    curl -sS -o /dev/null --max-time 5 \
      -X POST \
      -H "MCP-Session-Id: $session_id" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      --data "$initialized_payload" \
      "$url" >/dev/null 2>&1 || true
    tools_status="$(
      curl -sS -o "$tools_body_file" --max-time 5 -w '%{{http_code}}' \
        -X POST \
        -H "MCP-Session-Id: $session_id" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        --data "$tools_payload" \
        "$url" 2>"$curl_err_file"
    )"
    tools_curl_status=$?
    if [ "$tools_curl_status" -ne 0 ]; then
      last_line="$(tail -n 1 "$curl_err_file" | tr -d '\r')"
      probe_result="ERROR tools/list request failed: $last_line"
    elif grep -Eq '"name"[[:space:]]*:[[:space:]]*"list_gitlab_paths"' "$tools_body_file" && grep -Eq '"name"[[:space:]]*:[[:space:]]*"inspect_gitlab_repo"' "$tools_body_file" && grep -Eq '"name"[[:space:]]*:[[:space:]]*"clone_gitlab_repo"' "$tools_body_file"; then
      probe_result='OK gitlab discovery MCP tools reachable'
    else
      probe_result="ERROR tools/list response missing GitLab discovery tools (http $tools_status)"
    fi
    printf '%s\n' "$probe_result"
    close_session
  else
    last_line="$(tail -n 1 "$curl_err_file" | tr -d '\r')"
    printf 'ERROR initialize request failed: %s\n' "$last_line"
  fi
elif command -v python3 >/dev/null 2>&1; then
  URL="$url" HEALTH_URL="$health_url" python3 - <<'PY'
import json
import os
import socket
import urllib.error
import urllib.request

def decode_mcp_response(response, body_bytes):
    body_text = body_bytes.decode()
    content_type = response.headers.get("Content-Type", "")
    if "text/event-stream" not in content_type:
        return body_text
    data_lines = []
    for line in body_text.splitlines():
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    return "\n".join(data_lines)

url = os.environ["URL"]
health_url = os.environ["HEALTH_URL"]
session_id = None
try:
    try:
        with urllib.request.urlopen(health_url, timeout=5) as response:
            health_body = response.read().decode().strip()
            if response.status != 200 or health_body != "OK":
                print(
                    f"INFO healthz unavailable: http {{response.status}} body={{health_body or '<empty>'}}"
                )
            else:
                print("INFO healthz ok")
    except urllib.error.HTTPError as err:
        print(f"INFO healthz unavailable: http {{err.code}} {{err.reason}}")
    except (urllib.error.URLError, socket.timeout) as err:
        print(f"INFO healthz skipped: {{err}}")
    init_request = urllib.request.Request(
        url,
        data=json.dumps(
            {{
                "jsonrpc": "2.0",
                "id": "probe-init",
                "method": "initialize",
                "params": {{
                    "protocolVersion": "2025-03-26",
                    "capabilities": {{}},
                    "clientInfo": {{"name": "codex-gitlab-review-probe", "version": "0.0.0"}},
                }},
            }}
        ).encode(),
        method="POST",
        headers={{
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }},
    )
    with urllib.request.urlopen(init_request, timeout=5) as response:
        session_id = response.headers.get("MCP-Session-Id")
        if not session_id:
            print(f"ERROR initialize response missing mcp-session-id header (http {{response.status}})")
        else:
            initialized_request = urllib.request.Request(
                url,
                data=json.dumps(
                    {{"jsonrpc": "2.0", "method": "notifications/initialized", "params": {{}}}}
                ).encode(),
                method="POST",
                headers={{
                    "MCP-Session-Id": session_id,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                }},
            )
            try:
                urllib.request.urlopen(initialized_request, timeout=5).read()
            except Exception:
                pass
            tools_request = urllib.request.Request(
                url,
                data=json.dumps(
                    {{"jsonrpc": "2.0", "id": "probe-tools", "method": "tools/list", "params": {{}}}}
                ).encode(),
                method="POST",
                headers={{
                    "MCP-Session-Id": session_id,
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                }},
            )
            with urllib.request.urlopen(tools_request, timeout=5) as tools_response:
                payload_text = decode_mcp_response(tools_response, tools_response.read())
                payload = json.loads(payload_text or "{{}}")
            tools = {{
                tool.get("name")
                for tool in payload.get("result", {{}}).get("tools", [])
                if isinstance(tool, dict)
            }}
            if {{"list_gitlab_paths", "inspect_gitlab_repo", "clone_gitlab_repo"}}.issubset(tools):
                print("OK gitlab discovery MCP tools reachable")
            else:
                print("ERROR tools/list response missing GitLab discovery tools")
except urllib.error.HTTPError as err:
    print(f"ERROR initialize request returned http {{err.code}} {{err.reason}}")
except (urllib.error.URLError, socket.timeout) as err:
    print(f"ERROR connect failure: {{err}}")
except Exception as err:
    print(f"ERROR {{err}}")
finally:
    if session_id:
        close_request = urllib.request.Request(
            url,
            method="DELETE",
            headers={{
                "MCP-Session-Id": session_id,
            }},
        )
        try:
            urllib.request.urlopen(close_request, timeout=5).read()
        except Exception:
            pass
PY
else
  printf 'SKIP no curl or python3 available\n'
fi
"#,
    );

    Some(vec!["/bin/bash".to_string(), "-lc".to_string(), script])
}

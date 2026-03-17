use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitLabDiscoveryMcpRuntimeConfig {
    pub(crate) server_name: String,
    pub(crate) advertise_url: String,
    pub(crate) bearer_token_env_var: String,
    pub(crate) clone_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedGitLabDiscoveryMcp {
    pub(crate) bearer_token: String,
    pub(crate) source_repo: String,
    pub(crate) feature_flags: FeatureFlagSnapshot,
    pub(crate) allow: ResolvedGitLabDiscoveryAllowList,
    pub(crate) runtime_config: GitLabDiscoveryMcpRuntimeConfig,
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
            bearer_token: generate_bearer_token(),
            source_repo: source_repo.to_string(),
            feature_flags: feature_flags.clone(),
            allow,
            runtime_config: GitLabDiscoveryMcpRuntimeConfig {
                server_name: service.server_name().to_string(),
                advertise_url: service.advertise_url().to_string(),
                bearer_token_env_var: service.bearer_token_env_var().to_string(),
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

    pub(crate) async fn register_gitlab_discovery_session(
        &self,
        prepared: Option<&PreparedGitLabDiscoveryMcp>,
        container_id: &str,
        run_history_id: Option<i64>,
    ) {
        let (Some(service), Some(prepared)) = (self.gitlab_discovery_mcp.as_ref(), prepared) else {
            return;
        };
        service
            .registry()
            .register_token(
                prepared.bearer_token.clone(),
                GitLabDiscoverySessionBinding {
                    run_history_id: run_history_id.unwrap_or_default(),
                    container_id: container_id.to_string(),
                    source_repo: prepared.source_repo.clone(),
                    clone_root: prepared.runtime_config.clone_root.clone(),
                    feature_flags: prepared.feature_flags.clone(),
                    allow: prepared.allow.clone(),
                    created_at: Utc::now(),
                },
            )
            .await;
    }

    pub(crate) async fn probe_gitlab_discovery_mcp_endpoint(
        &self,
        prepared: Option<&PreparedGitLabDiscoveryMcp>,
        container_id: &str,
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
                    .find(|line| !line.is_empty())
                    .unwrap_or("");
                if first_line.starts_with("OK ") {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                    debug!(
                        container_id,
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
                        "gitlab discovery MCP endpoint passed startup probe"
                    );
                } else if first_line.starts_with("SKIP ") {
                    self.clear_gitlab_discovery_mcp_startup_failure(run_history_id)
                        .await;
                    warn!(
                        container_id,
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
                        "gitlab discovery MCP reachability probe skipped inside review container"
                    );
                } else {
                    warn!(
                        container_id,
                        url = prepared.runtime_config.advertise_url.as_str(),
                        detail = first_line,
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
        prepared: Option<&PreparedGitLabDiscoveryMcp>,
    ) {
        let (Some(service), Some(prepared)) = (self.gitlab_discovery_mcp.as_ref(), prepared) else {
            return;
        };
        service
            .registry()
            .remove_token(&prepared.bearer_token)
            .await;
    }
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
    let auth_var_q = shell_quote(&runtime_config.bearer_token_env_var);
    let script = format!(
        r#"set -u
url={url_q}
auth_var={auth_var_q}
init_payload='{{"jsonrpc":"2.0","id":"probe-init","method":"initialize","params":{{"protocolVersion":"2025-03-26","capabilities":{{}},"clientInfo":{{"name":"codex-gitlab-review-probe","version":"0.0.0"}}}}}}'
initialized_payload='{{"jsonrpc":"2.0","method":"notifications/initialized","params":{{}}}}'
tools_payload='{{"jsonrpc":"2.0","id":"probe-tools","method":"tools/list","params":{{}}}}'
if command -v curl >/dev/null 2>&1; then
  auth_value="${{!auth_var-}}"
  if [ -z "$auth_value" ]; then
    printf 'ERROR missing bearer env %s\n' "$auth_var"
    exit 0
  fi
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  tools_body_file="$(mktemp)"
  cleanup() {{
    rm -f "$headers_file" "$body_file" "$tools_body_file"
  }}
  trap cleanup EXIT
  status="$(
    curl -sS -o "$body_file" -D "$headers_file" --max-time 5 -w '%{{http_code}}' \
      -X POST \
      -H "Authorization: Bearer $auth_value" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      --data "$init_payload" \
      "$url" 2>&1
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
        -H "Authorization: Bearer $auth_value" \
        -H "MCP-Session-Id: $session_id" \
        "$url" >/dev/null 2>&1 || true
    }}
    curl -sS -o /dev/null --max-time 5 \
      -X POST \
      -H "Authorization: Bearer $auth_value" \
      -H "MCP-Session-Id: $session_id" \
      -H "Content-Type: application/json" \
      -H "Accept: application/json, text/event-stream" \
      --data "$initialized_payload" \
      "$url" >/dev/null 2>&1 || true
    tools_status="$(
      curl -sS -o "$tools_body_file" --max-time 5 -w '%{{http_code}}' \
        -X POST \
        -H "Authorization: Bearer $auth_value" \
        -H "MCP-Session-Id: $session_id" \
        -H "Content-Type: application/json" \
        -H "Accept: application/json, text/event-stream" \
        --data "$tools_payload" \
        "$url" 2>&1
    )"
    tools_curl_status=$?
    if [ "$tools_curl_status" -ne 0 ]; then
      probe_result="ERROR tools/list request failed: $tools_status"
    elif grep -Eq '"name"[[:space:]]*:[[:space:]]*"list_gitlab_paths"' "$tools_body_file" && grep -Eq '"name"[[:space:]]*:[[:space:]]*"clone_gitlab_repo"' "$tools_body_file"; then
      probe_result='OK gitlab discovery MCP tools reachable'
    else
      probe_result="ERROR tools/list response missing GitLab discovery tools (http $tools_status)"
    fi
    printf '%s\n' "$probe_result"
    close_session
  else
    last_line="$(printf '%s\n' "$status" | tail -n 1)"
    printf 'ERROR initialize request failed: %s\n' "$last_line"
  fi
elif command -v python3 >/dev/null 2>&1; then
  URL="$url" AUTH_VAR="$auth_var" python3 - <<'PY'
import json
import os
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
auth_var = os.environ["AUTH_VAR"]
token = os.environ.get(auth_var, "")
if not token:
    print(f"ERROR missing bearer env {{auth_var}}")
else:
    session_id = None
    try:
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
                "Authorization": f"Bearer {{token}}",
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
                        "Authorization": f"Bearer {{token}}",
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
                        "Authorization": f"Bearer {{token}}",
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
                if {{"list_gitlab_paths", "clone_gitlab_repo"}}.issubset(tools):
                    print("OK gitlab discovery MCP tools reachable")
                else:
                    print("ERROR tools/list response missing GitLab discovery tools")
    except urllib.error.HTTPError as err:
        print(f"ERROR initialize request returned http {{err.code}} {{err.reason}}")
    except Exception as err:
        print(f"ERROR {{err}}")
    finally:
        if session_id:
            close_request = urllib.request.Request(
                url,
                method="DELETE",
                headers={{
                    "Authorization": f"Bearer {{token}}",
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
        url_q = url_q,
        auth_var_q = auth_var_q,
    );

    Some(vec!["/bin/bash".to_string(), "-lc".to_string(), script])
}

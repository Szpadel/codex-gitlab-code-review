use super::{
    AsyncWriteExt, Future, HashMap, LogOutput, NewRunHistoryEvent, Pin, RefCell, Result,
    SecondsFormat, SecurityReviewContentFlagged, StreamExt, Utc, Uuid, Value, VecDeque, anyhow,
    debug, info, json, warn,
};
use std::sync::{Arc, Mutex};

pub(crate) struct TurnNotificationContext<'a> {
    pub(crate) thread_id: &'a str,
    pub(crate) turn_id: &'a str,
    pub(crate) history_capture: &'a mut TurnHistoryCapture,
}

pub(crate) struct AppServerClient {
    pub(crate) input: Pin<Box<dyn tokio::io::AsyncWrite + Send>>,
    pub(crate) output:
        Pin<Box<dyn futures::Stream<Item = Result<LogOutput, bollard::errors::Error>> + Send>>,
    pub(crate) stdout_buffer: Vec<u8>,
    pub(crate) stderr_buffer: Vec<u8>,
    pub(crate) stdout_scan_offset: usize,
    pub(crate) stderr_scan_offset: usize,
    pub(crate) pending_notifications: VecDeque<Value>,
    pub(crate) pending_history: TurnHistoryCapture,
    pub(crate) reasoning_buffers: HashMap<String, ReasoningBuffer>,
    pub(crate) agent_message_buffers: HashMap<String, String>,
    pub(crate) command_output_buffers: HashMap<String, String>,
    pub(crate) recent_runner_errors: VecDeque<String>,
    pub(crate) log_all_json: bool,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppServerIoFailure {
    #[error("write codex app-server input")]
    WriteInput,
    #[error("codex app-server closed stdout")]
    ClosedStdout,
    #[error("read codex app-server output")]
    ReadOutput,
}

pub(crate) fn is_app_server_io_failure(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AppServerIoFailure>().is_some()
}

#[derive(Default)]
pub(crate) struct ReasoningBuffer {
    summary: String,
    text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TurnStreamNotificationOutcome {
    Continue,
    TurnCompleted,
}

#[derive(Default)]
pub(crate) struct TurnHistoryCapture {
    pub(crate) next_sequence: i64,
    pub(crate) events: Vec<NewRunHistoryEvent>,
    pending_on_drop: Option<Arc<Mutex<Vec<NewRunHistoryEvent>>>>,
}

pub(crate) const GITLAB_DISCOVERY_MCP_STARTUP_TURN_ID: &str = "gitlab-discovery-mcp-startup";

// Bound each SQLite transaction while reducing writes during notification bursts.
const HISTORY_EVENT_BATCH_SIZE: usize = 32;

impl TurnHistoryCapture {
    /// Move unflushed events to the outer cleanup when this capture is dropped.
    pub(crate) fn preserve_pending_on_drop(
        &mut self,
        retained_events: Arc<Mutex<Vec<NewRunHistoryEvent>>>,
    ) {
        self.pending_on_drop = Some(retained_events);
    }

    pub(crate) fn push(&mut self, turn_id: Option<&str>, event_type: &str, payload: Value) {
        self.next_sequence += 1;
        let payload = annotate_event_payload(payload);
        self.events.push(NewRunHistoryEvent {
            sequence: self.next_sequence,
            turn_id: turn_id.map(ToOwned::to_owned),
            event_type: event_type.to_string(),
            payload,
        });
    }

    pub(crate) fn take_pending(&mut self) -> Vec<NewRunHistoryEvent> {
        self.next_sequence = 0;
        std::mem::take(&mut self.events)
    }
}

impl Drop for TurnHistoryCapture {
    fn drop(&mut self) {
        if let Some(retained_events) = self.pending_on_drop.take() {
            retained_events
                .lock()
                .expect("pending transcript cleanup lock poisoned")
                .extend(self.take_pending());
        }
    }
}

pub(crate) fn annotate_event_payload(mut payload: Value) -> Value {
    if let Some(object) = payload.as_object_mut()
        && !object.contains_key("createdAt")
        && !object.contains_key("created_at")
        && !object.contains_key("timestamp")
    {
        object.insert(
            "createdAt".to_string(),
            Value::String(Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)),
        );
    }
    payload
}

impl AppServerClient {
    pub(crate) fn new(
        attach: bollard::container::AttachContainerResults,
        log_all_json: bool,
    ) -> Self {
        Self {
            input: attach.input,
            output: attach.output,
            stdout_buffer: Vec::new(),
            stderr_buffer: Vec::new(),
            stdout_scan_offset: 0,
            stderr_scan_offset: 0,
            pending_notifications: VecDeque::new(),
            pending_history: TurnHistoryCapture::default(),
            reasoning_buffers: HashMap::new(),
            agent_message_buffers: HashMap::new(),
            command_output_buffers: HashMap::new(),
            recent_runner_errors: VecDeque::new(),
            log_all_json,
        }
    }

    pub(crate) async fn initialize(&mut self) -> Result<()> {
        let response = self
            .request(
                "initialize",
                json!({
                "clientInfo": {
                    "name": "codex-gitlab-review",
                    "title": "Codex GitLab Review Service",
                    "version": env!("CARGO_PKG_VERSION"),
                    },
                    "capabilities": {
                        "experimentalApi": true,
                    }
                }),
            )
            .await?;
        debug!(response = ?response, "codex app-server initialized");
        Ok(())
    }

    pub(crate) async fn initialized(&mut self) -> Result<()> {
        self.send_json(&json!({ "method": "initialized" })).await
    }

    /// Retains the batch in the client if the persistence future is cancelled.
    pub(crate) async fn flush_pending_history<FPersist, FPersistFut>(
        &mut self,
        persist_events: &mut FPersist,
    ) where
        FPersist: FnMut(Vec<NewRunHistoryEvent>) -> FPersistFut,
        FPersistFut: Future<Output = ()>,
    {
        if self.pending_history.events.is_empty() {
            return;
        }
        persist_events(self.pending_history.events.clone()).await;
        self.pending_history.take_pending();
    }

    pub(crate) async fn stream_review<FPersist, FGitLab, FPersistFut, FGitLabFut>(
        &mut self,
        thread_id: &str,
        turn_id: &str,
        gitlab_discovery_server_name: Option<&str>,
        mut persist_events: FPersist,
        mut on_gitlab_discovery_success: FGitLab,
    ) -> Result<String>
    where
        FPersist: FnMut(Vec<NewRunHistoryEvent>) -> FPersistFut,
        FGitLab: FnMut() -> FGitLabFut,
        FPersistFut: Future<Output = ()>,
        FGitLabFut: Future<Output = ()>,
    {
        let mut review_text = None;
        let mut gitlab_discovery_success_observed = false;
        loop {
            let message = match self.next_notification().await {
                Ok(message) => message,
                Err(err) => {
                    self.flush_pending_history(&mut persist_events).await;
                    break Err(err);
                }
            };
            let method = message
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or("<unknown>");
            let params = message.get("params");
            if !matches_thread_turn(params, thread_id, turn_id) {
                continue;
            }

            let mut history_capture = std::mem::take(&mut self.pending_history);
            let outcome = self.handle_turn_notification(
                method,
                params,
                TurnNotificationContext {
                    thread_id,
                    turn_id,
                    history_capture: &mut history_capture,
                },
                |_, _| {},
                |item| {
                    if let Some(review) = item.get("review").and_then(|value| value.as_str())
                        && item.get("type").and_then(|value| value.as_str())
                            == Some("exitedReviewMode")
                    {
                        review_text = Some(review.to_string());
                    }
                    if item_is_successful_gitlab_discovery_call(item, gitlab_discovery_server_name)
                    {
                        gitlab_discovery_success_observed = true;
                    }
                },
            );
            self.pending_history = history_capture;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(err) => {
                    self.flush_pending_history(&mut persist_events).await;
                    if gitlab_discovery_success_observed {
                        on_gitlab_discovery_success().await;
                    }
                    break Err(err);
                }
            };
            if self.pending_history.events.len() >= HISTORY_EVENT_BATCH_SIZE
                || outcome == TurnStreamNotificationOutcome::TurnCompleted
            {
                self.flush_pending_history(&mut persist_events).await;
            }
            if gitlab_discovery_success_observed {
                on_gitlab_discovery_success().await;
                gitlab_discovery_success_observed = false;
            }
            if outcome == TurnStreamNotificationOutcome::TurnCompleted {
                break review_text.ok_or_else(|| anyhow!("codex review missing review text"));
            }
        }
    }

    pub(crate) async fn stream_turn_message<FPersist, FGitLab, FPersistFut, FGitLabFut>(
        &mut self,
        thread_id: &str,
        turn_id: &str,
        gitlab_discovery_server_name: Option<&str>,
        mut persist_events: FPersist,
        mut on_gitlab_discovery_success: FGitLab,
    ) -> Result<String>
    where
        FPersist: FnMut(Vec<NewRunHistoryEvent>) -> FPersistFut,
        FGitLab: FnMut() -> FGitLabFut,
        FPersistFut: Future<Output = ()>,
        FGitLabFut: Future<Output = ()>,
    {
        let final_message = RefCell::new(None);
        let message_deltas: RefCell<HashMap<String, String>> = RefCell::new(HashMap::new());
        let mut gitlab_discovery_success_observed = false;
        loop {
            let message = match self.next_notification().await {
                Ok(message) => message,
                Err(err) => {
                    self.flush_pending_history(&mut persist_events).await;
                    break Err(err);
                }
            };
            let method = message
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or("<unknown>");
            let params = message.get("params");
            if !matches_thread_turn(params, thread_id, turn_id) {
                continue;
            }

            let mut history_capture = std::mem::take(&mut self.pending_history);
            let outcome = self.handle_turn_notification(
                method,
                params,
                TurnNotificationContext {
                    thread_id,
                    turn_id,
                    history_capture: &mut history_capture,
                },
                |item_id, delta| {
                    if item_id != "<unknown>" {
                        message_deltas
                            .borrow_mut()
                            .entry(item_id.to_string())
                            .or_default()
                            .push_str(delta);
                    }
                },
                |item| {
                    if matches!(
                        item.get("type").and_then(|value| value.as_str()),
                        Some("agentMessage" | "AgentMessage")
                    ) {
                        let item_id = item
                            .get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let extracted = extract_agent_message_text(item)
                            .or_else(|| message_deltas.borrow_mut().remove(item_id))
                            .unwrap_or_default();
                        if !extracted.trim().is_empty() {
                            info!(
                                item_id,
                                kind = "agent",
                                message = extracted.as_str(),
                                "codex item message"
                            );
                            *final_message.borrow_mut() = Some(extracted);
                        }
                    }
                    if item_is_successful_gitlab_discovery_call(item, gitlab_discovery_server_name)
                    {
                        gitlab_discovery_success_observed = true;
                    }
                },
            );
            self.pending_history = history_capture;
            let outcome = match outcome {
                Ok(outcome) => outcome,
                Err(err) => {
                    self.flush_pending_history(&mut persist_events).await;
                    if gitlab_discovery_success_observed {
                        on_gitlab_discovery_success().await;
                    }
                    break Err(err);
                }
            };
            if self.pending_history.events.len() >= HISTORY_EVENT_BATCH_SIZE
                || outcome == TurnStreamNotificationOutcome::TurnCompleted
            {
                self.flush_pending_history(&mut persist_events).await;
            }
            if gitlab_discovery_success_observed {
                on_gitlab_discovery_success().await;
                gitlab_discovery_success_observed = false;
            }
            if outcome == TurnStreamNotificationOutcome::TurnCompleted {
                break if let Some(message) = final_message.into_inner() {
                    Ok(message)
                } else {
                    let fallback = message_deltas
                        .into_inner()
                        .into_values()
                        .find(|value| !value.trim().is_empty())
                        .unwrap_or_default();
                    Ok(fallback)
                };
            }
        }
    }

    pub(crate) fn handle_turn_notification<FDelta, FCompleted>(
        &mut self,
        method: &str,
        params: Option<&Value>,
        context: TurnNotificationContext<'_>,
        mut on_agent_message_delta: FDelta,
        mut on_item_completed: FCompleted,
    ) -> Result<TurnStreamNotificationOutcome>
    where
        FDelta: FnMut(&str, &str),
        FCompleted: FnMut(&Value),
    {
        let TurnNotificationContext {
            thread_id,
            turn_id,
            history_capture,
        } = context;
        match method {
            "turn/started" => {
                history_capture.push(
                    Some(turn_id_from_params(params).unwrap_or(turn_id)),
                    "turn_started",
                    json!({}),
                );
                info!(thread_id, turn_id, "codex turn started");
            }
            "item/agentMessage/delta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.agent_message_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .push_str(delta);
                    }
                    on_agent_message_delta(item_id, delta);
                }
            }
            "item/commandExecution/outputDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.command_output_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .push_str(delta);
                    }
                    info!(item_id, kind = "command", output = %delta, "codex command output");
                }
            }
            "item/reasoning/summaryTextDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.reasoning_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .summary
                            .push_str(delta);
                    }
                }
            }
            "item/reasoning/textDelta" => {
                if let Some(delta) = params
                    .and_then(|value| value.get("delta"))
                    .and_then(|value| value.as_str())
                {
                    let item_id = params
                        .and_then(|value| value.get("itemId"))
                        .and_then(|value| value.as_str())
                        .unwrap_or("<unknown>");
                    if item_id != "<unknown>" {
                        self.reasoning_buffers
                            .entry(item_id.to_string())
                            .or_default()
                            .text
                            .push_str(delta);
                    }
                }
            }
            "item/reasoning/summaryPartAdded" => {
                let item_id = params
                    .and_then(|value| value.get("itemId"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("<unknown>");
                if item_id != "<unknown>" {
                    let entry = self
                        .reasoning_buffers
                        .entry(item_id.to_string())
                        .or_default();
                    if !entry.summary.is_empty() {
                        entry.summary.push('\n');
                    }
                }
            }
            "item/started" => {
                if let Some(item) = params.and_then(|value| value.get("item"))
                    && let Some(item_type) = item.get("type").and_then(|value| value.as_str())
                {
                    match item_type {
                        "commandExecution" => {
                            let item_id = item
                                .get("id")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let command = item
                                .get("command")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let cwd = item
                                .get("cwd")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            let status = item
                                .get("status")
                                .and_then(|value| value.as_str())
                                .unwrap_or("<unknown>");
                            info!(item_id, command, cwd, status, "codex command started");
                        }
                        "reasoning" => {
                            if self.log_all_json {
                                debug!(item_type, "codex item started");
                            }
                        }
                        _ => {
                            info!(item_type, "codex item started");
                        }
                    }
                }
            }
            "item/completed" => {
                if let Some(item) = params.and_then(|value| value.get("item"))
                    && let Some(item_type) = item.get("type").and_then(|value| value.as_str())
                {
                    let event_turn_id = turn_id_from_params(params).unwrap_or(turn_id);
                    let mut completed_item = item.clone();
                    if item_type == "reasoning" {
                        if let Some(item_id) = item.get("id").and_then(|value| value.as_str())
                            && let Some(buffer) = self.reasoning_buffers.remove(item_id)
                        {
                            let summary = buffer.summary.trim().to_string();
                            let text = buffer.text.trim().to_string();
                            completed_item = enrich_reasoning_item(
                                item,
                                item_id,
                                summary.as_str(),
                                text.as_str(),
                            );
                            let reasoning_log = match (summary.is_empty(), text.is_empty()) {
                                (false, false) => format!("{summary}\n\n{text}"),
                                (false, true) => summary.clone(),
                                (true, false) => text.clone(),
                                (true, true) => String::new(),
                            };
                            if !reasoning_log.trim().is_empty() {
                                info!(
                                    item_id,
                                    reasoning = reasoning_log.as_str(),
                                    "codex reasoning completed"
                                );
                            }
                        }
                    } else if matches!(item_type, "agentMessage" | "AgentMessage") {
                        let item_id = item
                            .get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let buffered_message = (item_id != "<unknown>")
                            .then(|| self.agent_message_buffers.remove(item_id))
                            .flatten();
                        let extracted = extract_agent_message_text(item).or(buffered_message);
                        if let Some(message) = extracted
                            && !message.trim().is_empty()
                        {
                            completed_item = enrich_agent_message_item(item, message.as_str());
                        }
                    } else if item_type == "commandExecution" {
                        let item_id = item
                            .get("id")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        if let Some(output) = (item_id != "<unknown>")
                            .then(|| self.command_output_buffers.remove(item_id))
                            .flatten()
                            && !output.is_empty()
                        {
                            completed_item = enrich_command_execution_item(item, output.as_str());
                        }
                        let command = item
                            .get("command")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let cwd = item
                            .get("cwd")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let status = item
                            .get("status")
                            .and_then(|value| value.as_str())
                            .unwrap_or("<unknown>");
                        let exit_code = item.get("exitCode").and_then(serde_json::Value::as_i64);
                        let duration_ms =
                            item.get("durationMs").and_then(serde_json::Value::as_i64);
                        info!(
                            item_id,
                            command, cwd, status, exit_code, duration_ms, "codex command completed"
                        );
                    } else {
                        info!(item_type, "codex item completed");
                    }
                    history_capture.push(
                        Some(event_turn_id),
                        "item_completed",
                        completed_item.clone(),
                    );
                    on_item_completed(&completed_item);
                }
            }
            "rawResponse/completed" => {
                if let Some(payload) = params {
                    history_capture.push(
                        Some(turn_id_from_params(params).unwrap_or(turn_id)),
                        "raw_response_completed",
                        payload.clone(),
                    );
                }
            }
            "turn/completed" => {
                let status = params
                    .and_then(|value| value.get("turn"))
                    .and_then(|value| value.get("status"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown");
                let error_message = turn_completed_error_message(params);
                let payload = match error_message.as_deref() {
                    Some(error) => json!({ "status": status, "error": error }),
                    None => json!({ "status": status }),
                };
                history_capture.push(
                    Some(turn_id_from_params(params).unwrap_or(turn_id)),
                    "turn_completed",
                    payload,
                );
                info!(status, "codex turn completed");
                if status == "failed" {
                    let error_message = error_message.as_deref().unwrap_or("unknown error");
                    if SecurityReviewContentFlagged::matches(error_message) {
                        return Err(SecurityReviewContentFlagged.into());
                    }
                    return Err(anyhow!("codex turn failed: {error_message}"));
                }
                return Ok(TurnStreamNotificationOutcome::TurnCompleted);
            }
            "error" => {
                if let Some(error_message) = params
                    .and_then(|value| value.get("error"))
                    .and_then(|value| value.get("message"))
                    .and_then(|value| value.as_str())
                {
                    warn!(error_message, "codex error");
                }
            }
            _ => {
                if self.log_all_json {
                    debug!(method, "codex notification");
                }
            }
        }
        Ok(TurnStreamNotificationOutcome::Continue)
    }

    pub(crate) async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = Value::String(Uuid::new_v4().to_string());
        let request = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        self.send_json(&request).await?;

        loop {
            let message = self.next_message().await?;
            let method_name = message.get("method").and_then(|value| value.as_str());
            let message_id = message.get("id");
            if let (Some(method_name), Some(message_id)) = (method_name, message_id) {
                self.handle_server_request(method_name, message_id, message.get("params"))
                    .await?;
                continue;
            }
            if message_id == Some(&id) {
                if let Some(error) = message.get("error") {
                    return Err(anyhow!("codex app-server error: {error}"));
                }
                if let Some(result) = message.get("result") {
                    return Ok(result.clone());
                }
                return Err(anyhow!("codex app-server response missing result"));
            }
            if method_name.is_some() {
                self.pending_notifications.push_back(message);
            }
        }
    }

    pub(crate) async fn next_notification(&mut self) -> Result<Value> {
        if let Some(notification) = self.pending_notifications.pop_front() {
            return Ok(notification);
        }

        loop {
            let message = self.next_message().await?;
            let method = message.get("method").and_then(|value| value.as_str());
            let id = message.get("id");
            if let (Some(method), Some(id)) = (method, id) {
                self.handle_server_request(method, id, message.get("params"))
                    .await?;
                continue;
            }
            if method.is_some() {
                return Ok(message);
            }
        }
    }

    pub(crate) async fn handle_server_request(
        &mut self,
        method: &str,
        id: &Value,
        params: Option<&Value>,
    ) -> Result<()> {
        debug!(method, params = ?params, "codex app-server request");
        match method {
            "item/commandExecution/requestApproval" | "item/fileChange/requestApproval" => {
                self.send_json(&json!({
                    "id": id,
                    "result": { "decision": "accept" }
                }))
                .await
            }
            other => {
                warn!(method = other, "unsupported codex app-server request");
                self.send_json(&json!({
                    "id": id,
                    "error": { "message": "unsupported request" }
                }))
                .await
            }
        }
    }

    pub(crate) async fn send_json(&mut self, value: &Value) -> Result<()> {
        let line = serde_json::to_string(value)?;
        if self.log_all_json {
            debug!(json = %line, "codex app-server message");
        }
        if let Err(err) = self.input.write_all(line.as_bytes()).await {
            return Err(with_recent_runner_errors(
                anyhow!(err).context(AppServerIoFailure::WriteInput),
                &self.recent_runner_errors,
            ));
        }
        if let Err(err) = self.input.write_all(b"\n").await {
            return Err(with_recent_runner_errors(
                anyhow!(err).context(AppServerIoFailure::WriteInput),
                &self.recent_runner_errors,
            ));
        }
        if let Err(err) = self.input.flush().await {
            return Err(with_recent_runner_errors(
                anyhow!(err).context(AppServerIoFailure::WriteInput),
                &self.recent_runner_errors,
            ));
        }
        Ok(())
    }

    pub(crate) async fn next_message(&mut self) -> Result<Value> {
        loop {
            if let Some(line) =
                take_output_line(&mut self.stdout_buffer, &mut self.stdout_scan_offset)
            {
                let line = String::from_utf8_lossy(&line);
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if self.handle_runner_diagnostic(trimmed) {
                    continue;
                }
                if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
                    if self.log_all_json {
                        debug!(json = %trimmed, "codex app-server message");
                    }
                    return Ok(value);
                }
                if self.log_all_json {
                    debug!(line = %trimmed, "codex app-server non-json output");
                }
                continue;
            }

            match self.output.next().await {
                Some(Ok(output)) => match output {
                    LogOutput::StdOut { message } | LogOutput::Console { message } => {
                        self.stdout_buffer.extend_from_slice(&message);
                    }
                    LogOutput::StdErr { message } => {
                        self.stderr_buffer.extend_from_slice(&message);
                        while let Some(line) =
                            take_output_line(&mut self.stderr_buffer, &mut self.stderr_scan_offset)
                        {
                            let line = String::from_utf8_lossy(&line);
                            let trimmed = line.trim();
                            if !trimmed.is_empty() && !self.handle_runner_diagnostic(trimmed) {
                                debug!(line = %trimmed, "codex app-server stderr");
                            }
                        }
                    }
                    LogOutput::StdIn { .. } => {}
                },
                Some(Err(err)) => {
                    return Err(with_recent_runner_errors(
                        anyhow!(err).context(AppServerIoFailure::ReadOutput),
                        &self.recent_runner_errors,
                    ));
                }
                None => {
                    return Err(with_recent_runner_errors(
                        anyhow!(AppServerIoFailure::ClosedStdout),
                        &self.recent_runner_errors,
                    ));
                }
            }
        }
    }

    /// Log runner prefixes and retain errors for later I/O failures.
    fn handle_runner_diagnostic(&mut self, line: &str) -> bool {
        if line.starts_with("codex-runner:") || line.starts_with("codex-install:") {
            info!("{}", line);
        } else if line.starts_with("codex-runner-error:")
            || line.starts_with("codex-install-error:")
        {
            warn!("{}", line);
            self.push_runner_error(line);
        } else if line.starts_with("codex-runner-warn:") {
            warn!("{}", line);
        } else {
            return false;
        }
        true
    }

    pub(crate) fn push_runner_error(&mut self, line: &str) {
        const MAX_RECENT_RUNNER_ERRORS: usize = 8;
        self.recent_runner_errors.push_back(line.to_string());
        while self.recent_runner_errors.len() > MAX_RECENT_RUNNER_ERRORS {
            self.recent_runner_errors.pop_front();
        }
    }
}

/// Scan only new bytes. Reset the offset after a complete line is consumed.
fn take_output_line(buffer: &mut Vec<u8>, scan_offset: &mut usize) -> Option<Vec<u8>> {
    if let Some(position) = buffer[*scan_offset..]
        .iter()
        .position(|byte| *byte == b'\n')
    {
        let end = *scan_offset + position;
        *scan_offset = 0;
        return Some(buffer.drain(..=end).collect());
    }
    *scan_offset = buffer.len();
    None
}

pub(crate) fn matches_thread_turn(params: Option<&Value>, thread_id: &str, turn_id: &str) -> bool {
    let Some(params) = params else {
        return true;
    };
    let thread_matches = params
        .get("threadId")
        .and_then(|value| value.as_str())
        .is_none_or(|value| value == thread_id);
    let turn_matches = params
        .get("turnId")
        .and_then(|value| value.as_str())
        .is_none_or(|value| value == turn_id);
    thread_matches && turn_matches
}

pub(crate) fn turn_id_from_params(params: Option<&Value>) -> Option<&str> {
    params
        .and_then(|value| value.get("turnId"))
        .and_then(|value| value.as_str())
}

fn turn_completed_error_message(params: Option<&Value>) -> Option<String> {
    params
        .and_then(|value| value.get("turn"))
        .and_then(|value| value.get("error"))
        .and_then(|value| {
            value
                .get("message")
                .and_then(|message| message.as_str())
                .map(ToOwned::to_owned)
                .or_else(|| value.as_str().map(ToOwned::to_owned))
                .or_else(|| {
                    if value.is_null() {
                        None
                    } else {
                        Some(value.to_string())
                    }
                })
        })
        .filter(|value| !value.trim().is_empty())
}

pub(crate) fn item_is_successful_gitlab_discovery_call(
    item: &Value,
    gitlab_discovery_server_name: Option<&str>,
) -> bool {
    let Some(server_name) = gitlab_discovery_server_name else {
        return false;
    };
    item.get("type").and_then(|value| value.as_str()) == Some("mcpToolCall")
        && item.get("server").and_then(|value| value.as_str()) == Some(server_name)
        && item.get("status").and_then(|value| value.as_str()) == Some("completed")
        && item.get("error").is_none_or(Value::is_null)
}

pub(crate) fn enrich_reasoning_item(
    item: &Value,
    item_id: &str,
    summary: &str,
    text: &str,
) -> Value {
    let mut enriched = item.clone();
    let Some(object) = enriched.as_object_mut() else {
        return enriched;
    };
    let summary_fallback = if summary.trim().is_empty() {
        text
    } else {
        summary
    };
    let content_fallback = if text.trim().is_empty() {
        summary
    } else {
        text
    };
    if object
        .get("summary")
        .and_then(|value| value.as_array())
        .is_none_or(std::vec::Vec::is_empty)
    {
        object.insert("summary".to_string(), json!([summary_fallback]));
    }
    if object
        .get("content")
        .and_then(|value| value.as_array())
        .is_none_or(std::vec::Vec::is_empty)
    {
        object.insert("content".to_string(), json!([content_fallback]));
    }
    if object.get("id").and_then(|value| value.as_str()).is_none() {
        object.insert("id".to_string(), Value::String(item_id.to_string()));
    }
    enriched
}

pub(crate) fn enrich_agent_message_item(item: &Value, text: &str) -> Value {
    let mut enriched = item.clone();
    let Some(object) = enriched.as_object_mut() else {
        return enriched;
    };
    if object
        .get("text")
        .and_then(|value| value.as_str())
        .is_none_or(str::is_empty)
    {
        object.insert("text".to_string(), Value::String(text.to_string()));
    }
    enriched
}

pub(crate) fn enrich_command_execution_item(item: &Value, output: &str) -> Value {
    let mut enriched = item.clone();
    let Some(object) = enriched.as_object_mut() else {
        return enriched;
    };
    if object
        .get("aggregatedOutput")
        .and_then(|value| value.as_str())
        .is_none_or(str::is_empty)
    {
        object.insert(
            "aggregatedOutput".to_string(),
            Value::String(output.to_string()),
        );
    }
    enriched
}

pub(crate) fn extract_agent_message_text(item: &Value) -> Option<String> {
    if let Some(text) = item.get("text").and_then(Value::as_str)
        && !text.trim().is_empty()
    {
        return Some(text.to_string());
    }

    let content = item.get("content")?.as_array()?;
    let mut parts = Vec::new();
    for entry in content {
        if entry.get("type").and_then(|value| value.as_str()) == Some("Text")
            && let Some(text) = entry.get("text").and_then(|value| value.as_str())
            && !text.trim().is_empty()
        {
            parts.push(text.to_string());
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("\n\n"))
    }
}

pub(crate) fn with_recent_runner_errors(
    err: anyhow::Error,
    recent_runner_errors: &VecDeque<String>,
) -> anyhow::Error {
    if recent_runner_errors.is_empty() {
        err
    } else {
        err.context(format!(
            "recent runner errors: {}",
            recent_runner_errors
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(" | ")
        ))
    }
}

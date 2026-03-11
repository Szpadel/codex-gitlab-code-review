use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::state::{
    AuthLimitResetEntry, InProgressMentionCommand, InProgressReview, PersistedScanStatus,
    ProjectCatalogSummary, ReviewStateStore, RunHistoryEventRecord, RunHistoryKind,
    RunHistoryListQuery, RunHistoryRecord, ScanMode, ScanOutcome, ScanState,
};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;
use tracing::warn;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusSnapshot {
    pub generated_at: String,
    pub config: StatusConfigSnapshot,
    pub scan: StatusScanSnapshot,
    pub in_progress_reviews: Vec<InProgressReview>,
    pub in_progress_mentions: Vec<InProgressMentionCommand>,
    pub auth_limit_resets: Vec<AuthLimitResetEntry>,
    pub project_catalogs: Vec<ProjectCatalogSummary>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusConfigSnapshot {
    pub gitlab_base_url: String,
    pub bind_addr: String,
    pub run_once: bool,
    pub dry_run: bool,
    pub mention_commands_enabled: bool,
    pub browser_mcp_enabled: bool,
    pub max_concurrent: usize,
    pub schedule_cron: String,
    pub schedule_timezone: String,
    pub created_after: Option<String>,
    pub repo_targets: usize,
    pub repo_targets_all: bool,
    pub group_targets: usize,
    pub group_targets_all: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusScanSnapshot {
    pub scan_state: String,
    pub mode: Option<String>,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub outcome: Option<String>,
    pub error: Option<String>,
    pub next_scan_at: Option<String>,
}

#[derive(Clone)]
pub struct StatusService {
    config: StatusConfig,
    state: Arc<ReviewStateStore>,
    runner: Option<Arc<dyn CodexRunner>>,
}

#[derive(Clone)]
struct StatusConfig {
    gitlab_base_url: String,
    bind_addr: String,
    status_ui_enabled: bool,
    run_once: bool,
    dry_run: bool,
    mention_commands_enabled: bool,
    browser_mcp_enabled: bool,
    max_concurrent: usize,
    schedule_cron: String,
    schedule_timezone: String,
    repo_targets: usize,
    repo_targets_all: bool,
    group_targets: usize,
    group_targets_all: bool,
}

impl StatusService {
    pub fn new(
        config: Config,
        state: Arc<ReviewStateStore>,
        run_once: bool,
        runner: Option<Arc<dyn CodexRunner>>,
    ) -> Self {
        Self {
            config: StatusConfig {
                gitlab_base_url: config.gitlab.base_url,
                bind_addr: config.server.bind_addr,
                status_ui_enabled: config.server.status_ui_enabled,
                run_once,
                dry_run: config.review.dry_run,
                mention_commands_enabled: config.review.mention_commands.enabled,
                browser_mcp_enabled: config.codex.browser_mcp.enabled,
                max_concurrent: config.review.max_concurrent,
                schedule_cron: config.schedule.cron,
                schedule_timezone: config
                    .schedule
                    .timezone
                    .unwrap_or_else(|| "UTC".to_string()),
                repo_targets: config.gitlab.targets.repos.list().len(),
                repo_targets_all: config.gitlab.targets.repos.is_all(),
                group_targets: config.gitlab.targets.groups.list().len(),
                group_targets_all: config.gitlab.targets.groups.is_all(),
            },
            state,
            runner,
        }
    }

    pub(crate) fn status_ui_enabled(&self) -> bool {
        self.config.status_ui_enabled
    }

    pub async fn snapshot(&self) -> Result<StatusSnapshot> {
        let created_after = self.state.get_created_after().await?;
        let scan = self.state.get_scan_status().await?;
        Ok(StatusSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            config: StatusConfigSnapshot {
                gitlab_base_url: self.config.gitlab_base_url.clone(),
                bind_addr: self.config.bind_addr.clone(),
                run_once: self.config.run_once,
                dry_run: self.config.dry_run,
                mention_commands_enabled: self.config.mention_commands_enabled,
                browser_mcp_enabled: self.config.browser_mcp_enabled,
                max_concurrent: self.config.max_concurrent,
                schedule_cron: self.config.schedule_cron.clone(),
                schedule_timezone: self.config.schedule_timezone.clone(),
                created_after,
                repo_targets: self.config.repo_targets,
                repo_targets_all: self.config.repo_targets_all,
                group_targets: self.config.group_targets,
                group_targets_all: self.config.group_targets_all,
            },
            scan: scan_into_snapshot(scan),
            in_progress_reviews: self.state.list_in_progress_reviews().await?,
            in_progress_mentions: self.state.list_in_progress_mention_commands().await?,
            auth_limit_resets: self.state.list_auth_limit_reset_entries().await?,
            project_catalogs: self.state.list_project_catalog_summaries().await?,
        })
    }

    pub async fn mark_scan_started(&self, mode: ScanMode) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.state = ScanState::Scanning;
        scan.mode = Some(mode);
        scan.started_at = Some(Utc::now().to_rfc3339());
        scan.finished_at = None;
        scan.outcome = None;
        scan.error = None;
        scan.next_scan_at = None;
        self.state.set_scan_status(&scan).await
    }

    pub async fn mark_scan_finished(
        &self,
        mode: ScanMode,
        outcome: ScanOutcome,
        error: Option<String>,
    ) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.state = ScanState::Idle;
        scan.mode = Some(mode);
        if scan.started_at.is_none() {
            scan.started_at = Some(Utc::now().to_rfc3339());
        }
        scan.finished_at = Some(Utc::now().to_rfc3339());
        scan.outcome = Some(outcome);
        scan.error = error;
        self.state.set_scan_status(&scan).await
    }

    pub async fn set_next_scan_at(&self, next_scan_at: Option<DateTime<Utc>>) -> Result<()> {
        let mut scan = self.state.get_scan_status().await?;
        scan.next_scan_at = next_scan_at.map(|value| value.to_rfc3339());
        self.state.set_scan_status(&scan).await
    }

    pub async fn clear_next_scan_at(&self) -> Result<()> {
        self.state.clear_next_scan_at().await
    }

    pub async fn recover_startup_status(&self) -> Result<()> {
        self.reconcile_interrupted_run_history().await?;
        let mut scan = self.state.get_scan_status().await?;
        scan.next_scan_at = None;
        if scan.state == ScanState::Scanning {
            scan.state = ScanState::Idle;
            scan.outcome = Some(ScanOutcome::Failure);
            scan.finished_at = Some(Utc::now().to_rfc3339());
            scan.error = Some("scan interrupted by service restart".to_string());
        }
        self.state.set_scan_status(&scan).await
    }

    pub async fn reconcile_interrupted_run_history(&self) -> Result<()> {
        self.state
            .reconcile_interrupted_run_history("run interrupted by service restart")
            .await?;
        Ok(())
    }

    pub async fn history_snapshot(&self, query: HistoryQuery) -> Result<HistorySnapshot> {
        let runs = self
            .state
            .list_run_history(&RunHistoryListQuery {
                repo: query.repo.clone(),
                iid: query.iid,
                kind: query.kind,
                result: query.result.clone(),
                search: query.search.clone(),
                limit: query.limit,
            })
            .await?;
        Ok(HistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            filters: query,
            runs,
        })
    }

    pub async fn mr_history_snapshot(&self, repo: &str, iid: u64) -> Result<MrHistorySnapshot> {
        let runs = self.state.list_run_history_for_mr(repo, iid).await?;
        Ok(MrHistorySnapshot {
            generated_at: Utc::now().to_rfc3339(),
            repo: repo.to_string(),
            iid,
            runs,
        })
    }

    pub async fn run_detail_snapshot(&self, run_id: i64) -> Result<Option<RunDetailSnapshot>> {
        let Some(run) = self.state.get_run_history(run_id).await? else {
            return Ok(None);
        };
        let related_runs = self
            .state
            .list_run_history_for_mr(&run.repo, run.iid)
            .await?;
        let events = self.state.list_run_history_events(run.id).await?;
        let thread_from_events = thread_snapshot_from_events(&run, &events);
        let live_thread = if run.events_persisted_cleanly
            && thread_from_events
                .as_ref()
                .is_some_and(thread_snapshot_is_complete)
        {
            None
        } else {
            self.load_thread_snapshot(&run, thread_from_events.is_none())
                .await?
        };
        let thread = if !run.events_persisted_cleanly {
            live_thread.or(thread_from_events)
        } else {
            match (thread_from_events, live_thread) {
                (Some(persisted), Some(live)) => {
                    if thread_snapshot_is_richer(&live, &persisted) {
                        Some(live)
                    } else if thread_snapshot_is_complete(&persisted) {
                        Some(persisted)
                    } else {
                        Some(live)
                    }
                }
                (Some(persisted), None) => Some(persisted),
                (None, Some(live)) => Some(live),
                (None, None) => None,
            }
        };
        Ok(Some(RunDetailSnapshot {
            generated_at: Utc::now().to_rfc3339(),
            run,
            related_runs,
            thread,
        }))
    }

    async fn load_thread_snapshot(
        &self,
        run: &RunHistoryRecord,
        warn_on_error: bool,
    ) -> Result<Option<ThreadSnapshot>> {
        let Some(runner) = self.runner.as_ref() else {
            return Ok(None);
        };
        let Some(account_name) = run.auth_account_name.as_deref() else {
            return Ok(None);
        };
        let thread_id = run.review_thread_id.as_deref().or(run.thread_id.as_deref());
        let Some(thread_id) = thread_id else {
            return Ok(None);
        };
        let response = match runner.read_thread(account_name, thread_id).await {
            Ok(response) => response,
            Err(err) => {
                if warn_on_error {
                    warn!(
                        run_id = run.id,
                        repo = %run.repo,
                        iid = run.iid,
                        thread_id,
                        error = %err,
                        "failed to load thread history for run"
                    );
                }
                return Ok(None);
            }
        };
        let Some(thread) = response.get("thread") else {
            return Ok(None);
        };
        Ok(Some(parse_thread_snapshot(thread)))
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct HistoryQuery {
    pub repo: Option<String>,
    pub iid: Option<u64>,
    pub kind: Option<RunHistoryKind>,
    pub result: Option<String>,
    pub search: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct HistorySnapshot {
    pub generated_at: String,
    pub filters: HistoryQuery,
    pub runs: Vec<RunHistoryRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MrHistorySnapshot {
    pub generated_at: String,
    pub repo: String,
    pub iid: u64,
    pub runs: Vec<RunHistoryRecord>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RunDetailSnapshot {
    pub generated_at: String,
    pub run: RunHistoryRecord,
    pub related_runs: Vec<RunHistoryRecord>,
    pub thread: Option<ThreadSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadSnapshot {
    pub id: String,
    pub preview: String,
    pub status: String,
    pub turns: Vec<TurnSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TurnSnapshot {
    pub id: String,
    pub status: String,
    pub items: Vec<ThreadItemSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ThreadItemSnapshot {
    pub item_type: String,
    pub title: String,
    pub preview: Option<String>,
    pub body: Option<String>,
    pub meta: Vec<(String, String)>,
    pub timestamp: Option<String>,
}

fn scan_into_snapshot(scan: PersistedScanStatus) -> StatusScanSnapshot {
    StatusScanSnapshot {
        scan_state: match scan.state {
            ScanState::Idle => "idle".to_string(),
            ScanState::Scanning => "scanning".to_string(),
        },
        mode: scan.mode.map(|value| match value {
            ScanMode::Full => "full".to_string(),
            ScanMode::Incremental => "incremental".to_string(),
        }),
        started_at: scan.started_at,
        finished_at: scan.finished_at,
        outcome: scan.outcome.map(|value| match value {
            ScanOutcome::Success => "success".to_string(),
            ScanOutcome::Failure => "failure".to_string(),
        }),
        error: scan.error,
        next_scan_at: scan.next_scan_at,
    }
}

fn parse_thread_snapshot(thread: &Value) -> ThreadSnapshot {
    ThreadSnapshot {
        id: json_string(thread.get("id")).unwrap_or_else(|| "<unknown>".to_string()),
        preview: json_string(thread.get("preview")).unwrap_or_default(),
        status: json_string(thread.get("status")).unwrap_or_else(|| "unknown".to_string()),
        turns: thread
            .get("turns")
            .and_then(Value::as_array)
            .map(|turns| turns.iter().map(parse_turn_snapshot).collect())
            .unwrap_or_default(),
    }
}

fn thread_snapshot_from_events(
    run: &RunHistoryRecord,
    events: &[RunHistoryEventRecord],
) -> Option<ThreadSnapshot> {
    if events.is_empty() {
        return None;
    }
    let mut turns = Vec::<TurnSnapshot>::new();
    for event in events {
        let turn_id = event.turn_id.as_deref().unwrap_or("<unknown>");
        let turn = if let Some(existing) = turns.iter_mut().find(|entry| entry.id == turn_id) {
            existing
        } else {
            turns.push(TurnSnapshot {
                id: turn_id.to_string(),
                status: "in_progress".to_string(),
                items: Vec::new(),
            });
            turns.last_mut().expect("turn inserted")
        };
        match event.event_type.as_str() {
            "turn_started" => {}
            // Per-item timestamps must come from the item payload itself. The row-level
            // created_at is the append-batch write time and can be shared across multiple
            // events, so rendering it as an exact item timestamp would be misleading.
            "item_completed" => turn.items.push(parse_thread_item_snapshot(
                &event.payload,
                extract_item_timestamp(&event.payload),
            )),
            "turn_completed" => {
                turn.status = json_string(event.payload.get("status"))
                    .unwrap_or_else(|| "unknown".to_string());
            }
            _ => {}
        }
    }
    let status = turns
        .last()
        .map(|turn| turn.status.clone())
        .unwrap_or_else(|| "unknown".to_string());
    Some(ThreadSnapshot {
        id: run
            .review_thread_id
            .clone()
            .or_else(|| run.thread_id.clone())
            .unwrap_or_else(|| format!("run-{}", run.id)),
        preview: run.preview.clone().unwrap_or_default(),
        status,
        turns,
    })
}

fn thread_snapshot_is_complete(thread: &ThreadSnapshot) -> bool {
    !thread.turns.is_empty()
        && !thread.turns.iter().any(|turn| {
            matches!(turn.status.as_str(), "in_progress" | "unknown")
                || turn.items.is_empty()
                || turn
                    .items
                    .iter()
                    .any(|item| !thread_item_is_self_contained(item))
        })
}

fn thread_snapshot_is_richer(candidate: &ThreadSnapshot, baseline: &ThreadSnapshot) -> bool {
    if candidate.turns.len() > baseline.turns.len() {
        return true;
    }
    candidate
        .turns
        .iter()
        .zip(baseline.turns.iter())
        .any(|(candidate_turn, baseline_turn)| {
            candidate_turn.items.len() > baseline_turn.items.len()
        })
}

fn thread_item_is_self_contained(item: &ThreadItemSnapshot) -> bool {
    match item.item_type.as_str() {
        "agentMessage" | "AgentMessage" => {
            item.body.as_deref().is_some_and(|body| !body.is_empty())
        }
        "commandExecution" => item.body.as_deref().is_some_and(|body| !body.is_empty()),
        "reasoning" => item.body.as_deref().is_some_and(|body| !body.is_empty()),
        _ => true,
    }
}

fn parse_turn_snapshot(turn: &Value) -> TurnSnapshot {
    TurnSnapshot {
        id: json_string(turn.get("id")).unwrap_or_else(|| "<unknown>".to_string()),
        status: json_string(turn.get("status")).unwrap_or_else(|| "unknown".to_string()),
        items: turn
            .get("items")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .map(|item| parse_thread_item_snapshot(item, extract_item_timestamp(item)))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

fn parse_thread_item_snapshot(
    item: &serde_json::Value,
    timestamp: Option<String>,
) -> ThreadItemSnapshot {
    let item_type = json_string(item.get("type")).unwrap_or_else(|| "unknown".to_string());
    match item_type.as_str() {
        "userMessage" => ThreadItemSnapshot {
            item_type,
            title: "User message".to_string(),
            preview: None,
            body: Some(join_user_content(item.get("content"))),
            meta: Vec::new(),
            timestamp,
        },
        "agentMessage" | "AgentMessage" => ThreadItemSnapshot {
            item_type,
            title: "Agent message".to_string(),
            preview: None,
            body: json_string(item.get("text")).or_else(|| {
                let content = join_agent_message_content(item.get("content"));
                (!content.is_empty()).then_some(content)
            }),
            meta: phase_meta(item),
            timestamp,
        },
        "reasoning" => ThreadItemSnapshot {
            item_type,
            title: "Reasoning".to_string(),
            preview: None,
            body: Some(join_reasoning_content(item)),
            meta: Vec::new(),
            timestamp,
        },
        "commandExecution" => ThreadItemSnapshot {
            item_type,
            title: json_string(item.get("command")).unwrap_or_else(|| "Command".to_string()),
            preview: None,
            body: json_string(item.get("aggregatedOutput")),
            meta: vec![
                optional_meta("cwd", item.get("cwd")),
                optional_meta("status", item.get("status")),
                optional_meta("exit", item.get("exitCode")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp,
        },
        "mcpToolCall" => ThreadItemSnapshot {
            item_type,
            title: format!(
                "{}:{}",
                json_string(item.get("server")).unwrap_or_else(|| "mcp".to_string()),
                json_string(item.get("tool")).unwrap_or_else(|| "tool".to_string())
            ),
            preview: tool_call_preview(item),
            body: combine_detail_sections(&[
                ("Arguments", tool_call_arguments(item)),
                ("Result", item.get("result")),
                ("Error", item.get("error")),
            ]),
            meta: vec![
                optional_meta("status", item.get("status")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp,
        },
        "dynamicToolCall" => ThreadItemSnapshot {
            item_type,
            title: json_string(item.get("tool")).unwrap_or_else(|| "Dynamic tool".to_string()),
            preview: item
                .get("contentItems")
                .map(single_line_preview)
                .or_else(|| item.get("result").map(single_line_preview))
                .or_else(|| item.get("error").map(single_line_preview)),
            body: combine_detail_sections(&[
                ("Input", item.get("contentItems")),
                ("Result", item.get("result")),
                ("Error", item.get("error")),
            ]),
            meta: vec![
                optional_meta("status", item.get("status")),
                optional_meta("durationMs", item.get("durationMs")),
            ]
            .into_iter()
            .flatten()
            .collect(),
            timestamp,
        },
        "webSearch" => ThreadItemSnapshot {
            item_type,
            title: "Web search".to_string(),
            preview: json_string(item.get("query"))
                .or_else(|| item.get("action").map(single_line_preview)),
            body: item
                .get("action")
                .map(compact_json)
                .filter(|body| Some(body.as_str()) != json_string(item.get("query")).as_deref()),
            meta: Vec::new(),
            timestamp,
        },
        "fileChange" => {
            let summary = file_change_preview_and_body(item.get("changes"));
            ThreadItemSnapshot {
                item_type,
                title: "File change".to_string(),
                preview: summary.preview,
                body: summary.body,
                meta: vec![
                    optional_meta("status", item.get("status")),
                    Some(("bodyFormat".to_string(), summary.body_format.to_string())),
                    Some(("addedLines".to_string(), summary.added_lines.to_string())),
                    Some((
                        "removedLines".to_string(),
                        summary.removed_lines.to_string(),
                    )),
                ]
                .into_iter()
                .flatten()
                .collect(),
                timestamp,
            }
        }
        "enteredReviewMode" | "exitedReviewMode" => ThreadItemSnapshot {
            item_type: item_type.clone(),
            title: if item_type == "enteredReviewMode" {
                "Entered review mode".to_string()
            } else {
                "Exited review mode".to_string()
            },
            preview: None,
            body: json_string(item.get("review")),
            meta: Vec::new(),
            timestamp,
        },
        "contextCompaction" => ThreadItemSnapshot {
            item_type,
            title: "Context compaction".to_string(),
            preview: None,
            body: None,
            meta: Vec::new(),
            timestamp,
        },
        _ => ThreadItemSnapshot {
            item_type,
            title: "Event".to_string(),
            preview: None,
            body: Some(compact_json(item)),
            meta: Vec::new(),
            timestamp,
        },
    }
}

fn extract_item_timestamp(item: &Value) -> Option<String> {
    let value = item
        .get("createdAt")
        .or_else(|| item.get("created_at"))
        .or_else(|| item.get("timestamp"))?;
    match value {
        Value::Number(number) => number.as_i64().map(format_history_timestamp).or_else(|| {
            number
                .as_u64()
                .map(|value| format_history_timestamp(value as i64))
        }),
        Value::String(text) => format_history_timestamp_text(text).or_else(|| Some(text.clone())),
        _ => None,
    }
}

fn format_history_timestamp(timestamp: i64) -> String {
    DateTime::<Utc>::from_timestamp(normalize_unix_timestamp(timestamp), 0)
        .map(|value| value.format("%-I:%M %p UTC").to_string())
        .unwrap_or_else(|| timestamp.to_string())
}

fn normalize_unix_timestamp(timestamp: i64) -> i64 {
    if timestamp.unsigned_abs() >= 1_000_000_000_000 {
        timestamp / 1_000
    } else {
        timestamp
    }
}

fn format_history_timestamp_text(timestamp: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(timestamp).ok().map(|value| {
        value
            .with_timezone(&Utc)
            .format("%-I:%M %p UTC")
            .to_string()
    })
}

fn join_user_content(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    if item.get("type").and_then(Value::as_str) == Some("text") {
                        json_string(item.get("text"))
                    } else {
                        Some(compact_json(item))
                    }
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn join_agent_message_content(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item.get("type").and_then(Value::as_str) {
                    Some("Text") => json_string(item.get("text")),
                    _ => Some(compact_json(item)),
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .unwrap_or_default()
}

fn join_reasoning_content(item: &Value) -> String {
    const ENCRYPTED_REASONING_PLACEHOLDER: &str =
        "Reasoning is unavailable because Codex returned only encrypted history for this step.";
    let summary = join_reasoning_entries(item.get("summary"));
    let content = join_reasoning_entries(item.get("content"));
    match (summary.is_empty(), content.is_empty()) {
        (false, false) => format!("{summary}\n\n{content}"),
        (false, true) => summary,
        (true, false) => content,
        (true, true) => item
            .get("encrypted_content")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|_| ENCRYPTED_REASONING_PLACEHOLDER.to_string())
            .unwrap_or_default(),
    }
}

fn join_reasoning_entries(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(reasoning_entry_text)
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn reasoning_entry_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.clone()),
        Value::Object(_) => value
            .get("text")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .or_else(|| Some(compact_json(value))),
        _ => None,
    }
}

fn tool_call_arguments(item: &Value) -> Option<&Value> {
    item.get("arguments")
        .or_else(|| item.get("args"))
        .or_else(|| item.get("input"))
        .or_else(|| item.get("params"))
}

fn tool_call_preview(item: &Value) -> Option<String> {
    tool_call_arguments(item)
        .map(single_line_preview)
        .or_else(|| item.get("result").map(single_line_preview))
        .or_else(|| item.get("error").map(single_line_preview))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn join_reasoning_content_extracts_typed_summary_and_content_entries() {
        let item = json!({
            "type": "reasoning",
            "summary": [
                { "type": "summary_text", "text": "Typed reasoning summary" }
            ],
            "content": [
                { "type": "reasoning_text", "text": "Typed reasoning detail." }
            ]
        });

        assert_eq!(
            join_reasoning_content(&item),
            "Typed reasoning summary\n\nTyped reasoning detail."
        );
    }

    #[test]
    fn join_reasoning_content_returns_placeholder_for_encrypted_only_reasoning() {
        let item = json!({
            "type": "reasoning",
            "summary": [],
            "content": null,
            "encrypted_content": "opaque-reasoning-blob"
        });

        assert_eq!(
            join_reasoning_content(&item),
            "Reasoning is unavailable because Codex returned only encrypted history for this step."
        );
    }
}

fn combine_detail_sections(sections: &[(&str, Option<&Value>)]) -> Option<String> {
    let rendered = sections
        .iter()
        .filter_map(|(label, value)| value.map(|value| format!("{label}\n{}", compact_json(value))))
        .collect::<Vec<_>>();
    (!rendered.is_empty()).then(|| rendered.join("\n\n"))
}

fn single_line_preview(value: &Value) -> String {
    let compact = compact_json(value)
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    truncate_preview(&compact, 140)
}

fn truncate_preview(value: &str, max_chars: usize) -> String {
    let mut output = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            output.push('…');
            break;
        }
        output.push(ch);
    }
    output
}

struct FileChangeSummary {
    preview: Option<String>,
    body: Option<String>,
    body_format: &'static str,
    added_lines: usize,
    removed_lines: usize,
}

fn file_change_preview_and_body(changes: Option<&Value>) -> FileChangeSummary {
    #[derive(Serialize)]
    struct FileChangeBodySection {
        kind: &'static str,
        path: String,
        body: String,
    }

    let Some(changes) = changes.and_then(Value::as_object) else {
        return FileChangeSummary {
            preview: None,
            body: None,
            body_format: "payload",
            added_lines: 0,
            removed_lines: 0,
        };
    };
    let preview = match changes.len() {
        0 => None,
        1 => changes.keys().next().cloned(),
        count => Some(format!("{count} files changed")),
    };
    let sections = changes
        .iter()
        .map(|(path, value)| {
            if let Some(diff) = value.get("unified_diff").and_then(Value::as_str) {
                FileChangeBodySection {
                    kind: "diff",
                    path: path.clone(),
                    body: format!("diff --git a/{path} b/{path}\n{diff}"),
                }
            } else {
                FileChangeBodySection {
                    kind: "payload",
                    path: path.clone(),
                    body: compact_json(value),
                }
            }
        })
        .collect::<Vec<_>>();
    let (added_lines, removed_lines) = sections
        .iter()
        .filter(|section| section.kind == "diff")
        .map(|section| unified_diff_stats(&section.body))
        .fold(
            (0usize, 0usize),
            |(added_acc, removed_acc), (added, removed)| (added_acc + added, removed_acc + removed),
        );
    let has_diff = sections.iter().any(|section| section.kind == "diff");
    let has_payload = sections.iter().any(|section| section.kind == "payload");
    let (body, body_format) = if has_diff && has_payload {
        (serde_json::to_string(&sections).ok(), "mixed")
    } else if has_diff {
        (
            Some(
                sections
                    .into_iter()
                    .map(|section| section.body)
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            ),
            "diff",
        )
    } else {
        (
            Some(
                sections
                    .into_iter()
                    .map(|section| format!("{}\n{}", section.path, section.body))
                    .collect::<Vec<_>>()
                    .join("\n\n"),
            ),
            "payload",
        )
    };
    FileChangeSummary {
        preview,
        body: body.filter(|body| !body.is_empty()),
        body_format,
        added_lines,
        removed_lines,
    }
}

fn unified_diff_stats(diff: &str) -> (usize, usize) {
    diff.lines()
        .fold((0usize, 0usize), |(added, removed), line| {
            if line.starts_with('+') && !is_unified_diff_header(line) {
                (added + 1, removed)
            } else if line.starts_with('-') && !is_unified_diff_header(line) {
                (added, removed + 1)
            } else {
                (added, removed)
            }
        })
}

fn is_unified_diff_header(line: &str) -> bool {
    if line.starts_with("diff --git ") || line.starts_with("@@") {
        return true;
    }
    let Some(path) = line
        .strip_prefix("+++ ")
        .or_else(|| line.strip_prefix("--- "))
    else {
        return false;
    };
    let path = path.trim();
    path == "/dev/null" || path.starts_with("a/") || path.starts_with("b/")
}

fn phase_meta(item: &Value) -> Vec<(String, String)> {
    optional_meta("phase", item.get("phase"))
        .into_iter()
        .collect()
}

fn optional_meta(label: &str, value: Option<&Value>) -> Option<(String, String)> {
    json_string(value).map(|value| (label.to_string(), value))
}

fn json_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(number)) => Some(number.to_string()),
        Some(Value::Bool(value)) => Some(value.to_string()),
        Some(Value::Null) | None => None,
        Some(other) => Some(compact_json(other)),
    }
}

fn compact_json(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

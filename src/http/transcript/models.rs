use crate::http::timestamp::UiTimestamp;
use serde::Serialize;

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
    pub title: String,
    pub preview: Option<String>,
    pub body: Option<String>,
    pub timestamp: Option<String>,
    #[serde(skip)]
    pub(crate) ui_timestamp: Option<UiTimestamp>,
    #[serde(flatten)]
    pub kind: ThreadItemKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum ThreadItemKind {
    UserMessage,
    AgentMessage {
        phase: Option<String>,
    },
    Reasoning,
    CommandExecution {
        cwd: Option<String>,
        status: Option<String>,
        exit: Option<String>,
        #[serde(rename = "durationMs")]
        duration_ms: Option<String>,
    },
    McpToolCall {
        server: String,
        tool: String,
        status: Option<String>,
        #[serde(rename = "durationMs")]
        duration_ms: Option<String>,
    },
    DynamicToolCall {
        tool: String,
        status: Option<String>,
        #[serde(rename = "durationMs")]
        duration_ms: Option<String>,
    },
    WebSearch,
    FileChange {
        status: Option<String>,
        #[serde(rename = "bodyFormat")]
        body_format: FileChangeBodyFormat,
        #[serde(rename = "addedLines")]
        added_lines: usize,
        #[serde(rename = "removedLines")]
        removed_lines: usize,
    },
    ReviewModeTransition {
        entered: bool,
    },
    ContextCompaction,
    Unknown {
        event_type: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FileChangeBodyFormat {
    Diff,
    Mixed,
    Payload,
}

impl ThreadItemSnapshot {
    pub(crate) fn status(&self) -> Option<&str> {
        match &self.kind {
            ThreadItemKind::CommandExecution { status, .. }
            | ThreadItemKind::McpToolCall { status, .. }
            | ThreadItemKind::DynamicToolCall { status, .. }
            | ThreadItemKind::FileChange { status, .. } => status.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn duration_ms(&self) -> Option<&str> {
        match &self.kind {
            ThreadItemKind::CommandExecution { duration_ms, .. }
            | ThreadItemKind::McpToolCall { duration_ms, .. }
            | ThreadItemKind::DynamicToolCall { duration_ms, .. } => duration_ms.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn exit_code(&self) -> Option<&str> {
        match &self.kind {
            ThreadItemKind::CommandExecution { exit, .. } => exit.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn cwd(&self) -> Option<&str> {
        match &self.kind {
            ThreadItemKind::CommandExecution { cwd, .. } => cwd.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn phase(&self) -> Option<&str> {
        match &self.kind {
            ThreadItemKind::AgentMessage { phase } => phase.as_deref(),
            _ => None,
        }
    }

    pub(crate) fn file_change_format(&self) -> Option<FileChangeBodyFormat> {
        match &self.kind {
            ThreadItemKind::FileChange { body_format, .. } => Some(*body_format),
            _ => None,
        }
    }

    pub(crate) fn file_change_added_lines(&self) -> usize {
        match &self.kind {
            ThreadItemKind::FileChange { added_lines, .. } => *added_lines,
            _ => 0,
        }
    }

    pub(crate) fn file_change_removed_lines(&self) -> usize {
        match &self.kind {
            ThreadItemKind::FileChange { removed_lines, .. } => *removed_lines,
            _ => 0,
        }
    }

    pub(crate) fn kind_label(&self) -> &'static str {
        match &self.kind {
            ThreadItemKind::UserMessage => "User",
            ThreadItemKind::AgentMessage { .. } => "Agent",
            ThreadItemKind::Reasoning => "Reasoning",
            ThreadItemKind::CommandExecution { .. } => "Command",
            ThreadItemKind::McpToolCall { .. } => "MCP tool",
            ThreadItemKind::DynamicToolCall { .. } => "Dynamic tool",
            ThreadItemKind::WebSearch => "Web search",
            ThreadItemKind::FileChange { .. } => "File change",
            ThreadItemKind::ReviewModeTransition { .. } => "Review mode",
            ThreadItemKind::ContextCompaction => "System",
            ThreadItemKind::Unknown { .. } => "Activity",
        }
    }

    pub(crate) fn css_token(&self) -> &'static str {
        match &self.kind {
            ThreadItemKind::UserMessage => "user-message",
            ThreadItemKind::AgentMessage { .. } => "agent-message",
            ThreadItemKind::Reasoning => "reasoning",
            ThreadItemKind::CommandExecution { .. } => "command-execution",
            ThreadItemKind::McpToolCall { .. } => "mcp-tool-call",
            ThreadItemKind::DynamicToolCall { .. } => "dynamic-tool-call",
            ThreadItemKind::WebSearch => "web-search",
            ThreadItemKind::FileChange { .. } => "file-change",
            ThreadItemKind::ReviewModeTransition { .. } => "review-mode-transition",
            ThreadItemKind::ContextCompaction => "context-compaction",
            ThreadItemKind::Unknown { .. } => "unknown",
        }
    }
}

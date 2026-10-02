use crate::state::{ReviewStateStore, RunHistoryFinish};
use anyhow::Result;
use chrono::Utc;

#[derive(Clone, Debug)]
pub(crate) struct ScheduledTaskContext {
    pub(crate) repo: String,
    pub(crate) iid: u64,
    pub(crate) head_sha: String,
    pub(crate) run_history_id: i64,
}

impl ScheduledTaskContext {
    pub(crate) fn new(repo: &str, iid: u64, head_sha: &str, run_history_id: i64) -> Self {
        Self {
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
            run_history_id,
        }
    }
}

pub(crate) fn task_cancelled_finish(result: &str, preview: String) -> RunHistoryFinish {
    RunHistoryFinish {
        result: result.to_string(),
        preview: Some(preview),
        ..RunHistoryFinish::default()
    }
}

pub(crate) fn task_error_finish(
    result: &str,
    preview: String,
    err: &anyhow::Error,
) -> RunHistoryFinish {
    RunHistoryFinish {
        result: result.to_string(),
        preview: Some(preview),
        error: Some(format!("{err:#}")),
        ..RunHistoryFinish::default()
    }
}

pub(crate) async fn finish_task_run_history(
    state: &ReviewStateStore,
    task: &ScheduledTaskContext,
    finish: RunHistoryFinish,
) -> Result<()> {
    state
        .run_history
        .finish_run_history(task.run_history_id, finish)
        .await
}

pub(crate) async fn refund_review_rate_limits(
    state: &ReviewStateStore,
    acquired_rule_ids: &[String],
) -> Result<()> {
    if acquired_rule_ids.is_empty() {
        return Ok(());
    }
    state
        .review_rate_limit
        .refund_review_rate_limit_buckets(acquired_rule_ids, Utc::now().timestamp())
        .await
}

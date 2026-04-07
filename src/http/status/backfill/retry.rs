use crate::state::RunHistoryRecord;
use crate::transcript_backfill::{
    TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR, TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR,
};
use chrono::Utc;
use std::time::Duration;

pub(super) const TRANSCRIPT_BACKFILL_RETRY_COOLDOWN: Duration = Duration::from_secs(1);
pub(super) const TRANSCRIPT_BACKFILL_MISSING_HISTORY_RETRY_WINDOW: Duration =
    Duration::from_secs(5 * 60);

pub(crate) const TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR: &str =
    "matching Codex session history was not found";
pub(crate) const TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR: &str =
    "local session history remained incomplete after retry window";
pub(crate) const TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR: &str =
    "matching Codex session history was not found before retry window expired";
pub(crate) const TRANSCRIPT_BACKFILL_STALE_SOURCE_UNAVAILABLE_ERROR: &str =
    "local Codex session history directory remained unavailable before retry window expired";

pub(crate) fn should_retry_transcript_backfill_error(run: &RunHistoryRecord, error: &str) -> bool {
    if is_retry_window_backfill_error(error) {
        return missing_history_retry_window_open(run, Utc::now().timestamp());
    }
    is_retryable_transcript_backfill_error(error)
}

pub(crate) fn should_retry_transcript_backfill_failure(
    run: &RunHistoryRecord,
    error: &str,
    retry_window_open_at_attempt_start: bool,
) -> bool {
    should_retry_transcript_backfill_error(run, error)
        || (retry_window_open_at_attempt_start && is_retry_window_backfill_error(error))
}

pub(crate) fn is_final_retry_window_attempt_pending(run: &RunHistoryRecord, error: &str) -> bool {
    is_retry_window_backfill_error(error)
        && !missing_history_retry_window_open(run, Utc::now().timestamp())
}

fn is_retry_window_backfill_error(error: &str) -> bool {
    matches!(
        error,
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR
            | TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
            | TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR
    )
}

pub(crate) fn terminal_transcript_backfill_error_text(error: &str, should_retry: bool) -> String {
    if should_retry {
        return error.to_string();
    }
    match error {
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR.to_string()
        }
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR.to_string()
        }
        TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR => {
            TRANSCRIPT_BACKFILL_STALE_SOURCE_UNAVAILABLE_ERROR.to_string()
        }
        _ => error.to_string(),
    }
}

pub(crate) fn missing_history_retry_window_open(run: &RunHistoryRecord, now: i64) -> bool {
    let reference = run.finished_at.unwrap_or(run.updated_at);
    let retry_window = i64::try_from(TRANSCRIPT_BACKFILL_MISSING_HISTORY_RETRY_WINDOW.as_secs())
        .unwrap_or(i64::MAX);
    now.saturating_sub(reference) <= retry_window
}

fn is_retryable_transcript_backfill_error(error: &str) -> bool {
    error == TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR
        || error == TRANSCRIPT_BACKFILL_SOURCE_UNAVAILABLE_ERROR
}

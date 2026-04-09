mod admin_service;
mod backfill;
mod http_services;
mod models;
mod rate_limit_service;
mod skills_service;
mod status_service;

pub use super::transcript::ThreadSnapshot;
pub use admin_service::AdminService;
pub use backfill::BackfillService;
pub use http_services::HttpServices;
pub use models::{
    HistoryQuery, HistorySnapshot, MrHistorySnapshot, RunDetailSnapshot, SecurityContextPreview,
    StatusConfigSnapshot, StatusFeatureFlagSnapshot, StatusRateLimitSnapshot, StatusSnapshot,
    TranscriptBackfillSnapshot,
};
pub use rate_limit_service::RateLimitService;
pub use skills_service::SkillsService;
pub use status_service::StatusService;

#[cfg(test)]
pub(crate) use backfill::{
    TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR, TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR,
    TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR, events_have_missing_review_child_history,
    fallback_session_history_path, initial_backfill_candidate_events,
    is_final_retry_window_attempt_pending, merge_recovered_target_turn_events,
    missing_history_retry_window_open, missing_review_child_history_has_renderable_fallback,
    persisted_turn_ids_are_covered, preserve_auxiliary_persisted_events,
    primary_session_history_path, run_transcript_backfill, sanitize_persisted_events_for_backfill,
    should_retry_transcript_backfill_error, should_retry_transcript_backfill_failure,
    strip_missing_review_child_history_markers, terminal_transcript_backfill_error_text,
    turn_ids_from_new_events,
};

#[cfg(test)]
mod tests;

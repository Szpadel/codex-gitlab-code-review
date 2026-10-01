//! Admission policy for automatic reviews, including pending retries.

use crate::gitlab::MergeRequest;
use chrono::{DateTime, Utc};

#[derive(Debug)]
pub(super) enum ReviewSkipReason {
    NotOpened,
    Draft,
    MissingCreatedAt,
    BeforeCutoff,
}

/// Requires an opened, non-draft MR with a creation time after the cutoff.
pub(super) fn review_skip_reason(
    mr: &MergeRequest,
    created_after: DateTime<Utc>,
) -> Option<ReviewSkipReason> {
    if mr.state.as_deref() != Some("opened") {
        return Some(ReviewSkipReason::NotOpened);
    }
    if mr.draft {
        return Some(ReviewSkipReason::Draft);
    }
    let Some(created_at) = mr.created_at else {
        return Some(ReviewSkipReason::MissingCreatedAt);
    };
    if created_at <= created_after {
        return Some(ReviewSkipReason::BeforeCutoff);
    }
    None
}

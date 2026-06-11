use crate::review::ReviewLane;
use crate::state::PROJECT_RATE_LIMIT_SUBJECT_IID;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitScope {
    Project,
    MergeRequest,
}

impl ReviewRateLimitScope {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Project => "project",
            Self::MergeRequest => "merge_request",
        }
    }

    pub(crate) fn subject_iid(self, iid: Option<u64>) -> i64 {
        match self {
            Self::Project => PROJECT_RATE_LIMIT_SUBJECT_IID,
            Self::MergeRequest => iid
                .and_then(|value| i64::try_from(value).ok())
                .unwrap_or(PROJECT_RATE_LIMIT_SUBJECT_IID),
        }
    }

    pub(crate) fn display_iid(self, subject_iid: i64) -> Option<u64> {
        match self {
            Self::Project => None,
            Self::MergeRequest if subject_iid <= 0 => None,
            Self::MergeRequest => u64::try_from(subject_iid).ok(),
        }
    }
}

impl FromStr for ReviewRateLimitScope {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "project" => Ok(Self::Project),
            "merge_request" => Ok(Self::MergeRequest),
            other => bail!("invalid review rate limit scope: {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitTargetKind {
    Repo,
    Group,
}

impl ReviewRateLimitTargetKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Repo => "repo",
            Self::Group => "group",
        }
    }
}

impl FromStr for ReviewRateLimitTargetKind {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "repo" => Ok(Self::Repo),
            "group" => Ok(Self::Group),
            other => bail!("invalid review rate limit target kind: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewRateLimitTarget {
    pub kind: ReviewRateLimitTargetKind,
    pub path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewRateLimitBucketMode {
    Shared,
    Independent,
}

impl ReviewRateLimitBucketMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Independent => "independent",
        }
    }
}

impl FromStr for ReviewRateLimitBucketMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "shared" => Ok(Self::Shared),
            "independent" => Ok(Self::Independent),
            other => bail!("invalid review rate limit bucket mode: {other}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewRateLimitRule {
    pub id: String,
    pub label: String,
    pub scope_repo: String,
    pub targets: Vec<ReviewRateLimitTarget>,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub scope_iid: Option<u64>,
    pub scope_subject: String,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub scope: ReviewRateLimitScope,
    pub capacity: u32,
    pub window_seconds: u64,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewRateLimitRuleUpsert {
    pub id: Option<String>,
    pub label: String,
    pub targets: Vec<ReviewRateLimitTarget>,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub scope_iid: Option<u64>,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub scope: ReviewRateLimitScope,
    pub capacity: u32,
    pub window_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ReviewRateLimitBucketSnapshot {
    pub bucket_id: String,
    pub rule_id: String,
    pub rule_label: String,
    pub bucket_mode: ReviewRateLimitBucketMode,
    pub target_kind: ReviewRateLimitTargetKind,
    pub target_path: String,
    pub scope_repo: String,
    pub scope_iid: Option<u64>,
    pub scope_subject: String,
    pub scope: ReviewRateLimitScope,
    pub repo: String,
    pub iid: Option<u64>,
    pub applies_to_review: bool,
    pub applies_to_security: bool,
    pub available_slots: f64,
    pub capacity: u32,
    pub window_seconds: u64,
    pub updated_at: i64,
    pub next_slot_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReviewRateLimitPendingEntry {
    pub lane: ReviewLane,
    pub repo: String,
    pub iid: u64,
    pub first_blocked_at: i64,
    pub last_blocked_at: i64,
    pub last_seen_head_sha: String,
    pub next_retry_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewRateLimitAcquireOutcome {
    Unmatched,
    Acquired { bucket_ids: Vec<String> },
    Blocked { next_retry_at: i64 },
}

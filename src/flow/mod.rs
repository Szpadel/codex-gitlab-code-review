use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::flow::award_service::AwardService;
use crate::flow::mention::QueuedMention;
use crate::flow::review::QueuedReview;
use crate::flow::run_queue::{JobKey, QueueJob};
use crate::gitlab::GitLabApi;
use crate::lifecycle::ServiceLifecycle;
use crate::review_lane::ReviewLane;
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;

pub(crate) mod admission;
pub(crate) mod award_service;
mod comment_text;
pub(crate) mod mention;
pub(crate) mod mention_assets;
pub(crate) mod orchestration;
pub mod retry;
pub(crate) mod review;
pub(crate) mod review_comments;
mod review_project;
pub(crate) mod run_queue;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ActiveReviewKey {
    pub(crate) lane: ReviewLane,
    pub(crate) repo: String,
    pub(crate) iid: u64,
    pub(crate) head_sha: String,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ActiveMentionKey {
    pub(crate) repo: String,
    pub(crate) iid: u64,
    pub(crate) discussion_id: String,
    pub(crate) trigger_note_id: u64,
    pub(crate) head_sha: String,
}

/// Claims held by running reviews and mentions.
/// The scan coordinator refreshes these claims before it sweeps stale ones.
#[derive(Default)]
pub(crate) struct ActiveTaskRegistry {
    reviews: Mutex<HashSet<ActiveReviewKey>>,
    mentions: Mutex<HashSet<ActiveMentionKey>>,
}

impl ActiveTaskRegistry {
    pub(crate) fn track_review(self: &Arc<Self>, key: ActiveReviewKey) -> ActiveReviewGuard {
        self.reviews.lock().unwrap().insert(key.clone());
        ActiveReviewGuard {
            registry: Arc::clone(self),
            key: Some(key),
        }
    }

    pub(crate) fn track_mention(self: &Arc<Self>, key: ActiveMentionKey) -> ActiveMentionGuard {
        self.mentions.lock().unwrap().insert(key.clone());
        ActiveMentionGuard {
            registry: Arc::clone(self),
            key: Some(key),
        }
    }

    pub(crate) fn active_reviews(&self) -> Vec<ActiveReviewKey> {
        self.reviews.lock().unwrap().iter().cloned().collect()
    }

    pub(crate) fn active_mentions(&self) -> Vec<ActiveMentionKey> {
        self.mentions.lock().unwrap().iter().cloned().collect()
    }

    fn remove_review(&self, key: &ActiveReviewKey) {
        self.reviews.lock().unwrap().remove(key);
    }

    fn remove_mention(&self, key: &ActiveMentionKey) {
        self.mentions.lock().unwrap().remove(key);
    }
}

pub(crate) struct ActiveReviewGuard {
    registry: Arc<ActiveTaskRegistry>,
    key: Option<ActiveReviewKey>,
}

impl Drop for ActiveReviewGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.registry.remove_review(&key);
        }
    }
}

pub(crate) struct ActiveMentionGuard {
    registry: Arc<ActiveTaskRegistry>,
    key: Option<ActiveMentionKey>,
}

impl Drop for ActiveMentionGuard {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.registry.remove_mention(&key);
        }
    }
}

/// Repositories that the next incremental scan must read again, even without new MR activity.
///
/// A queued run that fails before its review or command finishes requests this. The scan
/// that queued the run may already have stored the repository activity marker.
#[derive(Default)]
pub(crate) struct RescanRequests {
    /// Request count per repository. A scan removes an entry only if the count did not change
    /// while it scanned, so a failure during that scan still forces the next one.
    counts: Mutex<HashMap<String, u64>>,
}

impl RescanRequests {
    pub(crate) fn request(&self, repo: &str) {
        *self
            .counts
            .lock()
            .unwrap()
            .entry(repo.to_string())
            .or_default() += 1;
    }

    /// Returns the request count to pass to `complete`, or `None` when no request exists.
    pub(crate) fn pending(&self, repo: &str) -> Option<u64> {
        self.counts.lock().unwrap().get(repo).copied()
    }

    /// Removes the request when no new request arrived since `pending` returned `count`.
    pub(crate) fn complete(&self, repo: &str, count: u64) {
        let mut counts = self.counts.lock().unwrap();
        if counts.get(repo) == Some(&count) {
            counts.remove(repo);
        }
    }
}

/// Shared dependencies for merge-request flows (review and mention).
#[derive(Clone)]
pub(crate) struct FlowShared {
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) award_service: AwardService,
    pub(crate) state: Arc<ReviewStateStore>,
    pub(crate) codex: Arc<dyn CodexRunner>,
    pub(crate) bot_user_id: u64,
    /// Automatic reviews ignore MRs created at or before this time.
    pub(crate) created_after: DateTime<Utc>,
    pub(crate) lifecycle: Arc<ServiceLifecycle>,
    pub(crate) active_tasks: Arc<ActiveTaskRegistry>,
    pub(crate) rescan_requests: Arc<RescanRequests>,
}

impl FlowShared {
    pub(crate) fn shutdown_requested(&self) -> bool {
        !self.lifecycle.accepts_new_work()
    }
}

/// Job type of the service run queue.
#[derive(Debug)]
pub(crate) enum FlowJob {
    Review(QueuedReview),
    /// Boxed because a mention carries its MR and discussion notes.
    Mention(Box<QueuedMention>),
}

impl QueueJob for FlowJob {
    fn key(&self) -> JobKey {
        match self {
            Self::Review(review) => review.key(),
            Self::Mention(mention) => mention.key(),
        }
    }

    fn head_sha(&self) -> &str {
        match self {
            Self::Review(review) => review.head_sha(),
            Self::Mention(mention) => mention.head_sha(),
        }
    }

    fn mention_branch(&self) -> Option<&str> {
        match self {
            Self::Review(review) => review.mention_branch(),
            Self::Mention(mention) => mention.mention_branch(),
        }
    }
}

#[async_trait]
pub(crate) trait MergeRequestFlow: Send + Sync {
    fn flow_name(&self) -> &'static str;

    async fn clear_stale_in_progress(&self) -> Result<()>;

    async fn recover_in_progress(&self) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::RescanRequests;

    #[test]
    fn rescan_request_survives_a_scan_that_started_before_it() {
        let requests = RescanRequests::default();

        requests.request("group/repo");
        let seen_by_scan = requests.pending("group/repo").expect("request exists");
        requests.request("group/repo");
        requests.complete("group/repo", seen_by_scan);
        let after_first_scan = requests.pending("group/repo");
        requests.complete("group/repo", after_first_scan.expect("request remains"));

        assert!(after_first_scan.is_some());
        assert_eq!(requests.pending("group/repo"), None);
    }
}

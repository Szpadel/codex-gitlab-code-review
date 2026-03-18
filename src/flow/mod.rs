use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::gitlab::GitLabApi;
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Semaphore;

pub(crate) mod mention;
pub(crate) mod review;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ActiveReviewKey {
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

#[derive(Clone)]
pub(crate) struct FlowShared {
    pub(crate) config: Config,
    pub(crate) gitlab: Arc<dyn GitLabApi>,
    pub(crate) state: Arc<ReviewStateStore>,
    pub(crate) codex: Arc<dyn CodexRunner>,
    pub(crate) bot_user_id: u64,
    pub(crate) semaphore: Arc<Semaphore>,
    pub(crate) shutdown: Arc<AtomicBool>,
    pub(crate) active_tasks: Arc<ActiveTaskRegistry>,
}

impl FlowShared {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: Config,
        gitlab: Arc<dyn GitLabApi>,
        state: Arc<ReviewStateStore>,
        codex: Arc<dyn CodexRunner>,
        bot_user_id: u64,
        semaphore: Arc<Semaphore>,
        shutdown: Arc<AtomicBool>,
        active_tasks: Arc<ActiveTaskRegistry>,
    ) -> Self {
        Self {
            config,
            gitlab,
            state,
            codex,
            bot_user_id,
            semaphore,
            shutdown,
            active_tasks,
        }
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

#[async_trait]
pub(crate) trait MergeRequestFlow: Send + Sync {
    fn flow_name(&self) -> &'static str;

    async fn clear_stale_in_progress(&self) -> Result<()>;

    async fn recover_in_progress(&self) -> Result<()>;
}

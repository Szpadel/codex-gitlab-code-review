use crate::codex_runner::CodexRunner;
use crate::config::Config;
use crate::gitlab::GitLabApi;
use crate::lifecycle::ServiceLifecycle;
use crate::review_lane::ReviewLane;
use crate::state::ReviewStateStore;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::{Notify, Semaphore};

pub(crate) mod mention;
pub(crate) mod mention_assets;
pub(crate) mod review;
pub(crate) mod review_comments;

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

#[derive(Default)]
pub(crate) struct ActiveTaskRegistry {
    reviews: Mutex<HashSet<ActiveReviewKey>>,
    mentions: Mutex<HashSet<ActiveMentionKey>>,
    active_count: AtomicUsize,
    idle_notify: Notify,
}

impl ActiveTaskRegistry {
    pub(crate) fn track_review(self: &Arc<Self>, key: ActiveReviewKey) -> ActiveReviewGuard {
        self.reviews.lock().unwrap().insert(key.clone());
        self.active_count.fetch_add(1, Ordering::SeqCst);
        ActiveReviewGuard {
            registry: Arc::clone(self),
            key: Some(key),
        }
    }

    pub(crate) fn track_mention(self: &Arc<Self>, key: ActiveMentionKey) -> ActiveMentionGuard {
        self.mentions.lock().unwrap().insert(key.clone());
        self.active_count.fetch_add(1, Ordering::SeqCst);
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

    pub(crate) async fn wait_for_idle(&self) {
        let notified = self.idle_notify.notified();
        tokio::pin!(notified);
        loop {
            notified.as_mut().enable();
            if self.active_count.load(Ordering::SeqCst) == 0 {
                return;
            }
            notified.as_mut().await;
            notified.set(self.idle_notify.notified());
        }
    }

    fn remove_review(&self, key: &ActiveReviewKey) {
        self.reviews.lock().unwrap().remove(key);
        self.finish_active_task();
    }

    fn remove_mention(&self, key: &ActiveMentionKey) {
        self.mentions.lock().unwrap().remove(key);
        self.finish_active_task();
    }

    fn finish_active_task(&self) {
        if self.active_count.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.idle_notify.notify_waiters();
        }
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
    pub(crate) lifecycle: Arc<ServiceLifecycle>,
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
        lifecycle: Arc<ServiceLifecycle>,
        active_tasks: Arc<ActiveTaskRegistry>,
    ) -> Self {
        Self {
            config,
            gitlab,
            state,
            codex,
            bot_user_id,
            semaphore,
            lifecycle,
            active_tasks,
        }
    }

    pub(crate) fn shutdown_requested(&self) -> bool {
        !self.lifecycle.accepts_new_work()
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
    use super::*;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn wait_for_idle_blocks_until_last_task_finishes() {
        let registry = Arc::new(ActiveTaskRegistry::default());
        let review = registry.track_review(ActiveReviewKey {
            lane: ReviewLane::General,
            repo: "group/project".to_string(),
            iid: 1,
            head_sha: "abc".to_string(),
        });
        let mention = registry.track_mention(ActiveMentionKey {
            repo: "group/project".to_string(),
            iid: 1,
            discussion_id: "discussion".to_string(),
            trigger_note_id: 2,
            head_sha: "abc".to_string(),
        });
        let wait_registry = Arc::clone(&registry);
        let waiter = tokio::spawn(async move {
            wait_registry.wait_for_idle().await;
        });

        assert!(timeout(Duration::from_millis(10), waiter).await.is_err());

        drop(review);
        let wait_registry = Arc::clone(&registry);
        assert!(
            timeout(Duration::from_millis(10), wait_registry.wait_for_idle())
                .await
                .is_err()
        );

        drop(mention);
        timeout(Duration::from_secs(1), registry.wait_for_idle())
            .await
            .expect("registry should become idle after last task finishes");
    }
}

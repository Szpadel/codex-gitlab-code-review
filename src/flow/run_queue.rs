//! In-memory queue that starts mention commands and reviews in priority order.
//!
//! Scans add jobs and return. A free run slot starts the oldest waiting mention
//! or general review. A security review starts only when no mention or general
//! review can start. Same-MR and same-branch exclusions are in `Blockers`.
//!
//! The queue keeps at most one waiting and one running job per key. Its size is
//! thus bounded by the open MRs per review lane plus the unprocessed mention notes.

use crate::review_lane::ReviewLane;
use futures::future::BoxFuture;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::Notify;
use tracing::{debug, error, info};

/// Identity of a job. The queue keeps at most one waiting and one running job per key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) enum JobKey {
    Review {
        lane: ReviewLane,
        repo: String,
        iid: u64,
    },
    Mention {
        repo: String,
        iid: u64,
        discussion_id: String,
        trigger_note_id: u64,
    },
}

impl JobKey {
    fn merge_request(&self) -> MergeRequestKey {
        match self {
            Self::Review { repo, iid, .. } | Self::Mention { repo, iid, .. } => {
                MergeRequestKey(repo.clone(), *iid)
            }
        }
    }

    const fn priority(&self) -> JobPriority {
        match self {
            Self::Review {
                lane: ReviewLane::Security,
                ..
            } => JobPriority::Background,
            Self::Review { .. } | Self::Mention { .. } => JobPriority::Foreground,
        }
    }
}

/// Start order between job groups. Foreground jobs always start first.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum JobPriority {
    Foreground,
    Background,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct MergeRequestKey(String, u64);

/// Supplies the facts the queue needs to order and separate a job.
pub(crate) trait QueueJob: Send + 'static {
    fn key(&self) -> JobKey;

    /// Head SHA that the producer saw when it queued the job. A running review starts
    /// with this head and sets the head it really reviews through `RunningHead`.
    fn head_sha(&self) -> &str;

    /// Branch that a mention command can push to. Two mentions that share a
    /// branch never run at the same time. Reviews return `None`.
    fn mention_branch(&self) -> Option<&str>;
}

/// Head that a running job works on. A review sets it after it reads the MR again,
/// so the queue can tell whether a new head needs a follow-up review.
#[derive(Clone, Debug)]
pub(crate) struct RunningHead(Arc<Mutex<String>>);

impl RunningHead {
    fn new(head_sha: &str) -> Self {
        Self(Arc::new(Mutex::new(head_sha.to_string())))
    }

    pub(crate) fn set(&self, head_sha: &str) {
        head_sha.clone_into(&mut self.lock());
    }

    fn is(&self, head_sha: &str) -> bool {
        *self.lock() == head_sha
    }

    fn lock(&self) -> MutexGuard<'_, String> {
        self.0.lock().expect("running head lock poisoned")
    }
}

/// Starts one job and resolves when the job has finished all its cleanup.
pub(crate) type RunJob<J> = Arc<dyn Fn(J, RunningHead) -> BoxFuture<'static, ()> + Send + Sync>;

/// Result of `RunQueue::enqueue`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EnqueueOutcome {
    /// The job was added at the end of the queue.
    Queued,
    /// A waiting job with the same key now carries this payload and keeps its place.
    Replaced,
    /// A running job already handles this key: a review of the same head, or the same
    /// trigger note.
    AlreadyRunning,
    /// The queue is closed for shutdown.
    Closed,
}

struct WaitingEntry<J> {
    sequence: u64,
    job: J,
}

struct RunningEntry {
    head: RunningHead,
    mention_branch: Option<String>,
}

struct QueueState<J> {
    open: bool,
    next_sequence: u64,
    waiting: HashMap<JobKey, WaitingEntry<J>>,
    running: HashMap<JobKey, RunningEntry>,
}

/// Owns waiting jobs and the run slots. See the module documentation for the order.
pub(crate) struct RunQueue<J: QueueJob> {
    max_running: usize,
    run_job: RunJob<J>,
    state: Mutex<QueueState<J>>,
    state_changed: Notify,
    job_finished: Notify,
}

impl<J: QueueJob> RunQueue<J> {
    /// Creates an open queue with `max_running` run slots.
    pub(crate) fn new(max_running: usize, run_job: RunJob<J>) -> Arc<Self> {
        assert!(max_running > 0, "run queue needs at least one run slot");
        Arc::new(Self {
            max_running,
            run_job,
            state: Mutex::new(QueueState {
                open: true,
                next_sequence: 0,
                waiting: HashMap::new(),
                running: HashMap::new(),
            }),
            state_changed: Notify::new(),
            job_finished: Notify::new(),
        })
    }

    /// Adds a job and starts every job that can start. Must run inside a tokio runtime.
    ///
    /// A review for another head than its running review waits as a follow-up and
    /// starts after that run.
    pub(crate) fn enqueue(self: &Arc<Self>, job: J) -> EnqueueOutcome {
        let key = job.key();
        let head_sha = job.head_sha().to_string();
        let mut state = self.lock_state();
        if !state.open {
            return EnqueueOutcome::Closed;
        }
        let outcome = if let Some(waiting) = state.waiting.get_mut(&key) {
            waiting.job = job;
            EnqueueOutcome::Replaced
        } else if state
            .running
            .get(&key)
            .is_some_and(|running| makes_redundant(&key, running, &head_sha))
        {
            EnqueueOutcome::AlreadyRunning
        } else {
            let sequence = state.next_sequence;
            state.next_sequence += 1;
            state
                .waiting
                .insert(key.clone(), WaitingEntry { sequence, job });
            EnqueueOutcome::Queued
        };
        let started = self.take_startable(&mut state);
        drop(state);
        debug!(
            ?key,
            head_sha = head_sha.as_str(),
            ?outcome,
            "run queue updated"
        );
        self.spawn_started(started);
        outcome
    }

    /// Rejects new jobs and drops waiting jobs. Running jobs continue.
    pub(crate) fn close(&self) {
        let mut state = self.lock_state();
        state.open = false;
        let dropped = state.waiting.len();
        state.waiting.clear();
        drop(state);
        if dropped > 0 {
            info!(dropped, "run queue closed and dropped its waiting jobs");
        }
        self.state_changed.notify_waiters();
    }

    /// Reports whether a job with this key waits or runs.
    pub(crate) fn contains(&self, key: &JobKey) -> bool {
        let state = self.lock_state();
        state.waiting.contains_key(key) || state.running.contains_key(key)
    }

    /// Waits until no job waits and no job runs.
    pub(crate) async fn wait_for_idle(&self) {
        self.wait_until(|state| state.waiting.is_empty() && state.running.is_empty())
            .await;
    }

    /// Waits until no job runs. Waiting jobs can remain.
    pub(crate) async fn wait_for_running(&self) {
        self.wait_until(|state| state.running.is_empty()).await;
    }

    /// Returns when a job finished after the previous call returned.
    /// A finish that happens while nobody waits is kept for the next call.
    pub(crate) async fn wait_for_job_finished(&self) {
        self.job_finished.notified().await;
    }

    fn lock_state(&self) -> MutexGuard<'_, QueueState<J>> {
        self.state.lock().expect("run queue state lock poisoned")
    }

    fn take_startable(&self, state: &mut QueueState<J>) -> Vec<(JobKey, J, RunningHead)> {
        let mut started = Vec::new();
        while state.open && state.running.len() < self.max_running {
            let Some(key) = next_startable_key(state) else {
                break;
            };
            let entry = state
                .waiting
                .remove(&key)
                .expect("startable key must be waiting");
            let head = RunningHead::new(entry.job.head_sha());
            state.running.insert(
                key.clone(),
                RunningEntry {
                    head: head.clone(),
                    mention_branch: entry.job.mention_branch().map(ToOwned::to_owned),
                },
            );
            started.push((key, entry.job, head));
        }
        started
    }

    fn spawn_started(self: &Arc<Self>, started: Vec<(JobKey, J, RunningHead)>) {
        for (key, job, head) in started {
            debug!(?key, "run queue started job");
            let run = (self.run_job)(job, head);
            let queue = Arc::clone(self);
            tokio::spawn(async move {
                // The inner task isolates a panic, so the slot is always released.
                if let Err(err) = tokio::spawn(run).await {
                    error!(?key, error = %err, "queued job panicked or was cancelled");
                }
                queue.finish(&key);
            });
        }
    }

    fn finish(self: &Arc<Self>, key: &JobKey) {
        let mut state = self.lock_state();
        state.running.remove(key);
        let started = self.take_startable(&mut state);
        drop(state);
        self.spawn_started(started);
        self.state_changed.notify_waiters();
        self.job_finished.notify_one();
    }

    async fn wait_until(&self, condition: impl Fn(&QueueState<J>) -> bool) {
        let notified = self.state_changed.notified();
        tokio::pin!(notified);
        loop {
            notified.as_mut().enable();
            if condition(&self.lock_state()) {
                return;
            }
            notified.as_mut().await;
            notified.set(self.state_changed.notified());
        }
    }
}

/// A running review covers a new job for the head it reviews. A running mention
/// covers its trigger note, because a trigger note runs at most once.
fn makes_redundant(key: &JobKey, running: &RunningEntry, head_sha: &str) -> bool {
    match key {
        JobKey::Review { .. } => running.head.is(head_sha),
        JobKey::Mention { .. } => true,
    }
}

fn next_startable_key<J: QueueJob>(state: &QueueState<J>) -> Option<JobKey> {
    let blockers = Blockers::new(state);
    state
        .waiting
        .iter()
        .filter(|(key, entry)| blockers.allow(key, entry.job.mention_branch()))
        .min_by_key(|(key, entry)| (key.priority(), entry.sequence))
        .map(|(key, _)| key.clone())
}

/// Work that stops a waiting job from starting now.
struct Blockers<'a> {
    running_keys: &'a HashMap<JobKey, RunningEntry>,
    running_review_mrs: HashSet<MergeRequestKey>,
    running_mention_mrs: HashSet<MergeRequestKey>,
    running_mention_branches: HashSet<&'a str>,
    waiting_mention_mrs: HashSet<MergeRequestKey>,
}

impl<'a> Blockers<'a> {
    fn new<J: QueueJob>(state: &'a QueueState<J>) -> Self {
        let mut blockers = Self {
            running_keys: &state.running,
            running_review_mrs: HashSet::new(),
            running_mention_mrs: HashSet::new(),
            running_mention_branches: HashSet::new(),
            waiting_mention_mrs: HashSet::new(),
        };
        for (key, running) in &state.running {
            match key {
                JobKey::Review { .. } => blockers.running_review_mrs.insert(key.merge_request()),
                JobKey::Mention { .. } => blockers.running_mention_mrs.insert(key.merge_request()),
            };
            if let Some(branch) = running.mention_branch.as_deref() {
                blockers.running_mention_branches.insert(branch);
            }
        }
        for key in state.waiting.keys() {
            if matches!(key, JobKey::Mention { .. }) {
                blockers.waiting_mention_mrs.insert(key.merge_request());
            }
        }
        blockers
    }

    /// Keeps one run per review key, and keeps mentions and reviews of one MR apart.
    /// A waiting mention also holds back reviews, because the mention can push commits.
    fn allow(&self, key: &JobKey, mention_branch: Option<&str>) -> bool {
        let merge_request = key.merge_request();
        match key {
            JobKey::Review { .. } => {
                !self.running_keys.contains_key(key)
                    && !self.running_mention_mrs.contains(&merge_request)
                    && !self.waiting_mention_mrs.contains(&merge_request)
            }
            JobKey::Mention { .. } => {
                !self.running_review_mrs.contains(&merge_request)
                    && !self.running_mention_mrs.contains(&merge_request)
                    && mention_branch
                        .is_none_or(|branch| !self.running_mention_branches.contains(branch))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::Semaphore;
    use tokio::time::timeout;

    #[derive(Debug)]
    struct TestJob {
        key: JobKey,
        head_sha: String,
        mention_branch: Option<String>,
    }

    impl QueueJob for TestJob {
        fn key(&self) -> JobKey {
            self.key.clone()
        }

        fn head_sha(&self) -> &str {
            &self.head_sha
        }

        fn mention_branch(&self) -> Option<&str> {
            self.mention_branch.as_deref()
        }
    }

    fn review(lane: ReviewLane, iid: u64, head_sha: &str) -> TestJob {
        TestJob {
            key: review_key(lane, iid),
            head_sha: head_sha.to_string(),
            mention_branch: None,
        }
    }

    fn review_key(lane: ReviewLane, iid: u64) -> JobKey {
        JobKey::Review {
            lane,
            repo: "group/repo".to_string(),
            iid,
        }
    }

    fn mention(iid: u64, trigger_note_id: u64, branch: &str) -> TestJob {
        TestJob {
            key: mention_key(iid, trigger_note_id),
            head_sha: "head".to_string(),
            mention_branch: Some(branch.to_string()),
        }
    }

    fn mention_key(iid: u64, trigger_note_id: u64) -> JobKey {
        JobKey::Mention {
            repo: "group/repo".to_string(),
            iid,
            discussion_id: format!("discussion-{trigger_note_id}"),
            trigger_note_id,
        }
    }

    /// Records start order. Each started job holds its slot until the test finishes it.
    struct Harness {
        queue: Arc<RunQueue<TestJob>>,
        started: Arc<Mutex<Vec<(JobKey, String)>>>,
        gates: Arc<Mutex<HashMap<JobKey, Arc<Semaphore>>>>,
    }

    impl Harness {
        fn new(max_running: usize) -> Self {
            let started = Arc::new(Mutex::new(Vec::new()));
            let gates = Arc::new(Mutex::new(HashMap::<JobKey, Arc<Semaphore>>::new()));
            let run_job: RunJob<TestJob> = {
                let started = Arc::clone(&started);
                let gates = Arc::clone(&gates);
                Arc::new(move |job: TestJob, _head: RunningHead| {
                    started
                        .lock()
                        .unwrap()
                        .push((job.key.clone(), job.head_sha.clone()));
                    let gate = Arc::clone(
                        gates
                            .lock()
                            .unwrap()
                            .entry(job.key.clone())
                            .or_insert_with(|| Arc::new(Semaphore::new(0))),
                    );
                    Box::pin(async move {
                        gate.acquire().await.unwrap().forget();
                    })
                })
            };
            Self {
                queue: RunQueue::new(max_running, run_job),
                started,
                gates,
            }
        }

        fn started(&self) -> Vec<(JobKey, String)> {
            self.started.lock().unwrap().clone()
        }

        fn started_keys(&self) -> Vec<JobKey> {
            self.started().into_iter().map(|(key, _)| key).collect()
        }

        /// Ends the running job with this key and waits until `expected_starts` jobs started.
        async fn finish(&self, key: &JobKey, expected_starts: usize) {
            let gate = Arc::clone(
                self.gates
                    .lock()
                    .unwrap()
                    .get(key)
                    .expect("finished job must have started"),
            );
            gate.add_permits(1);
            timeout(Duration::from_secs(1), async {
                while self.started().len() < expected_starts {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("expected job start");
        }

        /// Lets every queued and running job finish.
        async fn finish_all(&self) {
            timeout(Duration::from_secs(1), async {
                loop {
                    for gate in self.gates.lock().unwrap().values() {
                        gate.add_permits(1);
                    }
                    tokio::select! {
                        () = self.queue.wait_for_idle() => return,
                        () = tokio::task::yield_now() => {}
                    }
                }
            })
            .await
            .expect("queue should become idle");
        }

        /// Lets the queue start every job that can start now.
        async fn settle(&self) {
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
    }

    #[tokio::test]
    async fn security_review_starts_after_waiting_mentions_and_general_reviews() {
        let harness = Harness::new(1);

        harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        harness.queue.enqueue(review(ReviewLane::Security, 1, "a1"));
        harness.queue.enqueue(review(ReviewLane::General, 2, "b1"));
        harness.queue.enqueue(mention(3, 30, "feature-3"));
        harness.settle().await;
        harness.finish(&review_key(ReviewLane::General, 1), 2).await;
        harness.finish(&review_key(ReviewLane::General, 2), 3).await;
        harness.finish(&mention_key(3, 30), 4).await;
        harness.finish_all().await;

        assert_eq!(
            harness.started_keys(),
            vec![
                review_key(ReviewLane::General, 1),
                review_key(ReviewLane::General, 2),
                mention_key(3, 30),
                review_key(ReviewLane::Security, 1),
            ]
        );
    }

    #[tokio::test]
    async fn replaced_waiting_review_keeps_its_place_and_carries_the_new_head() {
        let harness = Harness::new(1);

        harness
            .queue
            .enqueue(review(ReviewLane::General, 9, "running"));
        let first = harness.queue.enqueue(review(ReviewLane::General, 1, "old"));
        harness.queue.enqueue(review(ReviewLane::General, 2, "b1"));
        let replaced = harness.queue.enqueue(review(ReviewLane::General, 1, "new"));
        harness.settle().await;
        harness.finish(&review_key(ReviewLane::General, 9), 2).await;
        harness.finish_all().await;

        assert_eq!(first, EnqueueOutcome::Queued);
        assert_eq!(replaced, EnqueueOutcome::Replaced);
        assert_eq!(
            harness.started()[1],
            (review_key(ReviewLane::General, 1), "new".to_string())
        );
    }

    #[tokio::test]
    async fn new_head_for_running_review_waits_for_the_running_job() {
        let harness = Harness::new(2);

        harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        let same_head = harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        let new_head = harness.queue.enqueue(review(ReviewLane::General, 1, "a2"));
        harness.settle().await;
        let started_while_first_runs = harness.started().len();
        harness.finish(&review_key(ReviewLane::General, 1), 2).await;
        harness.finish_all().await;

        assert_eq!(same_head, EnqueueOutcome::AlreadyRunning);
        assert_eq!(new_head, EnqueueOutcome::Queued);
        assert_eq!(
            started_while_first_runs, 1,
            "a free slot must not start a second run of one MR and lane"
        );
        assert_eq!(harness.started()[1].1, "a2");
    }

    #[tokio::test]
    async fn follow_up_compares_with_the_head_that_the_running_review_set() {
        let heads = Arc::new(Mutex::new(Vec::new()));
        let release = Arc::new(Semaphore::new(0));
        let run_job: RunJob<TestJob> = {
            let heads = Arc::clone(&heads);
            let release = Arc::clone(&release);
            Arc::new(move |_job: TestJob, head: RunningHead| {
                // The review read the MR again and found head "b".
                head.set("b");
                heads.lock().unwrap().push(head);
                let release = Arc::clone(&release);
                Box::pin(async move {
                    release.acquire().await.unwrap().forget();
                })
            })
        };
        let queue = RunQueue::new(1, run_job);

        queue.enqueue(review(ReviewLane::General, 1, "a"));
        tokio::task::yield_now().await;
        let reviewed_head = queue.enqueue(review(ReviewLane::General, 1, "b"));
        let earlier_head = queue.enqueue(review(ReviewLane::General, 1, "a"));
        release.add_permits(2);
        timeout(Duration::from_secs(1), queue.wait_for_idle())
            .await
            .expect("queue should become idle");

        assert_eq!(reviewed_head, EnqueueOutcome::AlreadyRunning);
        assert_eq!(earlier_head, EnqueueOutcome::Queued);
        assert_eq!(heads.lock().unwrap().len(), 2, "the follow-up must run");
    }

    #[tokio::test]
    async fn running_mention_makes_a_repeat_of_its_trigger_redundant() {
        let harness = Harness::new(2);

        harness.queue.enqueue(mention(1, 10, "feature-1"));
        harness.settle().await;
        let repeat = harness.queue.enqueue(mention(1, 10, "feature-1"));
        harness.finish_all().await;

        assert_eq!(repeat, EnqueueOutcome::AlreadyRunning);
        assert_eq!(harness.started().len(), 1);
    }

    #[tokio::test]
    async fn waiting_mention_alone_holds_back_reviews_of_its_merge_request() {
        let harness = Harness::new(3);

        // MR 2's mention holds the shared branch, so MR 1's mention waits.
        harness.queue.enqueue(mention(2, 20, "shared"));
        harness.queue.enqueue(mention(1, 10, "shared"));
        harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        harness.settle().await;
        let started_while_mention_waits = harness.started_keys();
        harness.finish(&mention_key(2, 20), 2).await;
        harness.finish(&mention_key(1, 10), 3).await;
        harness.finish_all().await;

        assert_eq!(
            started_while_mention_waits,
            vec![mention_key(2, 20)],
            "a free slot must not start a review while a mention of its MR waits"
        );
        assert_eq!(
            harness.started_keys(),
            vec![
                mention_key(2, 20),
                mention_key(1, 10),
                review_key(ReviewLane::General, 1)
            ]
        );
    }

    #[tokio::test]
    async fn mentions_of_one_merge_request_run_in_order_before_its_review() {
        let harness = Harness::new(2);

        harness.queue.enqueue(mention(1, 10, "feature-1"));
        harness.queue.enqueue(mention(1, 11, "feature-1"));
        harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        harness.queue.enqueue(review(ReviewLane::General, 2, "b1"));
        harness.settle().await;
        let first_starts = harness.started_keys();
        harness.finish(&mention_key(1, 10), 3).await;
        harness.finish(&mention_key(1, 11), 4).await;
        harness.finish_all().await;

        assert_eq!(
            first_starts,
            vec![mention_key(1, 10), review_key(ReviewLane::General, 2)]
        );
        assert_eq!(
            harness.started_keys()[2..],
            [mention_key(1, 11), review_key(ReviewLane::General, 1)]
        );
    }

    #[tokio::test]
    async fn running_review_holds_back_mentions_of_its_merge_request() {
        let harness = Harness::new(2);

        harness.queue.enqueue(review(ReviewLane::Security, 1, "a1"));
        harness.queue.enqueue(mention(1, 10, "feature-1"));
        harness.settle().await;
        let started_while_review_runs = harness.started().len();
        harness
            .finish(&review_key(ReviewLane::Security, 1), 2)
            .await;
        harness.finish_all().await;

        assert_eq!(started_while_review_runs, 1);
        assert_eq!(harness.started_keys()[1], mention_key(1, 10));
    }

    #[tokio::test]
    async fn mentions_that_share_a_branch_run_one_at_a_time() {
        let harness = Harness::new(2);

        harness.queue.enqueue(mention(1, 10, "shared"));
        harness.queue.enqueue(mention(2, 20, "shared"));
        harness.settle().await;
        let started_while_branch_is_busy = harness.started().len();
        harness.finish(&mention_key(1, 10), 2).await;
        harness.finish_all().await;

        assert_eq!(started_while_branch_is_busy, 1);
    }

    #[tokio::test]
    async fn close_drops_waiting_jobs_and_keeps_running_jobs() {
        let harness = Harness::new(1);

        harness.queue.enqueue(review(ReviewLane::General, 1, "a1"));
        harness.queue.enqueue(review(ReviewLane::General, 2, "b1"));
        harness.settle().await;
        harness.queue.close();
        let after_close = harness.queue.enqueue(review(ReviewLane::General, 3, "c1"));
        let second_waits_after_close = harness.queue.contains(&review_key(ReviewLane::General, 2));
        harness.finish_all().await;

        assert_eq!(after_close, EnqueueOutcome::Closed);
        assert!(!second_waits_after_close);
        assert_eq!(
            harness.started_keys(),
            vec![review_key(ReviewLane::General, 1)]
        );
    }

    #[tokio::test]
    async fn panicking_job_releases_its_slot() {
        let started = Arc::new(Mutex::new(Vec::new()));
        let run_job: RunJob<TestJob> = {
            let started = Arc::clone(&started);
            Arc::new(move |job: TestJob, _head: RunningHead| {
                started.lock().unwrap().push(job.head_sha.clone());
                let panics = job.head_sha == "panic";
                Box::pin(async move {
                    assert!(!panics, "test job panic");
                })
            })
        };
        let queue = RunQueue::new(1, run_job);

        queue.enqueue(review(ReviewLane::General, 1, "panic"));
        queue.enqueue(review(ReviewLane::General, 2, "next"));
        timeout(Duration::from_secs(1), queue.wait_for_idle())
            .await
            .expect("queue should become idle after a panic");

        assert_eq!(*started.lock().unwrap(), vec!["panic", "next"]);
    }
}

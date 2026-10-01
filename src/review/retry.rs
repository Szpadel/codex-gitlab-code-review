use crate::config::Config;
use crate::flow::award_service::AwardService;
use crate::review::ReviewLane;
use chrono::{DateTime, Duration, Utc};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use tracing::warn;

pub(crate) const REVIEW_RETRY_WARNING_EMOJI: &str = "warning";
pub(crate) const REVIEW_RETRY_BLOCKED_DEFER_SECONDS: i64 = 60;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct RetryKey {
    pub(crate) lane: ReviewLane,
    pub(crate) repo: String,
    pub(crate) iid: u64,
    pub(crate) head_sha: String,
}

impl RetryKey {
    pub(crate) fn new(lane: ReviewLane, repo: &str, iid: u64, head_sha: &str) -> Self {
        Self {
            lane,
            repo: repo.to_string(),
            iid,
            head_sha: head_sha.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RetryState {
    pub(crate) retry_number: u32,
    pub(crate) run_history_id: i64,
    pub(crate) next_retry_at: Option<DateTime<Utc>>,
    pub(crate) exhausted: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct RetryFailure {
    pub(crate) retry_number: u32,
    pub(crate) max_retries: u32,
    pub(crate) next_retry_at: Option<DateTime<Utc>>,
    pub(crate) exhausted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RunRetryStatus {
    pub retry_number: u32,
    pub max_retries: u32,
    pub next_retry_at: Option<i64>,
    pub exhausted: bool,
    pub label: String,
}

pub trait RunRetryStatusProvider: Send + Sync {
    fn retry_statuses_for_run_ids(&self, run_ids: &[i64]) -> HashMap<i64, RunRetryStatus>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RetryGateStatus {
    Ready(Option<RetryState>),
    Pending(RetryState),
    Exhausted(RetryState),
}

pub(crate) struct RetryBackoff {
    base_delay: Duration,
    max_retries: u32,
    entries: Mutex<HashMap<RetryKey, RetryState>>,
}

#[derive(Clone)]
pub(crate) struct RetryWarningAwardService {
    config: Config,
    award_service: AwardService,
}

impl RetryWarningAwardService {
    pub(crate) fn new(config: Config, award_service: AwardService) -> Self {
        Self {
            config,
            award_service,
        }
    }

    pub(crate) async fn ensure_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run {
            return;
        }
        if let Err(err) = self
            .award_service
            .ensure_award(repo, iid, REVIEW_RETRY_WARNING_EMOJI)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to add retry warning award"
            );
        }
    }

    pub(crate) async fn remove_best_effort(&self, repo: &str, iid: u64) {
        if self.config.review.dry_run {
            return;
        }
        if let Err(err) = self
            .award_service
            .remove_award(repo, iid, REVIEW_RETRY_WARNING_EMOJI)
            .await
        {
            warn!(
                repo = repo,
                iid = iid,
                error = %err,
                "failed to remove retry warning award"
            );
        }
    }

    pub(crate) async fn remove_if_no_active_retry(
        &self,
        retry_backoff: &RetryBackoff,
        repo: &str,
        iid: u64,
    ) {
        if !retry_backoff.has_active_retry_for_mr(repo, iid) {
            self.remove_best_effort(repo, iid).await;
        }
    }

    pub(crate) async fn remove_if_no_other_active_retry(
        &self,
        retry_backoff: &RetryBackoff,
        retry_key: &RetryKey,
    ) {
        if !retry_backoff.has_other_active_retry_for_mr(retry_key) {
            self.remove_best_effort(&retry_key.repo, retry_key.iid)
                .await;
        }
    }

    pub(crate) async fn clear_key_and_remove_if_inactive(
        &self,
        retry_backoff: &RetryBackoff,
        retry_key: &RetryKey,
    ) {
        retry_backoff.clear(retry_key);
        self.remove_if_no_active_retry(retry_backoff, &retry_key.repo, retry_key.iid)
            .await;
    }
}

impl RetryBackoff {
    pub(crate) fn new(base_delay: Duration, max_retries: u32) -> Self {
        Self {
            base_delay,
            max_retries,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn gate_status(&self, key: &RetryKey, now: DateTime<Utc>) -> RetryGateStatus {
        let entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some(state) if state.exhausted => RetryGateStatus::Exhausted(state.clone()),
            Some(state) if state.next_retry_at.is_some_and(|next| now < next) => {
                RetryGateStatus::Pending(state.clone())
            }
            Some(state) => RetryGateStatus::Ready(Some(state.clone())),
            None => RetryGateStatus::Ready(None),
        }
    }

    pub(crate) fn record_failure(
        &self,
        key: RetryKey,
        run_history_id: i64,
        now: DateTime<Utc>,
    ) -> RetryFailure {
        let mut entries = self.entries.lock().unwrap();
        let next_retry_number = entries
            .get(&key)
            .map_or(1, |state| state.retry_number.saturating_add(1));
        if next_retry_number > self.max_retries {
            let retry_number = self.max_retries;
            entries.insert(
                key,
                RetryState {
                    retry_number,
                    run_history_id,
                    next_retry_at: None,
                    exhausted: true,
                },
            );
            return RetryFailure {
                retry_number,
                max_retries: self.max_retries,
                next_retry_at: None,
                exhausted: true,
            };
        }
        let retry_number = next_retry_number;
        let base_seconds = self.base_delay.num_seconds().max(0);
        let exponent = retry_number.saturating_sub(1).min(30);
        let multiplier = 1i64 << exponent;
        let delay_seconds = base_seconds.saturating_mul(multiplier);
        let next_retry_at = now + Duration::seconds(delay_seconds);
        entries.insert(
            key,
            RetryState {
                retry_number,
                run_history_id,
                next_retry_at: Some(next_retry_at),
                exhausted: false,
            },
        );
        RetryFailure {
            retry_number,
            max_retries: self.max_retries,
            next_retry_at: Some(next_retry_at),
            exhausted: false,
        }
    }

    pub(crate) fn defer_until(&self, key: &RetryKey, next_retry_at: DateTime<Utc>) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let Some(state) = entries.get_mut(key) else {
            return false;
        };
        if state.exhausted {
            return false;
        }
        state.next_retry_at = Some(next_retry_at);
        true
    }

    pub(crate) fn clear(&self, key: &RetryKey) {
        let mut entries = self.entries.lock().unwrap();
        entries.remove(key);
    }

    pub(crate) fn clear_for_repo_iids_not_in(
        &self,
        repo: &str,
        open_iids: &[u64],
    ) -> Vec<RetryKey> {
        let open_iids = open_iids.iter().copied().collect::<HashSet<_>>();
        let mut entries = self.entries.lock().unwrap();
        let removed = entries
            .keys()
            .filter(|key| key.repo == repo && !open_iids.contains(&key.iid))
            .cloned()
            .collect::<Vec<_>>();
        for key in &removed {
            entries.remove(key);
        }
        removed
    }

    /// Removes retry state for repositories outside the current scan targets.
    /// Returns removed keys so the caller can remove their warning awards.
    pub(crate) fn clear_for_repos_not_in(&self, repos: &[String]) -> Vec<RetryKey> {
        let repos = repos.iter().map(String::as_str).collect::<HashSet<_>>();
        let mut entries = self.entries.lock().unwrap();
        let removed = entries
            .keys()
            .filter(|key| !repos.contains(key.repo.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for key in &removed {
            entries.remove(key);
        }
        removed
    }

    pub(crate) fn clear_for_mr_other_heads(
        &self,
        lane: ReviewLane,
        repo: &str,
        iid: u64,
        head_sha: &str,
    ) -> Vec<RetryKey> {
        let mut entries = self.entries.lock().unwrap();
        let removed = entries
            .keys()
            .filter(|key| {
                key.lane == lane && key.repo == repo && key.iid == iid && key.head_sha != head_sha
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in &removed {
            entries.remove(key);
        }
        removed
    }

    pub(crate) fn clear_for_mr(&self, repo: &str, iid: u64) -> Vec<RetryKey> {
        let mut entries = self.entries.lock().unwrap();
        let removed = entries
            .keys()
            .filter(|key| key.repo == repo && key.iid == iid)
            .cloned()
            .collect::<Vec<_>>();
        for key in &removed {
            entries.remove(key);
        }
        removed
    }

    pub(crate) fn defer_due_for_mr(
        &self,
        repo: &str,
        iid: u64,
        now: DateTime<Utc>,
        next_retry_at: DateTime<Utc>,
    ) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let mut deferred = 0;
        for (key, state) in entries.iter_mut() {
            if key.repo == repo
                && key.iid == iid
                && !state.exhausted
                && state.next_retry_at.is_some_and(|next| now >= next)
            {
                state.next_retry_at = Some(next_retry_at);
                deferred += 1;
            }
        }
        deferred
    }

    pub(crate) fn earliest_retry_at(&self) -> Option<DateTime<Utc>> {
        let entries = self.entries.lock().unwrap();
        entries
            .values()
            .filter(|state| !state.exhausted)
            .filter_map(|state| state.next_retry_at)
            .min()
    }

    pub(crate) fn repo_has_due_retry(&self, repo: &str, now: DateTime<Utc>) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.iter().any(|(key, state)| {
            key.repo == repo
                && !state.exhausted
                && state.next_retry_at.is_some_and(|next| now >= next)
        })
    }

    pub(crate) fn has_active_retry_for_mr(&self, repo: &str, iid: u64) -> bool {
        let entries = self.entries.lock().unwrap();
        entries
            .iter()
            .any(|(key, state)| key.repo == repo && key.iid == iid && !state.exhausted)
    }

    pub(crate) fn has_other_active_retry_for_mr(&self, current: &RetryKey) -> bool {
        let entries = self.entries.lock().unwrap();
        entries.iter().any(|(key, state)| {
            key != current && key.repo == current.repo && key.iid == current.iid && !state.exhausted
        })
    }

    pub(crate) fn statuses_for_run_ids(
        &self,
        run_ids: &[i64],
        now: DateTime<Utc>,
    ) -> HashMap<i64, RunRetryStatus> {
        let run_ids = run_ids.iter().copied().collect::<HashSet<_>>();
        let entries = self.entries.lock().unwrap();
        entries
            .values()
            .filter(|state| run_ids.contains(&state.run_history_id))
            .map(|state| {
                (
                    state.run_history_id,
                    retry_status_from_state(state, self.max_retries, now),
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn state_for(&self, key: &RetryKey) -> Option<RetryState> {
        let entries = self.entries.lock().unwrap();
        entries.get(key).cloned()
    }
}

fn retry_status_from_state(
    state: &RetryState,
    max_retries: u32,
    now: DateTime<Utc>,
) -> RunRetryStatus {
    let next_retry_at = state.next_retry_at.map(|value| value.timestamp());
    RunRetryStatus {
        retry_number: state.retry_number,
        max_retries,
        next_retry_at,
        exhausted: state.exhausted,
        label: retry_status_label(
            state.retry_number,
            max_retries,
            state.next_retry_at,
            state.exhausted,
            now,
        ),
    }
}

fn retry_status_label(
    retry_number: u32,
    max_retries: u32,
    next_retry_at: Option<DateTime<Utc>>,
    exhausted: bool,
    now: DateTime<Utc>,
) -> String {
    if exhausted {
        return format!("retry exhausted {retry_number}/{max_retries}");
    }
    let seconds = next_retry_at
        .map(|value| value.signed_duration_since(now).num_seconds().max(0))
        .unwrap_or(0);
    format!(
        "retry {retry_number}/{max_retries} in {}",
        format_retry_delay(seconds)
    )
}

fn format_retry_delay(seconds: i64) -> String {
    if seconds >= 3600 && seconds % 3600 == 0 {
        format!("{}h", seconds / 3600)
    } else if seconds >= 60 && seconds % 60 == 0 {
        format!("{}m", seconds / 60)
    } else {
        format!("{seconds}s")
    }
}

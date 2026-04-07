use crate::codex_runner::{CodexResult, CodexRunner, ReviewContext};
use crate::state::NewRunHistoryEvent;
use crate::transcript_backfill::TranscriptBackfillSource;
use anyhow::Result;
use async_trait::async_trait;
use serde_json::{Value, json};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub(crate) struct ThreadReaderRunner {
    pub(crate) response: Value,
}

#[async_trait]
impl CodexRunner for ThreadReaderRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        unreachable!("run_review is not used in status tests")
    }

    async fn read_thread(&self, _account_name: &str, _thread_id: &str) -> Result<Value> {
        Ok(self.response.clone())
    }
}

#[derive(Clone)]
pub(crate) struct CountingThreadReaderRunner {
    pub(crate) read_calls: Arc<AtomicUsize>,
}

#[async_trait]
impl CodexRunner for CountingThreadReaderRunner {
    async fn run_review(&self, _ctx: ReviewContext) -> Result<CodexResult> {
        unreachable!("run_review is not used in status tests")
    }

    async fn read_thread(&self, _account_name: &str, _thread_id: &str) -> Result<Value> {
        self.read_calls.fetch_add(1, Ordering::SeqCst);
        Ok(json!({
            "thread": {
                "id": "unused",
                "preview": "unused",
                "status": "completed",
                "turns": []
            }
        }))
    }
}

#[derive(Clone)]
pub(crate) struct StaticTranscriptBackfillSource {
    pub(crate) events: Vec<NewRunHistoryEvent>,
    pub(crate) calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for StaticTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.events.clone()))
    }
}

#[derive(Clone)]
pub(crate) struct SequencedTranscriptBackfillSource {
    pub(crate) responses: Arc<Mutex<Vec<Option<Vec<NewRunHistoryEvent>>>>>,
    pub(crate) calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for SequencedTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut responses = self
            .responses
            .lock()
            .expect("sequenced transcript responses mutex");
        if responses.len() > 1 {
            Ok(responses.remove(0))
        } else {
            Ok(responses.first().cloned().unwrap_or(None))
        }
    }
}

#[derive(Clone)]
pub(crate) struct CapturingTranscriptBackfillSource {
    pub(crate) events: Vec<NewRunHistoryEvent>,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) seen_thread_id: Arc<Mutex<Option<String>>>,
    pub(crate) seen_turn_id: Arc<Mutex<Option<String>>>,
}

#[async_trait]
impl TranscriptBackfillSource for CapturingTranscriptBackfillSource {
    async fn load_events(
        &self,
        thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self
            .seen_thread_id
            .lock()
            .expect("capturing transcript thread id mutex") = Some(thread_id.to_string());
        *self
            .seen_turn_id
            .lock()
            .expect("capturing transcript turn id mutex") = turn_id.map(ToOwned::to_owned);
        Ok(Some(self.events.clone()))
    }
}

#[derive(Clone)]
pub(crate) struct TurnScopedFallbackTranscriptBackfillSource {
    pub(crate) turn_events: Option<Vec<NewRunHistoryEvent>>,
    pub(crate) full_thread_events: Vec<NewRunHistoryEvent>,
    pub(crate) seen_turn_ids: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl TranscriptBackfillSource for TurnScopedFallbackTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.seen_turn_ids
            .lock()
            .expect("turn-scoped fallback seen turn ids mutex")
            .push(turn_id.map(ToOwned::to_owned));
        Ok(match turn_id {
            Some(_) => self.turn_events.clone(),
            None => Some(self.full_thread_events.clone()),
        })
    }
}

#[derive(Clone)]
pub(crate) struct ErroringTranscriptBackfillSource {
    pub(crate) error: &'static str,
    pub(crate) calls: Arc<AtomicUsize>,
}

#[async_trait]
impl TranscriptBackfillSource for ErroringTranscriptBackfillSource {
    async fn load_events(
        &self,
        _thread_id: &str,
        _turn_id: Option<&str>,
    ) -> Result<Option<Vec<NewRunHistoryEvent>>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        anyhow::bail!(self.error);
    }
}

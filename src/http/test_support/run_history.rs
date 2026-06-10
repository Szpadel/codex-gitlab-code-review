use crate::state::{
    NewRunHistory, NewRunHistoryEvent, ReviewStateStore, RunHistoryFinish, RunHistoryKind,
    RunHistorySessionUpdate,
};
use anyhow::Result;
use serde_json::{Value, json};

pub(crate) struct RunFixture {
    new_run: NewRunHistory,
    session: RunHistorySessionUpdate,
    finish: RunHistoryFinish,
}

impl RunFixture {
    pub(crate) fn review(repo: &str, iid: u64, head_sha: &str) -> Self {
        Self::new(RunHistoryKind::Review, repo, iid, head_sha)
    }

    pub(crate) fn security(repo: &str, iid: u64, head_sha: &str) -> Self {
        Self::new(RunHistoryKind::Security, repo, iid, head_sha)
    }

    pub(crate) fn mention(repo: &str, iid: u64, head_sha: &str) -> Self {
        Self::new(RunHistoryKind::Mention, repo, iid, head_sha)
    }

    fn new(kind: RunHistoryKind, repo: &str, iid: u64, head_sha: &str) -> Self {
        Self {
            new_run: NewRunHistory {
                kind,
                repo: repo.to_string(),
                iid,
                head_sha: head_sha.to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            session: RunHistorySessionUpdate::default(),
            finish: RunHistoryFinish::default(),
        }
    }

    pub(crate) fn discussion(
        mut self,
        discussion_id: impl Into<String>,
        trigger_note_id: u64,
    ) -> Self {
        self.new_run.discussion_id = Some(discussion_id.into());
        self.new_run.trigger_note_id = Some(trigger_note_id);
        self
    }

    pub(crate) fn trigger_note(
        mut self,
        author: impl Into<String>,
        body: impl Into<String>,
    ) -> Self {
        self.new_run.trigger_note_author_name = Some(author.into());
        self.new_run.trigger_note_body = Some(body.into());
        self
    }

    pub(crate) fn command_repo(mut self, repo: impl Into<String>) -> Self {
        self.new_run.command_repo = Some(repo.into());
        self
    }

    pub(crate) fn thread(mut self, thread_id: impl Into<String>) -> Self {
        self.session.thread_id = Some(thread_id.into());
        self
    }

    pub(crate) fn turn(mut self, turn_id: impl Into<String>) -> Self {
        self.session.turn_id = Some(turn_id.into());
        self
    }

    pub(crate) fn review_thread(mut self, review_thread_id: impl Into<String>) -> Self {
        self.session.review_thread_id = Some(review_thread_id.into());
        self
    }

    pub(crate) fn auth_account(mut self, name: impl Into<String>) -> Self {
        self.session.auth_account_name = Some(name.into());
        self
    }

    pub(crate) fn result(mut self, result: impl Into<String>) -> Self {
        self.finish.result = result.into();
        self
    }

    pub(crate) fn preview(mut self, value: impl Into<String>) -> Self {
        self.finish.preview = Some(value.into());
        self
    }

    pub(crate) fn summary(mut self, value: impl Into<String>) -> Self {
        self.finish.summary = Some(value.into());
        self
    }

    pub(crate) fn finish_error(mut self, value: impl Into<String>) -> Self {
        self.finish.error = Some(value.into());
        self
    }

    pub(crate) fn commit_sha(mut self, value: impl Into<String>) -> Self {
        self.finish.commit_sha = Some(value.into());
        self
    }

    pub(crate) async fn start(self, state: &ReviewStateStore) -> Result<i64> {
        let run_id = state.run_history.start_run_history(self.new_run).await?;
        if self.session != RunHistorySessionUpdate::default() {
            state
                .run_history
                .update_run_history_session(run_id, self.session)
                .await?;
        }
        Ok(run_id)
    }

    pub(crate) async fn insert(self, state: &ReviewStateStore) -> Result<i64> {
        insert_run_history(state, self.new_run, self.session, self.finish).await
    }
}

pub(crate) fn run_event(
    sequence: i64,
    turn_id: Option<&str>,
    event_type: &str,
    payload: Value,
) -> NewRunHistoryEvent {
    NewRunHistoryEvent {
        sequence,
        turn_id: turn_id.map(str::to_string),
        event_type: event_type.to_string(),
        payload,
    }
}

pub(crate) fn turn_started_event(sequence: i64, turn_id: &str) -> NewRunHistoryEvent {
    run_event(sequence, Some(turn_id), "turn_started", json!({}))
}

pub(crate) fn turn_started_event_at(
    sequence: i64,
    turn_id: &str,
    created_at: &str,
) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "turn_started",
        json!({ "createdAt": created_at }),
    )
}

pub(crate) fn turn_completed_event(sequence: i64, turn_id: &str) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "turn_completed",
        json!({ "status": "completed" }),
    )
}

pub(crate) fn turn_completed_event_at(
    sequence: i64,
    turn_id: &str,
    created_at: &str,
) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "turn_completed",
        json!({
            "status": "completed",
            "createdAt": created_at,
        }),
    )
}

pub(crate) fn agent_message_event(sequence: i64, turn_id: &str, text: &str) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "agentMessage",
            "text": text,
        }),
    )
}

pub(crate) fn agent_message_event_at(
    sequence: i64,
    turn_id: &str,
    text: &str,
    created_at: &str,
) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "agentMessage",
            "text": text,
            "createdAt": created_at,
        }),
    )
}

pub(crate) fn empty_reasoning_event(sequence: i64, turn_id: &str) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "reasoning",
            "summary": [],
            "content": [],
        }),
    )
}

pub(crate) fn reasoning_event(
    sequence: i64,
    turn_id: &str,
    summary_text: &str,
    content_text: &str,
) -> NewRunHistoryEvent {
    run_event(
        sequence,
        Some(turn_id),
        "item_completed",
        json!({
            "type": "reasoning",
            "summary": [{"type": "summary_text", "text": summary_text}],
            "content": [{"type": "reasoning_text", "text": content_text}],
        }),
    )
}

pub(crate) async fn insert_run_history(
    state: &ReviewStateStore,
    new_run: NewRunHistory,
    session: RunHistorySessionUpdate,
    finish: RunHistoryFinish,
) -> Result<i64> {
    let run_id = state.run_history.start_run_history(new_run).await?;
    if session != RunHistorySessionUpdate::default() {
        state
            .run_history
            .update_run_history_session(run_id, session)
            .await?;
    }
    state.run_history.finish_run_history(run_id, finish).await?;
    Ok(run_id)
}

pub(crate) async fn insert_run_history_events(
    state: &ReviewStateStore,
    run_id: i64,
    events: Vec<NewRunHistoryEvent>,
) -> Result<()> {
    state
        .run_history
        .append_run_history_events(run_id, &events)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn run_fixture_roundtrips_inserted_run_history() -> Result<()> {
        let state = ReviewStateStore::new(":memory:").await?;
        let run_id = RunFixture::mention("group/repo", 42, "feedabc")
            .discussion("discussion-42", 1001)
            .trigger_note("qa", "please check this")
            .command_repo("group/repo")
            .thread("thread-42")
            .turn("turn-42")
            .review_thread("review-thread-42")
            .auth_account("primary")
            .result("committed")
            .preview("Mention group/repo !42")
            .summary("Fixture summary")
            .finish_error("Fixture error")
            .commit_sha("abc123")
            .insert(&state)
            .await?;

        let run = state.run_history.get_run_history(run_id).await?.unwrap();
        assert_eq!(run.kind, RunHistoryKind::Mention);
        assert_eq!(run.repo, "group/repo");
        assert_eq!(run.iid, 42);
        assert_eq!(run.head_sha, "feedabc");
        assert_eq!(run.discussion_id.as_deref(), Some("discussion-42"));
        assert_eq!(run.trigger_note_id, Some(1001));
        assert_eq!(run.trigger_note_author_name.as_deref(), Some("qa"));
        assert_eq!(run.trigger_note_body.as_deref(), Some("please check this"));
        assert_eq!(run.command_repo.as_deref(), Some("group/repo"));
        assert_eq!(run.thread_id.as_deref(), Some("thread-42"));
        assert_eq!(run.turn_id.as_deref(), Some("turn-42"));
        assert_eq!(run.review_thread_id.as_deref(), Some("review-thread-42"));
        assert_eq!(run.auth_account_name.as_deref(), Some("primary"));
        assert_eq!(run.result.as_deref(), Some("committed"));
        assert_eq!(run.preview.as_deref(), Some("Mention group/repo !42"));
        assert_eq!(run.summary.as_deref(), Some("Fixture summary"));
        assert_eq!(run.error.as_deref(), Some("Fixture error"));
        assert_eq!(run.commit_sha.as_deref(), Some("abc123"));
        Ok(())
    }
}

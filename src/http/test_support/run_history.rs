use crate::state::{
    NewRunHistory, NewRunHistoryEvent, ReviewStateStore, RunHistoryFinish, RunHistorySessionUpdate,
};
use anyhow::Result;

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

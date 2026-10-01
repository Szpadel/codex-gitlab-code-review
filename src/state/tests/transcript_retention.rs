use super::*;

#[tokio::test]
async fn transcript_retention_preserves_history_usage_and_boundaries() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    sqlx::raw_sql(
        "WITH RECURSIVE runs(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM runs WHERE id < 25)
         INSERT INTO run_history (id, kind, repo, iid, head_sha, status, started_at, updated_at,
                                  finished_at, transcript_backfill_state, transcript_backfill_error)
         SELECT id, 'review', 'group/repo', id, 'sha', 'done', 99, 110, 110, 'failed', 'old error' FROM runs;
         INSERT INTO run_history (id, kind, repo, iid, head_sha, status, started_at, updated_at,
                                  transcript_backfill_state) VALUES
         (26, 'review', 'group/repo', 26, 'sha', 'done', 100, 100, 'complete'),
         (27, 'mention', 'group/repo', 27, 'sha', 'done', 101, 101, 'complete'),
         (28, 'review', 'group/repo', 28, 'sha', 'in_progress', 99, 99, 'not_requested'),
         (29, 'review', 'group/repo', 29, 'sha', 'done', 99, 99, 'expired');
         INSERT INTO run_history_event (run_history_id, sequence, event_type, payload_json, created_at)
         SELECT id, 1, 'turn_started', '{}', 99 FROM run_history WHERE id != 29;
         INSERT INTO run_history_event (run_history_id, sequence, event_type, payload_json, created_at)
         SELECT id, 2, 'turn_completed', '{}', 99 FROM run_history WHERE id <= 25;
         INSERT INTO run_history_token_usage
         SELECT id, 'response', 'thread', 'turn', 100, 20, 0, 30, 10, 130, 99 FROM run_history;",
    ).execute(store.pool()).await?;
    let query = RunHistoryListQuery::default();
    let statistics = store.run_history.token_usage_statistics(&query).await?;
    let ids = (1..=29).collect::<Vec<_>>();
    let usage = store.run_history.token_usage_for_runs(&ids).await?;
    let mut runs = 0;
    let mut events = 0;
    let mut last_run_id = None;
    loop {
        let pruned = store
            .run_history
            .prune_transcripts_batch(100, last_run_id)
            .await?;
        if pruned.runs == 0 {
            break;
        }
        assert!(
            pruned.runs <= 10,
            "each transaction must keep a small run batch"
        );
        runs += pruned.runs;
        events += pruned.events;
        assert!(pruned.last_run_id > last_run_id);
        last_run_id = pruned.last_run_id;
    }
    assert_eq!((runs, events), (25, 50));
    for id in 1..=25 {
        assert!(
            store
                .run_history
                .list_run_history_events(id)
                .await?
                .is_empty()
        );
        let run = store.run_history.get_run_history(id).await?.unwrap();
        assert_eq!(
            run.transcript_backfill_state,
            TranscriptBackfillState::Expired
        );
        assert_eq!(run.transcript_backfill_error, None);
        assert_eq!(run.finished_at, Some(110));
    }
    for id in 26..=28 {
        assert_eq!(
            store.run_history.list_run_history_events(id).await?.len(),
            1
        );
        assert_ne!(
            store
                .run_history
                .get_run_history(id)
                .await?
                .unwrap()
                .transcript_backfill_state,
            TranscriptBackfillState::Expired
        );
    }
    assert_eq!(
        store.run_history.token_usage_statistics(&query).await?,
        statistics
    );
    assert_eq!(store.run_history.token_usage_for_runs(&ids).await?, usage);
    let raw_usage: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM run_history_token_usage")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(raw_usage, 29);
    assert_eq!(
        store.run_history.prune_transcripts_batch(100, None).await?,
        Default::default()
    );
    Ok(())
}

#[tokio::test]
async fn transcript_retention_cannot_be_reversed_by_stale_backfill_writes() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    sqlx::raw_sql(
        "INSERT INTO run_history (id, kind, repo, iid, head_sha, status, started_at, updated_at,
                                  transcript_backfill_state)
         VALUES (1, 'review', 'group/repo', 1, 'sha', 'done', 0, 0, 'expired');",
    )
    .execute(store.pool())
    .await?;
    let events = vec![NewRunHistoryEvent {
        sequence: 1,
        turn_id: None,
        event_type: "turn_started".to_string(),
        payload: serde_json::json!({}),
    }];
    store
        .run_history
        .complete_run_history_transcript_backfill_bg(1, events.clone())
        .await?;
    store.flush_background_writes().await?;
    store
        .run_history
        .append_run_history_events(1, &events)
        .await?;
    store
        .run_history
        .update_run_history_transcript_backfill(1, TranscriptBackfillState::InProgress, None)
        .await?;
    assert!(
        store
            .run_history
            .list_run_history_events(1)
            .await?
            .is_empty()
    );
    assert_eq!(
        store
            .run_history
            .get_run_history(1)
            .await?
            .unwrap()
            .transcript_backfill_state,
        TranscriptBackfillState::Expired
    );
    Ok(())
}

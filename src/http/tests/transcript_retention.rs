use super::*;
use crate::state::ReviewStateStore;

#[tokio::test]
async fn transcript_retention_rejects_backfill_from_a_stale_run_snapshot() -> Result<()> {
    let config = test_config();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let calls = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(CapturingTranscriptBackfillSource {
        events: vec![],
        calls: Arc::clone(&calls),
        seen_thread_id: Arc::new(Mutex::new(None)),
        seen_turn_id: Arc::new(Mutex::new(None)),
    });
    let service = crate::http::status::BackfillService::new(&config, Arc::clone(&state))
        .with_transcript_backfill_source(source);
    let run_id = RunFixture::review("group/repo", 32, "sha")
        .thread("expired-thread")
        .turn("expired-turn")
        .result("comment")
        .insert(&state)
        .await?;
    let stale = state.run_history.get_run_history(run_id).await?.unwrap();
    state
        .run_history
        .prune_transcripts_batch(i64::MAX, None)
        .await?;
    let snapshot = service
        .resolve_transcript_backfill(&stale, None)
        .await?
        .unwrap();
    assert_eq!(snapshot.state, TranscriptBackfillState::Expired);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn transcript_retention_detail_notice_keeps_metadata_and_never_starts_backfill() -> Result<()>
{
    let mut config = test_config();
    config.database.transcript_retention_days = 17;
    let calls = Arc::new(AtomicUsize::new(0));
    let source = Arc::new(CapturingTranscriptBackfillSource {
        events: vec![],
        calls: Arc::clone(&calls),
        seen_thread_id: Arc::new(Mutex::new(None)),
        seen_turn_id: Arc::new(Mutex::new(None)),
    });
    let server = HttpTestServerBuilder::new()
        .with_config(config)
        .with_transcript_backfill_source(source)
        .spawn()
        .await?;
    let run_id = RunFixture::review("group/retained", 31, "retained-sha")
        .thread("expired-thread")
        .turn("expired-turn")
        .result("comment")
        .insert(&server.state)
        .await?;
    server
        .state
        .run_history
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::Expired, None)
        .await?;
    let snapshot = server
        .services
        .status
        .run_detail_snapshot(run_id)
        .await?
        .unwrap();
    assert_eq!(
        snapshot.transcript_backfill.unwrap().state,
        TranscriptBackfillState::Expired
    );
    let response = test_get(format!("http://{}/history/{run_id}", server.address)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Transcript removed after 17 days by the retention policy."));
    assert!(body.contains("group/retained"));
    assert!(body.contains("retained-sha"));
    assert!(body.contains("Token usage"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        server
            .state
            .run_history
            .get_run_history(run_id)
            .await?
            .unwrap()
            .transcript_backfill_state,
        TranscriptBackfillState::Expired
    );
    Ok(())
}

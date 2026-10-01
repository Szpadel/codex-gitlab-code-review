use super::*;

#[tokio::test]
async fn note_publication_failure_finalizes_review_and_retry() -> Result<()> {
    check_publication_failure(CodexResult::Comment(crate::codex_runner::ReviewComment {
        summary: "needs changes".to_string(),
        body: "Review text".to_string(),
        overall_explanation: None,
        overall_confidence_score: None,
        findings: vec![],
        omitted_duplicate_count: 0,
    }))
    .await
}

#[tokio::test]
async fn award_publication_failure_finalizes_review_and_retry() -> Result<()> {
    check_publication_failure(CodexResult::Pass {
        summary: "ok".to_string(),
    })
    .await
}

async fn check_publication_failure(result: CodexResult) -> Result<()> {
    let config = test_config();
    let mut gitlab = InlineReviewGitLab::new(fake_gitlab(vec![mr(1, "sha1")]), vec![], vec![]);
    match result {
        CodexResult::Pass { .. } => {
            gitlab.add_award_error = Some(config.review.thumbs_emoji.clone())
        }
        CodexResult::Comment(_) => {
            gitlab.create_note_error = Some("note publication failed".to_string())
        }
    }
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(result)),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        Arc::new(gitlab),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let row = sqlx::query("SELECT status, result FROM review_state WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(1_i64)
        .fetch_one(state.pool())
        .await?;
    assert_eq!(row.try_get::<String, _>("status")?, "done");
    assert_eq!(row.try_get::<String, _>("result")?, "error");
    let history = state
        .run_history
        .list_run_history(&RunHistoryListQuery::default())
        .await?;
    assert_eq!(history.runs.len(), 1);
    assert_eq!(history.runs[0].result.as_deref(), Some("error"));
    assert!(
        history.runs[0]
            .error
            .as_deref()
            .is_some_and(|error| error.contains("publication failed"))
    );
    assert!(service.has_active_review_backoff_retry_for_mr("group/repo", 1));
    assert!(
        service
            .next_review_backoff_retry_at()
            .is_some_and(|next| next > Utc::now())
    );
    service.scan_once().await?;
    assert_eq!(*runner.calls.lock().unwrap(), 1);
    Ok(())
}

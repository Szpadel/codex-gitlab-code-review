use super::*;

enum IneligibleReview {
    Closed,
    Draft,
    BeforeCutoff,
    OutsideTargets,
}

#[tokio::test]
async fn pending_review_skips_closed_merge_request() -> Result<()> {
    check_ineligible_pending_review(IneligibleReview::Closed).await
}

#[tokio::test]
async fn pending_review_skips_draft_merge_request() -> Result<()> {
    check_ineligible_pending_review(IneligibleReview::Draft).await
}

#[tokio::test]
async fn pending_review_skips_merge_request_before_cutoff() -> Result<()> {
    check_ineligible_pending_review(IneligibleReview::BeforeCutoff).await
}

#[tokio::test]
async fn pending_review_skips_repository_outside_targets() -> Result<()> {
    check_ineligible_pending_review(IneligibleReview::OutsideTargets).await
}

async fn check_ineligible_pending_review(case: IneligibleReview) -> Result<()> {
    for lane in [ReviewLane::General, ReviewLane::Security] {
        let mut config = test_config();
        config.feature_flags.security_review = true;
        let mut merge_request = mr(1, "sha1");
        match case {
            IneligibleReview::Closed => {
                let mut wire_mr = serde_json::to_value(&merge_request)?;
                wire_mr["state"] = serde_json::json!("closed");
                merge_request = serde_json::from_value(wire_mr)?;
            }
            IneligibleReview::Draft => merge_request.draft = true,
            IneligibleReview::BeforeCutoff => {
                merge_request.created_at = Some(default_created_after())
            }
            IneligibleReview::OutsideTargets => {
                config.gitlab.targets.repos = TargetSelector::List(vec!["group/other".to_string()])
            }
        }
        let gitlab = fake_gitlab(vec![merge_request]);
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        state
            .review_rate_limit
            .upsert_review_rate_limit_pending(lane, "group/repo", 1, "sha1", 0, 0)
            .await?;
        let runner = Arc::new(FakeRunner {
            result: Mutex::new(None),
            calls: Mutex::new(0),
        });
        let service = ReviewService::new(
            config,
            gitlab,
            state.clone(),
            runner.clone(),
            1,
            default_created_after(),
        );

        service.process_due_pending_retries().await?;

        assert_eq!(
            *runner.calls.lock().unwrap(),
            0,
            "ineligible pending reviews must not run"
        );
        assert!(
            state
                .review_rate_limit
                .list_review_rate_limit_pending()
                .await?
                .is_empty()
        );
        assert!(
            state
                .run_history
                .list_run_history(&RunHistoryListQuery::default())
                .await?
                .runs
                .is_empty()
        );
    }
    Ok(())
}

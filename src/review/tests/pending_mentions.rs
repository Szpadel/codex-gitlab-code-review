use super::*;
use crate::state::MentionQuotaPendingUpsert;

#[tokio::test]
async fn pending_mention_discussion_failure_keeps_pending_row() -> Result<()> {
    check_pending_mention_failure(Some("discussion lookup failed")).await
}

#[tokio::test]
async fn pending_mention_source_failure_keeps_pending_row() -> Result<()> {
    check_pending_mention_failure(None).await
}

async fn check_pending_mention_failure(discussion_error: Option<&str>) -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("bot".to_string());
    let mut merge_request = mr(1, "sha1");
    if discussion_error.is_none() {
        merge_request.source_project_id = None;
    }
    let mut gitlab = InlineReviewGitLab::new(fake_gitlab(vec![merge_request]), vec![], vec![]);
    gitlab.list_discussions_error = discussion_error.map(ToOwned::to_owned);
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .mention_quota_pending
        .upsert_mention_quota_pending(MentionQuotaPendingUpsert {
            repo: "group/repo",
            iid: 1,
            discussion_id: "discussion",
            trigger_note_id: 2,
            head_sha: "sha1",
            blocked_at: 0,
            next_retry_at: 0,
        })
        .await?;
    let service = ReviewService::new(
        config,
        Arc::new(gitlab),
        state.clone(),
        Arc::new(MentionRunner {
            mention_calls: Mutex::new(0),
        }),
        1,
        default_created_after(),
    );

    let result = service.process_due_pending_rate_limit_reviews().await;
    assert!(result.is_err(), "mention read failures must be reported");
    let pending = state
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].trigger_note_id, 2);
    assert!(pending[0].next_retry_at > Utc::now().timestamp());

    state
        .project_catalog
        .set_project_last_mr_activity("group/repo", "old-marker")
        .await?;
    assert!(service.scan_once().await.is_err());
    assert_eq!(
        state
            .project_catalog
            .get_project_last_mr_activity("group/repo")
            .await?
            .as_deref(),
        Some("old-marker")
    );
    Ok(())
}

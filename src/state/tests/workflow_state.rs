use super::*;
#[tokio::test]
async fn begin_review_locks_in_progress() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first = store
        .review_state
        .begin_review("group/repo", 1, "sha1")
        .await?;
    let second = store
        .review_state
        .begin_review("group/repo", 1, "sha1")
        .await?;
    assert_eq!(first, true);
    assert_eq!(second, false);

    store
        .review_state
        .finish_review("group/repo", 1, "sha1", "pass")
        .await?;
    let third = store
        .review_state
        .begin_review("group/repo", 1, "sha2")
        .await?;
    assert_eq!(third, true);
    Ok(())
}

#[tokio::test]
async fn clear_stale_releases_lock() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_state
        .begin_review("group/repo", 2, "sha1")
        .await?;

    sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(2i64)
        .execute(store.pool())
        .await?;

    store.review_state.clear_stale_in_progress(1).await?;
    let again = store
        .review_state
        .begin_review("group/repo", 2, "sha2")
        .await?;
    assert_eq!(again, true);
    Ok(())
}

#[tokio::test]
async fn clear_stale_mentions_mark_error_and_block_replay() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";
    let iid = 11u64;
    let discussion_id = "discussion-1";
    let trigger_note_id = 22u64;
    store
        .mention_commands
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
        .await?;

    sqlx::query(
        r#"
        UPDATE mention_command_state
        SET updated_at = 0
        WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
        "#,
    )
    .bind(repo)
    .bind(iid as i64)
    .bind(discussion_id)
    .bind(trigger_note_id as i64)
    .execute(store.pool())
    .await?;

    store
        .mention_commands
        .clear_stale_in_progress_mentions(1)
        .await?;
    let again = store
        .mention_commands
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
        .await?;

    assert_eq!(again, false);
    let row = sqlx::query(
        r#"
        SELECT status, result
        FROM mention_command_state
        WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?
        "#,
    )
    .bind(repo)
    .bind(iid as i64)
    .bind(discussion_id)
    .bind(trigger_note_id as i64)
    .fetch_one(store.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done".to_string());
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn list_in_progress_reviews_returns_only_active_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_state
        .begin_review("group/repo-a", 1, "sha1")
        .await?;
    store
        .review_state
        .begin_review("group/repo-b", 2, "sha2")
        .await?;
    store
        .review_state
        .finish_review("group/repo-b", 2, "sha2", "pass")
        .await?;

    let in_progress = store.review_state.list_in_progress_reviews().await?;
    assert_eq!(
        in_progress,
        vec![InProgressReview {
            lane: crate::review_lane::ReviewLane::General,
            repo: "group/repo-a".to_string(),
            iid: 1,
            head_sha: "sha1".to_string(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn security_review_context_cache_evicts_expired_rows_on_upsert() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "expired-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{}".to_string(),
            source_run_history_id: 0,
            generated_at: 100,
            expires_at: 100,
        })
        .await?;

    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "fresh-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"ok\":true}".to_string(),
            source_run_history_id: 0,
            generated_at: 200,
            expires_at: 400,
        })
        .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_review_context_cache")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(count, 1);
    Ok(())
}

#[tokio::test]
async fn security_review_context_cache_roundtrips_source_run_history_id() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "sha-1".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"focus_paths\":[]}".to_string(),
            source_run_history_id: 42,
            generated_at: 100,
            expires_at: 200,
        })
        .await?;

    let entry = store
        .security_context_cache
        .get_security_review_context_cache("group/repo", "main", "sha-1", "v1", 150)
        .await?
        .expect("cache entry");

    assert_eq!(entry.source_run_history_id, 42);
    Ok(())
}

#[tokio::test]
async fn security_review_context_cache_fallback_returns_newest_live_branch_entry() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "stale-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"version\":1}".to_string(),
            source_run_history_id: 1,
            generated_at: 100,
            expires_at: 100,
        })
        .await?;
    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "older-live-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"version\":2}".to_string(),
            source_run_history_id: 2,
            generated_at: 200,
            expires_at: 500,
        })
        .await?;
    store
        .security_context_cache
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "newest-live-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"version\":3}".to_string(),
            source_run_history_id: 3,
            generated_at: 300,
            expires_at: 600,
        })
        .await?;

    let entry = store
        .security_context_cache
        .get_latest_security_review_context_cache_for_branch("group/repo", "main", "v1", 400)
        .await?
        .expect("branch cache entry");

    assert_eq!(entry.base_head_sha, "newest-live-sha");
    assert_eq!(entry.payload_json, "{\"version\":3}");
    assert_eq!(entry.source_run_history_id, 3);
    Ok(())
}

#[tokio::test]
async fn security_review_debounce_state_roundtrips_and_marks_repo_due() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .security_review_debounce
        .upsert_security_review_debounce("group/repo", 7, 100, 3_700)
        .await?;

    let row = store
        .security_review_debounce
        .get_security_review_debounce("group/repo", 7)
        .await?
        .expect("debounce state");
    assert_eq!(row.last_started_at, 100);
    assert_eq!(row.next_eligible_at, 3_700);
    assert!(
        !store
            .security_review_debounce
            .repo_has_due_security_review_debounce("group/repo", 3_699)
            .await?
    );
    assert!(
        store
            .security_review_debounce
            .repo_has_due_security_review_debounce("group/repo", 3_700)
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn sync_security_review_debounce_state_prunes_closed_merge_requests() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .security_review_debounce
        .upsert_security_review_debounce("group/repo", 7, 100, 200)
        .await?;
    store
        .security_review_debounce
        .upsert_security_review_debounce("group/repo", 8, 100, 150)
        .await?;

    store
        .security_review_debounce
        .sync_security_review_debounce_rows("group/repo", &[8])
        .await?;

    assert!(
        store
            .security_review_debounce
            .get_security_review_debounce("group/repo", 7)
            .await?
            .is_none()
    );
    assert!(
        store
            .security_review_debounce
            .get_security_review_debounce("group/repo", 8)
            .await?
            .is_some()
    );
    assert!(
        store
            .security_review_debounce
            .repo_has_due_security_review_debounce("group/repo", 150)
            .await?
    );
    Ok(())
}

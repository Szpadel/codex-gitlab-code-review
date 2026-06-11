use super::*;

fn pending<'a>(
    repo: &'a str,
    iid: u64,
    discussion_id: &'a str,
    trigger_note_id: u64,
    head_sha: &'a str,
    blocked_at: i64,
    next_retry_at: i64,
) -> MentionQuotaPendingUpsert<'a> {
    MentionQuotaPendingUpsert {
        repo,
        iid,
        discussion_id,
        trigger_note_id,
        head_sha,
        blocked_at,
        next_retry_at,
    }
}

#[tokio::test]
async fn mention_quota_pending_deduplicates_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            15,
            "discussion-1",
            99,
            "sha-1",
            100,
            500,
        ))
        .await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            15,
            "discussion-1",
            99,
            "sha-2",
            150,
            700,
        ))
        .await?;

    let rows = store
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].repo, "group/repo");
    assert_eq!(rows[0].iid, 15);
    assert_eq!(rows[0].discussion_id, "discussion-1");
    assert_eq!(rows[0].trigger_note_id, 99);
    assert_eq!(rows[0].first_blocked_at, 100);
    assert_eq!(rows[0].last_blocked_at, 150);
    assert_eq!(rows[0].last_seen_head_sha, "sha-2");
    assert_eq!(rows[0].next_retry_at, 700);
    Ok(())
}

#[tokio::test]
async fn mention_quota_pending_clear_removes_row() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            18,
            "discussion-1",
            99,
            "sha-1",
            100,
            500,
        ))
        .await?;

    assert!(
        store
            .mention_quota_pending
            .clear_mention_quota_pending("group/repo", 18, "discussion-1", 99)
            .await?
    );
    assert!(
        store
            .mention_quota_pending
            .list_mention_quota_pending()
            .await?
            .is_empty()
    );
    assert_eq!(
        store
            .mention_quota_pending
            .earliest_mention_quota_pending_retry_at()
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn mention_quota_pending_due_queries_track_retry_times() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            16,
            "discussion-1",
            99,
            "sha-1",
            100,
            500,
        ))
        .await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            17,
            "discussion-2",
            100,
            "sha-2",
            120,
            300,
        ))
        .await?;

    assert_eq!(
        store
            .mention_quota_pending
            .earliest_mention_quota_pending_retry_at()
            .await?,
        Some(300)
    );
    assert!(
        store
            .mention_quota_pending
            .repo_has_due_mention_quota_pending("group/repo", 300)
            .await?
    );
    assert!(
        !store
            .mention_quota_pending
            .repo_has_due_mention_quota_pending("group/repo", 299)
            .await?
    );
    assert!(
        !store
            .mention_quota_pending
            .repo_has_due_mention_quota_pending("other/repo", 1_000)
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn sync_mention_quota_pending_rows_returns_deleted_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            16,
            "discussion-1",
            99,
            "sha-1",
            100,
            500,
        ))
        .await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "group/repo",
            17,
            "discussion-2",
            100,
            "sha-2",
            120,
            300,
        ))
        .await?;
    store
        .mention_quota_pending
        .upsert_mention_quota_pending(pending(
            "other/repo",
            18,
            "discussion-3",
            101,
            "sha-3",
            130,
            400,
        ))
        .await?;

    let deleted = store
        .mention_quota_pending
        .sync_mention_quota_pending_rows("group/repo", &[16])
        .await?;
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].repo, "group/repo");
    assert_eq!(deleted[0].iid, 17);
    assert_eq!(deleted[0].discussion_id, "discussion-2");
    assert_eq!(deleted[0].trigger_note_id, 100);

    let rows = store
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?;
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .any(|row| row.repo == "group/repo" && row.iid == 16)
    );
    assert!(
        rows.iter()
            .any(|row| row.repo == "other/repo" && row.iid == 18)
    );

    let deleted = store
        .mention_quota_pending
        .sync_mention_quota_pending_rows("group/repo", &[])
        .await?;
    assert_eq!(deleted.len(), 1);
    assert_eq!(deleted[0].iid, 16);

    let rows = store
        .mention_quota_pending
        .list_mention_quota_pending()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].repo, "other/repo");
    Ok(())
}

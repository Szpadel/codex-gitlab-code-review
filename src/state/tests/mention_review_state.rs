use super::*;
#[tokio::test]
async fn finish_review_is_noop_once_row_is_not_in_progress() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_state
        .begin_review("group/repo", 3, "sha1")
        .await?;

    store
        .review_state
        .finish_review("group/repo", 3, "sha1", "pass")
        .await?;
    store
        .review_state
        .finish_review("group/repo", 3, "sha2", "error")
        .await?;

    let row =
        sqlx::query("SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(3i64)
            .fetch_one(store.pool())
            .await?;
    let status: String = row.try_get("status")?;
    let head_sha: String = row.try_get("head_sha")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done".to_string());
    assert_eq!(head_sha, "sha1".to_string());
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn finish_review_ignores_outdated_sha_for_new_in_progress_review() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";
    let iid = 4u64;
    store.review_state.begin_review(repo, iid, "sha1").await?;

    sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
        .bind(repo)
        .bind(iid as i64)
        .execute(store.pool())
        .await?;
    store.review_state.clear_stale_in_progress(1).await?;

    let restarted = store.review_state.begin_review(repo, iid, "sha2").await?;
    assert_eq!(restarted, true);

    store
        .review_state
        .finish_review(repo, iid, "sha1", "error")
        .await?;
    let row =
        sqlx::query("SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind(repo)
            .bind(iid as i64)
            .fetch_one(store.pool())
            .await?;
    let status: String = row.try_get("status")?;
    let head_sha: String = row.try_get("head_sha")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "in_progress".to_string());
    assert_eq!(head_sha, "sha2".to_string());
    assert_eq!(result, None);

    store
        .review_state
        .finish_review(repo, iid, "sha2", "pass")
        .await?;
    let row =
        sqlx::query("SELECT status, head_sha, result FROM review_state WHERE repo = ? AND iid = ?")
            .bind(repo)
            .bind(iid as i64)
            .fetch_one(store.pool())
            .await?;
    let status: String = row.try_get("status")?;
    let head_sha: String = row.try_get("head_sha")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done".to_string());
    assert_eq!(head_sha, "sha2".to_string());
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn begin_mention_command_is_idempotent() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";
    let iid = 11u64;
    let discussion_id = "discussion-1";
    let trigger_note_id = 22u64;

    let first = store
        .mention_commands
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
        .await?;
    let second = store
        .mention_commands
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
        .await?;
    assert_eq!(first, true);
    assert_eq!(second, false);

    let row = sqlx::query(
        r#"
        SELECT status, head_sha, result
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
    let head_sha: String = row.try_get("head_sha")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "in_progress".to_string());
    assert_eq!(head_sha, "sha1".to_string());
    assert_eq!(result, None);
    Ok(())
}

#[tokio::test]
async fn begin_mention_command_retries_after_cancelled_but_not_error() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";
    let iid = 12u64;
    let discussion_id = "discussion-2";
    let trigger_note_id = 23u64;

    assert!(
        store
            .mention_commands
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
            .await?
    );
    store
        .mention_commands
        .finish_mention_command(
            repo,
            iid,
            discussion_id,
            trigger_note_id,
            "sha1",
            "cancelled",
        )
        .await?;
    assert!(
        store
            .mention_commands
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
            .await?
    );

    store
        .mention_commands
        .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2", "error")
        .await?;
    assert!(
        !store
            .mention_commands
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha3")
            .await?
    );

    let row = sqlx::query(
        r#"
        SELECT status, head_sha, result
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
    let head_sha: String = row.try_get("head_sha")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done".to_string());
    assert_eq!(head_sha, "sha2".to_string());
    assert_eq!(result, Some("error".to_string()));
    Ok(())
}

#[tokio::test]
async fn finish_mention_command_transitions_only_in_progress_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";
    let iid = 13u64;
    let discussion_id = "discussion-3";
    let trigger_note_id = 24u64;

    let started = store
        .mention_commands
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
        .await?;
    assert_eq!(started, true);

    store
        .mention_commands
        .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1", "pass")
        .await?;
    store
        .mention_commands
        .finish_mention_command(
            repo,
            iid,
            discussion_id,
            trigger_note_id,
            "sha1",
            "overwritten",
        )
        .await?;

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
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn list_in_progress_mention_commands_returns_only_active_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    store
        .mention_commands
        .begin_mention_command("group/repo-a", 1, "discussion-a", 101, "sha-a")
        .await?;
    store
        .mention_commands
        .begin_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b")
        .await?;
    store
        .mention_commands
        .finish_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b", "pass")
        .await?;

    let in_progress = store
        .mention_commands
        .list_in_progress_mention_commands()
        .await?;
    assert_eq!(
        in_progress,
        vec![InProgressMentionCommand {
            key: MentionCommandStateKey {
                repo: "group/repo-a".to_string(),
                iid: 1,
                discussion_id: "discussion-a".to_string(),
                trigger_note_id: 101,
            },
            head_sha: "sha-a".to_string(),
        }]
    );
    Ok(())
}

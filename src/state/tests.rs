use super::*;
use pretty_assertions::assert_eq;
use std::env;
use std::fs;
use uuid::Uuid;

#[tokio::test]
async fn begin_review_locks_in_progress() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first = store.begin_review("group/repo", 1, "sha1").await?;
    let second = store.begin_review("group/repo", 1, "sha1").await?;
    assert_eq!(first, true);
    assert_eq!(second, false);

    store.finish_review("group/repo", 1, "sha1", "pass").await?;
    let third = store.begin_review("group/repo", 1, "sha2").await?;
    assert_eq!(third, true);
    Ok(())
}

#[tokio::test]
async fn clear_stale_releases_lock() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store.begin_review("group/repo", 2, "sha1").await?;

    sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
        .bind("group/repo")
        .bind(2i64)
        .execute(store.pool())
        .await?;

    store.clear_stale_in_progress(1).await?;
    let again = store.begin_review("group/repo", 2, "sha2").await?;
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

    store.clear_stale_in_progress_mentions(1).await?;
    let again = store
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
    store.begin_review("group/repo-a", 1, "sha1").await?;
    store.begin_review("group/repo-b", 2, "sha2").await?;
    store
        .finish_review("group/repo-b", 2, "sha2", "pass")
        .await?;

    let in_progress = store.list_in_progress_reviews().await?;
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
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "expired-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{}".to_string(),
            generated_at: 100,
            expires_at: 100,
        })
        .await?;

    store
        .upsert_security_review_context_cache(&SecurityReviewContextCacheEntry {
            repo: "group/repo".to_string(),
            base_branch: "main".to_string(),
            base_head_sha: "fresh-sha".to_string(),
            prompt_version: "v1".to_string(),
            payload_json: "{\"ok\":true}".to_string(),
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
async fn finish_review_is_noop_once_row_is_not_in_progress() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store.begin_review("group/repo", 3, "sha1").await?;

    store.finish_review("group/repo", 3, "sha1", "pass").await?;
    store
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
    store.begin_review(repo, iid, "sha1").await?;

    sqlx::query("UPDATE review_state SET updated_at = 0 WHERE repo = ? AND iid = ?")
        .bind(repo)
        .bind(iid as i64)
        .execute(store.pool())
        .await?;
    store.clear_stale_in_progress(1).await?;

    let restarted = store.begin_review(repo, iid, "sha2").await?;
    assert_eq!(restarted, true);

    store.finish_review(repo, iid, "sha1", "error").await?;
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

    store.finish_review(repo, iid, "sha2", "pass").await?;
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
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
        .await?;
    let second = store
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
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
            .await?
    );
    store
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
            .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2")
            .await?
    );

    store
        .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha2", "error")
        .await?;
    assert!(
        !store
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
        .begin_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1")
        .await?;
    assert_eq!(started, true);

    store
        .finish_mention_command(repo, iid, discussion_id, trigger_note_id, "sha1", "pass")
        .await?;
    store
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
        .begin_mention_command("group/repo-a", 1, "discussion-a", 101, "sha-a")
        .await?;
    store
        .begin_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b")
        .await?;
    store
        .finish_mention_command("group/repo-b", 2, "discussion-b", 102, "sha-b", "pass")
        .await?;

    let in_progress = store.list_in_progress_mention_commands().await?;
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

#[tokio::test]
async fn creates_database_file_when_missing() -> Result<()> {
    let base = env::temp_dir().join(format!("codex-review-db-{}", Uuid::new_v4()));
    let path = base.join("nested").join("state.sqlite");
    if base.exists() {
        fs::remove_dir_all(&base).ok();
    }

    let store = ReviewStateStore::new(path.to_str().unwrap()).await?;
    assert!(path.exists());
    drop(store);
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[tokio::test]
async fn fails_when_database_path_is_directory() -> Result<()> {
    let base = env::temp_dir().join(format!("codex-review-db-{}", Uuid::new_v4()));
    fs::create_dir_all(&base)?;
    let err = match ReviewStateStore::new(base.to_str().unwrap()).await {
        Ok(_) => panic!("expected error for database path that is a directory"),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(msg.contains("database path is a directory"));
    assert!(msg.contains(base.to_str().unwrap()));
    let _ = fs::remove_dir_all(&base);
    Ok(())
}

#[tokio::test]
async fn project_last_activity_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let repo = "group/repo";

    let missing = store.get_project_last_mr_activity(repo).await?;
    assert_eq!(missing, None);

    store
        .set_project_last_mr_activity(repo, "2025-01-01T00:00:00Z")
        .await?;
    let loaded = store.get_project_last_mr_activity(repo).await?;
    assert_eq!(loaded, Some("2025-01-01T00:00:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn project_catalog_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let key = "mode=all;repos=;groups=";
    let projects = vec!["group/repo".to_string(), "group/other".to_string()];

    let missing = store.load_project_catalog(key).await?;
    assert!(missing.is_none());

    store.save_project_catalog(key, &projects).await?;
    let loaded = store.load_project_catalog(key).await?.expect("catalog");
    assert_eq!(loaded.projects, projects);
    assert!(loaded.fetched_at > 0);
    Ok(())
}

#[tokio::test]
async fn created_after_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let missing = store.get_created_after().await?;
    assert_eq!(missing, None);

    store.set_created_after("2025-01-02T03:04:05Z").await?;
    let loaded = store.get_created_after().await?;
    assert_eq!(loaded, Some("2025-01-02T03:04:05Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_owner_id_is_created_once_and_stable_across_calls() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first = store.get_or_create_review_owner_id().await?;
    assert!(!first.is_empty());

    let second = store.get_or_create_review_owner_id().await?;
    assert_eq!(second, first);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_roundtrip_and_clear() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let account = "backup-1";

    let missing = store.get_auth_limit_reset_at(account).await?;
    assert_eq!(missing, None);

    store
        .set_auth_limit_reset_at(account, "2026-03-02T10:15:00Z")
        .await?;
    let loaded = store.get_auth_limit_reset_at(account).await?;
    assert_eq!(loaded, Some("2026-03-02T10:15:00Z".to_string()));

    store.clear_auth_limit_reset_at(account).await?;
    let cleared = store.get_auth_limit_reset_at(account).await?;
    assert_eq!(cleared, None);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_tracks_accounts_independently() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .set_auth_limit_reset_at("primary", "2026-03-02T10:15:00Z")
        .await?;
    store
        .set_auth_limit_reset_at("backup-1", "2026-03-02T12:00:00Z")
        .await?;

    let primary = store.get_auth_limit_reset_at("primary").await?;
    let backup = store.get_auth_limit_reset_at("backup-1").await?;
    assert_eq!(primary, Some("2026-03-02T10:15:00Z".to_string()));
    assert_eq!(backup, Some("2026-03-02T12:00:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_keeps_latest_timestamp_for_account() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let account = "backup-1";

    store
        .set_auth_limit_reset_at(account, "2026-03-02T12:00:00Z")
        .await?;
    store
        .set_auth_limit_reset_at(account, "2026-03-02T10:00:00Z")
        .await?;
    let after_older_write = store.get_auth_limit_reset_at(account).await?;
    assert_eq!(after_older_write, Some("2026-03-02T12:00:00Z".to_string()));

    store
        .set_auth_limit_reset_at(account, "2026-03-02T13:30:00Z")
        .await?;
    let after_newer_write = store.get_auth_limit_reset_at(account).await?;
    assert_eq!(after_newer_write, Some("2026-03-02T13:30:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn scan_status_roundtrip_and_clear_next_scan() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let initial = store.get_scan_status().await?;
    assert_eq!(initial.state, ScanState::Idle);
    assert_eq!(initial.mode, None);
    assert_eq!(initial.started_at, None);
    assert_eq!(initial.finished_at, None);
    assert_eq!(initial.outcome, None);
    assert_eq!(initial.error, None);
    assert_eq!(initial.next_scan_at, None);

    store
        .set_scan_status(&PersistedScanStatus {
            state: ScanState::Scanning,
            mode: Some(ScanMode::Full),
            started_at: Some("2026-03-10T10:00:00Z".to_string()),
            finished_at: None,
            outcome: None,
            error: None,
            next_scan_at: Some("2026-03-10T10:10:00Z".to_string()),
        })
        .await?;

    let running = store.get_scan_status().await?;
    assert_eq!(running.state, ScanState::Scanning);
    assert_eq!(running.mode, Some(ScanMode::Full));
    assert_eq!(running.started_at, Some("2026-03-10T10:00:00Z".to_string()));
    assert_eq!(running.finished_at, None);
    assert_eq!(running.outcome, None);
    assert_eq!(running.error, None);
    assert_eq!(
        running.next_scan_at,
        Some("2026-03-10T10:10:00Z".to_string())
    );

    store.clear_next_scan_at().await?;
    let cleared = store.get_scan_status().await?;
    assert_eq!(cleared.next_scan_at, None);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_listing_returns_sorted_accounts() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .set_auth_limit_reset_at("backup-2", "2026-03-10T12:30:00Z")
        .await?;
    store
        .set_auth_limit_reset_at("primary", "2026-03-10T11:00:00Z")
        .await?;

    let entries = store.list_auth_limit_reset_entries().await?;
    assert_eq!(
        entries,
        vec![
            AuthLimitResetEntry {
                account_name: "backup-2".to_string(),
                reset_at: "2026-03-10T12:30:00Z".to_string(),
            },
            AuthLimitResetEntry {
                account_name: "primary".to_string(),
                reset_at: "2026-03-10T11:00:00Z".to_string(),
            },
        ]
    );
    Ok(())
}

#[tokio::test]
async fn project_catalog_summary_lists_project_counts() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .save_project_catalog(
            "all",
            &[
                "group/a".to_string(),
                "group/b".to_string(),
                "group/c".to_string(),
            ],
        )
        .await?;

    let summaries = store.list_project_catalog_summaries().await?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].cache_key, "all".to_string());
    assert_eq!(summaries[0].project_count, 3);
    assert!(summaries[0].fetched_at > 0);
    Ok(())
}

#[tokio::test]
async fn project_catalog_summary_falls_back_for_legacy_rows_without_count() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    sqlx::query(
        r#"
        INSERT INTO project_catalog (cache_key, fetched_at, projects, project_count)
        VALUES (?, ?, ?, NULL)
        "#,
    )
    .bind("legacy")
    .bind(123i64)
    .bind("[\"group/a\",\"group/b\"]")
    .execute(store.pool())
    .await?;

    let summaries = store.list_project_catalog_summaries().await?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].cache_key, "legacy".to_string());
    assert_eq!(summaries[0].project_count, 2);
    Ok(())
}

#[tokio::test]
async fn run_history_is_append_only_for_same_mr() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 42,
            head_sha: "sha1".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            first_id,
            RunHistoryFinish {
                result: "comment".to_string(),
                thread_id: Some("thread-1".to_string()),
                turn_id: Some("turn-1".to_string()),
                review_thread_id: Some("thread-1".to_string()),
                preview: Some("Review group/repo !42".to_string()),
                summary: Some("needs fixes".to_string()),
                error: None,
                auth_account_name: Some("primary".to_string()),
                commit_sha: None,
            },
        )
        .await?;

    let second_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 42,
            head_sha: "sha2".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    assert_ne!(first_id, second_id);

    let records = store.list_run_history_for_mr("group/repo", 42).await?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id, second_id);
    assert_eq!(records[0].head_sha, "sha2".to_string());
    assert_eq!(records[1].id, first_id);
    assert_eq!(records[1].result.as_deref(), Some("comment"));
    Ok(())
}

#[tokio::test]
async fn run_history_preserves_mention_trigger_metadata() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "sha-mention".to_string(),
            discussion_id: Some("discussion-9".to_string()),
            trigger_note_id: Some(123),
            trigger_note_author_name: Some("Reviewer".to_string()),
            trigger_note_body: Some("@codex please rename this".to_string()),
            command_repo: Some("fork/repo".to_string()),
        })
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "committed".to_string(),
                thread_id: Some("thread-mention".to_string()),
                turn_id: Some("turn-mention".to_string()),
                review_thread_id: None,
                preview: Some("note:123 author:reviewer".to_string()),
                summary: Some("renamed method".to_string()),
                error: None,
                auth_account_name: Some("backup".to_string()),
                commit_sha: Some("abc1234".to_string()),
            },
        )
        .await?;

    let record = store
        .get_run_history(run_id)
        .await?
        .expect("run history record should exist");
    assert_eq!(record.kind, RunHistoryKind::Mention);
    assert_eq!(record.discussion_id.as_deref(), Some("discussion-9"));
    assert_eq!(record.trigger_note_id, Some(123));
    assert_eq!(record.trigger_note_author_name.as_deref(), Some("Reviewer"));
    assert_eq!(
        record.trigger_note_body.as_deref(),
        Some("@codex please rename this")
    );
    assert_eq!(record.command_repo.as_deref(), Some("fork/repo"));
    assert_eq!(record.commit_sha.as_deref(), Some("abc1234"));
    assert_eq!(record.feature_flags, FeatureFlagSnapshot::default());
    Ok(())
}

#[tokio::test]
async fn runtime_feature_flag_overrides_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    assert_eq!(
        store.get_runtime_feature_flag_overrides().await?,
        RuntimeFeatureFlagOverrides::default()
    );

    let overrides = RuntimeFeatureFlagOverrides {
        gitlab_discovery_mcp: Some(true),
        gitlab_inline_review_comments: Some(false),
        security_review: Some(false),
        composer_install: Some(true),
        composer_auto_repositories: Some(true),
        composer_safe_install: Some(true),
    };
    store.set_runtime_feature_flag_overrides(&overrides).await?;

    assert_eq!(store.get_runtime_feature_flag_overrides().await?, overrides);
    Ok(())
}

#[tokio::test]
async fn run_history_feature_flags_snapshot_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 13,
            head_sha: "sha-flags".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    let feature_flags = FeatureFlagSnapshot {
        gitlab_discovery_mcp: true,
        gitlab_inline_review_comments: true,
        security_review: false,
        composer_install: true,
        composer_auto_repositories: true,
        composer_safe_install: true,
    };
    store
        .set_run_history_feature_flags(run_id, &feature_flags)
        .await?;

    let record = store
        .get_run_history(run_id)
        .await?
        .context("run history row should exist")?;
    assert_eq!(record.feature_flags, feature_flags);
    Ok(())
}

#[tokio::test]
async fn security_run_history_roundtrip_uses_security_kind() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history_for_lane(
            NewRunHistory {
                kind: RunHistoryKind::Security,
                repo: "group/repo".to_string(),
                iid: 13,
                head_sha: "sha-security".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            Some(crate::review_lane::ReviewLane::Security),
        )
        .await?;

    let record = store
        .get_run_history(run_id)
        .await?
        .context("run history row should exist")?;
    assert_eq!(record.kind, RunHistoryKind::Security);
    Ok(())
}

#[tokio::test]
async fn run_history_filters_by_mr() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let first = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 11,
            head_sha: "sha-a".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    let _other = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/other".to_string(),
            iid: 11,
            head_sha: "sha-b".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            first,
            RunHistoryFinish {
                result: "pass".to_string(),
                thread_id: Some("thread-a".to_string()),
                turn_id: Some("turn-a".to_string()),
                review_thread_id: Some("thread-a".to_string()),
                preview: Some("Review group/repo !11".to_string()),
                summary: Some("looks good".to_string()),
                error: None,
                auth_account_name: Some("primary".to_string()),
                commit_sha: None,
            },
        )
        .await?;

    let records = store.list_run_history_for_mr("group/repo", 11).await?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].repo, "group/repo".to_string());
    assert_eq!(records[0].iid, 11);
    Ok(())
}

#[tokio::test]
async fn completed_inline_review_detection_respects_security_kind() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history_for_lane(
            NewRunHistory {
                kind: RunHistoryKind::Security,
                repo: "group/repo".to_string(),
                iid: 21,
                head_sha: "sha-security-inline".to_string(),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            Some(crate::review_lane::ReviewLane::Security),
        )
        .await?;
    store
        .set_run_history_feature_flags(
            run_id,
            &FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..FeatureFlagSnapshot::default()
            },
        )
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "comment".to_string(),
                ..RunHistoryFinish::default()
            },
        )
        .await?;

    assert!(
        store
            .has_completed_inline_review_for_lane(
                "group/repo",
                21,
                "sha-security-inline",
                crate::review_lane::ReviewLane::Security,
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn list_run_history_pages_with_cursors_and_preserves_filtering() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let mut run_ids = Vec::new();
    for (iid, started_at) in [(21u64, 1_000i64), (22, 2_000), (23, 3_000)] {
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    preview: Some(format!("Review group/repo !{iid}")),
                    summary: Some("pagination target".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
            .bind(started_at)
            .bind(started_at)
            .bind(run_id)
            .execute(store.pool())
            .await?;
        run_ids.push(run_id);
    }
    let unrelated_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/other".to_string(),
            iid: 99,
            head_sha: "sha-other".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            unrelated_id,
            RunHistoryFinish {
                result: "pass".to_string(),
                preview: Some("Review group/other !99".to_string()),
                summary: Some("does not match".to_string()),
                ..Default::default()
            },
        )
        .await?;

    let filtered = RunHistoryListQuery {
        repo: Some("group/repo".to_string()),
        search: Some("pagination".to_string()),
        limit: 1,
        ..Default::default()
    };

    let first_page = store.list_run_history(&filtered).await?;
    assert_eq!(first_page.runs.len(), 1);
    assert_eq!(first_page.runs[0].id, run_ids[2]);
    assert_eq!(first_page.has_previous, false);
    assert_eq!(first_page.has_next, true);

    let second_page = store
        .list_run_history(&RunHistoryListQuery {
            after: first_page.next_cursor,
            ..filtered.clone()
        })
        .await?;
    assert_eq!(second_page.runs.len(), 1);
    assert_eq!(second_page.runs[0].id, run_ids[1]);
    assert_eq!(second_page.has_previous, true);
    assert_eq!(second_page.has_next, true);

    let previous_page = store
        .list_run_history(&RunHistoryListQuery {
            before: second_page.previous_cursor,
            ..filtered.clone()
        })
        .await?;
    assert_eq!(previous_page.runs.len(), 1);
    assert_eq!(previous_page.runs[0].id, run_ids[2]);
    assert_eq!(previous_page.has_previous, false);
    assert_eq!(previous_page.has_next, true);
    Ok(())
}

#[tokio::test]
async fn list_run_history_cursor_uses_id_as_tie_breaker() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let mut run_ids = Vec::new();
    for iid in [31u64, 32, 33] {
        let run_id = store
            .start_run_history(NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            })
            .await?;
        store
            .finish_run_history(
                run_id,
                RunHistoryFinish {
                    result: "commented".to_string(),
                    preview: Some(format!("Review group/repo !{iid}")),
                    summary: Some("same timestamp".to_string()),
                    ..Default::default()
                },
            )
            .await?;
        sqlx::query("UPDATE run_history SET started_at = 5_000, updated_at = 5_000 WHERE id = ?")
            .bind(run_id)
            .execute(store.pool())
            .await?;
        run_ids.push(run_id);
    }

    let first_page = store
        .list_run_history(&RunHistoryListQuery {
            limit: 2,
            ..Default::default()
        })
        .await?;
    assert_eq!(
        first_page.runs.iter().map(|run| run.id).collect::<Vec<_>>(),
        vec![run_ids[2], run_ids[1]]
    );

    let second_page = store
        .list_run_history(&RunHistoryListQuery {
            limit: 2,
            after: first_page.next_cursor,
            ..Default::default()
        })
        .await?;
    assert_eq!(
        second_page
            .runs
            .iter()
            .map(|run| run.id)
            .collect::<Vec<_>>(),
        vec![run_ids[0]]
    );
    Ok(())
}

#[tokio::test]
async fn file_backed_sqlite_uses_wal_and_normal_synchronous() -> Result<()> {
    let temp_dir = env::temp_dir().join(format!("codex-review-state-{}", Uuid::new_v4()));
    fs::create_dir_all(&temp_dir)?;
    let db_path = temp_dir.join("state.sqlite");
    let store = ReviewStateStore::new(db_path.to_str().context("db path utf-8")?).await?;

    let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(store.pool())
        .await?;
    let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
        .fetch_one(store.pool())
        .await?;

    assert_eq!(journal_mode.to_lowercase(), "wal");
    assert_eq!(synchronous, 1);

    drop(store);
    fs::remove_dir_all(temp_dir)?;
    Ok(())
}

#[tokio::test]
async fn reconcile_interrupted_run_history_marks_in_progress_rows_cancelled() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let interrupted_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "sha-interrupted".to_string(),
            discussion_id: Some("discussion-1".to_string()),
            trigger_note_id: Some(9),
            trigger_note_author_name: Some("reviewer".to_string()),
            trigger_note_body: Some("@codex fix this".to_string()),
            command_repo: Some("group/repo".to_string()),
        })
        .await?;
    let finished_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 12,
            head_sha: "sha-finished".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            finished_id,
            RunHistoryFinish {
                result: "pass".to_string(),
                preview: Some("Review group/repo !12".to_string()),
                summary: Some("looks good".to_string()),
                ..Default::default()
            },
        )
        .await?;

    let affected = store
        .reconcile_interrupted_run_history("run interrupted by service restart")
        .await?;
    assert_eq!(affected, 1);

    let interrupted = store
        .get_run_history(interrupted_id)
        .await?
        .expect("interrupted run should exist");
    assert_eq!(interrupted.status, "done".to_string());
    assert_eq!(interrupted.result.as_deref(), Some("cancelled"));
    assert_eq!(
        interrupted.error.as_deref(),
        Some("run interrupted by service restart")
    );
    assert!(interrupted.finished_at.is_some());

    let finished = store
        .get_run_history(finished_id)
        .await?
        .expect("finished run should exist");
    assert_eq!(finished.result.as_deref(), Some("pass"));
    Ok(())
}

#[tokio::test]
async fn run_history_events_roundtrip_in_sequence_order() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 99,
            head_sha: "sha-seq".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: serde_json::json!({"type": "agentMessage", "text": "done"}),
                },
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-1".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({}),
                },
            ],
        )
        .await?;

    let events = store.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].event_type, "turn_started");
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].event_type, "item_completed");
    assert_eq!(events[1].payload["text"], "done");
    Ok(())
}

#[tokio::test]
async fn run_history_events_offset_sequence_across_append_batches() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 100,
            head_sha: "sha-batches".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-a".to_string()),
                event_type: "turn_started".to_string(),
                payload: serde_json::json!({}),
            }],
        )
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"status": "completed"}),
                },
            ],
        )
        .await?;

    let events = store.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].turn_id.as_deref(), Some("turn-b"));
    assert_eq!(events[2].sequence, 3);
    assert_eq!(events[2].turn_id.as_deref(), Some("turn-b"));
    Ok(())
}

#[tokio::test]
async fn mark_run_history_events_incomplete_updates_flag() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 101,
            head_sha: "sha-flag".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    assert!(
        store
            .get_run_history(run_id)
            .await?
            .context("run history row")?
            .events_persisted_cleanly
    );

    store.mark_run_history_events_incomplete(run_id).await?;

    assert!(
        !store
            .get_run_history(run_id)
            .await?
            .context("run history row after mark")?
            .events_persisted_cleanly
    );
    Ok(())
}

#[tokio::test]
async fn transcript_backfill_state_and_event_rewrite_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 102,
            head_sha: "sha-backfill".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: serde_json::json!({
                        "type": "reasoning",
                        "summary": [],
                        "content": []
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"status": "completed"}),
                },
            ],
        )
        .await?;

    store
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    let in_progress = store
        .get_run_history(run_id)
        .await?
        .context("run history row after in-progress update")?;
    assert_eq!(
        in_progress.transcript_backfill_state,
        TranscriptBackfillState::InProgress
    );
    assert_eq!(in_progress.transcript_backfill_error, None);

    store
        .replace_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: serde_json::json!({
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "Recovered summary"}],
                        "content": [{"type": "reasoning_text", "text": "Recovered detail"}]
                    }),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"status": "completed"}),
                },
            ],
        )
        .await?;
    store
        .mark_run_history_transcript_backfill_complete(run_id)
        .await?;

    let run = store
        .get_run_history(run_id)
        .await?
        .context("run history row after rewrite")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Complete
    );
    assert_eq!(run.transcript_backfill_error, None);
    assert!(run.events_persisted_cleanly);

    let events = store.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 3);
    assert_eq!(
        events[1].payload["summary"][0]["text"],
        serde_json::json!("Recovered summary")
    );
    assert_eq!(
        events[1].payload["content"][0]["text"],
        serde_json::json!("Recovered detail")
    );
    Ok(())
}

#[tokio::test]
async fn replace_run_history_events_for_turn_preserves_other_turns() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 103,
            head_sha: "sha-turn-rewrite".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({"label": "turn-a-start"}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-a-end"}),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({"label": "turn-b-start"}),
                },
                NewRunHistoryEvent {
                    sequence: 4,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-b-end"}),
                },
            ],
        )
        .await?;

    store
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    store
        .replace_run_history_events_for_turn(
            run_id,
            "turn-b",
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({"label": "turn-b-new-start"}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "item_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-b-item"}),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-b-new-end"}),
                },
            ],
        )
        .await?;

    let events = store.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[0].payload["label"], "turn-a-start");
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[1].payload["label"], "turn-a-end");
    assert_eq!(events[2].sequence, 3);
    assert_eq!(events[2].turn_id.as_deref(), Some("turn-b"));
    assert_eq!(events[2].payload["label"], "turn-b-new-start");
    assert_eq!(events[3].sequence, 4);
    assert_eq!(events[3].turn_id.as_deref(), Some("turn-b"));
    assert_eq!(events[3].payload["label"], "turn-b-item");
    assert_eq!(events[4].sequence, 5);
    assert_eq!(events[4].turn_id.as_deref(), Some("turn-b"));
    assert_eq!(events[4].payload["label"], "turn-b-new-end");
    Ok(())
}

#[tokio::test]
async fn replace_run_history_events_for_turn_removes_turn_when_rewritten_empty() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 104,
            head_sha: "sha-turn-remove".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;
    store
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .append_run_history_events(
            run_id,
            &[
                NewRunHistoryEvent {
                    sequence: 1,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({"label": "turn-a-start"}),
                },
                NewRunHistoryEvent {
                    sequence: 2,
                    turn_id: Some("turn-a".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-a-end"}),
                },
                NewRunHistoryEvent {
                    sequence: 3,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_started".to_string(),
                    payload: serde_json::json!({"label": "turn-b-start"}),
                },
                NewRunHistoryEvent {
                    sequence: 4,
                    turn_id: Some("turn-b".to_string()),
                    event_type: "turn_completed".to_string(),
                    payload: serde_json::json!({"label": "turn-b-end"}),
                },
            ],
        )
        .await?;

    store
        .replace_run_history_events_for_turn(run_id, "turn-b", &[])
        .await?;

    let events = store.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[0].payload["label"], "turn-a-start");
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[1].payload["label"], "turn-a-end");
    Ok(())
}

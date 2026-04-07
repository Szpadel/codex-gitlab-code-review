use super::*;
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

    let missing = store
        .project_catalog
        .get_project_last_mr_activity(repo)
        .await?;
    assert_eq!(missing, None);

    store
        .project_catalog
        .set_project_last_mr_activity(repo, "2025-01-01T00:00:00Z")
        .await?;
    let loaded = store
        .project_catalog
        .get_project_last_mr_activity(repo)
        .await?;
    assert_eq!(loaded, Some("2025-01-01T00:00:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn project_catalog_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let key = "mode=all;repos=;groups=";
    let projects = vec!["group/repo".to_string(), "group/other".to_string()];

    let missing = store.project_catalog.load_project_catalog(key).await?;
    assert!(missing.is_none());

    store
        .project_catalog
        .save_project_catalog(key, &projects)
        .await?;
    let loaded = store
        .project_catalog
        .load_project_catalog(key)
        .await?
        .expect("catalog");
    assert_eq!(loaded.projects, projects);
    assert!(loaded.fetched_at > 0);
    Ok(())
}

#[tokio::test]
async fn created_after_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let missing = store.service_state.get_created_after().await?;
    assert_eq!(missing, None);

    store
        .service_state
        .set_created_after("2025-01-02T03:04:05Z")
        .await?;
    let loaded = store.service_state.get_created_after().await?;
    assert_eq!(loaded, Some("2025-01-02T03:04:05Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn review_owner_id_is_created_once_and_stable_across_calls() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first = store.service_state.get_or_create_review_owner_id().await?;
    assert!(!first.is_empty());

    let second = store.service_state.get_or_create_review_owner_id().await?;
    assert_eq!(second, first);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_roundtrip_and_clear() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let account = "backup-1";

    let missing = store.service_state.get_auth_limit_reset_at(account).await?;
    assert_eq!(missing, None);

    store
        .service_state
        .set_auth_limit_reset_at(account, "2026-03-02T10:15:00Z")
        .await?;
    let loaded = store.service_state.get_auth_limit_reset_at(account).await?;
    assert_eq!(loaded, Some("2026-03-02T10:15:00Z".to_string()));

    store
        .service_state
        .clear_auth_limit_reset_at(account)
        .await?;
    let cleared = store.service_state.get_auth_limit_reset_at(account).await?;
    assert_eq!(cleared, None);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_tracks_accounts_independently() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .service_state
        .set_auth_limit_reset_at("primary", "2026-03-02T10:15:00Z")
        .await?;
    store
        .service_state
        .set_auth_limit_reset_at("backup-1", "2026-03-02T12:00:00Z")
        .await?;

    let primary = store
        .service_state
        .get_auth_limit_reset_at("primary")
        .await?;
    let backup = store
        .service_state
        .get_auth_limit_reset_at("backup-1")
        .await?;
    assert_eq!(primary, Some("2026-03-02T10:15:00Z".to_string()));
    assert_eq!(backup, Some("2026-03-02T12:00:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_keeps_latest_timestamp_for_account() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let account = "backup-1";

    store
        .service_state
        .set_auth_limit_reset_at(account, "2026-03-02T12:00:00Z")
        .await?;
    store
        .service_state
        .set_auth_limit_reset_at(account, "2026-03-02T10:00:00Z")
        .await?;
    let after_older_write = store.service_state.get_auth_limit_reset_at(account).await?;
    assert_eq!(after_older_write, Some("2026-03-02T12:00:00Z".to_string()));

    store
        .service_state
        .set_auth_limit_reset_at(account, "2026-03-02T13:30:00Z")
        .await?;
    let after_newer_write = store.service_state.get_auth_limit_reset_at(account).await?;
    assert_eq!(after_newer_write, Some("2026-03-02T13:30:00Z".to_string()));
    Ok(())
}

#[tokio::test]
async fn scan_status_roundtrip_and_clear_next_scan() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let initial = store.service_state.get_scan_status().await?;
    assert_eq!(initial.state, ScanState::Idle);
    assert_eq!(initial.mode, None);
    assert_eq!(initial.started_at, None);
    assert_eq!(initial.finished_at, None);
    assert_eq!(initial.outcome, None);
    assert_eq!(initial.error, None);
    assert_eq!(initial.next_scan_at, None);

    store
        .service_state
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

    let running = store.service_state.get_scan_status().await?;
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

    store.service_state.clear_next_scan_at().await?;
    let cleared = store.service_state.get_scan_status().await?;
    assert_eq!(cleared.next_scan_at, None);
    Ok(())
}

#[tokio::test]
async fn auth_limit_reset_listing_returns_sorted_accounts() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .service_state
        .set_auth_limit_reset_at("backup-2", "2026-03-10T12:30:00Z")
        .await?;
    store
        .service_state
        .set_auth_limit_reset_at("primary", "2026-03-10T11:00:00Z")
        .await?;

    let entries = store.service_state.list_auth_limit_reset_entries().await?;
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
        .project_catalog
        .save_project_catalog(
            "all",
            &[
                "group/a".to_string(),
                "group/b".to_string(),
                "group/c".to_string(),
            ],
        )
        .await?;

    let summaries = store
        .project_catalog
        .list_project_catalog_summaries()
        .await?;
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

    let summaries = store
        .project_catalog
        .list_project_catalog_summaries()
        .await?;
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].cache_key, "legacy".to_string());
    assert_eq!(summaries[0].project_count, 2);
    Ok(())
}

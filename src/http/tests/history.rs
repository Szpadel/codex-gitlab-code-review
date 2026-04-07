use super::*;
#[tokio::test]
async fn history_snapshot_filters_runs_and_returns_summary_rows() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let matching_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Mention,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abcdef1".to_string(),
            discussion_id: Some("discussion-1".to_string()),
            trigger_note_id: Some(99),
            trigger_note_author_name: Some("reviewer".to_string()),
            trigger_note_body: Some("please inspect failing pipeline".to_string()),
            command_repo: Some("group/repo".to_string()),
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "committed".to_string(),
            preview: Some("Mention group/repo !7".to_string()),
            summary: Some("Committed a fix".to_string()),
            ..Default::default()
        },
    )
    .await?;
    insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/other".to_string(),
            iid: 8,
            head_sha: "abcdef2".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "pass".to_string(),
            preview: Some("Review group/other !8".to_string()),
            summary: Some("Looks good".to_string()),
            ..Default::default()
        },
    )
    .await?;

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let snapshot = status_service
        .status
        .history_snapshot(
            HistoryQueryParams {
                repo: Some("group/repo".to_string()),
                iid: None,
                kind: Some("mention".to_string()),
                result: None,
                q: Some("failing pipeline".to_string()),
                limit: None,
                page: None,
                after: None,
                before: None,
            }
            .into_query()?,
        )
        .await?;
    let body: Value = serde_json::to_value(snapshot)?;
    let runs = body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].get("id").and_then(Value::as_i64), Some(matching_id));
    assert_eq!(
        runs[0].get("preview").and_then(Value::as_str),
        Some("Mention group/repo !7")
    );
    assert_eq!(
        runs[0].get("summary").and_then(Value::as_str),
        Some("Committed a fix")
    );
    assert_eq!(runs[0].get("trigger_note_body"), None);
    Ok(())
}

#[tokio::test]
async fn history_page_renders_field_based_filters_layout() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 7,
            head_sha: "abc777".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "commented".to_string(),
            preview: Some("Review group/repo !7".to_string()),
            summary: Some("Posted findings".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let started_at = DateTime::parse_from_rfc3339("2026-03-10T12:00:00Z")?
        .with_timezone(&Utc)
        .timestamp();
    sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
        .bind(started_at)
        .bind(started_at)
        .bind(run_id)
        .execute(state.pool())
        .await?;
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/history?repo=group%2Frepo&iid=7&kind=review&q=findings"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("class=\"filter-field\""));
    assert!(body.contains("class=\"filter-field filter-field-wide\""));
    assert!(body.contains("class=\"filter-actions\""));
    assert!(body.contains("name=\"limit\" value=\"100\""));
    assert!(body.contains("name=\"repo\" value=\"group/repo\""));
    assert!(body.contains("name=\"iid\" value=\"7\""));
    assert!(body.contains("class=\"localized-timestamp\""));
    assert!(body.contains("data-timestamp=\"2026-03-10T12:00:00Z\""));
    assert!(body.contains("Mar 10, 2026, 12:00 PM UTC"));
    Ok(())
}

#[tokio::test]
async fn history_snapshot_searches_review_comment_body() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let run_id = insert_run_history(
        &state,
        NewRunHistory {
            kind: RunHistoryKind::Review,
            repo: "group/repo".to_string(),
            iid: 10,
            head_sha: "abc1010".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        },
        RunHistorySessionUpdate::default(),
        RunHistoryFinish {
            result: "comment".to_string(),
            preview: Some("Review group/repo !10".to_string()),
            summary: Some("Posted findings".to_string()),
            error: Some("Please rename this helper before merge.".to_string()),
            ..Default::default()
        },
    )
    .await?;
    let status_service = HttpServices::new(test_config(), Arc::clone(&state), false, None);

    let snapshot = status_service
        .status
        .history_snapshot(
            HistoryQueryParams {
                repo: None,
                iid: None,
                kind: None,
                result: None,
                q: Some("rename this helper".to_string()),
                limit: None,
                page: None,
                after: None,
                before: None,
            }
            .into_query()?,
        )
        .await?;

    assert_eq!(snapshot.runs.len(), 1);
    assert_eq!(snapshot.runs[0].id, run_id);
    Ok(())
}

#[test]
fn history_query_accepts_all_kind_as_unfiltered() -> Result<()> {
    let query = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: Some("all".to_string()),
        result: None,
        q: None,
        limit: None,
        page: None,
        after: None,
        before: None,
    }
    .into_query()?;

    assert_eq!(query.kind, None);
    Ok(())
}

#[test]
fn history_query_accepts_security_kind() -> Result<()> {
    let query = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: Some("security".to_string()),
        result: None,
        q: None,
        limit: None,
        page: None,
        after: None,
        before: None,
    }
    .into_query()?;

    assert_eq!(query.kind, Some(RunHistoryKind::Security));
    Ok(())
}

#[test]
fn history_query_rejects_page_based_pagination() {
    let error = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: None,
        result: None,
        q: None,
        limit: Some(25),
        page: Some(1),
        after: None,
        before: None,
    }
    .into_query()
    .expect_err("page-based history query should be rejected");

    assert!(error.to_string().contains("invalid"));
}

#[test]
fn history_query_rejects_simultaneous_after_and_before() {
    let error = HistoryQueryParams {
        repo: None,
        iid: None,
        kind: None,
        result: None,
        q: None,
        limit: None,
        page: None,
        after: Some("abc".to_string()),
        before: Some("def".to_string()),
    }
    .into_query()
    .expect_err("cursor query should reject simultaneous after and before");

    assert!(error.to_string().contains("invalid"));
}

#[tokio::test]
async fn history_api_returns_cursor_metadata() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut run_ids = Vec::new();
    for (iid, started_at) in [(41u64, 1_000i64), (42, 2_000), (43, 3_000)] {
        let run_id = insert_run_history(
            &state,
            NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            RunHistorySessionUpdate::default(),
            RunHistoryFinish {
                result: "commented".to_string(),
                preview: Some(format!("Review group/repo !{iid}")),
                summary: Some("pagination fixture".to_string()),
                ..Default::default()
            },
        )
        .await?;
        sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
            .bind(started_at)
            .bind(started_at)
            .bind(run_id)
            .execute(state.pool())
            .await?;
        run_ids.push(run_id);
    }
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/api/history?repo=group%2Frepo&limit=1"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let first_body: Value = response.json().await?;
    assert_eq!(first_body.get("limit").and_then(Value::as_u64), Some(1));
    assert_eq!(
        first_body.get("has_previous").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        first_body.get("has_next").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(first_body.get("previous_cursor"), Some(&Value::Null));
    assert_eq!(
        first_body
            .get("filters")
            .and_then(|filters| filters.get("after")),
        Some(&Value::Null)
    );
    let runs = first_body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].get("id").and_then(Value::as_i64), Some(run_ids[2]));
    assert_eq!(runs[0].get("head_sha"), None);

    let next_cursor = first_body
        .get("next_cursor")
        .and_then(Value::as_str)
        .expect("next cursor")
        .to_string();
    let response = reqwest::get(format!(
        "http://{address}/api/history?repo=group%2Frepo&limit=1&after={next_cursor}"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let second_body: Value = response.json().await?;
    assert_eq!(
        second_body.get("has_previous").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        second_body.get("has_next").and_then(Value::as_bool),
        Some(true)
    );
    let second_runs = second_body
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs array");
    assert_eq!(second_runs.len(), 1);
    assert_eq!(
        second_runs[0].get("id").and_then(Value::as_i64),
        Some(run_ids[1])
    );
    Ok(())
}

#[tokio::test]
async fn history_page_renders_pagination_links_with_active_filters() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    for (iid, started_at) in [(51u64, 1_000i64), (52, 2_000)] {
        let run_id = insert_run_history(
            &state,
            NewRunHistory {
                kind: RunHistoryKind::Review,
                repo: "group/repo".to_string(),
                iid,
                head_sha: format!("sha-{iid}"),
                discussion_id: None,
                trigger_note_id: None,
                trigger_note_author_name: None,
                trigger_note_body: None,
                command_repo: None,
            },
            RunHistorySessionUpdate::default(),
            RunHistoryFinish {
                result: "commented".to_string(),
                preview: Some(format!("Review group/repo !{iid}")),
                summary: Some("findings".to_string()),
                ..Default::default()
            },
        )
        .await?;
        sqlx::query("UPDATE run_history SET started_at = ?, updated_at = ? WHERE id = ?")
            .bind(started_at)
            .bind(started_at)
            .bind(run_id)
            .execute(state.pool())
            .await?;
    }
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = reqwest::get(format!(
        "http://{address}/history?repo=group%2Frepo&kind=review&q=findings&limit=1"
    ))
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Showing up to 1 matching runs"));
    assert!(body.contains("pagination-link pagination-link-disabled\">Previous</span>"));
    assert!(body.contains(
        "/history?limit=1&amp;repo=group%2Frepo&amp;kind=review&amp;q=findings&amp;after="
    ));
    Ok(())
}

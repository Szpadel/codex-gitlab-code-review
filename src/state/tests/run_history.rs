use super::*;
#[tokio::test]
async fn run_history_is_append_only_for_same_mr() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;

    let first_id = store
        .run_history
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
        .run_history
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
        .run_history
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

    let records = store
        .run_history
        .list_run_history_for_mr("group/repo", 42)
        .await?;
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
        .run_history
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
        .run_history
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
        .run_history
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
        store
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?,
        RuntimeFeatureFlagOverrides::default()
    );

    let overrides = RuntimeFeatureFlagOverrides {
        gitlab_discovery_mcp: Some(true),
        gitlab_inline_review_comments: Some(false),
        security_review: Some(false),
        security_context_ignore_base_head: Some(true),
        composer_install: Some(true),
        composer_auto_repositories: Some(true),
        composer_safe_install: Some(true),
    };
    store
        .feature_flags
        .set_runtime_feature_flag_overrides(&overrides)
        .await?;

    assert_eq!(
        store
            .feature_flags
            .get_runtime_feature_flag_overrides()
            .await?,
        overrides
    );
    Ok(())
}

#[tokio::test]
async fn run_history_feature_flags_snapshot_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .run_history
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
        security_context_ignore_base_head: true,
        composer_install: true,
        composer_auto_repositories: true,
        composer_safe_install: true,
    };
    store
        .run_history
        .set_run_history_feature_flags(run_id, &feature_flags)
        .await?;

    let record = store
        .run_history
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
        .run_history
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
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row should exist")?;
    assert_eq!(record.kind, RunHistoryKind::Security);
    Ok(())
}

#[tokio::test]
async fn run_history_session_roundtrips_security_context_metadata() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .run_history
        .start_run_history(NewRunHistory {
            kind: RunHistoryKind::Security,
            repo: "group/repo".to_string(),
            iid: 13,
            head_sha: "sha-security".to_string(),
            discussion_id: None,
            trigger_note_id: None,
            trigger_note_author_name: None,
            trigger_note_body: None,
            command_repo: None,
        })
        .await?;

    store
        .run_history
        .update_run_history_session(
            run_id,
            RunHistorySessionUpdate {
                security_context_source_run_id: Some(run_id),
                security_context_base_branch: Some("main".to_string()),
                security_context_base_head_sha: Some("base-sha".to_string()),
                security_context_prompt_version: Some("security-review-context-v1".to_string()),
                security_context_payload_json: Some("{\"components\":[\"api\"]}".to_string()),
                security_context_generated_at: Some(100),
                security_context_expires_at: Some(200),
                ..RunHistorySessionUpdate::default()
            },
        )
        .await?;

    let record = store
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row should exist")?;
    assert_eq!(record.security_context_source_run_id, Some(run_id));
    assert_eq!(record.security_context_base_branch.as_deref(), Some("main"));
    assert_eq!(
        record.security_context_base_head_sha.as_deref(),
        Some("base-sha")
    );
    assert_eq!(
        record.security_context_prompt_version.as_deref(),
        Some("security-review-context-v1")
    );
    assert_eq!(
        record.security_context_payload_json.as_deref(),
        Some("{\"components\":[\"api\"]}")
    );
    assert_eq!(record.security_context_generated_at, Some(100));
    assert_eq!(record.security_context_expires_at, Some(200));
    Ok(())
}

#[tokio::test]
async fn run_history_filters_by_mr() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let first = store
        .run_history
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
        .run_history
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
        .run_history
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

    let records = store
        .run_history
        .list_run_history_for_mr("group/repo", 11)
        .await?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].repo, "group/repo".to_string());
    assert_eq!(records[0].iid, 11);
    Ok(())
}

#[tokio::test]
async fn completed_inline_review_detection_respects_security_kind() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let run_id = store
        .run_history
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
        .run_history
        .set_run_history_feature_flags(
            run_id,
            &FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                ..FeatureFlagSnapshot::default()
            },
        )
        .await?;
    store
        .run_history
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
            .run_history
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
            .run_history
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
            .run_history
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
        .run_history
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
        .run_history
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

    let first_page = store.run_history.list_run_history(&filtered).await?;
    assert_eq!(first_page.runs.len(), 1);
    assert_eq!(first_page.runs[0].id, run_ids[2]);
    assert_eq!(first_page.has_previous, false);
    assert_eq!(first_page.has_next, true);

    let second_page = store
        .run_history
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
        .run_history
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
            .run_history
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
            .run_history
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
        .run_history
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
        .run_history
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
        .run_history
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
        .run_history
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
        .run_history
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
        .run_history
        .reconcile_interrupted_run_history("run interrupted by service restart")
        .await?;
    assert_eq!(affected, 1);

    let interrupted = store
        .run_history
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
        .run_history
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
        .run_history
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
        .run_history
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

    let events = store.run_history.list_run_history_events(run_id).await?;
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
        .run_history
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
        .run_history
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
        .run_history
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

    let events = store.run_history.list_run_history_events(run_id).await?;
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
        .run_history
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
        .run_history
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
            .run_history
            .get_run_history(run_id)
            .await?
            .context("run history row")?
            .events_persisted_cleanly
    );

    store
        .run_history
        .mark_run_history_events_incomplete(run_id)
        .await?;

    assert!(
        !store
            .run_history
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
        .run_history
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
        .run_history
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .run_history
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
        .run_history
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    let in_progress = store
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after in-progress update")?;
    assert_eq!(
        in_progress.transcript_backfill_state,
        TranscriptBackfillState::InProgress
    );
    assert_eq!(in_progress.transcript_backfill_error, None);

    store
        .run_history
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
        .run_history
        .mark_run_history_transcript_backfill_complete(run_id)
        .await?;

    let run = store
        .run_history
        .get_run_history(run_id)
        .await?
        .context("run history row after rewrite")?;
    assert_eq!(
        run.transcript_backfill_state,
        TranscriptBackfillState::Complete
    );
    assert_eq!(run.transcript_backfill_error, None);
    assert!(run.events_persisted_cleanly);

    let events = store.run_history.list_run_history_events(run_id).await?;
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
        .run_history
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
        .run_history
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .run_history
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
        .run_history
        .update_run_history_transcript_backfill(run_id, TranscriptBackfillState::InProgress, None)
        .await?;
    store
        .run_history
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

    let events = store.run_history.list_run_history_events(run_id).await?;
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
        .run_history
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
        .run_history
        .finish_run_history(
            run_id,
            RunHistoryFinish {
                result: "commented".to_string(),
                ..Default::default()
            },
        )
        .await?;
    store
        .run_history
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
        .run_history
        .replace_run_history_events_for_turn(run_id, "turn-b", &[])
        .await?;

    let events = store.run_history.list_run_history_events(run_id).await?;
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].sequence, 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[0].payload["label"], "turn-a-start");
    assert_eq!(events[1].sequence, 2);
    assert_eq!(events[1].turn_id.as_deref(), Some("turn-a"));
    assert_eq!(events[1].payload["label"], "turn-a-end");
    Ok(())
}

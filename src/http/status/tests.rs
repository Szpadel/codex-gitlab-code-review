use super::{
    StatusService, TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
    TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR, TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR,
    events_have_missing_review_child_history, fallback_session_history_path,
    initial_backfill_candidate_events, is_final_retry_window_attempt_pending,
    merge_recovered_target_turn_events, missing_history_retry_window_open,
    missing_review_child_history_has_renderable_fallback, persisted_turn_ids_are_covered,
    preserve_auxiliary_persisted_events, primary_session_history_path,
    sanitize_persisted_events_for_backfill, should_retry_transcript_backfill_error,
    should_retry_transcript_backfill_failure, strip_missing_review_child_history_markers,
    terminal_transcript_backfill_error_text, turn_ids_from_new_events,
};
use crate::config::{
    BrowserMcpConfig, CodexConfig, Config, DatabaseConfig, DockerConfig, GitLabConfig,
    GitLabDiscoveryMcpConfig, GitLabTargets, McpServerOverridesConfig,
    ReasoningEffortOverridesConfig, ReasoningSummaryOverridesConfig, ReviewConfig,
    ReviewMentionCommandsConfig, ScheduleConfig, ServerConfig, TargetSelector,
};
use crate::feature_flags::{FeatureFlagDefaults, FeatureFlagSnapshot};
use crate::state::{
    ReviewStateStore, RunHistoryEventRecord, RunHistoryKind, RunHistoryRecord,
    TranscriptBackfillState,
};
use crate::transcript_backfill::TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR;
use serde_json::json;
use std::sync::Arc;

#[test]
fn primary_session_history_defaults_to_auth_host_sessions_dir() {
    assert_eq!(
        primary_session_history_path("/srv/codex-auth", "/root/.codex", None),
        "/srv/codex-auth/sessions"
    );
    assert_eq!(
        primary_session_history_path("/srv/codex-auth/", "/root/.codex", None),
        "/srv/codex-auth/sessions"
    );
}

#[test]
fn fallback_session_history_preserves_primary_suffix() {
    assert_eq!(
        fallback_session_history_path(
            "/srv/codex-auth",
            "/root/.codex",
            "/srv/codex-auth/sessions/archive",
            "/srv/fallback-account",
        ),
        "/srv/fallback-account/sessions/archive"
    );
}

#[test]
fn fallback_session_history_defaults_to_fallback_auth_sessions_dir_for_custom_primary_path() {
    assert_eq!(
        fallback_session_history_path(
            "/srv/codex-auth",
            "/root/.codex",
            "/custom/transcripts/archive",
            "/srv/fallback-account",
        ),
        "/srv/fallback-account/sessions"
    );
}

#[test]
fn turn_id_helpers_ignore_auxiliary_startup_warning_turns() {
    let persisted_turn_ids = std::collections::HashSet::from([
        "gitlab-discovery-mcp-startup".to_string(),
        "composer-install".to_string(),
        "turn-1".to_string(),
    ]);
    let full_thread_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("composer-install".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 3,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
    ];

    assert!(persisted_turn_ids_are_covered(
        &persisted_turn_ids,
        &full_thread_events
    ));
    assert_eq!(
        turn_ids_from_new_events(&full_thread_events),
        std::collections::HashSet::from(["turn-1".to_string()])
    );
}

#[test]
fn preserve_auxiliary_persisted_events_reinjects_startup_warning_turn() {
    let persisted_events = vec![
        RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 2,
            run_history_id: 1,
            sequence: 2,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "agentMessage",
                "text": "GitLab discovery MCP startup warning"
            }),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 3,
            run_history_id: 1,
            sequence: 3,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
            created_at: 0,
        },
    ];
    let rewritten_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];

    let merged = preserve_auxiliary_persisted_events(&persisted_events, rewritten_events);

    assert_eq!(merged.len(), 5);
    assert_eq!(
        merged
            .iter()
            .filter_map(|event| event.turn_id.as_deref())
            .collect::<Vec<_>>(),
        vec![
            "gitlab-discovery-mcp-startup",
            "gitlab-discovery-mcp-startup",
            "gitlab-discovery-mcp-startup",
            "turn-1",
            "turn-1",
        ]
    );
    assert_eq!(merged[0].sequence, 1);
    assert_eq!(merged[4].sequence, 5);
}

#[test]
fn preserve_auxiliary_persisted_events_reinjects_composer_install_turn() {
    let persisted_events = vec![
        RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("composer-install".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 2,
            run_history_id: 1,
            sequence: 2,
            turn_id: Some("composer-install".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "commandExecution",
                "command": "composer install --no-interaction --no-progress --ignore-platform-reqs",
                "aggregatedOutput": "Installing dependencies",
                "status": "completed"
            }),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 3,
            run_history_id: 1,
            sequence: 3,
            turn_id: Some("composer-install".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
            created_at: 0,
        },
    ];
    let rewritten_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];

    let merged = preserve_auxiliary_persisted_events(&persisted_events, rewritten_events);

    assert_eq!(merged.len(), 5);
    assert_eq!(
        merged
            .iter()
            .filter_map(|event| event.turn_id.as_deref())
            .collect::<Vec<_>>(),
        vec![
            "composer-install",
            "composer-install",
            "composer-install",
            "turn-1",
            "turn-1",
        ]
    );
    assert_eq!(merged[0].sequence, 1);
    assert_eq!(merged[4].sequence, 5);
}

#[test]
fn preserve_auxiliary_persisted_events_keeps_missing_auxiliary_turns_in_mixed_runs() {
    let persisted_events = vec![
        RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 2,
            run_history_id: 1,
            sequence: 2,
            turn_id: Some("composer-install".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 3,
            run_history_id: 1,
            sequence: 3,
            turn_id: Some("composer-install".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
            created_at: 0,
        },
    ];
    let rewritten_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 3,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 4,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];

    let merged = preserve_auxiliary_persisted_events(&persisted_events, rewritten_events);

    assert_eq!(
        merged
            .iter()
            .filter_map(|event| event.turn_id.as_deref())
            .collect::<Vec<_>>(),
        vec![
            "composer-install",
            "composer-install",
            "gitlab-discovery-mcp-startup",
            "gitlab-discovery-mcp-startup",
            "turn-1",
            "turn-1",
        ]
    );
}

#[test]
fn initial_backfill_candidate_events_preserves_auxiliary_turns_for_turnless_rewrite() {
    let persisted_events = vec![
        RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        },
        RunHistoryEventRecord {
            id: 2,
            run_history_id: 1,
            sequence: 2,
            turn_id: Some("gitlab-discovery-mcp-startup".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
            created_at: 0,
        },
    ];
    let turn_scoped_events = Some(vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-1".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ]);

    let merged = initial_backfill_candidate_events(&persisted_events, None, turn_scoped_events)
        .expect("turn-less rewrite should keep auxiliary startup warning");

    assert_eq!(
        merged
            .iter()
            .filter_map(|event| event.turn_id.as_deref())
            .collect::<Vec<_>>(),
        vec![
            "gitlab-discovery-mcp-startup",
            "gitlab-discovery-mcp-startup",
            "turn-1",
            "turn-1",
        ]
    );
}

#[test]
fn primary_session_history_preserves_explicit_custom_root() {
    assert_eq!(
        primary_session_history_path(
            "/srv/codex-auth",
            "/root/.codex",
            Some("/var/lib/codex-history"),
        ),
        "/var/lib/codex-history"
    );
}

#[tokio::test]
async fn status_snapshot_includes_feature_flag_state() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = StatusService::new(test_config(), store, false, None);

    let snapshot = service.snapshot().await?;

    assert_eq!(snapshot.config.feature_flags.len(), 6);
    assert_eq!(
        snapshot
            .config
            .feature_flags
            .iter()
            .map(|flag| flag.name.as_str())
            .collect::<Vec<_>>(),
        vec![
            "gitlab_discovery_mcp",
            "gitlab_inline_review_comments",
            "security_review",
            "composer_install",
            "composer_auto_repositories",
            "composer_safe_install",
        ]
    );
    assert!(
        snapshot
            .config
            .feature_flags
            .iter()
            .all(|flag| !flag.effective_enabled)
    );
    Ok(())
}

#[tokio::test]
async fn update_runtime_feature_flag_persists_override() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    let mut config = test_config();
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/source".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/target".to_string()],
        target_groups: Vec::new(),
    }];
    let service = StatusService::new(config, Arc::clone(&store), false, None);

    let updated = service
        .update_runtime_feature_flag("gitlab_discovery_mcp", Some(true))
        .await?;

    assert_eq!(updated.runtime_override, Some(true));
    assert!(updated.effective_enabled);
    assert_eq!(
        store
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn update_runtime_feature_flag_persists_security_review_override() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

    let updated = service
        .update_runtime_feature_flag("security_review", Some(true))
        .await?;

    assert_eq!(updated.runtime_override, Some(true));
    assert!(updated.effective_enabled);
    assert_eq!(
        store
            .get_runtime_feature_flag_overrides()
            .await?
            .security_review,
        Some(true)
    );
    Ok(())
}

#[tokio::test]
async fn update_runtime_feature_flag_rejects_unavailable_flags() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

    let result = service
        .update_runtime_feature_flag("gitlab_discovery_mcp", Some(true))
        .await;

    assert!(result.is_err());
    assert_eq!(
        store
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[tokio::test]
async fn update_runtime_feature_flag_persists_composer_overrides() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

    let updated = service
        .update_runtime_feature_flag("composer_install", Some(true))
        .await?;
    assert_eq!(updated.runtime_override, Some(true));
    assert!(updated.effective_enabled);

    let auto_repo_updated = service
        .update_runtime_feature_flag("composer_auto_repositories", Some(true))
        .await?;
    assert_eq!(auto_repo_updated.runtime_override, Some(true));
    assert!(auto_repo_updated.effective_enabled);

    let safe_updated = service
        .update_runtime_feature_flag("composer_safe_install", Some(true))
        .await?;
    assert_eq!(safe_updated.runtime_override, Some(true));
    assert!(safe_updated.effective_enabled);

    let stored = store.get_runtime_feature_flag_overrides().await?;
    assert_eq!(stored.composer_install, Some(true));
    assert_eq!(stored.composer_auto_repositories, Some(true));
    assert_eq!(stored.composer_safe_install, Some(true));
    Ok(())
}

#[tokio::test]
async fn update_runtime_feature_flag_allows_clearing_unavailable_override() -> anyhow::Result<()> {
    let store = Arc::new(ReviewStateStore::new(":memory:").await?);
    store
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let service = StatusService::new(test_config(), Arc::clone(&store), false, None);

    let updated = service
        .update_runtime_feature_flag("gitlab_discovery_mcp", None)
        .await?;

    assert_eq!(updated.runtime_override, None);
    assert!(!updated.effective_enabled);
    assert_eq!(
        store
            .get_runtime_feature_flag_overrides()
            .await?
            .gitlab_discovery_mcp,
        None
    );
    Ok(())
}

#[test]
fn missing_history_and_unavailable_source_retry_only_for_recent_runs() {
    let recent_run = sample_run_history_record(1_000);
    let stale_run = sample_run_history_record(0);

    assert!(missing_history_retry_window_open(&recent_run, 1_100));
    assert!(!missing_history_retry_window_open(&stale_run, 1_000));
}

#[test]
fn incomplete_session_history_errors_retry_only_for_recent_runs() {
    let recent_run = sample_run_history_record(chrono::Utc::now().timestamp());
    let stale_run = sample_run_history_record(0);

    assert!(should_retry_transcript_backfill_error(
        &recent_run,
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
    ));
    assert!(!should_retry_transcript_backfill_error(
        &stale_run,
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR
    ));
}

#[test]
fn stale_incomplete_session_history_errors_are_reworded_for_terminal_state() {
    let stale_run = sample_run_history_record(0);
    let should_retry = should_retry_transcript_backfill_error(
        &stale_run,
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
    );
    assert!(!should_retry);
    assert_eq!(
        terminal_transcript_backfill_error_text(
            TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
            should_retry,
        ),
        TRANSCRIPT_BACKFILL_STALE_INCOMPLETE_ERROR
    );
}

#[test]
fn stale_missing_history_errors_are_reworded_for_terminal_state() {
    let stale_run = sample_run_history_record(0);
    let should_retry = should_retry_transcript_backfill_error(
        &stale_run,
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
    );
    assert!(!should_retry);
    assert_eq!(
        terminal_transcript_backfill_error_text(
            TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
            should_retry,
        ),
        TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR
    );
    assert!(is_final_retry_window_attempt_pending(
        &stale_run,
        TRANSCRIPT_BACKFILL_MISSING_HISTORY_ERROR,
    ));
    assert!(!is_final_retry_window_attempt_pending(
        &stale_run,
        TRANSCRIPT_BACKFILL_STALE_MISSING_HISTORY_ERROR,
    ));
}

#[test]
fn retry_window_errors_get_one_more_retry_when_attempt_started_before_deadline() {
    let stale_run = sample_run_history_record(0);

    assert!(should_retry_transcript_backfill_failure(
        &stale_run,
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
        true,
    ));
    assert!(!should_retry_transcript_backfill_failure(
        &stale_run,
        TRANSCRIPT_BACKFILL_SOURCE_INCOMPLETE_ERROR,
        false,
    ));
}

#[test]
fn review_child_history_retry_marker_requires_retry_until_fallback_is_allowed() {
    let events = vec![crate::state::NewRunHistoryEvent {
        sequence: 1,
        turn_id: Some("turn-parent".to_string()),
        event_type: "item_completed".to_string(),
        payload: json!({
            "type": "enteredReviewMode",
            "reviewMissingChildTurnIds": ["turn-child"]
        }),
    }];

    assert!(events_have_missing_review_child_history(&events));
    assert_eq!(
        strip_missing_review_child_history_markers(events.clone())[0]
            .payload
            .get("reviewMissingChildTurnIds"),
        None
    );
}

#[test]
fn missing_review_child_history_fallback_requires_renderable_wrapper_output() {
    let wrapper_only_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-parent".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];
    assert!(!missing_review_child_history_has_renderable_fallback(
        &wrapper_only_events
    ));

    let wrapper_fallback_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "agentMessage",
                "text": "Wrapper-only review message.",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 3,
            turn_id: Some("turn-parent".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];
    assert!(missing_review_child_history_has_renderable_fallback(
        &wrapper_fallback_events
    ));

    let unmarked_message_events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "agentMessage",
                "text": "Later same-turn message"
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 3,
            turn_id: Some("turn-parent".to_string()),
            event_type: "turn_completed".to_string(),
            payload: json!({"status": "completed"}),
        },
    ];
    assert!(!missing_review_child_history_has_renderable_fallback(
        &unmarked_message_events
    ));
}

#[test]
fn missing_review_child_history_fallback_must_be_on_the_same_turn() {
    let events = vec![
        crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-missing".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewMissingChildTurnIds": ["turn-child"]
            }),
        },
        crate::state::NewRunHistoryEvent {
            sequence: 2,
            turn_id: Some("turn-other".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "agentMessage",
                "text": "Unrelated rendered output"
            }),
        },
    ];

    assert!(!missing_review_child_history_has_renderable_fallback(
        &events
    ));
}

#[test]
fn sanitize_persisted_events_for_backfill_preserves_started_only_non_target_turns() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "renderable"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        None,
    );

    assert_eq!(events.len(), 3);
    assert_eq!(events[2].turn_id.as_deref(), Some("turn-stale-child"));
    assert_eq!(events[2].event_type, "turn_started");
}

#[test]
fn sanitize_persisted_events_for_backfill_preserves_target_turn_without_items() {
    let events = sanitize_persisted_events_for_backfill(
        vec![RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("turn-target".to_string()),
            event_type: "turn_started".to_string(),
            payload: json!({}),
            created_at: 0,
        }],
        Some("turn-target"),
        None,
    );

    assert_eq!(events.len(), 1);
    assert_eq!(events[0].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(events[0].event_type, "turn_started");
}

#[test]
fn sanitize_persisted_events_for_backfill_drops_empty_completed_non_target_turns() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "renderable"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 4,
                run_history_id: 1,
                sequence: 4,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        None,
    );

    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
}

#[test]
fn sanitize_persisted_events_for_backfill_drops_earlier_empty_non_target_turns() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 4,
                run_history_id: 1,
                sequence: 4,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "renderable"}),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        None,
    );

    assert_eq!(events.len(), 2);
    assert!(
        events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-parent"))
    );
}

#[test]
fn sanitize_persisted_events_for_backfill_drops_non_target_turns_for_review_wrapper_rewrites() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "stale child"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-stale-child".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        Some(&[crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "createdAt": "2026-03-11T21:32:37.160Z",
                "reviewChildTurnIds": ["turn-stale-child"]
            }),
        }]),
    );

    assert!(events.is_empty());
}

#[test]
fn sanitize_persisted_events_for_backfill_preserves_timestamped_later_turn_when_parent_missing() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:40:00.000Z"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:40:02.000Z"
                }),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        Some(&[crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "createdAt": "2026-03-11T21:32:37.160Z"
            }),
        }]),
    );

    assert_eq!(events.len(), 3);
    assert!(
        events
            .iter()
            .all(|event| event.turn_id.as_deref() == Some("turn-later"))
    );
}

#[test]
fn sanitize_persisted_events_for_backfill_preserves_interleaved_non_child_turns() {
    let events = sanitize_persisted_events_for_backfill(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-parent".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "parent start"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 3,
                run_history_id: 1,
                sequence: 3,
                turn_id: Some("turn-other".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 4,
                run_history_id: 1,
                sequence: 4,
                turn_id: Some("turn-other".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "other turn"}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 5,
                run_history_id: 1,
                sequence: 5,
                turn_id: Some("turn-parent".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
                created_at: 0,
            },
        ],
        Some("turn-parent"),
        Some(&[crate::state::NewRunHistoryEvent {
            sequence: 1,
            turn_id: Some("turn-parent".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "enteredReviewMode",
                "reviewChildTurnIds": ["turn-stale-child"]
            }),
        }]),
    );

    assert_eq!(events.len(), 5);
    assert!(
        events
            .iter()
            .any(|event| event.turn_id.as_deref() == Some("turn-other"))
    );
}

#[test]
fn merge_recovered_target_turn_events_appends_after_timestamp_less_existing_turns() {
    let merged = merge_recovered_target_turn_events(
        vec![RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("turn-later".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({"type": "agentMessage", "text": "later turn"}),
            created_at: 0,
        }],
        "turn-target",
        &[
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-target".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({"type": "agentMessage", "text": "target turn"}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({"status": "completed"}),
            },
        ],
    )
    .expect("merged recovered target turn events");

    assert_eq!(merged[0].turn_id.as_deref(), Some("turn-later"));
    assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[3].turn_id.as_deref(), Some("turn-target"));
}

#[test]
fn merge_recovered_target_turn_events_inserts_before_later_turn_start_without_timestamp() {
    let merged = merge_recovered_target_turn_events(
        vec![
            RunHistoryEventRecord {
                id: 1,
                run_history_id: 1,
                sequence: 1,
                turn_id: Some("turn-later".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({}),
                created_at: 0,
            },
            RunHistoryEventRecord {
                id: 2,
                run_history_id: 1,
                sequence: 2,
                turn_id: Some("turn-later".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "later turn",
                    "createdAt": "2026-03-11T21:40:01.000Z"
                }),
                created_at: 0,
            },
        ],
        "turn-target",
        &[
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.000Z"}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-target".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "target turn",
                    "createdAt": "2026-03-11T21:32:38.000Z"
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:39.000Z"
                }),
            },
        ],
    )
    .expect("merged recovered target turn events before later turn start");

    assert_eq!(merged[0].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[3].turn_id.as_deref(), Some("turn-later"));
    assert_eq!(merged[3].event_type, "turn_started");
    assert_eq!(merged[4].turn_id.as_deref(), Some("turn-later"));
}

#[test]
fn merge_recovered_target_turn_events_appends_when_target_is_newest_turn() {
    let merged = merge_recovered_target_turn_events(
        vec![RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("turn-old".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({
                "type": "agentMessage",
                "text": "older turn",
                "createdAt": "2026-03-11T21:20:00.000Z"
            }),
            created_at: 0,
        }],
        "turn-target",
        &[
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2026-03-11T21:32:37.000Z"}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-target".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "target turn",
                    "createdAt": "2026-03-11T21:32:38.000Z"
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2026-03-11T21:32:39.000Z"
                }),
            },
        ],
    )
    .expect("merged recovered target turn events after older turns");

    assert_eq!(merged[0].turn_id.as_deref(), Some("turn-old"));
    assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[3].turn_id.as_deref(), Some("turn-target"));
}

#[test]
fn merge_recovered_target_turn_events_uses_row_created_at_when_payload_timestamps_are_missing() {
    let merged = merge_recovered_target_turn_events(
        vec![RunHistoryEventRecord {
            id: 1,
            run_history_id: 1,
            sequence: 1,
            turn_id: Some("turn-later".to_string()),
            event_type: "item_completed".to_string(),
            payload: json!({"type": "agentMessage", "text": "later turn"}),
            created_at: 1_741_800_000,
        }],
        "turn-target",
        &[
            crate::state::NewRunHistoryEvent {
                sequence: 1,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_started".to_string(),
                payload: json!({"createdAt": "2025-03-11T21:32:37.000Z"}),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 2,
                turn_id: Some("turn-target".to_string()),
                event_type: "item_completed".to_string(),
                payload: json!({
                    "type": "agentMessage",
                    "text": "target turn",
                    "createdAt": "2025-03-11T21:32:38.000Z"
                }),
            },
            crate::state::NewRunHistoryEvent {
                sequence: 3,
                turn_id: Some("turn-target".to_string()),
                event_type: "turn_completed".to_string(),
                payload: json!({
                    "status": "completed",
                    "createdAt": "2025-03-11T21:32:39.000Z"
                }),
            },
        ],
    )
    .expect("merged recovered target turn events using row created_at");

    assert_eq!(merged[0].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[1].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[2].turn_id.as_deref(), Some("turn-target"));
    assert_eq!(merged[3].turn_id.as_deref(), Some("turn-later"));
}

fn sample_run_history_record(updated_at: i64) -> RunHistoryRecord {
    RunHistoryRecord {
        id: 1,
        kind: RunHistoryKind::Review,
        repo: "group/repo".to_string(),
        iid: 1,
        head_sha: "sha".to_string(),
        status: "done".to_string(),
        result: Some("commented".to_string()),
        started_at: updated_at,
        finished_at: Some(updated_at),
        updated_at,
        thread_id: Some("thread-1".to_string()),
        turn_id: Some("turn-1".to_string()),
        review_thread_id: None,
        preview: Some("Preview".to_string()),
        summary: None,
        error: None,
        auth_account_name: None,
        discussion_id: None,
        trigger_note_id: None,
        trigger_note_author_name: None,
        trigger_note_body: None,
        command_repo: None,
        commit_sha: None,
        feature_flags: FeatureFlagSnapshot::default(),
        events_persisted_cleanly: false,
        transcript_backfill_state: TranscriptBackfillState::Failed,
        transcript_backfill_error: Some("matching Codex session history was not found".to_string()),
    }
}

fn test_config() -> Config {
    Config {
        feature_flags: FeatureFlagDefaults::default(),
        gitlab: GitLabConfig {
            base_url: "https://gitlab.example.com".to_string(),
            token: String::new(),
            bot_user_id: Some(1),
            created_after: None,
            targets: GitLabTargets {
                repos: TargetSelector::List(vec!["group/repo".to_string()]),
                groups: TargetSelector::List(vec![]),
                exclude_repos: vec![],
                exclude_groups: vec![],
                refresh_seconds: 3600,
            },
        },
        schedule: ScheduleConfig {
            cron: "0 */10 * * * *".to_string(),
            timezone: Some("UTC".to_string()),
        },
        review: ReviewConfig {
            max_concurrent: 2,
            eyes_emoji: "eyes".to_string(),
            thumbs_emoji: "thumbsup".to_string(),
            comment_marker_prefix: "<!-- codex-review:sha=".to_string(),
            stale_in_progress_minutes: 120,
            dry_run: true,
            additional_developer_instructions: None,
            security: crate::config::ReviewSecurityConfig::default(),
            mention_commands: ReviewMentionCommandsConfig {
                enabled: false,
                bot_username: None,
                eyes_emoji: None,
                additional_developer_instructions: None,
            },
        },
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 1800,
            auth_host_path: "/tmp/codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: vec![],
            usage_limit_fallback_cooldown_seconds: 3600,
            deps: Default::default(),
            browser_mcp: BrowserMcpConfig::default(),
            gitlab_discovery_mcp: GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            reasoning_effort: ReasoningEffortOverridesConfig::default(),
            reasoning_summary: ReasoningSummaryOverridesConfig::default(),
        },
        docker: DockerConfig::default(),
        database: DatabaseConfig {
            path: ":memory:".to_string(),
        },
        server: ServerConfig {
            bind_addr: "127.0.0.1:0".to_string(),
            status_ui_enabled: true,
        },
    }
}

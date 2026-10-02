use super::*;
use crate::flow::admission::AdmissionHistory;
use crate::flow::{ActiveTaskRegistry, FlowShared, mention::MentionFlow};

#[tokio::test]
async fn mention_runner_rejected_after_stop_during_mr_refresh() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("bot".to_string());
    let merge_request = mr(1, "sha1");
    let inner = fake_gitlab(vec![merge_request.clone()]);
    inner.discussions.lock().unwrap().insert(
        ("group/repo".to_string(), 1),
        vec![MergeRequestDiscussion {
            id: "discussion".to_string(),
            individual_note: false,
            notes: vec![DiscussionNote {
                id: 2,
                body: "@bot please check".to_string(),
                author: GitLabUser {
                    id: 7,
                    username: Some("alice".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            }],
        }],
    );
    let lifecycle = Arc::new(ServiceLifecycle::default());
    let mut gitlab = InlineReviewGitLab::new(inner.clone(), vec![], vec![]);
    gitlab.stop_on_mr_refresh = Some(lifecycle.clone());
    let gitlab = Arc::new(gitlab);
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let flow = MentionFlow::new(FlowShared {
        config,
        gitlab: gitlab.clone(),
        award_service: AwardService::new(gitlab.clone(), 1),
        state: state.clone(),
        codex: runner.clone(),
        bot_user_id: 1,
        created_after: default_created_after(),
        lifecycle,
        active_tasks: Arc::new(ActiveTaskRegistry::default()),
        rescan_requests: Arc::default(),
    });
    let history = AdmissionHistory::new(gitlab.as_ref(), "group/repo", 1);
    let admission = flow
        .admit_for_scan("group/repo", &merge_request, "sha1", &history)
        .await?;
    assert_eq!(admission.jobs.len(), 1);
    for job in admission.jobs {
        flow.run_queued(job).await;
    }

    assert_eq!(
        *runner.mention_calls.lock().unwrap(),
        0,
        "shutdown must prevent the mention runner from starting"
    );
    let row =
        sqlx::query("SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ?")
            .bind("group/repo")
            .bind(1_i64)
            .fetch_one(state.pool())
            .await?;
    assert_eq!(row.try_get::<String, _>("status")?, "done");
    assert_eq!(row.try_get::<String, _>("result")?, "cancelled");
    let history = state
        .run_history
        .list_run_history_for_mr("group/repo", 1)
        .await?;
    assert_eq!(history[0].result.as_deref(), Some("cancelled"));
    assert!(
        inner
            .list_discussion_note_awards("group/repo", 1, "discussion", 2)
            .await?
            .is_empty()
    );
    assert!(!inner.calls.lock().unwrap().iter().any(|call| {
        call.starts_with("create_discussion_note:") || call.starts_with("create_note:")
    }));
    Ok(())
}

use super::*;
#[tokio::test]
async fn security_inline_review_comments_link_sectioned_references() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.gitlab_inline_review_comments = true;
    let render_sectioned_body = |sections: &[(&str, String)]| -> String {
        sections
            .iter()
            .map(|(label, body)| format!("{label}:\n{body}"))
            .collect::<Vec<_>>()
            .join("\n\n")
    };
    let auth_ref = "`/work/repo/group/repo/src/auth.rs:10`";
    let http_ref = "`/work/repo/group/repo/src/http.rs:22`";
    let finding_body = render_sectioned_body(&[
        ("Summary", format!("Untrusted callers can reach {auth_ref}.")),
        (
            "Severity",
            format!("P1 because {auth_ref} removes the only authorization gate."),
        ),
        (
            "Reproduction",
            format!("Replay the existing request flow and hit {auth_ref}."),
        ),
        (
            "Evidence",
            format!(
                "{auth_ref} returns before the guard and {http_ref} still executes the privileged handler."
            ),
        ),
        (
            "Attack-path analysis",
            "An attacker-controlled request crosses the HTTP boundary, bypasses the role check, and reaches the privileged sink.".to_string(),
        ),
        (
            "Likelihood",
            "High because the endpoint is externally reachable.".to_string(),
        ),
        ("Impact", "Cross-tenant data exposure.".to_string()),
        (
            "Assumptions",
            "The route is reachable to ordinary API clients.".to_string(),
        ),
        (
            "Blindspots",
            format!("Did not validate proxy-specific auth at {http_ref}."),
        ),
    ]);

    let mut merge_request = mr(25, "sha25");
    merge_request.web_url =
        Some("https://gitlab.example.com/group/repo/-/merge_requests/25".to_string());
    let inner = fake_gitlab(vec![merge_request.clone()]);
    let gitlab = Arc::new(InlineReviewGitLab::new(
        Arc::clone(&inner),
        vec![MergeRequestDiffVersion {
            id: 1,
            head_commit_sha: "sha25".to_string(),
            base_commit_sha: "base25".to_string(),
            start_commit_sha: "start25".to_string(),
        }],
        vec![MergeRequestDiff {
            old_path: "src/auth.rs".to_string(),
            new_path: "src/auth.rs".to_string(),
            diff: "@@ -10,1 +10,1 @@\n-old\n+new\n".to_string(),
            new_file: false,
            deleted_file: false,
            renamed_file: false,
            collapsed: false,
            too_large: false,
        }],
    ));
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Comment(
            crate::codex_runner::ReviewComment {
                summary: "confirmed auth bypass".to_string(),
                overall_explanation: None,
                overall_confidence_score: Some(0.93),
                findings: vec![crate::codex_runner::ReviewFinding {
                    title: "[P1] Missing auth guard".to_string(),
                    body: finding_body,
                    confidence_score: Some(0.93),
                    priority: Some(1),
                    code_location: crate::codex_runner::ReviewCodeLocation {
                        absolute_file_path: "/work/repo/group/repo/src/auth.rs".to_string(),
                        line_range: crate::codex_runner::ReviewLineRange { start: 10, end: 10 },
                    },
                }],
                body: "legacy body".to_string(),
            },
        ))),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review_for_lane(
            "group/repo",
            25,
            "sha25",
            crate::review_lane::ReviewLane::Security,
        )
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::Security,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle: Arc::new(ServiceLifecycle::default()),
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            merge_request,
            "sha25",
            crate::feature_flags::FeatureFlagSnapshot {
                gitlab_inline_review_comments: true,
                security_review: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
            0,
        )
        .await?;

    let inline_discussions = gitlab.created_diff_discussions();
    assert_eq!(inline_discussions.len(), 1);
    let (rendered_body, marker_suffix) = inline_discussions[0]
        .body
        .rsplit_once("\n\n<!-- ")
        .expect("inline finding marker");
    let auth_link =
        "[`src/auth.rs:10`](https://gitlab.example.com/group/repo/-/blob/sha25/src/auth.rs#L10)";
    let http_link =
        "[`src/http.rs:22`](https://gitlab.example.com/group/repo/-/blob/sha25/src/http.rs#L22)";
    let expected_rendered_body = format!(
        "Security finding: [P1] Missing auth guard\n\n{}",
        render_sectioned_body(&[
            ("Summary", format!("Untrusted callers can reach {auth_link}.")),
            (
                "Severity",
                format!("P1 because {auth_link} removes the only authorization gate."),
            ),
            (
                "Reproduction",
                format!("Replay the existing request flow and hit {auth_link}."),
            ),
            (
                "Evidence",
                format!(
                    "{auth_link} returns before the guard and {http_link} still executes the privileged handler."
                ),
            ),
            (
                "Attack-path analysis",
                "An attacker-controlled request crosses the HTTP boundary, bypasses the role check, and reaches the privileged sink.".to_string(),
            ),
            (
                "Likelihood",
                "High because the endpoint is externally reachable.".to_string(),
            ),
            ("Impact", "Cross-tenant data exposure.".to_string()),
            (
                "Assumptions",
                "The route is reachable to ordinary API clients.".to_string(),
            ),
            (
                "Blindspots",
                format!("Did not validate proxy-specific auth at {http_link}."),
            ),
        ])
    );
    assert_eq!(rendered_body, expected_rendered_body);
    assert!(!rendered_body.contains(auth_ref));
    assert!(!rendered_body.contains(http_ref));
    assert!(marker_suffix.starts_with("codex-security-review-finding:sha=sha25 key="));
    assert!(marker_suffix.ends_with(" -->"));
    assert!(gitlab.created_note_bodies().is_empty());
    Ok(())
}

#[tokio::test]
async fn security_review_pass_stays_silent() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "no confirmed security issues found".to_string(),
        })),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_state
        .begin_review_for_lane(
            "group/repo",
            25,
            "sha25",
            crate::review_lane::ReviewLane::Security,
        )
        .await?;
    let review_context = ReviewRunContext {
        lane: crate::review_lane::ReviewLane::Security,
        config,
        gitlab: gitlab.clone(),
        codex: runner.clone(),
        state: state.clone(),
        retry_backoff: Arc::new(RetryBackoff::new(Duration::hours(1))),
        bot_user_id: 1,
        lifecycle: Arc::new(ServiceLifecycle::default()),
        acquired_rate_limit_rule_ids: Vec::new(),
    };

    review_context
        .run(
            "group/repo",
            mr(25, "sha25"),
            "sha25",
            crate::feature_flags::FeatureFlagSnapshot {
                security_review: true,
                ..crate::feature_flags::FeatureFlagSnapshot::default()
            },
            0,
        )
        .await?;

    assert_eq!(*runner.calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(!calls.iter().any(|call| call.contains(":eyes")));
    assert!(!calls.iter().any(|call| call.contains(":thumbsup")));
    assert!(!calls.iter().any(|call| call.starts_with("create_note:")));

    let row = sqlx::query(
        "SELECT status, result FROM review_state WHERE repo = ? AND iid = ? AND lane = ?",
    )
    .bind("group/repo")
    .bind(25i64)
    .bind("security")
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("pass".to_string()));
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_blocks_same_mr_and_clears_pending_after_success() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    let first = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-old"), "sha26-old")
        .await?;
    let second = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-new"), "sha26-new")
        .await?;
    let third = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-newer"), "sha26-newer")
        .await?;

    assert_eq!(first, crate::flow::review::ReviewScheduleOutcome::Scheduled);
    assert_eq!(
        second,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert_eq!(
        third,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );

    let pending = state
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].lane, crate::review_lane::ReviewLane::General);
    assert_eq!(pending[0].repo, "group/repo".to_string());
    assert_eq!(pending[0].iid, 26);
    assert_eq!(pending[0].last_seen_head_sha, "sha26-newer".to_string());
    assert!(pending[0].first_blocked_at <= pending[0].last_blocked_at);
    assert!(pending[0].next_retry_at > pending[0].last_blocked_at);

    state
        .review_rate_limit
        .refund_review_rate_limit_buckets(
            &[format!("{rule_id}:repo:group/repo")],
            Utc::now().timestamp(),
        )
        .await?;

    let fourth = service
        .general_review_flow
        .run_for_mr("group/repo", mr(26, "sha26-final"), "sha26-final")
        .await?;
    assert_eq!(
        fourth,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    assert!(
        state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .is_empty()
    );
    assert_eq!(runner.review_contexts.lock().unwrap().len(), 2);
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_block_adds_configured_mr_award() -> Result<()> {
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let now = Utc::now().timestamp();
    state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 27, now)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(27, "sha27"), "sha27")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "add_award:group/repo:27:hourglass_flowing_sand")
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_block_skips_duplicate_mr_award_when_bot_already_has_it() -> Result<()> {
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 28),
            vec![AwardEmoji {
                id: 280,
                name: "hourglass_flowing_sand".to_string(),
                user: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let now = Utc::now().timestamp();
    state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 28, now)
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state,
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(28, "sha28"), "sha28")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::SkippedRateLimit
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .all(|call| call != "add_award:group/repo:28:hourglass_flowing_sand")
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_clear_removes_configured_mr_award_before_review_resumes() -> Result<()>
{
    let mut config = test_config();
    config.review.rate_limit_emoji = "hourglass_flowing_sand".to_string();
    let gitlab = Arc::new(FakeGitLab {
        bot_user: GitLabUser {
            id: 1,
            username: Some("bot".to_string()),
            name: Some("Bot".to_string()),
        },
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 29),
            vec![AwardEmoji {
                id: 290,
                name: "hourglass_flowing_sand".to_string(),
                user: GitLabUser {
                    id: 1,
                    username: Some("bot".to_string()),
                    name: Some("Bot".to_string()),
                },
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    state
        .review_rate_limit
        .upsert_review_rate_limit_pending(
            ReviewLane::General,
            "group/repo",
            29,
            "sha29-old",
            100,
            0,
        )
        .await?;
    state
        .review_rate_limit
        .refund_review_rate_limit_buckets(
            &[format!("{rule_id}:repo:group/repo")],
            Utc::now().timestamp(),
        )
        .await?;
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner,
        1,
        default_created_after(),
    );

    let outcome = service
        .general_review_flow
        .run_for_mr("group/repo", mr(29, "sha29"), "sha29")
        .await?;

    assert_eq!(
        outcome,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    assert!(
        gitlab
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|call| call == "delete_award:group/repo:29:290")
    );
    assert!(
        state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_applies_general_security_and_shared_rules() -> Result<()> {
    let mut config = test_config();
    config.feature_flags.security_review = true;
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let general_only = state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "general-only",
            "General only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let security_only = state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "security-only",
            "Security only",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: false,
                applies_to_security: true,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let shared = state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "shared",
            "Shared",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: true,
                capacity: 2,
                window_seconds: 3_600,
            },
        ))
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert_eq!(
        service
            .general_review_flow
            .run_for_mr("group/repo", mr(30, "sha30"), "sha30")
            .await?,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    let mut active_rule_ids = state
        .review_rate_limit
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?
        .into_iter()
        .map(|bucket| bucket.rule_id)
        .collect::<Vec<_>>();
    active_rule_ids.sort();
    assert_eq!(active_rule_ids, vec![general_only.clone(), shared.clone()]);

    assert_eq!(
        service
            .security_review_flow
            .run_for_mr("group/repo", mr(31, "sha31"), "sha31")
            .await?,
        crate::flow::review::ReviewScheduleOutcome::Scheduled
    );
    let mut active_rule_ids = state
        .review_rate_limit
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?
        .into_iter()
        .map(|bucket| bucket.rule_id)
        .collect::<Vec<_>>();
    active_rule_ids.sort();
    assert_eq!(active_rule_ids, vec![general_only, security_only, shared]);
    assert_eq!(
        runner
            .review_contexts
            .lock()
            .unwrap()
            .iter()
            .filter(|ctx| ctx.lane == crate::review_lane::ReviewLane::General)
            .count(),
        1
    );
    assert_eq!(
        runner
            .review_contexts
            .lock()
            .unwrap()
            .iter()
            .filter(|ctx| ctx.lane == crate::review_lane::ReviewLane::Security)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_refunds_on_startup_failure() -> Result<()> {
    let config = test_config();
    let gitlab = fake_gitlab(Vec::new());
    let runner = Arc::new(CapturingReviewRunner {
        result: Mutex::new(Some(CodexResult::Pass {
            summary: "ok".to_string(),
        })),
        review_contexts: Mutex::new(Vec::new()),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "startup-failure",
            "Startup failure",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                scope_repo: "group/repo",
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 3_600,
            },
        ))
        .await?;
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(
        service
            .general_review_flow
            .run_for_mr("group/repo", mr(32, "sha32"), "sha32")
            .await
            .is_err()
    );
    assert!(
        state
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .is_empty()
    );
    assert!(
        state
            .review_rate_limit
            .list_active_review_rate_limit_buckets(Utc::now().timestamp())
            .await?
            .is_empty()
    );
    assert!(
        state
            .review_state
            .list_in_progress_reviews()
            .await?
            .is_empty()
    );
    assert!(runner.review_contexts.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn queued_reviews_snapshot_feature_flags_before_runner_start() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/repo".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/shared".to_string()],
        target_groups: Vec::new(),
    }];
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(vec![mr(60, "sha60"), mr(61, "sha61")]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingReviewRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .feature_flags
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    for _ in 0..50 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'review'")
                .fetch_one(state.pool())
                .await?;
        if count == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    state
        .feature_flags
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(false),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;

    let mut snapshots = Vec::new();
    for _ in 0..50 {
        let rows = sqlx::query(
            "SELECT feature_flags_json FROM run_history WHERE kind = 'review' ORDER BY iid",
        )
        .fetch_all(state.pool())
        .await?;
        if rows.len() == 2 {
            snapshots = rows
                .into_iter()
                .map(|row| {
                    let json: String = row.try_get("feature_flags_json")?;
                    let snapshot =
                        serde_json::from_str::<crate::feature_flags::FeatureFlagSnapshot>(&json)?;
                    Ok(snapshot)
                })
                .collect::<Result<Vec<_>>>()?;
            if snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
            {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.gitlab_discovery_mcp)
    );

    release_first.notify_waiters();
    scan_task.await??;
    Ok(())
}

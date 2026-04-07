use super::*;
#[tokio::test]
async fn rate_limits_page_renders_create_form_and_empty_state() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .review_rate_limit
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Merge request backlog limit".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 2,
            window_seconds: 600,
        })
        .await?;

    let status_service = Arc::new(HttpServices::new(test_config(), state, false, None));
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_get(format!("http://{address}/rate-limits")).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Review rate limits"));
    assert!(body.contains("Create rule"));
    assert!(body.contains("Open create rule modal"));
    assert!(body.contains("Existing rules"));
    assert!(body.contains("Merge request backlog limit"));
    assert!(body.contains("group/repo"));
    assert!(body.contains("data-role=\"rate-limit-modal\""));
    assert!(body.contains("2h 15m"));
    assert!(body.contains("\"bucket_mode\":\"shared\""));
    assert!(body.contains("Per repository"));
    assert!(body.contains("one bucket per matched repository"));
    assert!(body.contains("/rate-limits"));
    assert!(body.contains("No active buckets."));
    assert!(body.contains("No pending review items."));
    assert!(body.contains("<a class=\"nav-link active\" href=\"/rate-limits\""));
    Ok(())
}

#[tokio::test]
async fn create_rate_limit_rule_endpoint_requires_csrf_and_persists_rule() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", "wrong"),
            ("label", "Create denied"),
            ("scope", "project"),
            ("targets_json", r#"[{"kind":"repo","path":"group/repo"}]"#),
            ("bucket_mode", "shared"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "2m"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let created = client
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Create allowed"),
            ("scope", "project"),
            (
                "targets_json",
                r#"[{"kind":"repo","path":"group/repo"},{"kind":"group","path":"group/platform"}]"#,
            ),
            ("bucket_mode", "independent"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "2m"),
        ])
        .send()
        .await?;
    assert_eq!(created.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?
            .len(),
        1
    );
    assert_eq!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?[0]
            .label,
        "Create allowed"
    );
    assert_eq!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?[0]
            .targets,
        vec![
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string()
            },
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Group,
                path: "group/platform".to_string()
            }
        ]
    );
    assert_eq!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?[0]
            .bucket_mode,
        ReviewRateLimitBucketMode::Shared
    );
    Ok(())
}

#[tokio::test]
async fn update_rate_limit_rule_endpoint_requires_csrf_and_applies_form_changes() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .review_rate_limit
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Original".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 3,
            window_seconds: 300,
        })
        .await?;

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/{rule_id}/update"))
        .form(&[
            ("csrf_token", "bad"),
            ("label", "Updated"),
            ("scope", "project"),
            ("targets_json", r#"[{"kind":"repo","path":"group/repo"}]"#),
            ("bucket_mode", "shared"),
            ("capacity", "5"),
            ("window_text", "5m"),
        ])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let updated = client
        .post(format!("http://{address}/rate-limits/{rule_id}/update"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Updated"),
            ("scope", "project"),
            (
                "targets_json",
                r#"[{"kind":"group","path":"group/platform"}]"#,
            ),
            ("bucket_mode", "independent"),
            ("capacity", "5"),
            ("window_text", "5m"),
            ("applies_to_review", "true"),
        ])
        .send()
        .await?;
    assert_eq!(updated.status(), StatusCode::SEE_OTHER);

    let rule = state
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rule.len(), 1);
    assert_eq!(rule[0].label, "Updated");
    assert_eq!(rule[0].capacity, 5);
    assert_eq!(rule[0].bucket_mode, ReviewRateLimitBucketMode::Shared);
    assert_eq!(
        rule[0].targets,
        vec![ReviewRateLimitTarget {
            kind: ReviewRateLimitTargetKind::Group,
            path: "group/platform".to_string(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn delete_rate_limit_rule_endpoint_requires_csrf_and_removes_rule() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .review_rate_limit
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Delete me".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 1,
            window_seconds: 60,
        })
        .await?;

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{address}/rate-limits/{rule_id}/delete"))
        .form(&[("csrf_token", "bad")])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?
            .len(),
        1
    );

    let deleted = client
        .post(format!("http://{address}/rate-limits/{rule_id}/delete"))
        .form(&[("csrf_token", csrf_token.as_str())])
        .send()
        .await?;
    assert_eq!(deleted.status(), StatusCode::SEE_OTHER);
    assert!(
        state
            .review_rate_limit
            .list_review_rate_limit_rules()
            .await?
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn regen_rate_limit_bucket_slot_endpoint_refunds_slot() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let rule_id = state
        .review_rate_limit
        .create_review_rate_limit_rule(&ReviewRateLimitRuleUpsert {
            id: None,
            label: "Regenerate".to_string(),
            targets: vec![ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            }],
            bucket_mode: ReviewRateLimitBucketMode::Shared,
            scope_iid: None,
            applies_to_review: true,
            applies_to_security: false,
            scope: ReviewRateLimitScope::Project,
            capacity: 2,
            window_seconds: 300,
        })
        .await?;

    let now = Utc::now().timestamp();
    state
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 11, now)
        .await?;
    state
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 11, now)
        .await?;
    let before = state
        .review_rate_limit
        .list_active_review_rate_limit_buckets(now)
        .await?;
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].available_slots, 0.0);
    let bucket_id = before[0].bucket_id.clone();

    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;
    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{address}/rate-limits/buckets/regen"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("bucket_id", bucket_id.as_str()),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let after = state
        .review_rate_limit
        .list_active_review_rate_limit_buckets(Utc::now().timestamp())
        .await?;
    assert_eq!(after.len(), 1);
    assert!(
        (1.0..=1.01).contains(&after[0].available_slots),
        "expected refunded slot count to be about 1.0, got {}",
        after[0].available_slots
    );
    assert_eq!(after[0].rule_id, rule_id);
    Ok(())
}

#[tokio::test]
async fn create_rate_limit_rule_endpoint_allows_global_rules_without_targets() -> Result<()> {
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let status_service = Arc::new(HttpServices::new(
        test_config(),
        Arc::clone(&state),
        false,
        None,
    ));
    let csrf_token = status_service.admin.admin_csrf_token().to_string();
    let address = spawn_test_server(app_router(status_service)).await?;

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{address}/rate-limits/create"))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("label", "Global cap"),
            ("scope", "project"),
            ("targets_json", "[]"),
            ("bucket_mode", "shared"),
            ("applies_to_review", "true"),
            ("capacity", "1"),
            ("window_text", "30m"),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let rules = state
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rules.len(), 1);
    assert!(rules[0].targets.is_empty());
    assert_eq!(rules[0].scope_subject, "Global".to_string());
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_accepts_friendly_duration_and_targets() -> Result<()> {
    let upsert = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Friendly".to_string(),
        scope: "project".to_string(),
        targets_json:
            r#"[{"kind":"repo","path":"group/repo"},{"kind":"group","path":"group/platform"}]"#
                .to_string(),
        bucket_mode: "independent".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 2,
        window_text: "2h 15m".to_string(),
    })?;

    assert_eq!(upsert.window_seconds, 8_100);
    assert_eq!(upsert.bucket_mode, ReviewRateLimitBucketMode::Independent);
    assert_eq!(
        upsert.targets,
        vec![
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Repo,
                path: "group/repo".to_string(),
            },
            ReviewRateLimitTarget {
                kind: ReviewRateLimitTargetKind::Group,
                path: "group/platform".to_string(),
            }
        ]
    );
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_accepts_empty_targets_for_global_rules() -> Result<()> {
    let upsert = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Global".to_string(),
        scope: "project".to_string(),
        targets_json: "[]".to_string(),
        bucket_mode: "shared".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 1,
        window_text: "45m".to_string(),
    })?;

    assert!(upsert.targets.is_empty());
    assert_eq!(upsert.window_seconds, 2_700);
    Ok(())
}

#[test]
fn parse_rate_limit_rule_upsert_rejects_invalid_duration_text() {
    let err = parse_rate_limit_rule_upsert(RateLimitRuleForm {
        csrf_token: "csrf".to_string(),
        label: "Bad".to_string(),
        scope: "project".to_string(),
        targets_json: r#"[{"kind":"repo","path":"group/repo"}]"#.to_string(),
        bucket_mode: "shared".to_string(),
        applies_to_review: Some(true),
        applies_to_security: Some(false),
        capacity: 1,
        window_text: "later".to_string(),
    })
    .expect_err("expected invalid duration");

    assert!(err.to_string().contains("window_text"));
}

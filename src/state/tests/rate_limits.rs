use super::*;
#[tokio::test]
async fn runtime_rate_limit_rule_crud_roundtrips() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-crud",
            "Initial label",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 100,
            },
        ))
        .await?;

    let rules = store
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].id, rule_id);
    assert_eq!(rules[0].label, "Initial label".to_string());
    assert_eq!(rules[0].targets, vec![repo_target("group/repo")]);
    assert_eq!(rules[0].bucket_mode, ReviewRateLimitBucketMode::Shared);
    assert_eq!(rules[0].scope_iid, None);
    assert_eq!(rules[0].scope_subject, "group/repo".to_string());
    assert_eq!(rules[0].capacity, 2);

    store
        .review_rate_limit
        .update_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-crud",
            "Updated label",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo"), group_target("group/platform")],
                bucket_mode: ReviewRateLimitBucketMode::Independent,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: true,
                capacity: 3,
                window_seconds: 200,
            },
        ))
        .await?;

    let rules = store
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].label, "Updated label".to_string());
    assert_eq!(
        rules[0].targets,
        vec![repo_target("group/repo"), group_target("group/platform")]
    );
    assert_eq!(rules[0].bucket_mode, ReviewRateLimitBucketMode::Shared);
    assert!(rules[0].applies_to_security);
    assert_eq!(rules[0].capacity, 3);
    assert_eq!(rules[0].window_seconds, 200);

    store
        .review_rate_limit
        .delete_review_rate_limit_rule("rule-crud")
        .await?;
    let rules = store
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert!(rules.is_empty());
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_refill_math_exposes_fractional_slots() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-refill",
            "Refill math",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 100,
            },
        ))
        .await?;

    let started_at = 1_000;
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 7, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/repo")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    let buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(started_at + 25)
        .await?;
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].rule_id, rule_id);
    assert_eq!(buckets[0].scope_subject, "group/repo".to_string());
    assert_approx_eq(buckets[0].available_slots, 1.5);
    assert_eq!(buckets[0].next_slot_at, Some(started_at + 50));
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_stacked_rules_block_only_when_every_bucket_is_empty() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let first_rule = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-a",
            "First",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 1_000,
            },
        ))
        .await?;
    let second_rule = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-b",
            "Second",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 1_000,
            },
        ))
        .await?;

    let started_at = 2_000;
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 1, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            let mut bucket_ids = bucket_ids;
            bucket_ids.sort();
            assert_eq!(
                bucket_ids,
                vec![
                    format!("{first_rule}:repo:group/repo"),
                    format!("{second_rule}:repo:group/repo"),
                ]
            );
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 1, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Blocked { next_retry_at } => {
            assert_eq!(next_retry_at, started_at + 1_000);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_project_and_mr_scopes_do_not_cross_apply() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let project_rule = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-project",
            "Project",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 3,
                window_seconds: 1_000,
            },
        ))
        .await?;
    let mr_rule = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-mr",
            "MR",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::MergeRequest,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 1_000,
            },
        ))
        .await?;

    let started_at = 3_000;
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 10, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            let mut bucket_ids = bucket_ids;
            bucket_ids.sort();
            assert_eq!(
                bucket_ids,
                vec![
                    format!("{mr_rule}:mr:group/repo:10"),
                    format!("{project_rule}:repo:group/repo"),
                ]
            );
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 11, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            let mut bucket_ids = bucket_ids;
            bucket_ids.sort();
            assert_eq!(
                bucket_ids,
                vec![
                    format!("{mr_rule}:mr:group/repo:11"),
                    format!("{project_rule}:repo:group/repo"),
                ]
            );
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_shared_review_and_security_rules_use_one_bucket() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-shared",
            "Shared",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: true,
                capacity: 2,
                window_seconds: 1_000,
            },
        ))
        .await?;

    let started_at = 4_000;
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 12, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/repo")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::Security, "group/repo", 12, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/repo")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 12, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Blocked { next_retry_at } => {
            assert_eq!(next_retry_at, started_at + 500);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_regen_one_slot_is_reflected_in_active_buckets() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-regen",
            "Regen",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 100,
            },
        ))
        .await?;

    let started_at = 5_000;
    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 13, started_at)
        .await?;
    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 13, started_at)
        .await?;
    store
        .review_rate_limit
        .refund_review_rate_limit_buckets(&[format!("{rule_id}:repo:group/repo")], started_at)
        .await?;

    let buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(started_at)
        .await?;
    assert_eq!(buckets.len(), 1);
    assert_approx_eq(buckets[0].available_slots, 1.0);
    assert_eq!(buckets[0].next_slot_at, Some(started_at + 50));
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_auto_deletes_full_bucket_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let _rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-auto-delete",
            "Auto delete",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 100,
            },
        ))
        .await?;

    let started_at = 6_000;
    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 14, started_at)
        .await?;

    let buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(started_at + 100)
        .await?;
    assert!(buckets.is_empty());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtime_review_rate_limit_bucket")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(count, 0);
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_pending_deduplicates_rows() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_rate_limit
        .upsert_review_rate_limit_pending(ReviewLane::General, "group/repo", 15, "sha-1", 100, 500)
        .await?;
    store
        .review_rate_limit
        .upsert_review_rate_limit_pending(ReviewLane::General, "group/repo", 15, "sha-2", 150, 700)
        .await?;

    let rows = store
        .review_rate_limit
        .list_review_rate_limit_pending()
        .await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].lane, ReviewLane::General);
    assert_eq!(rows[0].repo, "group/repo".to_string());
    assert_eq!(rows[0].iid, 15);
    assert_eq!(rows[0].first_blocked_at, 100);
    assert_eq!(rows[0].last_blocked_at, 150);
    assert_eq!(rows[0].last_seen_head_sha, "sha-2".to_string());
    assert_eq!(rows[0].next_retry_at, 700);
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_pending_clear_removes_row() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_rate_limit
        .upsert_review_rate_limit_pending(ReviewLane::Security, "group/repo", 18, "sha-1", 100, 500)
        .await?;

    assert!(
        store
            .review_rate_limit
            .clear_review_rate_limit_pending(ReviewLane::Security, "group/repo", 18)
            .await?
    );
    assert!(
        store
            .review_rate_limit
            .list_review_rate_limit_pending()
            .await?
            .is_empty()
    );
    assert_eq!(
        store
            .review_rate_limit
            .earliest_review_rate_limit_pending_retry_at()
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_earliest_pending_retry_tracks_minimum() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    store
        .review_rate_limit
        .upsert_review_rate_limit_pending(ReviewLane::General, "group/repo", 16, "sha-1", 100, 500)
        .await?;
    store
        .review_rate_limit
        .upsert_review_rate_limit_pending(ReviewLane::Security, "group/repo", 17, "sha-2", 120, 300)
        .await?;

    let earliest = store
        .review_rate_limit
        .earliest_review_rate_limit_pending_retry_at()
        .await?;
    assert_eq!(earliest, Some(300));
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_consume_and_refund_roundtrip() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-roundtrip",
            "Roundtrip",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 2,
                window_seconds: 1_000,
            },
        ))
        .await?;

    let started_at = 7_000;
    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 18, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/repo")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    store
        .review_rate_limit
        .refund_review_rate_limit_buckets(&[format!("{rule_id}:repo:group/repo")], started_at)
        .await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM runtime_review_rate_limit_bucket")
        .fetch_one(store.pool())
        .await?;
    assert_eq!(count, 0);

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 18, started_at)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/repo")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_group_targets_match_nested_repositories() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-group",
            "Group cap",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![group_target("group/platform")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 300,
            },
        ))
        .await?;

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/platform/service-a", 21, 8_000)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(
                bucket_ids,
                vec![format!("{rule_id}:repo:group/platform/service-a")]
            );
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_global_rules_apply_without_targets() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-global",
            "Global cap",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: Vec::new(),
                bucket_mode: ReviewRateLimitBucketMode::Independent,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    let rules = store
        .review_rate_limit
        .list_review_rate_limit_rules()
        .await?;
    assert_eq!(rules.len(), 1);
    assert!(rules[0].targets.is_empty());
    assert_eq!(rules[0].scope_subject, "Global".to_string());
    assert_eq!(rules[0].bucket_mode, ReviewRateLimitBucketMode::Shared);

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-a", 41, 9_500)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/service-a")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-b", 42, 9_500)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/service-b")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    let buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(9_500)
        .await?;
    assert_eq!(buckets.len(), 2);
    let mut scopes = buckets
        .iter()
        .map(|bucket| bucket.scope_subject.clone())
        .collect::<Vec<_>>();
    scopes.sort();
    assert_eq!(
        scopes,
        vec!["group/service-a".to_string(), "group/service-b".to_string()]
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_independent_bucket_mode_tracks_each_target_separately() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-independent",
            "Independent",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![
                    repo_target("group/service-a"),
                    repo_target("group/service-b"),
                ],
                bucket_mode: ReviewRateLimitBucketMode::Independent,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-a", 31, 9_000)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/service-a")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }

    match store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-b", 32, 9_000)
        .await?
    {
        ReviewRateLimitAcquireOutcome::Acquired { bucket_ids } => {
            assert_eq!(bucket_ids, vec![format!("{rule_id}:repo:group/service-b")]);
        }
        other => panic!("unexpected consume outcome: {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_project_scope_group_targets_isolate_each_repository() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-project-group-per-repo",
            "Per repo group cap",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![group_target("group/platform")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    let started_at = 12_000;
    let first = store
        .review_rate_limit
        .try_consume_review_rate_limits(
            ReviewLane::General,
            "group/platform/service-a",
            71,
            started_at,
        )
        .await?;
    let second = store
        .review_rate_limit
        .try_consume_review_rate_limits(
            ReviewLane::General,
            "group/platform/service-b",
            72,
            started_at,
        )
        .await?;

    assert_eq!(
        first,
        ReviewRateLimitAcquireOutcome::Acquired {
            bucket_ids: vec![format!("{rule_id}:repo:group/platform/service-a")],
        }
    );
    assert_eq!(
        second,
        ReviewRateLimitAcquireOutcome::Acquired {
            bucket_ids: vec![format!("{rule_id}:repo:group/platform/service-b")],
        }
    );
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_bucket_refund_only_restores_requested_bucket() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-bucket-refund",
            "Bucket refund",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![
                    repo_target("group/service-a"),
                    repo_target("group/service-b"),
                ],
                bucket_mode: ReviewRateLimitBucketMode::Independent,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    let started_at = 10_000;
    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-a", 51, started_at)
        .await?;
    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/service-b", 52, started_at)
        .await?;

    store
        .review_rate_limit
        .refund_review_rate_limit_bucket(&format!("{rule_id}:repo:group/service-a"), started_at)
        .await?;

    let mut buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(started_at)
        .await?;
    buckets.sort_by(|left, right| left.target_path.cmp(&right.target_path));
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].target_path, "group/service-b".to_string());
    assert_eq!(buckets[0].available_slots, 0.0);
    Ok(())
}

#[tokio::test]
async fn runtime_rate_limit_label_update_preserves_existing_bucket_state() -> Result<()> {
    let store = ReviewStateStore::new(":memory:").await?;
    let rule_id = store
        .review_rate_limit
        .create_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-preserve-update",
            "Original label",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    store
        .review_rate_limit
        .try_consume_review_rate_limits(ReviewLane::General, "group/repo", 61, 11_000)
        .await?;
    store
        .review_rate_limit
        .update_review_rate_limit_rule(&review_rate_limit_rule(
            "rule-preserve-update",
            "Renamed",
            ReviewRateLimitRuleSpec {
                scope: ReviewRateLimitScope::Project,
                targets: vec![repo_target("group/repo")],
                bucket_mode: ReviewRateLimitBucketMode::Shared,
                scope_iid: None,
                applies_to_review: true,
                applies_to_security: false,
                capacity: 1,
                window_seconds: 600,
            },
        ))
        .await?;

    let buckets = store
        .review_rate_limit
        .list_active_review_rate_limit_buckets(11_000)
        .await?;
    assert_eq!(buckets.len(), 1);
    assert_eq!(buckets[0].rule_id, rule_id);
    assert_eq!(buckets[0].available_slots, 0.0);
    Ok(())
}

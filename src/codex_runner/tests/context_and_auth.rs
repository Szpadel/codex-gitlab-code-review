use super::*;
#[test]
fn security_context_cache_repo_key_uses_canonical_repo_identity() {
    let runner = test_runner_with_codex(test_codex_config());
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.project_path = "fork/source".to_string();
    assert_eq!(runner.security_context_cache_repo_key(&ctx), "group/repo");
}

#[test]
fn security_review_disables_gitlab_discovery_mcp() {
    let mut codex = test_codex_config();
    codex.gitlab_discovery_mcp = crate::config::GitLabDiscoveryMcpConfig {
        enabled: true,
        bind_addr: "127.0.0.1:8091".to_string(),
        advertise_url: "http://mcp.internal:8091/mcp".to_string(),
        allow: vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["fork/source".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }],
        ..crate::config::GitLabDiscoveryMcpConfig::default()
    };
    let service = Arc::new(
        crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            },
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets::default(),
            },
            codex.gitlab_discovery_mcp.clone(),
        )
        .expect("gitlab discovery service"),
    );
    let mut runner = test_runner_with_codex(codex);
    runner.gitlab_discovery_mcp = Some(service as Arc<dyn GitLabDiscoveryHandle>);
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review::ReviewLane::Security;
    ctx.project_path = "fork/source".to_string();
    ctx.feature_flags.gitlab_discovery_mcp = true;

    assert!(runner.prepare_review_gitlab_discovery_mcp(&ctx).is_none());
}

#[tokio::test]
async fn prepare_runner_session_components_respects_discovery_toggle() {
    let mut codex = test_codex_config();
    codex.gitlab_discovery_mcp = crate::config::GitLabDiscoveryMcpConfig {
        enabled: true,
        bind_addr: "127.0.0.1:8091".to_string(),
        advertise_url: "http://mcp.internal:8091/mcp".to_string(),
        allow: vec![crate::config::GitLabDiscoveryAllowRule {
            source_repos: vec!["fork/source".to_string()],
            source_group_prefixes: Vec::new(),
            target_repos: vec!["group/shared".to_string()],
            target_groups: Vec::new(),
        }],
        ..crate::config::GitLabDiscoveryMcpConfig::default()
    };
    let service = Arc::new(
        crate::gitlab_discovery_mcp::GitLabDiscoveryMcpService::new(
            DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            },
            &crate::config::GitLabConfig {
                base_url: "https://gitlab.example.com".to_string(),
                token: "token".to_string(),
                bot_user_id: Some(1),
                created_after: None,
                targets: GitLabTargets::default(),
            },
            codex.gitlab_discovery_mcp.clone(),
        )
        .expect("gitlab discovery service"),
    );
    let mut runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    runner.gitlab_discovery_mcp = Some(service as Arc<dyn GitLabDiscoveryHandle>);
    let mut ctx = review_context_with_target_branch(Some("main"));
    ctx.lane = crate::review::ReviewLane::Security;
    ctx.project_path = "fork/source".to_string();
    ctx.feature_flags.gitlab_discovery_mcp = true;

    let prepared = runner
        .prepare_runner_session_components(
            None,
            &ctx.feature_flags,
            &ctx.project_path,
            &runner.codex.mcp_server_overrides.review,
            false,
        )
        .await;

    assert!(prepared.gitlab_discovery_mcp.is_none());
}

#[test]
fn review_target_request_uses_native_base_branch_without_extra_instructions() {
    let ctx = review_context_with_target_branch(Some("main"));
    let request = DockerCodexRunner::review_target_request(&ctx, Some("mergebase"), None);
    assert_eq!(
        request,
        ReviewTargetRequest::NativeBaseBranch {
            branch: "main".to_string()
        }
    );
}

#[test]
fn review_target_request_uses_synced_custom_prompt_with_extra_instructions() {
    let ctx = review_context_with_target_branch(Some("main"));
    let request = DockerCodexRunner::review_target_request(
        &ctx,
        Some("mergebase"),
        Some("Check performance-sensitive paths."),
    );
    match request {
        ReviewTargetRequest::NativeBaseBranch { .. } => {
            panic!("expected custom review target request")
        }
        ReviewTargetRequest::Custom { instructions } => {
            assert!(instructions.contains("merge base commit for this comparison is mergebase"));
            assert!(instructions.contains("Additional review instructions:"));
            assert!(instructions.contains("Check performance-sensitive paths."));
        }
    }
}

#[test]
fn review_target_request_falls_back_when_target_branch_missing() {
    let ctx = review_context_with_target_branch(None);
    let request =
        DockerCodexRunner::review_target_request(&ctx, None, Some("Check browser regressions."));
    match request {
        ReviewTargetRequest::NativeBaseBranch { .. } => {
            panic!("expected custom review target request")
        }
        ReviewTargetRequest::Custom { instructions } => {
            assert!(instructions.contains("introduced by commit abc123 (\"Title\")"));
            assert!(instructions.contains("did not provide target branch metadata"));
            assert!(instructions.contains("Additional review instructions:"));
            assert!(instructions.contains("Check browser regressions."));
        }
    }
}

#[test]
fn parse_usage_limit_reset_at_supports_rfc3339() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "rate limit reached; resets at 2026-03-02T12:30:00Z";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 12, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_compact_relative_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded, try again in 1h 20m";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 20, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_spaced_relative_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "quota reached; try again in 1 hour 30 minutes";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_conjunction_in_duration() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded; try again in 1 hour and 30 minutes";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 11, 30, 0)
            .single()
            .expect("valid")
    );
}

#[test]
fn parse_usage_limit_reset_at_supports_fractional_seconds() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let text = "usage limit exceeded; try again in 2.3s";
    let reset = parse_usage_limit_reset_at(text, now).expect("parsed reset");
    assert_eq!(
        reset,
        Utc.with_ymd_and_hms(2026, 3, 2, 10, 0, 3)
            .single()
            .expect("valid")
    );
}

#[test]
fn classify_auth_failure_usage_limit_falls_back_to_default_cooldown_when_unparseable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(
        kind,
        AuthFailureKind::UsageLimited {
            reset_at: Utc
                .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
                .single()
                .expect("valid"),
        }
    );
}

#[test]
fn classify_auth_failure_handles_huge_cooldown_without_panicking() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded");
    let kind = classify_auth_failure(&err, now, u64::MAX);
    match kind {
        AuthFailureKind::UsageLimited { reset_at } => {
            assert!(reset_at > now);
        }
        _ => panic!("expected usage-limited classification"),
    }
}

#[test]
fn classify_auth_failure_detects_rate_limit_reached_phrase() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: Rate limit reached, try again in 45m");
    let kind = classify_auth_failure(&err, now, 3600);
    assert!(matches!(kind, AuthFailureKind::UsageLimited { .. }));
}

#[test]
fn classify_auth_failure_handles_huge_relative_retry_hint_without_panicking() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex turn failed: usage limit exceeded, try again in 9223372036854775807s");
    let kind = classify_auth_failure(&err, now, 3600);
    match kind {
        AuthFailureKind::UsageLimited { reset_at } => {
            assert!(reset_at > now);
        }
        _ => panic!("expected usage-limited classification"),
    }
}

#[test]
fn classify_auth_failure_detects_auth_unavailable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex app-server error: not authenticated, run codex auth login");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::AuthUnavailable);
}

#[test]
fn classify_auth_failure_preserves_non_auth_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex app-server closed stdout");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[tokio::test]
async fn unclassified_review_failure_surfaces_error_chain_in_top_level_message() {
    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        false,
        Arc::new(FakeRunnerHarness::default()),
        None,
    )
    .await;

    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_account| async {
            Err::<(), anyhow::Error>(
                anyhow!("codex app-server closed stdout")
                    .context("recent runner errors: codex-runner-error: git clone failed"),
            )
        })
        .await
        .expect_err("unclassified review failure should stop fallback");

    let message = err.to_string();
    assert!(message.contains("codex review failed for account 'primary':"));
    assert!(message.contains("recent runner errors: codex-runner-error: git clone failed"));
    assert!(message.contains("codex app-server closed stdout"));
    assert!(!message.contains("without fallback classification"));
}

#[tokio::test]
async fn unclassified_mention_failure_surfaces_error_chain_in_top_level_message() {
    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        true,
        Arc::new(FakeRunnerHarness::default()),
        None,
    )
    .await;

    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::MentionCommand, |_account| async {
            Err::<(), anyhow::Error>(
                anyhow!("git status failed").context("mention command setup failed"),
            )
        })
        .await
        .expect_err("unclassified mention failure should stop fallback");

    let message = err.to_string();
    assert!(message.contains("mention command failed for account 'primary':"));
    assert!(message.contains("mention command setup failed"));
    assert!(message.contains("git status failed"));
    assert!(!message.contains("without fallback classification"));
}

#[test]
fn classify_auth_failure_ignores_non_codex_rate_limit_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("git clone failed: received HTTP 429 from gitlab");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_generic_app_server_429_without_codex_limit_context() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err =
        anyhow!("codex app-server closed stdout: recent runner errors: git clone failed with 429");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_openai_package_install_429() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("codex-runner-error: npm install -g @openai/codex failed with 429");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_ignores_disk_quota_exceeded_errors() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let err = anyhow!("write failed: disk quota exceeded");
    let kind = classify_auth_failure(&err, now, 3600);
    assert_eq!(kind, AuthFailureKind::Other);
}

#[test]
fn classify_auth_failure_for_account_marks_mount_path_errors_as_unavailable() {
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let account = AuthAccount {
        name: "backup".to_string(),
        auth_host_path: "/missing/codex-auth".to_string(),
        state_key: auth_account_state_key("backup", "/missing/codex-auth"),
        is_primary: false,
    };
    let err = anyhow!(
        "create docker container failed: invalid mount config for type \"bind\": bind source path does not exist: /missing/codex-auth"
    );
    let base = classify_auth_failure(&err, now, 3600);
    let kind = classify_auth_failure_for_account(base, &err, &account);
    assert_eq!(kind, AuthFailureKind::AuthUnavailable);
}

#[tokio::test]
async fn all_usage_limited_accounts_return_downcastable_quota_error() {
    let mut codex = test_codex_config();
    codex.usage_limit_recheck_seconds = 120;
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    let reset_at = Utc
        .with_ymd_and_hms(2099, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");

    let before = Utc::now();
    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_account| async move {
            Err::<(), anyhow::Error>(anyhow!(
                "codex turn failed: usage limit exceeded; resets at {}",
                reset_at.to_rfc3339()
            ))
        })
        .await
        .expect_err("all usage-limited accounts should defer");
    let after = Utc::now();

    let quota = err
        .downcast_ref::<CodexQuotaExhausted>()
        .expect("quota error should be downcastable");
    assert_eq!(quota.reset_at, reset_at);
    assert!(quota.retry_at >= before + ChronoDuration::seconds(120));
    assert!(quota.retry_at <= after + ChronoDuration::seconds(120));
}

#[tokio::test]
async fn mixed_usage_limit_and_auth_unavailable_keeps_combined_auth_error() {
    let mut codex = test_codex_config();
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;

    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |account| async move {
            if account.name == PRIMARY_AUTH_ACCOUNT_NAME {
                Err::<(), anyhow::Error>(anyhow!(
                    "codex turn failed: usage limit exceeded; resets at 2099-03-02T10:00:00Z"
                ))
            } else {
                Err::<(), anyhow::Error>(anyhow!("codex app-server error: not authenticated"))
            }
        })
        .await
        .expect_err("mixed account failures should still fail");

    assert!(err.downcast_ref::<CodexQuotaExhausted>().is_none());
    let message = err.to_string();
    assert!(message.contains("all codex auth accounts failed with usage-limit/auth errors"));
    assert!(message.contains("account 'primary' usage-limited until"));
    assert!(message.contains("account 'backup' unavailable"));
}

#[tokio::test]
async fn available_accounts_quota_exhaustion_records_probe_marker() {
    let mut codex = test_codex_config();
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;

    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_account| async move {
            Err::<(), anyhow::Error>(anyhow!(
                "codex turn failed: usage limit exceeded; resets at 2099-03-02T10:00:00Z"
            ))
        })
        .await
        .expect_err("all usage-limited accounts should defer");

    assert!(err.downcast_ref::<CodexQuotaExhausted>().is_some());
    assert!(
        runner
            .state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn all_preblocked_accounts_enter_probe_mode_and_clear_successful_marker() {
    let mut codex = test_codex_config();
    codex.usage_limit_recheck_seconds = 900;
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    let now = Utc::now();
    let primary = runner
        .auth_account_by_name(PRIMARY_AUTH_ACCOUNT_NAME)
        .expect("primary account")
        .clone();
    let backup = runner
        .auth_account_by_name("backup")
        .expect("backup account")
        .clone();
    let primary_reset = now + ChronoDuration::hours(2);
    let backup_reset = now + ChronoDuration::hours(1);
    runner
        .mark_limit_reset_at(&primary, primary_reset)
        .await
        .unwrap();
    runner
        .mark_limit_reset_at(&backup, backup_reset)
        .await
        .unwrap();

    let attempted = Arc::new(Mutex::new(Vec::new()));
    let attempted_for_run = Arc::clone(&attempted);
    let account_name = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, move |account| {
            let attempted = Arc::clone(&attempted_for_run);
            async move {
                attempted
                    .lock()
                    .expect("attempts")
                    .push(account.name.clone());
                Ok::<_, anyhow::Error>(account.name)
            }
        })
        .await
        .expect("probe should run a blocked account");

    assert_eq!(account_name, "backup");
    assert_eq!(
        *attempted.lock().expect("attempts"),
        vec!["backup".to_string()]
    );
    assert_eq!(
        runner
            .state
            .service_state
            .get_auth_limit_reset_at(&primary.state_key)
            .await
            .unwrap(),
        Some(primary_reset.to_rfc3339())
    );
    assert_eq!(
        runner
            .state
            .service_state
            .get_auth_limit_reset_at(&backup.state_key)
            .await
            .unwrap(),
        None
    );
    assert!(
        runner
            .state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn preblocked_probe_auth_unavailable_clears_probe_marker() {
    let mut codex = test_codex_config();
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    let now = Utc::now();
    for account in runner.auth_accounts.clone() {
        runner
            .mark_limit_reset_at(&account, now + ChronoDuration::hours(1))
            .await
            .unwrap();
    }

    let err = runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_account| async move {
            Err::<(), anyhow::Error>(anyhow!("codex app-server error: not authenticated"))
        })
        .await
        .expect_err("auth-unavailable probe should keep combined auth error");

    assert!(err.downcast_ref::<CodexQuotaExhausted>().is_none());
    assert_eq!(
        runner
            .state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn quota_block_at_requires_all_accounts_blocked_and_recent_probe() {
    let mut codex = test_codex_config();
    codex.usage_limit_recheck_seconds = 300;
    codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup".to_string(),
        auth_host_path: "/root/.codex-backup".to_string(),
    }];
    let runner =
        test_runner_with_fake_runtime(codex, false, Arc::new(FakeRunnerHarness::default()), None)
            .await;
    let now = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    assert!(runner.quota_block_at(now).await.unwrap().is_none());

    let primary = runner
        .auth_account_by_name(PRIMARY_AUTH_ACCOUNT_NAME)
        .expect("primary account")
        .clone();
    let backup = runner
        .auth_account_by_name("backup")
        .expect("backup account")
        .clone();
    let primary_reset = now + ChronoDuration::minutes(20);
    let backup_reset = now + ChronoDuration::minutes(30);
    runner
        .mark_limit_reset_at(&primary, primary_reset)
        .await
        .unwrap();
    runner
        .mark_limit_reset_at(&backup, backup_reset)
        .await
        .unwrap();
    assert!(runner.quota_block_at(now).await.unwrap().is_none());

    runner
        .state
        .service_state
        .set_service_state_value(
            QUOTA_LAST_PROBE_AT_KEY,
            &(now - ChronoDuration::seconds(60)).to_rfc3339(),
        )
        .await
        .unwrap();
    let block = runner
        .quota_block_at(now)
        .await
        .unwrap()
        .expect("recent probe should block");
    assert_eq!(block.reset_at, primary_reset);
    assert_eq!(block.retry_at, now + ChronoDuration::seconds(240));

    runner
        .state
        .service_state
        .set_service_state_value(
            QUOTA_LAST_PROBE_AT_KEY,
            &(now - ChronoDuration::seconds(300)).to_rfc3339(),
        )
        .await
        .unwrap();
    assert!(runner.quota_block_at(now).await.unwrap().is_none());
}

#[test]
fn should_clear_limit_reset_only_when_marker_is_not_newer_than_attempt() {
    let attempt_started_at = Utc
        .with_ymd_and_hms(2026, 3, 2, 10, 0, 0)
        .single()
        .expect("valid");
    let older_reset = Utc
        .with_ymd_and_hms(2026, 3, 2, 9, 0, 0)
        .single()
        .expect("valid");
    let newer_reset = Utc
        .with_ymd_and_hms(2026, 3, 2, 11, 0, 0)
        .single()
        .expect("valid");

    assert!(should_clear_limit_reset(older_reset, attempt_started_at));
    assert!(should_clear_limit_reset(
        attempt_started_at,
        attempt_started_at
    ));
    assert!(!should_clear_limit_reset(newer_reset, attempt_started_at));
}

#[test]
fn build_auth_accounts_keeps_primary_first_then_fallback_order() {
    let codex = CodexConfig {
        image: "ghcr.io/openai/codex-universal:latest".to_string(),
        timeout_seconds: 300,
        auth_host_path: "/root/.codex-primary".to_string(),
        auth_mount_path: "/root/.codex".to_string(),
        session_history_path: None,
        exec_sandbox: "danger-full-access".to_string(),
        fallback_auth_accounts: vec![
            FallbackAuthAccountConfig {
                name: "backup-high".to_string(),
                auth_host_path: "/root/.codex-backup-high".to_string(),
            },
            FallbackAuthAccountConfig {
                name: "backup-low".to_string(),
                auth_host_path: "/root/.codex-backup-low".to_string(),
            },
        ],
        usage_limit_fallback_cooldown_seconds: 3600,
        usage_limit_recheck_seconds: 900,
        deps: DepsConfig { enabled: false },
        browser_mcp: BrowserMcpConfig::default(),
        work_tmpfs: crate::config::WorkTmpfsConfig::default(),
        gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
        mcp_server_overrides: McpServerOverridesConfig::default(),
        session_overrides: SessionOverridesConfig::default(),
        reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
    };

    let accounts = DockerCodexRunner::build_auth_accounts(&codex);
    assert_eq!(accounts.len(), 3);
    assert_eq!(accounts[0].name, PRIMARY_AUTH_ACCOUNT_NAME);
    assert_eq!(accounts[0].auth_host_path, "/root/.codex-primary");
    assert_eq!(
        accounts[0].state_key,
        auth_account_state_key(PRIMARY_AUTH_ACCOUNT_NAME, "/root/.codex-primary")
    );
    assert!(accounts[0].is_primary);
    assert_eq!(accounts[1].name, "backup-high");
    assert_eq!(accounts[2].name, "backup-low");
    assert_eq!(
        accounts[1].state_key,
        auth_account_state_key("backup-high", "/root/.codex-backup-high")
    );
    assert_eq!(
        accounts[2].state_key,
        auth_account_state_key("backup-low", "/root/.codex-backup-low")
    );
    assert!(!accounts[1].is_primary);
    assert!(!accounts[2].is_primary);
}

#[test]
fn runner_env_vars_do_not_include_proxy_settings() {
    let runtime = tokio::runtime::Runtime::new().expect("runtime");
    let runner = DockerCodexRunner {
        runtime: RunnerRuntime::Docker {
            docker: connect_docker(&DockerConfig {
                host: "tcp://127.0.0.1:2375".to_string(),
            })
            .expect("docker client"),
            image_pull_manager: ImagePullManager::new(),
        },
        security_context_builds: Arc::new(Mutex::new(HashMap::new())),
        codex: CodexConfig {
            image: "ghcr.io/openai/codex-universal:latest".to_string(),
            timeout_seconds: 300,
            auth_host_path: "/root/.codex".to_string(),
            auth_mount_path: "/root/.codex".to_string(),
            session_history_path: None,
            exec_sandbox: "danger-full-access".to_string(),
            fallback_auth_accounts: Vec::new(),
            usage_limit_fallback_cooldown_seconds: 3600,
            usage_limit_recheck_seconds: 900,
            deps: DepsConfig { enabled: false },
            browser_mcp: BrowserMcpConfig::default(),
            work_tmpfs: crate::config::WorkTmpfsConfig::default(),
            gitlab_discovery_mcp: crate::config::GitLabDiscoveryMcpConfig::default(),
            mcp_server_overrides: McpServerOverridesConfig::default(),
            session_overrides: SessionOverridesConfig::default(),
            reasoning_summary: crate::config::ReasoningSummaryOverridesConfig::default(),
        },
        gitlab_discovery_mcp: None,
        mention_commands_active: false,
        review_additional_developer_instructions: None,
        git_base: Url::parse("https://gitlab.example.com").expect("url"),
        gitlab_token: "token".to_string(),
        log_all_json: false,
        owner_id: "owner-id".to_string(),
        state: Arc::new(
            runtime
                .block_on(ReviewStateStore::new(":memory:"))
                .expect("state"),
        ),
        auth_accounts: Vec::new(),
    };

    let env = runner.env_vars(&[]);

    assert_eq!(env, vec!["HOME=/root".to_string(),]);
}

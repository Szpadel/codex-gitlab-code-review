use super::*;

#[tokio::test]
async fn successful_quota_probe_keeps_concurrent_newer_marker() -> Result<()> {
    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        false,
        Arc::new(FakeRunnerHarness::default()),
        None,
    )
    .await;
    let account = &runner.auth_accounts[0];
    let observed =
        (Utc::now() + ChronoDuration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
    let newer = (Utc::now() + ChronoDuration::hours(2)).to_rfc3339_opts(SecondsFormat::Secs, true);
    runner
        .state
        .service_state
        .set_auth_limit_reset_at(&account.state_key, &observed)
        .await?;

    runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_| async {
            runner
                .state
                .service_state
                .set_auth_limit_reset_at(&account.state_key, &newer)
                .await?;
            Ok(())
        })
        .await?;
    assert_eq!(
        runner
            .state
            .service_state
            .get_auth_limit_reset_at(&account.state_key)
            .await?,
        Some(newer)
    );
    Ok(())
}

#[tokio::test]
async fn successful_quota_probe_clears_unchanged_marker() -> Result<()> {
    let runner = test_runner_with_fake_runtime(
        test_codex_config(),
        false,
        Arc::new(FakeRunnerHarness::default()),
        None,
    )
    .await;
    let account = &runner.auth_accounts[0];
    let observed =
        (Utc::now() + ChronoDuration::hours(1)).to_rfc3339_opts(SecondsFormat::Secs, true);
    runner
        .state
        .service_state
        .set_auth_limit_reset_at(&account.state_key, &observed)
        .await?;

    runner
        .run_with_auth_fallback(AuthFallbackAction::Review, |_| async { Ok(()) })
        .await?;
    assert_eq!(
        runner
            .state
            .service_state
            .get_auth_limit_reset_at(&account.state_key)
            .await?,
        None
    );
    Ok(())
}

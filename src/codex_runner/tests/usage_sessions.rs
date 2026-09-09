use super::*;

fn usage_response(credits: i64) -> ScriptedAppRequest {
    ScriptedAppRequest::result(
        "account/rateLimits/read",
        json!({"rateLimitResetCredits": {"availableCount": credits}}),
    )
}

async fn wait_for_protocol_method(harness: &FakeRunnerHarness, method: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while !harness
            .app_protocol_requests()
            .iter()
            .any(|request| request["method"] == method)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker should send protocol request");
}

#[tokio::test]
async fn concurrent_usage_requests_share_one_account_connection() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(2),
        usage_response(1),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    let (first, second) = tokio::join!(
        runner.read_usage_limits("primary"),
        runner.read_usage_limits("primary"),
    );
    assert_eq!(
        first
            .unwrap()
            .rate_limit_reset_credits
            .unwrap()
            .available_count,
        2
    );
    assert_eq!(
        second
            .unwrap()
            .rate_limit_reset_credits
            .unwrap()
            .available_count,
        1
    );
    assert_eq!(harness.app_server_starts().len(), 1);
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn failed_usage_connection_is_removed_and_next_request_starts_fresh() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(2).close_output_after(),
    ]));
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(1),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    runner.read_usage_limits("primary").await.unwrap();
    assert!(
        runner
            .consume_usage_limit_reset("primary", "reset-key")
            .await
            .is_err()
    );
    // A failed reset must not be replayed automatically on a fresh connection.
    assert_eq!(harness.app_server_starts().len(), 1);
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
    let usage = runner.read_usage_limits("primary").await.unwrap();
    assert_eq!(usage.rate_limit_reset_credits.unwrap().available_count, 1);
    assert_eq!(harness.app_server_starts().len(), 2);
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.removed_containers(), vec!["app-1", "app-2"]);
}

#[tokio::test]
async fn failed_usage_removal_preserves_the_error_and_recovers_without_leaking() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(2).close_output_after(),
    ]));
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(1),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    runner.read_usage_limits("primary").await.unwrap();
    harness.push_usage_removal_error("Docker temporarily unavailable");
    let error = runner.read_usage_limits("primary").await.unwrap_err();
    assert!(format!("{error:#}").contains("Docker temporarily unavailable"));
    assert!(!format!("{error:#}").contains("receive Usage response"));
    assert_eq!(harness.app_server_starts().len(), 1);
    assert!(harness.removed_containers().is_empty());

    harness.push_usage_removal_error("Docker still unavailable");
    assert!(runner.read_usage_limits("primary").await.is_err());
    assert_eq!(harness.app_server_starts().len(), 1);
    let usage = runner.read_usage_limits("primary").await.unwrap();
    assert_eq!(usage.rate_limit_reset_credits.unwrap().available_count, 1);
    assert_eq!(harness.app_server_starts().len(), 2);
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.removed_containers(), vec!["app-1", "app-2"]);
}

#[tokio::test]
async fn cancelled_usage_caller_does_not_interrupt_the_shared_protocol() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({}))
            .with_after_response(vec![ScriptedAppChunk::SleepMillis(100)]),
        usage_response(2),
        usage_response(1),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    let caller = tokio::spawn({
        let runner = runner.clone();
        async move { runner.read_usage_limits("primary").await }
    });
    wait_for_protocol_method(&harness, "initialize").await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    let usage = runner.read_usage_limits("primary").await.unwrap();
    assert_eq!(usage.rate_limit_reset_credits.unwrap().available_count, 1);
    assert_eq!(harness.app_server_starts().len(), 1);
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn usage_shutdown_interrupts_active_protocol_and_rejects_new_requests() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({}))
            .with_after_response(vec![ScriptedAppChunk::SleepMillis(60_000)]),
        usage_response(2),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    let caller = tokio::spawn({
        let runner = runner.clone();
        async move { runner.read_usage_limits("primary").await }
    });
    wait_for_protocol_method(&harness, "initialize").await;
    tokio::time::timeout(Duration::from_secs(5), runner.shutdown_usage_sessions())
        .await
        .unwrap()
        .unwrap();
    assert!(caller.await.unwrap().is_err());
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
    assert!(runner.read_usage_limits("primary").await.is_err());
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.app_server_starts().len(), 1);
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn dropping_runner_removes_idle_usage_container_without_a_reference_cycle() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.push_app_server(ScriptedAppServer::from_requests(vec![
        ScriptedAppRequest::result("initialize", json!({})),
        usage_response(2),
    ]));
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, harness.clone(), None).await;
    runner.read_usage_limits("primary").await.unwrap();
    let weak = Arc::downgrade(&runner);
    drop(runner);
    tokio::time::timeout(Duration::from_secs(5), async {
        while harness.removed_containers().is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(weak.upgrade().is_none());
    assert_eq!(harness.removed_containers(), vec!["app-1"]);
}

#[tokio::test]
async fn usage_accounts_keep_separate_connections_and_auth_mounts() {
    let harness = Arc::new(FakeRunnerHarness::default());
    for credits in [2, 7] {
        harness.push_app_server(ScriptedAppServer::from_requests(vec![
            ScriptedAppRequest::result("initialize", json!({})),
            usage_response(credits),
            usage_response(credits),
        ]));
    }
    let mut config = test_codex_config();
    config
        .fallback_auth_accounts
        .push(FallbackAuthAccountConfig {
            name: "backup".to_string(),
            auth_host_path: "/auth/backup".to_string(),
        });
    let runner = test_runner_with_fake_runtime(config, false, harness.clone(), None).await;
    for _ in 0..2 {
        assert_eq!(
            runner
                .read_usage_limits("primary")
                .await
                .unwrap()
                .rate_limit_reset_credits
                .unwrap()
                .available_count,
            2
        );
        assert_eq!(
            runner
                .read_usage_limits("backup")
                .await
                .unwrap()
                .rate_limit_reset_credits
                .unwrap()
                .available_count,
            7
        );
    }
    let starts = harness.app_server_starts();
    assert_eq!(starts.len(), 2);
    assert_eq!(
        starts[0].request.binds,
        vec!["/root/.codex:/root/.codex:rw"]
    );
    assert_eq!(
        starts[1].request.binds,
        vec!["/auth/backup:/root/.codex:rw"]
    );
    runner.shutdown_usage_sessions().await.unwrap();
    assert_eq!(harness.removed_containers().len(), 2);
}

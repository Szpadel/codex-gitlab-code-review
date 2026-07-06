use super::*;
use std::collections::{BTreeMap, VecDeque};

#[derive(Default)]
struct FakeUsageRunner {
    snapshots: Mutex<BTreeMap<String, VecDeque<Result<CodexUsageSnapshot, String>>>>,
    reset_outcomes: Mutex<VecDeque<Result<CodexUsageResetOutcome, String>>>,
    reset_calls: Mutex<Vec<(String, String)>>,
}

impl FakeUsageRunner {
    fn with_snapshot(self: &Arc<Self>, account: &str, snapshot: CodexUsageSnapshot) {
        self.snapshots
            .lock()
            .expect("snapshots")
            .entry(account.to_string())
            .or_default()
            .push_back(Ok(snapshot));
    }

    fn with_reset_outcome(self: &Arc<Self>, outcome: CodexUsageResetOutcome) {
        self.reset_outcomes
            .lock()
            .expect("reset outcomes")
            .push_back(Ok(outcome));
    }

    fn reset_calls(&self) -> Vec<(String, String)> {
        self.reset_calls.lock().expect("reset calls").clone()
    }
}

#[async_trait]
impl CodexRunner for FakeUsageRunner {
    async fn read_usage_limits(&self, account_name: &str) -> Result<CodexUsageSnapshot> {
        self.snapshots
            .lock()
            .expect("snapshots")
            .get_mut(account_name)
            .and_then(VecDeque::pop_front)
            .unwrap_or_else(|| Err(format!("no usage snapshot queued for {account_name}")))
            .map_err(anyhow::Error::msg)
    }

    async fn consume_usage_limit_reset(
        &self,
        account_name: &str,
        idempotency_key: &str,
    ) -> Result<CodexUsageResetOutcome> {
        self.reset_calls
            .lock()
            .expect("reset calls")
            .push((account_name.to_string(), idempotency_key.to_string()));
        self.reset_outcomes
            .lock()
            .expect("reset outcomes")
            .pop_front()
            .unwrap_or_else(|| Err("no reset outcome queued".to_string()))
            .map_err(anyhow::Error::msg)
    }

    async fn run_review(&self, _ctx: crate::codex_runner::ReviewContext) -> Result<CodexResult> {
        Ok(CodexResult::Pass {
            summary: "ok".to_string(),
        })
    }
}

#[tokio::test]
async fn usage_page_renders_all_accounts_and_all_returned_limits() -> Result<()> {
    let mut config = test_config();
    config.codex.fallback_auth_accounts = vec![FallbackAuthAccountConfig {
        name: "backup-high".to_string(),
        auth_host_path: "/tmp/codex-backup-high".to_string(),
    }];
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(
            Some(2),
            [
                ("codex", weekly_limit(100.0)),
                ("codex_other", windowed_limit(25.0, Some(300))),
            ],
        ),
    );
    runner.with_snapshot(
        "backup-high",
        usage_snapshot(Some(0), [("codex", weekly_limit(40.0))]),
    );
    let srv = HttpTestServerBuilder::new()
        .with_config(config)
        .with_runner(runner)
        .spawn()
        .await?;

    let response = test_get(format!("http://{}/usage", srv.address)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.text().await?;
    assert!(body.contains("Usage limits"));
    assert!(body.contains("primary"));
    assert!(body.contains("backup-high"));
    assert!(body.contains("codex"));
    assert!(body.contains("codex_other"));
    assert!(body.contains("Weekly"));
    assert!(body.contains("5h"));
    assert!(body.contains("100.00% used"));
    assert!(body.contains("25.00% used"));
    assert!(body.contains("2 reset credits"));
    assert!(body.contains("Use reset"));
    assert!(body.contains("<a class=\"nav-link active\" href=\"/usage\""));
    Ok(())
}

#[tokio::test]
async fn usage_reset_requires_csrf_and_weekly_exhaustion() -> Result<()> {
    let config = test_config();
    let primary_state_key = auth_account_state_key("primary", &config.codex.auth_host_path);
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(Some(1), [("codex", weekly_limit(99.0))]),
    );
    runner.with_reset_outcome(CodexUsageResetOutcome::Reset);
    let srv = HttpTestServerBuilder::new()
        .with_config(config)
        .with_runner(runner.clone())
        .spawn()
        .await?;
    srv.state
        .service_state
        .set_auth_limit_reset_at(&primary_state_key, "2099-03-10T12:00:00Z")
        .await?;
    let csrf_token = srv.services.admin.admin_csrf_token().to_string();
    let client = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    let denied = client
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[("csrf_token", "wrong"), ("account_name", "primary")])
        .send()
        .await?;
    assert_eq!(denied.status(), StatusCode::BAD_REQUEST);

    let blocked = client
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("account_name", "primary"),
        ])
        .send()
        .await?;
    assert_eq!(blocked.status(), StatusCode::BAD_REQUEST);
    assert_eq!(runner.reset_calls(), Vec::<(String, String)>::new());
    assert_eq!(
        srv.state
            .service_state
            .get_auth_limit_reset_at(&primary_state_key)
            .await?,
        Some("2099-03-10T12:00:00Z".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn usage_reset_consumes_credit_and_clears_selected_local_cooldown() -> Result<()> {
    let config = test_config();
    let primary_state_key = auth_account_state_key("primary", &config.codex.auth_host_path);
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(Some(1), [("codex", weekly_limit(100.0))]),
    );
    runner.with_reset_outcome(CodexUsageResetOutcome::Reset);
    let srv = HttpTestServerBuilder::new()
        .with_config(config)
        .with_runner(runner.clone())
        .spawn()
        .await?;
    srv.state
        .service_state
        .set_auth_limit_reset_at(&primary_state_key, "2099-03-10T12:00:00Z")
        .await?;
    srv.state
        .service_state
        .set_service_state_value(QUOTA_LAST_PROBE_AT_KEY, "2026-03-10T10:00:00Z")
        .await?;
    let csrf_token = srv.services.admin.admin_csrf_token().to_string();

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("account_name", "primary"),
        ])
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let calls = runner.reset_calls();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "primary");
    assert!(!calls[0].1.trim().is_empty());
    assert_eq!(
        srv.state
            .service_state
            .get_auth_limit_reset_at(&primary_state_key)
            .await?,
        None
    );
    assert_eq!(
        srv.state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn usage_reset_rejects_when_fresh_snapshot_has_no_reset_credits() -> Result<()> {
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(Some(0), [("codex", weekly_limit(100.0))]),
    );
    runner.with_reset_outcome(CodexUsageResetOutcome::Reset);
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner.clone())
        .spawn()
        .await?;
    let csrf_token = srv.services.admin.admin_csrf_token().to_string();

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("account_name", "primary"),
        ])
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(runner.reset_calls(), Vec::<(String, String)>::new());
    Ok(())
}

#[tokio::test]
async fn usage_reset_rejects_when_reset_credits_are_missing() -> Result<()> {
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(None, [("codex", weekly_limit(100.0))]),
    );
    runner.with_reset_outcome(CodexUsageResetOutcome::Reset);
    let srv = HttpTestServerBuilder::new()
        .with_runner(runner.clone())
        .spawn()
        .await?;
    let csrf_token = srv.services.admin.admin_csrf_token().to_string();

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("account_name", "primary"),
        ])
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(runner.reset_calls(), Vec::<(String, String)>::new());
    Ok(())
}

#[tokio::test]
async fn usage_reset_nothing_to_reset_clears_selected_local_cooldown() -> Result<()> {
    let config = test_config();
    let primary_state_key = auth_account_state_key("primary", &config.codex.auth_host_path);
    let runner = Arc::new(FakeUsageRunner::default());
    runner.with_snapshot(
        "primary",
        usage_snapshot(Some(1), [("codex", weekly_limit(100.0))]),
    );
    runner.with_reset_outcome(CodexUsageResetOutcome::NothingToReset);
    let srv = HttpTestServerBuilder::new()
        .with_config(config)
        .with_runner(runner.clone())
        .spawn()
        .await?;
    srv.state
        .service_state
        .set_auth_limit_reset_at(&primary_state_key, "2099-03-10T12:00:00Z")
        .await?;
    srv.state
        .service_state
        .set_service_state_value(QUOTA_LAST_PROBE_AT_KEY, "2026-03-10T10:00:00Z")
        .await?;
    let csrf_token = srv.services.admin.admin_csrf_token().to_string();

    let response = test_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(format!("http://{}/usage/reset", srv.address))
        .form(&[
            ("csrf_token", csrf_token.as_str()),
            ("account_name", "primary"),
        ])
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(runner.reset_calls().len(), 1);
    assert_eq!(
        srv.state
            .service_state
            .get_auth_limit_reset_at(&primary_state_key)
            .await?,
        None
    );
    assert_eq!(
        srv.state
            .service_state
            .get_service_state_value(QUOTA_LAST_PROBE_AT_KEY)
            .await?,
        None
    );
    Ok(())
}

fn usage_snapshot<const N: usize>(
    reset_credits: Option<i64>,
    limits: [(&str, CodexUsageLimitSnapshot); N],
) -> CodexUsageSnapshot {
    CodexUsageSnapshot {
        rate_limits_by_limit_id: limits
            .into_iter()
            .map(|(limit_id, snapshot)| (limit_id.to_string(), snapshot))
            .collect(),
        rate_limit_reset_credits: reset_credits
            .map(|available_count| CodexUsageResetCredits { available_count }),
    }
}

fn weekly_limit(used_percent: f64) -> CodexUsageLimitSnapshot {
    windowed_limit(used_percent, Some(7 * 24 * 60))
}

fn windowed_limit(used_percent: f64, window_duration_mins: Option<i64>) -> CodexUsageLimitSnapshot {
    CodexUsageLimitSnapshot {
        primary: Some(CodexUsageWindow {
            used_percent,
            window_duration_mins,
            resets_at: Some(1_735_693_200),
        }),
        secondary: None,
        credits: None,
        individual_limit: None,
        rate_limit_reached_type: None,
    }
}

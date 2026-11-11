use super::*;

#[derive(Clone)]
struct LogCapture(Arc<Mutex<Vec<u8>>>);

impl Write for LogCapture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn container_removal_warns_on_failure_but_not_when_already_removed() {
    use tracing::instrument::WithSubscriber;

    let harness = Arc::new(FakeRunnerHarness::default());
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;
    let log = LogCapture(Arc::new(Mutex::new(Vec::new())));
    let writer = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();

    async {
        for status_code in [500, 404] {
            harness.push_removal_error(bollard::errors::Error::DockerResponseServerError {
                status_code,
                message: "removal failed".to_string(),
            });
            runner.remove_container_best_effort("cleanup-id").await;
        }
    }
    .with_subscriber(subscriber)
    .await;

    let output = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
    assert_eq!(output.matches("WARN").count(), 1, "{output}");
    assert!(output.contains("cleanup-id"), "{output}");
    assert!(output.contains("removal failed"), "{output}");
}

#[tokio::test]
async fn stop_active_review_containers_with_fake_runtime_filters_to_owned_managed_names() {
    let harness = Arc::new(FakeRunnerHarness::default());
    harness.set_managed_containers(vec![
        ManagedContainerSummary {
            id: Some("remove-review".to_string()),
            names: vec!["/codex-review-123".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("remove-browser".to_string()),
            names: vec!["/codex-browser-456".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("skip-other-owner".to_string()),
            names: vec!["/codex-review-789".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "someone-else".to_string(),
            )])),
        },
        ManagedContainerSummary {
            id: Some("skip-unmanaged".to_string()),
            names: vec!["/not-codex".to_string()],
            labels: Some(HashMap::from([(
                REVIEW_OWNER_LABEL_KEY.to_string(),
                "owner-id".to_string(),
            )])),
        },
    ]);
    let runner =
        test_runner_with_fake_runtime(test_codex_config(), false, Arc::clone(&harness), None).await;

    runner.stop_active_review_containers_best_effort().await;

    assert_eq!(
        harness.removed_containers(),
        vec!["remove-review".to_string(), "remove-browser".to_string()]
    );
}

#[tokio::test]
async fn stop_active_docker_containers_filters_ownership_and_continues_after_removal_failure()
-> Result<()> {
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path_regex},
    };

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {"Id": "remove-review", "Names": ["/codex-review-1"], "Labels": {REVIEW_OWNER_LABEL_KEY: "owner-id"}},
            {"Id": "remove-browser", "Names": ["/codex-browser-2"], "Labels": {REVIEW_OWNER_LABEL_KEY: "owner-id"}},
            {"Id": "skip-other-owner", "Names": ["/codex-review-3"], "Labels": {REVIEW_OWNER_LABEL_KEY: "other-owner"}},
            {"Id": "skip-unmanaged", "Names": ["/other-4"], "Labels": {REVIEW_OWNER_LABEL_KEY: "owner-id"}},
            {"Names": ["/codex-review-no-id"], "Labels": {REVIEW_OWNER_LABEL_KEY: "owner-id"}}
        ])))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex("/containers/remove-review$"))
        .respond_with(
            ResponseTemplate::new(500).set_body_json(json!({"message": "removal failed"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path_regex("/containers/remove-browser$"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    let runner = DockerCodexRunner::new(
        &DockerConfig { host: server.uri() },
        test_codex_config(),
        Url::parse("https://gitlab.example.com")?,
        Arc::new(crate::gitlab::GitLabClient::new(
            "http://127.0.0.1:9",
            "token",
        )?),
        Arc::new(ReviewStateStore::new(":memory:").await?),
        None,
        RunnerRuntimeOptions {
            gitlab_token: "token".to_string(),
            log_all_json: false,
            owner_id: "owner-id".to_string(),
            mention_commands_active: false,
            review_additional_developer_instructions: None,
        },
    )?;

    runner.stop_active_review_containers_best_effort().await;

    server.verify().await;
    let requests = server.received_requests().await.expect("received requests");
    assert_eq!(
        requests.len(),
        3,
        "only remove owned managed containers with IDs"
    );
    assert!(
        requests[1]
            .url
            .path()
            .ends_with("/containers/remove-review")
    );
    assert!(
        requests[2]
            .url
            .path()
            .ends_with("/containers/remove-browser")
    );
    Ok(())
}

#[test]
fn review_container_prefix_matcher_handles_docker_name_format() {
    assert!(DockerCodexRunner::is_managed_container_name(
        "codex-review-abc"
    ));
    assert!(DockerCodexRunner::is_managed_container_name(
        "/codex-review-def"
    ));
    assert!(DockerCodexRunner::is_managed_container_name(
        "/codex-browser-jkl"
    ));
    assert!(!DockerCodexRunner::is_managed_container_name(
        "/codex-auth-ghi"
    ));
}

#[test]
fn review_container_labels_include_owner_label() {
    let labels = DockerCodexRunner::review_container_labels("worker-a");
    assert_eq!(
        labels.get(REVIEW_OWNER_LABEL_KEY),
        Some(&"worker-a".to_string())
    );
    assert_eq!(labels.len(), 1);
}

#[test]
fn review_container_filters_include_name_prefix_and_owner_label() {
    let filters = DockerCodexRunner::review_container_filters("worker-a");
    assert_eq!(
        filters.get("name"),
        Some(&vec![
            REVIEW_CONTAINER_NAME_PREFIX.to_string(),
            BROWSER_CONTAINER_NAME_PREFIX.to_string()
        ])
    );
    assert_eq!(
        filters.get("label"),
        Some(&vec![format!("{REVIEW_OWNER_LABEL_KEY}=worker-a")])
    );
}

#[test]
fn has_review_owner_label_requires_exact_owner_match() {
    let labels = HashMap::from([(REVIEW_OWNER_LABEL_KEY.to_string(), "worker-a".to_string())]);
    assert!(DockerCodexRunner::has_review_owner_label(
        Some(&labels),
        "worker-a"
    ));
    assert!(!DockerCodexRunner::has_review_owner_label(
        Some(&labels),
        "worker-b"
    ));
    assert!(!DockerCodexRunner::has_review_owner_label(None, "worker-a"));
}

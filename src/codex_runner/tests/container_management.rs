use super::*;
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

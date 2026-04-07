use super::*;
#[tokio::test]
async fn resolves_targets_with_exclusions() -> Result<()> {
    let mut config = test_config();
    config.gitlab.targets.repos =
        TargetSelector::List(vec!["group/keep".to_string(), "group/drop".to_string()]);
    config.gitlab.targets.groups = TargetSelector::List(vec!["group".to_string()]);
    config.gitlab.targets.exclude_repos = vec!["group/drop".to_string()];
    config.gitlab.targets.exclude_groups = vec!["group/exclude".to_string()];

    let bot_user = GitLabUser {
        id: 1,
        username: None,
        name: None,
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user,
        mrs: Mutex::new(Vec::new()),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::new()),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::from([(
            "group".to_string(),
            vec![
                "group/include".to_string(),
                "group/exclude/project".to_string(),
            ],
        )])),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(FakeRunner {
        result: Mutex::new(None),
        calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab, state, runner, 1, default_created_after());

    let repos = service.resolve_repos(ScanMode::Full).await?;

    assert_eq!(
        repos,
        vec!["group/include".to_string(), "group/keep".to_string()]
    );
    Ok(())
}

#[tokio::test]
async fn dev_mode_scan_persists_mocked_run_history_for_synthetic_merge_request() -> Result<()> {
    let config = test_config();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let dev_tools = Arc::new(DevToolsService::new("/tmp/dev-mode.sqlite"));
    dev_tools.simulate_new_mr("demo/group/service-a").await?;
    let first_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing synthetic head sha")?;
    let dynamic_repo_source: Arc<dyn DynamicRepoSource> = dev_tools.clone();
    let service = ReviewService::new(
        config,
        dev_tools.gitlab_api(),
        Arc::clone(&state),
        Arc::new(MockCodexRunner::new(Arc::clone(&state))),
        1,
        default_created_after(),
    )
    .with_dynamic_repo_source(dynamic_repo_source);

    service.scan_once().await?;

    let runs = state
        .run_history
        .list_run_history_for_mr("demo/group/service-a", 1)
        .await?;
    assert_eq!(runs.len(), 1);
    assert_eq!(runs[0].head_sha, first_head_sha);
    assert_eq!(runs[0].auth_account_name.as_deref(), Some("dev-mode"));

    let events = state
        .run_history
        .list_run_history_events(runs[0].id)
        .await?;
    assert!(!events.is_empty());
    assert!(
        events
            .iter()
            .any(|event| event.event_type == "turn_completed")
    );
    Ok(())
}

#[tokio::test]
async fn dev_mode_incremental_scan_detects_new_commit_on_existing_synthetic_merge_request()
-> Result<()> {
    let config = test_config();
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let dev_tools = Arc::new(DevToolsService::new("/tmp/dev-mode.sqlite"));
    dev_tools.simulate_new_mr("demo/group/service-a").await?;
    let first_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing initial synthetic head sha")?;
    let dynamic_repo_source: Arc<dyn DynamicRepoSource> = dev_tools.clone();
    let service = ReviewService::new(
        config,
        dev_tools.gitlab_api(),
        Arc::clone(&state),
        Arc::new(MockCodexRunner::new(Arc::clone(&state))),
        1,
        default_created_after(),
    )
    .with_dynamic_repo_source(dynamic_repo_source);

    service.scan_once().await?;
    dev_tools
        .simulate_new_commit("demo/group/service-a")
        .await?;
    let second_head_sha = dev_tools
        .snapshot()
        .await
        .repos
        .into_iter()
        .find(|repo| repo.repo_path == "demo/group/service-a")
        .and_then(|repo| repo.active_head_sha)
        .context("missing updated synthetic head sha")?;

    service.scan_once_incremental().await?;

    let runs = state
        .run_history
        .list_run_history_for_mr("demo/group/service-a", 1)
        .await?;
    assert_eq!(runs.len(), 2);
    assert_eq!(runs[0].head_sha, second_head_sha);
    assert_eq!(runs[1].head_sha, first_head_sha);
    Ok(())
}

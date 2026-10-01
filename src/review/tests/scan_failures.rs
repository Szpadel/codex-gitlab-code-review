use super::*;
use async_trait::async_trait;

struct DynamicTargets(Mutex<Vec<String>>);

#[async_trait]
impl DynamicRepoSource for DynamicTargets {
    async fn list_repos(&self) -> Result<Vec<String>> {
        Ok(self.0.lock().unwrap().clone())
    }
}

#[tokio::test]
async fn scan_removes_overdue_retries_outside_resolved_targets() -> Result<()> {
    for remaining_targets in [vec!["group/current".to_string()], vec![]] {
        let gitlab = fake_gitlab(vec![mr(1, "sha1")]);
        let targets = Arc::new(DynamicTargets(Mutex::new(vec![
            "group/removed".to_string(),
        ])));
        let state = Arc::new(ReviewStateStore::new(":memory:").await?);
        let service = ReviewService::new(
            test_config(),
            gitlab.clone(),
            state,
            Arc::new(FailingRunner {
                calls: Mutex::new(0),
            }),
            1,
            default_created_after(),
        )
        .with_dynamic_repo_source(targets.clone());
        service.scan_once().await?;
        let now = Utc::now();
        assert_eq!(
            service.defer_review_backoff_retries_for_mr(
                "group/removed",
                1,
                now + Duration::hours(1),
                now - Duration::minutes(1),
            ),
            1
        );
        assert!(
            service
                .next_review_backoff_retry_at()
                .is_some_and(|next| next < now)
        );
        gitlab.awards.lock().unwrap().insert(
            ("group/removed".to_string(), 1),
            vec![AwardEmoji {
                id: 99,
                name: "warning".to_string(),
                user: gitlab.bot_user.clone(),
            }],
        );
        *targets.0.lock().unwrap() = remaining_targets.clone();

        service.scan_once().await?;

        assert!(!service.has_active_review_backoff_retry_for_mr("group/removed", 1));
        assert!(
            service
                .next_review_backoff_retry_at()
                .is_none_or(|next| next > now)
        );
        assert_eq!(
            service.has_active_review_backoff_retry_for_mr("group/current", 1),
            !remaining_targets.is_empty()
        );
        assert!(
            gitlab
                .calls
                .lock()
                .unwrap()
                .iter()
                .any(|call| call == "delete_award:group/removed:1:99")
        );
    }
    Ok(())
}

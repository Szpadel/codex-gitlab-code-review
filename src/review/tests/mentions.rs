use super::*;
#[test]
fn mention_detection_honors_boundaries() {
    assert!(contains_mention("@botuser please fix", "botuser"));
    assert!(contains_mention("@botuser.", "botuser"));
    assert!(contains_mention("ping (@botuser).", "botuser"));
    assert!(!contains_mention("@botuser2 please fix", "botuser"));
    assert!(!contains_mention("@botuser.example please fix", "botuser"));
    assert!(!contains_mention("emailbotuser@example.com", "botuser"));
}

#[test]
fn extract_parent_chain_uses_reply_chain_when_available() {
    let discussion = MergeRequestDiscussion {
        id: "discussion".to_string(),
        notes: vec![
            DiscussionNote {
                id: 1,
                body: "root".to_string(),
                author: GitLabUser {
                    id: 1,
                    username: Some("a".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: None,
                created_at: None,
            },
            DiscussionNote {
                id: 2,
                body: "reply".to_string(),
                author: GitLabUser {
                    id: 2,
                    username: Some("b".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: Some(1),
                created_at: None,
            },
            DiscussionNote {
                id: 3,
                body: "second reply".to_string(),
                author: GitLabUser {
                    id: 3,
                    username: Some("c".to_string()),
                    name: None,
                },
                system: false,
                in_reply_to_id: Some(2),
                created_at: None,
            },
        ],
    };
    let chain = extract_parent_chain(&discussion, 3).expect("chain");
    assert_eq!(
        chain.iter().map(|note| note.id).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
}

#[tokio::test]
async fn scan_runs_mention_command_for_triggered_discussion_note() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.review.mention_commands.eyes_emoji = Some("inspect".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(30, "sha30")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 30),
            vec![AwardEmoji {
                id: 301,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 30),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 900,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 901,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(900),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:30:discussion-1")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| { call.as_str() == "create_discussion_note:group/repo:30:discussion-1" })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:30:discussion-1:901:inspect"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:30:discussion-1:901:10901"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(30i64)
    .bind("discussion-1")
    .bind(901i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn mention_history_insert_failure_releases_mention_lock() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(41, "sha41")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![AwardEmoji {
                id: 411,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 41),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 910,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 911,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(910),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    sqlx::query("DROP TABLE run_history")
        .execute(state.pool())
        .await?;
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner.clone(),
        1,
        default_created_after(),
    );

    assert!(service.scan_once().await.is_err());
    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    assert!(
        state
            .mention_commands
            .list_in_progress_mention_commands()
            .await?
            .is_empty()
    );
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(41i64)
    .bind("discussion-1")
    .bind(911i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result.as_deref(), Some("error"));
    Ok(())
}

#[tokio::test]
async fn mention_run_history_uses_refreshed_mr_sha() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let inner_gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(42, "sha-old")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 42),
            vec![AwardEmoji {
                id: 421,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 42),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "initial review comment".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser please implement change".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let gitlab = Arc::new(RefreshedMentionGitLab {
        inner: Arc::clone(&inner_gitlab),
        refreshed_mr: mr(42, "sha-new"),
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    let row = sqlx::query(
        "SELECT head_sha FROM run_history WHERE repo = ? AND iid = ? ORDER BY started_at DESC, id DESC LIMIT 1",
    )
    .bind("group/repo")
    .bind(42i64)
    .fetch_one(state.pool())
    .await?;
    let head_sha: String = row.try_get("head_sha")?;
    assert_eq!(head_sha, "sha-new");
    Ok(())
}

#[tokio::test]
async fn queued_mentions_snapshot_feature_flags_before_runner_start() -> Result<()> {
    let mut config = test_config();
    config.review.max_concurrent = 1;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    config.codex.gitlab_discovery_mcp.enabled = true;
    config.codex.gitlab_discovery_mcp.allow = vec![crate::config::GitLabDiscoveryAllowRule {
        source_repos: vec!["group/repo".to_string()],
        source_group_prefixes: Vec::new(),
        target_repos: vec!["group/shared".to_string()],
        target_groups: Vec::new(),
    }];
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(52, "sha52"), mr(53, "sha53")]),
        awards: Mutex::new(HashMap::from([
            (
                ("group/repo".to_string(), 52),
                vec![AwardEmoji {
                    id: 521,
                    name: "thumbsup".to_string(),
                    user: bot_user.clone(),
                }],
            ),
            (
                ("group/repo".to_string(), 53),
                vec![AwardEmoji {
                    id: 531,
                    name: "thumbsup".to_string(),
                    user: bot_user.clone(),
                }],
            ),
        ])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([
            (
                ("group/repo".to_string(), 52),
                vec![MergeRequestDiscussion {
                    id: "discussion-52".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 952,
                            body: "initial review comment".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 953,
                            body: "@botuser please implement change".to_string(),
                            author: requester.clone(),
                            system: false,
                            in_reply_to_id: Some(952),
                            created_at: None,
                        },
                    ],
                }],
            ),
            (
                ("group/repo".to_string(), 53),
                vec![MergeRequestDiscussion {
                    id: "discussion-53".to_string(),
                    notes: vec![
                        DiscussionNote {
                            id: 962,
                            body: "initial review comment".to_string(),
                            author: bot_user.clone(),
                            system: false,
                            in_reply_to_id: None,
                            created_at: None,
                        },
                        DiscussionNote {
                            id: 963,
                            body: "@botuser please implement another change".to_string(),
                            author: requester.clone(),
                            system: false,
                            in_reply_to_id: Some(962),
                            created_at: None,
                        },
                    ],
                }],
            ),
        ])),
        users: Mutex::new(HashMap::from([(
            7,
            GitLabUserDetail {
                id: 7,
                username: Some("alice".to_string()),
                name: Some("Alice".to_string()),
                public_email: Some("alice@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let first_started = Arc::new(tokio::sync::Notify::new());
    let release_first = Arc::new(tokio::sync::Notify::new());
    let runner = Arc::new(BlockingMentionRunner {
        first_started: Arc::clone(&first_started),
        release_first: Arc::clone(&release_first),
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    state
        .feature_flags
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(true),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;
    let service = Arc::new(ReviewService::new(
        config,
        gitlab,
        Arc::clone(&state),
        runner,
        1,
        default_created_after(),
    ));

    let first_started_wait = first_started.notified();
    let scan_task = {
        let service = Arc::clone(&service);
        tokio::spawn(async move { service.scan_once().await })
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), first_started_wait).await?;

    for _ in 0..50 {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM run_history WHERE kind = 'mention'")
                .fetch_one(state.pool())
                .await?;
        if count == 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    state
        .feature_flags
        .set_runtime_feature_flag_overrides(&crate::feature_flags::RuntimeFeatureFlagOverrides {
            gitlab_discovery_mcp: Some(false),
            gitlab_inline_review_comments: None,
            security_context_ignore_base_head: None,
            composer_install: None,
            composer_auto_repositories: None,
            composer_safe_install: None,
            security_review: None,
        })
        .await?;

    let mut snapshots = Vec::new();
    for _ in 0..50 {
        let rows = sqlx::query(
            "SELECT feature_flags_json FROM run_history WHERE kind = 'mention' ORDER BY trigger_note_id",
        )
        .fetch_all(state.pool())
        .await?;
        if rows.len() == 2 {
            snapshots = rows
                .into_iter()
                .map(|row| {
                    let json: String = row.try_get("feature_flags_json")?;
                    let snapshot =
                        serde_json::from_str::<crate::feature_flags::FeatureFlagSnapshot>(&json)?;
                    Ok(snapshot)
                })
                .collect::<Result<Vec<_>>>()?;
            if snapshots
                .iter()
                .all(|snapshot| snapshot.gitlab_discovery_mcp)
            {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.gitlab_discovery_mcp)
    );

    release_first.notify_waiters();
    scan_task.await??;
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_standalone_discussion_comment() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let standalone_author = GitLabUser {
        id: 42,
        username: Some("reviewer".to_string()),
        name: Some("Reviewer".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(33, "sha33")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 33),
            vec![AwardEmoji {
                id: 331,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 33),
            vec![MergeRequestDiscussion {
                id: "discussion-standalone".to_string(),
                notes: vec![DiscussionNote {
                    id: 930,
                    body: "@botuser please handle this standalone comment".to_string(),
                    author: standalone_author,
                    system: false,
                    in_reply_to_id: None,
                    created_at: None,
                }],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            42,
            GitLabUserDetail {
                id: 42,
                username: Some("reviewer".to_string()),
                name: Some("Reviewer".to_string()),
                public_email: Some("reviewer@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:33:discussion-standalone")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| {
                call.as_str() == "create_discussion_note:group/repo:33:discussion-standalone"
            })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:33:discussion-standalone:930:eyes"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str()
            == "delete_discussion_note_award:group/repo:33:discussion-standalone:930:10930"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(33i64)
    .bind("discussion-standalone")
    .bind(930i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn scan_runs_mention_command_for_reply_from_non_mr_author() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let reviewer = GitLabUser {
        id: 44,
        username: Some("reviewer2".to_string()),
        name: Some("Reviewer Two".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(34, "sha34")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 34),
            vec![AwardEmoji {
                id: 341,
                name: "thumbsup".to_string(),
                user: bot_user.clone(),
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 34),
            vec![MergeRequestDiscussion {
                id: "discussion-reply".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 940,
                        body: "Initial review thread note".to_string(),
                        author: bot_user,
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 941,
                        body: "@botuser please implement this follow-up".to_string(),
                        author: reviewer,
                        system: false,
                        in_reply_to_id: Some(940),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::from([(
            44,
            GitLabUserDetail {
                id: 44,
                username: Some("reviewer2".to_string()),
                name: Some("Reviewer Two".to_string()),
                public_email: Some("reviewer2@example.com".to_string()),
            },
        )])),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:34:discussion-reply")
    );
    assert_eq!(
        calls
            .iter()
            .filter(|call| {
                call.as_str() == "create_discussion_note:group/repo:34:discussion-reply"
            })
            .count(),
        1
    );
    assert!(calls.iter().any(|call| {
        call.as_str() == "add_discussion_note_award:group/repo:34:discussion-reply:941:eyes"
    }));
    assert!(calls.iter().any(|call| {
        call.as_str() == "delete_discussion_note_award:group/repo:34:discussion-reply:941:10941"
    }));
    let row = sqlx::query(
        "SELECT status, result FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(34i64)
    .bind("discussion-reply")
    .bind(941i64)
    .fetch_one(state.pool())
    .await?;
    let status: String = row.try_get("status")?;
    let result: Option<String> = row.try_get("result")?;
    assert_eq!(status, "done");
    assert_eq!(result, Some("committed".to_string()));
    Ok(())
}

#[tokio::test]
async fn dry_run_skips_mention_commands_and_thread_status_writes() -> Result<()> {
    let mut config = test_config();
    config.review.dry_run = true;
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr(31, "sha31")]),
        awards: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 31),
            vec![AwardEmoji {
                id: 311,
                name: "thumbsup".to_string(),
                user: bot_user,
            }],
        )])),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 31),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 910,
                        body: "review note".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 911,
                        body: "@botuser please implement".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(910),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionRunner {
        mention_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(
        config,
        gitlab.clone(),
        state.clone(),
        runner.clone(),
        1,
        default_created_after(),
    );

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 0);
    let calls = gitlab.calls.lock().unwrap().clone();
    assert!(
        !calls
            .iter()
            .any(|call| call == "create_discussion_note:group/repo:31:discussion-1")
    );
    let processed_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM mention_command_state WHERE repo = ? AND iid = ? AND discussion_id = ? AND trigger_note_id = ?",
    )
    .bind("group/repo")
    .bind(31i64)
    .bind("discussion-1")
    .bind(911i64)
    .fetch_one(state.pool())
    .await?;
    assert_eq!(processed_count, 0);
    Ok(())
}

#[tokio::test]
async fn mention_runs_even_when_mr_created_before_cutoff() -> Result<()> {
    let mut config = test_config();
    config.review.mention_commands.enabled = true;
    config.review.mention_commands.bot_username = Some("botuser".to_string());
    let bot_user = GitLabUser {
        id: 1,
        username: Some("botuser".to_string()),
        name: Some("Bot User".to_string()),
    };
    let requester = GitLabUser {
        id: 7,
        username: Some("alice".to_string()),
        name: Some("Alice".to_string()),
    };
    let created_at = Utc
        .with_ymd_and_hms(2025, 1, 1, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let cutoff = Utc
        .with_ymd_and_hms(2025, 1, 2, 0, 0, 0)
        .single()
        .expect("valid datetime");
    let gitlab = Arc::new(FakeGitLab {
        bot_user: bot_user.clone(),
        mrs: Mutex::new(vec![mr_with_created_at(32, "sha32", created_at)]),
        awards: Mutex::new(HashMap::new()),
        notes: Mutex::new(HashMap::new()),
        discussions: Mutex::new(HashMap::from([(
            ("group/repo".to_string(), 32),
            vec![MergeRequestDiscussion {
                id: "discussion-1".to_string(),
                notes: vec![
                    DiscussionNote {
                        id: 920,
                        body: "review note".to_string(),
                        author: GitLabUser {
                            id: 1,
                            username: Some("botuser".to_string()),
                            name: Some("Bot User".to_string()),
                        },
                        system: false,
                        in_reply_to_id: None,
                        created_at: None,
                    },
                    DiscussionNote {
                        id: 921,
                        body: "@botuser question".to_string(),
                        author: requester,
                        system: false,
                        in_reply_to_id: Some(920),
                        created_at: None,
                    },
                ],
            }],
        )])),
        users: Mutex::new(HashMap::new()),
        projects: Mutex::new(HashMap::new()),
        all_projects: Mutex::new(Vec::new()),
        group_projects: Mutex::new(HashMap::new()),
        calls: Mutex::new(Vec::new()),
        list_open_calls: Mutex::new(0),
        list_projects_calls: Mutex::new(0),
        list_group_projects_calls: Mutex::new(0),
        delete_award_fails: false,
    });
    let runner = Arc::new(MentionAndReviewCounterRunner {
        mention_calls: Mutex::new(0),
        review_calls: Mutex::new(0),
    });
    let state = Arc::new(ReviewStateStore::new(":memory:").await?);
    let service = ReviewService::new(config, gitlab, state, runner.clone(), 1, cutoff);

    service.scan_once().await?;

    assert_eq!(*runner.mention_calls.lock().unwrap(), 1);
    assert_eq!(*runner.review_calls.lock().unwrap(), 0);
    Ok(())
}

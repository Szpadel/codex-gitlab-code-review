use super::*;
#[test]
fn mention_command_script_clones_repo_and_starts_app_server() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(
        script.contains("run_git clone git clone --depth 1 --recurse-submodules \"https://oauth2:${GITLAB_TOKEN}@example.com/repo.git\"")
    );
    assert!(script.contains("repo_dir='/work/repo/group/repo'"));
    assert!(script.contains("export GITLAB_TOKEN='token'"));
    assert!(
        script
            .contains("export GIT_CONFIG_KEY_0='url.https://oauth2:token@example.com/.insteadOf'")
    );
    assert!(script.contains("unset GIT_CONFIG_COUNT"));
    assert!(script.contains("unset GITLAB_TOKEN"));
    assert!(!script.contains("rm -rf"));
    assert!(script.contains("git remote set-url --push origin \"no_push://disabled\""));
    assert!(script.contains("exec codex app-server"));
    assert!(!script.contains("codex exec --sandbox workspace-write"));
    assert!(!script.contains("GIT_AUTHOR_NAME="));
}

#[test]
fn mention_command_script_includes_mcp_server_overrides() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let overrides = BTreeMap::from([("playwright".to_string(), true)]);
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &overrides,
            session_override: ConfiguredSessionOverride::default(),
        },
    );
    assert!(script.contains("exec codex -c 'mcp_servers.playwright.enabled=true' app-server"));
}

#[test]
fn mention_command_script_includes_reasoning_effort_override() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                reasoning_effort: Some("low"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_effort=\"low\"' app-server"));
}

#[test]
fn mention_command_script_includes_model_override() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                model: Some("gpt-5.4-mini"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model=\"gpt-5.4-mini\"' app-server"));
}

#[test]
fn mention_command_script_includes_reasoning_summary_override() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let script = DockerCodexRunner::build_mention_command_script(
        &ctx,
        "https://oauth2:${GITLAB_TOKEN}@example.com/repo.git",
        "token",
        "/root/.codex",
        AppServerCommandOptions {
            browser_mcp: None,
            gitlab_discovery_mcp: None,
            mcp_server_overrides: &BTreeMap::new(),
            session_override: ConfiguredSessionOverride {
                reasoning_summary: Some("detailed"),
                ..ConfiguredSessionOverride::default()
            },
        },
    );
    assert!(script.contains("exec codex -c 'model_reasoning_summary=\"detailed\"' app-server"));
}

#[test]
fn mention_developer_instructions_require_commit_and_sha_reporting() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: None,
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
    assert!(instructions.contains("create at least one commit before you finish"));
    assert!(instructions.contains("include the commit SHA"));
    assert!(instructions.contains("no commit was created"));
    assert!(instructions.contains("Name: Alice Example"));
    assert!(instructions.contains("Email: alice@example.com"));
    assert!(!instructions.contains("Additional instructions:"));
}

#[test]
fn mention_developer_instructions_include_additional_section_when_configured() {
    let ctx = MentionCommandContext {
        repo: "group/repo".to_string(),
        project_path: "group/repo".to_string(),
        discussion_project_path: "group/repo".to_string(),
        mr: MergeRequest {
            iid: 11,
            title: Some("Title".to_string()),
            web_url: Some("https://gitlab.example.com/group/repo/-/merge_requests/11".to_string()),
            draft: false,
            created_at: None,
            updated_at: None,
            sha: Some("abc123".to_string()),
            source_branch: None,
            target_branch: Some("main".to_string()),
            author: None,
            source_project_id: None,
            target_project_id: None,
            diff_refs: None,
        },
        head_sha: "abc123".to_string(),
        discussion_id: "discussion-1".to_string(),
        trigger_note_id: 77,
        requester_name: "Alice Example".to_string(),
        requester_email: "alice@example.com".to_string(),
        additional_developer_instructions: Some(
            "  Prefer minimal diffs and include tests.  ".to_string(),
        ),
        prompt: "Do the change".to_string(),
        image_uploads: Vec::new(),
        feature_flags: FeatureFlagSnapshot::default(),
        run_history_id: None,
    };
    let instructions = DockerCodexRunner::mention_developer_instructions(&ctx);
    assert!(instructions.contains("Additional instructions:"));
    assert!(instructions.contains("Prefer minimal diffs and include tests."));
}

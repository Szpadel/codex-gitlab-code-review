use super::*;
use anyhow::Result;
use chrono::{DateTime, Utc};
use pretty_assertions::assert_eq;
use wiremock::{
    Mock, MockServer, ResponseTemplate,
    matchers::{body_string_contains, header_exists, method, path, query_param},
};

#[tokio::test]
async fn list_open_mrs_paginates() -> Result<()> {
    let server = MockServer::start().await;
    let page1 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "2")
        .set_body_json(vec![serde_json::json!({
            "iid": 1,
            "sha": "abc"
        })]);
    let page2 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "iid": 2,
            "sha": "def"
        })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "100"))
        .respond_with(page2)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mrs = client.list_open_mrs("group/repo").await?;
    assert_eq!(mrs.len(), 2);
    assert_eq!(mrs[0].iid, 1);
    assert_eq!(mrs[1].iid, 2);
    Ok(())
}

#[tokio::test]
async fn list_open_mrs_deserializes_draft_status() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "iid": 3,
            "sha": "abc",
            "draft": true
        })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mrs = client.list_open_mrs("group/repo").await?;
    assert_eq!(mrs.len(), 1);
    assert!(mrs[0].draft);
    Ok(())
}

#[tokio::test]
async fn get_mr_deserializes_legacy_work_in_progress_as_draft() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "iid": 4,
        "sha": "def",
        "work_in_progress": true
    }));

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests/4"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mr = client.get_mr("group/repo", 4).await?;
    assert!(mr.draft);
    Ok(())
}

#[tokio::test]
async fn list_open_mrs_accepts_both_draft_fields() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "iid": 5,
            "sha": "ghi",
            "draft": true,
            "work_in_progress": true
        })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mrs = client.list_open_mrs("group/repo").await?;
    assert_eq!(mrs.len(), 1);
    assert!(mrs[0].draft);
    Ok(())
}

#[tokio::test]
async fn list_open_mrs_prefers_draft_when_both_fields_exist() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "iid": 6,
            "sha": "jkl",
            "draft": false,
            "work_in_progress": true
        })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mrs = client.list_open_mrs("group/repo").await?;
    assert_eq!(mrs.len(), 1);
    assert!(!mrs[0].draft);
    Ok(())
}

#[tokio::test]
async fn get_latest_open_mr_activity_fetches_latest_update() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "iid": 7,
        "updated_at": "2025-01-05T12:34:56Z"
    })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "1"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mr = client
        .get_latest_open_mr_activity("group/repo")
        .await?
        .expect("latest MR");
    assert_eq!(mr.iid, 7);
    assert_eq!(
        mr.updated_at,
        Some(DateTime::parse_from_rfc3339("2025-01-05T12:34:56Z")?.with_timezone(&Utc))
    );
    Ok(())
}

#[tokio::test]
async fn get_latest_open_mr_activity_accepts_both_draft_fields() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "iid": 8,
        "updated_at": "2025-01-05T12:34:56Z",
        "draft": true,
        "work_in_progress": true
    })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "1"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let mr = client
        .get_latest_open_mr_activity("group/repo")
        .await?
        .expect("latest MR");
    assert_eq!(mr.iid, 8);
    assert!(mr.draft);
    Ok(())
}

#[tokio::test]
async fn get_latest_open_mr_activity_error_is_self_contained() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "1"))
        .respond_with(
            ResponseTemplate::new(502)
                .insert_header("content-type", "text/plain")
                .set_body_string("upstream proxy failure"),
        )
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let err = client
        .get_latest_open_mr_activity("group/repo")
        .await
        .expect_err("request should fail");
    let message = err.to_string();
    assert!(message.contains("gitlab GET"));
    assert!(message.contains("/projects/group%2Frepo/merge_requests?state=opened"));
    assert!(message.contains("status=502 Bad Gateway"));
    assert!(message.contains("body=upstream proxy failure"));
    Ok(())
}

#[tokio::test]
async fn get_latest_open_mr_activity_json_decode_error_keeps_request_context() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests"))
        .and(query_param("state", "opened"))
        .and(query_param("scope", "all"))
        .and(query_param("order_by", "updated_at"))
        .and(query_param("sort", "desc"))
        .and(query_param("per_page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/html")
                .set_body_string("<html>proxy splash</html>"),
        )
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let err = client
        .get_latest_open_mr_activity("group/repo")
        .await
        .expect_err("request should fail");
    let message = err.to_string();
    assert!(message.contains("gitlab GET"), "{message}");
    assert!(message.contains("status=200 OK"), "{message}");
    assert!(message.contains("content_type=text/"), "{message}");
    assert!(
        message.contains("/projects/group%2Frepo/merge_requests?state=opened"),
        "{message}"
    );
    assert!(
        message.contains("body=<html>proxy splash</html>"),
        "{message}"
    );
    assert!(message.contains("decode_error="), "{message}");
    Ok(())
}

#[tokio::test]
async fn list_projects_paginates() -> Result<()> {
    let server = MockServer::start().await;
    let page1 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "2")
        .set_body_json(vec![serde_json::json!({
            "path_with_namespace": "group/repo"
        })]);
    let page2 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "path_with_namespace": "group/other"
        })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v4/projects"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "100"))
        .respond_with(page2)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let projects = client.list_projects().await?;
    assert_eq!(projects.len(), 2);
    assert_eq!(projects[0].path_with_namespace, "group/repo");
    assert_eq!(projects[1].path_with_namespace, "group/other");
    Ok(())
}

#[tokio::test]
async fn list_projects_excludes_inactive_entries() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![
        serde_json::json!({
            "path_with_namespace": "group/active",
            "archived": false,
            "marked_for_deletion_on": null
        }),
        serde_json::json!({
            "path_with_namespace": "group/archived",
            "archived": true,
            "marked_for_deletion_on": null
        }),
        serde_json::json!({
            "path_with_namespace": "group/deleting",
            "archived": false,
            "marked_for_deletion_on": "2026-03-18"
        }),
    ]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let projects = client.list_projects().await?;
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].path_with_namespace, "group/active");
    Ok(())
}

#[tokio::test]
async fn create_note_error_is_self_contained() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests/7/notes"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"message":"forbidden"}"#),
        )
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let err = client
        .create_note("group/repo", 7, "hello")
        .await
        .expect_err("request should fail");
    let message = err.to_string();
    assert!(message.contains("gitlab POST"));
    assert!(message.contains("/projects/group%2Frepo/merge_requests/7/notes"));
    assert!(message.contains("status=403 Forbidden"));
    assert!(message.contains(r#"body={"message":"forbidden"}"#));
    Ok(())
}

#[tokio::test]
async fn download_project_upload_fetches_bytes_from_gitlab() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/uploads/hash/screenshot%20final.png",
        ))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "image/png")
                .set_body_bytes(b"png-bytes".to_vec()),
        )
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    assert_eq!(
        client
            .download_project_upload("group/repo", "hash", "screenshot final.png")
            .await?,
        b"png-bytes".to_vec()
    );
    Ok(())
}

#[tokio::test]
async fn download_project_upload_error_is_self_contained() -> Result<()> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/uploads/hash/missing.png",
        ))
        .respond_with(
            ResponseTemplate::new(404)
                .insert_header("content-type", "application/json")
                .set_body_string(r#"{"message":"404 Upload Not Found"}"#),
        )
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let err = client
        .download_project_upload("group/repo", "hash", "missing.png")
        .await
        .expect_err("request should fail");
    let message = err.to_string();
    assert!(message.contains("gitlab GET"));
    assert!(message.contains("/projects/group%2Frepo/uploads/hash/missing.png"));
    assert!(message.contains("status=404 Not Found"));
    assert!(message.contains(r#"body={"message":"404 Upload Not Found"}"#));
    Ok(())
}

#[tokio::test]
async fn list_group_projects_includes_subgroups() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "path_with_namespace": "group/sub/repo"
    })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/group%2Fsub/projects"))
        .and(query_param("include_subgroups", "true"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let projects = client.list_group_projects("group/sub").await?;
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].path_with_namespace, "group/sub/repo");
    Ok(())
}

#[tokio::test]
async fn list_group_projects_excludes_inactive_entries() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![
        serde_json::json!({
            "path_with_namespace": "group/sub/active",
            "archived": false,
            "marked_for_deletion_at": null
        }),
        serde_json::json!({
            "path_with_namespace": "group/sub/archived",
            "archived": true,
            "marked_for_deletion_at": null
        }),
        serde_json::json!({
            "path_with_namespace": "group/sub/deleting",
            "archived": false,
            "marked_for_deletion_at": "2026-03-18"
        }),
    ]);

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/group%2Fsub/projects"))
        .and(query_param("include_subgroups", "true"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let projects = client.list_group_projects("group/sub").await?;
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].path_with_namespace, "group/sub/active");
    Ok(())
}

#[tokio::test]
async fn list_direct_group_projects_excludes_subgroups() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "path_with_namespace": "group/sub/repo"
    })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/group%2Fsub/projects"))
        .and(query_param("include_subgroups", "false"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let projects = client.list_direct_group_projects("group/sub").await?;
    assert_eq!(projects.len(), 1);
    assert_eq!(projects[0].path_with_namespace, "group/sub/repo");
    Ok(())
}

#[tokio::test]
async fn list_group_subgroups_returns_full_paths() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "full_path": "group/sub/child"
    })]);

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/group%2Fsub/subgroups"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let groups = client.list_group_subgroups("group/sub").await?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].full_path, "group/sub/child");
    Ok(())
}

#[tokio::test]
async fn list_group_subgroups_excludes_inactive_entries() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![
        serde_json::json!({
            "full_path": "group/sub/active",
            "archived": false,
            "marked_for_deletion_on": null
        }),
        serde_json::json!({
            "full_path": "group/sub/archived",
            "archived": true,
            "marked_for_deletion_on": null
        }),
        serde_json::json!({
            "full_path": "group/sub/deleting",
            "archived": false,
            "marked_for_deletion_on": "2026-03-18"
        }),
    ]);

    Mock::given(method("GET"))
        .and(path("/api/v4/groups/group%2Fsub/subgroups"))
        .and(query_param("simple", "true"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let groups = client.list_group_subgroups("group/sub").await?;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].full_path, "group/sub/active");
    Ok(())
}

#[test]
fn normalize_api_base_appends_api_path() -> Result<()> {
    let base = normalize_api_base("https://gitlab.example.com")?;
    assert_eq!(base, "https://gitlab.example.com/api/v4");
    Ok(())
}

#[tokio::test]
async fn delete_award_accepts_no_content() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(204);
    Mock::given(method("DELETE"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/1/award_emoji/42",
        ))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    client.delete_award("group/repo", 1, 42).await?;
    Ok(())
}

#[tokio::test]
async fn get_project_reads_last_activity() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "web_url": "https://gitlab.example.com/group/repo",
        "default_branch": "main",
        "last_activity_at": "2025-01-01T00:00:00Z"
    }));
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let project = client.get_project("group/repo").await?;
    assert_eq!(
        project.web_url,
        Some("https://gitlab.example.com/group/repo".to_string())
    );
    assert_eq!(project.default_branch, Some("main".to_string()));
    assert_eq!(
        project.last_activity_at,
        Some("2025-01-01T00:00:00Z".to_string())
    );
    Ok(())
}

#[tokio::test]
async fn list_repository_branches_paginates_and_sorts_names() -> Result<()> {
    let server = MockServer::start().await;
    let page1 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "2")
        .set_body_json(vec![
            serde_json::json!({ "name": "release" }),
            serde_json::json!({ "name": "main" }),
        ]);
    let page2 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![
            serde_json::json!({ "name": "develop" }),
            serde_json::json!({ "name": "main" }),
        ]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/repository/branches"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/repository/branches"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page2)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let branches = client.list_repository_branches("group/repo").await?;

    assert_eq!(branches, vec!["develop", "main", "release"]);
    Ok(())
}

#[tokio::test]
async fn list_repository_tags_paginates_and_sorts_names() -> Result<()> {
    let server = MockServer::start().await;
    let page1 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "2")
        .set_body_json(vec![
            serde_json::json!({ "name": "v2.0.0" }),
            serde_json::json!({ "name": "v1.0.0" }),
        ]);
    let page2 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![
            serde_json::json!({ "name": "v1.5.0" }),
            serde_json::json!({ "name": "v1.0.0" }),
        ]);

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/repository/tags"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page1)
        .mount(&server)
        .await;

    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/repository/tags"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page2)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let tags = client.list_repository_tags("group/repo").await?;

    assert_eq!(tags, vec!["v1.0.0", "v1.5.0", "v2.0.0"]);
    Ok(())
}

#[tokio::test]
async fn get_project_variable_requests_global_scope_filter() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "key": "COMPOSER_AUTH",
        "value": "{\"http-basic\":{}}",
        "environment_scope": "*",
        "variable_type": "env_var",
        "protected": false,
        "masked": true,
        "hidden": false,
        "raw": false,
        "description": null
    }));
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/variables/COMPOSER_AUTH",
        ))
        .and(query_param("filter[environment_scope]", "*"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let variable = client
        .get_project_variable("group/repo", "COMPOSER_AUTH")
        .await?;
    assert_eq!(variable.value, "{\"http-basic\":{}}");
    assert_eq!(variable.environment_scope, "*");
    Ok(())
}

#[tokio::test]
async fn get_group_variable_requests_global_scope_filter() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "key": "COMPOSER_AUTH",
        "value": "{\"http-basic\":{}}",
        "environment_scope": "*",
        "variable_type": "env_var",
        "protected": false,
        "masked": true,
        "hidden": false,
        "raw": false,
        "description": null
    }));
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/groups/group%2Fsubgroup/variables/COMPOSER_AUTH",
        ))
        .and(query_param("filter[environment_scope]", "*"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let variable = client
        .get_group_variable("group/subgroup", "COMPOSER_AUTH")
        .await?;
    assert_eq!(variable.value, "{\"http-basic\":{}}");
    assert_eq!(variable.environment_scope, "*");
    Ok(())
}

#[tokio::test]
async fn list_discussions_reads_thread_notes() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(vec![serde_json::json!({
        "id": "discussion-1",
        "notes": [
            {
                "id": 101,
                "body": "root",
                "system": false,
                "author": { "id": 1, "username": "alice", "name": "Alice" }
            },
            {
                "id": 102,
                "body": "@botuser please fix",
                "system": false,
                "in_reply_to_id": 101,
                "author": { "id": 2, "username": "bob", "name": "Bob" }
            }
        ]
    })]);
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/9/discussions",
        ))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let discussions = client.list_discussions("group/repo", 9).await?;
    assert_eq!(discussions.len(), 1);
    assert_eq!(discussions[0].id, "discussion-1");
    assert_eq!(discussions[0].notes.len(), 2);
    assert_eq!(discussions[0].notes[1].in_reply_to_id, Some(101));
    Ok(())
}

#[tokio::test]
async fn list_mr_diff_versions_reads_latest_version_metadata() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "id": 110,
            "head_commit_sha": "head-1",
            "base_commit_sha": "base-1",
            "start_commit_sha": "start-1"
        })]);
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/3/versions",
        ))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let versions = client.list_mr_diff_versions("group/repo", 3).await?;
    assert_eq!(
        versions,
        vec![MergeRequestDiffVersion {
            id: 110,
            head_commit_sha: "head-1".to_string(),
            base_commit_sha: "base-1".to_string(),
            start_commit_sha: "start-1".to_string(),
        }]
    );
    Ok(())
}

#[tokio::test]
async fn list_mr_diffs_reads_all_pages() -> Result<()> {
    let server = MockServer::start().await;
    let page1 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "2")
        .set_body_json(vec![serde_json::json!({
            "old_path": "src/old.rs",
            "new_path": "src/new.rs",
            "diff": "@@ -1 +1 @@\n-old\n+new\n",
            "renamed_file": true,
            "new_file": false,
            "deleted_file": false,
            "collapsed": false,
            "too_large": false
        })]);
    let page2 = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "old_path": "src/lib.rs",
            "new_path": "src/lib.rs",
            "diff": "@@ -4 +4 @@\n-old\n+new\n",
            "renamed_file": false,
            "new_file": false,
            "deleted_file": false,
            "collapsed": false,
            "too_large": false
        })]);
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests/8/diffs"))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v4/projects/group%2Frepo/merge_requests/8/diffs"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "100"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(page2)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let diffs = client.list_mr_diffs("group/repo", 8).await?;
    assert_eq!(diffs.len(), 2);
    assert_eq!(diffs[0].new_path, "src/new.rs");
    assert!(diffs[0].renamed_file);
    assert_eq!(diffs[1].new_path, "src/lib.rs");
    Ok(())
}

#[tokio::test]
async fn create_diff_discussion_posts_position_form_fields() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "id": "discussion-77"
    }));
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/4/discussions",
        ))
        .and(header_exists("PRIVATE-TOKEN"))
        .and(body_string_contains("body=inline+review"))
        .and(body_string_contains("position%5Bposition_type%5D=text"))
        .and(body_string_contains("position%5Bbase_sha%5D=base"))
        .and(body_string_contains("position%5Bhead_sha%5D=head"))
        .and(body_string_contains("position%5Bstart_sha%5D=start"))
        .and(body_string_contains("position%5Bold_path%5D=src%2Flib.rs"))
        .and(body_string_contains("position%5Bnew_path%5D=src%2Flib.rs"))
        .and(body_string_contains("position%5Bnew_line%5D=14"))
        .and(body_string_contains(
            "position%5Bline_range%5D%5Bstart%5D%5Bline_code%5D=hash_14_14",
        ))
        .and(body_string_contains(
            "position%5Bline_range%5D%5Bend%5D%5Bline_code%5D=hash_16_16",
        ))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    client
        .create_diff_discussion(
            "group/repo",
            4,
            &MergeRequestDiffDiscussion {
                body: "inline review".to_string(),
                position: DiffDiscussionPosition {
                    base_sha: "base".to_string(),
                    head_sha: "head".to_string(),
                    start_sha: "start".to_string(),
                    old_path: "src/lib.rs".to_string(),
                    new_path: "src/lib.rs".to_string(),
                    old_line: Some(14),
                    new_line: Some(14),
                    line_range: Some(DiffDiscussionLineRange {
                        start: DiffDiscussionLineEndpoint {
                            line_code: "hash_14_14".to_string(),
                            line_type: DiffDiscussionLineType::New,
                            old_line: Some(14),
                            new_line: Some(14),
                        },
                        end: DiffDiscussionLineEndpoint {
                            line_code: "hash_16_16".to_string(),
                            line_type: DiffDiscussionLineType::New,
                            old_line: Some(16),
                            new_line: Some(16),
                        },
                    }),
                },
            },
        )
        .await?;
    Ok(())
}

#[tokio::test]
async fn create_discussion_note_posts_to_discussion_endpoint() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "id": 777
    }));
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes",
        ))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    client
        .create_discussion_note("group/repo", 3, "discussion-123", "working on it")
        .await?;
    Ok(())
}

#[tokio::test]
async fn discussion_note_award_endpoints_use_discussion_note_path() -> Result<()> {
    let server = MockServer::start().await;
    let list_response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "id": 501,
            "name": "eyes",
            "user": { "id": 1, "username": "botuser", "name": "Bot User" }
        })]);
    Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(list_response)
            .mount(&server)
            .await;

    let add_response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "id": 777
    }));
    Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("name", "eyes"))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(add_response)
            .mount(&server)
            .await;

    let delete_response = ResponseTemplate::new(204);
    Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji/501",
            ))
            .and(header_exists("PRIVATE-TOKEN"))
            .respond_with(delete_response)
            .mount(&server)
            .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let awards = client
        .list_discussion_note_awards("group/repo", 3, "discussion-123", 777)
        .await?;
    assert_eq!(awards.len(), 1);
    client
        .add_discussion_note_award("group/repo", 3, "discussion-123", 777, "eyes")
        .await?;
    client
        .delete_discussion_note_award("group/repo", 3, "discussion-123", 777, 501)
        .await?;
    Ok(())
}

#[tokio::test]
async fn discussion_note_award_endpoints_fallback_to_merge_request_note_path() -> Result<()> {
    let server = MockServer::start().await;

    let not_found = ResponseTemplate::new(404).set_body_string("not found");
    Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("page", "1"))
            .and(query_param("per_page", "100"))
            .respond_with(not_found.clone())
            .mount(&server)
            .await;
    Mock::given(method("POST"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji",
            ))
            .and(query_param("name", "eyes"))
            .respond_with(not_found.clone())
            .mount(&server)
            .await;
    Mock::given(method("DELETE"))
            .and(path(
                "/api/v4/projects/group%2Frepo/merge_requests/3/discussions/discussion-123/notes/777/award_emoji/501",
            ))
            .respond_with(not_found)
            .mount(&server)
            .await;

    let list_fallback_response = ResponseTemplate::new(200)
        .append_header("X-Next-Page", "")
        .set_body_json(vec![serde_json::json!({
            "id": 501,
            "name": "eyes",
            "user": { "id": 1, "username": "botuser", "name": "Bot User" }
        })]);
    Mock::given(method("GET"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji",
        ))
        .and(query_param("page", "1"))
        .and(query_param("per_page", "100"))
        .respond_with(list_fallback_response)
        .mount(&server)
        .await;
    let add_fallback_response = ResponseTemplate::new(201).set_body_json(serde_json::json!({
        "id": 777
    }));
    Mock::given(method("POST"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji",
        ))
        .and(query_param("name", "eyes"))
        .respond_with(add_fallback_response)
        .mount(&server)
        .await;
    let delete_fallback_response = ResponseTemplate::new(204);
    Mock::given(method("DELETE"))
        .and(path(
            "/api/v4/projects/group%2Frepo/merge_requests/3/notes/777/award_emoji/501",
        ))
        .respond_with(delete_fallback_response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let awards = client
        .list_discussion_note_awards("group/repo", 3, "discussion-123", 777)
        .await?;
    assert_eq!(awards.len(), 1);
    client
        .add_discussion_note_award("group/repo", 3, "discussion-123", 777, "eyes")
        .await?;
    client
        .delete_discussion_note_award("group/repo", 3, "discussion-123", 777, 501)
        .await?;
    Ok(())
}

#[tokio::test]
async fn get_user_reads_public_email() -> Result<()> {
    let server = MockServer::start().await;
    let response = ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "id": 44,
        "username": "dev-user",
        "name": "Dev User",
        "public_email": "dev@example.com"
    }));
    Mock::given(method("GET"))
        .and(path("/api/v4/users/44"))
        .and(header_exists("PRIVATE-TOKEN"))
        .respond_with(response)
        .mount(&server)
        .await;

    let client = GitLabClient::new(&server.uri(), "token")?;
    let user = client.get_user(44).await?;
    assert_eq!(user.id, 44);
    assert_eq!(user.username.as_deref(), Some("dev-user"));
    assert_eq!(user.public_email.as_deref(), Some("dev@example.com"));
    Ok(())
}

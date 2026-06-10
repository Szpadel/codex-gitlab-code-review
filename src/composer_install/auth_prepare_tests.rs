use super::{
    ComposerAuthLookup, ComposerAuthLookupAttempt, PreparedComposerAuth, composer_debug_lines,
    prepare_composer_auth,
};
use serde_json::{Value, json};

#[test]
fn prepare_composer_auth_leaves_env_unchanged_when_auto_repositories_disabled() {
    let raw = r#"{"http-basic":{"example.com":{"username":"bot","password":"s3cr3t"}}}"#;

    let prepared = prepare_composer_auth(Some(raw), false);

    assert_eq!(prepared.env_value.as_deref(), Some(raw));
    assert_eq!(prepared.repository_config_json, None);
    assert_eq!(prepared.supported_sections, vec!["http-basic".to_string()]);
    assert_eq!(
        prepared.repository_urls,
        vec!["https://example.com".to_string()]
    );
    assert!(prepared.ignored_repository_entries.is_empty());
    assert!(!prepared.parse_failed);
}

#[test]
fn prepare_composer_auth_derives_supported_http_auth_hosts() {
    let raw = r#"{
      "http-basic":{"repo.example.com":{"username":"bot","password":"s3cr3t"}},
      "bearer":{"cache.example.com":"token"},
      "custom-headers":{"https://mirror.example.com/packages.json":["Authorization: token value"]},
      "gitlab-token":{"gitlab.example.com":"token"},
      "github-oauth":{"github.com":"token"}
    }"#;

    let prepared = prepare_composer_auth(Some(raw), true);
    let config = serde_json::from_str::<Value>(
        prepared
            .repository_config_json
            .as_deref()
            .expect("repository config"),
    )
    .expect("valid repository config");

    assert_eq!(prepared.env_value.as_deref(), Some(raw));
    assert_eq!(
        prepared.supported_sections,
        vec![
            "bearer".to_string(),
            "custom-headers".to_string(),
            "http-basic".to_string()
        ]
    );
    assert_eq!(
        prepared.repository_urls,
        vec![
            "https://cache.example.com".to_string(),
            "https://mirror.example.com/packages.json".to_string(),
            "https://repo.example.com".to_string()
        ]
    );
    assert_eq!(
        config,
        json!({
            "repositories": [
                { "type": "composer", "url": "https://cache.example.com" },
                { "type": "composer", "url": "https://mirror.example.com/packages.json" },
                { "type": "composer", "url": "https://repo.example.com" }
            ]
        })
    );
}

#[test]
fn prepare_composer_auth_preserves_ipv6_host_format() {
    let raw = r#"{
      "http-basic":{
        "[2001:db8::1]":{"username":"bot","password":"s3cr3t"},
        "[2001:db8::2]:8443":{"username":"bot","password":"s3cr3t"}
      }
    }"#;

    let prepared = prepare_composer_auth(Some(raw), true);
    let config = serde_json::from_str::<Value>(
        prepared
            .repository_config_json
            .as_deref()
            .expect("repository config"),
    )
    .expect("valid repository config");

    assert_eq!(
        config,
        json!({
            "repositories": [
                { "type": "composer", "url": "https://[2001:db8::1]" },
                { "type": "composer", "url": "https://[2001:db8::2]:8443" }
            ]
        })
    );
}

#[test]
fn prepare_composer_auth_ignores_invalid_or_unsupported_hosts() {
    let raw = r#"{
      "http-basic":{"":"bad","https://scheme.example.com":"bad","path/example.com":"bad","oauth2:token@example.com":"bad"},
      "gitlab-token":{"gitlab.example.com":"token"}
    }"#;

    let prepared = prepare_composer_auth(Some(raw), true);

    assert_eq!(prepared.env_value.as_deref(), Some(raw));
    assert_eq!(
        prepared.repository_urls,
        vec!["https://scheme.example.com".to_string()]
    );
    assert_eq!(
        prepared.ignored_repository_entries,
        vec![
            "".to_string(),
            "oauth2:token@example.com".to_string(),
            "path/example.com".to_string()
        ]
    );
}

#[test]
fn prepare_composer_auth_ignores_invalid_json() {
    let raw = "{not-json";

    let prepared = prepare_composer_auth(Some(raw), true);

    assert_eq!(prepared.env_value.as_deref(), Some(raw));
    assert_eq!(prepared.repository_config_json, None);
    assert!(prepared.parse_failed);
}

#[test]
fn composer_debug_lines_report_lookup_and_repository_derivation_steps() {
    let lookup = ComposerAuthLookup {
        value: Some("secret".to_string()),
        source: Some("group:team/platform".to_string()),
        attempts: vec![
            ComposerAuthLookupAttempt {
                scope: "project:team/platform/app".to_string(),
                found: false,
            },
            ComposerAuthLookupAttempt {
                scope: "group:team/platform".to_string(),
                found: true,
            },
        ],
    };
    let prepared = PreparedComposerAuth {
        env_value: Some("secret".to_string()),
        repository_config_json: Some(
            r#"{"repositories":[{"type":"composer","url":"https://repo.example.com"}]}"#
                .to_string(),
        ),
        supported_sections: vec!["http-basic".to_string()],
        repository_urls: vec!["https://repo.example.com".to_string()],
        ignored_repository_entries: vec!["path/example.com".to_string()],
        parse_failed: false,
    };

    let lines = composer_debug_lines(&lookup, &prepared, true);

    assert_eq!(
        lines,
        vec![
            "checked project:team/platform/app -> not found".to_string(),
            "checked group:team/platform -> found".to_string(),
            "COMPOSER_AUTH detected from group team/platform".to_string(),
            "composer_auto_repositories: enabled".to_string(),
            "supported COMPOSER_AUTH sections: http-basic".to_string(),
            "derived Composer repository hosts: repo.example.com".to_string(),
            "ignored COMPOSER_AUTH repository entries: 1".to_string(),
            "temporary COMPOSER_HOME config: written".to_string(),
            "COMPOSER_AUTH exported to composer: yes".to_string(),
        ]
    );
}

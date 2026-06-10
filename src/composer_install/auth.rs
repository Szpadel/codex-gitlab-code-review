use super::COMPOSER_AUTH_VARIABLE_KEY;
use crate::gitlab::{GitLabApi, GitLabCiVariable};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use url::{Host, Url};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerAuthLookup {
    pub value: Option<String>,
    pub source: Option<String>,
    pub attempts: Vec<ComposerAuthLookupAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComposerAuthLookupAttempt {
    pub scope: String,
    pub found: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedComposerAuth {
    pub env_value: Option<String>,
    pub repository_config_json: Option<String>,
    pub supported_sections: Vec<String>,
    pub repository_urls: Vec<String>,
    pub ignored_repository_entries: Vec<String>,
    pub parse_failed: bool,
}

#[derive(Default)]
struct ComposerAuthAnalysis {
    supported_sections: Vec<String>,
    repository_urls: Vec<String>,
    ignored_repository_entries: Vec<String>,
    parse_failed: bool,
}

pub async fn resolve_composer_auth(gitlab: &dyn GitLabApi, repo_path: &str) -> ComposerAuthLookup {
    if repo_path.trim().is_empty() {
        return ComposerAuthLookup {
            value: None,
            source: None,
            attempts: Vec::new(),
        };
    }

    let mut attempts = Vec::new();
    if let Some(variable) = resolve_project_variable(gitlab, repo_path).await {
        attempts.push(ComposerAuthLookupAttempt {
            scope: format!("project:{repo_path}"),
            found: true,
        });
        return ComposerAuthLookup {
            value: Some(variable.value),
            source: Some(format!("project:{repo_path}")),
            attempts,
        };
    }
    attempts.push(ComposerAuthLookupAttempt {
        scope: format!("project:{repo_path}"),
        found: false,
    });

    for group in repo_parent_groups(repo_path) {
        if let Some(variable) = resolve_group_variable(gitlab, &group).await {
            attempts.push(ComposerAuthLookupAttempt {
                scope: format!("group:{group}"),
                found: true,
            });
            return ComposerAuthLookup {
                value: Some(variable.value),
                source: Some(format!("group:{group}")),
                attempts,
            };
        }
        attempts.push(ComposerAuthLookupAttempt {
            scope: format!("group:{group}"),
            found: false,
        });
    }

    ComposerAuthLookup {
        value: None,
        source: None,
        attempts,
    }
}

pub fn prepare_composer_auth(
    composer_auth: Option<&str>,
    auto_repositories_enabled: bool,
) -> PreparedComposerAuth {
    let env_value = composer_auth.map(ToOwned::to_owned);
    let analysis = analyze_composer_auth(composer_auth);
    let repository_config_json =
        (auto_repositories_enabled && !analysis.repository_urls.is_empty()).then(|| {
            json!({
                "repositories": analysis
                    .repository_urls
                    .iter()
                    .map(|url| json!({
                        "type": "composer",
                        "url": url,
                    }))
                    .collect::<Vec<_>>()
            })
            .to_string()
        });
    PreparedComposerAuth {
        env_value,
        repository_config_json,
        supported_sections: analysis.supported_sections,
        repository_urls: analysis.repository_urls,
        ignored_repository_entries: analysis.ignored_repository_entries,
        parse_failed: analysis.parse_failed,
    }
}

fn analyze_composer_auth(composer_auth: Option<&str>) -> ComposerAuthAnalysis {
    let Some(composer_auth) = composer_auth else {
        return ComposerAuthAnalysis::default();
    };
    let Ok(parsed) = serde_json::from_str::<Value>(composer_auth) else {
        return ComposerAuthAnalysis {
            parse_failed: true,
            ..ComposerAuthAnalysis::default()
        };
    };
    supported_repository_urls(&parsed)
}

fn supported_repository_urls(value: &Value) -> ComposerAuthAnalysis {
    let mut supported_sections = BTreeSet::new();
    let mut repository_urls = BTreeSet::new();
    let mut ignored_entries = BTreeSet::new();
    let Some(map) = value.as_object() else {
        return ComposerAuthAnalysis::default();
    };
    for section in ["http-basic", "bearer", "custom-headers"] {
        let Some(section_value) = map.get(section) else {
            continue;
        };
        let Some(section_map) = section_value.as_object() else {
            continue;
        };
        supported_sections.insert(section.to_string());
        for raw_host in section_map.keys() {
            if let Some(url) = normalized_composer_repository_url(raw_host) {
                repository_urls.insert(url);
            } else {
                ignored_entries.insert(raw_host.clone());
            }
        }
    }
    ComposerAuthAnalysis {
        supported_sections: supported_sections.into_iter().collect(),
        repository_urls: repository_urls.into_iter().collect(),
        ignored_repository_entries: ignored_entries.into_iter().collect(),
        parse_failed: false,
    }
}

fn normalized_composer_repository_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.contains("://") {
        let parsed = Url::parse(raw).ok()?;
        return normalized_repository_url_from_parsed(&parsed, Some(parsed.scheme()), true);
    }
    let parsed = Url::parse(&format!("https://{raw}")).ok()?;
    normalized_repository_url_from_parsed(&parsed, Some("https"), false)
}

fn normalized_repository_url_from_parsed(
    parsed: &Url,
    forced_scheme: Option<&str>,
    allow_path: bool,
) -> Option<String> {
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    if !allow_path && parsed.path() != "/" {
        return None;
    }
    let scheme = forced_scheme.unwrap_or(parsed.scheme());
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let host = match parsed.host()? {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(ip) => ip.to_string(),
        Host::Ipv6(ip) => format!("[{ip}]"),
    };
    let host_port = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    };
    let path = match parsed.path() {
        "/" => "",
        other => other,
    };
    Some(format!("{scheme}://{host_port}{path}"))
}

pub(super) fn composer_auth_notice(auth_source: Option<&str>) -> Option<String> {
    let auth_source = auth_source?;
    if let Some(repo_path) = auth_source.strip_prefix("project:") {
        return Some(format!(
            "COMPOSER_AUTH detected from repository {repo_path}"
        ));
    }
    if let Some(group_path) = auth_source.strip_prefix("group:") {
        return Some(format!("COMPOSER_AUTH detected from group {group_path}"));
    }
    Some(format!("COMPOSER_AUTH detected from {auth_source}"))
}

#[must_use]
pub fn composer_debug_lines(
    auth_lookup: &ComposerAuthLookup,
    prepared_auth: &PreparedComposerAuth,
    auto_repositories_enabled: bool,
) -> Vec<String> {
    let mut lines = auth_lookup
        .attempts
        .iter()
        .map(|attempt| {
            format!(
                "checked {} -> {}",
                attempt.scope,
                if attempt.found { "found" } else { "not found" }
            )
        })
        .collect::<Vec<_>>();

    if let Some(notice) = composer_auth_notice(auth_lookup.source.as_deref()) {
        lines.push(notice);
    } else {
        lines.push("COMPOSER_AUTH detected: none".to_string());
    }

    lines.push(format!(
        "composer_auto_repositories: {}",
        if auto_repositories_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));

    if prepared_auth.parse_failed {
        lines.push("COMPOSER_AUTH JSON parse: failed".to_string());
    } else {
        lines.push(format!(
            "supported COMPOSER_AUTH sections: {}",
            if prepared_auth.supported_sections.is_empty() {
                "none".to_string()
            } else {
                prepared_auth.supported_sections.join(", ")
            }
        ));
    }

    lines.push(format!(
        "derived Composer repository hosts: {}",
        if prepared_auth.repository_urls.is_empty() {
            "none".to_string()
        } else {
            repository_debug_labels(&prepared_auth.repository_urls).join(", ")
        }
    ));

    if !prepared_auth.ignored_repository_entries.is_empty() {
        lines.push(format!(
            "ignored COMPOSER_AUTH repository entries: {}",
            prepared_auth.ignored_repository_entries.len()
        ));
    }

    lines.push(format!(
        "temporary COMPOSER_HOME config: {}",
        if prepared_auth.repository_config_json.is_some() {
            "written"
        } else {
            "skipped"
        }
    ));
    lines.push(format!(
        "COMPOSER_AUTH exported to composer: {}",
        if prepared_auth.env_value.is_some() {
            "yes"
        } else {
            "no"
        }
    ));

    lines
}

fn repository_debug_labels(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| {
            let parsed = Url::parse(url).ok()?;
            let host = parsed.host_str()?;
            Some(match parsed.port() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(super) fn collect_string_leaves(value: &Value, output: &mut Vec<String>) {
    match value {
        Value::String(string) => output.push(string.clone()),
        Value::Array(items) => {
            for item in items {
                collect_string_leaves(item, output);
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                collect_string_leaves(value, output);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

async fn resolve_project_variable(
    gitlab: &dyn GitLabApi,
    repo_path: &str,
) -> Option<GitLabCiVariable> {
    match gitlab
        .get_project_variable(repo_path, COMPOSER_AUTH_VARIABLE_KEY)
        .await
    {
        Ok(variable) => Some(variable),
        Err(_) => select_global_scope_variable(
            gitlab
                .list_project_variables(repo_path)
                .await
                .unwrap_or_default(),
        ),
    }
}

async fn resolve_group_variable(gitlab: &dyn GitLabApi, group: &str) -> Option<GitLabCiVariable> {
    match gitlab
        .get_group_variable(group, COMPOSER_AUTH_VARIABLE_KEY)
        .await
    {
        Ok(variable) => Some(variable),
        Err(_) => select_global_scope_variable(
            gitlab.list_group_variables(group).await.unwrap_or_default(),
        ),
    }
}

fn select_global_scope_variable(
    variables: impl IntoIterator<Item = GitLabCiVariable>,
) -> Option<GitLabCiVariable> {
    variables.into_iter().find(|variable| {
        variable.key == COMPOSER_AUTH_VARIABLE_KEY && variable.environment_scope == "*"
    })
}

fn repo_parent_groups(repo_path: &str) -> Vec<String> {
    let mut parts = repo_path
        .split('/')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 2 {
        return Vec::new();
    }
    parts.pop();
    let mut groups = Vec::new();
    for depth in (1..=parts.len()).rev() {
        groups.push(parts[..depth].join("/"));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_parent_groups_prefers_closest_group_first() {
        assert_eq!(
            repo_parent_groups("group/subgroup/project"),
            vec!["group/subgroup".to_string(), "group".to_string()]
        );
    }
}

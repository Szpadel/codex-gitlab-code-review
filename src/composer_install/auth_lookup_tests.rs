use super::{COMPOSER_AUTH_VARIABLE_KEY, ComposerAuthLookupAttempt, resolve_composer_auth};
use crate::gitlab::{GitLabApi, GitLabCiVariable};
use anyhow::Result;
use async_trait::async_trait;
use std::collections::BTreeMap;

#[derive(Default)]
struct FakeVariableGitLab {
    project_variables: BTreeMap<String, GitLabCiVariable>,
    group_variables: BTreeMap<String, GitLabCiVariable>,
}

#[async_trait]
impl GitLabApi for FakeVariableGitLab {
    async fn current_user(&self) -> Result<crate::gitlab::GitLabUser> {
        unimplemented!()
    }

    async fn list_projects(&self) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        unimplemented!()
    }

    async fn list_group_projects(
        &self,
        _group: &str,
    ) -> Result<Vec<crate::gitlab::GitLabProjectSummary>> {
        unimplemented!()
    }

    async fn list_open_mrs(&self, _project: &str) -> Result<Vec<crate::gitlab::MergeRequest>> {
        unimplemented!()
    }

    async fn get_latest_open_mr_activity(
        &self,
        _project: &str,
    ) -> Result<Option<crate::gitlab::MergeRequest>> {
        unimplemented!()
    }

    async fn get_mr(&self, _project: &str, _iid: u64) -> Result<crate::gitlab::MergeRequest> {
        unimplemented!()
    }

    async fn get_project(&self, _project: &str) -> Result<crate::gitlab::GitLabProject> {
        unimplemented!()
    }

    async fn get_group(&self, _group: &str) -> Result<crate::gitlab::GitLabGroup> {
        unimplemented!()
    }

    async fn list_awards(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<crate::gitlab::AwardEmoji>> {
        unimplemented!()
    }

    async fn add_award(&self, _project: &str, _iid: u64, _name: &str) -> Result<()> {
        unimplemented!()
    }

    async fn delete_award(&self, _project: &str, _iid: u64, _award_id: u64) -> Result<()> {
        unimplemented!()
    }

    async fn list_notes(&self, _project: &str, _iid: u64) -> Result<Vec<crate::gitlab::Note>> {
        unimplemented!()
    }

    async fn list_discussions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<crate::gitlab::MergeRequestDiscussion>> {
        unimplemented!()
    }

    async fn create_note(&self, _project: &str, _iid: u64, _body: &str) -> Result<()> {
        unimplemented!()
    }

    async fn get_project_variable(&self, project: &str, key: &str) -> Result<GitLabCiVariable> {
        self.project_variables
            .get(&format!("{project}:{key}"))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not found"))
    }

    async fn list_project_variables(&self, project: &str) -> Result<Vec<GitLabCiVariable>> {
        Ok(self
            .project_variables
            .iter()
            .filter_map(|(composite_key, variable)| {
                composite_key
                    .strip_suffix(&format!(":{COMPOSER_AUTH_VARIABLE_KEY}"))
                    .filter(|candidate| *candidate == project)
                    .map(|_| variable.clone())
            })
            .collect())
    }

    async fn get_group_variable(&self, group: &str, key: &str) -> Result<GitLabCiVariable> {
        self.group_variables
            .get(&format!("{group}:{key}"))
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("not found"))
    }

    async fn list_group_variables(&self, group: &str) -> Result<Vec<GitLabCiVariable>> {
        Ok(self
            .group_variables
            .iter()
            .filter_map(|(composite_key, variable)| {
                composite_key
                    .strip_suffix(&format!(":{COMPOSER_AUTH_VARIABLE_KEY}"))
                    .filter(|candidate| *candidate == group)
                    .map(|_| variable.clone())
            })
            .collect())
    }
}

#[tokio::test]
async fn resolve_composer_auth_prefers_project_variable_and_records_attempts() {
    let mut gitlab = FakeVariableGitLab::default();
    gitlab.project_variables.insert(
        "group/sub/repo:COMPOSER_AUTH".to_string(),
        GitLabCiVariable {
            key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
            value: r#"{"http-basic":{"repo.example.com":{"password":"s3cr3t"}}}"#.to_string(),
            environment_scope: "*".to_string(),
        },
    );

    let lookup = resolve_composer_auth(&gitlab, "group/sub/repo").await;

    assert_eq!(lookup.source.as_deref(), Some("project:group/sub/repo"));
    assert_eq!(
        lookup.attempts,
        vec![ComposerAuthLookupAttempt {
            scope: "project:group/sub/repo".to_string(),
            found: true,
        }]
    );
}

#[tokio::test]
async fn resolve_composer_auth_falls_back_to_nearest_parent_group_and_records_attempts() {
    let mut gitlab = FakeVariableGitLab::default();
    gitlab.group_variables.insert(
        "group/sub:COMPOSER_AUTH".to_string(),
        GitLabCiVariable {
            key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
            value: r#"{"bearer":{"cache.example.com":"token"}}"#.to_string(),
            environment_scope: "*".to_string(),
        },
    );
    gitlab.group_variables.insert(
        "group:COMPOSER_AUTH".to_string(),
        GitLabCiVariable {
            key: COMPOSER_AUTH_VARIABLE_KEY.to_string(),
            value: r#"{"http-basic":{"repo.example.com":{"password":"s3cr3t"}}}"#.to_string(),
            environment_scope: "*".to_string(),
        },
    );

    let lookup = resolve_composer_auth(&gitlab, "group/sub/repo").await;

    assert_eq!(lookup.source.as_deref(), Some("group:group/sub"));
    assert_eq!(
        lookup.attempts,
        vec![
            ComposerAuthLookupAttempt {
                scope: "project:group/sub/repo".to_string(),
                found: false,
            },
            ComposerAuthLookupAttempt {
                scope: "group:group/sub".to_string(),
                found: true,
            },
        ]
    );
}

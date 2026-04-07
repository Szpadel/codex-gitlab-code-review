use super::client::GitLabClient;
use super::types::{
    GitLabCiVariable, GitLabGroup, GitLabGroupSummary, GitLabProject, GitLabProjectSummary,
    GitLabRepositoryRef,
};
use anyhow::Result;
use url::Url;

impl GitLabClient {
    pub(crate) async fn list_projects_endpoint(&self) -> Result<Vec<GitLabProjectSummary>> {
        let url = format!("{}/projects?simple=true", self.api_base());
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    pub(crate) async fn list_group_projects_endpoint(
        &self,
        group: &str,
    ) -> Result<Vec<GitLabProjectSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/projects?include_subgroups=true&simple=true",
            self.api_base(),
            encoded
        );
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    pub(crate) async fn list_direct_group_projects_endpoint(
        &self,
        group: &str,
    ) -> Result<Vec<GitLabProjectSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/projects?include_subgroups=false&simple=true",
            self.api_base(),
            encoded
        );
        Ok(self
            .get_paginated::<GitLabProjectSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabProjectSummary::is_active)
            .collect())
    }

    pub(crate) async fn list_group_subgroups_endpoint(
        &self,
        group: &str,
    ) -> Result<Vec<GitLabGroupSummary>> {
        let encoded = urlencoding::encode(group);
        let url = format!(
            "{}/groups/{}/subgroups?simple=true",
            self.api_base(),
            encoded
        );
        Ok(self
            .get_paginated::<GitLabGroupSummary>(&url)
            .await?
            .into_iter()
            .filter(GitLabGroupSummary::is_active)
            .collect())
    }

    pub(crate) async fn get_project_endpoint(&self, project: &str) -> Result<GitLabProject> {
        let url = self.project_path(project);
        self.get_json(&url).await
    }

    pub(crate) async fn list_repository_branches_endpoint(
        &self,
        project: &str,
    ) -> Result<Vec<String>> {
        self.list_repository_refs_endpoint(project, "branches")
            .await
    }

    pub(crate) async fn list_repository_tags_endpoint(&self, project: &str) -> Result<Vec<String>> {
        self.list_repository_refs_endpoint(project, "tags").await
    }

    pub(crate) async fn get_group_endpoint(&self, group: &str) -> Result<GitLabGroup> {
        let url = self.group_path(group);
        self.get_json(&url).await
    }

    pub(crate) async fn list_project_variables_endpoint(
        &self,
        project: &str,
    ) -> Result<Vec<GitLabCiVariable>> {
        let url = format!("{}/variables", self.project_path(project));
        self.get_paginated(&url).await
    }

    pub(crate) async fn get_project_variable_endpoint(
        &self,
        project: &str,
        key: &str,
    ) -> Result<GitLabCiVariable> {
        let encoded_key = urlencoding::encode(key);
        let mut url = Url::parse(&format!(
            "{}/variables/{}",
            self.project_path(project),
            encoded_key
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("filter[environment_scope]", "*");
        }
        self.get_json(url.as_str()).await
    }

    pub(crate) async fn list_group_variables_endpoint(
        &self,
        group: &str,
    ) -> Result<Vec<GitLabCiVariable>> {
        let url = format!("{}/variables", self.group_path(group));
        self.get_paginated(&url).await
    }

    pub(crate) async fn get_group_variable_endpoint(
        &self,
        group: &str,
        key: &str,
    ) -> Result<GitLabCiVariable> {
        let encoded_key = urlencoding::encode(key);
        let mut url = Url::parse(&format!(
            "{}/variables/{}",
            self.group_path(group),
            encoded_key
        ))?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair("filter[environment_scope]", "*");
        }
        self.get_json(url.as_str()).await
    }

    async fn list_repository_refs_endpoint(
        &self,
        project: &str,
        ref_kind: &str,
    ) -> Result<Vec<String>> {
        let url = format!("{}/repository/{}", self.project_path(project), ref_kind);
        let refs = self.get_paginated::<GitLabRepositoryRef>(&url).await?;
        Ok(sorted_unique(refs.into_iter().map(|item| item.name)))
    }
}

fn sorted_unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

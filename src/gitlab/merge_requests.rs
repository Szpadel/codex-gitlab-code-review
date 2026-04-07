use super::client::GitLabClient;
use super::types::{MergeRequest, MergeRequestDiff, MergeRequestDiffVersion};
use anyhow::Result;

impl GitLabClient {
    pub(crate) async fn list_open_mrs_endpoint(&self, project: &str) -> Result<Vec<MergeRequest>> {
        let url = format!(
            "{}/merge_requests?state=opened&scope=all",
            self.project_path(project)
        );
        self.get_paginated(&url).await
    }

    pub(crate) async fn get_latest_open_mr_activity_endpoint(
        &self,
        project: &str,
    ) -> Result<Option<MergeRequest>> {
        let url = format!(
            "{}/merge_requests?state=opened&scope=all&order_by=updated_at&sort=desc&per_page=1",
            self.project_path(project)
        );
        let mut mrs: Vec<MergeRequest> = self.get_json(&url).await?;
        Ok(mrs.pop())
    }

    pub(crate) async fn get_mr_endpoint(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        let url = format!("{}/merge_requests/{}", self.project_path(project), iid);
        self.get_json(&url).await
    }

    pub(crate) async fn list_mr_diff_versions_endpoint(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        let url = format!(
            "{}/merge_requests/{}/versions",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    pub(crate) async fn list_mr_diffs_endpoint(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiff>> {
        let url = format!(
            "{}/merge_requests/{}/diffs",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }
}

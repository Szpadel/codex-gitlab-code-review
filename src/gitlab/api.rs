use super::client::GitLabClient;
use super::types::{
    AwardEmoji, GitLabCiVariable, GitLabGroup, GitLabGroupSummary, GitLabProject,
    GitLabProjectSummary, GitLabUser, GitLabUserDetail, MergeRequest, MergeRequestDiff,
    MergeRequestDiffDiscussion, MergeRequestDiffVersion, MergeRequestDiscussion, Note,
};
use anyhow::{Result, anyhow};
use async_trait::async_trait;

#[async_trait]
pub trait GitLabApi: Send + Sync {
    async fn current_user(&self) -> Result<GitLabUser>;
    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>>;
    async fn list_direct_group_projects(&self, _group: &str) -> Result<Vec<GitLabProjectSummary>> {
        Ok(Vec::new())
    }
    async fn list_group_subgroups(&self, _group: &str) -> Result<Vec<GitLabGroupSummary>> {
        Ok(Vec::new())
    }
    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>>;
    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>>;
    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest>;
    async fn list_mr_diff_versions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        Ok(Vec::new())
    }
    async fn list_mr_diffs(&self, _project: &str, _iid: u64) -> Result<Vec<MergeRequestDiff>> {
        Ok(Vec::new())
    }
    async fn get_project(&self, project: &str) -> Result<GitLabProject>;
    async fn list_repository_branches(&self, _project: &str) -> Result<Vec<String>> {
        Err(anyhow!(
            "list_repository_branches not implemented for this gitlab client"
        ))
    }
    async fn list_repository_tags(&self, _project: &str) -> Result<Vec<String>> {
        Err(anyhow!(
            "list_repository_tags not implemented for this gitlab client"
        ))
    }
    async fn get_group(&self, group: &str) -> Result<GitLabGroup> {
        Err(anyhow!(
            "get_group not implemented for this gitlab client (group={group})"
        ))
    }
    async fn list_project_variables(&self, _project: &str) -> Result<Vec<GitLabCiVariable>> {
        Err(anyhow!(
            "list_project_variables not implemented for this gitlab client"
        ))
    }
    async fn get_project_variable(&self, _project: &str, _key: &str) -> Result<GitLabCiVariable> {
        Err(anyhow!(
            "get_project_variable not implemented for this gitlab client"
        ))
    }
    async fn list_group_variables(&self, _group: &str) -> Result<Vec<GitLabCiVariable>> {
        Err(anyhow!(
            "list_group_variables not implemented for this gitlab client"
        ))
    }
    async fn get_group_variable(&self, _group: &str, _key: &str) -> Result<GitLabCiVariable> {
        Err(anyhow!(
            "get_group_variable not implemented for this gitlab client"
        ))
    }
    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>>;
    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()>;
    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()>;
    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>>;
    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()>;
    async fn create_diff_discussion(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        self.create_note(project, iid, &request.body).await
    }
    async fn list_discussions(
        &self,
        _project: &str,
        _iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        Ok(Vec::new())
    }
    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        _discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        self.create_note(project, iid, body).await
    }
    async fn list_discussion_note_awards(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        Ok(Vec::new())
    }
    async fn add_discussion_note_award(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
        _name: &str,
    ) -> Result<()> {
        Ok(())
    }
    async fn delete_discussion_note_award(
        &self,
        _project: &str,
        _iid: u64,
        _discussion_id: &str,
        _note_id: u64,
        _award_id: u64,
    ) -> Result<()> {
        Ok(())
    }
    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        Err(anyhow!(
            "get_user not implemented for this gitlab client (user_id={user_id})"
        ))
    }
    async fn download_project_upload(
        &self,
        _project: &str,
        _secret: &str,
        _filename: &str,
    ) -> Result<Vec<u8>> {
        Err(anyhow!(
            "download_project_upload not implemented for this gitlab client"
        ))
    }
}

#[async_trait]
impl GitLabApi for GitLabClient {
    async fn current_user(&self) -> Result<GitLabUser> {
        self.current_user_endpoint().await
    }

    async fn list_projects(&self) -> Result<Vec<GitLabProjectSummary>> {
        self.list_projects_endpoint().await
    }

    async fn list_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        self.list_group_projects_endpoint(group).await
    }

    async fn list_direct_group_projects(&self, group: &str) -> Result<Vec<GitLabProjectSummary>> {
        self.list_direct_group_projects_endpoint(group).await
    }

    async fn list_group_subgroups(&self, group: &str) -> Result<Vec<GitLabGroupSummary>> {
        self.list_group_subgroups_endpoint(group).await
    }

    async fn list_open_mrs(&self, project: &str) -> Result<Vec<MergeRequest>> {
        self.list_open_mrs_endpoint(project).await
    }

    async fn get_latest_open_mr_activity(&self, project: &str) -> Result<Option<MergeRequest>> {
        self.get_latest_open_mr_activity_endpoint(project).await
    }

    async fn get_mr(&self, project: &str, iid: u64) -> Result<MergeRequest> {
        self.get_mr_endpoint(project, iid).await
    }

    async fn list_mr_diff_versions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiffVersion>> {
        self.list_mr_diff_versions_endpoint(project, iid).await
    }

    async fn list_mr_diffs(&self, project: &str, iid: u64) -> Result<Vec<MergeRequestDiff>> {
        self.list_mr_diffs_endpoint(project, iid).await
    }

    async fn get_project(&self, project: &str) -> Result<GitLabProject> {
        self.get_project_endpoint(project).await
    }

    async fn list_repository_branches(&self, project: &str) -> Result<Vec<String>> {
        self.list_repository_branches_endpoint(project).await
    }

    async fn list_repository_tags(&self, project: &str) -> Result<Vec<String>> {
        self.list_repository_tags_endpoint(project).await
    }

    async fn get_group(&self, group: &str) -> Result<GitLabGroup> {
        self.get_group_endpoint(group).await
    }

    async fn list_project_variables(&self, project: &str) -> Result<Vec<GitLabCiVariable>> {
        self.list_project_variables_endpoint(project).await
    }

    async fn get_project_variable(&self, project: &str, key: &str) -> Result<GitLabCiVariable> {
        self.get_project_variable_endpoint(project, key).await
    }

    async fn list_group_variables(&self, group: &str) -> Result<Vec<GitLabCiVariable>> {
        self.list_group_variables_endpoint(group).await
    }

    async fn get_group_variable(&self, group: &str, key: &str) -> Result<GitLabCiVariable> {
        self.get_group_variable_endpoint(group, key).await
    }

    async fn list_awards(&self, project: &str, iid: u64) -> Result<Vec<AwardEmoji>> {
        self.list_awards_endpoint(project, iid).await
    }

    async fn add_award(&self, project: &str, iid: u64, name: &str) -> Result<()> {
        self.add_award_endpoint(project, iid, name).await
    }

    async fn delete_award(&self, project: &str, iid: u64, award_id: u64) -> Result<()> {
        self.delete_award_endpoint(project, iid, award_id).await
    }

    async fn list_notes(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        self.list_notes_endpoint(project, iid).await
    }

    async fn create_note(&self, project: &str, iid: u64, body: &str) -> Result<()> {
        self.create_note_endpoint(project, iid, body).await
    }

    async fn create_diff_discussion(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        self.create_diff_discussion_endpoint(project, iid, request)
            .await
    }

    async fn list_discussions(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        self.list_discussions_endpoint(project, iid).await
    }

    async fn create_discussion_note(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        self.create_discussion_note_endpoint(project, iid, discussion_id, body)
            .await
    }

    async fn list_discussion_note_awards(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        self.list_discussion_note_awards_endpoint(project, iid, discussion_id, note_id)
            .await
    }

    async fn add_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        self.add_discussion_note_award_endpoint(project, iid, discussion_id, note_id, name)
            .await
    }

    async fn delete_discussion_note_award(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        self.delete_discussion_note_award_endpoint(project, iid, discussion_id, note_id, award_id)
            .await
    }

    async fn get_user(&self, user_id: u64) -> Result<GitLabUserDetail> {
        self.get_user_endpoint(user_id).await
    }

    async fn download_project_upload(
        &self,
        project: &str,
        secret: &str,
        filename: &str,
    ) -> Result<Vec<u8>> {
        self.download_project_upload_endpoint(project, secret, filename)
            .await
    }
}

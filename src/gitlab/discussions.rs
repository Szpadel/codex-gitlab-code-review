use super::client::GitLabClient;
use super::transport::gitlab_error_has_status;
use super::types::{
    AwardEmoji, DiffDiscussionLineEndpoint, MergeRequestDiffDiscussion, MergeRequestDiscussion,
    Note,
};
use anyhow::{Context, Result};

impl GitLabClient {
    pub(crate) async fn list_awards_endpoint(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<AwardEmoji>> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    pub(crate) async fn add_award_endpoint(
        &self,
        project: &str,
        iid: u64,
        name: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji?name={}",
            self.project_path(project),
            iid,
            name
        );
        self.post_empty(&url).await
    }

    pub(crate) async fn delete_award_endpoint(
        &self,
        project: &str,
        iid: u64,
        award_id: u64,
    ) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/award_emoji/{}",
            self.project_path(project),
            iid,
            award_id
        );
        self.delete_empty(&url).await
    }

    pub(crate) async fn list_notes_endpoint(&self, project: &str, iid: u64) -> Result<Vec<Note>> {
        let url = format!(
            "{}/merge_requests/{}/notes",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    pub(crate) async fn create_note_endpoint(
        &self,
        project: &str,
        iid: u64,
        body: &str,
    ) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/notes",
            self.project_path(project),
            iid
        );
        self.post_note(&url, body).await
    }

    pub(crate) async fn create_diff_discussion_endpoint(
        &self,
        project: &str,
        iid: u64,
        request: &MergeRequestDiffDiscussion,
    ) -> Result<()> {
        let url = format!(
            "{}/merge_requests/{}/discussions",
            self.project_path(project),
            iid
        );
        let mut form = vec![
            ("body".to_string(), request.body.clone()),
            ("position[position_type]".to_string(), "text".to_string()),
            (
                "position[base_sha]".to_string(),
                request.position.base_sha.clone(),
            ),
            (
                "position[head_sha]".to_string(),
                request.position.head_sha.clone(),
            ),
            (
                "position[start_sha]".to_string(),
                request.position.start_sha.clone(),
            ),
            (
                "position[old_path]".to_string(),
                request.position.old_path.clone(),
            ),
            (
                "position[new_path]".to_string(),
                request.position.new_path.clone(),
            ),
        ];
        if let Some(old_line) = request.position.old_line {
            form.push(("position[old_line]".to_string(), old_line.to_string()));
        }
        if let Some(new_line) = request.position.new_line {
            form.push(("position[new_line]".to_string(), new_line.to_string()));
        }
        if let Some(line_range) = &request.position.line_range {
            append_line_range_form_fields(&mut form, "start", &line_range.start);
            append_line_range_form_fields(&mut form, "end", &line_range.end);
        }
        self.post_form(&url, &form).await
    }

    pub(crate) async fn list_discussions_endpoint(
        &self,
        project: &str,
        iid: u64,
    ) -> Result<Vec<MergeRequestDiscussion>> {
        let url = format!(
            "{}/merge_requests/{}/discussions",
            self.project_path(project),
            iid
        );
        self.get_paginated(&url).await
    }

    pub(crate) async fn create_discussion_note_endpoint(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        body: &str,
    ) -> Result<()> {
        let encoded_discussion_id = urlencoding::encode(discussion_id);
        let url = format!(
            "{}/merge_requests/{}/discussions/{}/notes",
            self.project_path(project),
            iid,
            encoded_discussion_id
        );
        self.post_note(&url, body).await
    }

    pub(crate) async fn list_discussion_note_awards_endpoint(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
    ) -> Result<Vec<AwardEmoji>> {
        let discussion_url =
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id);
        match self.get_paginated(&discussion_url).await {
            Ok(awards) => Ok(awards),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = self.merge_request_note_award_base_url(project, iid, note_id);
                self.get_paginated(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }

    pub(crate) async fn add_discussion_note_award_endpoint(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        name: &str,
    ) -> Result<()> {
        let discussion_url = format!(
            "{}?name={}",
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id),
            name
        );
        match self.post_empty(&discussion_url).await {
            Ok(()) => Ok(()),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = format!(
                    "{}?name={}",
                    self.merge_request_note_award_base_url(project, iid, note_id),
                    name
                );
                self.post_empty(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }

    pub(crate) async fn delete_discussion_note_award_endpoint(
        &self,
        project: &str,
        iid: u64,
        discussion_id: &str,
        note_id: u64,
        award_id: u64,
    ) -> Result<()> {
        let discussion_url = format!(
            "{}/{}",
            self.discussion_note_award_base_url(project, iid, discussion_id, note_id),
            award_id
        );
        match self.delete_empty(&discussion_url).await {
            Ok(()) => Ok(()),
            Err(discussion_err) => {
                if !should_fallback_to_merge_request_note_awards(&discussion_err) {
                    return Err(discussion_err);
                }
                let note_url = format!(
                    "{}/{}",
                    self.merge_request_note_award_base_url(project, iid, note_id),
                    award_id
                );
                self.delete_empty(&note_url).await.with_context(|| {
                    format!(
                        "fallback to merge-request-note award endpoint after discussion-note award endpoint error: {discussion_err:#}"
                    )
                })
            }
        }
    }
}

fn append_line_range_form_fields(
    form: &mut Vec<(String, String)>,
    endpoint_name: &str,
    endpoint: &DiffDiscussionLineEndpoint,
) {
    let prefix = format!("position[line_range][{endpoint_name}]");
    form.push((format!("{prefix}[line_code]"), endpoint.line_code.clone()));
    form.push((
        format!("{prefix}[type]"),
        endpoint.line_type.as_str().to_string(),
    ));
    if let Some(old_line) = endpoint.old_line {
        form.push((format!("{prefix}[old_line]"), old_line.to_string()));
    }
    if let Some(new_line) = endpoint.new_line {
        form.push((format!("{prefix}[new_line]"), new_line.to_string()));
    }
}

fn should_fallback_to_merge_request_note_awards(err: &anyhow::Error) -> bool {
    gitlab_error_has_status(err, &[404, 405, 400, 422])
}

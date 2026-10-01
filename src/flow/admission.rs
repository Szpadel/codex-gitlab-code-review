//! Remote history shared by all flows during one merge-request admission.

use crate::gitlab::{GitLabApi, MergeRequestDiscussion, Note};
use anyhow::{Result, anyhow};
use tokio::sync::OnceCell;

/// Loads each history list at most once, including failures. Publication reads
/// must use the GitLab API directly to observe comments added after admission.
pub(crate) struct AdmissionHistory<'a> {
    gitlab: &'a dyn GitLabApi,
    repo: &'a str,
    iid: u64,
    notes: OnceCell<Result<Vec<Note>, String>>,
    discussions: OnceCell<Result<Vec<MergeRequestDiscussion>, String>>,
}

impl<'a> AdmissionHistory<'a> {
    pub(crate) fn new(gitlab: &'a dyn GitLabApi, repo: &'a str, iid: u64) -> Self {
        Self {
            gitlab,
            repo,
            iid,
            notes: OnceCell::new(),
            discussions: OnceCell::new(),
        }
    }

    /// Returns the admission snapshot or the first read failure.
    pub(crate) async fn notes(&self) -> Result<&[Note]> {
        self.notes
            .get_or_init(|| async {
                self.gitlab
                    .list_notes(self.repo, self.iid)
                    .await
                    .map_err(|err| format!("{err:#}"))
            })
            .await
            .as_deref()
            .map_err(|err| anyhow!(err.clone()))
    }

    /// Returns the admission snapshot or the first read failure.
    pub(crate) async fn discussions(&self) -> Result<&[MergeRequestDiscussion]> {
        self.discussions
            .get_or_init(|| async {
                self.gitlab
                    .list_discussions(self.repo, self.iid)
                    .await
                    .map_err(|err| format!("{err:#}"))
            })
            .await
            .as_deref()
            .map_err(|err| anyhow!(err.clone()))
    }
}

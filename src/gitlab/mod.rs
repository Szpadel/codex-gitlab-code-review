mod api;
mod client;
mod discussions;
mod merge_requests;
mod pagination;
mod projects;
mod transport;
mod types;
mod uploads;
mod users;

pub use api::GitLabApi;
pub use client::GitLabClient;
pub use types::{
    AwardEmoji, DiffDiscussionLineEndpoint, DiffDiscussionLineRange, DiffDiscussionLineType,
    DiffDiscussionPosition, DiffRefs, DiscussionNote, GitLabCiVariable, GitLabGroup,
    GitLabGroupSummary, GitLabProject, GitLabProjectSummary, GitLabUser, GitLabUserDetail,
    MergeRequest, MergeRequestDiff, MergeRequestDiffDiscussion, MergeRequestDiffVersion,
    MergeRequestDiscussion, Note,
};

#[cfg(test)]
pub(crate) use client::normalize_api_base;
pub(crate) use transport::gitlab_error_has_status;

#[cfg(test)]
mod tests;

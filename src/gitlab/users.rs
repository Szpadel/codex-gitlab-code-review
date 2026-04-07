use super::client::GitLabClient;
use super::types::{GitLabUser, GitLabUserDetail};
use anyhow::Result;

impl GitLabClient {
    pub(crate) async fn current_user_endpoint(&self) -> Result<GitLabUser> {
        let url = format!("{}/user", self.api_base());
        self.get_json(&url).await
    }

    pub(crate) async fn get_user_endpoint(&self, user_id: u64) -> Result<GitLabUserDetail> {
        let url = format!("{}/users/{}", self.api_base(), user_id);
        self.get_json(&url).await
    }
}

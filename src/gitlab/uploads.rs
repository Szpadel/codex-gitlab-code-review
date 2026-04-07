use super::client::GitLabClient;
use anyhow::Result;

impl GitLabClient {
    pub(crate) async fn download_project_upload_endpoint(
        &self,
        project: &str,
        secret: &str,
        filename: &str,
    ) -> Result<Vec<u8>> {
        let url = format!(
            "{}/uploads/{}/{}",
            self.project_path(project),
            urlencoding::encode(secret),
            urlencoding::encode(filename)
        );
        self.get_bytes(&url).await
    }
}

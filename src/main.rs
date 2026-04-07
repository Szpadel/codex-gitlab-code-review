use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    codex_gitlab_code_review::cli::run().await
}

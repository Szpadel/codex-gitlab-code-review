use anyhow::Result;
use axum::Router;
use tokio::net::TcpListener;
use tokio::time::{Duration, sleep};

pub(crate) fn test_client_builder() -> reqwest::ClientBuilder {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::Client::builder()
}

pub(crate) fn test_client() -> reqwest::Client {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::Client::new()
}

pub(crate) async fn test_get(url: impl reqwest::IntoUrl) -> reqwest::Result<reqwest::Response> {
    crate::tls::ensure_reqwest_rustls_provider();
    reqwest::get(url).await
}

pub(crate) async fn spawn_test_server(app: Router) -> Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve test app");
    });
    sleep(Duration::from_millis(10)).await;
    Ok(addr)
}

use std::sync::Once;

static RUSTLS_PROVIDER_INIT: Once = Once::new();

pub(crate) fn ensure_reqwest_rustls_provider() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

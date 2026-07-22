use {crate::error::ConnectError, std::sync::Arc};

pub(crate) const ALPN: &[u8] = b"solana-gun-ingress/1";

/// TLS 1.3 WebPKI client config; `root_store` override or system roots.
pub(crate) fn rustls_client_config(
    root_store: Option<&Arc<rustls::RootCertStore>>,
) -> Result<Arc<rustls::ClientConfig>, ConnectError> {
    let roots = match root_store {
        Some(roots) => Arc::clone(roots),
        None => Arc::new(system_roots()?),
    };
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

fn system_roots() -> Result<rustls::RootCertStore, ConnectError> {
    let loaded = rustls_native_certs::load_native_certs();
    let mut store = rustls::RootCertStore::empty();
    store.add_parsable_certificates(loaded.certs);
    if store.is_empty() {
        return Err(ConnectError::Tls(match loaded.errors.first() {
            Some(e) => format!("no usable system root certificates ({e})"),
            None => "no usable system root certificates".into(),
        }));
    }
    Ok(store)
}

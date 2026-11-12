use {
    crate::{config::Security, error::ConnectError},
    rustls::{
        DigitallySignedStruct, SignatureScheme,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{CryptoProvider, ring::default_provider},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
    std::sync::Arc,
};

pub(crate) const ALPN: &[u8] = b"solana-gun-ingress/1";

/// TLS 1.3 WebPKI client config for QUIC; `root_store` override or system roots.
pub(crate) fn rustls_client_config(
    security: Security,
    root_store: Option<&Arc<rustls::RootCertStore>>,
) -> Result<Arc<rustls::ClientConfig>, ConnectError> {
    let mut cfg = match security {
        Security::VerifiedTls => base_client_config(root_store)?,
        Security::SkipVerification => skip_verify_client_config(),
        Security::Unencrypted => {
            return Err(ConnectError::Config(
                "unencrypted mode has no TLS configuration".into(),
            ));
        }
    };
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(cfg))
}

/// Same trust and provider as QUIC, without the ingress ALPN, for HTTPS discovery.
pub(crate) fn https_client_config(
    root_store: Option<&Arc<rustls::RootCertStore>>,
) -> Result<rustls::ClientConfig, ConnectError> {
    base_client_config(root_store)
}

fn base_client_config(
    root_store: Option<&Arc<rustls::RootCertStore>>,
) -> Result<rustls::ClientConfig, ConnectError> {
    let roots = match root_store {
        Some(roots) => Arc::clone(roots),
        None => Arc::new(system_roots()?),
    };
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .expect("ring provider supports TLS 1.3")
    .with_root_certificates(roots)
    .with_no_client_auth())
}

pub(crate) fn system_roots() -> Result<rustls::RootCertStore, ConnectError> {
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

/// Accepts any certificate chain; handshake signatures are still verified with the
/// ring provider, so only the identity check is skipped. No roots are consulted.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn skip_verify_client_config() -> rustls::ClientConfig {
    let provider = Arc::new(default_provider());
    rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("ring provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification(provider)))
        .with_no_client_auth()
}

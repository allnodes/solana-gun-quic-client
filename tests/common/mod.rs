//! Test stubs: a trusted QUIC ingress, a fixed-response HTTPS server, and a UDP
//! blackhole. All stubs in a test share one `Ca`, so one root store trusts them all.
#![allow(dead_code)]

use {
    quinn::VarInt,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    solana_gun_quic_client::{AutoConfig, ClientConfig, RootCertStore},
    std::{
        net::{Ipv4Addr, SocketAddr, UdpSocket},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    },
    tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::TcpListener,
    },
    tokio_rustls::TlsAcceptor,
};

const ALPN: &[u8] = b"solana-gun-ingress/1";

/// Self-signed certificate for `127.0.0.1`.
pub struct Ca {
    cert_der: CertificateDer<'static>,
    key_pkcs8: Vec<u8>,
}

impl Ca {
    pub fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        Self {
            cert_der: CertificateDer::from(cert.cert.der().to_vec()),
            key_pkcs8: cert.key_pair.serialize_der(),
        }
    }

    pub fn roots(&self) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(self.cert_der.clone()).unwrap();
        Arc::new(roots)
    }

    fn server_tls(&self) -> rustls::ServerConfig {
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(self.key_pkcs8.clone()));
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![self.cert_der.clone()], key)
        .unwrap()
    }
}

/// Stub reaction to the client's token line.
#[derive(Clone, Copy)]
pub enum Handshake {
    /// Reply `OK\n`, then drain uni-streams like the real ingress.
    Ok,
    /// Close with this application code (0x01 = unauthorized).
    CloseWith(u32),
}

pub struct QuicStub {
    addr: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<quinn::Connection>>>,
}

impl QuicStub {
    /// `accept_delay` is added to the QUIC handshake, i.e. to the measured probe latency.
    pub async fn spawn(ca: &Ca, accept_delay: Duration, handshake: Handshake) -> Self {
        let mut tls = ca.server_tls();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let counter = Arc::clone(&handshakes);
        let registry = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let counter = Arc::clone(&counter);
                let registry = Arc::clone(&registry);
                tokio::spawn(async move {
                    tokio::time::sleep(accept_delay).await;
                    let Ok(conn) = incoming.await else { return };
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        return;
                    };
                    let _ = recv.read_to_end(256).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    match handshake {
                        Handshake::Ok => {
                            let _ = send.write_all(b"OK\n").await;
                            let _ = send.finish();
                            registry.lock().unwrap().push(conn.clone());
                            while let Ok(mut uni) = conn.accept_uni().await {
                                tokio::spawn(async move {
                                    let _ = uni.read_to_end(4096).await;
                                });
                            }
                        }
                        Handshake::CloseWith(code) => {
                            conn.close(VarInt::from_u32(code), b"stub");
                        }
                    }
                });
            }
        });
        Self {
            addr,
            handshakes,
            connections,
        }
    }

    pub fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    /// Token lines received; probes send none.
    pub fn handshakes(&self) -> usize {
        self.handshakes.load(Ordering::SeqCst)
    }

    /// Close every established connection, forcing the client to reconnect.
    pub fn close_all(&self) {
        for conn in self.connections.lock().unwrap().drain(..) {
            conn.close(VarInt::from_u32(0), b"server closing");
        }
    }
}

/// HTTP/1.1 server returning one fixed response to every request; TLS unless `plain`.
pub struct HttpsStub {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
    plain: bool,
}

impl HttpsStub {
    pub async fn serve(ca: &Ca, status: u16, body: &str) -> Self {
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            reason_phrase(status),
            body.len()
        );
        Self::serve_raw(Some(ca), response).await
    }

    /// Plain-HTTP variant of [`Self::serve`].
    pub async fn serve_plain(status: u16, body: &str) -> Self {
        let response = format!(
            "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            reason_phrase(status),
            body.len()
        );
        Self::serve_raw(None, response).await
    }

    pub async fn redirect_to(ca: &Ca, location: &str) -> Self {
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        Self::serve_raw(Some(ca), response).await
    }

    async fn serve_raw(ca: Option<&Ca>, response: String) -> Self {
        let acceptor = ca.map(|ca| TlsAcceptor::from(Arc::new(ca.server_tls())));
        let plain = acceptor.is_none();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                let counter = Arc::clone(&counter);
                let response = response.clone();
                tokio::spawn(async move {
                    match acceptor {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(tcp).await {
                                respond(stream, &response, &counter).await;
                            }
                        }
                        None => respond(tcp, &response, &counter).await,
                    }
                });
            }
        });
        Self { addr, hits, plain }
    }

    pub fn url(&self) -> String {
        let scheme = if self.plain { "http" } else { "https" };
        format!("{scheme}://{}/discovery", self.addr)
    }

    /// Requests received (after a successful TLS handshake).
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

async fn respond<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    response: &str,
    counter: &AtomicUsize,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
    counter.fetch_add(1, Ordering::SeqCst);
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

const fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Bound-but-unread UDP socket: QUIC dials hang until they time out.
pub struct Blackhole {
    socket: UdpSocket,
}

impl Blackhole {
    pub fn bind() -> Self {
        Self {
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        }
    }

    pub fn endpoint(&self) -> String {
        format!("127.0.0.1:{}", self.socket.local_addr().unwrap().port())
    }
}

/// Trusts `ca`; short connect timeout so failures finish quickly.
pub fn client_config(ca: &Ca) -> ClientConfig {
    let mut config = ClientConfig::default();
    config.root_store = Some(ca.roots());
    config.reconnect.connect_timeout = Duration::from_millis(1500);
    config
}

/// Discovery at `url` with short timeouts.
pub fn auto_config(url: String) -> AutoConfig {
    let mut auto = AutoConfig::default();
    auto.discovery_url = url;
    auto.discovery_timeout = Duration::from_secs(2);
    auto.probe_timeout = Duration::from_millis(800);
    auto
}

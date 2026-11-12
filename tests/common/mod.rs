//! Test stubs: a trusted QUIC ingress, a fixed-response HTTPS server, and a UDP
//! blackhole. All stubs in a test share one `Ca`, so one root store trusts them all.
#![allow(dead_code)]

pub mod relay;

use {
    quinn::VarInt,
    rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    solana_gun_quic_client::{AutoConfig, ClientConfig, RootCertStore, Security, plaintext},
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

/// Extra stub behaviour for tokenless tests.
#[derive(Clone, Copy, Default)]
pub struct StubOptions {
    /// Delay before replying `OK\n`.
    pub ok_delay: Duration,
    /// Close with 0x02 on an anonymous hello (an old server).
    pub reject_anonymous: bool,
    /// Answer bidi (verdict) streams: reply `verdicts[n % len]` to the n-th stream.
    /// Empty = an old server that never calls `accept_bi` after the handshake.
    pub verdicts: &'static [&'static [u8]],
    /// Stop the receive half (0x11) before answering.
    pub stop_upload: bool,
}

pub struct QuicStub {
    hellos: Arc<Mutex<Vec<String>>>,
    uni_streams: Arc<AtomicUsize>,
    bidi_streams: Arc<AtomicUsize>,
    addr: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    connections: Arc<Mutex<Vec<quinn::Connection>>>,
}

impl QuicStub {
    /// `accept_delay` is added to the QUIC handshake, i.e. to the measured probe latency.
    pub async fn spawn(ca: &Ca, accept_delay: Duration, handshake: Handshake) -> Self {
        Self::spawn_with(ca, accept_delay, handshake, StubOptions::default()).await
    }

    pub async fn spawn_with(
        ca: &Ca,
        accept_delay: Duration,
        handshake: Handshake,
        options: StubOptions,
    ) -> Self {
        let hellos: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let uni_streams = Arc::new(AtomicUsize::new(0));
        let bidi_streams = Arc::new(AtomicUsize::new(0));
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
        let seen = Arc::clone(&hellos);
        let unis = Arc::clone(&uni_streams);
        let bidis = Arc::clone(&bidi_streams);
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let counter = Arc::clone(&counter);
                let registry = Arc::clone(&registry);
                let seen = Arc::clone(&seen);
                let unis = Arc::clone(&unis);
                let bidis = Arc::clone(&bidis);
                tokio::spawn(async move {
                    tokio::time::sleep(accept_delay).await;
                    let Ok(conn) = incoming.await else { return };
                    let Ok((mut send, mut recv)) = conn.accept_bi().await else {
                        return;
                    };
                    let hello = recv.read_to_end(256).await.unwrap_or_default();
                    seen.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&hello).into_owned());
                    counter.fetch_add(1, Ordering::SeqCst);
                    if options.reject_anonymous && hello == b"SOLANA-GUN-QUIC/1-ANON\n" {
                        conn.close(VarInt::from_u32(0x02), b"bad request");
                        return;
                    }
                    match handshake {
                        Handshake::Ok => {
                            tokio::time::sleep(options.ok_delay).await;
                            let _ = send.write_all(b"OK\n").await;
                            let _ = send.finish();
                            registry.lock().unwrap().push(conn.clone());
                            let bidi_conn = conn.clone();
                            tokio::spawn(async move {
                                // An old server (no verdicts) never answers: the streams
                                // are counted and held open.
                                let mut unanswered = Vec::new();
                                while let Ok((mut send, mut recv)) = bidi_conn.accept_bi().await {
                                    let n = bidis.fetch_add(1, Ordering::SeqCst);
                                    if options.verdicts.is_empty() {
                                        unanswered.push((send, recv));
                                        continue;
                                    }
                                    let reply = options.verdicts[n % options.verdicts.len()];
                                    tokio::spawn(async move {
                                        if options.stop_upload {
                                            let _ = recv.stop(VarInt::from_u32(0x11));
                                        } else {
                                            let _ = recv.read_to_end(4096).await;
                                        }
                                        let _ = send.write_all(reply).await;
                                        let _ = send.finish();
                                        let _ = send.stopped().await;
                                    });
                                }
                            });
                            while let Ok(mut uni) = conn.accept_uni().await {
                                unis.fetch_add(1, Ordering::SeqCst);
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
            hellos,
            uni_streams,
            bidi_streams,
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

    /// Handshake lines received, in arrival order.
    pub fn hellos(&self) -> Vec<String> {
        self.hellos.lock().unwrap().clone()
    }

    /// Transaction uni-streams accepted.
    pub fn uni_streams(&self) -> usize {
        self.uni_streams.load(Ordering::SeqCst)
    }

    /// Bidi (verdict) streams accepted after the handshake stream, answered or not.
    pub fn bidi_streams(&self) -> usize {
        self.bidi_streams.load(Ordering::SeqCst)
    }

    /// Close every established connection, forcing the client to reconnect.
    pub fn close_all(&self) {
        for conn in self.connections.lock().unwrap().drain(..) {
            conn.close(VarInt::from_u32(0), b"server closing");
        }
    }
}

/// Unencrypted ingress stub built from `plaintext::server_crypto()`: takes every
/// connection through `into_0rtt()` and reads streams before establishment.
pub struct PlainStub {
    addr: SocketAddr,
    endpoint: quinn::Endpoint,
    connections: Arc<Mutex<Vec<quinn::Connection>>>,
    txs: Arc<Mutex<Vec<Vec<u8>>>>,
    bidi_streams: Arc<AtomicUsize>,
}

impl PlainStub {
    /// Answers the n-th bidi stream with `verdicts[n % len]` (`[0x00]` when empty).
    pub async fn spawn(verdicts: &'static [&'static [u8]]) -> Self {
        Self::spawn_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), verdicts, false).await
    }

    /// Reads each bidi (confirmed) transaction, then closes the connection (code 0)
    /// instead of answering.
    pub async fn spawn_closing_after_confirmed_read() -> Self {
        Self::spawn_on(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), &[], true).await
    }

    pub async fn spawn_on(
        bind: SocketAddr,
        verdicts: &'static [&'static [u8]],
        close_after_read: bool,
    ) -> Self {
        const STREAMS: u32 = 64;
        const WINDOW: u32 = 4097;
        let conn_window = u64::from(WINDOW) * 2 * u64::from(STREAMS);
        plaintext::check_server_limits(STREAMS, STREAMS, WINDOW.into(), conn_window).unwrap();
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(STREAMS.into());
        transport.max_concurrent_bidi_streams(STREAMS.into());
        transport.stream_receive_window(WINDOW.into());
        transport.receive_window(VarInt::from_u64(conn_window).unwrap());
        let mut server_config = quinn::ServerConfig::with_crypto(plaintext::server_crypto());
        server_config.transport_config(Arc::new(transport));
        server_config.migration(false);
        let endpoint = quinn::Endpoint::new(
            plaintext::endpoint_config(),
            Some(server_config),
            UdpSocket::bind(bind).unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let connections: Arc<Mutex<Vec<quinn::Connection>>> = Arc::new(Mutex::new(Vec::new()));
        let txs: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let bidi_streams = Arc::new(AtomicUsize::new(0));
        let (ep, registry, seen, bidis) = (
            endpoint.clone(),
            Arc::clone(&connections),
            Arc::clone(&txs),
            Arc::clone(&bidi_streams),
        );
        tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                let Ok(connecting) = incoming.accept() else {
                    continue;
                };
                let Ok((conn, _)) = connecting.into_0rtt() else {
                    continue;
                };
                registry.lock().unwrap().push(conn.clone());
                let (uni_conn, seen) = (conn.clone(), Arc::clone(&seen));
                tokio::spawn(async move {
                    while let Ok(mut uni) = uni_conn.accept_uni().await {
                        let seen = Arc::clone(&seen);
                        tokio::spawn(async move {
                            if let Ok(tx) = uni.read_to_end(4096).await {
                                seen.lock().unwrap().push(tx);
                            }
                        });
                    }
                });
                let bidis = Arc::clone(&bidis);
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let conn = conn.clone();
                        let n = bidis.fetch_add(1, Ordering::SeqCst);
                        let reply: &[u8] = if verdicts.is_empty() {
                            &[0x00]
                        } else {
                            verdicts[n % verdicts.len()]
                        };
                        tokio::spawn(async move {
                            let _ = recv.read_to_end(4096).await;
                            if close_after_read {
                                conn.close(VarInt::from_u32(0), b"closing");
                                return;
                            }
                            let _ = send.write_all(reply).await;
                            let _ = send.finish();
                            let _ = send.stopped().await;
                        });
                    }
                });
            }
        });
        Self {
            addr,
            endpoint,
            connections,
            txs,
            bidi_streams,
        }
    }

    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn endpoint(&self) -> String {
        self.addr.to_string()
    }

    /// Connections accepted.
    pub fn connections(&self) -> usize {
        self.connections.lock().unwrap().len()
    }

    /// Transactions read from uni streams, in completion order.
    pub fn txs(&self) -> Vec<Vec<u8>> {
        self.txs.lock().unwrap().clone()
    }

    pub fn bidi_streams(&self) -> usize {
        self.bidi_streams.load(Ordering::SeqCst)
    }

    /// Close every connection, forcing the client to reconnect.
    pub fn close_all(&self) {
        self.close_all_with(0);
    }

    pub fn close_all_with(&self, code: u32) {
        for conn in self.connections.lock().unwrap().iter() {
            conn.close(VarInt::from_u32(code), b"server closing");
        }
    }

    /// Stop the server: closes every connection and the endpoint.
    pub async fn shutdown(self) {
        self.endpoint.close(VarInt::from_u32(0), b"restart");
        let _ = tokio::time::timeout(Duration::from_secs(2), self.endpoint.wait_idle()).await;
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

/// Unencrypted client with a short connect timeout.
pub fn plain_config() -> ClientConfig {
    let mut config = ClientConfig::default();
    config.security = Security::Unencrypted;
    config.reconnect.connect_timeout = Duration::from_millis(1500);
    config
}

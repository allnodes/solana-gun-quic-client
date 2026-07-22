use {
    crate::{
        config::{ClientConfig, ReconnectPolicy},
        error::{ConnectError, HandshakeError, SendError},
        tls,
    },
    quinn::{
        ClientConfig as QuinnClientConfig, Connection, Endpoint, VarInt,
        crypto::rustls::QuicClientConfig,
    },
    std::{net::SocketAddr, sync::Arc, time::Duration},
    tokio::sync::{Mutex, RwLock},
    zeroize::Zeroizing,
};

/// Maximum transaction payload (Solana packet size).
pub(crate) const MAX_TX_BYTES: usize = 1232;
/// Hard cap on token length (mirror of the server's handshake limit).
const MAX_TOKEN_BYTES: usize = 200;
/// Handshake line prefix (note the trailing space).
const HANDSHAKE_PREFIX: &str = "SOLANA-GUN-QUIC/1 ";

/// Connection-close application codes used by the server.
const CLOSE_UNAUTHORIZED: u64 = 0x01;
const CLOSE_BAD_REQUEST: u64 = 0x02;
const CLOSE_TOO_MANY: u64 = 0x03;
const CLOSE_REVOKED: u64 = 0x04;

/// Shared client state.
struct Inner {
    endpoint: Endpoint,
    addr: SocketAddr,
    server_name: String,
    token: Zeroizing<String>,
    reconnect: ReconnectPolicy,
    send_timeout: Duration,
    connection: RwLock<Arc<Connection>>,
    reconnect_lock: Mutex<()>,
}

#[derive(Clone)]
pub struct SolanaGunQuicClient {
    inner: Arc<Inner>,
}

impl SolanaGunQuicClient {
    /// Low-level connect: explicit socket address + TLS server name, no blocking DNS.
    pub async fn connect_addr(
        addr: SocketAddr,
        server_name: &str,
        token: &str,
        config: ClientConfig,
    ) -> Result<Self, ConnectError> {
        config.validate()?;
        validate_token(token)?;
        let endpoint = build_endpoint(addr, &config)?;
        let connection = tokio::time::timeout(
            config.reconnect.connect_timeout,
            dial_and_handshake(&endpoint, addr, server_name, token),
        )
        .await
        .map_err(|_| ConnectError::Handshake(HandshakeError::Timeout))??;
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                addr,
                server_name: server_name.to_owned(),
                token: Zeroizing::new(token.to_owned()),
                reconnect: config.reconnect,
                send_timeout: config.send_timeout,
                connection: RwLock::new(Arc::new(connection)),
                reconnect_lock: Mutex::new(()),
            }),
        })
    }

    /// Convenience: resolve `host:port`, then `connect_addr`.
    /// Resolves `host:port` (bounded by `reconnect.connect_timeout`) and tries each
    /// resolved address in turn, returning the first successful connection.
    pub async fn connect(
        addr: &str,
        token: &str,
        config: ClientConfig,
    ) -> Result<Self, ConnectError> {
        config.validate()?;
        validate_token(token)?;
        let host = if let Some(rest) = addr.strip_prefix('[') {
            rest.split_once(']')
                .map(|(h, _)| h.to_owned())
                .ok_or_else(|| {
                    ConnectError::Resolve(format!("unterminated IPv6 literal in {addr}"))
                })?
        } else {
            addr.rsplit_once(':')
                .map(|(h, _)| h.to_owned())
                .ok_or_else(|| ConnectError::Resolve(format!("missing port in {addr}")))?
        };
        let addrs: Vec<SocketAddr> = tokio::time::timeout(
            config.reconnect.connect_timeout,
            tokio::net::lookup_host(addr),
        )
        .await
        .map_err(|_| ConnectError::Resolve(format!("dns lookup for {addr} timed out")))?
        .map_err(|e| ConnectError::Resolve(e.to_string()))?
        .collect();
        if addrs.is_empty() {
            return Err(ConnectError::Resolve(format!("no addresses for {addr}")));
        }
        let mut last_err = None;
        for sockaddr in addrs {
            match Self::connect_addr(sockaddr, &host, token, config.clone()).await {
                Ok(client) => return Ok(client),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| ConnectError::Resolve(format!("no addresses for {addr}"))))
    }

    /// Fire-and-forget with transparent reconnect. Returns Ok once the bytes are written
    /// and the uni-stream finished — i.e. queued in the local QUIC send buffer.
    pub async fn send_transaction_bytes(&self, tx_bytes: &[u8]) -> Result<(), SendError> {
        if tx_bytes.len() > MAX_TX_BYTES {
            return Err(SendError::TooLarge(tx_bytes.len()));
        }
        let timeout = self.inner.send_timeout;
        let conn = self.inner.connection.read().await.clone();
        match send_on_timed(&conn, tx_bytes, timeout).await {
            Ok(()) => Ok(()),
            Err(e) if self.inner.reconnect.enabled && is_reconnectable_send_error(&e) => {
                if matches!(e, SendError::Timeout) {
                    conn.close(VarInt::from_u32(0), b"send timeout");
                }
                let fresh = self.reconnect(&conn).await?;
                send_on_timed(&fresh, tx_bytes, timeout).await
            }
            Err(e) => Err(e),
        }
    }

    /// Re-establish the connection if `stale` is still the current one.
    async fn reconnect(&self, stale: &Arc<Connection>) -> Result<Arc<Connection>, SendError> {
        let _guard = self.inner.reconnect_lock.lock().await;
        {
            let cur = self.inner.connection.read().await.clone();
            if !Arc::ptr_eq(&cur, stale) {
                return Ok(cur);
            }
        }
        let policy = &self.inner.reconnect;
        let mut backoff = policy.initial_backoff;
        let mut attempts = 0u32;
        loop {
            let attempt = tokio::time::timeout(
                policy.connect_timeout,
                dial_and_handshake(
                    &self.inner.endpoint,
                    self.inner.addr,
                    &self.inner.server_name,
                    &self.inner.token,
                ),
            )
            .await;
            let last = match attempt {
                Ok(Ok(conn)) => {
                    let arc = Arc::new(conn);
                    *self.inner.connection.write().await = Arc::clone(&arc);
                    return Ok(arc);
                }
                Ok(Err(e)) if is_terminal(&e) => return Err(SendError::Reconnect(e)),
                Ok(Err(transient)) => transient,
                Err(_elapsed) => ConnectError::Handshake(HandshakeError::Timeout),
            };
            attempts += 1;
            if let Some(max) = policy.max_attempts
                && attempts >= max
            {
                return Err(SendError::ReconnectExhausted {
                    attempts,
                    last: Box::new(last),
                });
            }
            tokio::time::sleep(jittered(backoff)).await;
            backoff = next_backoff(backoff, policy.max_backoff);
        }
    }

    /// Close the connection and wait for the endpoint to go idle.
    pub async fn close(self) {
        let conn = self.inner.connection.read().await.clone();
        conn.close(VarInt::from_u32(0), b"bye");
        self.inner.endpoint.wait_idle().await;
    }
}

fn build_endpoint(addr: SocketAddr, config: &ClientConfig) -> Result<Endpoint, ConnectError> {
    let rustls_cfg = tls::rustls_client_config(config.root_store.as_ref())?;
    let quic_crypto = QuicClientConfig::try_from((*rustls_cfg).clone())
        .map_err(|e| ConnectError::Tls(e.to_string()))?;
    let mut quinn_cfg = QuinnClientConfig::new(Arc::new(quic_crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        config
            .idle_timeout
            .try_into()
            .map_err(|_| ConnectError::Tls("idle_timeout out of range".into()))?,
    ));
    transport.keep_alive_interval(Some(config.keep_alive_interval));
    quinn_cfg.transport_config(Arc::new(transport));
    let bind: SocketAddr = if addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let mut endpoint = Endpoint::client(bind)?;
    endpoint.set_default_client_config(quinn_cfg);
    Ok(endpoint)
}

async fn dial_and_handshake(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    token: &str,
) -> Result<Connection, ConnectError> {
    let connection = endpoint.connect(addr, server_name)?.await?;
    handshake(&connection, token).await?;
    Ok(connection)
}

/// The server's handshake ack is exactly `OK\n`; anything else is a failure.
fn handshake_reply_ok(buf: &[u8]) -> bool {
    buf == b"OK\n"
}

/// Reject tokens the server's line-based handshake parser would refuse, so a bad token
/// fails locally with a clear error instead of an opaque server BadRequest.
fn validate_token(token: &str) -> Result<(), ConnectError> {
    if token.is_empty() {
        return Err(ConnectError::Config("token is empty".into()));
    }
    if token.len() > MAX_TOKEN_BYTES {
        return Err(ConnectError::Config(format!(
            "token is {} bytes, exceeds maximum {MAX_TOKEN_BYTES}",
            token.len()
        )));
    }
    if !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(ConnectError::Config(
            "token must be printable ASCII with no spaces or control characters".into(),
        ));
    }
    Ok(())
}

async fn handshake(connection: &Connection, token: &str) -> Result<(), HandshakeError> {
    let (mut send, mut recv) = connection.open_bi().await.map_err(map_close)?;
    let mut line = Zeroizing::new(String::with_capacity(
        HANDSHAKE_PREFIX.len() + token.len() + 1,
    ));
    line.push_str(HANDSHAKE_PREFIX);
    line.push_str(token);
    line.push('\n');
    send.write_all(line.as_bytes())
        .await
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e)))?;
    send.finish()
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e)))?;
    let read = tokio::time::timeout(Duration::from_millis(750), recv.read_to_end(16));
    let buf = match read.await {
        Err(_) => return Err(HandshakeError::Timeout),
        Ok(Ok(b)) => b,
        Ok(Err(_)) => return Err(connection_close_error(connection)),
    };
    if handshake_reply_ok(&buf) {
        Ok(())
    } else {
        Err(connection_close_error(connection))
    }
}

async fn send_on(conn: &Connection, bytes: &[u8]) -> Result<(), SendError> {
    let mut uni = conn.open_uni().await?;
    uni.write_all(bytes).await?;
    uni.finish()?;
    uni.stopped().await.map_err(quinn::WriteError::from)?;
    Ok(())
}

async fn send_on_timed(
    conn: &Connection,
    bytes: &[u8],
    timeout: Duration,
) -> Result<(), SendError> {
    tokio::time::timeout(timeout, send_on(conn, bytes))
        .await
        .map_err(|_| SendError::Timeout)?
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    current.saturating_mul(2).min(max)
}

fn apply_jitter(base: Duration, rand_unit: f64) -> Duration {
    let half = base / 2;
    half + half.mul_f64(rand_unit.clamp(0.0, 1.0))
}

fn jittered(base: Duration) -> Duration {
    use std::time::{SystemTime, UNIX_EPOCH};
    let unit = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as f64 / 1_000_000_000.0)
        .unwrap_or(0.0);
    apply_jitter(base, unit)
}

/// A send failure that warrants a transparent reconnect + retry: a genuinely lost
/// connection, or a send timeout (which usually means the connection is wedged — a
/// path failure or flow-control stall QUIC has not yet surfaced).
const fn is_reconnectable_send_error(e: &SendError) -> bool {
    matches!(
        e,
        SendError::Timeout
            | SendError::ConnectionLost(_)
            | SendError::StreamWrite(quinn::WriteError::ConnectionLost(_))
    )
}

/// Reconnection-terminal: token auth failure, a client-side TLS/config error, or a TLS
/// handshake (crypto) failure such as an untrusted server certificate. Transport
/// failures (server down, reset, timeout, refused) are transient and retried with backoff.
const fn is_terminal(e: &ConnectError) -> bool {
    match e {
        ConnectError::Tls(_) => true,
        ConnectError::Handshake(h) => matches!(
            h,
            HandshakeError::Unauthorized | HandshakeError::Revoked | HandshakeError::BadRequest
        ),
        // TLS handshake (crypto) failure, such as an untrusted server certificate. Other
        // `ConnectionError` variants (Reset / TimedOut / ConnectionClosed / ...) and
        // `ConnectError::Dial` / `Resolve` remain transient.
        ConnectError::Connection(quinn::ConnectionError::TransportError(_)) => true,
        _ => false,
    }
}

fn map_close(e: quinn::ConnectionError) -> HandshakeError {
    match e {
        quinn::ConnectionError::ApplicationClosed(ac) => code_to_err(ac.error_code.into_inner()),
        other => HandshakeError::Io(std::io::Error::other(other)),
    }
}

fn connection_close_error(connection: &Connection) -> HandshakeError {
    match connection.close_reason() {
        Some(quinn::ConnectionError::ApplicationClosed(ac)) => {
            code_to_err(ac.error_code.into_inner())
        }
        Some(other) => HandshakeError::Io(std::io::Error::other(other)),
        None => HandshakeError::Unexpected(0),
    }
}

const fn code_to_err(code: u64) -> HandshakeError {
    match code {
        CLOSE_UNAUTHORIZED => HandshakeError::Unauthorized,
        CLOSE_BAD_REQUEST => HandshakeError::BadRequest,
        CLOSE_TOO_MANY => HandshakeError::TooManyConnections,
        CLOSE_REVOKED => HandshakeError::Revoked,
        other => HandshakeError::Unexpected(other),
    }
}

#[cfg(test)]
mod terminal_tests {
    use {
        super::*,
        std::net::{Ipv4Addr, SocketAddr},
    };

    /// Stand up an in-process quinn server with a fresh self-signed cert (ALPN matched to
    /// the client's), accept-and-ignore connections, and return its bound address. The
    /// client will fail at certificate verification before the handshake completes.
    async fn spawn_untrusted_server() -> SocketAddr {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );

        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
        tls.alpn_protocols = vec![crate::tls::ALPN.to_vec()];

        let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(qsc));
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
                .unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = incoming.await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn untrusted_cert_is_terminal() {
        let addr = spawn_untrusted_server().await;
        let config = ClientConfig::default();
        let endpoint = build_endpoint(addr, &config).unwrap();

        let err = dial_and_handshake(&endpoint, addr, "localhost", "tok")
            .await
            .expect_err("handshake must fail on an untrusted certificate");
        assert!(
            is_terminal(&err),
            "an untrusted certificate must be reconnect-terminal, got {err:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation_rejects_malformed_tokens() {
        assert!(validate_token("good-token").is_ok());
        assert!(validate_token("").is_err());
        assert!(validate_token("has space").is_err());
        assert!(validate_token("has\nnewline").is_err());
        assert!(validate_token(&"a".repeat(MAX_TOKEN_BYTES + 1)).is_err());
        assert!(validate_token(&"a".repeat(MAX_TOKEN_BYTES)).is_ok());
    }

    #[test]
    fn handshake_reply_requires_exact_ok() {
        assert!(handshake_reply_ok(b"OK\n"));
        assert!(!handshake_reply_ok(b"OK"));
        assert!(!handshake_reply_ok(b"OKAY\n"));
        assert!(!handshake_reply_ok(b"NO\n"));
    }

    #[test]
    fn client_handle_is_clone_send_sync() {
        fn assert_traits<T: Clone + Send + Sync>() {}
        assert_traits::<SolanaGunQuicClient>();
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let max = Duration::from_secs(5);
        assert_eq!(
            next_backoff(Duration::from_millis(100), max),
            Duration::from_millis(200)
        );
        assert_eq!(
            next_backoff(Duration::from_millis(200), max),
            Duration::from_millis(400)
        );
        assert_eq!(next_backoff(Duration::from_secs(4), max), max);
        assert_eq!(next_backoff(Duration::from_secs(10), max), max);
        // `current * 2` would panic on overflow; saturating_mul must clamp instead.
        assert_eq!(next_backoff(Duration::MAX, max), max);
    }

    #[test]
    fn terminal_classification() {
        assert!(is_terminal(&ConnectError::Handshake(
            HandshakeError::Unauthorized
        )));
        assert!(is_terminal(&ConnectError::Handshake(
            HandshakeError::Revoked
        )));
        assert!(is_terminal(&ConnectError::Tls("bad".into())));
        assert!(!is_terminal(&ConnectError::Resolve("dns".into())));
        assert!(!is_terminal(&ConnectError::Handshake(
            HandshakeError::TooManyConnections
        )));
    }

    #[test]
    fn jitter_stays_within_half_to_full() {
        let base = Duration::from_millis(800);
        assert_eq!(apply_jitter(base, 0.0), Duration::from_millis(400));
        assert_eq!(apply_jitter(base, 1.0), Duration::from_millis(800));
        let mid = apply_jitter(base, 0.5);
        assert!(mid >= base / 2 && mid <= base);
        assert_eq!(apply_jitter(base, 2.0), base);
        assert_eq!(apply_jitter(base, -1.0), base / 2);
    }

    #[test]
    fn timeout_is_reconnectable_but_stream_stop_is_not() {
        // A send timeout means the connection is likely wedged → reconnect.
        assert!(is_reconnectable_send_error(&SendError::Timeout));
        // Size errors are caller errors, never reconnectable.
        assert!(!is_reconnectable_send_error(&SendError::TooLarge(9999)));
        // A stream-level STOP (incl. the server's 0x10 reset) must NOT reconnect:
        // replaying on a stream stop amplifies overload for no reason.
        assert!(!is_reconnectable_send_error(&SendError::StreamWrite(
            quinn::WriteError::Stopped(VarInt::from_u32(0x10))
        )));
    }

    #[tokio::test]
    async fn connect_resolves_and_times_out_on_blackhole() {
        // 127.0.0.1 resolves locally (no network); a bound-but-unread UDP socket is a
        // deterministic black hole, so the new resolve-all connect path must still time
        // out fast via connect_timeout.
        let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = blackhole.local_addr().unwrap().port();
        let mut config = ClientConfig::default();
        config.reconnect.connect_timeout = Duration::from_millis(300);

        let start = std::time::Instant::now();
        match SolanaGunQuicClient::connect(&format!("127.0.0.1:{port}"), "tok", config).await {
            Err(ConnectError::Handshake(HandshakeError::Timeout)) => {}
            Err(e) => panic!("expected handshake timeout, got {e:?}"),
            Ok(_) => panic!("expected handshake timeout, got Ok(connected)"),
        }
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "timeout did not fire promptly"
        );
    }
}

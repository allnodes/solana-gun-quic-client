use {
    crate::{
        autoconfig::EndpointSource,
        config::{ClientConfig, ReconnectPolicy, Security},
        error::{ConnectError, HandshakeError, SendError},
        plaintext, tls,
    },
    quinn::{
        ClientConfig as QuinnClientConfig, Connection, ConnectionError, Endpoint, RecvStream,
        SendStream, VarInt, crypto::rustls::QuicClientConfig,
    },
    std::{net::SocketAddr, ops::Deref, pin::pin, sync::Arc, time::Duration},
    tokio::sync::{Mutex, RwLock, watch},
    zeroize::Zeroizing,
};

/// Maximum transaction payload (Solana packet size).
/// Largest transaction the ingress accepts: the v1 (SIMD-0385) limit. The library has
/// no Solana dependency, so this mirrors `solana_message::v1::MAX_TRANSACTION_SIZE`.
pub(crate) const MAX_TX_BYTES: usize = 4096;
/// Hard cap on token length (mirror of the server's handshake limit).
const MAX_TOKEN_BYTES: usize = 200;
/// Handshake line prefix (note the trailing space).
const HANDSHAKE_PREFIX: &str = "SOLANA-GUN-QUIC/1 ";
/// Tokenless hello line (no trailing-space prefix, so it cannot collide with a token).
const ANON_HELLO: &[u8] = b"SOLANA-GUN-QUIC/1-ANON\n";

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
    token: Option<Zeroizing<String>>,
    security: Security,
    /// Tokenless: the handshake stream's receive half, kept open for the connection's
    /// lifetime and never read; replaced on reconnect.
    anon_recv: std::sync::Mutex<Option<RecvStream>>,
    reconnect: ReconnectPolicy,
    send_timeout: Duration,
    connection: RwLock<Arc<Conn>>,
    reconnect_lock: Mutex<()>,
    source: EndpointSource,
}

/// A connection plus, in unencrypted mode, its establishment signal.
#[derive(Debug)]
struct Conn {
    conn: Connection,
    /// Unencrypted only: becomes `true` once the connection is established or failed.
    /// quinn raises the stream limits from the compiled-in early values to the
    /// server's real ones without waking an open already waiting at the early limit,
    /// so such an open is retried afresh at that point.
    settled: Option<watch::Receiver<bool>>,
}

impl Deref for Conn {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.conn
    }
}

impl Conn {
    const fn established(conn: Connection) -> Self {
        Self {
            conn,
            settled: None,
        }
    }

    async fn wait_settled(&self) {
        if let Some(rx) = &self.settled {
            let _ = rx.clone().wait_for(|settled| *settled).await;
        }
    }

    async fn open_uni(&self) -> Result<SendStream, ConnectionError> {
        if self.settled.is_none() {
            return self.conn.open_uni().await;
        }
        let mut open = pin!(self.conn.open_uni());
        tokio::select! {
            biased;
            r = &mut open => r,
            () = self.wait_settled() => self.conn.open_uni().await,
        }
    }

    async fn open_bi(&self) -> Result<(SendStream, RecvStream), ConnectionError> {
        if self.settled.is_none() {
            return self.conn.open_bi().await;
        }
        let mut open = pin!(self.conn.open_bi());
        tokio::select! {
            biased;
            r = &mut open => r,
            () = self.wait_settled() => self.conn.open_bi().await,
        }
    }
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
        Self::connect_addr_with_source(
            addr,
            server_name,
            Some(token),
            config,
            EndpointSource::Manual,
        )
        .await
    }

    /// Tokenless twin of [`Self::connect_addr`]. Returns without waiting for the
    /// server's reply; a refusal surfaces on a later send (which may itself have
    /// returned `Ok` if it raced the close) as `SendError::Reconnect` with
    /// `TokenlessUnsupported` (old server) or `Unauthorized` (tokenless disabled).
    pub async fn connect_addr_anonymous(
        addr: SocketAddr,
        server_name: &str,
        config: ClientConfig,
    ) -> Result<Self, ConnectError> {
        Self::connect_addr_with_source(addr, server_name, None, config, EndpointSource::Manual)
            .await
    }

    pub(crate) async fn connect_addr_with_source(
        addr: SocketAddr,
        server_name: &str,
        token: Option<&str>,
        config: ClientConfig,
        source: EndpointSource,
    ) -> Result<Self, ConnectError> {
        validate_credentials(token, &config)?;
        let endpoint = build_endpoint(addr, &config)?;
        // Before dialing: a failed attempt has sent the token too.
        if token.is_some() && config.security == Security::SkipVerification {
            tracing::warn!(
                "server identity is not verified; the token is sent to an unauthenticated server"
            );
        }
        let (connection, anon_recv) = tokio::time::timeout(
            config.reconnect.connect_timeout,
            dial_and_handshake(&endpoint, addr, server_name, token, config.security),
        )
        .await
        .map_err(|_| ConnectError::Handshake(HandshakeError::Timeout))??;
        Ok(Self {
            inner: Arc::new(Inner {
                endpoint,
                addr,
                server_name: server_name.to_owned(),
                token: token.map(|t| Zeroizing::new(t.to_owned())),
                security: config.security,
                anon_recv: std::sync::Mutex::new(anon_recv),
                reconnect: config.reconnect,
                send_timeout: config.send_timeout,
                connection: RwLock::new(Arc::new(connection)),
                reconnect_lock: Mutex::new(()),
                source,
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
        Self::connect_with_source(addr, Some(token), config, EndpointSource::Manual).await
    }

    /// Tokenless twin of [`Self::connect`]; see [`Self::connect_addr_anonymous`].
    pub async fn connect_anonymous(addr: &str, config: ClientConfig) -> Result<Self, ConnectError> {
        Self::connect_with_source(addr, None, config, EndpointSource::Manual).await
    }

    pub(crate) async fn connect_with_source(
        addr: &str,
        token: Option<&str>,
        config: ClientConfig,
        source: EndpointSource,
    ) -> Result<Self, ConnectError> {
        validate_credentials(token, &config)?;
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
            match Self::connect_addr_with_source(
                sockaddr,
                &host,
                token,
                config.clone(),
                source.clone(),
            )
            .await
            {
                Ok(client) => return Ok(client),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| ConnectError::Resolve(format!("no addresses for {addr}"))))
    }

    /// Opt-in autoconfiguration: query `auto.discovery_url`, probe every returned
    /// endpoint over QUIC, and connect through the lowest-latency reachable one. If that
    /// fails, connect to `auto.fallback_endpoint`, or return [`ConnectError::AutoConfig`]
    /// when none is set. The chosen endpoint is kept for the client's lifetime.
    pub async fn connect_auto(
        token: &str,
        config: ClientConfig,
        auto: crate::autoconfig::AutoConfig,
    ) -> Result<Self, ConnectError> {
        crate::autoconfig::connect_auto(Some(token), config, auto).await
    }

    /// Tokenless twin of [`Self::connect_auto`].
    pub async fn connect_auto_anonymous(
        config: ClientConfig,
        auto: crate::autoconfig::AutoConfig,
    ) -> Result<Self, ConnectError> {
        crate::autoconfig::connect_auto(None, config, auto).await
    }

    /// How the active endpoint was chosen; fixed for the client's lifetime.
    pub fn endpoint_source(&self) -> &EndpointSource {
        &self.inner.source
    }

    /// Fire-and-forget with transparent reconnect. Returns Ok once the server's QUIC
    /// transport has acknowledged the whole stream (or stopped it). That is not an
    /// admission: rate limits and rejections are not reported here.
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

    /// Sends on a bidirectional verdict stream and waits for the server's answer:
    /// `Ok` accepted, `RateLimited` or `Rejected` otherwise. A server without verdict
    /// support never answers, so this ends in `Timeout`. Only a send that never reached
    /// the server (connection already lost, or early data discarded) triggers a
    /// reconnect and retry; a verdict or a timeout never resubmits.
    pub async fn send_transaction_bytes_confirmed(&self, tx_bytes: &[u8]) -> Result<(), SendError> {
        if tx_bytes.len() > MAX_TX_BYTES {
            return Err(SendError::TooLarge(tx_bytes.len()));
        }
        let timeout = self.inner.send_timeout;
        let conn = self.inner.connection.read().await.clone();
        match confirm_on_timed(&conn, tx_bytes, timeout).await {
            Err(Confirm::NotSent(_)) if self.inner.reconnect.enabled => {
                let fresh = self.reconnect(&conn).await?;
                confirm_on_timed(&fresh, tx_bytes, timeout)
                    .await
                    .map_err(Confirm::into_error)
            }
            other => other.map_err(Confirm::into_error),
        }
    }

    /// Re-establish the connection if `stale` is still the current one.
    async fn reconnect(&self, stale: &Arc<Conn>) -> Result<Arc<Conn>, SendError> {
        let _guard = self.inner.reconnect_lock.lock().await;
        {
            let cur = self.inner.connection.read().await.clone();
            if !Arc::ptr_eq(&cur, stale) {
                return Ok(cur);
            }
        }
        if let Some(ConnectionError::VersionMismatch) = stale.close_reason() {
            return Err(SendError::Reconnect(
                ConnectionError::VersionMismatch.into(),
            ));
        }
        if self.inner.token.is_none()
            && let Some(ConnectionError::ApplicationClosed(ac)) = stale.close_reason()
        {
            match ac.error_code.into_inner() {
                // Unencrypted has no hello: 0x02 there is the control-exchange
                // deadline (e.g. a lossy link), so it is transient.
                CLOSE_BAD_REQUEST if self.inner.security != Security::Unencrypted => {
                    return Err(SendError::Reconnect(
                        HandshakeError::TokenlessUnsupported.into(),
                    ));
                }
                CLOSE_UNAUTHORIZED => {
                    return Err(SendError::Reconnect(HandshakeError::Unauthorized.into()));
                }
                _ => {}
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
                    self.inner.token.as_deref().map(String::as_str),
                    self.inner.security,
                ),
            )
            .await;
            let last = match attempt {
                Ok(Ok((conn, anon_recv))) => {
                    *self.inner.anon_recv.lock().unwrap() = anon_recv;
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

pub(crate) fn build_endpoint(
    addr: SocketAddr,
    config: &ClientConfig,
) -> Result<Endpoint, ConnectError> {
    let mut quinn_cfg = if config.security == Security::Unencrypted {
        plaintext::client_config()
    } else {
        let rustls_cfg = tls::rustls_client_config(config.security, config.root_store.as_ref())?;
        let quic_crypto = QuicClientConfig::try_from((*rustls_cfg).clone())
            .map_err(|e| ConnectError::Tls(e.to_string()))?;
        QuinnClientConfig::new(Arc::new(quic_crypto))
    };
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
    let mut endpoint = if config.security == Security::Unencrypted {
        // Lists only the private version; never offered to a TLS port.
        Endpoint::new(
            plaintext::endpoint_config(),
            None,
            std::net::UdpSocket::bind(bind)?,
            Arc::new(quinn::TokioRuntime),
        )?
    } else {
        Endpoint::client(bind)?
    };
    endpoint.set_default_client_config(quinn_cfg);
    Ok(endpoint)
}

async fn dial_and_handshake(
    endpoint: &Endpoint,
    addr: SocketAddr,
    server_name: &str,
    token: Option<&str>,
    security: Security,
) -> Result<(Conn, Option<RecvStream>), ConnectError> {
    let connecting = endpoint.connect(addr, server_name)?;
    if security == Security::Unencrypted {
        // Returns at once; the first stream goes out in the first flight. No hello stream.
        return Ok((dial_unencrypted(connecting).await?, None));
    }
    let connection = connecting.await?;
    match token {
        Some(token) => {
            handshake(&connection, token).await?;
            Ok((Conn::established(connection), None))
        }
        None => {
            let recv = anonymous_hello(&connection).await?;
            Ok((Conn::established(connection), Some(recv)))
        }
    }
}

async fn dial_unencrypted(connecting: quinn::Connecting) -> Result<Conn, ConnectionError> {
    match connecting.into_0rtt() {
        Ok((conn, accepted)) => {
            let (tx, rx) = watch::channel(false);
            tokio::spawn(async move {
                let _ = accepted.await;
                let _ = tx.send(true);
            });
            Ok(Conn {
                conn,
                settled: Some(rx),
            })
        }
        // The plaintext session always has early keys; kept as a plain fallback.
        Err(connecting) => Ok(Conn::established(connecting.await?)),
    }
}

/// Writes the tokenless hello and returns without waiting for the reply. The receive
/// half is handed back so the caller keeps it open.
async fn anonymous_hello(connection: &Connection) -> Result<RecvStream, HandshakeError> {
    let (mut send, recv) = connection.open_bi().await.map_err(map_close)?;
    send.write_all(ANON_HELLO)
        .await
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e)))?;
    send.finish()
        .map_err(|e| HandshakeError::Io(std::io::Error::other(e)))?;
    Ok(recv)
}

pub(crate) fn validate_credentials(
    token: Option<&str>,
    config: &ClientConfig,
) -> Result<(), ConnectError> {
    config.validate_with_token(token.is_some())?;
    config.validate()?;
    match token {
        Some(token) => validate_token(token),
        None => Ok(()),
    }
}

/// The server's handshake ack is exactly `OK\n`; anything else is a failure.
fn handshake_reply_ok(buf: &[u8]) -> bool {
    buf == b"OK\n"
}

/// Split `host:port` or `[v6-literal]:port`; the port must be a non-zero u16.
pub(crate) fn split_host_port(addr: &str) -> Result<(&str, &str), String> {
    let (host, port) = if let Some(rest) = addr.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("unterminated IPv6 literal in {addr}"))?;
        let port = after
            .strip_prefix(':')
            .ok_or_else(|| format!("missing port in {addr}"))?;
        (host, port)
    } else {
        addr.rsplit_once(':')
            .ok_or_else(|| format!("missing port in {addr}"))?
    };
    if host.is_empty() {
        return Err(format!("missing host in {addr}"));
    }
    match port.parse::<u16>() {
        Ok(p) if p != 0 => Ok((host, port)),
        _ => Err(format!("invalid port in {addr}")),
    }
}

/// Reject tokens the server's line-based handshake parser would refuse, so a bad token
/// fails locally with a clear error instead of an opaque server BadRequest.
pub(crate) fn validate_token(token: &str) -> Result<(), ConnectError> {
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

async fn send_on(conn: &Conn, bytes: &[u8]) -> Result<(), SendError> {
    let mut uni = conn.open_uni().await?;
    let sent = match uni.write_all(bytes).await {
        Ok(()) => {
            uni.finish()?;
            uni.stopped()
                .await
                .map(drop)
                .map_err(quinn::WriteError::from)
        }
        Err(e) => Err(e),
    };
    match sent {
        Ok(()) => Ok(()),
        // The uni path replays on a lost connection anyway; this only names the cause.
        Err(quinn::WriteError::ZeroRttRejected) => Err(early_failure(conn).into_error()),
        Err(e) => Err(e.into()),
    }
}

async fn send_on_timed(conn: &Conn, bytes: &[u8], timeout: Duration) -> Result<(), SendError> {
    tokio::time::timeout(timeout, send_on(conn, bytes))
        .await
        .map_err(|_| SendError::Timeout)?
}

enum Confirm {
    /// Nothing reached the server: the stream could not be opened, or its early data
    /// was discarded undelivered.
    NotSent(SendError),
    Failed(SendError),
}

impl Confirm {
    fn into_error(self) -> SendError {
        match self {
            Self::NotSent(e) | Self::Failed(e) => e,
        }
    }
}

async fn confirm_on_timed(conn: &Conn, bytes: &[u8], timeout: Duration) -> Result<(), Confirm> {
    tokio::time::timeout(timeout, confirm_on(conn, bytes))
        .await
        .map_err(|_| Confirm::Failed(SendError::Timeout))?
}

async fn confirm_on(conn: &Conn, bytes: &[u8]) -> Result<(), Confirm> {
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Confirm::NotSent(e.into()))?;
    // A stream-local stop of the upload is not an outcome; the verdict may still follow.
    match send.write_all(bytes).await {
        Ok(()) | Err(quinn::WriteError::Stopped(_) | quinn::WriteError::ClosedStream) => {}
        Err(quinn::WriteError::ZeroRttRejected) => return Err(early_failure(conn)),
        Err(e) => return Err(Confirm::Failed(e.into())),
    }
    let _ = send.finish();
    // At most 5 bytes are valid; a 6-byte buffer detects any extra byte.
    let mut buf = [0u8; 6];
    let mut len = 0;
    while len < buf.len() {
        match recv.read(&mut buf[len..]).await {
            Ok(Some(n)) => len += n,
            Ok(None) => break,
            Err(quinn::ReadError::ConnectionLost(e)) => {
                return Err(Confirm::Failed(SendError::ConnectionLost(e)));
            }
            Err(quinn::ReadError::ZeroRttRejected) => return Err(early_failure(conn)),
            Err(_) => return Err(Confirm::Failed(SendError::Rejected)),
        }
    }
    match &buf[..len] {
        [0x00] => Ok(()),
        [0x01, a, b, c, d] => Err(Confirm::Failed(SendError::RateLimited {
            retry_after: Duration::from_millis(u64::from(u32::from_le_bytes([*a, *b, *c, *d]))),
        })),
        _ => Err(Confirm::Failed(SendError::Rejected)),
    }
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
/// connection, a send timeout (which usually means the connection is wedged — a
/// path failure or flow-control stall QUIC has not yet surfaced).
const fn is_reconnectable_send_error(e: &SendError) -> bool {
    matches!(
        e,
        SendError::Timeout
            | SendError::ConnectionLost(_)
            | SendError::StreamWrite(quinn::WriteError::ConnectionLost(_))
    )
}

/// quinn fails every stream opened before establishment with `ZeroRttRejected` when
/// the connection ends unestablished — whether or not the server already read the
/// data. Only a version mismatch proves nothing was delivered; otherwise report the
/// real close reason and never resubmit.
fn early_failure(conn: &Conn) -> Confirm {
    match conn.close_reason() {
        Some(ConnectionError::VersionMismatch) => {
            Confirm::NotSent(SendError::ConnectionLost(ConnectionError::VersionMismatch))
        }
        Some(reason) => Confirm::Failed(SendError::ConnectionLost(reason)),
        None => Confirm::Failed(quinn::WriteError::ZeroRttRejected.into()),
    }
}

/// Reconnection-terminal: token auth failure, a client-side TLS/config error, or a TLS
/// handshake (crypto) failure such as an untrusted server certificate. Transport
/// failures (server down, reset, timeout, refused) are transient and retried with backoff.
const fn is_terminal(e: &ConnectError) -> bool {
    match e {
        ConnectError::Tls(_) => true,
        ConnectError::Handshake(h) => matches!(
            h,
            HandshakeError::Unauthorized
                | HandshakeError::Revoked
                | HandshakeError::BadRequest
                | HandshakeError::TokenlessUnsupported
        ),
        // TLS handshake (crypto) failure, such as an untrusted server certificate. Other
        // `ConnectionError` variants (Reset / TimedOut / ConnectionClosed / ...) and
        // `ConnectError::Dial` / `Resolve` remain transient.
        ConnectError::Connection(
            ConnectionError::TransportError(_) | ConnectionError::VersionMismatch,
        ) => true,
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
pub(crate) mod test_support {
    use {
        super::*,
        std::net::{Ipv4Addr, SocketAddr},
    };

    /// In-process QUIC server with a fresh self-signed cert for `127.0.0.1` that
    /// completes the QUIC handshake and then idles. Returns its address and a root
    /// store trusting it; with system roots the server is untrusted.
    pub(crate) async fn spawn_stub_server() -> (SocketAddr, Arc<rustls::RootCertStore>) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.cert.der().to_vec());
        let key_der = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.clone()).unwrap();

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
                    if let Ok(conn) = incoming.await {
                        conn.closed().await;
                    }
                });
            }
        });
        (addr, Arc::new(roots))
    }
}

#[cfg(test)]
mod terminal_tests {
    use super::*;

    #[tokio::test]
    async fn untrusted_cert_is_terminal() {
        let (addr, _roots) = test_support::spawn_stub_server().await;
        let config = ClientConfig::default();
        let endpoint = build_endpoint(addr, &config).unwrap();

        let err = dial_and_handshake(&endpoint, addr, "127.0.0.1", Some("tok"), config.security)
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
        assert!(is_terminal(&ConnectError::Connection(
            ConnectionError::VersionMismatch
        )));
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
        assert!(!is_reconnectable_send_error(&SendError::StreamWrite(
            quinn::WriteError::ZeroRttRejected
        )));
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

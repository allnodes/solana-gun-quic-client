use thiserror::Error;

/// Connection-establishment failures.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("address resolution failed: {0}")]
    Resolve(String),
    #[error("quic dial failed: {0}")]
    Dial(#[from] quinn::ConnectError),
    #[error("quic connection failed: {0}")]
    Connection(#[from] quinn::ConnectionError),
    #[error("handshake failed: {0}")]
    Handshake(#[from] HandshakeError),
    #[error("tls setup failed: {0}")]
    Tls(String),
    #[error("invalid client configuration: {0}")]
    Config(String),
    #[error("endpoint setup failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Token-handshake outcomes, derived from the server's connection-close code.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("unauthorized (unknown or invalid token)")]
    Unauthorized,
    #[error("too many connections for this token")]
    TooManyConnections,
    #[error("bad request")]
    BadRequest,
    #[error("revoked")]
    Revoked,
    #[error("handshake i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("handshake timed out")]
    Timeout,
    #[error("server closed with unexpected code {0:#x}")]
    Unexpected(u64),
}

/// Per-transaction send failures.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum SendError {
    #[error("transaction is {0} bytes, exceeds maximum {max}", max = crate::client::MAX_TX_BYTES)]
    TooLarge(usize),
    #[error("transaction send timed out")]
    Timeout,
    #[error("connection lost: {0}")]
    ConnectionLost(#[from] quinn::ConnectionError),
    #[error("stream write failed: {0}")]
    StreamWrite(#[from] quinn::WriteError),
    #[error("stream closed before finish: {0}")]
    StreamClosed(#[from] quinn::ClosedStream),
    #[error("reconnect failed: {0}")]
    Reconnect(#[from] ConnectError),
    #[error("reconnect gave up after {attempts} attempts; last error: {last}")]
    ReconnectExhausted {
        attempts: u32,
        last: Box<ConnectError>,
    },
}

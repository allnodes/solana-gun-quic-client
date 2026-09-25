#![forbid(unsafe_code)]

mod autoconfig;
mod client;
mod config;
mod error;
mod tls;

pub use autoconfig::{AutoConfig, DEFAULT_DISCOVERY_URL, EndpointSource, FallbackReason};
pub use client::SolanaGunQuicClient;
pub use config::{ClientConfig, ReconnectPolicy};
pub use error::{AutoConfigError, ConnectError, HandshakeError, SendError};
pub use rustls::RootCertStore;

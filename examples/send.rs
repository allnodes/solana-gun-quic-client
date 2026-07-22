//! Smoke test: dial the QUIC ingress and submit N dummy payloads, configured via
//! environment variables. Proves connectivity + token auth only — the dummy
//! bytes are rejected at decode by the server, which is expected.
//!
//! Usage:
//!   export HOST=fra-1.publicnode.com:7000
//!   export TOKEN=<token>
//!   export COUNT=4                       # optional, default 1
//!   cargo run --release --example send
//!
//! The server certificate is validated against system roots + hostname (standard TLS).

use solana_gun_quic_client::{ClientConfig, SolanaGunQuicClient};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = require_var("HOST")?;
    let token = require_var("TOKEN")?;
    let count: usize = match env::var("COUNT") {
        Ok(v) => v
            .parse()
            .map_err(|e| format!("COUNT must be a positive integer: {e}"))?,
        Err(_) => 1,
    };

    let config = ClientConfig::default();
    let client = SolanaGunQuicClient::connect(&host, &token, config).await?;
    for i in 0..count {
        // Dummy 64-byte payload (real callers send bincode VersionedTransaction bytes).
        client.send_transaction_bytes(&[0u8; 64]).await?;
        println!("sent {}", i + 1);
    }
    client.close().await;
    Ok(())
}

/// Read a required, non-empty environment variable.
fn require_var(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    match env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Err(format!("{name} is required (set it as an environment variable)").into()),
    }
}

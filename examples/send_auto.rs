//! Smoke test for endpoint autoconfiguration: discover and probe endpoints, connect to
//! the fastest, and submit N dummy payloads (rejected at decode by the server, which
//! is expected — this proves discovery, connectivity and token auth only).
//!
//! Usage:
//!   export TOKEN=<token>
//!   export DISCOVERY_URL=https://...              # optional, default: bundled URL
//!   export FALLBACK_HOST=fra1.solanagun.com:7000  # optional static fallback
//!   export COUNT=4                                # optional, default 1
//!   cargo run --release --example send_auto

use solana_gun_quic_client::{AutoConfig, ClientConfig, EndpointSource, SolanaGunQuicClient};
use std::env;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = require_var("TOKEN")?;
    let count: usize = match env::var("COUNT") {
        Ok(v) => v
            .parse()
            .map_err(|e| format!("COUNT must be a positive integer: {e}"))?,
        Err(_) => 1,
    };

    let mut auto = AutoConfig::default();
    if let Ok(url) = env::var("DISCOVERY_URL")
        && !url.is_empty()
    {
        auto.discovery_url = url;
    }
    if let Ok(host) = env::var("FALLBACK_HOST")
        && !host.is_empty()
    {
        auto.fallback_endpoint = Some(host);
    }
    println!("discovery url: {}", auto.discovery_url);

    let client = SolanaGunQuicClient::connect_auto(&token, ClientConfig::default(), auto).await?;
    match client.endpoint_source() {
        EndpointSource::Discovered {
            endpoint,
            addr,
            latency,
        } => println!(
            "connected to discovered endpoint {endpoint} ({addr}), probe latency {latency:?}"
        ),
        EndpointSource::Fallback { endpoint, reason } => {
            println!("connected to static fallback {endpoint} because: {reason}")
        }
        other => println!("connected via {other:?}"),
    }

    for i in 0..count {
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

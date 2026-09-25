# solana-gun-quic-client

Rust client for the Solana Gun QUIC transaction-submission ingress. Token-authenticated, standard TLS (WebPKI), fire-and-forget.

## What it does

- Opens a single QUIC connection to the ingress endpoint authenticated by a bearer token at handshake time.
- Sends serialized Solana `VersionedTransaction` bytes over short-lived uni-streams (one transaction per stream, ≤4096 bytes — the v1 transaction limit).
- Keeps the connection alive between transactions; no per-transaction handshake.
- Re-dials automatically when the connection drops and replays the failed send, with bounded jittered backoff.
- Surfaces authentication errors immediately so a stale token never silently retries forever.

The crate has no `solana-*` dependencies — callers serialize their own transactions and pass the bytes in.

## Quick start

```rust
use solana_gun_quic_client::{SolanaGunQuicClient, ClientConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::default();
    let client = SolanaGunQuicClient::connect("fra1.solanagun.com:7000", "my-token", config).await?;

    let tx_bytes: Vec<u8> = wincode::serialize(&my_transaction)?;
    client.send_transaction_bytes(&tx_bytes).await?;

    client.close().await;
    Ok(())
}
```

A runnable smoke test lives in `examples/send.rs`:

```
export HOST=fra1.solanagun.com:7000
export TOKEN=<token>
export COUNT=4                       # optional, default 1
cargo run --release --example send
```

## Endpoint autoconfiguration

Optional: use `connect_auto` instead of `connect` to let the client pick the endpoint.

- Fetches the endpoint list from the discovery API over HTTPS (default `https://www.allnodes.com/api/v1/solana-gun/discovery`).
- Probes every endpoint over QUIC and connects to the one with the lowest latency.
- Keeps that endpoint for the whole session (no runtime failover).

```rust
let mut auto = AutoConfig::default();
auto.discovery_url = "https://my-proxy.example/discovery".into(); // optional override
auto.fallback_endpoint = Some("fra1.solanagun.com:7000".into()); // optional static fallback

let client = SolanaGunQuicClient::connect_auto("my-token", ClientConfig::default(), auto).await?;
println!("{:?}", client.endpoint_source()); // Discovered { .. } or Fallback { reason, .. }
```

The static fallback is used when discovery fails, returns no usable endpoints, every probe fails, or the selected endpoint cannot connect. No fallback is bundled: without one, these cases return `ConnectError::AutoConfig` with the reason. The endpoint source and fallback reason are also logged via `tracing`.

A runnable smoke test lives in `examples/send_auto.rs` (`TOKEN` required; `DISCOVERY_URL`, `FALLBACK_HOST` optional).

## Full transfer example

`examples/transfer.rs` is a self-contained end-to-end demo: it loads your Solana keypair, fetches a recent blockhash, builds a v0 `VersionedTransaction` with two `SystemProgram::Transfer` instructions (recipient + tip), serializes it with `wincode` (byte-identical to bincode for legacy/v0, and the only codec that encodes v1), and submits it over the QUIC ingress. The Solana Gun production tip addresses are pre-filled; pick one via `TIP_INDEX`.

Edit the constants at the top of the file (`HOST`, `TOKEN`, `RECIPIENT`, `AMOUNT_LAMPORTS`, `TIP_INDEX`, `TIP_LAMPORTS`, `KEYPAIR_PATH`, `RPC_URL`) and run:

```
cargo run --example transfer
```

This is fire-and-forget: the example prints the locally-computed signature and exits. Confirm landing via `getSignatureStatus` / `getTransaction` on whichever cluster `RPC_URL` points at.

`examples/transfer_no_tip.rs` is the same flow with a single transfer and no tip — run it with `cargo run --example transfer_no_tip` using the same environment variables minus `TIP_ADDRESS` / `TIP_LAMPORTS`.

## Configuration

`ClientConfig::default()` returns sensible defaults (system roots trust); override fields directly to change behavior.

| Field | Default | Notes |
|---|---|---|
| `root_store` | `None` (system roots) | Override trust roots for tests; chain + hostname validation always runs. |
| `idle_timeout` | 30 s | Connection idle deadline (QUIC transport setting). |
| `keep_alive_interval` | 10 s | Must be `< idle_timeout`. |
| `send_timeout` | 10 s | Per-`send_transaction_bytes` budget; on timeout the connection is closed and reconnect kicks in. |
| `reconnect.enabled` | `true` | Set to `false` to opt out of automatic reconnection. |
| `reconnect.connect_timeout` | 10 s | Per-attempt ceiling on dial + handshake. |
| `reconnect.initial_backoff` | 100 ms | Doubled per attempt. |
| `reconnect.max_backoff` | 5 s | Equal-jitter applied to half the cap. |
| `reconnect.max_attempts` | `Some(10)` | `None` retries indefinitely; the default is finite so a stuck send returns within a bounded time. |

`ClientConfig::validate()` runs at connect time and rejects degenerate values (empty `root_store` override, zero durations, `keep_alive_interval >= idle_timeout`, `max_backoff < initial_backoff`).

## Error model

Errors split into three enums:

- **`ConnectError`** — dial/handshake/TLS/config failures; `AutoConfig` when autoconfiguration fails.
- **`HandshakeError`** — token outcome (`Unauthorized`, `Revoked`, `TooManyConnections`, `BadRequest`, `Timeout`, …).
- **`SendError`** — per-transaction failures, including reconnection results (`Reconnect`, `ReconnectExhausted`).

The reconnect loop distinguishes **terminal** from **transient**:

| Cause | Behavior |
|---|---|
| `HandshakeError::Unauthorized` (unknown token) | Terminal — caller must update the token. |
| `HandshakeError::Revoked` | Terminal — the server removed your token. |
| `HandshakeError::BadRequest` | Terminal — client/protocol mismatch. |
| `ConnectError::Tls(_)` or TLS handshake alert (e.g. untrusted server certificate) | Terminal. |
| `HandshakeError::TooManyConnections` | Transient — retried with backoff. |
| Network reset / timeout / refused / DNS hiccup | Transient — retried with backoff. |

A **stream-level** reset by the server (close code `0x10`, used for per-tx backpressure or oversized/decode failures) does **not** trigger a reconnect — the connection stays up and only that one stream is dropped.

## Protocol summary

| Property | Value |
|---|---|
| ALPN | `solana-gun-ingress/1` |
| TLS | 1.3 only, server cert validated against system roots + hostname (WebPKI) |
| Handshake | bidi stream: client sends `SOLANA-GUN-QUIC/1 <token>\n`, server replies `OK\n` then closes |
| Submission | one uni-stream per transaction, ≤ 4096 bytes (v1 transaction limit) |
| Server response | none (fire-and-forget) |
| Close codes | `0x01` unauthorized · `0x02` bad request · `0x03` too many connections · `0x04` revoked |
| Stream reset code | `0x10` (backpressure / oversized / decode failure) |

Maximum token length is 200 ASCII-graphic bytes (`MAX_TOKEN_BYTES`).

## MSRV

Edition 2024 (Rust 1.88+).

## License

Apache-2.0.
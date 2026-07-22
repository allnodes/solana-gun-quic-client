//! End-to-end example: build a plain SOL transfer (no tip) and submit it
//! through the QUIC ingress. Configuration is read from environment variables.
//! Fire-and-forget; prints the locally-computed signature and exits.
//!
//! Usage:
//!   export HOST=fra-1.publicnode.com:7000
//!   export TOKEN=<token>
//!   export RECIPIENT=<base58 recipient pubkey>
//!   export KEYPAIR_PATH=/path/to/keypair.json  # payer; supports ~
//!   export AMOUNT_LAMPORTS=1000000             # optional, default 10000
//!   export RPC_URL=https://api.mainnet-beta.solana.com   # optional, for blockhash
//!   cargo run --release --example transfer_no_tip
//!
//! This is the no-tip counterpart to `transfer.rs`: a single `SystemProgram::Transfer`
//! instruction, no tip. See `transfer.rs` for the tip-enabled variant.

use anyhow::{Context, anyhow, bail, ensure};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_gun_quic_client::{ClientConfig, SolanaGunQuicClient};
use solana_keypair::{Keypair, read_keypair_file};
use solana_message::{VersionedMessage, v0};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction::transfer;
use solana_transaction::versioned::VersionedTransaction;
use std::{env, path::PathBuf, str::FromStr};

const DEFAULT_AMOUNT_LAMPORTS: u64 = 10_000;
const DEFAULT_RPC_URL: &str = "https://api.mainnet-beta.solana.com";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Configuration from environment variables ─────────────────
    let host = require_var("HOST")?;
    let token = require_var("TOKEN")?;
    let recipient = Pubkey::from_str(&require_var("RECIPIENT")?)
        .context("RECIPIENT must be a base58 pubkey")?;
    let keypair_path = expand_tilde(&require_var("KEYPAIR_PATH")?)?;

    let amount_lamports = match env::var("AMOUNT_LAMPORTS") {
        Ok(v) => v.parse().context("AMOUNT_LAMPORTS must be a u64")?,
        Err(_) => DEFAULT_AMOUNT_LAMPORTS,
    };
    let rpc_url = env::var("RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());

    // ── Load payer keypair + fetch a recent blockhash ────────────
    let payer: Keypair = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow!("loading keypair from {}: {e}", keypair_path.display()))?;
    let payer_pubkey = payer.pubkey();

    let rpc = RpcClient::new(rpc_url.clone());
    let (blockhash, _) = rpc
        .get_latest_blockhash_with_commitment(CommitmentConfig::confirmed())
        .await
        .with_context(|| format!("fetching recent blockhash from {rpc_url}"))?;

    // ── Build + sign a v0 VersionedTransaction (single transfer) ──
    let ixs = vec![transfer(&payer_pubkey, &recipient, amount_lamports)];
    let message = v0::Message::try_compile(&payer_pubkey, &ixs, &[], blockhash)
        .context("compiling v0 message")?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[&payer])
        .context("signing transaction")?;
    let tx_bytes = bincode::serialize(&tx).context("bincode-serializing transaction")?;
    let signature = tx.signatures[0];

    // ── Pre-flight summary ───────────────────────────────────────
    println!("payer:     {payer_pubkey}");
    println!("recipient: {recipient}  amount: {amount_lamports} lamports");
    println!("tip:       (none)");
    println!("blockhash: {blockhash}");
    println!("connecting to {host} ...");

    // ── Connect to the QUIC ingress and fire-and-forget ──────────
    let config = ClientConfig::default();
    let client = SolanaGunQuicClient::connect(&host, &token, config).await?;
    client.send_transaction_bytes(&tx_bytes).await?;

    println!("sent. signature: {signature}");
    println!("note: fire-and-forget; confirm landing via getSignatureStatus / getTransaction");

    client.close().await;
    Ok(())
}

/// Read a required, non-empty environment variable.
fn require_var(name: &str) -> anyhow::Result<String> {
    match env::var(name) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => bail!("{name} is required (set it as an environment variable)"),
    }
}

/// Expand a leading `~/` to `$HOME`.
fn expand_tilde(path: &str) -> anyhow::Result<PathBuf> {
    ensure!(
        path != "~",
        "KEYPAIR_PATH '~' is ambiguous; use '~/' followed by a path"
    );
    if let Some(rest) = path.strip_prefix("~/") {
        let home = env::var("HOME").context("$HOME not set; cannot expand ~ in KEYPAIR_PATH")?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

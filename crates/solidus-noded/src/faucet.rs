//! Testnet faucet — the "funded path" an outsider needs to use a public v2
//! network without talking to us. One process holding one genesis-funded
//! dev key, exposing a JSON-RPC drip:
//!
//! ```text
//! curl -s http://<faucet> -H 'content-type: application/json' \
//!   -d '{"jsonrpc":"2.0","id":1,"method":"faucet_drip","params":["<base58 address>"]}'
//! ```
//!
//! Design mirrors `solidus-rpc2`: the logic (tx construction, rate limit)
//! is pure and unit-tested here; the async glue (nonce fetch → sign →
//! submit over HTTP) is thin and covered by the devnet end-to-end in
//! `docs/v2-validator-join.md`. Drips are serialized behind one lock so the
//! faucet account's nonce never races itself. **Testnet-grade by design**
//! (plain-hex key in config, in-memory rate map) — never hold real value.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use jsonrpsee::rpc_params;
use jsonrpsee::server::{RpcModule, Server};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::Mutex;

use solidus_crypto::ed25519::sign;
use solidus_crypto::keys::Address;
use solidus_exec::{wire, WireMode};
use solidus_txns::types::{Transaction, TxPayload};

/// Faucet configuration (`faucet.toml`).
#[derive(Deserialize, Clone)]
pub struct FaucetConfig {
    /// JSON-RPC URL of a v2 node, e.g. `http://127.0.0.1:8545`.
    pub rpc_url: String,
    /// HTTP bind address for the faucet itself, e.g. `127.0.0.1:8600`.
    pub bind_addr: String,
    /// The funded account's ed25519 secret (32-byte hex). DEV/TESTNET ONLY.
    pub secret_hex: String,
    /// Amount per drip (default 1_000_000 — 100 transfers' worth of fees).
    #[serde(default = "default_drip")]
    pub drip_amount: u64,
    /// Minimum seconds between drips to the same address (default 3600).
    #[serde(default = "default_interval")]
    pub min_interval_secs: u64,
}

fn default_drip() -> u64 {
    1_000_000
}
fn default_interval() -> u64 {
    3_600
}

/// Build and sign the drip Transfer for `mode` (pure - unit-tested below).
fn build_drip_tx(
    key: &SigningKey,
    nonce: u64,
    to: Address,
    amount: u64,
    mode: WireMode,
) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = wire::signing_bytes(&tx, mode);
    tx.signature = sign(key, &msg);
    tx
}

/// The signing wire the chain reports for its next block. A node older than
/// bridge plan 01 reports no `wire`, and it verifies BinaryV2.
pub(crate) fn wire_from_chain_info(info: &Value) -> std::result::Result<WireMode, String> {
    match info.get("wire").and_then(Value::as_str) {
        None | Some("binary-v2") => Ok(WireMode::BinaryV2),
        Some("binary-v3") => info
            .get("chainIdNumeric")
            .and_then(Value::as_u64)
            .map(|chain_id| WireMode::BinaryV3 { chain_id })
            .ok_or_else(|| "chainInfo reports binary-v3 without chainIdNumeric".to_string()),
        Some(other) => Err(format!("chainInfo reports an unknown wire: {other}")),
    }
}

/// Per-address rate limiter (pure — the clock is injected so tests don't
/// sleep). Entries older than the window are dropped on insert so the map
/// doesn't grow without bound.
struct RateLimiter {
    window: Duration,
    last: HashMap<String, Instant>,
}

impl RateLimiter {
    fn new(window: Duration) -> Self {
        Self {
            window,
            last: HashMap::new(),
        }
    }

    /// If `addr` may drip at `now`, record it and return `Ok`; otherwise
    /// return the remaining wait.
    fn check(&mut self, addr: &str, now: Instant) -> std::result::Result<(), Duration> {
        if let Some(&prev) = self.last.get(addr) {
            let elapsed = now.duration_since(prev);
            if elapsed < self.window {
                return Err(self.window - elapsed);
            }
        }
        self.last
            .retain(|_, &mut t| now.duration_since(t) < self.window);
        self.last.insert(addr.to_string(), now);
        Ok(())
    }
}

struct FaucetState {
    key: SigningKey,
    address: Address,
    drip_amount: u64,
    client: HttpClient,
    /// One lock over (rate map + the whole nonce-fetch→sign→submit flow) so
    /// concurrent drips can't reuse the faucet account's nonce.
    inner: Mutex<RateLimiter>,
}

fn rpc_err(code: i32, msg: String) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(code, msg, None::<()>)
}

/// The nonce a rejected drip should be rebuilt with, if it was rejected for its nonce.
///
/// ⛔ `solidus_submitTransaction` RETURNS BEFORE THE NONCE IS CHECKED. It accepts the
/// transaction into the mempool; `executor.rs` compares `tx.nonce` against the account
/// at EXECUTION. So a drip can be "submitted" and still fail, which is exactly what
/// happened on 2026-09-24: every drip returned a hash and every receipt read
/// `invalid nonce: expected N, got N-1`, because another transaction on the faucet
/// account landed between the nonce fetch and execution. The lock around the handler
/// could not prevent it: it is released when submit returns, and a nonce only advances
/// when a block executes.
///
/// The executor's own message carries the value it wanted, so a loser can retry exactly
/// once with it instead of guessing.
fn nonce_to_retry(failure_reason: &str) -> Option<u64> {
    let rest = failure_reason.strip_prefix("invalid nonce: expected ")?;
    let (want, _got) = rest.split_once(", got ")?;
    want.parse().ok()
}

async fn handle_drip(state: &FaucetState, params: &Value) -> Result<Value, ErrorObjectOwned> {
    let addr_str = params
        .as_array()
        .and_then(|a| a.first())
        .or_else(|| params.as_object().and_then(|o| o.get("address")))
        .and_then(Value::as_str)
        .ok_or_else(|| rpc_err(-32602, "missing param address".into()))?;
    let to = Address::from_base58(addr_str)
        .map_err(|_| rpc_err(-32602, format!("bad address: {addr_str}")))?;

    // Hold the lock across the entire flow (rate check + nonce + submit).
    let mut limiter = state.inner.lock().await;
    if let Err(wait) = limiter.check(addr_str, Instant::now()) {
        return Err(rpc_err(
            -32005,
            format!("rate limited: retry in {}s", wait.as_secs().max(1)),
        ));
    }

    let nonce: u64 = state
        .client
        .request("solidus_getNonce", rpc_params![state.address.to_base58()])
        .await
        .map_err(|e| rpc_err(-32010, format!("upstream nonce query failed: {e}")))?;

    let info: Value = state
        .client
        .request("solidus_chainInfo", rpc_params![])
        .await
        .map_err(|e| rpc_err(-32010, format!("upstream chainInfo query failed: {e}")))?;
    let mode = wire_from_chain_info(&info).map_err(|e| rpc_err(-32010, e))?;
    // ⛔ A SUBMITTED DRIP IS NOT A SUCCESSFUL DRIP. Confirm the receipt before saying so,
    // and retry exactly once if the nonce went stale under us. See `nonce_to_retry`.
    let mut next_nonce = nonce;
    let mut last_failure = String::from("no receipt");
    for attempt in 0..2 {
        let tx = build_drip_tx(&state.key, next_nonce, to, state.drip_amount, mode);
        #[allow(clippy::expect_used)] // fixed-shape serde struct; no error path
        let hex_tx = hex::encode(bincode::serialize(&tx).expect("Transaction bincode"));
        let tx_hash: String = state
            .client
            .request("solidus_submitTransaction", rpc_params![hex_tx])
            .await
            .map_err(|e| rpc_err(-32010, format!("upstream submit failed: {e}")))?;

        let receipt = await_receipt(state, &tx_hash).await?;
        if receipt.get("status").and_then(Value::as_str) == Some("success") {
            return Ok(json!({
                "txHash": tx_hash,
                "amount": state.drip_amount.to_string(),
                "blockHeight": receipt.get("blockHeight").cloned().unwrap_or(Value::Null),
            }));
        }
        last_failure = receipt
            .get("failureReason")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        match nonce_to_retry(&last_failure) {
            Some(want) if attempt == 0 => next_nonce = want,
            _ => break,
        }
    }
    Err(rpc_err(-32011, format!("drip failed: {last_failure}")))
}

/// Wait for a transaction's receipt. `solidus_getReceipt` answers `-32004 not found`
/// until the transaction is executed, so a short poll is the whole mechanism. Blocks
/// land about every 0.5 s; a drip that never lands is an error rather than a silent
/// success, which is the bug this whole path exists to stop.
async fn await_receipt(state: &FaucetState, tx_hash: &str) -> Result<Value, ErrorObjectOwned> {
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        if let Ok(receipt) = state
            .client
            .request::<Value, _>("solidus_getReceipt", rpc_params![tx_hash])
            .await
        {
            return Ok(receipt);
        }
    }
    Err(rpc_err(
        -32012,
        format!("no receipt for {tx_hash} within 6s"),
    ))
}

fn handle_info(state: &FaucetState) -> Value {
    json!({
        "address": state.address.to_base58(),
        "dripAmount": state.drip_amount.to_string(),
    })
}

pub async fn run(cfg: FaucetConfig) -> Result<()> {
    let secret: [u8; 32] = hex::decode(&cfg.secret_hex)
        .context("secret_hex: invalid hex")?
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("secret_hex: expected 32 bytes"))?;
    let key = SigningKey::from_bytes(&secret);
    let address = Address::from_public_key(&key.verifying_key());

    let client = HttpClientBuilder::default()
        .build(&cfg.rpc_url)
        .with_context(|| format!("rpc client for {}", cfg.rpc_url))?;

    let state = Arc::new(FaucetState {
        key,
        address,
        drip_amount: cfg.drip_amount,
        client,
        inner: Mutex::new(RateLimiter::new(Duration::from_secs(cfg.min_interval_secs))),
    });

    let mut module = RpcModule::new(Arc::clone(&state));
    module.register_async_method("faucet_drip", |params, ctx, _| async move {
        let value: Value = params.parse().unwrap_or(Value::Null);
        handle_drip(&ctx, &value).await
    })?;
    module.register_method("faucet_info", |_, ctx, _| {
        Ok::<_, ErrorObjectOwned>(handle_info(ctx))
    })?;

    let addr: SocketAddr = cfg
        .bind_addr
        .parse()
        .with_context(|| format!("bad bind_addr {}", cfg.bind_addr))?;
    let server = Server::builder().build(addr).await?;
    let bound = server.local_addr()?;
    let handle = server.start(module);
    println!(
        "faucet up on http://{bound} — account {} drips {} (min interval {}s) via {}",
        address.to_base58(),
        cfg.drip_amount,
        cfg.min_interval_secs,
        cfg.rpc_url
    );
    handle.stopped().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use solidus_crypto::ed25519::{generate_signing_key, verify};

    use super::*;

    #[test]
    fn drip_tx_is_well_formed_and_verifiable() {
        let key = generate_signing_key();
        let to = Address::from_bytes([7; 20]);
        let tx = build_drip_tx(&key, 42, to, 1_000_000, WireMode::BinaryV2);

        assert_eq!(tx.nonce, 42);
        assert!(matches!(
            tx.payload,
            TxPayload::Transfer { to: t, amount: 1_000_000 } if t == to
        ));
        // Signature verifies over the v2 binary signing bytes.
        let msg = wire::signing_bytes(&tx, WireMode::BinaryV2);
        assert!(verify(&key.verifying_key(), &msg, &tx.signature));
        // And the wire encoding round-trips (what the RPC edge decodes).
        let bytes = bincode::serialize(&tx).expect("encode");
        let back: Transaction = bincode::deserialize(&bytes).expect("decode");
        assert_eq!(back, tx);
    }

    #[test]
    fn rate_limiter_blocks_within_window_and_recovers() {
        let mut rl = RateLimiter::new(Duration::from_secs(60));
        let t0 = Instant::now();

        assert!(rl.check("addr-a", t0).is_ok(), "first drip allowed");
        let wait = rl.check("addr-a", t0 + Duration::from_secs(10));
        assert!(
            matches!(wait, Err(w) if w == Duration::from_secs(50)),
            "second drip inside the window reports the remaining wait"
        );
        assert!(rl.check("addr-b", t0).is_ok(), "other addresses unaffected");
        assert!(
            rl.check("addr-a", t0 + Duration::from_secs(60)).is_ok(),
            "window elapsed → allowed again"
        );
    }

    #[test]
    fn rate_limiter_prunes_expired_entries() {
        let mut rl = RateLimiter::new(Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..100 {
            assert!(rl.check(&format!("addr-{i}"), t0).is_ok());
        }
        // A new drip far past the window prunes all stale entries.
        assert!(rl.check("fresh", t0 + Duration::from_secs(120)).is_ok());
        assert_eq!(rl.last.len(), 1, "expired entries pruned on insert");
    }

    #[test]
    fn config_defaults_apply() {
        let cfg: FaucetConfig = toml::from_str(
            r#"
            rpc_url = "http://127.0.0.1:8545"
            bind_addr = "127.0.0.1:8600"
            secret_hex = "00"
            "#,
        )
        .expect("parse");
        assert_eq!(cfg.drip_amount, 1_000_000);
        assert_eq!(cfg.min_interval_secs, 3_600);
    }

    #[test]
    fn drip_tx_verifies_only_under_the_wire_it_was_built_for() {
        let key = generate_signing_key();
        let to = Address::from_bytes([7; 20]);
        let v3 = WireMode::BinaryV3 { chain_id: 50_002 };
        let tx = build_drip_tx(&key, 1, to, 5, v3);
        assert!(wire::verify_signature(&tx, v3));
        assert!(!wire::verify_signature(&tx, WireMode::BinaryV2));
        assert!(!wire::verify_signature(
            &tx,
            WireMode::BinaryV3 { chain_id: 50_003 }
        ));
    }

    #[test]
    fn the_signing_wire_is_read_from_chain_info() {
        assert_eq!(
            wire_from_chain_info(&json!({ "wire": "binary-v3", "chainIdNumeric": 50_002 })),
            Ok(WireMode::BinaryV3 { chain_id: 50_002 })
        );
        assert_eq!(
            wire_from_chain_info(&json!({ "wire": "binary-v2", "chainIdNumeric": 50_002 })),
            Ok(WireMode::BinaryV2)
        );
        assert_eq!(
            wire_from_chain_info(&json!({ "chain_id": "solidus-testnet" })),
            Ok(WireMode::BinaryV2),
            "a node older than this plan reports no wire"
        );
        assert!(wire_from_chain_info(&json!({ "wire": "binary-v3" }))
            .unwrap_err()
            .contains("chainIdNumeric"));
        assert!(
            wire_from_chain_info(&json!({ "wire": "binary-v9", "chainIdNumeric": 1 }))
                .unwrap_err()
                .contains("unknown wire")
        );
    }

    /// ⛔ EVERY DRIP FAILED IN PRODUCTION ON 2026-09-24 AND THE FAUCET REPORTED SUCCESS.
    /// `solidus_submitTransaction` returns a hash as soon as the tx is accepted into the
    /// mempool, but the nonce is checked at EXECUTION. The old handler returned that hash
    /// and never looked at the receipt, so a drip that failed with
    /// `invalid nonce: expected 3, got 2` was indistinguishable from one that worked.
    /// The executor's message carries the nonce it wanted, so a losing drip can say so.
    #[test]
    fn a_nonce_failure_reports_the_nonce_to_retry_with() {
        assert_eq!(nonce_to_retry("invalid nonce: expected 3, got 2"), Some(3));
        assert_eq!(nonce_to_retry("invalid nonce: expected 0, got 41"), Some(0));
    }

    #[test]
    fn only_a_nonce_failure_is_retryable() {
        assert_eq!(
            nonce_to_retry("insufficient balance for fee: have 0, need 1"),
            None
        );
        assert_eq!(nonce_to_retry(""), None);
        // Shape-alike that is NOT the executor's nonce message.
        assert_eq!(nonce_to_retry("invalid nonce: expected soon"), None);
    }
}

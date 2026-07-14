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

/// Build and sign the drip Transfer (pure — unit-tested below).
fn build_drip_tx(key: &SigningKey, nonce: u64, to: Address, amount: u64) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = wire::signing_bytes(&tx, WireMode::BinaryV2);
    tx.signature = sign(key, &msg);
    tx
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

    let tx = build_drip_tx(&state.key, nonce, to, state.drip_amount);
    #[allow(clippy::expect_used)] // fixed-shape serde struct; no error path
    let hex_tx = hex::encode(bincode::serialize(&tx).expect("Transaction bincode"));
    let tx_hash: String = state
        .client
        .request("solidus_submitTransaction", rpc_params![hex_tx])
        .await
        .map_err(|e| rpc_err(-32010, format!("upstream submit failed: {e}")))?;

    Ok(json!({ "txHash": tx_hash, "amount": state.drip_amount.to_string() }))
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
        let tx = build_drip_tx(&key, 42, to, 1_000_000);

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
}

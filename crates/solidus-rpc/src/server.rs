use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::{header, HeaderValue, Method};
use jsonrpsee::server::{Server, ServerHandle};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::{info, warn};

use solidus_consensus::mempool::Mempool;
use solidus_consensus::types::ValidatorIdentity;
use solidus_state::store::Store;
use solidus_txns::types::Transaction;

use crate::methods::{ChainMeta, SolidusApiServer, SolidusRpcImpl};

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Build the CORS layer for the RPC HTTP server from the `SOLIDUS_RPC_CORS` env
/// var — a comma-separated allowlist of browser origins (e.g.
/// `https://node.solidus.network`). An empty/unset value allows NO cross-origin
/// browser request (identical to having no CORS), so non-browser RPC clients and
/// the default deployment are unaffected. Operators who want to drive their node
/// from the hosted dashboard set this to that origin. Never use `*`; keep the RPC
/// bound to `127.0.0.1`.
fn rpc_cors_layer() -> CorsLayer {
    let origins: Vec<HeaderValue> = std::env::var("SOLIDUS_RPC_CORS")
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|s| HeaderValue::from_str(s).ok())
        .collect();
    if !origins.is_empty() {
        info!(
            count = origins.len(),
            "RPC CORS enabled for configured origins"
        );
    }
    CorsLayer::new()
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE])
        .allow_origin(AllowOrigin::list(origins))
}

// ---------------------------------------------------------------------------
// Server startup
// ---------------------------------------------------------------------------

/// Start the JSON-RPC server and return a handle + the actual local address.
///
/// The caller should hold onto the [`ServerHandle`] to keep the server running
/// and call `handle.stop()` for a graceful shutdown.
///
/// `committee` is the in-process consensus committee: it is unioned with the
/// on-chain validator set for `solidus_getValidators` so dev/testnet
/// deployments (which produce blocks without staking transactions) still
/// surface the active voters. Pass an empty `Vec` when no consensus engine
/// is attached.
///
/// `chain_meta` is the static chain metadata (id, native token, version)
/// surfaced by `solidus_chainInfo`.
///
/// `tx_broadcast` is the optional fan-out channel for transactions
/// submitted via `solidus_sendTransaction`. Pass `Some(sender)` from the
/// consensus / full-node path so submitted txs reach other nodes via the
/// libp2p `txs` gossipsub topic; `None` for tests / standalone RPC.
///
/// `tx_wake` is fired (`notify_waiters`) whenever `solidus_sendTransaction`
/// accepts a tx, so an idle event-driven consensus loop proposes
/// immediately. Pass a fresh `Notify` when no consensus loop listens.
#[allow(clippy::too_many_arguments)]
pub async fn start_rpc_server(
    listen_addr: SocketAddr,
    store: Arc<Store>,
    mempool: Arc<Mutex<Mempool>>,
    latest_height: Arc<Mutex<u64>>,
    committee: Arc<Vec<ValidatorIdentity>>,
    chain_meta: ChainMeta,
    tx_broadcast: Option<tokio::sync::mpsc::UnboundedSender<Transaction>>,
    tx_wake: Arc<tokio::sync::Notify>,
) -> Result<(ServerHandle, SocketAddr), Box<dyn std::error::Error + Send + Sync>> {
    let middleware = tower::ServiceBuilder::new().layer(rpc_cors_layer());
    let server = Server::builder()
        .set_http_middleware(middleware)
        .build(listen_addr)
        .await?;

    let local_addr = server.local_addr()?;
    info!("JSON-RPC server listening on {local_addr}");

    // Subject enumeration is opt-in via the environment rather than a parameter.
    // `start_rpc_server` has six call sites, five of them tests, and threading a
    // bool through all of them is how a secure default gets passed wrong once and
    // never noticed. An env var also lets an operator open it without a rebuild,
    // which is what makes the refusal message ("run a node with subject
    // enumeration explicitly enabled") a true statement rather than a dead end.
    //
    // Anything other than exactly "1" or "true" leaves it closed, including the
    // empty string, so a blank entry in a unit file does not silently open it.
    let allow_subject_enumeration = std::env::var("SOLIDUS_RPC_ALLOW_SUBJECT_ENUMERATION")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true"
        })
        .unwrap_or(false);
    if allow_subject_enumeration {
        warn!(
            "solidus_credentialsBySubject is ENABLED: any caller can enumerate every \
             credential held by a given subject DID. Intended for local development."
        );
    }

    let rpc_impl = SolidusRpcImpl::new(
        store,
        mempool,
        latest_height,
        committee,
        chain_meta,
        tx_broadcast,
        tx_wake,
    )
    .with_subject_enumeration(allow_subject_enumeration);
    let handle = server.start(rpc_impl.into_rpc());

    Ok((handle, local_addr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn server_starts_and_stops() {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let latest_height = Arc::new(Mutex::new(0u64));

        // Bind to port 0 so the OS picks a random free port.
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

        let committee = Arc::new(Vec::new());
        let (handle, local_addr) = start_rpc_server(
            addr,
            store,
            mempool,
            latest_height,
            committee,
            ChainMeta::default(),
            None, // standalone test — no tx broadcast
            Arc::new(tokio::sync::Notify::new()),
        )
        .await
        .expect("server should start");

        assert_ne!(local_addr.port(), 0, "should have a real port");

        // Graceful shutdown.
        handle.stop().expect("server should stop");
    }
}

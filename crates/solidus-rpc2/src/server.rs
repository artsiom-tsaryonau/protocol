//! The `jsonrpsee` HTTP binding: registers the [`crate::methods`] handlers
//! under the `solidus_` namespace and serves them. This is the only async
//! / transport code in the crate; all logic lives in the pure handlers.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{RpcModule, Server, ServerHandle};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde_json::Value;

use crate::backend::RpcBackend;
use crate::methods::{self, RpcError};

type Ctx = Arc<dyn RpcBackend>;

fn to_rpc_error(e: RpcError) -> ErrorObjectOwned {
    let code = match e {
        RpcError::InvalidParams(_) => -32602,
        RpcError::NotFound => -32004,
        RpcError::SubmitRejected(_) => -32003,
    };
    ErrorObjectOwned::owned(code, e.to_string(), None::<()>)
}

/// Build the RPC module (registered methods) over a backend. Separated
/// from [`serve`] so it can be tested without binding a socket.
pub fn build_module(backend: Ctx) -> RpcModule<Ctx> {
    let mut module = RpcModule::new(backend);

    macro_rules! register {
        ($name:literal, $handler:path) => {
            module
                .register_method($name, |params, ctx, _| {
                    let value: Value = params.parse().unwrap_or(Value::Null);
                    $handler(ctx.as_ref(), &value).map_err(to_rpc_error)
                })
                .expect("method name is unique");
        };
    }

    register!("solidus_getBalance", methods::get_balance);
    register!("solidus_getNonce", methods::get_nonce);
    register!("solidus_getBlockHeight", methods::get_block_height);
    register!("solidus_getStateRoot", methods::get_state_root);
    register!("solidus_getReceipt", methods::get_receipt);
    register!("solidus_submitTransaction", methods::submit_transaction);

    module
}

/// Bind and start the JSON-RPC server. Returns the bound address (useful
/// when `addr` used port 0) and the handle (drop or `.stop()` to shut
/// down).
pub async fn serve(
    addr: SocketAddr,
    backend: Ctx,
) -> Result<(SocketAddr, ServerHandle), std::io::Error> {
    let server = Server::builder().build(addr).await?;
    let bound = server.local_addr()?;
    let handle = server.start(build_module(backend));
    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_exec::{Account, AccountType, StateKey, WireMode};
    use solidus_store2::{Profile, Store2};
    use solidus_txns::types::{Transaction, TxPayload};

    use super::*;
    use crate::backend::Store2Backend;

    /// End-to-end: a real Store2-backed backend behind a live HTTP server,
    /// queried by a real HTTP client. Proves the whole edge, not just the
    /// handlers.
    #[tokio::test]
    async fn live_server_serves_reads_and_submit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store2::open(dir.path(), Profile::Testnet).expect("store"));

        // Seed one funded account into committed state.
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        let acct = Account::with_balance(addr, 5_000_000, AccountType::Regular);
        store
            .seed_state(&StateKey::account(&addr), &acct.to_bytes())
            .expect("seed");

        let anchor = Arc::new(Mutex::new((7u64, [0x42u8; 32])));
        let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let sink = Arc::clone(&submitted);
        let backend: Ctx = Arc::new(Store2Backend::new(
            Arc::clone(&store),
            Arc::clone(&anchor),
            move |tx| {
                let hash = solidus_exec::wire::tx_hash(&tx, WireMode::BinaryV2);
                sink.lock().expect("lock").push(tx);
                Ok(hash)
            },
        ));

        let (bound, handle) = serve("127.0.0.1:0".parse().unwrap(), backend)
            .await
            .expect("serve");
        let url = format!("http://{bound}");
        let client = HttpClientBuilder::default().build(&url).expect("client");

        // Reads.
        let balance: String = client
            .request("solidus_getBalance", rpc_params![addr.to_base58()])
            .await
            .expect("balance");
        assert_eq!(balance, "5000000");

        let height: u64 = client
            .request("solidus_getBlockHeight", rpc_params![])
            .await
            .expect("height");
        assert_eq!(height, 7);

        let root: String = client
            .request("solidus_getStateRoot", rpc_params![])
            .await
            .expect("root");
        assert_eq!(root, hex::encode([0x42u8; 32]));

        // Submit a genuine signed transfer.
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([9; 20]),
                amount: 1_000,
            },
            signature: [0u8; 64],
        };
        let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
        tx.signature = sign(&key, &msg);
        let hex_tx = hex::encode(bincode::serialize(&tx).unwrap());

        let returned_hash: String = client
            .request("solidus_submitTransaction", rpc_params![hex_tx])
            .await
            .expect("submit");
        assert_eq!(
            returned_hash,
            hex::encode(solidus_exec::wire::tx_hash(&tx, WireMode::BinaryV2))
        );
        assert_eq!(
            submitted.lock().expect("lock").len(),
            1,
            "tx reached the sink"
        );

        // A tampered (bad-signature) submit is rejected at the edge.
        let mut bad = tx.clone();
        bad.signature[0] ^= 0xFF;
        let bad_hex = hex::encode(bincode::serialize(&bad).unwrap());
        let err: Result<String, _> = client
            .request("solidus_submitTransaction", rpc_params![bad_hex])
            .await;
        assert!(err.is_err(), "bad-signature submit must be rejected");
        assert_eq!(
            submitted.lock().expect("lock").len(),
            1,
            "rejected tx never reached the sink"
        );

        handle.stop().expect("stop");
    }
}

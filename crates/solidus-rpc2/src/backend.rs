//! What the RPC edge needs from the node, and a Store2-backed impl.

use std::sync::{Arc, Mutex};

use solidus_crypto::keys::Address;
use solidus_exec::{Account, StateKey, StateReader};
use solidus_store2::Store2;
use solidus_txns::types::{Receipt, Transaction};

/// The node capabilities the JSON-RPC edge exposes. Reads are over
/// **committed** state (store2's persisted CFs); submit hands a
/// signature-checked-elsewhere tx into the mempool.
pub trait RpcBackend: Send + Sync + 'static {
    /// Committed balance of `addr` (0 if the account was never seen).
    fn balance(&self, addr: &Address) -> u64;
    /// Committed nonce of `addr`.
    fn nonce(&self, addr: &Address) -> u64;
    /// Newest committed block height.
    fn block_height(&self) -> u64;
    /// Global state root at the newest committed height.
    fn state_root(&self) -> [u8; 32];
    /// Receipt for a tx by (height, tx hash), if persisted.
    fn receipt(&self, height: u64, tx_hash: &[u8; 32]) -> Option<Receipt>;
    /// Submit a transaction to the mempool. Returns the v2 tx hash.
    fn submit(&self, tx: Transaction) -> Result<[u8; 32], String>;
}

/// Reads from a shared [`Store2`]; height/root from a shared exec anchor
/// (kept current by the node's commit path); submit through a callback
/// (the node wires this to `NodeInput::SubmitTx`).
pub struct Store2Backend {
    store: Arc<Store2>,
    /// (height, global root) of the newest executed block.
    anchor: Arc<Mutex<(u64, [u8; 32])>>,
    submit: Box<dyn Fn(Transaction) -> Result<[u8; 32], String> + Send + Sync>,
    wire: solidus_exec::WireMode,
}

impl Store2Backend {
    pub fn new(
        store: Arc<Store2>,
        anchor: Arc<Mutex<(u64, [u8; 32])>>,
        submit: impl Fn(Transaction) -> Result<[u8; 32], String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            store,
            anchor,
            submit: Box::new(submit),
            wire: solidus_exec::WireMode::BinaryV2,
        }
    }

    fn account(&self, addr: &Address) -> Account {
        match self.store.get(&StateKey::account(addr)) {
            Ok(Some(bytes)) => Account::from_bytes(&bytes).unwrap_or_else(|_| Account::new(*addr)),
            _ => Account::new(*addr),
        }
    }
}

impl RpcBackend for Store2Backend {
    fn balance(&self, addr: &Address) -> u64 {
        self.account(addr).balance
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.account(addr).nonce
    }

    fn block_height(&self) -> u64 {
        #[allow(clippy::expect_used)]
        self.anchor.lock().expect("anchor poisoned").0
    }

    fn state_root(&self) -> [u8; 32] {
        #[allow(clippy::expect_used)]
        self.anchor.lock().expect("anchor poisoned").1
    }

    fn receipt(&self, height: u64, tx_hash: &[u8; 32]) -> Option<Receipt> {
        self.store.receipt(height, tx_hash).ok().flatten()
    }

    fn submit(&self, tx: Transaction) -> Result<[u8; 32], String> {
        // Reject an unsigned/garbage tx at the edge (the mempool + executor
        // re-check, but a fast edge rejection saves a round trip).
        if !solidus_exec::wire::verify_signature(&tx, self.wire) {
            return Err("invalid signature".to_string());
        }
        (self.submit)(tx)
    }
}

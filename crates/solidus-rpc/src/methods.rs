use std::sync::{Arc, Mutex};

use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::types::ErrorObjectOwned;
use tracing::error;

use solidus_consensus::mempool::Mempool;
use solidus_consensus::types::Block;
use solidus_crypto::keys::Address;
use solidus_state::executor::load_account;
use solidus_state::store::{Store, CF_BLOCKS, CF_RECEIPTS};
use solidus_txns::types::{Receipt, Transaction};

use crate::types::{RpcBlock, RpcReceipt};

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

/// JSON-RPC error code for invalid parameters.
const INVALID_PARAMS: i32 = -32602;
/// JSON-RPC error code for internal errors.
const INTERNAL_ERROR: i32 = -32603;

fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INVALID_PARAMS, msg.into(), None::<()>)
}

fn internal_error(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(INTERNAL_ERROR, msg.into(), None::<()>)
}

// ---------------------------------------------------------------------------
// Trait definition (jsonrpsee proc macro generates SolidusApiServer)
// ---------------------------------------------------------------------------

#[rpc(server)]
pub trait SolidusApi {
    /// Return the balance (in smallest units) for the given base58 address.
    #[method(name = "solidus_getBalance")]
    fn get_balance(&self, address: String) -> RpcResult<u64>;

    /// Return the current nonce for the given base58 address.
    #[method(name = "solidus_getNonce")]
    fn get_nonce(&self, address: String) -> RpcResult<u64>;

    /// Submit a signed transaction (JSON-encoded). Returns the transaction
    /// hash as a hex string.
    #[method(name = "solidus_sendTransaction")]
    fn send_transaction(&self, tx_json: String) -> RpcResult<String>;

    /// Return a block by height, or `null` if it does not exist.
    #[method(name = "solidus_getBlock")]
    fn get_block(&self, height: u64) -> RpcResult<Option<RpcBlock>>;

    /// Return the latest committed block, or `null` if no blocks exist.
    #[method(name = "solidus_getLatestBlock")]
    fn get_latest_block(&self) -> RpcResult<Option<RpcBlock>>;

    /// Return the receipt for a transaction identified by its hex hash.
    #[method(name = "solidus_getReceipt")]
    fn get_receipt(&self, tx_hash: String) -> RpcResult<Option<RpcReceipt>>;

    /// Return the full transaction JSON for a transaction identified by its
    /// hex hash. Scans blocks backwards from latest — acceptable for testnet.
    #[method(name = "solidus_getTransaction")]
    fn get_transaction(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/// Holds shared state required by the RPC methods.
pub struct SolidusRpcImpl {
    pub store: Arc<Store>,
    pub mempool: Arc<Mutex<Mempool>>,
    pub latest_height: Arc<Mutex<u64>>,
}

impl SolidusRpcImpl {
    /// Create a new RPC implementation with shared state.
    pub fn new(
        store: Arc<Store>,
        mempool: Arc<Mutex<Mempool>>,
        latest_height: Arc<Mutex<u64>>,
    ) -> Self {
        Self {
            store,
            mempool,
            latest_height,
        }
    }

    /// Load a block from the store by height.
    fn load_block(&self, height: u64) -> RpcResult<Option<Block>> {
        let key = height.to_le_bytes();
        let bytes = self
            .store
            .get(CF_BLOCKS, &key)
            .map_err(|e| {
                error!("failed to read block at height {height}: {e}");
                internal_error(format!("store error: {e}"))
            })?;

        match bytes {
            None => Ok(None),
            Some(data) => {
                let block: Block = serde_json::from_slice(&data).map_err(|e| {
                    error!("failed to deserialize block at height {height}: {e}");
                    internal_error(format!("deserialization error: {e}"))
                })?;
                Ok(Some(block))
            }
        }
    }
}

impl SolidusApiServer for SolidusRpcImpl {
    fn get_balance(&self, address: String) -> RpcResult<u64> {
        let addr = Address::from_base58(&address)
            .map_err(|e| invalid_params(format!("invalid address: {e}")))?;

        let account = load_account(&self.store, &addr)
            .map_err(|e| {
                error!("failed to load account {address}: {e}");
                internal_error(format!("store error: {e}"))
            })?;

        Ok(account.balance)
    }

    fn get_nonce(&self, address: String) -> RpcResult<u64> {
        let addr = Address::from_base58(&address)
            .map_err(|e| invalid_params(format!("invalid address: {e}")))?;

        let account = load_account(&self.store, &addr)
            .map_err(|e| {
                error!("failed to load account {address}: {e}");
                internal_error(format!("store error: {e}"))
            })?;

        Ok(account.nonce)
    }

    fn send_transaction(&self, tx_json: String) -> RpcResult<String> {
        let tx: Transaction = serde_json::from_str(&tx_json)
            .map_err(|e| invalid_params(format!("invalid transaction JSON: {e}")))?;

        if !tx.verify_signature() {
            return Err(invalid_params("invalid transaction signature"));
        }

        let tx_hash = tx.hash();
        let hex_hash = hex::encode(tx_hash);

        let mut pool = self.mempool.lock().map_err(|e| {
            error!("mempool lock poisoned: {e}");
            internal_error("internal error")
        })?;

        if !pool.insert(tx) {
            return Err(invalid_params(
                "transaction rejected: duplicate or mempool full",
            ));
        }

        Ok(hex_hash)
    }

    fn get_block(&self, height: u64) -> RpcResult<Option<RpcBlock>> {
        let block = self.load_block(height)?;
        Ok(block.as_ref().map(RpcBlock::from_block))
    }

    fn get_latest_block(&self) -> RpcResult<Option<RpcBlock>> {
        let height = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;

        if height == 0 {
            // Check if genesis block exists at height 0.
            return self.get_block(0);
        }

        self.get_block(height)
    }

    fn get_receipt(&self, tx_hash: String) -> RpcResult<Option<RpcReceipt>> {
        let hash_bytes = hex::decode(&tx_hash)
            .map_err(|e| invalid_params(format!("invalid hex hash: {e}")))?;

        if hash_bytes.len() != 32 {
            return Err(invalid_params(format!(
                "invalid hash length: expected 32 bytes, got {}",
                hash_bytes.len()
            )));
        }

        let bytes = self
            .store
            .get(CF_RECEIPTS, &hash_bytes)
            .map_err(|e| {
                error!("failed to read receipt for {tx_hash}: {e}");
                internal_error(format!("store error: {e}"))
            })?;

        match bytes {
            None => Ok(None),
            Some(data) => {
                let receipt: Receipt = serde_json::from_slice(&data).map_err(|e| {
                    error!("failed to deserialize receipt for {tx_hash}: {e}");
                    internal_error(format!("deserialization error: {e}"))
                })?;
                Ok(Some(RpcReceipt::from_receipt(&receipt)))
            }
        }
    }

    fn get_transaction(&self, tx_hash: String) -> RpcResult<Option<serde_json::Value>> {
        let hash_bytes = hex::decode(&tx_hash)
            .map_err(|e| invalid_params(format!("invalid hex hash: {e}")))?;

        if hash_bytes.len() != 32 {
            return Err(invalid_params(format!(
                "invalid hash length: expected 32 bytes, got {}",
                hash_bytes.len()
            )));
        }

        let mut target_hash = [0u8; 32];
        target_hash.copy_from_slice(&hash_bytes);

        let latest = *self.latest_height.lock().map_err(|e| {
            error!("latest_height lock poisoned: {e}");
            internal_error("internal error")
        })?;

        // Scan blocks backwards from latest to 0, looking for the tx.
        // This is O(blocks) which is acceptable for testnet.
        let mut height = latest;
        loop {
            if let Some(block) = self.load_block(height)? {
                for tx in &block.transactions {
                    if tx.hash() == target_hash {
                        let value = serde_json::to_value(tx).map_err(|e| {
                            error!("failed to serialize transaction: {e}");
                            internal_error(format!("serialization error: {e}"))
                        })?;
                        return Ok(Some(value));
                    }
                }
            }

            if height == 0 {
                break;
            }
            height -= 1;
        }

        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_consensus::types::{Block, BlockHeader};
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::TxPayload;
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> (Arc<Store>, tempfile::TempDir) {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Store::open(dir.path()).expect("failed to open store");
        (Arc::new(store), dir)
    }

    /// Helper: create an RPC impl with default shared state.
    fn make_rpc(store: Arc<Store>) -> SolidusRpcImpl {
        SolidusRpcImpl::new(
            store,
            Arc::new(Mutex::new(Mempool::new())),
            Arc::new(Mutex::new(0)),
        )
    }

    /// Helper: build a signed Transfer transaction.
    fn make_transfer_tx(
        sender_key: &ed25519_dalek::SigningKey,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::Transfer { to, amount };

        let mut tx = Transaction {
            sender_pubkey: pubkey,
            nonce,
            payload,
            signature: [0u8; 64],
        };

        let msg = tx.signing_bytes();
        tx.signature = sign(sender_key, &msg);
        tx
    }

    #[test]
    fn get_balance_default_account() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let addr = Address::from_bytes([0xAA; 20]);
        let balance = rpc.get_balance(addr.to_base58()).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn get_balance_invalid_address() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_balance("not-valid-base58!!!".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn send_transaction_and_verify() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let sender = generate_signing_key();
        let to = Address::from_bytes([0xBB; 20]);
        let tx = make_transfer_tx(&sender, to, 100, 0);
        let expected_hash = hex::encode(tx.hash());

        let tx_json = serde_json::to_string(&tx).unwrap();
        let result = rpc.send_transaction(tx_json).unwrap();
        assert_eq!(result, expected_hash);

        // Verify it's in the mempool.
        let pool = rpc.mempool.lock().unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn send_transaction_bad_signature_rejected() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let tx = Transaction {
            sender_pubkey: [1u8; 32],
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([0xBB; 20]),
                amount: 100,
            },
            signature: [0u8; 64],
        };

        let tx_json = serde_json::to_string(&tx).unwrap();
        let result = rpc.send_transaction(tx_json);
        assert!(result.is_err());
    }

    #[test]
    fn get_block_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_block(999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_block_after_store() {
        let (store, _dir) = open_tmp();

        // Store a block at height 1.
        let block = Block {
            header: BlockHeader {
                height: 1,
                parent_hash: [0u8; 32],
                state_root: [0xAA; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
            },
            transactions: vec![],
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &1u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 1;

        let result = rpc.get_block(1).unwrap();
        assert!(result.is_some());
        let rpc_block = result.unwrap();
        assert_eq!(rpc_block.height, 1);
        assert_eq!(rpc_block.tx_count, 0);
    }

    #[test]
    fn get_latest_block() {
        let (store, _dir) = open_tmp();

        let block = Block {
            header: BlockHeader {
                height: 5,
                parent_hash: [0u8; 32],
                state_root: [0xBB; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
            },
            transactions: vec![],
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &5u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 5;

        let result = rpc.get_latest_block().unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().height, 5);
    }

    #[test]
    fn get_receipt_missing() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let hash = hex::encode([0x11; 32]);
        let result = rpc.get_receipt(hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_receipt_after_store() {
        let (store, _dir) = open_tmp();

        let receipt = solidus_txns::types::Receipt {
            tx_hash: [0x33; 32],
            status: solidus_txns::types::TxStatus::Success,
            block_height: 1,
            fee_paid: 10_000,
            events: vec![],
        };
        let data = serde_json::to_vec(&receipt).unwrap();
        store.put(CF_RECEIPTS, &receipt.tx_hash, &data).unwrap();

        let rpc = make_rpc(store);
        let hash = hex::encode([0x33; 32]);
        let result = rpc.get_receipt(hash).unwrap();
        assert!(result.is_some());
        let rpc_receipt = result.unwrap();
        assert_eq!(rpc_receipt.status, "success");
        assert_eq!(rpc_receipt.fee_paid, 10_000);
    }

    #[test]
    fn get_receipt_invalid_hex() {
        let (store, _dir) = open_tmp();
        let rpc = make_rpc(store);

        let result = rpc.get_receipt("not-hex".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn get_transaction_scan_blocks() {
        let (store, _dir) = open_tmp();

        let sender = generate_signing_key();
        let to = Address::from_bytes([0xCC; 20]);
        let tx = make_transfer_tx(&sender, to, 1000, 0);
        let tx_hash = tx.hash();

        // Store a block containing the transaction at height 2.
        let block = Block {
            header: BlockHeader {
                height: 2,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 1,
            },
            transactions: vec![tx],
        };
        let data = serde_json::to_vec(&block).unwrap();
        store.put(CF_BLOCKS, &2u64.to_le_bytes(), &data).unwrap();

        let rpc = make_rpc(store);
        *rpc.latest_height.lock().unwrap() = 2;

        let hash_hex = hex::encode(tx_hash);
        let result = rpc.get_transaction(hash_hex).unwrap();
        assert!(result.is_some());
    }
}

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use solidus_crypto::keys::Address;
use solidus_state::executor::{compute_state_root, execute_block};
use solidus_state::store::{Store, CF_BLOCKS, CF_HEADERS};
use solidus_txns::types::Receipt;
use tokio::sync::watch;
use tracing::{info, warn};

use crate::mempool::Mempool;
use crate::types::{compute_transactions_root, Block, BlockHeader};

/// Result type for block proposal: `(Block, Vec<Receipt>)`.
type ProposalResult = (Block, Vec<Receipt>);

// ---------------------------------------------------------------------------
// ProposerConfig
// ---------------------------------------------------------------------------

/// Configuration for the single-node block proposer.
pub struct ProposerConfig {
    /// Target interval between blocks in milliseconds.
    pub block_time_ms: u64,
    /// Maximum number of transactions to include per block.
    pub max_block_txs: usize,
    /// Address that receives the treasury share of fees.
    pub treasury_address: Address,
    /// Addresses that receive the validator share of fees.
    pub validator_addresses: Vec<Address>,
    /// Network identifier used in DID strings (`testnet`, `mainnet`, etc.).
    /// Threaded through to `execute_block` so DID handlers no longer
    /// hardcode `"testnet"`.
    pub network: String,
}

// ---------------------------------------------------------------------------
// Proposer
// ---------------------------------------------------------------------------

/// A single-node block proposer that periodically drains the mempool,
/// executes transactions, and persists new blocks to the store.
pub struct Proposer {
    store: Arc<Store>,
    mempool: Arc<Mutex<Mempool>>,
    config: ProposerConfig,
    current_height: u64,
    last_block_hash: [u8; 32],
    /// Shared latest height — updated after each block so RPC can serve it.
    latest_height: Option<Arc<Mutex<u64>>>,
}

impl Proposer {
    /// Create a new proposer starting from the given genesis state.
    pub fn new(
        store: Arc<Store>,
        mempool: Arc<Mutex<Mempool>>,
        config: ProposerConfig,
        genesis_height: u64,
        genesis_hash: [u8; 32],
    ) -> Self {
        Self {
            store,
            mempool,
            config,
            current_height: genesis_height,
            last_block_hash: genesis_hash,
            latest_height: None,
        }
    }

    /// Set the shared latest_height so RPC getLatestBlock works.
    pub fn set_latest_height(&mut self, height: Arc<Mutex<u64>>) {
        self.latest_height = Some(height);
    }

    /// Attempt to propose and commit a new block.
    ///
    /// Returns `Ok(Some((block, receipts)))` if a block was produced, or
    /// `Ok(None)` if the mempool was empty.
    pub fn propose_block(&mut self) -> Result<Option<ProposalResult>, Box<dyn Error>> {
        // Take transactions from the mempool. Recover from a poisoned mutex
        // (a previous holder panicked) by extracting the inner Mempool —
        // its state is plain data (Vec + HashSet); safe to read. See the
        // matching pattern in HotStuffEngine::build_block.
        let txs = {
            let mut pool = match self.mempool.lock() {
                Ok(p) => p,
                Err(poisoned) => {
                    tracing::warn!("mempool lock poisoned; recovering inner state");
                    poisoned.into_inner()
                }
            };
            pool.take(self.config.max_block_txs)
        };

        // Produce blocks even when mempool is empty to maintain chain liveness.
        // Empty blocks keep the block height advancing, which is needed for:
        // - Explorer indexer to show activity
        // - SDK time-based operations
        // - Consistent block intervals

        let new_height = self.current_height + 1;

        // Block timestamp (ms since epoch). Computed ONCE here so the same
        // value feeds both execution (DID/credential `created_ms` must be
        // identical across the proposer and every re-executing validator, or
        // the state roots diverge) and the header below. Defensive 0 fallback
        // on a pre-1970 clock rather than panic. Matches HotStuffEngine::build_block.
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Execute the block against the state store.
        let receipts = execute_block(
            &self.store,
            &txs,
            new_height,
            timestamp_ms,
            &self.config.treasury_address,
            &self.config.validator_addresses,
            &self.config.network,
        )?;

        // Compute state root after execution.
        let state_root = compute_state_root(&self.store)?;

        // Build the block header.
        let transactions_root = compute_transactions_root(&txs);

        let header = BlockHeader {
            height: new_height,
            round: 0,
            parent_hash: self.last_block_hash,
            state_root,
            transactions_root,
            timestamp_ms,
            tx_count: txs.len() as u32,
            proposer: self.config.treasury_address,
        };

        let block = Block {
            header,
            transactions: txs,
            parent_qc: None,
            vrf_proof: None,
        };

        let block_hash = block.hash();

        // Persist block and header to the store.
        let block_bytes = serde_json::to_vec(&block)?;
        self.store
            .put(CF_BLOCKS, &new_height.to_le_bytes(), &block_bytes)?;

        let header_bytes = serde_json::to_vec(&block.header)?;
        self.store.put(CF_HEADERS, &block_hash, &header_bytes)?;

        // Advance chain tip.
        self.current_height = new_height;
        self.last_block_hash = block_hash;

        // Update shared latest_height for RPC.
        if let Some(ref lh) = self.latest_height {
            if let Ok(mut h) = lh.lock() {
                *h = new_height;
            }
        }

        info!(
            height = new_height,
            tx_count = block.header.tx_count,
            "committed block"
        );

        Ok(Some((block, receipts)))
    }

    /// Run the proposer loop, producing blocks every `block_time_ms`
    /// milliseconds until the shutdown signal is received.
    pub async fn run(&mut self, mut shutdown: watch::Receiver<bool>) {
        let interval = tokio::time::Duration::from_millis(self.config.block_time_ms);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    match self.propose_block() {
                        Ok(Some((block, _receipts))) => {
                            if block.header.tx_count > 0 {
                                info!(
                                    height = block.header.height,
                                    tx_count = block.header.tx_count,
                                    "produced block"
                                );
                            }
                            // Silently produce empty blocks (don't spam logs).
                        }
                        Ok(None) => {
                            // Should not happen anymore (we always produce blocks).
                        }
                        Err(e) => {
                            warn!(error = %e, "failed to propose block");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("proposer shutting down");
                        break;
                    }
                }
            }
        }
    }

    /// Return the current chain height.
    pub fn current_height(&self) -> u64 {
        self.current_height
    }

    /// Return the hash of the last committed block.
    pub fn last_block_hash(&self) -> [u8; 32] {
        self.last_block_hash
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_state::account::{Account, AccountType};
    use solidus_state::executor::save_account;
    use solidus_txns::types::{Transaction, TxPayload, TxStatus};
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> (Arc<Store>, tempfile::TempDir) {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));
        (store, dir)
    }

    /// Helper: build a signed Transfer transaction.
    fn make_transfer_tx(
        sender_key: &SigningKey,
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

    /// Helper: fund an account by directly writing to the store.
    fn fund_account(store: &Store, address: Address, balance: u64) {
        let account = Account::with_balance(address, balance, AccountType::Regular);
        save_account(store, &account).expect("fund_account failed");
    }

    fn make_proposer(store: Arc<Store>, mempool: Arc<Mutex<Mempool>>) -> Proposer {
        let config = ProposerConfig {
            block_time_ms: 1000,
            max_block_txs: 100,
            treasury_address: Address::from_bytes([0xAAu8; 20]),
            validator_addresses: vec![Address::from_bytes([0xBBu8; 20])],
            network: "testnet".to_string(),
        };
        Proposer::new(store, mempool, config, 0, [0u8; 32])
    }

    #[test]
    fn no_txs_produces_empty_block() {
        // Updated 2026-05-09: the proposer now produces empty blocks when
        // the mempool is empty, to maintain chain liveness (height advances
        // for the explorer indexer, time-based SDK ops, and consistent
        // block intervals). The previous assertion `is_none()` was stale.
        let (store, _dir) = open_tmp();
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let mut proposer = make_proposer(store, mempool);

        let result = proposer.propose_block().expect("propose_block failed");
        let (block, receipts) = result.expect("empty mempool must still produce a block");
        assert_eq!(block.header.tx_count, 0);
        assert!(receipts.is_empty());
        assert_eq!(proposer.current_height(), 1);
    }

    #[test]
    fn produces_block_with_transactions() {
        let (store, _dir) = open_tmp();
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_bytes([0xCCu8; 20]);

        fund_account(&store, sender_addr, 1_000_000);

        let tx = make_transfer_tx(&sender_key, receiver_addr, 500, 0);
        {
            let mut pool = mempool.lock().unwrap();
            assert!(pool.insert(tx));
        }

        let mut proposer = make_proposer(Arc::clone(&store), mempool);
        let result = proposer
            .propose_block()
            .expect("propose_block failed")
            .expect("expected a block");

        let (block, receipts) = result;
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.tx_count, 1);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].status, TxStatus::Success);

        // Verify the block was persisted.
        let stored = store
            .get(CF_BLOCKS, &1u64.to_le_bytes())
            .expect("get failed")
            .expect("block should be stored");
        let stored_block: Block = serde_json::from_slice(&stored).expect("deserialize block");
        assert_eq!(stored_block.header.height, 1);
    }

    #[test]
    fn height_increments() {
        let (store, _dir) = open_tmp();
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_bytes([0xCCu8; 20]);

        // Fund enough for two blocks.
        fund_account(&store, sender_addr, 10_000_000);

        // Block 1
        {
            let tx = make_transfer_tx(&sender_key, receiver_addr, 100, 0);
            mempool.lock().unwrap().insert(tx);
        }

        let mut proposer = make_proposer(Arc::clone(&store), Arc::clone(&mempool));

        let (block1, _) = proposer
            .propose_block()
            .expect("propose_block 1 failed")
            .expect("expected block 1");
        assert_eq!(block1.header.height, 1);
        assert_eq!(proposer.current_height(), 1);

        // Block 2
        {
            let tx = make_transfer_tx(&sender_key, receiver_addr, 200, 1);
            mempool.lock().unwrap().insert(tx);
        }

        let (block2, _) = proposer
            .propose_block()
            .expect("propose_block 2 failed")
            .expect("expected block 2");
        assert_eq!(block2.header.height, 2);
        assert_eq!(proposer.current_height(), 2);
    }

    #[test]
    fn parent_hash_chains() {
        let (store, _dir) = open_tmp();
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        let sender_key = generate_signing_key();
        let sender_addr = Address::from_public_key(&sender_key.verifying_key());
        let receiver_addr = Address::from_bytes([0xCCu8; 20]);

        fund_account(&store, sender_addr, 10_000_000);

        // Block 1
        {
            let tx = make_transfer_tx(&sender_key, receiver_addr, 100, 0);
            mempool.lock().unwrap().insert(tx);
        }

        let mut proposer = make_proposer(Arc::clone(&store), Arc::clone(&mempool));

        let (block1, _) = proposer
            .propose_block()
            .expect("propose_block 1 failed")
            .expect("expected block 1");

        // Block 1's parent should be the genesis hash (all zeros).
        assert_eq!(block1.header.parent_hash, [0u8; 32]);

        let block1_hash = block1.hash();
        assert_eq!(proposer.last_block_hash(), block1_hash);

        // Block 2
        {
            let tx = make_transfer_tx(&sender_key, receiver_addr, 200, 1);
            mempool.lock().unwrap().insert(tx);
        }

        let (block2, _) = proposer
            .propose_block()
            .expect("propose_block 2 failed")
            .expect("expected block 2");

        // Block 2's parent should be block 1's hash.
        assert_eq!(block2.header.parent_hash, block1_hash);
        assert_eq!(proposer.last_block_hash(), block2.hash());
    }
}

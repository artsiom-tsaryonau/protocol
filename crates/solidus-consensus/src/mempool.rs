use std::collections::{HashMap, VecDeque};

use solidus_txns::types::Transaction;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of pending transactions the mempool will hold.
const MAX_MEMPOOL_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Mempool
// ---------------------------------------------------------------------------

/// An in-memory transaction pool that de-duplicates by transaction hash and
/// preserves insertion order (FIFO).
pub struct Mempool {
    /// Ordered queue of pending transactions.
    txs: VecDeque<Transaction>,
    /// Set of transaction hashes currently in the pool (for O(1) duplicate
    /// detection).
    seen: HashMap<[u8; 32], ()>,
}

impl Mempool {
    /// Create a new empty mempool.
    pub fn new() -> Self {
        Self {
            txs: VecDeque::new(),
            seen: HashMap::new(),
        }
    }

    /// Insert a transaction into the mempool.
    ///
    /// Returns `true` if the transaction was accepted, `false` if it was
    /// rejected (duplicate or mempool full).
    pub fn insert(&mut self, tx: Transaction) -> bool {
        if self.txs.len() >= MAX_MEMPOOL_SIZE {
            return false;
        }

        let hash = tx.hash();
        if self.seen.contains_key(&hash) {
            return false;
        }

        self.seen.insert(hash, ());
        self.txs.push_back(tx);
        true
    }

    /// Drain up to `max` transactions from the front of the mempool.
    ///
    /// Removed transactions are also purged from the `seen` set so they can be
    /// re-submitted later if needed.
    pub fn take(&mut self, max: usize) -> Vec<Transaction> {
        let count = max.min(self.txs.len());
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(tx) = self.txs.pop_front() {
                self.seen.remove(&tx.hash());
                out.push(tx);
            }
        }
        out
    }

    /// Number of transactions currently in the pool.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Remove transactions that have been committed in a block, identified by
    /// their hashes.
    ///
    /// This is used after a block is committed to clean up any transactions
    /// that may still be lingering in the pool (e.g. if they were re-inserted
    /// between `take` and commit).
    pub fn remove_committed(&mut self, tx_hashes: &[[u8; 32]]) {
        let committed: HashMap<[u8; 32], ()> =
            tx_hashes.iter().map(|h| (*h, ())).collect();

        self.txs.retain(|tx| {
            let h = tx.hash();
            if committed.contains_key(&h) {
                self.seen.remove(&h);
                false
            } else {
                true
            }
        });

        // Also remove from seen in case they were already taken but hash
        // lingers.
        for h in tx_hashes {
            self.seen.remove(h);
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::TxPayload;

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
    fn insert_and_take() {
        let mut pool = Mempool::new();
        let sender = generate_signing_key();
        let to = Address::from_bytes([0xBBu8; 20]);

        let tx1 = make_transfer_tx(&sender, to, 100, 0);
        let tx2 = make_transfer_tx(&sender, to, 200, 1);

        assert!(pool.insert(tx1.clone()));
        assert!(pool.insert(tx2.clone()));
        assert_eq!(pool.len(), 2);

        let taken = pool.take(10);
        assert_eq!(taken.len(), 2);
        assert_eq!(taken[0].hash(), tx1.hash());
        assert_eq!(taken[1].hash(), tx2.hash());
        assert!(pool.is_empty());
    }

    #[test]
    fn rejects_duplicate() {
        let mut pool = Mempool::new();
        let sender = generate_signing_key();
        let to = Address::from_bytes([0xBBu8; 20]);

        let tx = make_transfer_tx(&sender, to, 100, 0);
        assert!(pool.insert(tx.clone()));
        assert!(!pool.insert(tx)); // duplicate
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn take_respects_max() {
        let mut pool = Mempool::new();
        let sender = generate_signing_key();
        let to = Address::from_bytes([0xBBu8; 20]);

        for i in 0..5 {
            let tx = make_transfer_tx(&sender, to, 100 + i, i);
            assert!(pool.insert(tx));
        }
        assert_eq!(pool.len(), 5);

        let taken = pool.take(3);
        assert_eq!(taken.len(), 3);
        assert_eq!(pool.len(), 2);
    }
}

use serde::{Deserialize, Serialize};
use solidus_crypto::hash::blake3_hash;
use solidus_txns::types::Transaction;

// ---------------------------------------------------------------------------
// BlockHeader
// ---------------------------------------------------------------------------

/// Header of a committed block. Contains metadata sufficient to verify block
/// integrity without downloading the full transaction list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// The sequential block number (0 = genesis).
    pub height: u64,
    /// Hash of the parent block header (all zeros for genesis).
    pub parent_hash: [u8; 32],
    /// Global state root after executing all transactions in this block.
    pub state_root: [u8; 32],
    /// Merkle root of the transaction hashes in this block.
    pub transactions_root: [u8; 32],
    /// Unix timestamp in milliseconds when the block was proposed.
    pub timestamp_ms: u64,
    /// Number of transactions included in this block.
    pub tx_count: u32,
}

impl BlockHeader {
    /// Compute the content-address of this header.
    ///
    /// `BLAKE3(serde_json(self))`
    pub fn hash(&self) -> [u8; 32] {
        let bytes = serde_json::to_vec(self).expect("header serialization");
        blake3_hash(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

/// A complete block: header + ordered list of transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block metadata.
    pub header: BlockHeader,
    /// Ordered list of transactions included in this block.
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Content-address of the block (delegates to header hash).
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the transactions root from an ordered slice of transactions.
///
/// The root is `BLAKE3(tx0_hash || tx1_hash || ... || txN_hash)`.
/// Returns `[0u8; 32]` for an empty slice.
pub fn compute_transactions_root(transactions: &[Transaction]) -> [u8; 32] {
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(&tx.hash());
    }
    if data.is_empty() {
        [0u8; 32]
    } else {
        blake3_hash(&data)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_transactions_root() {
        let root = compute_transactions_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn block_header_hash_deterministic() {
        let header = BlockHeader {
            height: 1,
            parent_hash: [0u8; 32],
            state_root: [1u8; 32],
            transactions_root: [2u8; 32],
            timestamp_ms: 1_700_000_000_000,
            tx_count: 5,
        };

        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2);

        // Changing any field should change the hash.
        let mut header2 = header.clone();
        header2.height = 2;
        assert_ne!(header.hash(), header2.hash());
    }
}

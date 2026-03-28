use serde::{Deserialize, Serialize};
use solidus_consensus::types::Block;
use solidus_txns::types::{Event, Receipt, TxStatus};

// ---------------------------------------------------------------------------
// RpcBlock
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a committed block. All byte arrays are
/// encoded as hex strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    /// Sequential block number (0 = genesis).
    pub height: u64,
    /// Block header hash as hex.
    pub hash: String,
    /// Parent block header hash as hex.
    pub parent_hash: String,
    /// Global state root after this block as hex.
    pub state_root: String,
    /// Merkle root of transaction hashes as hex.
    pub transactions_root: String,
    /// Unix timestamp in milliseconds.
    pub timestamp_ms: u64,
    /// Number of transactions in this block.
    pub tx_count: u32,
    /// Transaction hashes (hex) in block order.
    pub transactions: Vec<String>,
}

impl RpcBlock {
    /// Convert a domain [`Block`] into the RPC representation.
    pub fn from_block(block: &Block) -> Self {
        let tx_hashes: Vec<String> = block
            .transactions
            .iter()
            .map(|tx| hex::encode(tx.hash()))
            .collect();

        Self {
            height: block.header.height,
            hash: hex::encode(block.hash()),
            parent_hash: hex::encode(block.header.parent_hash),
            state_root: hex::encode(block.header.state_root),
            transactions_root: hex::encode(block.header.transactions_root),
            timestamp_ms: block.header.timestamp_ms,
            tx_count: block.header.tx_count,
            transactions: tx_hashes,
        }
    }
}

// ---------------------------------------------------------------------------
// RpcReceipt
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a transaction receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcReceipt {
    /// Transaction hash as hex.
    pub tx_hash: String,
    /// `"success"` or `"failed: <reason>"`.
    pub status: String,
    /// Block height where the transaction was included.
    pub block_height: u64,
    /// Fee deducted from the sender.
    pub fee_paid: u64,
    /// Events emitted during execution.
    pub events: Vec<serde_json::Value>,
}

impl RpcReceipt {
    /// Convert a domain [`Receipt`] into the RPC representation.
    pub fn from_receipt(receipt: &Receipt) -> Self {
        let status_str = match &receipt.status {
            TxStatus::Success => "success".to_string(),
            TxStatus::Failed(reason) => format!("failed: {reason}"),
        };

        let events: Vec<serde_json::Value> = receipt
            .events
            .iter()
            .map(event_to_json)
            .collect();

        Self {
            tx_hash: hex::encode(receipt.tx_hash),
            status: status_str,
            block_height: receipt.block_height,
            fee_paid: receipt.fee_paid,
            events,
        }
    }
}

/// Convert a domain [`Event`] into a JSON value.
fn event_to_json(event: &Event) -> serde_json::Value {
    match event {
        Event::Transfer { from, to, amount } => {
            serde_json::json!({
                "type": "Transfer",
                "from": from.to_base58(),
                "to": to.to_base58(),
                "amount": amount,
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_consensus::types::{Block, BlockHeader};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::{Receipt, TxStatus};

    #[test]
    fn rpc_block_from_block() {
        let block = Block {
            header: BlockHeader {
                height: 42,
                parent_hash: [0xAA; 32],
                state_root: [0xBB; 32],
                transactions_root: [0xCC; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
            },
            transactions: vec![],
        };

        let rpc = RpcBlock::from_block(&block);
        assert_eq!(rpc.height, 42);
        assert_eq!(rpc.parent_hash, hex::encode([0xAA; 32]));
        assert_eq!(rpc.state_root, hex::encode([0xBB; 32]));
        assert!(rpc.transactions.is_empty());
    }

    #[test]
    fn rpc_receipt_success() {
        let receipt = Receipt {
            tx_hash: [0x11; 32],
            status: TxStatus::Success,
            block_height: 10,
            fee_paid: 10_000,
            events: vec![Event::Transfer {
                from: Address::from_bytes([1; 20]),
                to: Address::from_bytes([2; 20]),
                amount: 500,
            }],
        };

        let rpc = RpcReceipt::from_receipt(&receipt);
        assert_eq!(rpc.status, "success");
        assert_eq!(rpc.fee_paid, 10_000);
        assert_eq!(rpc.events.len(), 1);
        assert_eq!(rpc.events[0]["type"], "Transfer");
    }

    #[test]
    fn rpc_receipt_failed() {
        let receipt = Receipt {
            tx_hash: [0x22; 32],
            status: TxStatus::Failed("insufficient balance".to_string()),
            block_height: 5,
            fee_paid: 0,
            events: vec![],
        };

        let rpc = RpcReceipt::from_receipt(&receipt);
        assert_eq!(rpc.status, "failed: insufficient balance");
    }
}

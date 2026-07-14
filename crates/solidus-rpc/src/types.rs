use serde::{Deserialize, Serialize};
use solidus_consensus::types::Block;
use solidus_txns::compute::ComputeTier;
use solidus_txns::credential::CredentialRecord;
use solidus_txns::did::{DidDocument, RecoveryPolicy};
use solidus_txns::staking::ValidatorInfo;
use solidus_txns::types::{Event, Receipt, TxStatus};

fn tier_str(tier: &ComputeTier) -> &'static str {
    match tier {
        ComputeTier::Trusted => "trusted",
        ComputeTier::Attested => "attested",
    }
}

// ---------------------------------------------------------------------------
// RpcBlock
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a committed block. All byte arrays are
/// encoded as hex strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcBlock {
    /// Sequential block number (0 = genesis).
    pub height: u64,
    /// The consensus round in which this block was proposed.
    pub round: u64,
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
    /// Address of the block proposer (base58).
    pub proposer: String,
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
            round: block.header.round,
            hash: hex::encode(block.hash()),
            parent_hash: hex::encode(block.header.parent_hash),
            state_root: hex::encode(block.header.state_root),
            transactions_root: hex::encode(block.header.transactions_root),
            timestamp_ms: block.header.timestamp_ms,
            tx_count: block.header.tx_count,
            proposer: block.header.proposer.to_base58(),
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

        let events: Vec<serde_json::Value> = receipt.events.iter().map(event_to_json).collect();

        Self {
            tx_hash: hex::encode(receipt.tx_hash),
            status: status_str,
            block_height: receipt.block_height,
            fee_paid: receipt.fee_paid,
            events,
        }
    }
}

// ---------------------------------------------------------------------------
// RpcDidDocument
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a DID document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDidDocument {
    pub context: String,
    pub id: String,
    pub controller: String,
    pub verification_method: Vec<serde_json::Value>,
    pub authentication: Vec<String>,
    #[serde(default)]
    pub assertion_method: Vec<String>,
    #[serde(default)]
    pub key_agreement: Vec<String>,
    #[serde(default)]
    pub capability_invocation: Vec<String>,
    #[serde(default)]
    pub capability_delegation: Vec<String>,
    pub service: Vec<serde_json::Value>,
    pub active: bool,
    pub created_ms: u64,
    pub updated_ms: u64,
    /// W3C DID Resolution `versionId`: hex-encoded BLAKE3 hash of the
    /// stored document. `#[serde(default)]` means pre-2026-05-09 records
    /// surface as `""`; SDK callers should treat empty string as
    /// "metadata unavailable".
    #[serde(default)]
    pub version_id: String,
    /// On-chain social-recovery policy, if the owner has set one. `None`
    /// until configured; recovery is impossible without it. `#[serde(default)]`
    /// keeps legacy records (which omit this field) deserializing cleanly.
    #[serde(default)]
    pub recovery_policy: Option<RecoveryPolicy>,
    /// Monotonic per-DID recovery counter, bumped on each successful recovery.
    /// Guardian approvals are bound to this value for replay protection.
    #[serde(default)]
    pub recovery_nonce: u64,
}

impl RpcDidDocument {
    /// Convert a domain [`DidDocument`] into the RPC representation.
    pub fn from_did_document(doc: &DidDocument) -> Self {
        Self {
            context: doc.context.clone(),
            id: doc.id.clone(),
            controller: doc.controller.clone(),
            verification_method: doc
                .verification_method
                .iter()
                .map(|vm| {
                    serde_json::json!({
                        "id": vm.id,
                        "type": vm.method_type,
                        "controller": vm.controller,
                        "publicKeyHex": vm.public_key_hex,
                    })
                })
                .collect(),
            authentication: doc.authentication.clone(),
            assertion_method: doc.assertion_method.clone(),
            key_agreement: doc.key_agreement.clone(),
            capability_invocation: doc.capability_invocation.clone(),
            capability_delegation: doc.capability_delegation.clone(),
            service: doc
                .service
                .iter()
                .map(|svc| {
                    serde_json::json!({
                        "id": svc.id,
                        "type": svc.service_type,
                        "serviceEndpoint": svc.service_endpoint,
                    })
                })
                .collect(),
            active: doc.active,
            created_ms: doc.created_ms,
            updated_ms: doc.updated_ms,
            version_id: doc.version_id.clone(),
            recovery_policy: doc.recovery_policy.clone(),
            recovery_nonce: doc.recovery_nonce,
        }
    }
}

// ---------------------------------------------------------------------------
// RpcCredentialRecord
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a credential record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCredentialRecord {
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub credential_type: String,
    /// BLAKE3 hash of the off-chain credential payload (hex-encoded).
    pub hash: String,
    pub issued_ms: u64,
    pub revoked: bool,
    pub revoked_ms: Option<u64>,
    /// 96-byte BBS+ public key (hex), present only for BBS+ credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbs_pubkey: Option<String>,
    /// Total number of messages signed by the BBS+ signature, present only
    /// for BBS+ credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bbs_message_count: Option<u32>,
}

impl RpcCredentialRecord {
    /// Convert a domain [`CredentialRecord`] into the RPC representation.
    pub fn from_credential(cred: &CredentialRecord) -> Self {
        Self {
            id: cred.id.clone(),
            issuer_did: cred.issuer_did.clone(),
            subject_did: cred.subject_did.clone(),
            credential_type: format!("{:?}", cred.credential_type),
            hash: hex::encode(cred.hash),
            issued_ms: cred.issued_ms,
            revoked: cred.revoked,
            revoked_ms: cred.revoked_ms,
            bbs_pubkey: cred.bbs_pubkey.map(hex::encode),
            bbs_message_count: cred.bbs_message_count,
        }
    }
}

// ---------------------------------------------------------------------------
// RpcCredentialVerifyResult
// ---------------------------------------------------------------------------

/// Result returned by `solidus_credentialVerify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCredentialVerifyResult {
    /// `true` if the credential exists and has not been revoked.
    pub valid: bool,
    /// The credential record, if found.
    pub credential: Option<RpcCredentialRecord>,
    /// Whether the credential has been revoked.
    pub revoked: bool,
}

// ---------------------------------------------------------------------------
// RpcValidatorInfo
// ---------------------------------------------------------------------------

/// JSON-friendly representation of a validator record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcValidatorInfo {
    /// The validator's on-chain address (base58).
    pub address: String,
    /// Currently staked amount (in smallest units).
    pub staked: u64,
    /// Amount being unbonded (21-day lock).
    pub unbonding: u64,
    /// Reputation score (0-1000).
    pub reputation: u64,
    /// Whether the validator is currently participating in consensus.
    pub active: bool,
}

impl RpcValidatorInfo {
    /// Convert a domain [`ValidatorInfo`] into the RPC representation.
    pub fn from_validator(info: &ValidatorInfo) -> Self {
        Self {
            address: info.address.to_base58(),
            staked: info.staked,
            unbonding: info.unbonding,
            reputation: info.reputation,
            active: info.active,
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
        Event::DidCreated { did, controller } => {
            serde_json::json!({
                "type": "DidCreated",
                "did": did,
                "controller": controller.to_base58(),
            })
        }
        Event::DidUpdated { did } => {
            serde_json::json!({
                "type": "DidUpdated",
                "did": did,
            })
        }
        Event::DidDeactivated { did } => {
            serde_json::json!({
                "type": "DidDeactivated",
                "did": did,
            })
        }
        Event::DidRecovered { did } => {
            serde_json::json!({
                "type": "DidRecovered",
                "did": did,
            })
        }
        Event::CredentialIssued {
            credential_id,
            issuer,
            subject,
        } => {
            serde_json::json!({
                "type": "CredentialIssued",
                "credentialId": credential_id,
                "issuer": issuer,
                "subject": subject,
            })
        }
        Event::CredentialRevoked { credential_id } => {
            serde_json::json!({
                "type": "CredentialRevoked",
                "credentialId": credential_id,
            })
        }
        Event::Staked {
            validator,
            amount,
            total_stake,
        } => {
            serde_json::json!({
                "type": "Staked",
                "validator": validator.to_base58(),
                "amount": amount,
                "totalStake": total_stake,
            })
        }
        Event::Unstaked {
            validator,
            amount,
            remaining_stake,
        } => {
            serde_json::json!({
                "type": "Unstaked",
                "validator": validator.to_base58(),
                "amount": amount,
                "remainingStake": remaining_stake,
            })
        }
        Event::ComputeAdmitted { operator, tier } => {
            serde_json::json!({
                "type": "ComputeAdmitted",
                "operator": operator.to_base58(),
                "tier": tier_str(tier),
            })
        }
        Event::ComputeRemoved { operator } => {
            serde_json::json!({
                "type": "ComputeRemoved",
                "operator": operator.to_base58(),
            })
        }
        Event::ComputeRegistered {
            operator,
            jurisdiction,
            tier,
        } => {
            serde_json::json!({
                "type": "ComputeRegistered",
                "operator": operator.to_base58(),
                "jurisdiction": jurisdiction,
                "tier": tier_str(tier),
            })
        }
        Event::ComputeAnchored {
            merkle_root,
            batch_count,
        } => {
            serde_json::json!({
                "type": "ComputeAnchored",
                "merkleRoot": hex::encode(merkle_root),
                "batchCount": batch_count,
            })
        }
        Event::ComputeSlashed {
            operator,
            severe,
            reputation,
        } => {
            serde_json::json!({
                "type": "ComputeSlashed",
                "operator": operator.to_base58(),
                "severe": severe,
                "reputation": reputation,
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
                round: 0,
                parent_hash: [0xAA; 32],
                state_root: [0xBB; 32],
                transactions_root: [0xCC; 32],
                timestamp_ms: 1_700_000_000_000,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
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

    #[test]
    fn node_info_serialization_roundtrip() {
        let info = NodeInfo {
            version: "0.1.0".to_string(),
            uptime_seconds: 123,
            rss_bytes: 4096,
        };
        let json = serde_json::to_string(&info).unwrap();
        let back: NodeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }
}

// ---------------------------------------------------------------------------
// BBS+ RPC types
// ---------------------------------------------------------------------------

/// One disclosed message in a BBS+ proof. Index is the position in the
/// original signed vector; message bytes are hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcDisclosedMessage {
    /// Position in the original signed message vector.
    pub index: u32,
    /// Hex-encoded message bytes.
    pub message: String,
}

/// Result returned by `solidus_bbsVerifyCredentialProof`. Combines proof
/// validity with on-chain credential state (revocation status, full record).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcCredentialProofResult {
    /// `true` iff the proof verifies AND the credential is not revoked.
    pub valid: bool,
    /// `true` if the proof itself is cryptographically valid.
    /// `valid` may be `false` while this is `true` if the credential
    /// was revoked after proof generation.
    pub proof_valid: bool,
    /// `true` if the credential exists and carries a BBS+ pubkey.
    pub is_bbs: bool,
    /// `true` if the credential has been revoked.
    pub revoked: bool,
    /// The credential record on-chain (or `null` if not found).
    pub credential: Option<RpcCredentialRecord>,
}

// ---------------------------------------------------------------------------
// Chain info
// ---------------------------------------------------------------------------

/// Native token metadata as surfaced over JSON-RPC.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcNativeToken {
    /// Display symbol — e.g. `"SLDS"`. Uppercase, no `$` prefix.
    pub symbol: String,
    /// Display name — e.g. `"Solidus"`.
    pub name: String,
    /// Decimal precision (`8` → `1 SLDS = 10^8` base units).
    pub decimals: u8,
}

/// Result returned by `solidus_chainInfo`: a self-description of the chain
/// for wallets, explorers, indexers, and listing aggregators (CoinMarketCap
/// and CoinGecko moderators included).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcChainInfo {
    /// Unique chain identifier from genesis.
    pub chain_id: String,
    /// Native token metadata.
    pub native_token: RpcNativeToken,
    /// Hex-encoded hash of the genesis block (height 0). Empty string when
    /// no genesis block is present in the store.
    pub genesis_hash: String,
    /// Height of the latest committed block.
    pub latest_block: u64,
    /// Node software version (`CARGO_PKG_VERSION`).
    pub version: String,
}

/// Process-level node observability surfaced by `solidus_nodeInfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    /// Node software version (same value as `RpcChainInfo.version`).
    pub version: String,
    /// Seconds since the node's RPC service started.
    pub uptime_seconds: u64,
    /// Resident set size of the node process in bytes. `0` when unavailable
    /// (non-Linux hosts, or `/proc` not readable).
    pub rss_bytes: u64,
}

/// Head of the contiguous canonical ledger surfaced by `solidus_canonHead`.
///
/// `seq` is the authoritative chain position (the index into `CF_CANON`),
/// distinct from `BlockHeader::height` which can be lossy under fast leader
/// rotation. `hash` is the hex-encoded block hash at that seq.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RpcCanonHead {
    /// Contiguous canonical sequence number (`0` for genesis, monotonic).
    pub seq: u64,
    /// Hex-encoded hash of the block at this seq.
    pub hash: String,
}

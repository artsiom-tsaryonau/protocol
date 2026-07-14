use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use solidus_crypto::ed25519;
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;

use crate::compute::ComputeTier;
use crate::credential::CredentialType;
use crate::did::{DidPatch, GuardianApproval, Service};

// ---------------------------------------------------------------------------
// Serde helpers for large byte arrays ([u8; 64]) that serde doesn't cover
// ---------------------------------------------------------------------------

mod serde_bytes_64 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Deserialize::deserialize(deserializer)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"64 bytes"))
    }
}

mod serde_bytes_96 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<u8> = Deserialize::deserialize(deserializer)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"96 bytes"))
    }
}

// ---------------------------------------------------------------------------
// Fee constants (in smallest units; 1 SLDS = 10^8)
// ---------------------------------------------------------------------------

/// 0.0001 SLDS — fee for a value transfer.
pub const FEE_TRANSFER: u64 = 10_000;
/// 0.001 SLDS — fee for creating a DID document.
pub const FEE_DID_CREATE: u64 = 100_000;
/// 0.0001 SLDS — fee for updating a DID document.
pub const FEE_DID_UPDATE: u64 = 10_000;
/// 0.0001 SLDS — fee for deactivating a DID document.
pub const FEE_DID_DEACTIVATE: u64 = 10_000;
/// 0.0001 SLDS — fee for revoking a credential.
pub const FEE_CREDENTIAL_REVOKE: u64 = 10_000;
/// 0.0001 SLDS — fee for staking.
pub const FEE_STAKE: u64 = 10_000;
/// 0.0001 SLDS — fee for unstaking.
pub const FEE_UNSTAKE: u64 = 10_000;
/// 0.001 SLDS — fee for a guardian-authorized recovery (multi-sig verify).
pub const FEE_DID_RECOVER: u64 = 100_000;
/// Fee for a compute-network governance/registration transaction (§6.5).
pub const FEE_COMPUTE: u64 = 10_000;
/// 1 SLDS expressed in the smallest unit.
pub const ONE_SLDS: u64 = 100_000_000;

// ---------------------------------------------------------------------------
// TxPayload
// ---------------------------------------------------------------------------

/// The inner payload of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxPayload {
    /// Transfer `amount` (in smallest units) to `to`.
    Transfer { to: Address, amount: u64 },
    /// Register a new DID document for the sender.
    DidCreate {
        /// Raw 32-byte Ed25519 public key embedded in the DID document.
        public_key: [u8; 32],
        /// Initial service endpoints to include in the document.
        service_endpoints: Vec<Service>,
    },
    /// Apply a set of patches to an existing DID document.
    DidUpdate {
        /// The DID string to update.
        did: String,
        /// Ordered list of patches to apply atomically.
        patches: Vec<DidPatch>,
    },
    /// Permanently deactivate a DID document.
    DidDeactivate {
        /// The DID string to deactivate.
        did: String,
    },
    /// Issue a new verifiable credential from the sender (issuer) to a subject DID.
    CredentialIssue {
        /// DID of the credential subject.
        subject_did: String,
        /// The type of credential being issued.
        credential_type: CredentialType,
        /// BLAKE3 hash of the off-chain credential payload.
        hash: [u8; 32],
    },
    /// Issue a BBS+ verifiable credential, enabling selective disclosure.
    /// The issuer commits on-chain to a BBS+ public key over a fixed-length
    /// message vector; the actual signature and messages live off-chain with
    /// the subject. Verifiers later check selective-disclosure proofs against
    /// the on-chain `bbs_pubkey`.
    CredentialIssueBbs {
        /// DID of the credential subject.
        subject_did: String,
        /// The type of credential being issued.
        credential_type: CredentialType,
        /// BLAKE3 hash of the off-chain credential payload.
        hash: [u8; 32],
        /// 96-byte compressed BLS12-381 G2 point (the BBS+ public key).
        #[serde(with = "serde_bytes_96")]
        bbs_pubkey: [u8; 96],
        /// Number of messages signed.
        bbs_message_count: u32,
    },
    /// Revoke a previously issued credential. Only the original issuer may do this.
    CredentialRevoke {
        /// The unique credential identifier to revoke.
        credential_id: String,
    },
    /// Stake `amount` (in smallest units) to become or remain an active validator.
    Stake { amount: u64 },
    /// Begin unbonding `amount` from the sender's staked balance.
    Unstake { amount: u64 },
    /// Rotate a DID's key via k-of-n guardian approval (social recovery).
    /// The envelope MUST be signed by `new_public_key` (the recovered key).
    DidRecover {
        /// The subject DID being recovered.
        did: String,
        /// The new 32-byte Ed25519 key to install as sole authentication.
        new_public_key: [u8; 32],
        /// Guardian authorizations (≥ policy threshold valid+distinct required).
        approvals: Vec<GuardianApproval>,
    },
    /// GOVERNANCE (active validator): admit an operator to the compute allow-list
    /// (Rebuild #5 §6.2.4 / BD-2).
    ComputeAdmit {
        operator: Address,
        tier: ComputeTier,
    },
    /// GOVERNANCE: remove an operator from the compute network (allow-list + node).
    ComputeRemove { operator: Address },
    /// SELF-CERTIFYING: an admitted operator registers its keys + jurisdiction.
    /// The sender must be the address derived from `ed25519_pub`.
    ComputeRegister {
        ed25519_pub: [u8; 32],
        x25519_pub: [u8; 32],
        /// ISO-3166 alpha-2 processing jurisdiction.
        jurisdiction: String,
    },
    /// GOVERNANCE: anchor a batch of off-chain job receipts by Merkle root (§6.5).
    ComputeAnchor {
        merkle_root: [u8; 32],
        batch_count: u32,
    },
    /// GOVERNANCE/referee: slash a cheating operator (§6.5).
    ComputeSlash {
        operator: Address,
        reputation_penalty: u64,
        severe: bool,
    },
}

impl TxPayload {
    /// Return the fee for this payload type.
    pub fn fee(&self) -> u64 {
        match self {
            TxPayload::Transfer { .. } => FEE_TRANSFER,
            TxPayload::DidCreate { .. } => FEE_DID_CREATE,
            TxPayload::DidUpdate { .. } => FEE_DID_UPDATE,
            TxPayload::DidDeactivate { .. } => FEE_DID_DEACTIVATE,
            TxPayload::CredentialIssue {
                credential_type, ..
            } => credential_type.issue_fee(),
            TxPayload::CredentialIssueBbs {
                credential_type, ..
            } => credential_type.issue_fee_bbs(),
            TxPayload::CredentialRevoke { .. } => FEE_CREDENTIAL_REVOKE,
            TxPayload::Stake { .. } => FEE_STAKE,
            TxPayload::Unstake { .. } => FEE_UNSTAKE,
            TxPayload::DidRecover { .. } => FEE_DID_RECOVER,
            TxPayload::ComputeAdmit { .. }
            | TxPayload::ComputeRemove { .. }
            | TxPayload::ComputeRegister { .. }
            | TxPayload::ComputeAnchor { .. }
            | TxPayload::ComputeSlash { .. } => FEE_COMPUTE,
        }
    }
}

// ---------------------------------------------------------------------------
// Transaction (signed envelope)
// ---------------------------------------------------------------------------

/// A signed transaction ready for inclusion in a block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// The raw 32-byte Ed25519 public key of the sender.
    pub sender_pubkey: [u8; 32],
    /// Monotonically increasing per-account nonce (replay protection).
    pub nonce: u64,
    /// The operation to execute.
    pub payload: TxPayload,
    /// Ed25519 signature over `signing_bytes()`.
    #[serde(with = "serde_bytes_64")]
    pub signature: [u8; 64],
}

impl Transaction {
    /// Compute the message that must be signed.
    ///
    /// `BLAKE3(sender_pubkey || nonce_le_bytes || serde_json(payload))`
    pub fn signing_bytes(&self) -> [u8; 32] {
        let payload_json =
            serde_json::to_vec(&self.payload).expect("TxPayload serialization cannot fail");

        let mut buf = Vec::with_capacity(32 + 8 + payload_json.len());
        buf.extend_from_slice(&self.sender_pubkey);
        buf.extend_from_slice(&self.nonce.to_le_bytes());
        buf.extend_from_slice(&payload_json);

        blake3_hash(&buf)
    }

    /// Content-address of the full signed transaction.
    ///
    /// `BLAKE3(serde_json(self))`
    pub fn hash(&self) -> [u8; 32] {
        let encoded = serde_json::to_vec(self).expect("Transaction serialization cannot fail");
        blake3_hash(&encoded)
    }

    /// Derive the sender's on-chain address from the embedded public key.
    pub fn sender_address(&self) -> Address {
        let vk = VerifyingKey::from_bytes(&self.sender_pubkey)
            .expect("sender_pubkey must be a valid Ed25519 public key");
        Address::from_public_key(&vk)
    }

    /// Verify the Ed25519 signature against the signing bytes.
    pub fn verify_signature(&self) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(&self.sender_pubkey) else {
            return false;
        };
        let msg = self.signing_bytes();
        ed25519::verify(&vk, &msg, &self.signature)
    }
}

// ---------------------------------------------------------------------------
// Receipt types
// ---------------------------------------------------------------------------

/// Outcome of transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TxStatus {
    /// The transaction executed successfully.
    Success,
    /// The transaction failed with a human-readable reason.
    Failed(String),
}

/// A domain event emitted during transaction execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Event {
    /// A value transfer took place.
    Transfer {
        from: Address,
        to: Address,
        amount: u64,
    },
    /// A new DID document was registered.
    DidCreated { did: String, controller: Address },
    /// An existing DID document was updated.
    DidUpdated { did: String },
    /// A DID document was permanently deactivated.
    DidDeactivated { did: String },
    /// A new verifiable credential was issued.
    CredentialIssued {
        credential_id: String,
        issuer: String,
        subject: String,
    },
    /// A credential was revoked by its issuer.
    CredentialRevoked { credential_id: String },
    /// A validator staked tokens.
    Staked {
        validator: Address,
        amount: u64,
        total_stake: u64,
    },
    /// A validator began unbonding tokens.
    Unstaked {
        validator: Address,
        amount: u64,
        remaining_stake: u64,
    },
    /// A DID's key was rotated through guardian recovery.
    DidRecovered { did: String },
    /// A compute operator was admitted to the allow-list (§6.2.4).
    ComputeAdmitted {
        operator: Address,
        tier: ComputeTier,
    },
    /// A compute operator was removed from the network.
    ComputeRemoved { operator: Address },
    /// A compute operator registered its keys.
    ComputeRegistered {
        operator: Address,
        jurisdiction: String,
        tier: ComputeTier,
    },
    /// A batch of job receipts was anchored (§6.5).
    ComputeAnchored {
        merkle_root: [u8; 32],
        batch_count: u32,
    },
    /// A compute operator was slashed.
    ComputeSlashed {
        operator: Address,
        severe: bool,
        reputation: u64,
    },
}

/// Post-execution receipt stored alongside the block.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    /// Hash of the transaction this receipt belongs to.
    pub tx_hash: [u8; 32],
    /// Whether the transaction succeeded or failed.
    pub status: TxStatus,
    /// The block height at which the transaction was included.
    pub block_height: u64,
    /// The fee deducted from the sender.
    pub fee_paid: u64,
    /// Events emitted during execution.
    pub events: Vec<Event>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::ed25519::{generate_signing_key, sign};

    /// Helper: build a signed Transfer transaction.
    fn make_transfer_tx(
        sender_key: &ed25519_dalek::SigningKey,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let pubkey = sender_key.verifying_key().to_bytes();
        let payload = TxPayload::Transfer { to, amount };

        // Build a temporary unsigned tx so we can call signing_bytes().
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
    fn transfer_fee_is_correct() {
        let payload = TxPayload::Transfer {
            to: Address::from_bytes([0u8; 20]),
            amount: 1_000,
        };
        assert_eq!(payload.fee(), FEE_TRANSFER);
    }

    #[test]
    fn signed_transaction_verifies() {
        let sender = generate_signing_key();
        let receiver = generate_signing_key();
        let to = Address::from_public_key(&receiver.verifying_key());

        let tx = make_transfer_tx(&sender, to, 50_000, 0);
        assert!(tx.verify_signature());
    }

    #[test]
    fn tampered_transaction_fails_verification() {
        let sender = generate_signing_key();
        let receiver = generate_signing_key();
        let to = Address::from_public_key(&receiver.verifying_key());

        let mut tx = make_transfer_tx(&sender, to, 50_000, 0);

        // Tamper with the amount — the signature should no longer match.
        tx.payload = TxPayload::Transfer { to, amount: 99_999 };
        assert!(!tx.verify_signature());
    }

    #[test]
    fn transaction_hash_is_deterministic() {
        let sender = generate_signing_key();
        let receiver = generate_signing_key();
        let to = Address::from_public_key(&receiver.verifying_key());

        let tx = make_transfer_tx(&sender, to, 1_000, 42);
        assert_eq!(tx.hash(), tx.hash());
    }

    #[test]
    fn sender_address_derived_from_pubkey() {
        let sender = generate_signing_key();
        let receiver = generate_signing_key();
        let to = Address::from_public_key(&receiver.verifying_key());

        let tx = make_transfer_tx(&sender, to, 1_000, 0);

        let expected = Address::from_public_key(&sender.verifying_key());
        assert_eq!(tx.sender_address(), expected);
    }

    // -----------------------------------------------------------------------
    // CredentialIssueBbs tests
    // -----------------------------------------------------------------------

    #[test]
    fn bbs_credential_fee_uses_bbs_multiplier() {
        let payload = TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL2,
            hash: [0u8; 32],
            bbs_pubkey: [0u8; 96],
            bbs_message_count: 8,
        };
        // KycL2 base fee 5 SLDS = 500_000_000; BBS = 1.25x = 625_000_000
        assert_eq!(payload.fee(), 625_000_000);
    }

    #[test]
    fn bbs_credential_payload_serde_roundtrip() {
        let original = TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL2,
            hash: [0xAB; 32],
            bbs_pubkey: [0xCD; 96],
            bbs_message_count: 8,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let decoded: TxPayload = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, decoded);
    }

    #[test]
    fn bbs_credential_transaction_signature_verifies() {
        let sender = generate_signing_key();
        let payload = TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL1,
            hash: [0x42; 32],
            bbs_pubkey: [0x99; 96],
            bbs_message_count: 5,
        };
        let mut tx = Transaction {
            sender_pubkey: sender.verifying_key().to_bytes(),
            nonce: 7,
            payload,
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = sign(&sender, &msg);
        assert!(tx.verify_signature());
    }

    #[test]
    fn did_recover_fee_and_roundtrip() {
        let payload = TxPayload::DidRecover {
            did: "did:solidus:testnet:s".into(),
            new_public_key: [9u8; 32],
            approvals: vec![],
        };
        assert_eq!(payload.fee(), FEE_DID_RECOVER);
        let json = serde_json::to_vec(&payload).unwrap();
        let back: TxPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(payload, back);
    }

    #[test]
    fn bbs_credential_tampered_pubkey_breaks_signature() {
        let sender = generate_signing_key();
        let payload = TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL1,
            hash: [0x42; 32],
            bbs_pubkey: [0x99; 96],
            bbs_message_count: 5,
        };
        let mut tx = Transaction {
            sender_pubkey: sender.verifying_key().to_bytes(),
            nonce: 7,
            payload,
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = sign(&sender, &msg);

        // Tamper with the BBS pubkey.
        tx.payload = TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL1,
            hash: [0x42; 32],
            bbs_pubkey: [0x88; 96], // changed
            bbs_message_count: 5,
        };
        assert!(!tx.verify_signature());
    }
}

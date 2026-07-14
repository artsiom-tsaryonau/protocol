//! Chain-side compute module (Rebuild #5, §6.5) — pure transaction logic.
//!
//! The on-chain **authoritative mirror** of the Compute Broker's off-chain
//! registry: a governance-gated allow-list (BD-2), a node registry, batched
//! job-receipt anchoring, and compute-specific slashing.
//!
//! **Phase-1 consensus boundary (deliberate).** The chain's global state root is
//! a fixed 4-tree hash (accounts ‖ dids ‖ credentials ‖ validators). Adding a 5th
//! tree would change the state root for every block → a hard fork of the live
//! testnet. So compute state lives in **auxiliary column families that are NOT in
//! the state root**. This is safe pre-mainnet because the "stake" here is
//! **reputation/points, not SLDS** (no real value to consensus-commit yet, per
//! §5.7). At an audited mainnet, when stakes become real SLDS that MUST be
//! consensus-committed, the registry graduates into the state root as a fifth
//! tree — a deliberate genesis/migration, not a silent change.
//!
//! Privileged operations (admit / remove / slash / anchor) require the caller to
//! be **authorized for governance**. This module takes that as an `authorized:
//! bool` so it stays policy-agnostic; the executor decides the policy. Phase-1
//! policy = the caller is an **active validator** (a hand-picked testnet's
//! validator set is its governance); a dedicated compute-governance multisig is a
//! Phase-2 refinement, a one-line change at the executor.
//!
//! Node registration is **self-certifying**: the sender must be the address
//! DERIVED from the Ed25519 key it registers (matching the broker's registration
//! gate and the `solidus-node-identity` DID derivation).

use serde::{Deserialize, Serialize};
use solidus_crypto::keys::Address;
use thiserror::Error;

/// Node assurance tier (§6.6). `Attested` = a validated H100/H200 confidential VM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeTier {
    Trusted,
    Attested,
}

/// Lifecycle status of a registered operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ComputeStatus {
    Active,
    Paused,
    Slashed,
}

/// The starting reputation of a freshly-registered node (0..=1000, mirroring the
/// validator scale).
pub const INITIAL_COMPUTE_REPUTATION: u64 = 700;
pub const MAX_COMPUTE_REPUTATION: u64 = 1000;

/// An allow-list entry — the on-chain permission that a governance action grants
/// before an operator may register (BD-2, §6.2.4).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeAllowEntry {
    pub operator: Address,
    pub tier: ComputeTier,
    pub admitted_at_ms: u64,
}

impl ComputeAllowEntry {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ComputeError> {
        serde_json::to_vec(self).map_err(|e| ComputeError::Serialization(e.to_string()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The on-chain registry record for an admitted, registered operator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeNodeInfo {
    pub address: Address,
    pub x25519_pub: [u8; 32],
    pub ed25519_pub: [u8; 32],
    /// ISO-3166 alpha-2 declared processing jurisdiction (§6.2).
    pub jurisdiction: String,
    pub tier: ComputeTier,
    pub reputation: u64,
    pub status: ComputeStatus,
    pub registered_at_ms: u64,
}

impl ComputeNodeInfo {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ComputeError> {
        serde_json::to_vec(self).map_err(|e| ComputeError::Serialization(e.to_string()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// A recorded receipt-batch anchor — the audit record for a batch of off-chain
/// job receipts (the receipts live with the broker; the Merkle root anchors them).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeReceiptAnchor {
    pub merkle_root: [u8; 32],
    pub batch_count: u32,
    pub anchored_at_ms: u64,
}

impl ComputeReceiptAnchor {
    pub fn to_bytes(&self) -> Result<Vec<u8>, ComputeError> {
        serde_json::to_vec(self).map_err(|e| ComputeError::Serialization(e.to_string()))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum ComputeError {
    #[error("not authorized: only the governance authority may perform this action")]
    NotGovernance,
    #[error("operator {0} is already on the allow-list")]
    AlreadyAdmitted(Address),
    #[error("operator is not on the allow-list (must be admitted by governance first)")]
    NotAdmitted,
    #[error("operator is already registered")]
    AlreadyRegistered,
    #[error("node_did/address does not derive from the registered ed25519 key (self-certification failed)")]
    KeyAddressMismatch,
    #[error("jurisdiction must be a 2-letter ISO-3166 code")]
    BadJurisdiction,
    #[error("operator is not registered")]
    NotRegistered,
    #[error("empty receipt batch")]
    EmptyBatch,
    #[error("a receipt batch with this Merkle root has already been anchored")]
    AlreadyAnchored,
    #[error("failed to serialize compute record: {0}")]
    Serialization(String),
}

/// **Governance:** admit an operator to the allow-list (§6.2.4). Rejects a
/// duplicate admission. `authorized` = the caller may act as governance.
pub fn execute_compute_admit(
    authorized: bool,
    operator: &Address,
    tier: ComputeTier,
    existing: Option<&ComputeAllowEntry>,
    timestamp_ms: u64,
) -> Result<ComputeAllowEntry, ComputeError> {
    if !authorized {
        return Err(ComputeError::NotGovernance);
    }
    if existing.is_some() {
        return Err(ComputeError::AlreadyAdmitted(*operator));
    }
    Ok(ComputeAllowEntry {
        operator: *operator,
        tier,
        admitted_at_ms: timestamp_ms,
    })
}

/// **Self-serve, gated:** an admitted operator registers its keys + jurisdiction.
/// Self-certifying — the sender MUST be the address derived from `ed25519_pub`
/// (the same derivation as `did:solidus`), so a leaked DID cannot be registered
/// by anyone but the key holder. The tier comes from the allow-list entry (an
/// operator cannot self-assign `Attested`).
#[allow(clippy::too_many_arguments)]
pub fn execute_compute_register(
    sender: &Address,
    ed25519_pub: &[u8; 32],
    x25519_pub: &[u8; 32],
    jurisdiction: &str,
    allow: Option<&ComputeAllowEntry>,
    existing_node: Option<&ComputeNodeInfo>,
    timestamp_ms: u64,
) -> Result<ComputeNodeInfo, ComputeError> {
    let allow = allow.ok_or(ComputeError::NotAdmitted)?;
    if existing_node.is_some() {
        return Err(ComputeError::AlreadyRegistered);
    }
    // Self-certification: the sender address must be BLAKE3(ed25519_pub)[..20].
    let vk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_pub)
        .map_err(|_| ComputeError::KeyAddressMismatch)?;
    if Address::from_public_key(&vk) != *sender {
        return Err(ComputeError::KeyAddressMismatch);
    }
    if jurisdiction.len() != 2 || !jurisdiction.bytes().all(|b| b.is_ascii_alphabetic()) {
        return Err(ComputeError::BadJurisdiction);
    }
    Ok(ComputeNodeInfo {
        address: *sender,
        x25519_pub: *x25519_pub,
        ed25519_pub: *ed25519_pub,
        jurisdiction: jurisdiction.to_string(),
        tier: allow.tier,
        reputation: INITIAL_COMPUTE_REPUTATION,
        status: ComputeStatus::Active,
        registered_at_ms: timestamp_ms,
    })
}

/// **Governance:** anchor a batch of off-chain job receipts by their Merkle root
/// (§6.5). Never one tx per job — the root anchors the whole batch. Records are
/// append-only (the executor keys them by a monotonic seq); `already_anchored`
/// signals that this root is already in the secondary root→seq index, in which
/// case the anchor is rejected so a repeat root cannot destroy the prior record.
pub fn execute_compute_anchor(
    authorized: bool,
    merkle_root: [u8; 32],
    batch_count: u32,
    already_anchored: bool,
    timestamp_ms: u64,
) -> Result<ComputeReceiptAnchor, ComputeError> {
    if !authorized {
        return Err(ComputeError::NotGovernance);
    }
    if batch_count == 0 {
        return Err(ComputeError::EmptyBatch);
    }
    if already_anchored {
        return Err(ComputeError::AlreadyAnchored);
    }
    Ok(ComputeReceiptAnchor {
        merkle_root,
        batch_count,
        anchored_at_ms: timestamp_ms,
    })
}

/// **Governance/referee:** slash a cheating operator. A `severe` slash (evidenced
/// DPA/zero-retention breach or collusion) removes it entirely; otherwise its
/// reputation is reduced (saturating) — the §6.5 schedule tuned for compute.
pub fn execute_compute_slash(
    authorized: bool,
    reputation_penalty: u64,
    severe: bool,
    existing_node: Option<&ComputeNodeInfo>,
) -> Result<ComputeNodeInfo, ComputeError> {
    if !authorized {
        return Err(ComputeError::NotGovernance);
    }
    let node = existing_node.ok_or(ComputeError::NotRegistered)?;
    let mut updated = node.clone();
    if severe {
        updated.status = ComputeStatus::Slashed;
        updated.reputation = 0;
    } else {
        updated.reputation = updated.reputation.saturating_sub(reputation_penalty);
    }
    Ok(updated)
}

/// **Governance:** remove an operator from the network entirely. The executor
/// deletes BOTH the allow-list entry AND the node record, so the DID can only
/// re-enter via a **fresh admission + registration** (a cleared record no longer
/// trips `AlreadyRegistered`). Removing an operator that was never admitted (no
/// allow-list entry and no node record) fails with `NotAdmitted` — there is
/// nothing to remove, and a success here would emit a misleading event.
///
/// Note this differs from a non-severe *slash*, which keeps the record with
/// `status=Slashed`; a slashed-but-not-removed node still cannot re-register.
pub fn execute_compute_remove(
    authorized: bool,
    allow: Option<&ComputeAllowEntry>,
    existing_node: Option<&ComputeNodeInfo>,
) -> Result<(), ComputeError> {
    if !authorized {
        return Err(ComputeError::NotGovernance);
    }
    if allow.is_none() && existing_node.is_none() {
        return Err(ComputeError::NotAdmitted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn stranger() -> Address {
        Address::from_bytes([0x11; 20])
    }
    /// A keypair + its derived address (the self-certifying operator identity).
    fn operator() -> (Address, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let ed = sk.verifying_key().to_bytes();
        (Address::from_public_key(&sk.verifying_key()), ed)
    }

    #[test]
    fn admit_requires_governance() {
        let (op, _) = operator();
        assert_eq!(
            execute_compute_admit(false, &op, ComputeTier::Trusted, None, 1),
            Err(ComputeError::NotGovernance)
        );
        let entry = execute_compute_admit(true, &op, ComputeTier::Trusted, None, 1).unwrap();
        assert_eq!(entry.operator, op);
        assert_eq!(entry.tier, ComputeTier::Trusted);
    }

    #[test]
    fn admit_rejects_duplicate() {
        let (op, _) = operator();
        let existing = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Trusted,
            admitted_at_ms: 1,
        };
        assert_eq!(
            execute_compute_admit(true, &op, ComputeTier::Trusted, Some(&existing), 2),
            Err(ComputeError::AlreadyAdmitted(op))
        );
    }

    #[test]
    fn register_requires_admission() {
        let (op, ed) = operator();
        assert_eq!(
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", None, None, 1),
            Err(ComputeError::NotAdmitted)
        );
    }

    #[test]
    fn register_is_self_certifying() {
        let (op, ed) = operator();
        let allow = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Trusted,
            admitted_at_ms: 1,
        };
        // Correct sender (derives from the key) → ok.
        let node =
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), None, 2).unwrap();
        assert_eq!(node.address, op);
        assert_eq!(node.tier, ComputeTier::Trusted);
        assert_eq!(node.reputation, INITIAL_COMPUTE_REPUTATION);
        assert_eq!(node.status, ComputeStatus::Active);
        // Wrong sender (does NOT derive from the key) → rejected.
        assert_eq!(
            execute_compute_register(&stranger(), &ed, &[9u8; 32], "TR", Some(&allow), None, 2),
            Err(ComputeError::KeyAddressMismatch)
        );
    }

    #[test]
    fn register_rejects_bad_jurisdiction_and_double_register() {
        let (op, ed) = operator();
        let allow = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Trusted,
            admitted_at_ms: 1,
        };
        assert_eq!(
            execute_compute_register(&op, &ed, &[9u8; 32], "TUR", Some(&allow), None, 2),
            Err(ComputeError::BadJurisdiction)
        );
        let node =
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), None, 2).unwrap();
        assert_eq!(
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), Some(&node), 3),
            Err(ComputeError::AlreadyRegistered)
        );
    }

    #[test]
    fn anchor_requires_governance_nonempty_and_rejects_duplicate_root() {
        assert_eq!(
            execute_compute_anchor(false, [1u8; 32], 5, false, 1),
            Err(ComputeError::NotGovernance)
        );
        assert_eq!(
            execute_compute_anchor(true, [1u8; 32], 0, false, 1),
            Err(ComputeError::EmptyBatch)
        );
        let a = execute_compute_anchor(true, [1u8; 32], 5, false, 42).unwrap();
        assert_eq!(a.batch_count, 5);
        assert_eq!(a.anchored_at_ms, 42);
        // A root already present in the index is rejected (append-only, no overwrite).
        assert_eq!(
            execute_compute_anchor(true, [1u8; 32], 9, true, 43),
            Err(ComputeError::AlreadyAnchored)
        );
    }

    #[test]
    fn slash_reduces_reputation_and_severe_removes() {
        let (op, ed) = operator();
        let allow = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Trusted,
            admitted_at_ms: 1,
        };
        let node =
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), None, 2).unwrap();

        // Non-governance cannot slash.
        assert_eq!(
            execute_compute_slash(false, 100, false, Some(&node)),
            Err(ComputeError::NotGovernance)
        );
        // A minor slash reduces reputation (saturating).
        let dinged = execute_compute_slash(true, 200, false, Some(&node)).unwrap();
        assert_eq!(dinged.reputation, INITIAL_COMPUTE_REPUTATION - 200);
        assert_eq!(dinged.status, ComputeStatus::Active);
        // A severe slash removes the operator.
        let killed = execute_compute_slash(true, 0, true, Some(&node)).unwrap();
        assert_eq!(killed.reputation, 0);
        assert_eq!(killed.status, ComputeStatus::Slashed);
        // Saturating: a penalty larger than the reputation floors at 0.
        let floored = execute_compute_slash(true, 99_999, false, Some(&node)).unwrap();
        assert_eq!(floored.reputation, 0);
    }

    #[test]
    fn remove_requires_governance_and_fails_when_never_admitted() {
        let (op, ed) = operator();
        let allow = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Trusted,
            admitted_at_ms: 1,
        };
        let node =
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), None, 2).unwrap();
        // Non-governance cannot remove.
        assert_eq!(
            execute_compute_remove(false, Some(&allow), Some(&node)),
            Err(ComputeError::NotGovernance)
        );
        // A registered operator can be removed (executor deletes allow-list + record).
        assert_eq!(
            execute_compute_remove(true, Some(&allow), Some(&node)),
            Ok(())
        );
        // An admitted-but-not-yet-registered operator can also be removed.
        assert_eq!(execute_compute_remove(true, Some(&allow), None), Ok(()));
        // Removing an operator that was never admitted fails (nothing to remove).
        assert_eq!(
            execute_compute_remove(true, None, None),
            Err(ComputeError::NotAdmitted)
        );
    }

    #[test]
    fn records_roundtrip() {
        let (op, ed) = operator();
        let allow = ComputeAllowEntry {
            operator: op,
            tier: ComputeTier::Attested,
            admitted_at_ms: 9,
        };
        assert_eq!(
            ComputeAllowEntry::from_bytes(&allow.to_bytes().unwrap()).unwrap(),
            allow
        );
        let node =
            execute_compute_register(&op, &ed, &[9u8; 32], "TR", Some(&allow), None, 2).unwrap();
        assert_eq!(
            ComputeNodeInfo::from_bytes(&node.to_bytes().unwrap()).unwrap(),
            node
        );
        let anchor = ComputeReceiptAnchor {
            merkle_root: [3u8; 32],
            batch_count: 7,
            anchored_at_ms: 5,
        };
        assert_eq!(
            ComputeReceiptAnchor::from_bytes(&anchor.to_bytes().unwrap()).unwrap(),
            anchor
        );
    }
}

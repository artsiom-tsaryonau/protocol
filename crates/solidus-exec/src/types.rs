//! Frozen Stage-0 core types. These are the interfaces every later stage
//! builds against; changing them after Stage 0 requires a design-doc
//! amendment, not a drive-by edit.

use solidus_crypto::keys::Address;
pub use solidus_state_tree::TreeId;

// ---------------------------------------------------------------------------
// Lanes
// ---------------------------------------------------------------------------

/// The two execution lanes (BD-1). `Transfer`-only traffic from
/// payment-pure senders runs parallel; everything else — the 7 identity
/// payloads, the 2 staking payloads, and *any* tx from a sender that also
/// does one of those in the block — runs strictly serial.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Payment,
    Identity,
}

/// Default per-block cap on identity-lane transactions. Bounds the serial
/// prefix so an issuance burst can never starve the payment lane (§4.3).
pub const DEFAULT_IDENTITY_CAP: usize = 512;

// ---------------------------------------------------------------------------
// State addressing
// ---------------------------------------------------------------------------

/// Which logical namespace a state key lives in.
///
/// `Tree(_)` spaces feed the 4-sub-tree global state root. The remaining
/// spaces are real, consensus-written state (they must be identical across
/// validators) but do **not** bear on the root — mirroring the live chain,
/// where the credential secondary indexes and meta keys live outside the
/// root-scanned column families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateSpace {
    /// One of the four root-bearing sub-trees.
    Tree(TreeId),
    /// Credential-id list keyed by subject DID.
    CredBySubject,
    /// Credential-id list keyed by issuer DID.
    CredByIssuer,
    /// Small metadata keys (v2 fee-burn counter, chain markers).
    Meta,
}

/// A fully-qualified state key: `(space, raw key bytes)`. This is the only
/// coordinate system handlers may use — no handler ever touches a store or
/// column family directly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StateKey {
    pub space: StateSpace,
    pub key: Vec<u8>,
}

impl StateKey {
    pub fn account(addr: &Address) -> Self {
        Self {
            space: StateSpace::Tree(TreeId::Accounts),
            key: addr.as_bytes().to_vec(),
        }
    }

    pub fn did(did: &str) -> Self {
        Self {
            space: StateSpace::Tree(TreeId::Dids),
            key: did.as_bytes().to_vec(),
        }
    }

    pub fn credential(credential_id: &str) -> Self {
        Self {
            space: StateSpace::Tree(TreeId::Credentials),
            key: credential_id.as_bytes().to_vec(),
        }
    }

    pub fn validator(addr: &Address) -> Self {
        Self {
            space: StateSpace::Tree(TreeId::Validators),
            key: addr.as_bytes().to_vec(),
        }
    }

    pub fn cred_by_subject(subject_did: &str) -> Self {
        Self {
            space: StateSpace::CredBySubject,
            key: subject_did.as_bytes().to_vec(),
        }
    }

    pub fn cred_by_issuer(issuer_did: &str) -> Self {
        Self {
            space: StateSpace::CredByIssuer,
            key: issuer_did.as_bytes().to_vec(),
        }
    }

    pub fn meta(key: &[u8]) -> Self {
        Self {
            space: StateSpace::Meta,
            key: key.to_vec(),
        }
    }
}

// ---------------------------------------------------------------------------
// Execution configuration
// ---------------------------------------------------------------------------

/// Which wire format governs signature verification and tx hashing.
///
/// The v2 chain signs and hashes over **bincode** (see [`crate::wire`]);
/// `LegacyJson` exists solely so the reference executor can replay
/// live-chain streams for the Stage-0 parity anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireMode {
    /// Live-chain format: BLAKE3 over serde_json payload/envelope.
    LegacyJson,
    /// v2 format: BLAKE3 over bincode payload/envelope (R-WIRE pin).
    BinaryV2,
    /// V2 rules (bridge): v2 bytes with a domain prefix and the numeric chain id,
    /// so a signature from one chain never verifies on another (spec §6.2 replay).
    BinaryV3 { chain_id: u64 },
}

/// Which canonical order the block's transactions execute in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecOrder {
    /// Raw committed order — the live chain's semantics (parity anchor).
    RawBlock,
    /// v2 semantics (D-ORDER): identity lane first, then payment lane,
    /// each preserving relative block order.
    LanePartitioned,
}

/// Block-end fee settlement policy (Hazard-C rule: the fee destination is
/// never written per-tx; fees accumulate and settle exactly once).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeePolicy {
    /// v2 default: add the block's total fees to the cumulative
    /// `fees_burned_total` meta counter. One write, no hot account.
    Burn,
    /// Optional v2 variant: credit the whole total to the block proposer.
    ProposerReward(Address),
    /// Live-chain policy, kept for the parity anchor: 70% split equally
    /// among validators, 20% to treasury, 10% burned implicitly.
    LegacyDistribute {
        treasury: Address,
        validators: Vec<Address>,
    },
}

/// Consensus-agreed per-block execution context. `timestamp_ms` is the
/// block header timestamp — the sole time source for DID/credential
/// records (determinism invariant, same as the live chain).
#[derive(Debug, Clone, Copy)]
pub struct BlockCtx<'a> {
    pub height: u64,
    pub timestamp_ms: u64,
    pub network: &'a str,
    /// Global state root before this block. Consensus-agreed: the node passes
    /// its forest root, which every honest node computes identically.
    pub parent_state_root: [u8; 32],
}

impl BlockCtx<'_> {
    /// Which execution rules govern THIS block.
    ///
    /// ⛔ DERIVED FROM `height` AND NOTHING ELSE, and it must stay that way.
    /// Two nodes that disagree about the rule set at the same height fork, and
    /// the disagreement stays invisible until their state roots differ. There is
    /// deliberately no way to pass a version in: it is not an input, it is a
    /// consequence of where the block sits in the chain.
    ///
    /// ⚠ There is no signature change anywhere for this. `height` was already
    /// on the context, so every executor and handler can ask without being
    /// rewired, which is what makes threading the version a no-op refactor
    /// rather than a churn of call sites.
    #[must_use]
    pub fn protocol_version(&self) -> crate::protocol::ProtocolVersion {
        crate::protocol::version_at(self.height)
    }
}

/// Full execution options for a block run.
#[derive(Debug, Clone)]
pub struct ExecOptions {
    pub wire: WireMode,
    /// Numeric chain id (the header's `chain_id`). Bound into V3 signatures.
    pub chain_id: u64,
    pub order: ExecOrder,
    pub fee_policy: FeePolicy,
    pub identity_cap: usize,
}

impl ExecOptions {
    /// v2 chain defaults: binary wire, lane-partitioned order, burn fees.
    ///
    /// `wire` is the pre-V2 mode; executors derive the effective mode per block
    /// with [`crate::wire::wire_for_height`].
    pub fn v2_defaults(chain_id: u64) -> Self {
        Self {
            wire: WireMode::BinaryV2,
            chain_id,
            order: ExecOrder::LanePartitioned,
            fee_policy: FeePolicy::Burn,
            identity_cap: DEFAULT_IDENTITY_CAP,
        }
    }

    /// Live-chain-equivalent configuration for the Stage-0 parity anchor.
    pub fn legacy_anchor(treasury: Address, validators: Vec<Address>) -> Self {
        Self {
            wire: WireMode::LegacyJson,
            chain_id: 0,
            order: ExecOrder::RawBlock,
            fee_policy: FeePolicy::LegacyDistribute {
                treasury,
                validators,
            },
            identity_cap: usize::MAX,
        }
    }
}

#[cfg(test)]
mod block_ctx_tests {
    use super::*;

    #[test]
    fn block_ctx_carries_the_parent_state_root() {
        let ctx = BlockCtx {
            height: 1,
            timestamp_ms: 2,
            network: "testnet",
            parent_state_root: [9; 32],
        };
        assert_eq!(ctx.parent_state_root, [9; 32]);
    }
}

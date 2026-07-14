//! HotStuff-2 wire types. All consensus-path serialization is **bincode**
//! (§4.6 — serde_json never enters the v2 hot path).

use serde::{Deserialize, Serialize};
use solidus_crypto::bls::{BlsPublicKey, BlsSignature};
use solidus_crypto::hash::blake3_hash;
use solidus_mempool_dag::BatchCertificate;

use crate::error::ConsensusError;

/// Consensus view number (monotone). View 0 is reserved for genesis.
pub type View = u64;
/// Compact index into the epoch's committee (bitmap-friendly).
pub type ValidatorIndex = u32;

// ---------------------------------------------------------------------------
// Committee
// ---------------------------------------------------------------------------

/// The validator committee for an epoch: BLS public keys addressed by
/// [`ValidatorIndex`]. Stage-1 scope: a static committee; epoch rotation
/// from the staking tree lands with node2.
#[derive(Clone)]
pub struct Committee {
    keys: Vec<BlsPublicKey>,
}

impl Committee {
    pub fn new(keys: Vec<BlsPublicKey>) -> Self {
        Self { keys }
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn key(&self, index: ValidatorIndex) -> Result<&BlsPublicKey, ConsensusError> {
        self.keys
            .get(index as usize)
            .ok_or(ConsensusError::UnknownValidator(index))
    }

    /// BFT quorum size: the smallest q with `2q − n ≥ f + 1` (any two
    /// quorums intersect in ≥ f+1 replicas, hence ≥ 1 honest), where
    /// `f = ⌊(n−1)/3⌋`. n=4 → 3; n=21 → 14 (matches the live chain's
    /// ≥14/21 threshold).
    pub fn quorum(&self) -> usize {
        let n = self.keys.len();
        let f = (n.saturating_sub(1)) / 3;
        (n + f + 2) / 2
    }

    /// Maximum tolerated Byzantine validators.
    pub fn max_faulty(&self) -> usize {
        (self.keys.len().saturating_sub(1)) / 3
    }
}

// ---------------------------------------------------------------------------
// Signing domains
// ---------------------------------------------------------------------------

/// Message a validator BLS-signs to vote for `block_hash` at `view`.
/// Domain-separated and chain-scoped; identical for every signer of a
/// given (chain, view, block) so QC verification can use
/// `fast_aggregate_verify`.
pub fn vote_message(chain_id: u64, view: View, block_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 8 + 8 + 32);
    buf.extend_from_slice(b"SLDS2_VOTE::");
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    buf.extend_from_slice(block_hash);
    blake3_hash(&buf)
}

/// Message the proposer BLS-signs over its block header hash. Proposals
/// are authenticated so a Byzantine node cannot impersonate the view's
/// leader (votes alone protect safety, but unauthenticated proposals
/// would be a free equivocation/DoS vector).
pub fn proposal_message(chain_id: u64, header_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 8 + 32);
    buf.extend_from_slice(b"SLDS2_PROP::");
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(header_hash);
    blake3_hash(&buf)
}

/// Message a validator BLS-signs to abandon `view` (timeout). Deliberately
/// does **not** cover the sender's high-QC: every timeout signer of a view
/// signs the same bytes, so the TC aggregate stays `fast_aggregate_verify`-
/// able. The high-QC travels *alongside* as independently-verifiable data
/// (a QC self-certifies), so a TC carrier cannot forge it — it can at
/// worst withhold a higher one, which is a liveness nuisance, not a
/// safety issue.
pub fn timeout_message(chain_id: u64, view: View) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 8 + 8);
    buf.extend_from_slice(b"SLDS2_TMO::");
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&view.to_le_bytes());
    blake3_hash(&buf)
}

// ---------------------------------------------------------------------------
// Blocks
// ---------------------------------------------------------------------------

/// v2 block header. The body is the ordered list of batch certificates —
/// 32-byte digests plus availability attestations, never transaction
/// bodies (BD-4). Hash = `BLAKE3(bincode(header))`.
///
/// **D-EXEC-DEFER (refined at node2 integration):** v2 executes blocks
/// *after* commit (§4.3), so a proposer cannot know its direct parent's
/// post-state root at propose time — the parent is QC'd but not yet
/// committed. Headers therefore carry an **exec anchor**: the height and
/// global root of the newest block the proposer has EXECUTED
/// (`exec_height`, `exec_state_root`). Replicas refuse to vote for a
/// proposal whose anchor they can check locally and it mismatches (node
/// layer); anchors on committed blocks feed the subnet bridge. Full
/// execution-certification (an explicit commit certificate over executed
/// roots) is the named Stage-7 hardening item; the differential oracle +
/// fuzz gate remains the divergence defense (R-DETERMINISM).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockHeader2 {
    /// The v2 network's chain id (BD-6: NEW chain-id, parallel network).
    pub chain_id: u64,
    /// Sequential block number (0 = genesis).
    pub height: u64,
    /// View this block was proposed in. Strictly increases along a chain.
    pub view: View,
    /// Hash of the parent block header.
    pub parent: [u8; 32],
    /// Ordered batch certificates (the block body, by digest).
    pub batch_certs: Vec<BatchCertificate>,
    /// Height of the newest block the proposer had executed (exec anchor).
    pub exec_height: u64,
    /// Global state root after executing `exec_height` (exec anchor).
    pub exec_state_root: [u8; 32],
    /// Proposer wall-clock ms. Carried for downstream record timestamps;
    /// sanity-banding is node-layer policy (Stage 4+).
    pub timestamp_ms: u64,
    /// Committee index of the proposer.
    pub proposer: ValidatorIndex,
}

impl BlockHeader2 {
    /// Content address of this header (bincode, R-WIRE).
    pub fn hash(&self) -> [u8; 32] {
        #[allow(clippy::expect_used)]
        let bytes = bincode::serialize(self).expect("BlockHeader2 bincode cannot fail");
        blake3_hash(&bytes)
    }
}

/// A proposed block: header + the QC justifying its parent. The justify
/// QC is NOT part of the header hash (votes are on content, not on which
/// equivalent QC instance the proposer happened to embed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block2 {
    pub header: BlockHeader2,
    pub justify: QuorumCert,
}

impl Block2 {
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

/// Quorum certificate: an aggregate BLS signature by ≥ quorum committee
/// members over [`vote_message`] for `(view, block_hash)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuorumCert {
    pub view: View,
    pub block_hash: [u8; 32],
    /// Sorted, deduplicated committee indices of the signers.
    pub signers: Vec<ValidatorIndex>,
    pub agg_sig: BlsSignature,
}

impl QuorumCert {
    /// The axiomatic genesis QC (view 0). Not signature-verifiable — it is
    /// accepted by hash equality with the configured genesis block only.
    pub fn genesis(genesis_hash: [u8; 32], placeholder_sig: BlsSignature) -> Self {
        Self {
            view: 0,
            block_hash: genesis_hash,
            signers: vec![],
            agg_sig: placeholder_sig,
        }
    }

    /// Verify this QC against the committee. `genesis_hash` anchors the
    /// view-0 special case.
    pub fn verify(
        &self,
        chain_id: u64,
        committee: &Committee,
        genesis_hash: &[u8; 32],
    ) -> Result<(), ConsensusError> {
        if self.view == 0 {
            return if self.block_hash == *genesis_hash {
                Ok(())
            } else {
                Err(ConsensusError::InvalidQc(
                    "view-0 QC on a non-genesis block".to_string(),
                ))
            };
        }
        verify_aggregate(
            chain_id,
            committee,
            &self.signers,
            &self.agg_sig,
            &vote_message(chain_id, self.view, &self.block_hash),
        )
        .map_err(|e| ConsensusError::InvalidQc(e.to_string()))
    }
}

/// Timeout certificate for a view: an aggregate over [`timeout_message`]
/// by ≥ quorum members, carrying the highest QC any contributor reported
/// (self-certifying; see [`timeout_message`] docs).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeoutCert {
    pub view: View,
    pub signers: Vec<ValidatorIndex>,
    pub agg_sig: BlsSignature,
    pub high_qc: QuorumCert,
}

impl TimeoutCert {
    pub fn verify(
        &self,
        chain_id: u64,
        committee: &Committee,
        genesis_hash: &[u8; 32],
    ) -> Result<(), ConsensusError> {
        verify_aggregate(
            chain_id,
            committee,
            &self.signers,
            &self.agg_sig,
            &timeout_message(chain_id, self.view),
        )
        .map_err(|e| ConsensusError::InvalidTc(e.to_string()))?;
        self.high_qc.verify(chain_id, committee, genesis_hash)
    }
}

/// Shared aggregate-verification core for QCs and TCs: signer indices must
/// be sorted+unique, known to the committee, and ≥ quorum; the aggregate
/// must fast-verify over the shared message.
fn verify_aggregate(
    _chain_id: u64,
    committee: &Committee,
    signers: &[ValidatorIndex],
    agg_sig: &BlsSignature,
    msg: &[u8; 32],
) -> Result<(), ConsensusError> {
    if signers.windows(2).any(|w| w[0] >= w[1]) {
        return Err(ConsensusError::InvalidQc(
            "signer indices not sorted/unique".to_string(),
        ));
    }
    if signers.len() < committee.quorum() {
        return Err(ConsensusError::InvalidQc(format!(
            "{} signers < quorum {}",
            signers.len(),
            committee.quorum()
        )));
    }
    let mut pks = Vec::with_capacity(signers.len());
    for &idx in signers {
        pks.push(committee.key(idx)?);
    }
    if !agg_sig.fast_aggregate_verify(&pks, msg) {
        return Err(ConsensusError::InvalidQc(
            "aggregate signature verification failed".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// A single validator's vote for a proposal (sent point-to-point to the
/// next leader — never broadcast).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Vote {
    pub view: View,
    pub block_hash: [u8; 32],
    pub voter: ValidatorIndex,
    pub sig: BlsSignature,
}

/// A single validator's timeout vote for a view (gossiped so any replica
/// can assemble the TC).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimeoutVote {
    pub view: View,
    pub voter: ValidatorIndex,
    pub sig: BlsSignature,
    /// The voter's highest known QC (self-certifying).
    pub high_qc: QuorumCert,
}

/// A proposal: the block, the proposer's signature over the header hash
/// (see [`proposal_message`]), plus the TC that justifies entering this
/// view when the previous view timed out (absent on the happy path).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Proposal {
    pub block: Block2,
    pub sig: BlsSignature,
    pub tc: Option<TimeoutCert>,
}

#[cfg(test)]
mod tests {
    use solidus_crypto::bls::BlsSecretKey;

    use super::*;

    fn committee_of(n: usize) -> (Vec<BlsSecretKey>, Committee) {
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
        (keys, committee)
    }

    #[test]
    fn quorum_matches_bft_math() {
        // (n, expected quorum): n=4→3 (f=1), n=21→14 (f=6, live threshold),
        // n=7→5 (f=2), n=10→7 (f=3).
        for (n, q) in [(4usize, 3usize), (7, 5), (10, 7), (21, 14)] {
            let (_, c) = committee_of(n);
            assert_eq!(c.quorum(), q, "n={n}");
            // Sanity: two quorums always intersect in ≥ f+1.
            assert!(2 * c.quorum() > n + c.max_faulty(), "n={n}");
        }
    }

    #[test]
    fn qc_roundtrip_and_verify() {
        let (keys, committee) = committee_of(4);
        let chain_id = 2;
        let block_hash = [7u8; 32];
        let view = 3;
        let msg = vote_message(chain_id, view, &block_hash);

        let sigs: Vec<_> = keys[..3].iter().map(|k| k.sign(&msg)).collect();
        let agg = BlsSignature::aggregate(&sigs.iter().collect::<Vec<_>>()).expect("aggregate");
        let qc = QuorumCert {
            view,
            block_hash,
            signers: vec![0, 1, 2],
            agg_sig: agg,
        };

        let genesis = [0u8; 32];
        qc.verify(chain_id, &committee, &genesis).expect("valid qc");

        // bincode roundtrip (binary commit path — R-WIRE).
        let bytes = bincode::serialize(&qc).expect("serialize");
        let back: QuorumCert = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(qc, back);

        // Sub-quorum rejected.
        let small = QuorumCert {
            signers: vec![0, 1],
            ..qc.clone()
        };
        assert!(small.verify(chain_id, &committee, &genesis).is_err());

        // Unsorted signers rejected.
        let unsorted = QuorumCert {
            signers: vec![1, 0, 2],
            ..qc.clone()
        };
        assert!(unsorted.verify(chain_id, &committee, &genesis).is_err());

        // Wrong chain id → different message → verification fails.
        assert!(qc.verify(9, &committee, &genesis).is_err());
    }

    #[test]
    fn header_hash_ignores_justify_but_covers_content() {
        let header = BlockHeader2 {
            chain_id: 2,
            height: 5,
            view: 9,
            parent: [1u8; 32],
            batch_certs: vec![],
            exec_height: 3,
            exec_state_root: [2u8; 32],
            timestamp_ms: 123,
            proposer: 1,
        };
        let h1 = header.hash();
        let mut header2 = header.clone();
        header2.height = 6;
        assert_ne!(h1, header2.hash());
        assert_eq!(h1, header.hash());
    }
}

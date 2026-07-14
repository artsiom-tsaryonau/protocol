//! Equivocation slashing (§7 Stage-7 hardening — "slashing, closing the
//! Stake/Unstake loop"). The safety-critical half: **detect** a validator
//! that double-signs, and **prove** it with self-contained cryptographic
//! evidence anyone can verify against the committee.
//!
//! Two slashable equivocations in HotStuff-2:
//! - **Double-vote:** a validator signs two votes for *different* block
//!   hashes at the *same* view (violates the one-vote-per-view rule R1 —
//!   the very rule the 2-chain safety proof leans on).
//! - **Double-proposal:** a leader signs two *different* block headers at
//!   the *same* view.
//!
//! Evidence is a pair of the offending signed messages. Verification is
//! stateless: check both signatures against the accused's committee key,
//! confirm same signer + same view + *different* content. A verified piece
//! of evidence is an incontestable slashing proof.
//!
//! **On-chain execution scope:** reducing the offender's stake goes through
//! the staking machinery in `solidus-txns` — which this rebuild reuses
//! UNCHANGED (the moat). `solidus-txns` has no `Slash` payload today, so
//! the stake-reduction *transaction* is a founder decision (add a native
//! payload, or a governance action) recorded as a follow-up. What ships
//! here is the detection + evidence + verification — the part that must be
//! correct and is fully testable now.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::types::{
    proposal_message, vote_message, Committee, Proposal, ValidatorIndex, View, Vote,
};

/// A self-contained, independently-verifiable proof that a validator
/// equivocated.
// Rare, serialized-on-broadcast evidence — the in-memory variant-size
// asymmetry (two inline Votes vs two boxed Proposals) doesn't matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Equivocation {
    /// Two votes, same voter + view, different block hashes.
    DoubleVote { a: Vote, b: Vote },
    /// Two proposals, same proposer + view, different header hashes.
    DoubleProposal { a: Box<Proposal>, b: Box<Proposal> },
}

/// Why a piece of purported evidence is not a valid slashing proof.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum EvidenceError {
    #[error("the two messages are from different validators ({0} vs {1})")]
    DifferentSigners(ValidatorIndex, ValidatorIndex),
    #[error("the two messages are at different views ({0} vs {1})")]
    DifferentViews(View, View),
    #[error("the two messages are identical — not an equivocation")]
    NotConflicting,
    #[error("signature {0} does not verify against the accused's key")]
    BadSignature(u8),
    #[error("validator index {0} is not in the committee")]
    UnknownValidator(ValidatorIndex),
}

impl Equivocation {
    /// The validator this evidence accuses.
    pub fn accused(&self) -> ValidatorIndex {
        match self {
            Equivocation::DoubleVote { a, .. } => a.voter,
            Equivocation::DoubleProposal { a, .. } => a.block.header.proposer,
        }
    }

    /// The view the equivocation occurred at.
    pub fn view(&self) -> View {
        match self {
            Equivocation::DoubleVote { a, .. } => a.view,
            Equivocation::DoubleProposal { a, .. } => a.block.header.view,
        }
    }

    /// Verify this is genuine, incontestable equivocation evidence.
    /// Stateless: both signatures valid, same signer, same view, and the
    /// two messages genuinely conflict.
    pub fn verify(&self, chain_id: u64, committee: &Committee) -> Result<(), EvidenceError> {
        match self {
            Equivocation::DoubleVote { a, b } => {
                if a.voter != b.voter {
                    return Err(EvidenceError::DifferentSigners(a.voter, b.voter));
                }
                if a.view != b.view {
                    return Err(EvidenceError::DifferentViews(a.view, b.view));
                }
                if a.block_hash == b.block_hash {
                    return Err(EvidenceError::NotConflicting);
                }
                let key = committee
                    .key(a.voter)
                    .map_err(|_| EvidenceError::UnknownValidator(a.voter))?;
                if !a
                    .sig
                    .verify(key, &vote_message(chain_id, a.view, &a.block_hash))
                {
                    return Err(EvidenceError::BadSignature(0));
                }
                if !b
                    .sig
                    .verify(key, &vote_message(chain_id, b.view, &b.block_hash))
                {
                    return Err(EvidenceError::BadSignature(1));
                }
                Ok(())
            }
            Equivocation::DoubleProposal { a, b } => {
                let (pa, pb) = (a.block.header.proposer, b.block.header.proposer);
                if pa != pb {
                    return Err(EvidenceError::DifferentSigners(pa, pb));
                }
                if a.block.header.view != b.block.header.view {
                    return Err(EvidenceError::DifferentViews(
                        a.block.header.view,
                        b.block.header.view,
                    ));
                }
                let (ha, hb) = (a.block.hash(), b.block.hash());
                if ha == hb {
                    return Err(EvidenceError::NotConflicting);
                }
                let key = committee
                    .key(pa)
                    .map_err(|_| EvidenceError::UnknownValidator(pa))?;
                if !a.sig.verify(key, &proposal_message(chain_id, &ha)) {
                    return Err(EvidenceError::BadSignature(0));
                }
                if !b.sig.verify(key, &proposal_message(chain_id, &hb)) {
                    return Err(EvidenceError::BadSignature(1));
                }
                Ok(())
            }
        }
    }
}

/// Watches the votes and proposals a node observes and flags the first
/// equivocation from each validator, retaining the full prior message so
/// it can hand back a complete, broadcast-ready [`Equivocation`] on
/// conflict. The node layer feeds it every verified vote/proposal.
///
/// Memory: one entry per (validator, view) until GC. The node calls
/// [`EquivocationDetector::gc`] to drop views below the committed height
/// (already-committed views can't be usefully re-slashed, and a validator
/// that equivocated is caught the first time).
#[derive(Default)]
pub struct EquivocationDetector {
    votes: HashMap<(ValidatorIndex, View), Vote>,
    proposals: HashMap<(ValidatorIndex, View), Proposal>,
    slashed: std::collections::HashSet<ValidatorIndex>,
}

impl EquivocationDetector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_vote(&mut self, vote: &Vote) -> Option<Equivocation> {
        if self.slashed.contains(&vote.voter) {
            return None;
        }
        match self.votes.get(&(vote.voter, vote.view)) {
            Some(prior) if prior.block_hash != vote.block_hash => {
                self.slashed.insert(vote.voter);
                Some(Equivocation::DoubleVote {
                    a: prior.clone(),
                    b: vote.clone(),
                })
            }
            Some(_) => None,
            None => {
                self.votes.insert((vote.voter, vote.view), vote.clone());
                None
            }
        }
    }

    pub fn observe_proposal(&mut self, proposal: &Proposal) -> Option<Equivocation> {
        let proposer = proposal.block.header.proposer;
        let view = proposal.block.header.view;
        if self.slashed.contains(&proposer) {
            return None;
        }
        match self.proposals.get(&(proposer, view)) {
            Some(prior) if prior.block.hash() != proposal.block.hash() => {
                self.slashed.insert(proposer);
                Some(Equivocation::DoubleProposal {
                    a: Box::new(prior.clone()),
                    b: Box::new(proposal.clone()),
                })
            }
            Some(_) => None,
            None => {
                self.proposals.insert((proposer, view), proposal.clone());
                None
            }
        }
    }

    pub fn gc(&mut self, keep_from: View) {
        self.votes.retain(|&(_, v), _| v >= keep_from);
        self.proposals.retain(|&(_, v), _| v >= keep_from);
    }

    pub fn already_slashed(&self, validator: ValidatorIndex) -> bool {
        self.slashed.contains(&validator)
    }
}

#[cfg(test)]
mod tests {
    use solidus_crypto::bls::BlsSecretKey;

    use super::*;
    use crate::types::{proposal_message, vote_message, Block2, BlockHeader2, QuorumCert};

    fn committee_of(n: usize) -> (Vec<BlsSecretKey>, Committee) {
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
        (keys, committee)
    }

    fn signed_vote(
        key: &BlsSecretKey,
        chain: u64,
        voter: ValidatorIndex,
        view: View,
        block: [u8; 32],
    ) -> Vote {
        Vote {
            view,
            block_hash: block,
            voter,
            sig: key.sign(&vote_message(chain, view, &block)),
        }
    }

    fn signed_proposal(
        key: &BlsSecretKey,
        chain: u64,
        proposer: ValidatorIndex,
        view: View,
        height: u64,
    ) -> Proposal {
        let genesis_qc = QuorumCert::genesis([0u8; 32], key.sign(b"g"));
        let header = BlockHeader2 {
            chain_id: chain,
            height,
            view,
            parent: [1u8; 32],
            batch_certs: vec![],
            exec_height: 0,
            exec_state_root: [0u8; 32],
            timestamp_ms: 1,
            proposer,
        };
        let block = Block2 {
            header,
            justify: genesis_qc,
        };
        let sig = key.sign(&proposal_message(chain, &block.hash()));
        Proposal {
            block,
            sig,
            tc: None,
        }
    }

    #[test]
    fn double_vote_is_valid_slashing_evidence() {
        let (keys, committee) = committee_of(4);
        let chain = 2;
        let a = signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]);
        let b = signed_vote(&keys[1], chain, 1, 5, [0xBB; 32]);
        let ev = Equivocation::DoubleVote { a, b };
        ev.verify(chain, &committee).expect("valid equivocation");
        assert_eq!(ev.accused(), 1);
        assert_eq!(ev.view(), 5);
    }

    #[test]
    fn double_vote_rejects_non_equivocation() {
        let (keys, committee) = committee_of(4);
        let chain = 2;

        // Same block twice → not conflicting.
        let a = signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]);
        let same = Equivocation::DoubleVote {
            a: a.clone(),
            b: a.clone(),
        };
        assert_eq!(
            same.verify(chain, &committee),
            Err(EvidenceError::NotConflicting)
        );

        // Different views → not equivocation (allowed to vote in each view).
        let b_diff_view = signed_vote(&keys[1], chain, 1, 6, [0xBB; 32]);
        let dv = Equivocation::DoubleVote {
            a: a.clone(),
            b: b_diff_view,
        };
        assert_eq!(
            dv.verify(chain, &committee),
            Err(EvidenceError::DifferentViews(5, 6))
        );

        // Different signers → not one validator's equivocation.
        let b_other = signed_vote(&keys[2], chain, 2, 5, [0xBB; 32]);
        let ds = Equivocation::DoubleVote { a, b: b_other };
        assert_eq!(
            ds.verify(chain, &committee),
            Err(EvidenceError::DifferentSigners(1, 2))
        );
    }

    #[test]
    fn double_vote_rejects_forged_signature() {
        let (keys, committee) = committee_of(4);
        let chain = 2;
        // b claims to be voter 1 but is signed by voter 2 → bad signature.
        let a = signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]);
        let mut b = signed_vote(&keys[2], chain, 1, 5, [0xBB; 32]);
        b.voter = 1; // lie about who signed
        let ev = Equivocation::DoubleVote { a, b };
        assert!(matches!(
            ev.verify(chain, &committee),
            Err(EvidenceError::BadSignature(1))
        ));
    }

    #[test]
    fn double_vote_rejects_wrong_chain() {
        let (keys, committee) = committee_of(4);
        let a = signed_vote(&keys[1], 2, 1, 5, [0xAA; 32]);
        let b = signed_vote(&keys[1], 2, 1, 5, [0xBB; 32]);
        let ev = Equivocation::DoubleVote { a, b };
        // Signed for chain 2, verified against chain 9 → signatures fail.
        assert!(matches!(
            ev.verify(9, &committee),
            Err(EvidenceError::BadSignature(0))
        ));
    }

    #[test]
    fn double_proposal_is_valid_evidence() {
        let (keys, committee) = committee_of(4);
        let chain = 2;
        let a = signed_proposal(&keys[3], chain, 3, 7, 10);
        let b = signed_proposal(&keys[3], chain, 3, 7, 11); // different height → different hash
        assert_ne!(a.block.hash(), b.block.hash());
        let ev = Equivocation::DoubleProposal {
            a: Box::new(a),
            b: Box::new(b),
        };
        ev.verify(chain, &committee).expect("valid double proposal");
        assert_eq!(ev.accused(), 3);
    }

    #[test]
    fn detector_flags_first_double_vote_and_dedups() {
        let (keys, _committee) = committee_of(4);
        let chain = 2;
        let mut det = EquivocationDetector::new();

        // Honest single vote → nothing.
        assert!(det
            .observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]))
            .is_none());
        // Same vote again → nothing.
        assert!(det
            .observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]))
            .is_none());
        // Conflicting vote at the same view → evidence!
        let ev = det
            .observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xBB; 32]))
            .expect("equivocation detected");
        assert_eq!(ev.accused(), 1);
        assert!(det.already_slashed(1));
        // A third conflicting vote → no duplicate evidence.
        assert!(det
            .observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xCC; 32]))
            .is_none());
    }

    #[test]
    fn detector_flags_double_proposal() {
        let (keys, committee) = committee_of(4);
        let chain = 2;
        let mut det = EquivocationDetector::new();
        assert!(det
            .observe_proposal(&signed_proposal(&keys[0], chain, 0, 4, 10))
            .is_none());
        let ev = det
            .observe_proposal(&signed_proposal(&keys[0], chain, 0, 4, 99))
            .expect("double proposal detected");
        ev.verify(chain, &committee).expect("evidence verifies");
    }

    #[test]
    fn detector_gc_drops_old_views() {
        let (keys, _committee) = committee_of(4);
        let chain = 2;
        let mut det = EquivocationDetector::new();
        det.observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xAA; 32]));
        det.gc(6); // drop view 5
                   // After GC, a conflicting vote at view 5 is no longer detectable
                   // (the prior is gone) — acceptable: committed views aren't re-slashed.
        assert!(det
            .observe_vote(&signed_vote(&keys[1], chain, 1, 5, [0xBB; 32]))
            .is_none());
    }
}

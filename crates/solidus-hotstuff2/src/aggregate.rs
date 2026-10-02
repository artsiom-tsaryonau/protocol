//! Vote and timeout-vote aggregation into QCs / TCs.
//!
//! **Own-vote rule (regression-guarded):** when the local node is one of
//! the N participants, broadcasting alone does not advance local state —
//! the caller must feed its OWN vote through the same `add_*` path before
//! or alongside broadcasting. The live chain's TC-formation wedge
//! (commit 6921d4f) came from violating exactly this; the tests here pin
//! it.

use std::collections::{BTreeMap, HashMap};

use solidus_crypto::bls::BlsSignature;

use crate::error::ConsensusError;
use crate::types::{
    timeout_message, vote_message, Committee, QuorumCert, TimeoutCert, TimeoutVote, ValidatorIndex,
    View, Vote,
};

/// Collects proposal votes per (view, block) and forms a QC at quorum.
#[derive(Default)]
pub struct VoteAggregator {
    /// view → block_hash → voter → signature (BTreeMap keeps signer
    /// indices sorted for the certificate).
    pending: HashMap<View, HashMap<[u8; 32], BTreeMap<ValidatorIndex, BlsSignature>>>,
}

impl VoteAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and record a vote. Returns `Ok(Some(qc))` exactly once —
    /// when this vote completes the quorum. Duplicate votes from the same
    /// voter are ignored; a quorum already reached returns `None` for
    /// late votes (the QC was already emitted).
    pub fn add_vote(
        &mut self,
        chain_id: u64,
        committee: &Committee,
        vote: &Vote,
    ) -> Result<Option<QuorumCert>, ConsensusError> {
        let pk = committee.key(vote.voter)?;
        let msg = vote_message(chain_id, vote.view, &vote.block_hash);
        // ⛔ Verify under the ciphersuite OF THIS VOTE'S VIEW. The core signs with
        // `committee.dst_for_view(view)`; checking with the legacy Basic verify
        // rejects every valid vote from the activation view on, and no QC forms.
        if !vote
            .sig
            .verify_with_dst(pk, &msg, committee.dst_for_view(vote.view))
        {
            return Err(ConsensusError::InvalidSignature(vote.voter));
        }

        let slot = self
            .pending
            .entry(vote.view)
            .or_default()
            .entry(vote.block_hash)
            .or_default();

        let quorum = committee.quorum();
        if slot.len() >= quorum {
            return Ok(None); // QC already formed for this (view, block)
        }
        slot.insert(vote.voter, vote.sig.clone());
        if slot.len() < quorum {
            return Ok(None);
        }

        let signers: Vec<ValidatorIndex> = slot.keys().copied().collect();
        let sigs: Vec<&BlsSignature> = slot.values().collect();
        let agg_sig = BlsSignature::aggregate(&sigs)?;
        Ok(Some(QuorumCert {
            view: vote.view,
            block_hash: vote.block_hash,
            signers,
            agg_sig,
        }))
    }

    /// Drop state for views below `keep_from` (they can no longer form a
    /// certificate we'd use).
    pub fn gc(&mut self, keep_from: View) {
        self.pending.retain(|&v, _| v >= keep_from);
    }
}

/// Collects timeout votes per view and forms a TC at quorum, carrying the
/// highest verified QC any contributor reported.
#[derive(Default)]
pub struct TimeoutAggregator {
    pending: HashMap<View, BTreeMap<ValidatorIndex, (BlsSignature, QuorumCert)>>,
}

impl TimeoutAggregator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify and record a timeout vote (the caller has already verified
    /// `tv.high_qc`). Returns the TC exactly once, at quorum.
    pub fn add_timeout(
        &mut self,
        chain_id: u64,
        committee: &Committee,
        tv: &TimeoutVote,
    ) -> Result<Option<TimeoutCert>, ConsensusError> {
        let pk = committee.key(tv.voter)?;
        let msg = timeout_message(chain_id, tv.view);
        // ⛔ Same rule as `add_vote`: the timeout's own view picks the suite.
        if !tv
            .sig
            .verify_with_dst(pk, &msg, committee.dst_for_view(tv.view))
        {
            return Err(ConsensusError::InvalidSignature(tv.voter));
        }

        let slot = self.pending.entry(tv.view).or_default();
        let quorum = committee.quorum();
        if slot.len() >= quorum {
            return Ok(None);
        }
        slot.insert(tv.voter, (tv.sig.clone(), tv.high_qc.clone()));
        if slot.len() < quorum {
            return Ok(None);
        }

        let signers: Vec<ValidatorIndex> = slot.keys().copied().collect();
        let sigs: Vec<&BlsSignature> = slot.values().map(|(s, _)| s).collect();
        let agg_sig = BlsSignature::aggregate(&sigs)?;
        #[allow(clippy::expect_used)]
        let high_qc = slot
            .values()
            .map(|(_, qc)| qc)
            .max_by_key(|qc| qc.view)
            .expect("quorum slot cannot be empty")
            .clone();
        Ok(Some(TimeoutCert {
            view: tv.view,
            signers,
            agg_sig,
            high_qc,
        }))
    }

    /// How many distinct validators have timed out in `view`.
    ///
    /// Used for view SYNCHRONISATION rather than certificate formation: a
    /// quorum makes a TC, but f+1 already proves at least one honest validator
    /// is in that view, which is enough to follow it there.
    pub fn votes_for(&self, view: View) -> usize {
        self.pending.get(&view).map_or(0, |slot| slot.len())
    }

    pub fn gc(&mut self, keep_from: View) {
        self.pending.retain(|&v, _| v >= keep_from);
    }
}

#[cfg(test)]
mod tests {
    use solidus_crypto::bls::BlsSecretKey;

    use super::*;

    fn setup(n: usize) -> (Vec<BlsSecretKey>, Committee) {
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
        (keys, committee)
    }

    fn vote_from(keys: &[BlsSecretKey], i: usize, chain: u64, view: View, block: [u8; 32]) -> Vote {
        let msg = vote_message(chain, view, &block);
        Vote {
            view,
            block_hash: block,
            voter: i as ValidatorIndex,
            sig: keys[i].sign(&msg),
        }
    }

    #[test]
    fn qc_forms_exactly_at_quorum_including_own_vote() {
        // The own-vote regression pin: a 4-committee needs 3 votes; the
        // aggregating node's OWN vote must count — 2 remote + 1 own = QC.
        let (keys, committee) = setup(4);
        let mut agg = VoteAggregator::new();
        let block = [9u8; 32];

        // Own vote first (the pattern the core enforces).
        let own = vote_from(&keys, 0, 2, 1, block);
        assert!(agg.add_vote(2, &committee, &own).expect("own").is_none());

        let v1 = vote_from(&keys, 1, 2, 1, block);
        assert!(agg.add_vote(2, &committee, &v1).expect("v1").is_none());

        let v2 = vote_from(&keys, 2, 2, 1, block);
        let qc = agg
            .add_vote(2, &committee, &v2)
            .expect("v2")
            .expect("quorum of 3 reached");
        assert_eq!(qc.signers, vec![0, 1, 2]);
        qc.verify(2, &committee, &[0u8; 32]).expect("qc verifies");

        // A late 4th vote does not re-emit the QC.
        let v3 = vote_from(&keys, 3, 2, 1, block);
        assert!(agg.add_vote(2, &committee, &v3).expect("v3").is_none());
    }

    #[test]
    fn duplicate_votes_do_not_count_twice() {
        let (keys, committee) = setup(4);
        let mut agg = VoteAggregator::new();
        let block = [9u8; 32];
        let v = vote_from(&keys, 1, 2, 1, block);
        assert!(agg.add_vote(2, &committee, &v).expect("first").is_none());
        assert!(agg.add_vote(2, &committee, &v).expect("dup").is_none());
        // Still needs two MORE distinct voters.
        let v2 = vote_from(&keys, 2, 2, 1, block);
        assert!(agg.add_vote(2, &committee, &v2).expect("v2").is_none());
    }

    #[test]
    fn bad_signature_is_rejected() {
        let (keys, committee) = setup(4);
        let mut agg = VoteAggregator::new();
        let mut v = vote_from(&keys, 1, 2, 1, [9u8; 32]);
        v.view = 2; // signature no longer matches
        assert!(matches!(
            agg.add_vote(2, &committee, &v),
            Err(ConsensusError::InvalidSignature(1))
        ));
    }

    #[test]
    fn tc_forms_at_quorum_and_carries_max_high_qc() {
        let (keys, committee) = setup(4);
        let mut agg = TimeoutAggregator::new();
        let chain = 2;
        let view = 7;

        // Build two distinct (structurally-valid, genesis-style) QCs.
        let qc_low = QuorumCert::genesis([0u8; 32], keys[0].sign(b"x"));
        let mut qc_high = qc_low.clone();
        qc_high.view = 5;

        let msg = timeout_message(chain, view);
        for (i, hq) in [(0usize, &qc_low), (1, &qc_high)] {
            let tv = TimeoutVote {
                view,
                voter: i as ValidatorIndex,
                sig: keys[i].sign(&msg),
                high_qc: hq.clone(),
            };
            assert!(agg
                .add_timeout(chain, &committee, &tv)
                .expect("tv")
                .is_none());
        }
        let tv = TimeoutVote {
            view,
            voter: 2,
            sig: keys[2].sign(&msg),
            high_qc: qc_low.clone(),
        };
        let tc = agg
            .add_timeout(chain, &committee, &tv)
            .expect("tv")
            .expect("quorum");
        assert_eq!(tc.view, view);
        assert_eq!(tc.signers, vec![0, 1, 2]);
        assert_eq!(tc.high_qc.view, 5, "TC must carry the max reported QC");
    }
}

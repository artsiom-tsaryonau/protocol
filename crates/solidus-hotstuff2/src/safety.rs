//! The HotStuff-2 safety rules — the ONLY module allowed to decide
//! whether this replica votes. Mirrored 1:1 by the TLA+ spec
//! (`tla+/HotStuff2Commit.tla`); change both together or neither.
//!
//! Rules (with the safety argument in `docs/v2-consensus.md`):
//! - **R1 (vote monotonicity):** vote at most once per view, in strictly
//!   increasing views.
//! - **R3 (lock):** the lock is `high_qc` — the highest-view QC ever
//!   seen. Vote for a proposal only if its justify QC's view is ≥ the
//!   lock's view at decision time.
//!
//! (R2 — structural/view-continuity validation — lives in the core's
//! proposal validation, not here: it needs the block store and TC.)

use crate::types::{QuorumCert, View};

pub struct SafetyState {
    last_voted_view: View,
    high_qc: QuorumCert,
}

impl SafetyState {
    /// Start from the genesis QC (view 0).
    pub fn new(genesis_qc: QuorumCert) -> Self {
        Self {
            last_voted_view: 0,
            high_qc: genesis_qc,
        }
    }

    /// The current lock.
    pub fn high_qc(&self) -> &QuorumCert {
        &self.high_qc
    }

    pub fn last_voted_view(&self) -> View {
        self.last_voted_view
    }

    /// Merge a (already-verified) QC into the lock. Returns `true` if the
    /// lock advanced.
    pub fn observe_qc(&mut self, qc: &QuorumCert) -> bool {
        if qc.view > self.high_qc.view {
            self.high_qc = qc.clone();
            true
        } else {
            false
        }
    }

    /// R1 + R3: may this replica vote for a proposal at `proposal_view`
    /// whose justify QC has view `justify_view`? (The caller has already
    /// verified the justify QC and — per the merge-then-check discipline —
    /// called [`SafetyState::observe_qc`] with it, which can only make
    /// this check stricter.)
    pub fn safe_to_vote(&self, proposal_view: View, justify_view: View) -> bool {
        proposal_view > self.last_voted_view && justify_view >= self.high_qc.view
    }

    /// Record that we voted in `view` (call exactly when a vote is
    /// emitted).
    pub fn record_vote(&mut self, view: View) {
        debug_assert!(view > self.last_voted_view, "R1 violated by caller");
        self.last_voted_view = view;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn qc(view: View) -> QuorumCert {
        // Signature content is irrelevant to safety-rule logic; use a
        // structurally-valid placeholder.
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        QuorumCert {
            view,
            block_hash: [view as u8; 32],
            signers: vec![],
            agg_sig: sk.sign(b"placeholder"),
        }
    }

    #[test]
    fn votes_are_monotone_one_per_view() {
        let mut s = SafetyState::new(qc(0));
        assert!(s.safe_to_vote(1, 0));
        s.record_vote(1);
        assert!(
            !s.safe_to_vote(1, 0),
            "second vote in view 1 must be refused"
        );
        assert!(s.safe_to_vote(2, 0));
    }

    #[test]
    fn lock_rejects_stale_justify() {
        let mut s = SafetyState::new(qc(0));
        s.observe_qc(&qc(5));
        // Proposal justified by an older QC than the lock → refuse.
        assert!(!s.safe_to_vote(7, 4));
        // Justified at or above the lock → allowed.
        assert!(s.safe_to_vote(7, 5));
        assert!(s.safe_to_vote(7, 6));
    }

    #[test]
    fn observe_qc_only_advances() {
        let mut s = SafetyState::new(qc(0));
        assert!(s.observe_qc(&qc(3)));
        assert!(!s.observe_qc(&qc(2)));
        assert_eq!(s.high_qc().view, 3);
    }
}

//! Leader election. Safety of the 2-chain rules is elector-agnostic (the
//! TLA+ spec quantifies over arbitrary leaders); the elector only shapes
//! liveness/fairness. Stage-1 ships deterministic round-robin; the
//! VRF-by-stake elector (the live chain's model: committee of 21 from the
//! top-100 by stake) plugs in here when node2 wires the staking tree.

use crate::types::{ValidatorIndex, View};

pub trait LeaderElector: Send + Sync {
    fn leader(&self, view: View) -> ValidatorIndex;
}

/// Boxing an elector keeps it usable as `L` in `ConsensusCore<L, _>` —
/// the node layer picks the elector at runtime from config.
impl LeaderElector for Box<dyn LeaderElector> {
    fn leader(&self, view: View) -> ValidatorIndex {
        (**self).leader(view)
    }
}

/// Deterministic round-robin over the committee.
pub struct RoundRobin {
    committee_size: u32,
}

impl RoundRobin {
    pub fn new(committee_size: usize) -> Self {
        Self {
            committee_size: committee_size as u32,
        }
    }
}

impl LeaderElector for RoundRobin {
    fn leader(&self, view: View) -> ValidatorIndex {
        (view % self.committee_size as u64) as ValidatorIndex
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_robin_cycles() {
        let e = RoundRobin::new(4);
        assert_eq!(e.leader(1), 1);
        assert_eq!(e.leader(4), 0);
        assert_eq!(e.leader(7), 3);
    }
}

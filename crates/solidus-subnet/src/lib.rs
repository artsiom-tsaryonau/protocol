//! # solidus-subnet — subnet framework (Stage 0: interface freeze)
//!
//! Freezes the [`Subnet`] trait and the L1→subnet finalized-root bridge
//! message (§5.7). The runtime (per-subnet HotStuff-2 instance, bridge
//! gossip, commit-QC verification against the L1 validator set) lands in
//! Stage 5; the single REVM EVM subnet implements this trait in Stage 6.
//!
//! Frozen decisions carried by these types (BD-5):
//! - Each subnet owns its store, its own consensus instance, its own block
//!   stream; validators opt in per subnet (launch config: all L1
//!   validators run the one EVM subnet).
//! - The L1's finalized roots are **gossiped** to subnets at every L1
//!   commit; subnet-side identity reads verify inclusion proofs against
//!   those roots — no L1 re-execution, staleness bounded by gossip lag.

pub mod runtime;

use serde::{Deserialize, Serialize};
use solidus_state_tree::TreeId;

/// Bridge message gossiped at each L1 commit (§5.7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct L1FinalizedRoots {
    pub l1_height: u64,
    pub global_root: [u8; 32],
    pub accounts_root: [u8; 32],
    pub dids_root: [u8; 32],
    pub credentials_root: [u8; 32],
    pub validators_root: [u8; 32],
    /// HotStuff-2 commit QC over the L1 block carrying these roots,
    /// serialized. Subnets verify it against the L1 validator set before
    /// accepting the roots (exact QC format is Stage-1-final; opaque here
    /// so consumers don't re-freeze when it lands).
    pub commit_qc: Vec<u8>,
}

impl L1FinalizedRoots {
    /// Root of one sub-tree, addressed the way precompiles ask for it.
    pub fn subtree_root(&self, tree: TreeId) -> [u8; 32] {
        match tree {
            TreeId::Accounts => self.accounts_root,
            TreeId::Dids => self.dids_root,
            TreeId::Credentials => self.credentials_root,
            TreeId::Validators => self.validators_root,
        }
    }
}

/// Errors a subnet can raise while ingesting bridge messages.
#[derive(thiserror::Error, Debug)]
pub enum SubnetError {
    /// The bridge message's commit QC failed verification against the L1
    /// validator set.
    #[error("bridge commit QC rejected at l1_height {l1_height}")]
    InvalidCommitQc { l1_height: u64 },
    /// Bridge messages must arrive at non-decreasing L1 heights.
    #[error("stale bridge message: got {got}, latest {latest}")]
    StaleRoots { got: u64, latest: u64 },
}

/// The subnet runtime contract (frozen Stage 0).
///
/// A subnet is a consensus+execution instance sharing the L1 validator
/// set. The runtime drives it with verified L1 root updates; the subnet
/// exposes its latest verified roots to its own execution layer (e.g. the
/// EVM identity precompiles verify inclusion proofs against
/// [`Subnet::latest_finalized`]).
pub trait Subnet {
    /// Stable subnet identifier (chain-id scoped).
    fn id(&self) -> u64;

    /// Ingest a verified L1 finalized-root update. The runtime has already
    /// checked `commit_qc`; implementations enforce height monotonicity
    /// and update their read state.
    fn on_l1_finalized(&mut self, roots: L1FinalizedRoots) -> Result<(), SubnetError>;

    /// Latest verified root for `tree`, if any bridge message has been
    /// accepted yet. Precompiles compare caller-supplied roots against
    /// exactly this value.
    fn latest_finalized(&self, tree: TreeId) -> Option<[u8; 32]>;

    /// Latest verified L1 height (staleness telemetry).
    fn latest_l1_height(&self) -> Option<u64>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal in-memory Subnet impl proving the trait is implementable
    /// as frozen (the Stage-5 demo subnet grows from this shape).
    struct DemoSubnet {
        latest: Option<L1FinalizedRoots>,
    }

    impl Subnet for DemoSubnet {
        fn id(&self) -> u64 {
            1
        }

        fn on_l1_finalized(&mut self, roots: L1FinalizedRoots) -> Result<(), SubnetError> {
            if let Some(prev) = &self.latest {
                if roots.l1_height < prev.l1_height {
                    return Err(SubnetError::StaleRoots {
                        got: roots.l1_height,
                        latest: prev.l1_height,
                    });
                }
            }
            self.latest = Some(roots);
            Ok(())
        }

        fn latest_finalized(&self, tree: TreeId) -> Option<[u8; 32]> {
            self.latest.as_ref().map(|r| r.subtree_root(tree))
        }

        fn latest_l1_height(&self) -> Option<u64> {
            self.latest.as_ref().map(|r| r.l1_height)
        }
    }

    fn roots_at(h: u64) -> L1FinalizedRoots {
        L1FinalizedRoots {
            l1_height: h,
            global_root: [h as u8; 32],
            accounts_root: [1; 32],
            dids_root: [2; 32],
            credentials_root: [3; 32],
            validators_root: [4; 32],
            commit_qc: vec![],
        }
    }

    #[test]
    fn subnet_tracks_monotonic_roots() {
        let mut subnet = DemoSubnet { latest: None };
        assert!(subnet.latest_finalized(TreeId::Dids).is_none());

        subnet.on_l1_finalized(roots_at(10)).expect("ingest");
        assert_eq!(subnet.latest_l1_height(), Some(10));
        assert_eq!(subnet.latest_finalized(TreeId::Dids), Some([2; 32]));

        let err = subnet.on_l1_finalized(roots_at(9)).expect_err("stale");
        assert!(matches!(
            err,
            SubnetError::StaleRoots { got: 9, latest: 10 }
        ));
    }
}

//! The L1→subnet root bridge: verification of finalized-root
//! announcements and routing to registered subnets.
//!
//! **What "finalized" means here (load-bearing, from D-EXEC-DEFER):** a v2
//! block header carries the *parent's* post-state root. The roots for L1
//! height H are therefore certified by the block at height H+1 — and that
//! block's roots are only FINAL once the consecutive-view 2-chain commit
//! rule holds for it. A merely-QC'd block on an abandoned branch must
//! never feed precompile roots. The bridge attestation consequently
//! carries **full commit evidence** for the child block:
//!
//! - the child [`Block2`] (header + its embedded justify QC),
//! - the QC over the child itself,
//!
//! and verification checks: both QCs verify against the L1 committee; the
//! child QC certifies exactly this header; the justify is at the
//! immediately preceding view (`child.justify.view + 1 == child.view` —
//! the 2-chain commit of the parent... and of the child itself once its
//! own child certifies it). Precisely: this evidence proves the PARENT of
//! the child is committed; the roots we deliver are
//! `child.header.parent_state_root` — the committed parent's post-state.
//! Heights must line up (`roots.l1_height + 1 == child.header.height`).

use serde::{Deserialize, Serialize};
use solidus_hotstuff2::{Block2, BlockHeader2, Committee, QuorumCert};

use crate::{L1FinalizedRoots, Subnet, SubnetError};

/// The decoded content of `L1FinalizedRoots::commit_qc`: full commit
/// evidence for the child block whose header carries the announced roots.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BridgeAttestation {
    /// The COMMITTED parent block's header — its exec anchor is the
    /// (height, root) pair being announced.
    pub parent_header: BlockHeader2,
    /// The child block (header + justify QC on the committed parent).
    pub child: Block2,
    /// QC over the child block itself.
    pub child_qc: QuorumCert,
}

impl BridgeAttestation {
    /// Encode into the opaque `commit_qc` bytes.
    pub fn encode(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        bincode::serialize(self).expect("BridgeAttestation bincode cannot fail")
    }
}

/// Verifies bridge messages against the L1 committee and routes them to
/// registered subnets.
pub struct BridgeVerifier {
    chain_id: u64,
    committee: Committee,
    genesis_hash: [u8; 32],
}

impl BridgeVerifier {
    pub fn new(chain_id: u64, committee: Committee, genesis_hash: [u8; 32]) -> Self {
        Self {
            chain_id,
            committee,
            genesis_hash,
        }
    }

    /// Verify a finalized-root announcement end-to-end. Returns the
    /// verified attestation on success.
    pub fn verify(&self, roots: &L1FinalizedRoots) -> Result<BridgeAttestation, SubnetError> {
        let att: BridgeAttestation =
            bincode::deserialize(&roots.commit_qc).map_err(|_| SubnetError::InvalidCommitQc {
                l1_height: roots.l1_height,
            })?;

        let fail = || SubnetError::InvalidCommitQc {
            l1_height: roots.l1_height,
        };

        // 1. The child QC certifies exactly this child header, at the
        //    child's view.
        if att.child_qc.block_hash != att.child.hash() || att.child_qc.view != att.child.header.view
        {
            return Err(fail());
        }
        att.child_qc
            .verify(self.chain_id, &self.committee, &self.genesis_hash)
            .map_err(|_| fail())?;

        // 2. The child's justify QC verifies and sits at the immediately
        //    preceding view — the consecutive-view 2-chain rule: this is
        //    what makes the PARENT (whose post-state these roots are)
        //    committed.
        if att.child.justify.view + 1 != att.child.header.view {
            return Err(fail());
        }
        if att.child.header.parent != att.child.justify.block_hash {
            return Err(fail());
        }
        att.child
            .justify
            .verify(self.chain_id, &self.committee, &self.genesis_hash)
            .map_err(|_| fail())?;

        // 3. The committed parent is exactly the block the child extends,
        //    and its exec anchor is the (height, root) being announced.
        if att.parent_header.hash() != att.child.header.parent {
            return Err(fail());
        }
        if att.parent_header.exec_state_root != roots.global_root
            || att.parent_header.exec_height != roots.l1_height
        {
            return Err(fail());
        }

        // 4. Sub-tree roots must combine to the global root.
        let combined = solidus_state_tree::global_state_root(
            &roots.accounts_root,
            &roots.dids_root,
            &roots.credentials_root,
            &roots.validators_root,
        );
        if combined != roots.global_root {
            return Err(fail());
        }

        Ok(att)
    }

    /// Verify and deliver to a subnet.
    pub fn deliver<S: Subnet>(
        &self,
        subnet: &mut S,
        roots: L1FinalizedRoots,
    ) -> Result<(), SubnetError> {
        self.verify(&roots)?;
        subnet.on_l1_finalized(roots)
    }
}

/// A minimal root-tracking subnet: verifies nothing itself (the runtime
/// did), stores the latest roots, serves them to its execution layer.
/// The Stage-6 EVM subnet builds on exactly this shape.
pub struct TrackingSubnet {
    id: u64,
    latest: Option<L1FinalizedRoots>,
}

impl TrackingSubnet {
    pub fn new(id: u64) -> Self {
        Self { id, latest: None }
    }
}

impl Subnet for TrackingSubnet {
    fn id(&self) -> u64 {
        self.id
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

    fn latest_finalized(&self, tree: solidus_state_tree::TreeId) -> Option<[u8; 32]> {
        self.latest.as_ref().map(|r| r.subtree_root(tree))
    }

    fn latest_l1_height(&self) -> Option<u64> {
        self.latest.as_ref().map(|r| r.l1_height)
    }
}

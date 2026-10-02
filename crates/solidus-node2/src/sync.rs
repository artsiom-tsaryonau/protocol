//! Verification for blocks fetched from a peer during backfill.
//!
//! ⛔ THIS IS THE TRUST BOUNDARY OF BLOCK SYNC. Everything here operates on
//! bytes a peer chose to send. If any check fails open, a single malicious or
//! buggy peer can hand this node arbitrary state and it will execute it.
//! Nothing in this module returns a partial result: a range is accepted whole
//! or rejected whole.
//!
//! ⚠ THE SUBTLETY THAT SHAPES THE WHOLE DESIGN: a block's `justify` QC
//! certifies its **parent**, never itself. So a fetched range cannot
//! self-certify. It is verified by walking forward — block `i`'s justify must
//! name block `i-1` and carry a valid quorum signature — and the newest block
//! must be anchored by a QC this node ALREADY verified from live consensus.
//! Without that anchor a peer could invent an internally-consistent fork and
//! it would verify perfectly.

use solidus_hotstuff2::{Block2, Committee, QuorumCert};

/// Most blocks one `GetBlockRange` may ask for.
///
/// ⚠ BOUNDS THE RESPONSE, WHICH IS UNTRUSTED INPUT DRIVING AN ALLOCATION.
/// the workspace wire rules cap a block message at 2 MB; v2 blocks measured
/// ~0.1 KB each on the devnet, so 512 stays far inside that while still making
/// backfill progress in useful strides. A responder MUST clamp to this — never
/// trust the requested span.
pub const MAX_BLOCK_RANGE: u64 = 512;

/// Total byte budget for one `BlockRange` reply.
///
/// ⚠ THE COUNT CAP ALONE IS NOT A BOUND. 512 blocks are tiny by themselves, but
/// the batches they certify carry the transactions, so a busy range could be
/// enormous. the workspace wire rules cap a block message at 2 MB; this applies
/// that to the whole reply. Stopping early and answering short is correct.
pub const MAX_RANGE_REPLY_BYTES: usize = 2 * 1024 * 1024;

/// Why a fetched range was rejected. Every variant is a refusal to apply
/// anything from the range, never a request to apply part of it.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum SyncError {
    #[error("empty range")]
    Empty,

    #[error("block at index {index} has chain_id {found}, expected {expected}")]
    WrongChain {
        index: usize,
        found: u64,
        expected: u64,
    },

    #[error("block at index {index} has height {found}, expected {expected} (range must be contiguous and ascending)")]
    NonContiguous {
        index: usize,
        found: u64,
        expected: u64,
    },

    #[error("block at index {index} does not chain to its predecessor")]
    BrokenParentLink { index: usize },

    #[error("block at index {index} carries a justify QC for a different block")]
    JustifyMismatch { index: usize },

    #[error("block at index {index} carries an invalid quorum certificate: {reason}")]
    InvalidQc { index: usize, reason: String },

    #[error(
        "the range has no certified block: its tip is unanchored and there is \
         no successor inside the range to certify anything below it"
    )]
    NothingCertified,

    #[error("the newest block in the range is not the one the trusted anchor QC certifies")]
    UnanchoredTip,
}

/// Verify a contiguous run of fetched blocks before any of it is executed.
///
/// `expected_parent` is the hash of this node's current head, and
/// `anchor_qc` is a certificate this node ALREADY verified through live
/// consensus, certifying the newest block of the range.
///
/// ⚠ `anchor_qc` IS THE ONLY THING TYING THIS RANGE TO REALITY. Every other
/// check proves the range is internally consistent, which a fabricated fork
/// also is. Callers must never pass a QC that arrived alongside the blocks.
/// Proof that a run of blocks passed [`verify_fetched_range`].
///
/// ⛔ THE ONLY WAY TO BUILD ONE IS TO VERIFY. The field is private and this
/// module exposes no other constructor, so an apply path that takes a
/// `VerifiedRange` CANNOT be handed unverified blocks — not by a mistake, not
/// by a later refactor, not by someone who did not read the comment. The
/// earlier draft of this module relied on a doc comment telling callers to
/// verify first, and a doc comment is not a defence.
#[derive(Debug)]
pub struct VerifiedRange {
    blocks: Vec<Block2>,
}

impl VerifiedRange {
    /// The verified blocks, ascending, ready to execute in order.
    pub fn blocks(&self) -> &[Block2] {
        &self.blocks
    }

    /// Height of the first block in the range.
    pub fn first_height(&self) -> u64 {
        // Non-empty by construction: `verify_fetched_range` rejects an empty
        // range before it can build one of these.
        self.blocks.first().map_or(0, |b| b.header.height)
    }
}

/// How a fetched range's newest block is certified.
///
/// ⛔ EVERY APPLIED BLOCK IS CERTIFIED, IN BOTH ARMS. The difference is only
/// WHICH certificate covers the tip, never whether one does.
pub enum RangeAnchor<'a> {
    /// The tip is the block a QC this node verified through live consensus
    /// certifies. The whole range applies.
    ///
    /// This is the LAST chunk of a backfill, and the only chunk that can be
    /// anchored this way: the blocks a lagging node is missing are precisely
    /// the ones it holds no QC for.
    Verified(&'a QuorumCert),

    /// No QC of ours covers the tip, so the tip is DISCARDED and the rest
    /// applies.
    ///
    /// ⚠ TRIMMING IS THE WHOLE DEFENCE, AND IT IS NOT A WEAKER RULE. A peer can
    /// append one block of its own choosing to the end of real history and give
    /// it a genuine justify QC, because that QC certifies the PARENT and the
    /// parent is real. Nothing inside the range contradicts it. Dropping the
    /// tip removes the only position where that is possible.
    TrimTip,
}

pub fn verify_fetched_range(
    blocks: &[Block2],
    chain_id: u64,
    committee: &Committee,
    genesis_hash: &[u8; 32],
    expected_parent: [u8; 32],
    expected_first_height: u64,
    anchor: RangeAnchor<'_>,
) -> Result<VerifiedRange, SyncError> {
    if blocks.is_empty() {
        return Err(SyncError::Empty);
    }

    let mut prev_hash = expected_parent;
    for (index, block) in blocks.iter().enumerate() {
        if block.header.chain_id != chain_id {
            return Err(SyncError::WrongChain {
                index,
                found: block.header.chain_id,
                expected: chain_id,
            });
        }

        let expected_height = expected_first_height + index as u64;
        if block.header.height != expected_height {
            return Err(SyncError::NonContiguous {
                index,
                found: block.header.height,
                expected: expected_height,
            });
        }

        if block.header.parent != prev_hash {
            return Err(SyncError::BrokenParentLink { index });
        }

        // A block's justify certifies its PARENT. The first block's justify
        // therefore covers our existing head, which we already trust, so it is
        // checked for consistency but adds no new information.
        if block.justify.block_hash != prev_hash {
            return Err(SyncError::JustifyMismatch { index });
        }
        block
            .justify
            .verify(chain_id, committee, genesis_hash)
            .map_err(|e| SyncError::InvalidQc {
                index,
                reason: e.to_string(),
            })?;

        prev_hash = block.hash();
    }

    // ⛔ THE ANCHOR. Without one of these two, every check above is satisfiable
    // by a well-formed fork: a peer with a quorum of old keys, or any peer at
    // all if the caller sourced this QC from the same message as the blocks.
    let certified = match anchor {
        RangeAnchor::Verified(qc) => {
            if qc.block_hash != prev_hash {
                return Err(SyncError::UnanchoredTip);
            }
            blocks
        }
        RangeAnchor::TrimTip => {
            // A one-block range has nothing left once the tip is dropped, and
            // returning an empty `VerifiedRange` would hand the apply path a
            // range whose `first_height` is meaningless.
            let (_tip, rest) = blocks.split_last().ok_or(SyncError::Empty)?;
            if rest.is_empty() {
                return Err(SyncError::NothingCertified);
            }
            rest
        }
    };

    Ok(VerifiedRange {
        blocks: certified.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
    use solidus_hotstuff2::{vote_message, BlockHeader2};

    const CHAIN: u64 = 7;
    const GENESIS: [u8; 32] = [0xAA; 32];

    struct Fixture {
        keys: Vec<BlsSecretKey>,
        committee: Committee,
    }

    fn fixture() -> Fixture {
        let keys: Vec<BlsSecretKey> = (0..4).map(|_| BlsSecretKey::generate()).collect();
        let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
        Fixture { keys, committee }
    }

    /// A genuine quorum certificate: 3 of 4 sign the real vote message.
    fn qc(f: &Fixture, view: u64, block_hash: [u8; 32]) -> QuorumCert {
        let msg = vote_message(CHAIN, view, &block_hash);
        let sigs: Vec<BlsSignature> = f.keys[..3].iter().map(|k| k.sign(&msg)).collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        QuorumCert {
            view,
            block_hash,
            signers: vec![0, 1, 2],
            agg_sig: BlsSignature::aggregate(&refs).expect("aggregate"),
        }
    }

    fn header(height: u64, parent: [u8; 32]) -> BlockHeader2 {
        BlockHeader2 {
            chain_id: CHAIN,
            height,
            view: height,
            parent,
            batch_certs: vec![],
            exec_height: height.saturating_sub(1),
            exec_state_root: [0; 32],
            timestamp_ms: 1_700_000_000_000 + height,
            proposer: 0,
        }
    }

    /// A valid run of `n` blocks from `first_height`, chained onto `head`,
    /// plus a trusted anchor QC over the newest one.
    fn chain(f: &Fixture, head: [u8; 32], first_height: u64, n: u64) -> (Vec<Block2>, QuorumCert) {
        let mut blocks = Vec::new();
        let mut prev = head;
        for i in 0..n {
            let h = first_height + i;
            let b = Block2 {
                header: header(h, prev),
                justify: qc(f, h, prev),
            };
            prev = b.hash();
            blocks.push(b);
        }
        (blocks, qc(f, first_height + n, prev))
    }

    #[test]
    fn a_well_formed_anchored_range_verifies() {
        let f = fixture();
        let head = [1u8; 32];
        let (blocks, anchor) = chain(&f, head, 5, 3);
        let verified = verify_fetched_range(&blocks, CHAIN, &f.committee, &GENESIS, head, 5, RangeAnchor::Verified(&anchor))
            .expect("positive control: if this fails, every negative test below passes for the wrong reason");
        assert_eq!(verified.blocks().len(), 3);
        assert_eq!(verified.first_height(), 5);
    }

    #[test]
    fn an_empty_range_is_rejected() {
        let f = fixture();
        let anchor = qc(&f, 1, [9u8; 32]);
        assert_eq!(
            verify_fetched_range(
                &[],
                CHAIN,
                &f.committee,
                &GENESIS,
                [1u8; 32],
                5,
                RangeAnchor::Verified(&anchor)
            )
            .unwrap_err(),
            SyncError::Empty
        );
    }

    #[test]
    fn a_block_from_another_chain_is_rejected() {
        let f = fixture();
        let head = [1u8; 32];
        let (mut blocks, anchor) = chain(&f, head, 5, 2);
        blocks[1].header.chain_id = CHAIN + 1;
        assert!(matches!(
            verify_fetched_range(
                &blocks,
                CHAIN,
                &f.committee,
                &GENESIS,
                head,
                5,
                RangeAnchor::Verified(&anchor)
            ),
            Err(SyncError::WrongChain { index: 1, .. })
        ));
    }

    #[test]
    fn a_gap_in_heights_is_rejected() {
        let f = fixture();
        let head = [1u8; 32];
        let (blocks, anchor) = chain(&f, head, 5, 2);
        assert!(matches!(
            verify_fetched_range(
                &blocks,
                CHAIN,
                &f.committee,
                &GENESIS,
                head,
                6,
                RangeAnchor::Verified(&anchor)
            ),
            Err(SyncError::NonContiguous { index: 0, .. })
        ));
    }

    #[test]
    fn a_range_that_does_not_chain_to_our_head_is_rejected() {
        let f = fixture();
        let (blocks, anchor) = chain(&f, [1u8; 32], 5, 2);
        assert!(matches!(
            verify_fetched_range(
                &blocks,
                CHAIN,
                &f.committee,
                &GENESIS,
                [2u8; 32],
                5,
                RangeAnchor::Verified(&anchor)
            ),
            Err(SyncError::BrokenParentLink { index: 0 })
        ));
    }

    #[test]
    fn a_tampered_block_breaks_its_successors_parent_link() {
        let f = fixture();
        let head = [1u8; 32];
        let (mut blocks, anchor) = chain(&f, head, 5, 3);
        blocks[0].header.timestamp_ms += 1;
        assert!(matches!(
            verify_fetched_range(
                &blocks,
                CHAIN,
                &f.committee,
                &GENESIS,
                head,
                5,
                RangeAnchor::Verified(&anchor)
            ),
            Err(SyncError::BrokenParentLink { index: 1 })
        ));
    }

    #[test]
    fn a_quorum_of_non_committee_keys_is_rejected() {
        let f = fixture();
        let head = [1u8; 32];
        let (mut blocks, anchor) = chain(&f, head, 5, 2);
        let outsiders = fixture();
        blocks[1].justify = qc(&outsiders, 6, blocks[0].hash());
        assert!(matches!(
            verify_fetched_range(
                &blocks,
                CHAIN,
                &f.committee,
                &GENESIS,
                head,
                5,
                RangeAnchor::Verified(&anchor)
            ),
            Err(SyncError::InvalidQc { index: 1, .. })
        ));
    }

    /// An intermediate chunk keeps everything its own successors certify, and
    /// drops the one block nothing does.
    #[test]
    fn an_unanchored_chunk_applies_every_block_its_successors_certify() {
        let f = fixture();
        let head = [0x11; 32];
        let (blocks, _) = chain(&f, head, 5, 4);

        let verified = verify_fetched_range(
            &blocks,
            CHAIN,
            &f.committee,
            &GENESIS,
            head,
            5,
            RangeAnchor::TrimTip,
        )
        .expect("an unanchored chunk is usable, minus its tip");

        assert_eq!(
            verified.blocks().len(),
            3,
            "four blocks arrived and three are certified by the block that              follows them; the fourth has no successor in the range"
        );
        assert_eq!(verified.first_height(), 5);
        assert_eq!(
            verified.blocks().last().map(|b| b.header.height),
            Some(7),
            "the tip at height 8 must not be applied"
        );
    }

    /// ⛔ THE ATTACK THE TRIM EXISTS FOR. A peer appends one block of its own
    /// to the end of real history. Its justify QC is GENUINE, because that QC
    /// certifies the parent and the parent is real, so every check inside the
    /// range passes. Only the trim removes it.
    #[test]
    fn a_peer_appended_tip_never_reaches_the_apply_path() {
        let f = fixture();
        let head = [0x11; 32];
        let (honest, _) = chain(&f, head, 5, 3);
        let real_tip = honest.last().expect("non-empty").hash();

        // The peer extends the real chain with a block only it has seen.
        let mut forged = honest.clone();
        let (mut extra, _) = chain(&f, real_tip, 8, 1);
        forged.append(&mut extra);

        let verified = verify_fetched_range(
            &forged,
            CHAIN,
            &f.committee,
            &GENESIS,
            head,
            5,
            RangeAnchor::TrimTip,
        )
        .expect("the honest prefix is still usable");

        assert_eq!(
            verified.blocks().len(),
            3,
            "the appended block must be dropped, leaving only the prefix its              successors certify"
        );
        assert!(
            verified.blocks().iter().all(|b| b.header.height <= 7),
            "no block the peer chose unilaterally may survive"
        );
    }

    /// A single unanchored block certifies nothing at all, so there is no
    /// honest prefix to keep.
    #[test]
    fn a_lone_unanchored_block_is_refused_rather_than_trimmed_to_nothing() {
        let f = fixture();
        let head = [0x11; 32];
        let (blocks, _) = chain(&f, head, 5, 1);

        assert!(
            matches!(
                verify_fetched_range(
                    &blocks,
                    CHAIN,
                    &f.committee,
                    &GENESIS,
                    head,
                    5,
                    RangeAnchor::TrimTip
                ),
                Err(SyncError::NothingCertified)
            ),
            "trimming the only block leaves nothing, which must be an error              rather than an empty success"
        );
    }

    #[test]
    fn an_internally_consistent_fork_is_rejected_by_the_anchor() {
        // The check that matters most. Every structural rule above is satisfied
        // by a fabricated chain, because a peer can always build one that is
        // internally perfect. Only the anchor QC, verified earlier through live
        // consensus, ties a range to the real chain.
        let f = fixture();
        let head = [1u8; 32];
        let (fork, _) = chain(&f, head, 5, 3);
        let (_, real_anchor) = chain(&f, head, 5, 4);
        assert_eq!(
            verify_fetched_range(
                &fork,
                CHAIN,
                &f.committee,
                &GENESIS,
                head,
                5,
                RangeAnchor::Verified(&real_anchor)
            )
            .unwrap_err(),
            SyncError::UnanchoredTip,
            "a self-consistent fork must not verify against the real chain's anchor"
        );
    }
}

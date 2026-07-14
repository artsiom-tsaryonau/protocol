//! Backfill walk: pure helpers + the storage-only `apply_fetched` step. The
//! async loop wiring lives in main.rs. STORAGE-ONLY: reads/writes only the
//! canonical-ledger CFs via `ledger`; never mutates consensus state.

use solidus_consensus::ledger;
use solidus_consensus::types::Block;
use solidus_state::store::Store;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum BackfillError {
    #[error("hash mismatch: requested {requested:?} got {got:?}")]
    HashMismatch { requested: [u8; 32], got: [u8; 32] },

    /// A range fetch's first block did not chain to the expected parent — either
    /// our local canon head (when extending) or the genesis sentinel (when canon
    /// is empty). Either the peer started at the wrong seq or is on a different fork.
    #[error("range fetch: first block parent {got:?} did not match expected parent {expected:?}")]
    RangeParentMismatch { expected: [u8; 32], got: [u8; 32] },

    /// Within a range fetch's response, block[i].parent_hash != block[i-1].hash().
    /// The responder returned a non-contiguous chain or a fork transition mid-range.
    #[error("range fetch: block at offset {offset} parent_hash does not chain from previous")]
    RangeChainBroken { offset: usize },

    /// A range fetch's `from_seq` parameter didn't match our actual canon head
    /// + 1. Likely a logic error in the caller; rejected to keep canon contiguous.
    #[error("range fetch: from_seq {from_seq} does not equal canon_head + 1 = {expected}")]
    RangeSeqMismatch { from_seq: u64, expected: u64 },
}

/// The genesis sentinel parent used by build_block for the first block.
pub const GENESIS_PARENT: [u8; 32] = [0u8; 32];

/// A fetched block is valid for `requested` iff its content hash matches.
pub fn validate_fetched(block: &Block, requested: &[u8; 32]) -> Result<(), BackfillError> {
    let got = block.hash();
    if &got == requested {
        Ok(())
    } else {
        Err(BackfillError::HashMismatch {
            requested: *requested,
            got,
        })
    }
}

/// True if `block` is the first block (its parent is the genesis sentinel).
pub fn is_first_block(block: &Block) -> bool {
    block.header.parent_hash == GENESIS_PARENT
}

/// Given the seq the walk connected at (`Some(n)` = a known canon entry at seq n;
/// `None` = the walk reached the first block / genesis floor), and `pending`
/// hashes collected newest-first, return (seq, hash) appends in ascending order.
pub fn assign_seqs(
    connect_seq: Option<u64>,
    pending_newest_first: &[[u8; 32]],
) -> Vec<(u64, [u8; 32])> {
    let start = match connect_seq {
        Some(n) => n + 1,
        None => 0,
    };
    pending_newest_first
        .iter()
        .rev()
        .enumerate()
        .map(|(i, h)| (start + i as u64, *h))
        .collect()
}

/// Mid-operation walk progress toward the committed tip.
#[derive(Default)]
pub struct WalkState {
    /// Hashes collected on the current backward walk, newest-first.
    pub pending: Vec<[u8; 32]>,
    /// The hash currently being obtained (None = idle / start from target).
    pub cursor: Option<[u8; 32]>,
}

/// Decide the next hash to obtain to start/continue a walk toward `target`.
/// Returns None when `target` is already the canon head (nothing to do).
pub fn next_cursor(
    state: &WalkState,
    target: [u8; 32],
    canon_head_hash: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    if canon_head_hash == Some(target) {
        return None;
    }
    Some(state.cursor.unwrap_or(target))
}

/// Canonical seq of `hash` if it is in CF_CANON (scan back from the head). Only
/// runs during backfill; canon scans are cheap relative to network round-trips.
pub fn canon_seq_of(store: &Store, hash: &[u8; 32]) -> Option<u64> {
    let (head, _) = ledger::canon_head(store).ok().flatten()?;
    let mut seq = head;
    loop {
        if ledger::canon_get(store, seq).ok().flatten().as_ref() == Some(hash) {
            return Some(seq);
        }
        if seq == 0 {
            return None;
        }
        seq -= 1;
    }
}

/// Append the collected `pending` chain into CF_CANON, connecting at
/// `connect_seq` (`None` = genesis floor), then reset the walk. STORAGE-ONLY.
fn commit_pending(store: &Store, connect_seq: Option<u64>, walk: &mut WalkState) {
    for (seq, h) in assign_seqs(connect_seq, &walk.pending) {
        let _ = ledger::canon_append(store, seq, &h);
    }
    *walk = WalkState::default();
}

/// Apply a fetched block (validated against `want`), then walk back through any
/// locally-held ancestors, extending CF_CANON when the walk connects to a known
/// canon entry or the genesis floor. Returns `Some(hash)` = the next ancestor to
/// fetch over the network, or `None` = connected (canon extended) / done.
/// STORAGE-ONLY: writes only CF_BLOCK_BY_HASH / CF_CANON / CF_META.
pub fn apply_fetched(
    store: &Store,
    want: [u8; 32],
    block: Block,
    walk: &mut WalkState,
) -> Result<Option<[u8; 32]>, BackfillError> {
    validate_fetched(&block, &want)?;
    let _ = ledger::put_block_by_hash(store, &block);
    walk.pending.push(want);
    let mut last_was_first = is_first_block(&block);
    let mut cursor = block.header.parent_hash;
    loop {
        if last_was_first {
            commit_pending(store, None, walk); // genesis floor → seq 0..
            return Ok(None);
        }
        if let Some(seq) = canon_seq_of(store, &cursor) {
            commit_pending(store, Some(seq), walk); // connect to known canon
            return Ok(None);
        }
        // Consume a locally-held ancestor without a network round-trip.
        match ledger::get_block_by_hash(store, &cursor).ok().flatten() {
            Some(b) => {
                walk.pending.push(cursor);
                last_was_first = is_first_block(&b);
                cursor = b.header.parent_hash;
            }
            None => {
                walk.cursor = Some(cursor);
                return Ok(Some(cursor));
            }
        }
    }
}

/// Apply a contiguous forward range of blocks (C-3 batch sync). Validates:
///   1. `from_seq == canon_head + 1` (i.e. the range starts EXACTLY where our
///      local canon ends; no gap, no overlap). When canon is empty, requires
///      `from_seq == 0`.
///   2. The first block's `parent_hash` matches our current canon-head hash,
///      or the genesis sentinel when canon is empty.
///   3. For each subsequent block, `parent_hash == previous_block.hash()`.
///
/// If ALL checks pass, the range is written to `CF_BLOCK_BY_HASH` and appended
/// to `CF_CANON`. On any failure, NO writes occur (callers can retry safely).
/// STORAGE-ONLY: writes only `CF_BLOCK_BY_HASH` + `CF_CANON` + `CF_META`.
///
/// Returns the number of blocks applied (== `blocks.len()` on success).
pub fn apply_block_range(
    store: &Store,
    from_seq: u64,
    blocks: &[Block],
) -> Result<usize, BackfillError> {
    if blocks.is_empty() {
        return Ok(0);
    }

    // Determine the expected parent of the first block + verify the start seq.
    let head = ledger::canon_head(store).ok().flatten();
    let expected_parent = match head {
        Some((head_seq, head_hash)) => {
            let expected = head_seq + 1;
            if from_seq != expected {
                return Err(BackfillError::RangeSeqMismatch { from_seq, expected });
            }
            head_hash
        }
        None => {
            if from_seq != 0 {
                return Err(BackfillError::RangeSeqMismatch {
                    from_seq,
                    expected: 0,
                });
            }
            GENESIS_PARENT
        }
    };

    // Validate the chain inside the range BEFORE any writes — atomic semantics.
    if blocks[0].header.parent_hash != expected_parent {
        return Err(BackfillError::RangeParentMismatch {
            expected: expected_parent,
            got: blocks[0].header.parent_hash,
        });
    }
    for i in 1..blocks.len() {
        if blocks[i].header.parent_hash != blocks[i - 1].hash() {
            return Err(BackfillError::RangeChainBroken { offset: i });
        }
    }

    // All checks pass — append. Writes are not transactional with RocksDB at
    // this level, but failures here are storage errors (disk full, etc.) and
    // the validator can recover by re-running the walker on next tick.
    for (i, block) in blocks.iter().enumerate() {
        let seq = from_seq + i as u64;
        if ledger::put_block_by_hash(store, block).is_err() {
            return Err(BackfillError::RangeChainBroken { offset: i });
        }
        if ledger::canon_append(store, seq, &block.hash()).is_err() {
            return Err(BackfillError::RangeChainBroken { offset: i });
        }
    }

    Ok(blocks.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_consensus::types::{Block, BlockHeader};
    use solidus_crypto::keys::Address;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn store() -> Arc<Store> {
        let dir = tempdir().unwrap();
        Arc::new(Store::open(dir.path()).unwrap())
    }

    fn blk(parent: [u8; 32]) -> Block {
        Block {
            header: BlockHeader {
                height: 1,
                round: 1,
                parent_hash: parent,
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 0,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        }
    }

    #[test]
    fn validate_rejects_wrong_hash() {
        let b = blk([0u8; 32]);
        assert!(validate_fetched(&b, &b.hash()).is_ok());
        assert!(matches!(
            validate_fetched(&b, &[9u8; 32]),
            Err(BackfillError::HashMismatch { .. })
        ));
    }

    #[test]
    fn is_first_block_detects_genesis_parent() {
        assert!(is_first_block(&blk([0u8; 32])));
        assert!(!is_first_block(&blk([1u8; 32])));
    }

    #[test]
    fn assign_seqs_from_genesis_floor() {
        let h0 = [10u8; 32];
        let h1 = [11u8; 32];
        let h2 = [12u8; 32];
        // newest-first [h2,h1,h0] -> ascending (0,h0),(1,h1),(2,h2)
        assert_eq!(
            assign_seqs(None, &[h2, h1, h0]),
            vec![(0, h0), (1, h1), (2, h2)]
        );
    }

    #[test]
    fn assign_seqs_from_connect_point() {
        let h6 = [16u8; 32];
        let h7 = [17u8; 32];
        assert_eq!(assign_seqs(Some(5), &[h7, h6]), vec![(6, h6), (7, h7)]);
    }

    #[test]
    fn next_cursor_starts_at_target_and_stops_at_head() {
        let s = WalkState::default();
        assert_eq!(next_cursor(&s, [5u8; 32], Some([5u8; 32])), None); // already at tip
        assert_eq!(next_cursor(&s, [5u8; 32], Some([4u8; 32])), Some([5u8; 32])); // from target
        let s2 = WalkState {
            pending: vec![[5u8; 32]],
            cursor: Some([4u8; 32]),
        };
        assert_eq!(next_cursor(&s2, [5u8; 32], None), Some([4u8; 32])); // continue from cursor
    }

    #[test]
    fn apply_fetched_rebuilds_canon_from_local_blocks() {
        let s = store();
        let b0 = blk([0u8; 32]);
        let b1 = blk(b0.hash());
        let b2 = blk(b1.hash());
        ledger::put_block_by_hash(&s, &b0).unwrap();
        ledger::put_block_by_hash(&s, &b1).unwrap();
        ledger::put_block_by_hash(&s, &b2).unwrap();
        let mut walk = WalkState::default();
        let next = apply_fetched(&s, b2.hash(), b2.clone(), &mut walk).unwrap();
        assert_eq!(next, None, "connected to genesis floor");
        assert_eq!(ledger::canon_get(&s, 0).unwrap(), Some(b0.hash()));
        assert_eq!(ledger::canon_get(&s, 1).unwrap(), Some(b1.hash()));
        assert_eq!(ledger::canon_get(&s, 2).unwrap(), Some(b2.hash()));
        assert_eq!(ledger::canon_head(&s).unwrap(), Some((2, b2.hash())));
    }

    #[test]
    fn apply_fetched_requests_next_when_parent_missing() {
        let s = store();
        let b0 = blk([0u8; 32]);
        let b1 = blk(b0.hash());
        // Only the tip is present; its parent is missing -> must fetch the parent.
        let mut walk = WalkState::default();
        let next = apply_fetched(&s, b1.hash(), b1.clone(), &mut walk).unwrap();
        assert_eq!(next, Some(b0.hash()), "must request the missing parent");
        assert_eq!(walk.cursor, Some(b0.hash()));
    }

    // ----------------------------------------------------------------------
    // apply_block_range (C-3 batch forward sync)
    // ----------------------------------------------------------------------

    /// Distinct-hash block helper for range tests. Same shape as `blk` but
    /// takes height so that two blocks with the same parent serialize to
    /// distinct bytes -> distinct hashes (height is in the serialized header).
    fn blk_h(parent: [u8; 32], height: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                round: height,
                parent_hash: parent,
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 0,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        }
    }

    #[test]
    fn apply_block_range_empty_is_noop() {
        let s = store();
        let n = apply_block_range(&s, 0, &[]).unwrap();
        assert_eq!(n, 0);
        assert!(ledger::canon_head(&s).unwrap().is_none());
    }

    #[test]
    fn apply_block_range_from_empty_canon_starting_at_zero() {
        let s = store();
        let b0 = blk_h([0u8; 32], 0);
        let b1 = blk_h(b0.hash(), 1);
        let b2 = blk_h(b1.hash(), 2);
        let n = apply_block_range(&s, 0, &[b0.clone(), b1.clone(), b2.clone()]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(ledger::canon_get(&s, 0).unwrap(), Some(b0.hash()));
        assert_eq!(ledger::canon_get(&s, 1).unwrap(), Some(b1.hash()));
        assert_eq!(ledger::canon_get(&s, 2).unwrap(), Some(b2.hash()));
        assert_eq!(ledger::canon_head(&s).unwrap(), Some((2, b2.hash())));
    }

    #[test]
    fn apply_block_range_extends_existing_canon() {
        let s = store();
        let b0 = blk_h([0u8; 32], 0);
        ledger::put_block_by_hash(&s, &b0).unwrap();
        ledger::canon_append(&s, 0, &b0.hash()).unwrap();
        let b1 = blk_h(b0.hash(), 1);
        let b2 = blk_h(b1.hash(), 2);
        let n = apply_block_range(&s, 1, &[b1.clone(), b2.clone()]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(ledger::canon_head(&s).unwrap(), Some((2, b2.hash())));
    }

    #[test]
    fn apply_block_range_rejects_wrong_from_seq() {
        let s = store();
        let b0 = blk_h([0u8; 32], 0);
        ledger::put_block_by_hash(&s, &b0).unwrap();
        ledger::canon_append(&s, 0, &b0.hash()).unwrap();
        let b2 = blk_h([7u8; 32], 2); // peer started at 2, but our canon head is 0
        let err = apply_block_range(&s, 2, &[b2]).unwrap_err();
        assert!(matches!(
            err,
            BackfillError::RangeSeqMismatch {
                from_seq: 2,
                expected: 1
            }
        ));
        // Canon must remain unchanged after the rejection.
        assert_eq!(ledger::canon_head(&s).unwrap(), Some((0, b0.hash())));
    }

    #[test]
    fn apply_block_range_rejects_wrong_first_parent() {
        let s = store();
        let b0 = blk_h([0u8; 32], 0);
        ledger::put_block_by_hash(&s, &b0).unwrap();
        ledger::canon_append(&s, 0, &b0.hash()).unwrap();
        // b1's parent_hash doesn't match b0's hash → fork detected at the boundary.
        let b1_fork = blk_h([99u8; 32], 1);
        let err = apply_block_range(&s, 1, &[b1_fork]).unwrap_err();
        assert!(matches!(err, BackfillError::RangeParentMismatch { .. }));
        assert_eq!(ledger::canon_head(&s).unwrap(), Some((0, b0.hash())));
    }

    #[test]
    fn apply_block_range_rejects_internal_chain_break() {
        let s = store();
        let b0 = blk_h([0u8; 32], 0);
        let b1 = blk_h(b0.hash(), 1);
        let b2_bad = blk_h([42u8; 32], 2); // claims a wrong parent — breaks the chain
        let err = apply_block_range(&s, 0, &[b0, b1, b2_bad]).unwrap_err();
        assert!(matches!(err, BackfillError::RangeChainBroken { offset: 2 }));
        // No partial writes — even though b0 + b1 chained correctly, the
        // failure on b2 voids the whole range.
        assert!(ledger::canon_head(&s).unwrap().is_none());
    }

    #[test]
    fn apply_block_range_rejects_from_seq_nonzero_on_empty_canon() {
        let s = store();
        let b5 = blk_h([0u8; 32], 5);
        let err = apply_block_range(&s, 5, &[b5]).unwrap_err();
        assert!(matches!(
            err,
            BackfillError::RangeSeqMismatch {
                from_seq: 5,
                expected: 0
            }
        ));
    }
}

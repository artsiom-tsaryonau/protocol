//! Canonical-ledger storage: blocks by hash + a contiguous seq->hash index.
//! Storage-only layer over `Store`; never touches consensus state.

use crate::types::Block;
use solidus_state::store::{Store, StoreError, CF_BLOCK_BY_HASH, CF_CANON, CF_META};

const CANON_HEAD_SEQ: &[u8] = b"canon_head_seq";
const CANON_HEAD_HASH: &[u8] = b"canon_head_hash";

#[derive(thiserror::Error, Debug)]
pub enum LedgerError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("serde error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("corrupt canon value")]
    Corrupt,
}

/// Persist a committed block keyed by its content hash.
pub fn put_block_by_hash(store: &Store, block: &Block) -> Result<(), LedgerError> {
    let bytes = serde_json::to_vec(block)?;
    store.put(CF_BLOCK_BY_HASH, &block.hash(), &bytes)?;
    Ok(())
}

/// Fetch a committed block by its content hash.
pub fn get_block_by_hash(store: &Store, hash: &[u8; 32]) -> Result<Option<Block>, LedgerError> {
    match store.get(CF_BLOCK_BY_HASH, hash)? {
        Some(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        None => Ok(None),
    }
}

/// Whether a block with this hash is stored locally.
pub fn has_block(store: &Store, hash: &[u8; 32]) -> Result<bool, LedgerError> {
    Ok(store.get(CF_BLOCK_BY_HASH, hash)?.is_some())
}

/// The contiguous canonical tip, or `None` if nothing is canonicalized yet.
pub fn canon_head(store: &Store) -> Result<Option<(u64, [u8; 32])>, LedgerError> {
    let seq = match store.get(CF_META, CANON_HEAD_SEQ)? {
        Some(b) => u64::from_le_bytes(b.as_slice().try_into().map_err(|_| LedgerError::Corrupt)?),
        None => return Ok(None),
    };
    let hash = match store.get(CF_META, CANON_HEAD_HASH)? {
        Some(b) => <[u8; 32]>::try_from(b.as_slice()).map_err(|_| LedgerError::Corrupt)?,
        None => return Ok(None),
    };
    Ok(Some((seq, hash)))
}

/// Append `hash` at `seq` and advance the canon head pointer.
///
/// The head pointer is MONOTONE: re-writing an old seq (idempotent walker
/// re-walks; a lagging engine catching up on the shared dev store) records
/// the CF_CANON entry but never moves the head backward. Without this, a
/// lagging engine's backfill walker re-appending an early block regressed
/// the pointer past blocks another engine had already canonicalized —
/// and restart-resume (which trusts the pointer) then orphaned them.
/// (A read-then-write interleave across engines can still lose one
/// advance for a tick; the walker's next pass and the forward-scan in
/// `canon_tip_scan` both repair it.)
pub fn canon_append(store: &Store, seq: u64, hash: &[u8; 32]) -> Result<(), LedgerError> {
    store.put(CF_CANON, &seq.to_le_bytes(), hash)?;
    let advance = match canon_head(store)? {
        Some((cur, _)) => seq >= cur,
        None => true,
    };
    if advance {
        store.put(CF_META, CANON_HEAD_SEQ, &seq.to_le_bytes())?;
        store.put(CF_META, CANON_HEAD_HASH, hash)?;
    }
    Ok(())
}

/// The TRUE canonical tip: start at the head pointer and scan forward
/// through contiguous CF_CANON entries. Heals datadirs whose head pointer
/// lags the actual entries (possible under the pre-monotone `canon_append`
/// or a lost read-then-write interleave between engines).
pub fn canon_tip_scan(store: &Store) -> Result<Option<(u64, [u8; 32])>, LedgerError> {
    let (mut seq, mut hash) = match canon_head(store)? {
        Some(head) => head,
        None => return Ok(None),
    };
    while let Some(next) = canon_get(store, seq + 1)? {
        seq += 1;
        hash = next;
    }
    Ok(Some((seq, hash)))
}

/// The hash at canonical `seq`, if present.
pub fn canon_get(store: &Store, seq: u64) -> Result<Option<[u8; 32]>, LedgerError> {
    match store.get(CF_CANON, &seq.to_le_bytes())? {
        Some(b) => Ok(Some(
            <[u8; 32]>::try_from(b.as_slice()).map_err(|_| LedgerError::Corrupt)?,
        )),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader};
    use solidus_crypto::keys::Address;
    use std::sync::Arc;
    use tempfile::tempdir;

    fn test_block(height: u64, parent: [u8; 32]) -> Block {
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

    fn store() -> Arc<Store> {
        let dir = tempdir().unwrap();
        Arc::new(Store::open(dir.path()).unwrap())
    }

    #[test]
    fn block_by_hash_roundtrip_and_has_block() {
        let s = store();
        let b = test_block(1, [0u8; 32]);
        assert!(!has_block(&s, &b.hash()).unwrap());
        put_block_by_hash(&s, &b).unwrap();
        assert!(has_block(&s, &b.hash()).unwrap());
        assert_eq!(
            get_block_by_hash(&s, &b.hash()).unwrap().unwrap().hash(),
            b.hash()
        );
        assert!(get_block_by_hash(&s, &[9u8; 32]).unwrap().is_none());
    }

    #[test]
    fn canon_head_none_when_empty() {
        let s = store();
        assert!(canon_head(&s).unwrap().is_none());
    }

    #[test]
    fn canon_append_advances_head_and_get_returns_entries() {
        let s = store();
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        canon_append(&s, 0, &h0).unwrap();
        canon_append(&s, 1, &h1).unwrap();
        assert_eq!(canon_head(&s).unwrap(), Some((1, h1)));
        assert_eq!(canon_get(&s, 0).unwrap(), Some(h0));
        assert_eq!(canon_get(&s, 1).unwrap(), Some(h1));
        assert_eq!(canon_get(&s, 2).unwrap(), None);
    }

    /// A lagging engine's walker re-appending an early block must NOT move
    /// the head pointer backward — that regression orphaned newer blocks
    /// under restart-resume (found live 2026-07-13).
    #[test]
    fn canon_append_head_is_monotone() {
        let s = store();
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        canon_append(&s, 0, &h0).unwrap();
        canon_append(&s, 1, &h1).unwrap();
        // Idempotent re-append of an OLD seq (walker catch-up):
        canon_append(&s, 0, &h0).unwrap();
        assert_eq!(
            canon_head(&s).unwrap(),
            Some((1, h1)),
            "head must not regress on old-seq re-append"
        );
        // The CF_CANON entry itself is still written.
        assert_eq!(canon_get(&s, 0).unwrap(), Some(h0));
    }

    /// canon_tip_scan heals a head pointer that lags the real entries
    /// (possible on datadirs written by the pre-monotone canon_append).
    #[test]
    fn canon_tip_scan_heals_lagging_head_pointer() {
        let s = store();
        let h0 = [1u8; 32];
        let h1 = [2u8; 32];
        let h2 = [3u8; 32];
        canon_append(&s, 0, &h0).unwrap();
        canon_append(&s, 1, &h1).unwrap();
        canon_append(&s, 2, &h2).unwrap();
        // Simulate a regressed pointer (as the old blind canon_append could
        // leave behind after a lagging walker's re-append).
        s.put(CF_META, CANON_HEAD_SEQ, &0u64.to_le_bytes()).unwrap();
        s.put(CF_META, CANON_HEAD_HASH, &h0).unwrap();

        assert_eq!(canon_head(&s).unwrap(), Some((0, h0)), "pointer lags");
        assert_eq!(
            canon_tip_scan(&s).unwrap(),
            Some((2, h2)),
            "scan must recover the true contiguous tip"
        );
    }
}

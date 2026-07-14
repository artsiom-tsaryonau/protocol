//! In-memory batch store — the worker-local storage certified batches
//! resolve from. Digest-checked on insert, so anything stored can be
//! re-served byte-exactly. RocksDB-backed persistence is a `store2`
//! concern (Stage 4); the executor-facing [`BatchResolver`] contract is
//! identical either way.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::types::{Batch, BatchDigest, BatchResolver, MempoolError, ResolveError};

#[derive(Default)]
pub struct BatchStore {
    batches: HashMap<BatchDigest, Batch>,
}

impl BatchStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a batch, verifying the bytes hash to `expected` (the
    /// availability guarantee starts here: never ack what you cannot
    /// re-serve).
    pub fn insert_verified(
        &mut self,
        batch: Batch,
        expected: BatchDigest,
    ) -> Result<(), MempoolError> {
        if batch.digest() != expected {
            return Err(MempoolError::DigestMismatch);
        }
        self.batches.insert(expected, batch);
        Ok(())
    }

    pub fn contains(&self, digest: &BatchDigest) -> bool {
        self.batches.contains_key(digest)
    }

    pub fn len(&self) -> usize {
        self.batches.len()
    }

    pub fn is_empty(&self) -> bool {
        self.batches.is_empty()
    }

    /// Drop a batch (after its block's execution is durable — node-layer
    /// retention policy).
    pub fn remove(&mut self, digest: &BatchDigest) {
        self.batches.remove(digest);
    }
}

impl BatchResolver for BatchStore {
    fn resolve(&self, digest: &BatchDigest) -> Result<Batch, ResolveError> {
        self.batches
            .get(digest)
            .cloned()
            .ok_or(ResolveError::NotFound(*digest))
    }
}

/// Shared handle: the worker writes, the executor reads (BD-4).
pub type SharedBatchStore = Arc<RwLock<BatchStore>>;

/// Resolver view over the shared store.
pub struct SharedResolver(pub SharedBatchStore);

impl BatchResolver for SharedResolver {
    fn resolve(&self, digest: &BatchDigest) -> Result<Batch, ResolveError> {
        #[allow(clippy::expect_used)]
        self.0
            .read()
            .expect("batch store lock poisoned")
            .resolve(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_verified_rejects_wrong_digest() {
        let mut store = BatchStore::new();
        let batch = Batch {
            transactions: vec![],
        };
        let wrong = BatchDigest([1u8; 32]);
        assert!(matches!(
            store.insert_verified(batch.clone(), wrong),
            Err(MempoolError::DigestMismatch)
        ));
        store
            .insert_verified(batch.clone(), batch.digest())
            .expect("correct digest");
        assert!(store.contains(&batch.digest()));
    }

    #[test]
    fn resolver_roundtrip_and_missing() {
        let mut store = BatchStore::new();
        let batch = Batch {
            transactions: vec![],
        };
        store
            .insert_verified(batch.clone(), batch.digest())
            .expect("insert");
        assert_eq!(store.resolve(&batch.digest()).expect("resolve"), batch);
        assert!(matches!(
            store.resolve(&BatchDigest([9u8; 32])),
            Err(ResolveError::NotFound(_))
        ));
    }
}

use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};

// ---------------------------------------------------------------------------
// Column family constants
// ---------------------------------------------------------------------------

/// Column family for account state (address -> Account).
///
/// Holds the LIVE / speculative view: writes during `execute_block`
/// (proposer-side and receiver-side validation) land here immediately,
/// before the block reaches 3-chain commit. Use [`CF_COMMITTED_ACCOUNTS`]
/// for reads that must reflect finalized state only.
pub const CF_ACCOUNTS: &str = "accounts";

/// Column family for the COMMITTED account view (address -> Account).
///
/// A mirror of [`CF_ACCOUNTS`] kept current by `HotStuffEngine::try_commit`:
/// when a block is finalized via 3-chain, its touched accounts are copied
/// from `CF_ACCOUNTS` here. RPC reads (`getBalance`/`getNonce`) target this
/// CF so callers see only finalized balances, not in-flight speculation.
pub const CF_COMMITTED_ACCOUNTS: &str = "committed_accounts";
/// Column family for full blocks (height -> Block).
pub const CF_BLOCKS: &str = "blocks";
/// Column family for block headers (height -> Header).
pub const CF_HEADERS: &str = "headers";
/// Column family for transaction receipts (tx_hash -> Receipt).
pub const CF_RECEIPTS: &str = "receipts";
/// Column family for Merkle tree nodes (hash -> node bytes).
pub const CF_MERKLE: &str = "merkle";
/// Column family for DID documents (did_string -> DidDocument bytes).
pub const CF_DIDS: &str = "dids";
/// Column family for credential records (credential_id -> CredentialRecord bytes).
pub const CF_CREDENTIALS: &str = "credentials";

/// Owned key-value pairs returned by [`Store::iter_cf`].
pub type CfEntries = Vec<(Vec<u8>, Vec<u8>)>;
/// Column family for credential index by subject DID (subject_did -> [credential_id]).
pub const CF_CRED_BY_SUBJECT: &str = "cred_by_subject";
/// Column family for credential index by issuer DID (issuer_did -> [credential_id]).
pub const CF_CRED_BY_ISSUER: &str = "cred_by_issuer";
/// Column family for validator records (address_bytes -> ValidatorInfo).
pub const CF_VALIDATORS: &str = "validators";
/// Committed blocks keyed by their content hash (the canonical-ledger store).
pub const CF_BLOCK_BY_HASH: &str = "block_by_hash";
/// Contiguous canonical index: seq (u64 LE) -> block hash ([u8;32]).
pub const CF_CANON: &str = "canon";
/// Small metadata keys (canon head pointer).
pub const CF_META: &str = "meta";

// Compute-network CFs (Rebuild #5 §6.5). AUXILIARY — deliberately NOT part of the
// 4-tree global state root, so adding them does not fork the live chain. Pre-
// mainnet the "stake" is reputation/points (no consensus-critical value); at
// mainnet the registry graduates into the state root as a fifth tree.
/// Compute allow-list: operator address -> ComputeAllowEntry.
pub const CF_COMPUTE_ALLOWLIST: &str = "compute_allowlist";
/// Compute node registry: operator address -> ComputeNodeInfo.
pub const CF_COMPUTE_NODES: &str = "compute_nodes";
/// Anchored receipt batches — append-only. Three disjoint key kinds, kept
/// distinct by fixed length: anchor seq (u64 LE, 8 bytes) -> ComputeReceiptAnchor
/// (the primary record); Merkle root (32 bytes) -> anchor seq (u64 LE)
/// (duplicate-root index); and `meta:next_anchor_seq` (20 bytes) -> next seq
/// (u64 LE). A repeat root is rejected, never overwriting the prior record.
pub const CF_COMPUTE_ANCHORS: &str = "compute_anchors";

/// All column families used by the store.
pub const COLUMN_FAMILIES: &[&str] = &[
    CF_ACCOUNTS,
    CF_COMMITTED_ACCOUNTS,
    CF_BLOCKS,
    CF_HEADERS,
    CF_RECEIPTS,
    CF_MERKLE,
    CF_DIDS,
    CF_CREDENTIALS,
    CF_CRED_BY_SUBJECT,
    CF_CRED_BY_ISSUER,
    CF_VALIDATORS,
    CF_BLOCK_BY_HASH,
    CF_CANON,
    CF_META,
    CF_COMPUTE_ALLOWLIST,
    CF_COMPUTE_NODES,
    CF_COMPUTE_ANCHORS,
];

// ---------------------------------------------------------------------------
// StoreError
// ---------------------------------------------------------------------------

/// Errors produced by the key-value store.
#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    /// An error originating from RocksDB.
    #[error("rocksdb error: {0}")]
    Rocks(#[from] rocksdb::Error),

    /// The requested column family does not exist.
    #[error("column family not found: {0}")]
    CfNotFound(String),

    /// A serialization / deserialization error.
    #[error("serde error: {0}")]
    Serde(String),
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// A thin wrapper around RocksDB that enforces column-family-based access.
pub struct Store {
    db: DB,
}

impl Store {
    /// Open (or create) a store at the given filesystem path.
    ///
    /// All column families listed in [`COLUMN_FAMILIES`] are created if they do
    /// not already exist.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Conservative tuning for low disk + low RAM nodes (testnet validators on
        // small VPS). RocksDB defaults are generous (64 MiB write buffer per CF,
        // unbounded WAL, large SST targets) which causes dev-data to grow ~10 GiB
        // an hour from empty-block churn alone. These caps keep growth bounded
        // without meaningfully hurting throughput at the testnet block rate.
        opts.set_max_total_wal_size(64 * 1024 * 1024); // 64 MiB total WAL across all CFs
        opts.set_keep_log_file_num(1); // one rolling LOG, not 1000
        opts.set_recycle_log_file_num(0); // don't keep recycled WALs
        opts.set_max_open_files(128); // bound fd usage
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_write_buffer_size(8 * 1024 * 1024); // 8 MiB memtable per CF
        opts.set_max_write_buffer_number(2); // small flush queue
        opts.set_target_file_size_base(8 * 1024 * 1024); // 8 MiB SSTs at L0
        opts.set_max_bytes_for_level_base(64 * 1024 * 1024); // 64 MiB L1 cap
        opts.set_level_compaction_dynamic_level_bytes(true); // smarter level sizing

        let mut cf_opts = Options::default();
        cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        cf_opts.set_write_buffer_size(4 * 1024 * 1024);
        cf_opts.set_target_file_size_base(8 * 1024 * 1024);

        let cf_descriptors: Vec<ColumnFamilyDescriptor> = COLUMN_FAMILIES
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, cf_opts.clone()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)?;
        Ok(Self { db })
    }

    /// Read a value by column family and key.
    ///
    /// Returns `Ok(None)` when the key does not exist.
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StoreError::CfNotFound(cf_name.to_string()))?;
        let value = self.db.get_cf(&cf, key)?;
        Ok(value)
    }

    /// Write a key-value pair into the given column family.
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StoreError::CfNotFound(cf_name.to_string()))?;
        self.db.put_cf(&cf, key, value)?;
        Ok(())
    }

    /// Delete a key from the given column family.
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<(), StoreError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StoreError::CfNotFound(cf_name.to_string()))?;
        self.db.delete_cf(&cf, key)?;
        Ok(())
    }

    /// Create a new write batch for atomic multi-key writes.
    pub fn new_write_batch(&self) -> StoreBatch {
        StoreBatch {
            inner: WriteBatch::default(),
        }
    }

    /// Atomically apply a write batch to the database.
    pub fn write_batch(&self, batch: StoreBatch) -> Result<(), StoreError> {
        self.db.write(batch.inner)?;
        Ok(())
    }

    /// Iterate over all key-value pairs in a column family.
    pub fn iter_cf(&self, cf_name: &str) -> Result<CfEntries, StoreError> {
        let cf = self
            .db
            .cf_handle(cf_name)
            .ok_or_else(|| StoreError::CfNotFound(cf_name.to_string()))?;
        let iter = self.db.iterator_cf(&cf, rocksdb::IteratorMode::Start);
        let mut pairs = Vec::new();
        for item in iter {
            let (k, v) = item?;
            pairs.push((k.to_vec(), v.to_vec()));
        }
        Ok(pairs)
    }

    /// Expose the underlying `rocksdb::DB` for advanced use (e.g. obtaining CF
    /// handles when building a `StoreBatch`).
    pub fn inner(&self) -> &DB {
        &self.db
    }
}

// ---------------------------------------------------------------------------
// StoreBatch
// ---------------------------------------------------------------------------

/// An atomic write batch that buffers mutations until committed via
/// [`Store::write_batch`].
pub struct StoreBatch {
    inner: WriteBatch,
}

impl StoreBatch {
    /// Buffer a put operation for the given column family.
    ///
    /// # Panics
    ///
    /// Panics if `cf_name` does not exist in the database. Callers should use
    /// one of the `CF_*` constants.
    pub fn put(&mut self, db: &DB, cf_name: &str, key: &[u8], value: &[u8]) {
        let cf = db
            .cf_handle(cf_name)
            .unwrap_or_else(|| panic!("column family '{cf_name}' not found"));
        self.inner.put_cf(&cf, key, value);
    }

    /// Buffer a delete operation for the given column family.
    ///
    /// # Panics
    ///
    /// Panics if `cf_name` does not exist in the database.
    pub fn delete(&mut self, db: &DB, cf_name: &str, key: &[u8]) {
        let cf = db
            .cf_handle(cf_name)
            .unwrap_or_else(|| panic!("column family '{cf_name}' not found"));
        self.inner.delete_cf(&cf, key);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> Store {
        let dir = tempdir().expect("failed to create temp dir");
        Store::open(dir.path()).expect("failed to open store")
    }

    #[test]
    fn open_and_close() {
        let dir = tempdir().expect("failed to create temp dir");
        {
            let _store = Store::open(dir.path()).expect("failed to open store");
        }
        // Re-open to prove the DB was closed cleanly.
        let _store = Store::open(dir.path()).expect("failed to re-open store");
    }

    #[test]
    fn put_and_get() {
        let store = open_tmp();
        store
            .put(CF_ACCOUNTS, b"alice", b"100")
            .expect("put failed");
        let val = store
            .get(CF_ACCOUNTS, b"alice")
            .expect("get failed")
            .expect("value should exist");
        assert_eq!(val, b"100");
    }

    #[test]
    fn get_missing_key_returns_none() {
        let store = open_tmp();
        let val = store.get(CF_ACCOUNTS, b"nonexistent").expect("get failed");
        assert!(val.is_none());
    }

    #[test]
    fn delete_removes_key() {
        let store = open_tmp();
        store
            .put(CF_BLOCKS, b"block_0", b"data")
            .expect("put failed");
        store.delete(CF_BLOCKS, b"block_0").expect("delete failed");
        let val = store.get(CF_BLOCKS, b"block_0").expect("get failed");
        assert!(val.is_none());
    }

    #[test]
    fn write_batch_is_atomic() {
        let store = open_tmp();
        let mut batch = store.new_write_batch();
        batch.put(store.inner(), CF_ACCOUNTS, b"bob", b"200");
        batch.put(store.inner(), CF_ACCOUNTS, b"carol", b"300");
        store.write_batch(batch).expect("batch write failed");

        let bob = store
            .get(CF_ACCOUNTS, b"bob")
            .expect("get failed")
            .expect("bob should exist");
        let carol = store
            .get(CF_ACCOUNTS, b"carol")
            .expect("get failed")
            .expect("carol should exist");
        assert_eq!(bob, b"200");
        assert_eq!(carol, b"300");
    }

    #[test]
    fn different_column_families_are_isolated() {
        let store = open_tmp();
        store
            .put(CF_ACCOUNTS, b"key", b"accounts_val")
            .expect("put failed");
        store
            .put(CF_BLOCKS, b"key", b"blocks_val")
            .expect("put failed");

        let a = store
            .get(CF_ACCOUNTS, b"key")
            .expect("get failed")
            .expect("accounts value should exist");
        let b = store
            .get(CF_BLOCKS, b"key")
            .expect("get failed")
            .expect("blocks value should exist");

        assert_eq!(a, b"accounts_val");
        assert_eq!(b, b"blocks_val");
    }

    #[test]
    fn invalid_cf_returns_error() {
        let store = open_tmp();
        let err = store
            .get("nonexistent_cf", b"key")
            .expect_err("should fail for invalid CF");
        assert!(
            matches!(err, StoreError::CfNotFound(ref name) if name == "nonexistent_cf"),
            "expected CfNotFound, got: {err:?}"
        );
    }

    #[test]
    fn new_canonical_cfs_are_usable() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.put(CF_BLOCK_BY_HASH, b"h", b"block").unwrap();
        store.put(CF_CANON, &0u64.to_le_bytes(), b"hash").unwrap();
        store
            .put(CF_META, b"canon_head_seq", &0u64.to_le_bytes())
            .unwrap();
        assert_eq!(
            store.get(CF_BLOCK_BY_HASH, b"h").unwrap().as_deref(),
            Some(&b"block"[..])
        );
        assert_eq!(
            store.get(CF_CANON, &0u64.to_le_bytes()).unwrap().as_deref(),
            Some(&b"hash"[..])
        );
    }
}

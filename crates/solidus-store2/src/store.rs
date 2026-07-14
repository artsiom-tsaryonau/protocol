//! The v2 store: hot state CFs + cold history CFs, one WriteBatch per
//! block, range-prunable cold data.

use std::path::Path;

use rocksdb::{ColumnFamilyDescriptor, WriteBatch, DB};
use solidus_exec::{DeltaSet, ExecError, StateKey, StateReader, StateSpace};
use solidus_txns::types::Receipt;

use crate::profile::Profile;

// ---------------------------------------------------------------------------
// Column families
// ---------------------------------------------------------------------------

/// Hot CFs — one per executor state space (point-read tuned).
pub const CF_HOT: &[&str] = &[
    "s_accounts",
    "s_dids",
    "s_credentials",
    "s_validators",
    "s_cred_by_subject",
    "s_cred_by_issuer",
    "s_meta",
];

/// Cold CFs — history, bulk-write tuned, prunable.
/// - `blocks`:   block_hash → opaque block bytes (consensus encodes)
/// - `canon`:    height_be(8) → block_hash(32)
/// - `receipts`: height_be(8) ++ tx_hash(32) → bincode(Receipt)
///   (height-prefixed so pruning is one range-delete)
/// - `batches`:  batch digest → bincode(Batch) (mempool persistence)
pub const CF_COLD: &[&str] = &["blocks", "canon", "receipts", "batches"];

const META_CANON_HEAD: &[u8] = b"canon_head_height";

/// Owned key-value pairs from a state-space scan.
pub type SpaceEntries = Vec<(Vec<u8>, Vec<u8>)>;

fn cf_for_space(space: StateSpace) -> &'static str {
    match space {
        StateSpace::Tree(solidus_state_tree_id) => match solidus_state_tree_id {
            solidus_exec::types::TreeId::Accounts => "s_accounts",
            solidus_exec::types::TreeId::Dids => "s_dids",
            solidus_exec::types::TreeId::Credentials => "s_credentials",
            solidus_exec::types::TreeId::Validators => "s_validators",
        },
        StateSpace::CredBySubject => "s_cred_by_subject",
        StateSpace::CredByIssuer => "s_cred_by_issuer",
        StateSpace::Meta => "s_meta",
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(thiserror::Error, Debug)]
pub enum StoreError2 {
    #[error("rocksdb error: {0}")]
    Rocks(#[from] rocksdb::Error),

    #[error("column family not found: {0}")]
    CfNotFound(String),

    #[error("encode error: {0}")]
    Encode(String),
}

// ---------------------------------------------------------------------------
// Store2
// ---------------------------------------------------------------------------

pub struct Store2 {
    db: DB,
}

impl Store2 {
    /// Open (or create) a store with the given tuning profile.
    pub fn open(path: &Path, profile: Profile) -> Result<Self, StoreError2> {
        let db_opts = profile.db_options();
        let mut descriptors: Vec<ColumnFamilyDescriptor> = Vec::new();
        for name in CF_HOT {
            descriptors.push(ColumnFamilyDescriptor::new(*name, profile.hot_cf_options()));
        }
        for name in CF_COLD {
            descriptors.push(ColumnFamilyDescriptor::new(
                *name,
                profile.cold_cf_options(),
            ));
        }
        let db = DB::open_cf_descriptors(&db_opts, path, descriptors)?;
        Ok(Self { db })
    }

    fn cf(&self, name: &str) -> Result<&rocksdb::ColumnFamily, StoreError2> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StoreError2::CfNotFound(name.to_string()))
    }

    /// Direct state write (genesis seeding).
    pub fn seed_state(&self, key: &StateKey, value: &[u8]) -> Result<(), StoreError2> {
        let cf = self.cf(cf_for_space(key.space))?;
        self.db.put_cf(cf, &key.key, value)?;
        Ok(())
    }

    /// Persist one executed block atomically — the block's whole state
    /// delta, its receipts (height-prefixed for pruning), the opaque block
    /// bytes, and the canon pointer, in ONE WriteBatch (§4.6).
    pub fn persist_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        block_bytes: &[u8],
        delta: &DeltaSet,
        receipts: &[Receipt],
    ) -> Result<(), StoreError2> {
        let mut batch = WriteBatch::default();

        for (key, value) in delta.iter() {
            let cf = self.cf(cf_for_space(key.space))?;
            batch.put_cf(cf, &key.key, value);
        }

        let receipts_cf = self.cf("receipts")?;
        for receipt in receipts {
            let mut key = Vec::with_capacity(8 + 32);
            key.extend_from_slice(&height.to_be_bytes());
            key.extend_from_slice(&receipt.tx_hash);
            let bytes =
                bincode::serialize(receipt).map_err(|e| StoreError2::Encode(e.to_string()))?;
            batch.put_cf(receipts_cf, &key, &bytes);
        }

        batch.put_cf(self.cf("blocks")?, block_hash, block_bytes);
        batch.put_cf(self.cf("canon")?, height.to_be_bytes(), block_hash);
        batch.put_cf(self.cf("s_meta")?, META_CANON_HEAD, height.to_be_bytes());

        self.db.write(batch)?;
        Ok(())
    }

    /// Highest persisted block height, if any.
    pub fn canon_head(&self) -> Result<Option<u64>, StoreError2> {
        let cf = self.cf("s_meta")?;
        match self.db.get_cf(cf, META_CANON_HEAD)? {
            Some(bytes) => {
                let arr: [u8; 8] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StoreError2::Encode("canon head not 8 bytes".into()))?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Opaque block bytes by hash.
    pub fn block_by_hash(&self, hash: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError2> {
        Ok(self.db.get_cf(self.cf("blocks")?, hash)?)
    }

    /// Canonical block hash at a height.
    pub fn canon_hash(&self, height: u64) -> Result<Option<[u8; 32]>, StoreError2> {
        match self.db.get_cf(self.cf("canon")?, height.to_be_bytes())? {
            Some(v) if v.len() == 32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(&v);
                Ok(Some(h))
            }
            _ => Ok(None),
        }
    }

    /// A receipt by (height, tx hash).
    pub fn receipt(&self, height: u64, tx_hash: &[u8; 32]) -> Result<Option<Receipt>, StoreError2> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&height.to_be_bytes());
        key.extend_from_slice(tx_hash);
        match self.db.get_cf(self.cf("receipts")?, &key)? {
            Some(bytes) => Ok(Some(
                bincode::deserialize(&bytes).map_err(|e| StoreError2::Encode(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Prune cold history strictly below `height`: receipts and canonical
    /// blocks (state CFs and the canon index head are untouched). Bounded
    /// storage growth is this one call away from a retention policy.
    pub fn prune_cold_before(&self, height: u64) -> Result<(), StoreError2> {
        // Receipts: one range delete over the height-prefixed keyspace.
        let receipts_cf = self.cf("receipts")?;
        let from = 0u64.to_be_bytes().to_vec();
        let mut to = Vec::with_capacity(40);
        to.extend_from_slice(&height.to_be_bytes());
        self.db
            .delete_range_cf(receipts_cf, from.as_slice(), to.as_slice())?;

        // Blocks: walk the canon index below the horizon.
        let canon_cf = self.cf("canon")?;
        let blocks_cf = self.cf("blocks")?;
        let iter = self.db.iterator_cf(canon_cf, rocksdb::IteratorMode::Start);
        let mut batch = WriteBatch::default();
        for item in iter {
            let (k, v) = item?;
            let arr: [u8; 8] = match k.as_ref().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let h = u64::from_be_bytes(arr);
            if h >= height {
                break;
            }
            batch.delete_cf(blocks_cf, v);
            batch.delete_cf(canon_cf, k);
        }
        self.db.write(batch)?;
        Ok(())
    }

    /// Iterate a whole state space (boot-time forest rebuild).
    pub fn iter_space(&self, space: StateSpace) -> Result<SpaceEntries, StoreError2> {
        let cf = self.cf(cf_for_space(space))?;
        let mut out = Vec::new();
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            out.push((k.to_vec(), v.to_vec()));
        }
        Ok(out)
    }

    /// Approximate on-disk size of the cold CFs (growth-bound checks).
    pub fn cold_bytes_estimate(&self) -> Result<u64, StoreError2> {
        let mut total = 0u64;
        for name in CF_COLD {
            let cf = self.cf(name)?;
            if let Some(v) = self
                .db
                .property_int_value_cf(cf, "rocksdb.estimate-live-data-size")?
            {
                total += v;
            }
        }
        Ok(total)
    }
}

/// The executor reads its baseline directly from the hot CFs.
impl StateReader for Store2 {
    fn get(&self, key: &StateKey) -> Result<Option<Vec<u8>>, ExecError> {
        let cf = self
            .db
            .cf_handle(cf_for_space(key.space))
            .ok_or_else(|| ExecError::StateRead("missing column family".to_string()))?;
        self.db
            .get_cf(cf, &key.key)
            .map_err(|e| ExecError::StateRead(e.to_string()))
    }
}

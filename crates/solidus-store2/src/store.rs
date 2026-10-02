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
/// - `block_batches`: height_be(8) → the batch digests that block certifies
/// - `tx_index`:   tx_hash(32) → height_be(8)
///
/// ⚠ `block_batches` exists ONLY so pruning can delete batch bodies in step
/// with the blocks that reference them. Batches are keyed by digest, so without
/// it there is no range to delete and persisted batches grow forever — and a
/// batch holds the transactions, so it is the record type that dominates disk
/// under load, not the block. Adding a CF is safe on an existing database
/// because `create_missing_column_families` is set.
pub const CF_COLD: &[&str] = &[
    "blocks",
    "canon",
    "receipts",
    "batches",
    "block_batches",
    "tx_index",
    "sub_roots",
    // ⛔ NODE-LOCAL, NEVER CONSENSUS STATE. A bridge attestation is THIS validator's own signature
    // over an outbox entry, and nodes do not agree on each other's signatures, so nothing in the
    // state root may depend on it. Losing the whole family costs a re-sign on the next start; it
    // cannot fork the chain. Adding a CF is safe on an existing database because
    // `create_missing_column_families` is set (see the note above).
    "bridge_att",
];

const META_CANON_HEAD: &[u8] = b"canon_head_height";

/// Highest view this validator has voted in.
///
/// ⛔ THE SINGLE MOST SAFETY-CRITICAL VALUE IN THE STORE. A validator that
/// forgets it can vote twice in one view after a restart, which is
/// equivocation, which this repo's own `EquivocationDetector` catches and
/// which is slashable. Losing your place is recoverable; being slashed is not.
const META_LAST_VOTED_VIEW: &[u8] = b"safety_last_voted_view";

/// The locked high QC (bincode). Recovered alongside the voted view because
/// the commit rule depends on it.
const META_HIGH_QC: &[u8] = b"safety_high_qc";

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
    #[allow(clippy::too_many_arguments)]
    pub fn persist_block(
        &self,
        height: u64,
        block_hash: [u8; 32],
        block_bytes: &[u8],
        delta: &DeltaSet,
        receipts: &[Receipt],
        batch_digests: &[[u8; 32]],
        sub_roots: [[u8; 32]; 4],
    ) -> Result<(), StoreError2> {
        let mut batch = WriteBatch::default();

        // Height → the batch digests this block certifies, written in the SAME
        // WriteBatch as the block so the two cannot diverge. If it were a
        // separate write, a failure between them would orphan batch bodies that
        // pruning could then never find.
        if !batch_digests.is_empty() {
            let index_cf = self.cf("block_batches")?;
            let mut packed = Vec::with_capacity(batch_digests.len() * 32);
            for d in batch_digests {
                packed.extend_from_slice(d);
            }
            batch.put_cf(index_cf, height.to_be_bytes(), &packed);
        }

        for (key, value) in delta.iter() {
            let cf = self.cf(cf_for_space(key.space))?;
            batch.put_cf(cf, &key.key, value);
        }

        // ⛔ tx_hash → height, WITHOUT WHICH A LOOKUP BY HASH IS A FULL SCAN.
        // v1 answers `getTransaction` by walking every block backwards from the
        // tip, and says so: "This is O(blocks) which is acceptable for testnet".
        // At 1.8M blocks it is not, and this chain is built for 50K TPS, so v2
        // pays one 40-byte write per transaction instead of a scan per query.
        //
        // In the SAME WriteBatch as the block and receipts: a separate write
        // could leave an index entry pointing at a height that was never
        // committed, which is worse than having no index at all.
        //
        // ⛔ FIRST WRITE WINS, AND WITHOUT THAT THIS INDEX REPORTS SUCCESSFUL TRANSACTIONS
        // AS FAILED. The same transaction is legitimately included in more than one block:
        // every validator's worker seals its own batch and the DAG mempool dedupes BATCHES
        // by digest, not TRANSACTIONS across batches, which is how Narwhal-style mempools
        // are meant to behave. The first copy executes and moves the money; the second fails
        // the nonce check against the account its own first copy bumped.
        //
        // Receipts survive both, because they are keyed by (height, tx_hash). This index is
        // keyed by HASH ALONE, so an unconditional put re-pointed it at the failed execution
        // and `solidus_getReceipt(hash)` — which resolves through here — reported
        // `failed: invalid nonce` for a transfer that had demonstrably arrived. Measured on
        // the live chain 2026-09-24: tx df8676b0… in blocks 3222202 AND 3222203, proposers 0
        // then 1, receipt "failed", recipient funded.
        //
        // The winner must be the EARLIEST height: that is the inclusion that actually
        // executed. `seen` covers a repeat inside this same block, which the pending
        // WriteBatch would otherwise hide from the read below.
        let tx_index_cf = self.cf("tx_index")?;
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for receipt in receipts {
            if !seen.insert(receipt.tx_hash) {
                continue;
            }
            if self.db.get_cf(tx_index_cf, receipt.tx_hash)?.is_some() {
                continue;
            }
            batch.put_cf(tx_index_cf, receipt.tx_hash, height.to_be_bytes());
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
        // The four sub-tree roots after executing this height, so finality
        // evidence can be assembled for heights the in-memory forest has left.
        let mut packed = [0u8; 128];
        for (i, r) in sub_roots.iter().enumerate() {
            packed[i * 32..(i + 1) * 32].copy_from_slice(r);
        }
        batch.put_cf(self.cf("sub_roots")?, height.to_be_bytes(), packed);
        batch.put_cf(self.cf("s_meta")?, META_CANON_HEAD, height.to_be_bytes());

        self.db.write(batch)?;
        Ok(())
    }

    /// The four sub-tree roots persisted with `height`, or `None` if that height
    /// was never persisted or has been pruned.
    /// The key a bridge attestation is stored under: `domain BE ‖ seq BE`, 12 bytes.
    ///
    /// ⛔ BIG-ENDIAN ON BOTH HALVES, AND IT IS LOAD-BEARING. RocksDB orders keys bytewise, and the
    /// gateway reads a range in key order to find what it has not yet delivered. Little-endian
    /// would sort sequence 256 before sequence 2, and the symptom would be a gateway that skips
    /// messages under load and behaves perfectly under test.
    fn attestation_key(domain: u32, seq: u64) -> [u8; 12] {
        let mut key = [0u8; 12];
        key[..4].copy_from_slice(&domain.to_be_bytes());
        key[4..].copy_from_slice(&seq.to_be_bytes());
        key
    }

    /// Store this validator's own signature for one outbox entry.
    pub fn put_attestation(
        &self,
        domain: u32,
        seq: u64,
        sig: &[u8; 65],
    ) -> Result<(), StoreError2> {
        self.db.put_cf(
            self.cf("bridge_att")?,
            Self::attestation_key(domain, seq),
            sig,
        )?;
        Ok(())
    }

    pub fn attestation(&self, domain: u32, seq: u64) -> Result<Option<[u8; 65]>, StoreError2> {
        let Some(bytes) = self
            .db
            .get_cf(self.cf("bridge_att")?, Self::attestation_key(domain, seq))?
        else {
            return Ok(None);
        };
        let sig: [u8; 65] = bytes.as_slice().try_into().map_err(|_| {
            StoreError2::Encode(format!(
                "attestation {domain}/{seq} is {} bytes, expected 65",
                bytes.len()
            ))
        })?;
        Ok(Some(sig))
    }

    /// Up to `limit` attestations for `domain`, from `from_seq` upward, in ascending order.
    ///
    /// ⚠ THE PREFIX IS CHECKED ON EVERY ROW. A RocksDB iterator started at a key runs off the end
    /// of the prefix into the next domain, so without this a read for Sepolia would return Fuji's
    /// signatures once Sepolia ran out.
    pub fn attestations_from(
        &self,
        domain: u32,
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, [u8; 65])>, StoreError2> {
        let cf = self.cf("bridge_att")?;
        let start = Self::attestation_key(domain, from_seq);
        let mut out = Vec::new();
        let iter = self.db.iterator_cf(
            cf,
            rocksdb::IteratorMode::From(&start, rocksdb::Direction::Forward),
        );
        for row in iter {
            let (key, value) = row?;
            if key.len() != 12 || key[..4] != domain.to_be_bytes() {
                break;
            }
            let seq = u64::from_be_bytes(key[4..].try_into().expect("checked length"));
            let sig: [u8; 65] = value.as_ref().try_into().map_err(|_| {
                StoreError2::Encode(format!("attestation {domain}/{seq} is not 65 bytes"))
            })?;
            out.push((seq, sig));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn sub_roots(&self, height: u64) -> Result<Option<[[u8; 32]; 4]>, StoreError2> {
        let Some(bytes) = self
            .db
            .get_cf(self.cf("sub_roots")?, height.to_be_bytes())?
        else {
            return Ok(None);
        };
        if bytes.len() != 128 {
            return Err(StoreError2::Encode(format!(
                "sub_roots at {height} is {} bytes, expected 128",
                bytes.len()
            )));
        }
        let mut out = [[0u8; 32]; 4];
        for (i, r) in out.iter_mut().enumerate() {
            r.copy_from_slice(&bytes[i * 32..(i + 1) * 32]);
        }
        Ok(Some(out))
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

    /// Persist a batch body under its digest.
    ///
    /// ⛔ THE `batches` COLUMN FAMILY WAS DECLARED AND NEVER WRITTEN. It is in
    /// `CF_COLD` and documented "batch digest → bincode(Batch) (mempool
    /// persistence)", but `BatchStore` is an in-memory `HashMap`, so batch
    /// bodies vanished on restart. That matters more than it sounds: a v2 block
    /// carries `batch_certs` — the body BY DIGEST — so the transactions are NOT
    /// in the block. Without persisted batches, a restarted node cannot re-serve
    /// what it acked, and NO peer can supply the bodies a backfilling node needs
    /// to execute a fetched block.
    ///
    /// `BatchStore::insert_verified` already promises "never ack what you cannot
    /// re-serve". This is what makes that promise survive a restart.
    pub fn put_batch(&self, digest: &[u8; 32], bytes: &[u8]) -> Result<(), StoreError2> {
        let cf = self.cf("batches")?;
        self.db.put_cf(cf, digest, bytes)?;
        Ok(())
    }

    /// Durably record safety state BEFORE the vote it describes leaves the node.
    ///
    /// ⛔ `sync(true)` IS THE WHOLE POINT AND MUST NOT BE REMOVED FOR SPEED.
    /// A plain write reaches the WAL and survives a process restart, but not a
    /// power loss. The failure this guards against is precisely "the vote
    /// reached the network and the record of it did not", so the write has to
    /// be durable before the caller proceeds.
    ///
    /// ⚠ IT IS ON THE HOT PATH OF A CHAIN TARGETING 50K TPS, and that is a real
    /// cost, deliberately paid. One fsync per vote, not per transaction:
    /// a validator votes once per view, not once per tx, so this is bounded by
    /// consensus rounds rather than throughput. Measure before trading it away.
    pub fn put_safety(&self, last_voted_view: u64, high_qc: &[u8]) -> Result<(), StoreError2> {
        let cf = self.cf("s_meta")?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, META_LAST_VOTED_VIEW, last_voted_view.to_be_bytes());
        batch.put_cf(cf, META_HIGH_QC, high_qc);
        let mut opts = rocksdb::WriteOptions::default();
        opts.set_sync(true);
        self.db.write_opt(batch, &opts)?;
        Ok(())
    }

    /// Recorded safety state, or `None` on a validator that has never voted.
    ///
    /// ⚠ `None` MEANS "NEVER VOTED", NOT "SAFE TO VOTE ANYWHERE". A caller that
    /// reads `None` on a store that HAS committed blocks is looking at a node
    /// upgraded from a build that did not persist this, and must treat that as
    /// unsafe to resume rather than as a fresh validator.
    pub fn safety(&self) -> Result<Option<(u64, Vec<u8>)>, StoreError2> {
        let cf = self.cf("s_meta")?;
        let Some(view_bytes) = self.db.get_cf(cf, META_LAST_VOTED_VIEW)? else {
            return Ok(None);
        };
        let arr: [u8; 8] = view_bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError2::Encode("last_voted_view not 8 bytes".into()))?;
        let qc = self.db.get_cf(cf, META_HIGH_QC)?.unwrap_or_default();
        Ok(Some((u64::from_be_bytes(arr), qc)))
    }

    /// The height a transaction was committed at, if indexed.
    ///
    /// ⚠ A `None` here means "not indexed", which after pruning is not the same
    /// as "never existed". The RPC edge must not turn this into a claim that
    /// the transaction does not exist.
    pub fn tx_height(&self, tx_hash: &[u8; 32]) -> Result<Option<u64>, StoreError2> {
        let Some(bytes) = self.db.get_cf(self.cf("tx_index")?, tx_hash)? else {
            return Ok(None);
        };
        let arr: [u8; 8] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| StoreError2::Encode("tx_index value not 8 bytes".into()))?;
        Ok(Some(u64::from_be_bytes(arr)))
    }

    /// The batch digests certified by the block at `height`, if indexed.
    ///
    /// Used when serving a range: a v2 block carries only digests, so a peer
    /// receiving blocks alone still cannot execute them. This is how the
    /// responder finds the bodies to send with them.
    pub fn block_batch_digests(&self, height: u64) -> Result<Vec<[u8; 32]>, StoreError2> {
        let cf = self.cf("block_batches")?;
        let Some(packed) = self.db.get_cf(cf, height.to_be_bytes())? else {
            return Ok(Vec::new());
        };
        // A trailing partial digest would mean a corrupt row; ignore it rather
        // than serve a truncated key that can never match a body.
        Ok(packed.as_chunks::<32>().0.to_vec())
    }

    /// A persisted batch body by digest, if held.
    pub fn batch_by_digest(&self, digest: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError2> {
        Ok(self.db.get_cf(self.cf("batches")?, digest)?)
    }

    /// Persist a block body BEFORE it is committed, keyed by hash only.
    ///
    /// ⛔ WITHOUT THIS A VALIDATOR CANNOT RESUME. `persist_block` runs on
    /// COMMIT, so the store holds finalised blocks only — while a HotStuff lock
    /// always sits ABOVE the committed head, because that is what a lock is. So
    /// the block consensus resumes from is exactly the one the store never
    /// kept. Measured 2026-09-02 on 4 of 4 validators: every one had
    /// `head=22 lock@view23` and could not reload its locked block.
    ///
    /// ⚠ NO CANON ENTRY, DELIBERATELY. This block is not canonical yet, so it
    /// must not appear at a height. Only `persist_block` may do that.
    ///
    /// ⚠ NOT PRUNED BY `prune_cold_before`, WHICH WALKS canon. A block that is
    /// stored here and never commits leaks. That is a bounded leak — one entry
    /// per proposal seen — but it IS a leak, and the pruning rule for it is an
    /// open decision rather than an oversight.
    pub fn put_pending_block(&self, hash: &[u8; 32], bytes: &[u8]) -> Result<(), StoreError2> {
        self.db.put_cf(self.cf("blocks")?, hash, bytes)?;
        Ok(())
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
        // ⛔ MUST RUN BEFORE THE RECEIPTS RANGE-DELETE BELOW. This walks the
        // receipts to learn which hashes to drop, so deleting them first
        // leaves the index untouched and pointing at data that is gone. A
        // test caught exactly that ordering.
        //
        // tx_index is keyed by HASH, so there is no range to delete. Walk the
        // receipts being dropped and remove their entries, keeping the index in
        // step with the receipts it mirrors. An entry left behind would point at
        // a height whose data is gone.
        {
            let tx_index_cf = self.cf("tx_index")?;
            let receipts_cf2 = self.cf("receipts")?;
            let mut idx_batch = WriteBatch::default();
            let iter = self
                .db
                .iterator_cf(receipts_cf2, rocksdb::IteratorMode::Start);
            for item in iter {
                let (k, _) = item?;
                if k.len() < 40 {
                    continue;
                }
                let h_arr: [u8; 8] = match k[..8].try_into() {
                    Ok(a) => a,
                    Err(_) => continue,
                };
                if u64::from_be_bytes(h_arr) >= height {
                    break;
                }
                idx_batch.delete_cf(tx_index_cf, &k[8..40]);
            }
            self.db.write(idx_batch)?;
        }

        // Receipts: one range delete over the height-prefixed keyspace.
        let receipts_cf = self.cf("receipts")?;
        let from = 0u64.to_be_bytes().to_vec();
        let mut to = Vec::with_capacity(40);
        to.extend_from_slice(&height.to_be_bytes());
        self.db
            .delete_range_cf(receipts_cf, from.as_slice(), to.as_slice())?;

        // Sub-roots: keyed by height alone, so one range delete.
        self.db.delete_range_cf(
            self.cf("sub_roots")?,
            0u64.to_be_bytes(),
            height.to_be_bytes(),
        )?;

        // Batch bodies: walk the height → digest index below the horizon and
        // delete the bodies it names, then the index rows themselves.
        //
        // ⚠ THIS IS WHY THE INDEX EXISTS. Batches are keyed by DIGEST, so there
        // is no height range to delete directly, and deleting them at commit
        // time would remove exactly what a backfilling peer needs. Tying their
        // lifetime to the blocks that certify them keeps retention meaningful
        // for the record type that actually dominates disk under load — a block
        // holds only certificates; a batch holds the transactions.
        //
        // ⚠ Assumes a batch is certified by ONE canonical block. If a digest
        // were ever certified by two blocks at different heights, pruning the
        // lower one would drop a body the higher one still needs.
        let index_cf = self.cf("block_batches")?;
        let batches_cf = self.cf("batches")?;
        let mut batch = WriteBatch::default();
        let index_iter = self.db.iterator_cf(index_cf, rocksdb::IteratorMode::Start);
        for item in index_iter {
            let (k, v) = item?;
            let arr: [u8; 8] = match k.as_ref().try_into() {
                Ok(a) => a,
                Err(_) => continue,
            };
            if u64::from_be_bytes(arr) >= height {
                break;
            }
            for digest in v.as_chunks::<32>().0 {
                batch.delete_cf(batches_cf, digest);
            }
            batch.delete_cf(index_cf, k);
        }
        self.db.write(batch)?;

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

        // ⛔ FLUSH, OR THE TOMBSTONES THIS JUST WROTE BECOME AN UNBOOTABLE WAL.
        //
        // `delete_range_cf` above writes RANGE TOMBSTONES. Until the memtable is
        // flushed they live only in the WAL, and RocksDB re-fragments every one of
        // them on the next open. Measured on solidus-rpc 2026-09-06: 24 MB of WAL
        // needed more than the box's 9,8 GB of RAM plus swap, so all four
        // validators sat at their 2.048 MB cgroup ceiling and could not start.
        // heaptrack named the frame exactly: `FragmentTombstones` <-
        // `CompactionRangeDelAggregator::NewIterator` <- `BuildTable` <-
        // `WriteLevel0TableForRecovery` <- `RecoverLogFiles` <- `DBImpl::Open`.
        // 41.884.590 allocation calls, 1,34 GB peak, entirely inside `Store2::open`
        // and before a single line of consensus ran.
        //
        // ⚠ THE BLOW-UP IS SUPERLINEAR, SO A BIGGER BOX DOES NOT FIX IT. The same
        // store fails on 16 GB once the backlog grows. Flushing here is what keeps
        // the backlog from existing.
        //
        // ⚠ v1 NEVER HIT THIS because it calls `delete_range` zero times. v2 calls
        // it here, and that single difference is the whole 120x gap between v1
        // running four validators in 17 MB and v2 unable to hold quorum at 2 GB.
        //
        // Only the cold CFs are flushed: those are the ones this function
        // tombstones, and flushing the hot CFs on every prune would force the
        // point-read path to compact for no reason.
        self.flush_cold()?;
        Ok(())
    }

    /// Flush the cold column families so their range tombstones leave the WAL.
    ///
    /// Separate from `prune_cold_before` so a caller can flush without pruning
    /// (shutdown, or after a bulk import).
    pub fn flush_cold(&self) -> Result<(), StoreError2> {
        for name in CF_COLD {
            let cf = self.cf(name)?;
            self.db.flush_cf(cf)?;
        }
        Ok(())
    }

    /// Iterate a whole state space (boot-time forest rebuild).
    /// Stream one state space, key by key, without materialising it.
    ///
    /// ⚠ **`iter_space` COPIES THE WHOLE SPACE INTO A `Vec` AND THAT IS THE BOOT
    /// OOM.** RocksDB hands back a lazy iterator; collecting it allocates every key
    /// and every value again, and the only caller (`Node::new`'s forest rebuild)
    /// consumes each pair once, in order, and then drops the lot. Measured
    /// 2026-09-05 on solidus-rpc: 315-530 MB of compressed state per validator
    /// became a 1.4-1.6 GB resident peak at boot, before consensus started, on a
    /// 3.8 GB box running four of them. Every validator was OOM-killed during
    /// startup and the chain never regained quorum.
    ///
    /// The forest it feeds is still resident afterwards, so this does not make
    /// state free. It removes the transient second copy, which is the half that
    /// was pure waste.
    pub fn for_each_in_space<F>(&self, space: StateSpace, mut f: F) -> Result<(), StoreError2>
    where
        F: FnMut(&[u8], &[u8]),
    {
        let cf = self.cf(cf_for_space(space))?;
        for item in self.db.iterator_cf(cf, rocksdb::IteratorMode::Start) {
            let (k, v) = item?;
            f(&k, &v);
        }
        Ok(())
    }

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

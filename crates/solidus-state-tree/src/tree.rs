use std::collections::{BTreeMap, HashMap};
use std::sync::LazyLock;

use solidus_crypto::hash::{blake3_hash, empty_hashes};

// ---------------------------------------------------------------------------
// Precomputed empty hashes (256 levels) — identical ladder to the live tree.
// ---------------------------------------------------------------------------

pub(crate) static EMPTY_HASHES: LazyLock<Vec<[u8; 32]>> = LazyLock::new(empty_hashes);

/// Root of a tree with no leaves (`EMPTY_HASHES[255]`), exposed for tests
/// and genesis assertions.
pub static EMPTY_ROOT: LazyLock<[u8; 32]> = LazyLock::new(|| EMPTY_HASHES[255]);

// ---------------------------------------------------------------------------
// TreeId
// ---------------------------------------------------------------------------

/// Identifies which of the four root-bearing state sub-trees a key belongs
/// to. Matches the live chain's `TreeId` — the set and order are part of the
/// state-root definition (the global root concatenates the four roots in
/// this order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TreeId {
    Accounts,
    Dids,
    Credentials,
    Validators,
}

impl TreeId {
    /// All four sub-trees in global-root order.
    pub const ALL: [TreeId; 4] = [
        TreeId::Accounts,
        TreeId::Dids,
        TreeId::Credentials,
        TreeId::Validators,
    ];
}

// ---------------------------------------------------------------------------
// Bit helpers — ported verbatim from the live tree (path math must match).
// ---------------------------------------------------------------------------

/// Get the bit at `pos` (0..255) from a 32-byte hash. Bit 0 is the most
/// significant bit of byte 0.
pub fn get_bit(data: &[u8; 32], pos: usize) -> u8 {
    let byte_index = pos / 8;
    let bit_index = 7 - (pos % 8);
    (data[byte_index] >> bit_index) & 1
}

/// Flip the bit at `pos` (0..255) in a 32-byte hash.
pub fn flip_bit(data: &mut [u8; 32], pos: usize) {
    let byte_index = pos / 8;
    let bit_index = 7 - (pos % 8);
    data[byte_index] ^= 1 << bit_index;
}

/// Zero bits 0..pos (positions 0 through pos-1, inclusive) in `data`.
///
/// Canonicalizes internal-node storage paths: at SMT walk level L, the node
/// is uniquely identified by bits L..255 of the leaf hash (bits 0..L-1 have
/// been "consumed" by the walk up to this node, so two leaves that agree on
/// bits L..255 share this internal node).
pub fn zero_bits_below(data: &mut [u8; 32], pos: usize) {
    if pos == 0 {
        return;
    }
    let full_bytes = (pos / 8).min(32);
    let partial_bits = pos % 8;
    for byte in &mut data[..full_bytes] {
        *byte = 0;
    }
    if partial_bits > 0 && full_bytes < 32 {
        let mask: u8 = (1u16 << (8 - partial_bits)) as u8 - 1;
        data[full_bytes] &= mask;
    }
}

/// Reverse the bit order of a 32-byte hash: bit `i` becomes bit `255 - i`.
///
/// The walk consumes bits 0..L-1 (most significant first), so two leaves share
/// an internal node at level L exactly when they agree on bits L..255 — a
/// SUFFIX. Reversing turns that suffix into a PREFIX, which makes "every leaf
/// beneath this node" a contiguous range in a `BTreeMap`. That range query is
/// what lets the tree store only branching nodes: see `leaves_under`.
fn rev_bits(h: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..256usize {
        if get_bit(h, i) == 1 {
            let j = 255 - i;
            out[j / 8] |= 1 << (7 - (j % 8));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// SparseMerkleTree (in-memory, incremental)
// ---------------------------------------------------------------------------

/// A 256-bit-depth sparse Merkle tree with an in-memory node store.
///
/// Hashing is bit-for-bit identical to the live RocksDB-backed tree:
/// - leaf path  = `BLAKE3(key)`
/// - leaf hash  = `BLAKE3(key_hash || BLAKE3(value))`
/// - parent     = `BLAKE3(left || right)` walking levels 0..=255 with
///   canonical (bits-below-zeroed) internal-node paths and the shared
///   empty-hash ladder for absent siblings.
///
/// The root is a pure function of the final `key → value` map: insertion
/// order does not matter, and inserting a key again with a new value
/// updates the root as if the map always held the new value.
#[derive(Clone)]
pub struct SparseMerkleTree {
    /// (level, canonical path) → node hash, for BRANCHING nodes only.
    ///
    /// ⚠ **STORING EVERY LEVEL IS WHAT OOM-KILLED THE TESTNET.** The previous
    /// implementation inserted a node at all 256 levels on every `insert`. Near
    /// the leaves each key owns a distinct path, so the map held roughly
    /// `238 * N` entries — about 25 KB of heap PER STATE KEY. Measured
    /// 2026-09-05 on solidus-rpc: 315-530 MB of state on disk became
    /// `VmData` 8.5 GB, and all four validators were killed at boot.
    ///
    /// A node whose subtree holds exactly ONE leaf needs no entry: every
    /// sibling below it is empty by construction, so its hash folds up from
    /// that leaf through the empty ladder (`derive_single_leaf`). Only nodes
    /// with two or more leaves beneath them are stored, which is O(N), not
    /// O(256 N). Roots are unchanged — this is a storage change, not a
    /// hashing change, and `root_matches_naive_reference` pins that.
    nodes: HashMap<(u16, [u8; 32]), [u8; 32]>,
    /// rev_bits(key_hash) → (key_hash, raw value).
    ///
    /// Keyed by the REVERSED hash so that "the leaves beneath (level, path)"
    /// is a contiguous range. The true `key_hash` is carried in the value
    /// because deriving a node hash needs the unreversed bits.
    leaves: BTreeMap<[u8; 32], ([u8; 32], Vec<u8>)>,
    root: [u8; 32],
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// Up to two leaves found under one subtree, each as `(key hash, index)`.
type TwoLeaves = [Option<([u8; 32], usize)>; 2];

impl SparseMerkleTree {
    /// Create a new empty tree (root = empty ladder top).
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            leaves: BTreeMap::new(),
            root: EMPTY_HASHES[255],
        }
    }

    /// Current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Number of distinct leaves inserted.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Leaf hash for a key hash and its raw value: `BLAKE3(key_hash || BLAKE3(value))`.
    fn leaf_hash(key_hash: &[u8; 32], value: &[u8]) -> [u8; 32] {
        let mut leaf_data = [0u8; 64];
        leaf_data[..32].copy_from_slice(key_hash);
        leaf_data[32..].copy_from_slice(&blake3_hash(value));
        blake3_hash(&leaf_data)
    }

    /// Inclusive key range in `leaves` covering every leaf beneath `(level, path)`.
    ///
    /// Leaves under this node agree on bits `level..255`, which after `rev_bits`
    /// is a shared prefix of length `256 - level`. The range therefore runs from
    /// that prefix with all remaining bits 0 to the same prefix with all 1.
    fn subtree_range(level: u16, path: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let prefix_len = 256usize - level as usize;
        let rp = rev_bits(path);
        let mut lo = [0u8; 32];
        let mut hi = [0xffu8; 32];
        for i in 0..prefix_len {
            let bit = (rp[i / 8] >> (7 - (i % 8))) & 1;
            let mask = 1u8 << (7 - (i % 8));
            if bit == 1 {
                lo[i / 8] |= mask;
            } else {
                hi[i / 8] &= !mask;
            }
        }
        (lo, hi)
    }

    /// The leaves beneath `(level, path)`, capped at two.
    ///
    /// Two is all the caller needs: zero means an empty subtree, one means the
    /// hash is derivable, and two or more means the node must be stored. Taking
    /// only two keeps this O(log N) rather than O(subtree size).
    fn leaves_under(&self, level: u16, path: &[u8; 32]) -> (TwoLeaves, usize) {
        let (lo, hi) = Self::subtree_range(level, path);
        let mut found: TwoLeaves = [None, None];
        let mut n = 0usize;
        for (_rk, (kh, _v)) in self.leaves.range(lo..=hi) {
            if n < 2 {
                found[n] = Some((*kh, 0));
            }
            n += 1;
            if n >= 2 {
                break;
            }
        }
        (found, n)
    }

    /// Fold a lone leaf up to `level`, every sibling empty.
    ///
    /// Sound because a subtree holding exactly one leaf has no other leaf below
    /// `level`, so each sibling on the way up really is the empty-ladder hash.
    fn derive_single_leaf(&self, key_hash: &[u8; 32], level: u16) -> [u8; 32] {
        let value = self
            .leaves
            .get(&rev_bits(key_hash))
            .map(|(_, v)| v.as_slice())
            .unwrap_or(&[]);
        let mut h = Self::leaf_hash(key_hash, value);
        for j in 0..level as usize {
            let sibling = EMPTY_HASHES[j];
            let mut pair = [0u8; 64];
            if get_bit(key_hash, j) == 0 {
                pair[..32].copy_from_slice(&h);
                pair[32..].copy_from_slice(&sibling);
            } else {
                pair[..32].copy_from_slice(&sibling);
                pair[32..].copy_from_slice(&h);
            }
            h = blake3_hash(&pair);
        }
        h
    }

    /// Hash of the node at `(level, path)`: stored if branching, derived if a
    /// single leaf sits beneath it, empty-ladder if the subtree is empty.
    fn node_hash(&self, level: u16, path: &[u8; 32]) -> [u8; 32] {
        if let Some(h) = self.nodes.get(&(level, *path)) {
            return *h;
        }
        let (found, n) = self.leaves_under(level, path);
        match n {
            0 => EMPTY_HASHES[level as usize],
            _ => match found[0] {
                Some((kh, _)) => self.derive_single_leaf(&kh, level),
                None => EMPTY_HASHES[level as usize],
            },
        }
    }

    /// Insert (or update) a key-value pair, returning the new root.
    ///
    /// Still O(256) hashing per call, which the root requires. What changed is
    /// storage: a node is written only when two or more leaves sit beneath it.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> [u8; 32] {
        let key_hash = blake3_hash(key);
        self.leaves
            .insert(rev_bits(&key_hash), (key_hash, value.to_vec()));

        let mut current_hash = Self::leaf_hash(&key_hash, value);

        for level in 0..256u16 {
            let bit = get_bit(&key_hash, level as usize);

            let mut current_path = key_hash;
            zero_bits_below(&mut current_path, level as usize);

            let mut sibling_path = current_path;
            flip_bit(&mut sibling_path, level as usize);

            let sibling_hash = self.node_hash(level, &sibling_path);

            // Store only branching nodes. A single-leaf subtree is recomputed by
            // `derive_single_leaf`, and storing it is what made the map O(256 N).
            let (_, n) = self.leaves_under(level, &current_path);
            if n >= 2 {
                self.nodes.insert((level, current_path), current_hash);
            } else {
                self.nodes.remove(&(level, current_path));
            }

            let (left, right) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };

            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            current_hash = blake3_hash(&pair);
        }

        self.root = current_hash;
        self.root
    }

    /// Nodes held in memory. Exposed so the O(N) bound is observable: this must
    /// scale with leaf count, never with `256 * leaf_count`.
    pub fn stored_nodes(&self) -> usize {
        self.nodes.len()
    }

    /// Retrieve the raw value last inserted for `key`, if any.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let key_hash = blake3_hash(key);
        self.leaves
            .get(&rev_bits(&key_hash))
            .map(|(_, v)| v.as_slice())
    }

    /// Internal-node lookup at (level, canonical path) — proof generation.
    pub(crate) fn node(&self, level: u16, path: &[u8; 32]) -> Option<[u8; 32]> {
        // Derives when the node is not stored, so proofs are unaffected by the
        // branching-only storage rule.
        let (_, n) = self.leaves_under(level, path);
        if n == 0 && !self.nodes.contains_key(&(level, *path)) {
            return None;
        }
        Some(self.node_hash(level, path))
    }

    /// Leaf lookup by key hash — proof generation.
    pub(crate) fn leaf_value(&self, key_hash: &[u8; 32]) -> Option<&Vec<u8>> {
        self.leaves.get(&rev_bits(key_hash)).map(|(_, v)| v)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_empty_ladder_root() {
        let tree = SparseMerkleTree::new();
        assert_eq!(tree.root(), *EMPTY_ROOT);
    }

    #[test]
    fn insert_changes_root() {
        let mut tree = SparseMerkleTree::new();
        let old = tree.root();
        tree.insert(b"alice", b"100");
        assert_ne!(tree.root(), old);
    }

    #[test]
    fn get_returns_latest_value() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"alice", b"100");
        tree.insert(b"alice", b"200");
        assert_eq!(tree.get(b"alice"), Some(&b"200"[..]));
        assert_eq!(tree.get(b"missing"), None);
    }

    #[test]
    fn root_is_insertion_order_independent() {
        let mut t1 = SparseMerkleTree::new();
        t1.insert(b"alice", b"100");
        t1.insert(b"bob", b"200");

        let mut t2 = SparseMerkleTree::new();
        t2.insert(b"bob", b"200");
        t2.insert(b"alice", b"100");

        assert_eq!(t1.root(), t2.root());
    }

    #[test]
    fn root_depends_on_every_leaf() {
        let mut t1 = SparseMerkleTree::new();
        t1.insert(b"alice", b"100");
        t1.insert(b"bob", b"200");

        let mut t2 = SparseMerkleTree::new();
        t2.insert(b"alice", b"999"); // only alice differs
        t2.insert(b"bob", b"200");

        assert_ne!(t1.root(), t2.root());
    }

    #[test]
    fn update_equals_fresh_rebuild_with_final_value() {
        // Incremental update semantics: insert(k, v1) then insert(k, v2)
        // must equal a fresh tree with only insert(k, v2) plus the other
        // untouched leaves.
        let mut incremental = SparseMerkleTree::new();
        incremental.insert(b"a", b"1");
        incremental.insert(b"b", b"2");
        incremental.insert(b"a", b"9"); // update

        let mut fresh = SparseMerkleTree::new();
        fresh.insert(b"a", b"9");
        fresh.insert(b"b", b"2");

        assert_eq!(incremental.root(), fresh.root());
    }

    #[test]
    fn bit_helpers_match_live_semantics() {
        let mut data = [0u8; 32];
        data[0] = 0x80;
        assert_eq!(get_bit(&data, 0), 1);
        assert_eq!(get_bit(&data, 1), 0);

        let mut f = [0u8; 32];
        flip_bit(&mut f, 0);
        assert_eq!(f[0], 0x80);
        flip_bit(&mut f, 7);
        assert_eq!(f[0], 0x81);

        let mut z = [0xFFu8; 32];
        zero_bits_below(&mut z, 13);
        assert_eq!(z[0], 0x00);
        assert_eq!(z[1], 0b0000_0111);
        assert_eq!(z[2], 0xFF);
    }
}

use std::collections::HashMap;
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
    /// (level, canonical path) → node hash.
    nodes: HashMap<(u16, [u8; 32]), [u8; 32]>,
    /// key_hash → raw leaf value (for reads and proofs later).
    leaves: HashMap<[u8; 32], Vec<u8>>,
    root: [u8; 32],
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseMerkleTree {
    /// Create a new empty tree (root = empty ladder top).
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            leaves: HashMap::new(),
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

    /// Insert (or update) a key-value pair, returning the new root.
    /// O(256) node updates per call — this is the incremental path the
    /// live chain's block loop never used.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> [u8; 32] {
        let key_hash = blake3_hash(key);
        let value_hash = blake3_hash(value);

        self.leaves.insert(key_hash, value.to_vec());

        // Leaf hash: BLAKE3(key_hash || value_hash)
        let mut leaf_data = [0u8; 64];
        leaf_data[..32].copy_from_slice(&key_hash);
        leaf_data[32..].copy_from_slice(&value_hash);
        let mut current_hash = blake3_hash(&leaf_data);

        // Walk from level 0 to 255, updating canonical internal nodes.
        for level in 0..256u16 {
            let bit = get_bit(&key_hash, level as usize);

            let mut current_path = key_hash;
            zero_bits_below(&mut current_path, level as usize);

            let mut sibling_path = current_path;
            flip_bit(&mut sibling_path, level as usize);

            let sibling_hash = self
                .nodes
                .get(&(level, sibling_path))
                .copied()
                .unwrap_or(EMPTY_HASHES[level as usize]);

            self.nodes.insert((level, current_path), current_hash);

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

    /// Retrieve the raw value last inserted for `key`, if any.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let key_hash = blake3_hash(key);
        self.leaves.get(&key_hash).map(|v| v.as_slice())
    }

    /// Internal-node lookup at (level, canonical path) — proof generation.
    pub(crate) fn node(&self, level: u16, path: &[u8; 32]) -> Option<[u8; 32]> {
        self.nodes.get(&(level, *path)).copied()
    }

    /// Leaf lookup by key hash — proof generation.
    pub(crate) fn leaf_value(&self, key_hash: &[u8; 32]) -> Option<&Vec<u8>> {
        self.leaves.get(key_hash)
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

use std::sync::{Arc, LazyLock};

use solidus_crypto::hash::{blake3_hash, empty_hashes};

use crate::store::{Store, StoreError, CF_MERKLE};

// ---------------------------------------------------------------------------
// Precomputed empty hashes (256 levels)
// ---------------------------------------------------------------------------

/// Precomputed empty hashes for all 256 levels of the sparse Merkle tree.
/// Level 0 = BLAKE3(0x00..00 || 0x00..00), level n = BLAKE3(empty[n-1] || empty[n-1]).
static EMPTY_HASHES: LazyLock<Vec<[u8; 32]>> = LazyLock::new(empty_hashes);

// ---------------------------------------------------------------------------
// TreeId
// ---------------------------------------------------------------------------

/// Identifies which logical tree a key belongs to.
///
/// Each tree is stored in the same `CF_MERKLE` column family but namespaced
/// by a single-byte prefix so that keys never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeId {
    Accounts,
    Dids,
    Credentials,
    Validators,
}

impl TreeId {
    /// Single-byte prefix used to namespace storage keys within `CF_MERKLE`.
    pub fn prefix(self) -> u8 {
        match self {
            TreeId::Accounts => 0,
            TreeId::Dids => 1,
            TreeId::Credentials => 2,
            TreeId::Validators => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Bit helpers
// ---------------------------------------------------------------------------

/// Get the bit at `pos` (0..255) from a 32-byte hash.
///
/// Bit 0 is the most significant bit of byte 0.
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

// ---------------------------------------------------------------------------
// SparseMerkleTree
// ---------------------------------------------------------------------------

/// A 256-bit depth sparse Merkle tree backed by RocksDB.
///
/// Each tree instance is identified by a [`TreeId`] that namespaces its
/// storage keys so multiple logical trees can share the `CF_MERKLE` column
/// family.
pub struct SparseMerkleTree {
    store: Arc<Store>,
    tree_id: TreeId,
    root: [u8; 32],
}

impl SparseMerkleTree {
    /// Create a new empty sparse Merkle tree.
    ///
    /// The root is initialised to `EMPTY_HASHES[255]` (the root of a tree
    /// with all-zero leaves).
    pub fn new(store: Arc<Store>, tree_id: TreeId) -> Self {
        Self {
            store,
            tree_id,
            root: EMPTY_HASHES[255],
        }
    }

    /// Load an existing sparse Merkle tree with a known root.
    pub fn with_root(store: Arc<Store>, tree_id: TreeId, root: [u8; 32]) -> Self {
        Self {
            store,
            tree_id,
            root,
        }
    }

    /// Return the current root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Insert a key-value pair into the tree.
    ///
    /// Returns the new root hash after the insertion.
    ///
    /// # Algorithm
    ///
    /// 1. Hash the key to get a 256-bit path (`key_hash`).
    /// 2. Store the raw leaf value under `tree_prefix || "leaf:" || key_hash`.
    /// 3. Compute the leaf hash as `BLAKE3(key_hash || value_hash)`.
    /// 4. Walk from level 0 (leaf) to level 255 (root), updating internal
    ///    nodes and recomputing parent hashes.
    /// 5. The final hash at the top is the new root.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<[u8; 32], StoreError> {
        let key_hash = blake3_hash(key);
        let value_hash = blake3_hash(value);

        // Store the raw leaf value
        let leaf_key = self.leaf_storage_key(&key_hash);
        self.store.put(CF_MERKLE, &leaf_key, value)?;

        // Compute leaf hash: BLAKE3(key_hash || value_hash)
        let mut leaf_data = [0u8; 64];
        leaf_data[..32].copy_from_slice(&key_hash);
        leaf_data[32..].copy_from_slice(&value_hash);
        let mut current_hash = blake3_hash(&leaf_data);

        // Walk from level 0 to 255, updating internal nodes
        for level in 0..256u16 {
            let bit = get_bit(&key_hash, level as usize);

            // Look up the sibling hash
            let mut sibling_path = key_hash;
            flip_bit(&mut sibling_path, level as usize);
            let sibling_hash = self
                .get_node(level, &sibling_path)?
                .unwrap_or(EMPTY_HASHES[level as usize]);

            // Store this node
            self.put_node(level, &key_hash, &current_hash)?;

            // Compute parent: left || right
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
        Ok(self.root)
    }

    /// Retrieve the value associated with a key, if it exists.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let key_hash = blake3_hash(key);
        let leaf_key = self.leaf_storage_key(&key_hash);
        self.store.get(CF_MERKLE, &leaf_key)
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Build the storage key for a leaf value:
    /// `[tree_prefix, "leaf:", key_hash]`
    fn leaf_storage_key(&self, key_hash: &[u8; 32]) -> Vec<u8> {
        let prefix = self.tree_id.prefix();
        let mut k = Vec::with_capacity(1 + 5 + 32);
        k.push(prefix);
        k.extend_from_slice(b"leaf:");
        k.extend_from_slice(key_hash);
        k
    }

    /// Build the storage key for an internal node:
    /// `[tree_prefix, "node:", level_u16_le, path_prefix]`
    ///
    /// `path_prefix` is the key_hash with the current bit path taken so far.
    /// In practice we store the full key_hash as the path identifier since
    /// each leaf has a unique 256-bit path.
    fn node_storage_key(&self, level: u16, path: &[u8; 32]) -> Vec<u8> {
        let prefix = self.tree_id.prefix();
        let mut k = Vec::with_capacity(1 + 5 + 2 + 32);
        k.push(prefix);
        k.extend_from_slice(b"node:");
        k.extend_from_slice(&level.to_le_bytes());
        k.extend_from_slice(path);
        k
    }

    /// Retrieve an internal node hash from storage.
    fn get_node(&self, level: u16, path: &[u8; 32]) -> Result<Option<[u8; 32]>, StoreError> {
        let key = self.node_storage_key(level, path);
        match self.store.get(CF_MERKLE, &key)? {
            Some(v) if v.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&v);
                Ok(Some(hash))
            }
            _ => Ok(None),
        }
    }

    /// Store an internal node hash.
    fn put_node(
        &self,
        level: u16,
        path: &[u8; 32],
        hash: &[u8; 32],
    ) -> Result<(), StoreError> {
        let key = self.node_storage_key(level, path);
        self.store.put(CF_MERKLE, &key, hash)
    }
}

// ---------------------------------------------------------------------------
// Global state root
// ---------------------------------------------------------------------------

/// Compute the global state root from the four tree roots.
///
/// `global_root = BLAKE3(accounts_root || dids_root || credentials_root || validators_root)`
pub fn global_state_root(
    accounts_root: &[u8; 32],
    dids_root: &[u8; 32],
    credentials_root: &[u8; 32],
    validators_root: &[u8; 32],
) -> [u8; 32] {
    let mut data = [0u8; 128];
    data[..32].copy_from_slice(accounts_root);
    data[32..64].copy_from_slice(dids_root);
    data[64..96].copy_from_slice(credentials_root);
    data[96..128].copy_from_slice(validators_root);
    blake3_hash(&data)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Helper: create a store in a temp directory.
    fn open_tmp_store() -> Arc<Store> {
        let dir = tempdir().expect("failed to create temp dir");
        Arc::new(Store::open(dir.path()).expect("failed to open store"))
    }

    #[test]
    fn empty_tree_has_known_root() {
        let store = open_tmp_store();
        let tree = SparseMerkleTree::new(store, TreeId::Accounts);
        assert_eq!(tree.root(), EMPTY_HASHES[255]);
    }

    #[test]
    fn insert_changes_root() {
        let store = open_tmp_store();
        let mut tree = SparseMerkleTree::new(store, TreeId::Accounts);
        let old_root = tree.root();
        tree.insert(b"alice", b"100").expect("insert failed");
        assert_ne!(tree.root(), old_root);
    }

    #[test]
    fn get_returns_inserted_value() {
        let store = open_tmp_store();
        let mut tree = SparseMerkleTree::new(store, TreeId::Accounts);
        tree.insert(b"alice", b"100").expect("insert failed");
        let val = tree
            .get(b"alice")
            .expect("get failed")
            .expect("value should exist");
        assert_eq!(val, b"100");
    }

    #[test]
    fn get_missing_key_returns_none() {
        let store = open_tmp_store();
        let tree = SparseMerkleTree::new(store, TreeId::Accounts);
        let val = tree.get(b"nonexistent").expect("get failed");
        assert!(val.is_none());
    }

    #[test]
    fn insert_same_key_twice_updates_value() {
        let store = open_tmp_store();
        let mut tree = SparseMerkleTree::new(store, TreeId::Accounts);
        tree.insert(b"alice", b"100").expect("insert failed");
        let root1 = tree.root();
        tree.insert(b"alice", b"200").expect("insert failed");
        let root2 = tree.root();

        // Root should change because the value changed
        assert_ne!(root1, root2);

        // The stored value should be the latest
        let val = tree
            .get(b"alice")
            .expect("get failed")
            .expect("value should exist");
        assert_eq!(val, b"200");
    }

    #[test]
    fn deterministic_root_for_same_operations() {
        // Two trees with identical insertions should produce identical roots.
        let store1 = open_tmp_store();
        let store2 = open_tmp_store();
        let mut tree1 = SparseMerkleTree::new(store1, TreeId::Accounts);
        let mut tree2 = SparseMerkleTree::new(store2, TreeId::Accounts);

        tree1.insert(b"alice", b"100").expect("insert failed");
        tree1.insert(b"bob", b"200").expect("insert failed");

        tree2.insert(b"alice", b"100").expect("insert failed");
        tree2.insert(b"bob", b"200").expect("insert failed");

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn different_tree_ids_are_isolated() {
        let store = open_tmp_store();
        let mut accounts = SparseMerkleTree::new(Arc::clone(&store), TreeId::Accounts);
        let mut dids = SparseMerkleTree::new(Arc::clone(&store), TreeId::Dids);

        accounts.insert(b"key", b"value_a").expect("insert failed");
        dids.insert(b"key", b"value_d").expect("insert failed");

        // Same key in different trees should produce different roots
        assert_ne!(accounts.root(), dids.root());

        // Each tree retrieves its own value
        let a = accounts
            .get(b"key")
            .expect("get failed")
            .expect("value should exist");
        let d = dids
            .get(b"key")
            .expect("get failed")
            .expect("value should exist");
        assert_eq!(a, b"value_a");
        assert_eq!(d, b"value_d");
    }

    #[test]
    fn global_state_root_deterministic() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let d = [4u8; 32];
        let root1 = global_state_root(&a, &b, &c, &d);
        let root2 = global_state_root(&a, &b, &c, &d);
        assert_eq!(root1, root2);
    }

    #[test]
    fn global_state_root_changes_with_any_input() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let d = [4u8; 32];
        let base = global_state_root(&a, &b, &c, &d);

        // Changing any one input should change the root
        let mut a2 = a;
        a2[0] = 99;
        assert_ne!(base, global_state_root(&a2, &b, &c, &d));

        let mut b2 = b;
        b2[0] = 99;
        assert_ne!(base, global_state_root(&a, &b2, &c, &d));

        let mut c2 = c;
        c2[0] = 99;
        assert_ne!(base, global_state_root(&a, &b, &c2, &d));

        let mut d2 = d;
        d2[0] = 99;
        assert_ne!(base, global_state_root(&a, &b, &c, &d2));
    }

    #[test]
    fn get_bit_works() {
        // Byte 0 = 0b10000000 = 0x80, rest zeros
        let mut data = [0u8; 32];
        data[0] = 0x80;
        assert_eq!(get_bit(&data, 0), 1); // MSB of byte 0
        assert_eq!(get_bit(&data, 1), 0);
        assert_eq!(get_bit(&data, 7), 0);

        // Byte 0 = 0b01000001 = 0x41
        data[0] = 0x41;
        assert_eq!(get_bit(&data, 0), 0); // bit 0 (MSB) = 0
        assert_eq!(get_bit(&data, 1), 1); // bit 1 = 1
        assert_eq!(get_bit(&data, 7), 1); // bit 7 (LSB) = 1

        // Byte 1 = 0xFF
        data[1] = 0xFF;
        for i in 8..16 {
            assert_eq!(get_bit(&data, i), 1);
        }
    }

    #[test]
    fn flip_bit_works() {
        let mut data = [0u8; 32];

        // Flip bit 0 (MSB of byte 0): 0 -> 1
        flip_bit(&mut data, 0);
        assert_eq!(data[0], 0x80);

        // Flip it back: 1 -> 0
        flip_bit(&mut data, 0);
        assert_eq!(data[0], 0x00);

        // Flip bit 7 (LSB of byte 0): 0 -> 1
        flip_bit(&mut data, 7);
        assert_eq!(data[0], 0x01);

        // Flip bit 8 (MSB of byte 1): 0 -> 1
        flip_bit(&mut data, 8);
        assert_eq!(data[1], 0x80);
    }
}

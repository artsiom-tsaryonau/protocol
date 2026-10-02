use solidus_crypto::hash::blake3_hash;

use crate::tree::{SparseMerkleTree, TreeId};

/// Compute the global state root from the four sub-tree roots.
///
/// `global_root = BLAKE3(accounts_root || dids_root || credentials_root || validators_root)`
///
/// Identical to the live chain's combine — part of the state-root definition.
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

/// The four root-bearing sub-trees, applied incrementally.
///
/// This is the executor's write target for state-root purposes: after a
/// block's delta is final, each touched `(tree, key) → value` is applied
/// here (O(touched · 256)) and [`StateForest::global_root`] yields the new
/// header root. Column families that don't bear on the root (credential
/// secondary indexes, receipts, meta) never enter the forest.
#[derive(Default, Clone)]
pub struct StateForest {
    accounts: SparseMerkleTree,
    dids: SparseMerkleTree,
    credentials: SparseMerkleTree,
    validators: SparseMerkleTree,
}

impl StateForest {
    /// A forest of four empty trees.
    pub fn new() -> Self {
        Self::default()
    }

    fn tree_mut(&mut self, id: TreeId) -> &mut SparseMerkleTree {
        match id {
            TreeId::Accounts => &mut self.accounts,
            TreeId::Dids => &mut self.dids,
            TreeId::Credentials => &mut self.credentials,
            TreeId::Validators => &mut self.validators,
        }
    }

    fn tree(&self, id: TreeId) -> &SparseMerkleTree {
        match id {
            TreeId::Accounts => &self.accounts,
            TreeId::Dids => &self.dids,
            TreeId::Credentials => &self.credentials,
            TreeId::Validators => &self.validators,
        }
    }

    /// Apply one touched leaf: insert/update `key → value` in sub-tree `id`.
    pub fn apply(&mut self, id: TreeId, key: &[u8], value: &[u8]) {
        self.tree_mut(id).insert(key, value);
    }

    /// Root of one sub-tree.
    pub fn subtree_root(&self, id: TreeId) -> [u8; 32] {
        self.tree(id).root()
    }

    /// The stored value at `key` in sub-tree `id`, if any.
    pub fn get(&self, id: TreeId, key: &[u8]) -> Option<&[u8]> {
        self.tree(id).get(key)
    }

    /// The four sub-tree roots in combine order: accounts, dids, credentials, validators.
    pub fn sub_roots(&self) -> [[u8; 32]; 4] {
        [
            self.accounts.root(),
            self.dids.root(),
            self.credentials.root(),
            self.validators.root(),
        ]
    }

    /// Inclusion proof for `key` in sub-tree `id` (precompile path).
    pub fn prove(&self, id: TreeId, key: &[u8]) -> Option<crate::proof::InclusionProof> {
        self.tree(id).prove(key)
    }

    /// Combine the four sub-tree roots into the global state root.
    pub fn global_root(&self) -> [u8; 32] {
        global_state_root(
            &self.accounts.root(),
            &self.dids.root(),
            &self.credentials.root(),
            &self.validators.root(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::EMPTY_ROOT;

    #[test]
    fn empty_forest_root_is_combine_of_empty_roots() {
        let forest = StateForest::new();
        let e = *EMPTY_ROOT;
        assert_eq!(forest.global_root(), global_state_root(&e, &e, &e, &e));
    }

    #[test]
    fn sub_trees_are_isolated() {
        let mut forest = StateForest::new();
        forest.apply(TreeId::Accounts, b"key", b"value_a");
        forest.apply(TreeId::Dids, b"key", b"value_d");
        assert_ne!(
            forest.subtree_root(TreeId::Accounts),
            forest.subtree_root(TreeId::Dids)
        );
    }

    #[test]
    fn global_root_changes_with_any_subtree() {
        let mut base = StateForest::new();
        base.apply(TreeId::Accounts, b"a", b"1");
        let r0 = base.global_root();

        base.apply(TreeId::Validators, b"v", b"1");
        let r1 = base.global_root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn get_reads_a_leaf_and_sub_roots_are_in_tree_order() {
        let mut forest = StateForest::new();
        forest.apply(TreeId::Credentials, b"bridge:seq:x", b"v");
        assert_eq!(
            forest.get(TreeId::Credentials, b"bridge:seq:x"),
            Some(&b"v"[..])
        );
        assert_eq!(forest.get(TreeId::Dids, b"bridge:seq:x"), None);
        let r = forest.sub_roots();
        assert_eq!(r[2], forest.subtree_root(TreeId::Credentials));
        assert_eq!(
            global_state_root(&r[0], &r[1], &r[2], &r[3]),
            forest.global_root()
        );
    }
}

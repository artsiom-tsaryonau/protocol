//! Differential gate: the v2 in-memory tree must produce **byte-identical**
//! roots to the live RocksDB-backed `solidus-state::tree::SparseMerkleTree`
//! for any final `key → value` map, including under updates and arbitrary
//! insertion orders. This equality is what lets the Stage-0 reference
//! executor reproduce live-chain state roots exactly.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solidus_state::store::Store;
use solidus_state::tree::{SparseMerkleTree as LegacyTree, TreeId as LegacyTreeId};
use solidus_state_tree::{global_state_root, SparseMerkleTree as V2Tree, StateForest, TreeId};
use tempfile::tempdir;

fn legacy_tree(store: &Arc<Store>) -> LegacyTree {
    LegacyTree::new(Arc::clone(store), LegacyTreeId::Accounts)
}

fn open_store() -> (Arc<Store>, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path()).expect("open store"));
    (store, dir)
}

#[test]
fn empty_roots_match() {
    let (store, _dir) = open_store();
    let legacy = legacy_tree(&store);
    let v2 = V2Tree::new();
    assert_eq!(legacy.root(), v2.root());
}

#[test]
fn single_insert_roots_match() {
    let (store, _dir) = open_store();
    let mut legacy = legacy_tree(&store);
    let mut v2 = V2Tree::new();

    legacy.insert(b"alice", b"100").expect("legacy insert");
    v2.insert(b"alice", b"100");

    assert_eq!(legacy.root(), v2.root());
}

#[test]
fn randomized_maps_roots_match() {
    // 20 rounds of random maps (up to 64 keys, random value sizes, random
    // update ratio). Any divergence in path math, leaf hashing, or the
    // empty ladder shows up here immediately.
    let mut rng = StdRng::seed_from_u64(0x501D_0501);

    for round in 0..20 {
        let (store, _dir) = open_store();
        let mut legacy = legacy_tree(&store);
        let mut v2 = V2Tree::new();

        let n_keys = rng.gen_range(1..=64);
        let n_ops = n_keys + rng.gen_range(0..=n_keys); // includes updates
        for _ in 0..n_ops {
            let key_id: u32 = rng.gen_range(0..n_keys as u32);
            let key = format!("key-{key_id:08}");
            let val_len = rng.gen_range(1..=128);
            let value: Vec<u8> = (0..val_len).map(|_| rng.gen()).collect();

            legacy
                .insert(key.as_bytes(), &value)
                .expect("legacy insert");
            v2.insert(key.as_bytes(), &value);

            assert_eq!(
                legacy.root(),
                v2.root(),
                "root divergence in round {round} after inserting {key}"
            );
        }
    }
}

#[test]
fn insertion_order_independence_matches_legacy() {
    // Same final map inserted in two different orders → both trees agree
    // with each other AND across orders.
    let pairs: Vec<(String, Vec<u8>)> = (0..32)
        .map(|i| (format!("acct-{i}"), vec![i as u8; 40]))
        .collect();

    let (store_a, _da) = open_store();
    let mut legacy_fwd = legacy_tree(&store_a);
    let mut v2_fwd = V2Tree::new();
    for (k, v) in &pairs {
        legacy_fwd.insert(k.as_bytes(), v).expect("insert");
        v2_fwd.insert(k.as_bytes(), v);
    }

    let (store_b, _db) = open_store();
    let mut legacy_rev = legacy_tree(&store_b);
    let mut v2_rev = V2Tree::new();
    for (k, v) in pairs.iter().rev() {
        legacy_rev.insert(k.as_bytes(), v).expect("insert");
        v2_rev.insert(k.as_bytes(), v);
    }

    assert_eq!(legacy_fwd.root(), v2_fwd.root());
    assert_eq!(legacy_rev.root(), v2_rev.root());
    assert_eq!(v2_fwd.root(), v2_rev.root());
}

#[test]
fn global_root_combine_matches_legacy() {
    // The 4-way combine must equal solidus-state's global_state_root for
    // identical sub-tree roots.
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let d = [4u8; 32];
    assert_eq!(
        global_state_root(&a, &b, &c, &d),
        solidus_state::tree::global_state_root(&a, &b, &c, &d)
    );
}

#[test]
fn forest_reproduces_legacy_compute_state_root_shape() {
    // Mirror the live compute_state_root: four legacy trees fed from four
    // logical namespaces vs one v2 forest — the global roots must agree.
    let (store, _dir) = open_store();

    let mut legacy_accounts = LegacyTree::new(Arc::clone(&store), LegacyTreeId::Accounts);
    let mut legacy_dids = LegacyTree::new(Arc::clone(&store), LegacyTreeId::Dids);
    let mut legacy_creds = LegacyTree::new(Arc::clone(&store), LegacyTreeId::Credentials);
    let mut legacy_vals = LegacyTree::new(Arc::clone(&store), LegacyTreeId::Validators);

    let mut forest = StateForest::new();

    let mut rng = StdRng::seed_from_u64(0xF0E5);
    for i in 0..24u32 {
        let key = format!("k{i}");
        let value: Vec<u8> = (0..rng.gen_range(1..=64)).map(|_| rng.gen()).collect();
        match i % 4 {
            0 => {
                legacy_accounts.insert(key.as_bytes(), &value).expect("ins");
                forest.apply(TreeId::Accounts, key.as_bytes(), &value);
            }
            1 => {
                legacy_dids.insert(key.as_bytes(), &value).expect("ins");
                forest.apply(TreeId::Dids, key.as_bytes(), &value);
            }
            2 => {
                legacy_creds.insert(key.as_bytes(), &value).expect("ins");
                forest.apply(TreeId::Credentials, key.as_bytes(), &value);
            }
            _ => {
                legacy_vals.insert(key.as_bytes(), &value).expect("ins");
                forest.apply(TreeId::Validators, key.as_bytes(), &value);
            }
        }
    }

    let legacy_global = solidus_state::tree::global_state_root(
        &legacy_accounts.root(),
        &legacy_dids.root(),
        &legacy_creds.root(),
        &legacy_vals.root(),
    );
    assert_eq!(legacy_global, forest.global_root());
}

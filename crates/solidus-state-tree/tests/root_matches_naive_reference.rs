//! The path-compressed tree must hash EXACTLY like the one it replaces.
//!
//! ⛔ WHY THIS IS THE LOAD-BEARING TEST. State roots are consensus-critical: a
//! validator whose root differs by one byte disagrees with every peer, votes on
//! nothing, and the chain stops. The storage change here (store only branching
//! nodes, derive single-leaf subtrees from the empty ladder) is safe precisely
//! because it cannot move the root — so that claim is asserted directly against
//! an independent reference implementation of the ORIGINAL algorithm, rather
//! than trusted.
//!
//! The reference below is the pre-change `insert`, transcribed: a node written
//! at every one of the 256 levels. It is deliberately the slow, obvious version.

use std::collections::HashMap;

use solidus_crypto::hash::{blake3_hash, empty_hashes};
use solidus_state_tree::{get_bit, zero_bits_below, SparseMerkleTree};

/// The original algorithm, kept naive on purpose.
struct NaiveTree {
    nodes: HashMap<(u16, [u8; 32]), [u8; 32]>,
    root: [u8; 32],
}

impl NaiveTree {
    fn new(empty_root: [u8; 32]) -> Self {
        Self {
            nodes: HashMap::new(),
            root: empty_root,
        }
    }

    fn insert(&mut self, key: &[u8], value: &[u8], empty: &[[u8; 32]]) -> [u8; 32] {
        let key_hash = blake3_hash(key);
        let value_hash = blake3_hash(value);
        let mut leaf_data = [0u8; 64];
        leaf_data[..32].copy_from_slice(&key_hash);
        leaf_data[32..].copy_from_slice(&value_hash);
        let mut current_hash = blake3_hash(&leaf_data);

        for level in 0..256u16 {
            let bit = get_bit(&key_hash, level as usize);
            let mut current_path = key_hash;
            zero_bits_below(&mut current_path, level as usize);
            let mut sibling_path = current_path;
            let bi = level as usize / 8;
            let bx = 7 - (level as usize % 8);
            sibling_path[bi] ^= 1 << bx;

            let sibling_hash = self
                .nodes
                .get(&(level, sibling_path))
                .copied()
                .unwrap_or(empty[level as usize]);
            self.nodes.insert((level, current_path), current_hash);

            let (l, r) = if bit == 0 {
                (current_hash, sibling_hash)
            } else {
                (sibling_hash, current_hash)
            };
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&l);
            pair[32..].copy_from_slice(&r);
            current_hash = blake3_hash(&pair);
        }
        self.root = current_hash;
        self.root
    }
}

/// The tree's own empty-hash ladder.
///
/// ⚠ Reconstructing this by hand is a trap and cost a false failure: the real
/// ladder STARTS at `BLAKE3(zero || zero)`, not at raw zeros, so a hand-rolled
/// version is shifted by one level and every root disagrees. Use the shared one.
fn empty_ladder() -> Vec<[u8; 32]> {
    empty_hashes()
}

fn pairs(n: usize, salt: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    (0..n)
        .map(|i| {
            let k = blake3_hash(&(i as u64).wrapping_mul(salt).to_le_bytes()).to_vec();
            let v = blake3_hash(&(i as u64 ^ salt).to_le_bytes())[..16].to_vec();
            (k, v)
        })
        .collect()
}

#[test]
fn root_matches_naive_reference_across_sizes() {
    let empty = empty_ladder();
    for &n in &[1usize, 2, 3, 8, 64, 500] {
        let data = pairs(n, 0x9E37_79B9_7F4A_7C15);
        let mut fast = SparseMerkleTree::new();
        let mut naive = NaiveTree::new(empty[255]);
        for (k, v) in &data {
            fast.insert(k, v);
            naive.insert(k, v, &empty);
        }
        assert_eq!(
            fast.root(),
            naive.root,
            "root diverged from the original algorithm at n={n}. \
             A differing state root makes a validator disagree with every peer."
        );
    }
}

#[test]
fn root_matches_reference_through_updates_and_reinserts() {
    let empty = empty_ladder();
    let data = pairs(120, 0xDEAD_BEEF_CAFE_1234);
    let mut fast = SparseMerkleTree::new();
    let mut naive = NaiveTree::new(empty[255]);
    for (k, v) in &data {
        fast.insert(k, v);
        naive.insert(k, v, &empty);
    }
    // Overwrite a third of them, which is where a stale stored node would show.
    for (k, _) in data.iter().step_by(3) {
        fast.insert(k, b"rewritten");
        naive.insert(k, b"rewritten", &empty);
    }
    assert_eq!(
        fast.root(),
        naive.root,
        "root diverged after in-place updates"
    );
}

#[test]
fn stored_nodes_scale_with_leaves_not_with_256_times_leaves() {
    let n = 500usize;
    let mut t = SparseMerkleTree::new();
    for (k, v) in pairs(n, 0x1234_5678_9ABC_DEF0) {
        t.insert(&k, &v);
    }
    let stored = t.stored_nodes();
    // The old implementation stored ~238*N here (>100_000). Anything near that
    // means the branching-only rule regressed and the OOM is back.
    assert!(
        stored < n * 4,
        "stored {stored} nodes for {n} leaves: expected O(N), not O(256 N). \
         This is the allocation that OOM-killed the testnet validators."
    );
    assert_eq!(t.leaf_count(), n, "every leaf must still be present");
}

#[test]
fn report_the_reduction() {
    for &n in &[100usize, 1000, 5000] {
        let mut t = SparseMerkleTree::new();
        for (k, v) in pairs(n, 0xABCD_EF01_2345_6789) {
            t.insert(&k, &v);
        }
        let stored = t.stored_nodes();
        let old = n * 238; // what the previous implementation held, approximately
        println!(
            "  n={n:<6} stored={stored:<8} was~{old:<10} reduction={:.0}x  heap~{:.1}MB vs ~{:.0}MB",
            old as f64 / stored.max(1) as f64,
            (stored * 100) as f64 / 1_048_576.0,
            (old * 100) as f64 / 1_048_576.0,
        );
    }
}

//! Merkle inclusion proofs over the sparse state trees — the primitive
//! the EVM identity precompiles verify against L1-finalized sub-tree
//! roots (§5.7).
//!
//! Compressed form: a 256-bit bitmap marks which levels have a non-empty
//! sibling; only those sibling hashes ship. In a sparse tree with n
//! leaves the expected non-empty count is ~log₂(n), so proofs stay in the
//! hundreds of bytes instead of 256 × 32 B.

use serde::{Deserialize, Serialize};
use solidus_crypto::hash::blake3_hash;

use crate::tree::{flip_bit, get_bit, zero_bits_below, SparseMerkleTree, EMPTY_HASHES};

/// A compressed Merkle inclusion proof for one `(key, value)` leaf.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Bit L set ⇒ the level-L sibling is non-empty and present in
    /// `siblings` (ascending level order). Bit numbering matches the
    /// tree's path bits (bit 0 = MSB of byte 0).
    pub sibling_bitmap: [u8; 32],
    /// The non-empty sibling hashes, ascending by level.
    pub siblings: Vec<[u8; 32]>,
}

impl SparseMerkleTree {
    /// Produce an inclusion proof for `key`, or `None` if the key has no
    /// leaf in this tree.
    pub fn prove(&self, key: &[u8]) -> Option<InclusionProof> {
        let key_hash = blake3_hash(key);
        self.leaf_value(&key_hash)?;

        let mut bitmap = [0u8; 32];
        let mut siblings = Vec::new();
        for level in 0..256u16 {
            let mut current_path = key_hash;
            zero_bits_below(&mut current_path, level as usize);
            let mut sibling_path = current_path;
            flip_bit(&mut sibling_path, level as usize);

            if let Some(hash) = self.node(level, &sibling_path) {
                set_bit(&mut bitmap, level as usize);
                siblings.push(hash);
            }
        }
        Some(InclusionProof {
            sibling_bitmap: bitmap,
            siblings,
        })
    }
}

/// Verify that `(key, value)` is included under `root`.
pub fn verify_inclusion(root: &[u8; 32], key: &[u8], value: &[u8], proof: &InclusionProof) -> bool {
    // Sibling count must match the bitmap exactly (no smuggled extras).
    let claimed = (0..256)
        .filter(|&l| get_bit(&proof.sibling_bitmap, l) == 1)
        .count();
    if claimed != proof.siblings.len() {
        return false;
    }

    let key_hash = blake3_hash(key);
    let value_hash = blake3_hash(value);
    let mut leaf_data = [0u8; 64];
    leaf_data[..32].copy_from_slice(&key_hash);
    leaf_data[32..].copy_from_slice(&value_hash);
    let mut current = blake3_hash(&leaf_data);

    let mut next_sibling = 0usize;
    for level in 0..256usize {
        let sibling = if get_bit(&proof.sibling_bitmap, level) == 1 {
            let s = proof.siblings[next_sibling];
            next_sibling += 1;
            s
        } else {
            EMPTY_HASHES[level]
        };

        let bit = get_bit(&key_hash, level);
        let (left, right) = if bit == 0 {
            (current, sibling)
        } else {
            (sibling, current)
        };
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&left);
        pair[32..].copy_from_slice(&right);
        current = blake3_hash(&pair);
    }

    current == *root
}

fn set_bit(data: &mut [u8; 32], pos: usize) {
    let byte_index = pos / 8;
    let bit_index = 7 - (pos % 8);
    data[byte_index] |= 1 << bit_index;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_roundtrip_over_random_map() {
        let mut tree = SparseMerkleTree::new();
        let pairs: Vec<(String, Vec<u8>)> = (0..300)
            .map(|i| (format!("key-{i}"), vec![(i % 251) as u8; 40 + (i % 60)]))
            .collect();
        for (k, v) in &pairs {
            tree.insert(k.as_bytes(), v);
        }
        let root = tree.root();

        for (k, v) in pairs.iter().step_by(17) {
            let proof = tree.prove(k.as_bytes()).expect("leaf exists");
            assert!(
                verify_inclusion(&root, k.as_bytes(), v, &proof),
                "valid proof must verify for {k}"
            );
            // Wrong value fails.
            assert!(!verify_inclusion(&root, k.as_bytes(), b"forged", &proof));
            // Wrong root fails.
            assert!(!verify_inclusion(&[9u8; 32], k.as_bytes(), v, &proof));
            // Wrong key fails.
            assert!(!verify_inclusion(&root, b"key-none", v, &proof));
        }
    }

    #[test]
    fn absent_key_yields_no_proof() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"present", b"1");
        assert!(tree.prove(b"absent").is_none());
    }

    #[test]
    fn tampered_proofs_fail() {
        let mut tree = SparseMerkleTree::new();
        for i in 0..64 {
            tree.insert(format!("k{i}").as_bytes(), &[i as u8; 16]);
        }
        let root = tree.root();
        let proof = tree.prove(b"k7").expect("leaf");
        assert!(verify_inclusion(&root, b"k7", &[7u8; 16], &proof));

        // Flip a sibling hash byte.
        let mut bad = proof.clone();
        if !bad.siblings.is_empty() {
            bad.siblings[0][0] ^= 0xFF;
            assert!(!verify_inclusion(&root, b"k7", &[7u8; 16], &bad));
        }

        // Claim an extra bitmap bit without providing the sibling.
        let mut bad2 = proof.clone();
        bad2.sibling_bitmap[31] ^= 0x01;
        assert!(!verify_inclusion(&root, b"k7", &[7u8; 16], &bad2));

        // Smuggle an extra sibling not covered by the bitmap.
        let mut bad3 = proof.clone();
        bad3.siblings.push([0xAB; 32]);
        assert!(!verify_inclusion(&root, b"k7", &[7u8; 16], &bad3));
    }

    #[test]
    fn proofs_stay_compact_in_sparse_trees() {
        let mut tree = SparseMerkleTree::new();
        for i in 0..1_000 {
            tree.insert(format!("acct-{i}").as_bytes(), &[1u8; 73]);
        }
        let proof = tree.prove(b"acct-500").expect("leaf");
        let encoded = bincode::serialize(&proof).expect("serialize");
        // ~log2(1000) ≈ 10 non-empty siblings expected; allow generous slack.
        println!(
            "1000-leaf proof: {} siblings, {} bytes encoded",
            proof.siblings.len(),
            encoded.len()
        );
        assert!(
            proof.siblings.len() <= 40,
            "proof has {} siblings — sparse compression broken",
            proof.siblings.len()
        );
        assert!(encoded.len() < 2_000);
    }
}

//! Deterministic libp2p identity derivation from a node's Ed25519 `node.key`.
//!
//! The libp2p transport identity is **domain-separated** from the consensus
//! signing key: we hash `node.key ‖ "solidus/libp2p"` so the key that signs
//! blocks is never reused for the noise transport handshake, while the PeerId
//! stays deterministically derivable from `node.key` (no extra secret file).

use libp2p::identity::{DecodingError, Keypair};
use solidus_crypto::hash::blake3_hash;

const DOMAIN_TAG: &[u8] = b"solidus/libp2p";

/// Derive a libp2p Ed25519 [`Keypair`] from a 32-byte `node.key` seed.
pub fn libp2p_keypair_from_node_seed(seed: &[u8; 32]) -> Result<Keypair, DecodingError> {
    let material = blake3_hash(&[seed.as_slice(), DOMAIN_TAG].concat());
    Keypair::ed25519_from_bytes(material)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_id_b58(seed: &[u8; 32]) -> String {
        libp2p_keypair_from_node_seed(seed)
            .unwrap()
            .public()
            .to_peer_id()
            .to_base58()
    }

    #[test]
    fn derivation_is_deterministic() {
        let seed = [7u8; 32];
        assert_eq!(peer_id_b58(&seed), peer_id_b58(&seed));
    }

    #[test]
    fn derivation_is_domain_separated() {
        // The derived identity must NOT equal a keypair built directly from the
        // raw seed — proving the domain tag actually changes the key material.
        let seed = [7u8; 32];
        let raw = Keypair::ed25519_from_bytes(seed)
            .unwrap()
            .public()
            .to_peer_id()
            .to_base58();
        assert_ne!(peer_id_b58(&seed), raw);
    }

    #[test]
    fn distinct_seeds_distinct_peer_ids() {
        assert_ne!(peer_id_b58(&[1u8; 32]), peer_id_b58(&[2u8; 32]));
    }
}

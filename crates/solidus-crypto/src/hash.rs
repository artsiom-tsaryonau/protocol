/// BLAKE3-256 hash of the given data.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// First 20 bytes of the BLAKE3-256 hash (analogous to Bitcoin's HASH160).
/// Used for address derivation from public keys.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let full = blake3_hash(data);
    let mut out = [0u8; 20];
    out.copy_from_slice(&full[..20]);
    out
}

/// Precompute 256 empty hashes for sparse Merkle tree construction.
///
/// Level 0 = BLAKE3(0x00..00 || 0x00..00)  (two 32-byte zero children)
/// Level n = BLAKE3(empty[n-1] || empty[n-1])
pub fn empty_hashes() -> Vec<[u8; 32]> {
    let mut hashes = Vec::with_capacity(256);

    // Level 0: hash of two 32-byte zero leaves concatenated
    let zero = [0u8; 32];
    let mut pair = [0u8; 64];
    pair[..32].copy_from_slice(&zero);
    pair[32..].copy_from_slice(&zero);
    hashes.push(blake3_hash(&pair));

    // Each subsequent level hashes the previous level's empty hash with itself
    for i in 1..256 {
        let prev = hashes[i - 1];
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&prev);
        pair[32..].copy_from_slice(&prev);
        hashes.push(blake3_hash(&pair));
    }

    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_hash_deterministic() {
        let data = b"solidus network";
        assert_eq!(blake3_hash(data), blake3_hash(data));
    }

    #[test]
    fn blake3_hash_different_inputs_differ() {
        let a = blake3_hash(b"hello");
        let b = blake3_hash(b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn blake3_hash_empty_input() {
        let h = blake3_hash(b"");
        // BLAKE3 of empty input is a well-known constant
        assert_eq!(h, *blake3::hash(b"").as_bytes());
    }

    #[test]
    fn hash160_is_20_bytes() {
        let h = hash160(b"test data");
        assert_eq!(h.len(), 20);
    }

    /// Value-asserting golden vector — `hash160_is_20_bytes` above only ever
    /// checked the LENGTH, never the VALUE. That gap is exactly how
    /// `docs/protocol.md`'s formerly-wrong `RIPEMD-160(BLAKE3-256(data))`
    /// formula went unnoticed against this function's real behavior
    /// (truncated BLAKE3, no RIPEMD anywhere). This test locks the value so
    /// the spec can't drift again silently.
    #[test]
    fn hash160_matches_known_vector() {
        const FIXED_INPUT: &[u8] = b"solidus-hash160-test-vector-v1";
        let got = hex::encode(hash160(FIXED_INPUT));
        assert_eq!(got, "4384b9ff31cf1c42f97a2bf638547f8f7784ddc1");
    }

    #[test]
    fn hash160_deterministic() {
        let data = b"solidus address";
        assert_eq!(hash160(data), hash160(data));
    }

    #[test]
    fn hash160_is_prefix_of_blake3() {
        let data = b"prefix check";
        let full = blake3_hash(data);
        let short = hash160(data);
        assert_eq!(&full[..20], &short[..]);
    }

    #[test]
    fn empty_hashes_has_256_levels() {
        let hashes = empty_hashes();
        assert_eq!(hashes.len(), 256);
    }

    #[test]
    fn empty_hashes_level_0_is_hash_of_zero_pair() {
        let hashes = empty_hashes();
        let zero = [0u8; 32];
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&zero);
        pair[32..].copy_from_slice(&zero);
        assert_eq!(hashes[0], blake3_hash(&pair));
    }

    #[test]
    fn empty_hashes_each_level_derives_from_previous() {
        let hashes = empty_hashes();
        for i in 1..256 {
            let prev = hashes[i - 1];
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&prev);
            pair[32..].copy_from_slice(&prev);
            assert_eq!(hashes[i], blake3_hash(&pair));
        }
    }
}

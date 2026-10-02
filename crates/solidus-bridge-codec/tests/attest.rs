//! The bytes a validator signs, asserted field by field.
//!
//! ⚠ THE FOUR `assert_ne!` CASES BELOW ARE THE SECURITY OF THE WHOLE TRANSPORT, not tidiness. A
//! digest that ignores the destination domain lets a Sepolia signature be replayed on Fuji; one
//! that ignores the chain id lets a devnet signature pass on testnet.

use solidus_bridge_codec::attest::{
    attestation_digest, attestation_preimage, eth_signed_message_hash, ATTESTATION_DOMAIN,
};
use solidus_bridge_codec::keccak256;

const MSG: [u8; 32] = [0xA1; 32];

#[test]
fn the_preimage_is_the_documented_byte_string() {
    let p = attestation_preimage(50_002, 11_155_111, 7, &MSG, 900);
    assert_eq!(&p[..29], ATTESTATION_DOMAIN);
    assert_eq!(&p[29..37], &50_002u64.to_be_bytes());
    assert_eq!(&p[37..41], &11_155_111u32.to_be_bytes());
    assert_eq!(&p[41..49], &7u64.to_be_bytes());
    assert_eq!(&p[49..81], &MSG);
    assert_eq!(&p[81..89], &900u64.to_be_bytes());
    assert_eq!(p.len(), 89);
    assert_eq!(
        attestation_digest(50_002, 11_155_111, 7, &MSG, 900),
        keccak256(&p)
    );
}

#[test]
fn every_field_changes_the_digest() {
    let base = attestation_digest(50_002, 11_155_111, 7, &MSG, 900);
    assert_ne!(
        base,
        attestation_digest(50_003, 11_155_111, 7, &MSG, 900),
        "chain id"
    );
    assert_ne!(
        base,
        attestation_digest(50_002, 43_113, 7, &MSG, 900),
        "domain"
    );
    assert_ne!(
        base,
        attestation_digest(50_002, 11_155_111, 8, &MSG, 900),
        "sequence"
    );
    assert_ne!(
        base,
        attestation_digest(50_002, 11_155_111, 7, &[0xA2; 32], 900),
        "message id"
    );
    assert_ne!(
        base,
        attestation_digest(50_002, 11_155_111, 7, &MSG, 901),
        "height"
    );
}

#[test]
fn the_eth_signed_hash_matches_the_ethereum_prefix() {
    let d = attestation_digest(50_002, 11_155_111, 7, &MSG, 900);
    let mut expected = Vec::from(&b"\x19Ethereum Signed Message:\n32"[..]);
    expected.extend_from_slice(&d);
    assert_eq!(eth_signed_message_hash(&d), keccak256(&expected));
}

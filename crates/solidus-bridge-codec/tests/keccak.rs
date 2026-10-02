//! Known answers from the Keccak team's reference (Ethereum's keccak256, not
//! NIST SHA3-256, whose padding differs). If this fails the crate hashes with
//! the wrong function and every id and digest downstream is wrong.

use solidus_bridge_codec::keccak256;

#[test]
fn keccak256_of_empty_input_matches_the_ethereum_constant() {
    assert_eq!(
        hex::encode(keccak256(b"")),
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    );
}

#[test]
fn keccak256_of_abc_matches_the_known_answer() {
    assert_eq!(
        hex::encode(keccak256(b"abc")),
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
    );
}

#[test]
fn control_nist_sha3_would_give_a_different_answer() {
    // SHA3-256("") is a7ffc6f8..., so a crate that picked Sha3_256 fails here.
    assert_ne!(
        hex::encode(keccak256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
}

//! Validator attestation keys: sign the bytes, recover the signer.
//!
//! ⛔ RECOVERY PROVES ONLY THAT A SIGNATURE BELONGS TO SOME KEY. `ecrecover` and its Rust twin
//! return an address for almost any input, so "it recovered" is not "it is valid". The test that
//! says so honestly is the one where a signature over a DIFFERENT digest recovers to a different
//! address rather than failing: the caller, not the primitive, decides whether that address counts.

use std::path::Path;

use serde_json::Value;
use solidus_crypto::attest::{recover, AttestError, AttestationKey};

/// Anvil account #1. A published test key: it holds nothing, anywhere, ever.
const TEST_KEY: &str = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const TEST_ADDR: &str = "70997970c51812dc3a010c7d01b50e0d17dc79c8";

fn vectors() -> Value {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let candidate = dir.join("test-fixtures");
        if candidate.is_dir() {
            let path = candidate.join("bridge").join("attestation-v2.json");
            return serde_json::from_str(&std::fs::read_to_string(path).expect("vectors")).unwrap();
        }
        dir = dir.parent().expect("test-fixtures/ not found above the cwd");
    }
}

fn bytes32(hex_str: &str) -> [u8; 32] {
    hex::decode(hex_str.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn key() -> AttestationKey {
    AttestationKey::from_hex(TEST_KEY).expect("test key")
}

#[test]
fn the_fixed_test_key_derives_the_documented_address() {
    assert_eq!(hex::encode(key().address()), TEST_ADDR);
}

#[test]
fn a_signature_over_a_vector_digest_recovers_to_that_address() {
    let v = vectors();
    let cases = v["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 4, "attestation-v2.json case count changed");
    for case in cases {
        let eth_signed = bytes32(case["ethSigned"].as_str().unwrap());
        let sig = key().sign(&eth_signed);
        // RFC6979 is deterministic, so our signature IS the committed one, byte for byte.
        assert_eq!(
            format!("0x{}", hex::encode(sig)),
            case["signature"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            hex::encode(recover(&eth_signed, &sig).expect("recover")),
            TEST_ADDR,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn a_signature_is_65_bytes_with_v_27_or_28() {
    let sig = key().sign(&[0xAB; 32]);
    assert_eq!(sig.len(), 65);
    assert!(sig[64] == 27 || sig[64] == 28, "v was {}", sig[64]);
}

#[test]
fn a_high_s_signature_is_refused() {
    let digest = [0xAB; 32];
    let sig = key().sign(&digest);
    let low = k256::ecdsa::Signature::from_slice(&sig[..64]).unwrap();
    let (r, s) = low.split_scalars();
    let high = k256::ecdsa::Signature::from_scalars(r, -s).unwrap();
    let mut bad = high.to_bytes().to_vec();
    bad.push(sig[64]);
    assert_eq!(recover(&digest, &bad), Err(AttestError::HighS));
}

#[test]
fn a_signature_over_another_digest_recovers_to_a_different_address() {
    let sig = key().sign(&[0xAB; 32]);
    let other = recover(&[0xAC; 32], &sig).expect("recovery still succeeds");
    assert_ne!(
        hex::encode(other),
        TEST_ADDR,
        "recovery over the wrong digest must not yield the signer"
    );
}

#[test]
fn malformed_input_is_an_error_and_never_a_panic() {
    let digest = [0xAB; 32];
    let sig = key().sign(&digest);
    assert_eq!(
        recover(&digest, &sig[..64]),
        Err(AttestError::BadLength(64))
    );
    let mut long = sig.to_vec();
    long.push(0);
    assert_eq!(recover(&digest, &long), Err(AttestError::BadLength(66)));
    let mut bad_v = sig;
    bad_v[64] = 29;
    assert_eq!(
        recover(&digest, &bad_v),
        Err(AttestError::BadRecoveryId(29))
    );
}

#[test]
fn from_hex_refuses_a_key_that_is_not_32_bytes() {
    assert!(AttestationKey::from_hex("00").is_err());
    assert!(AttestationKey::from_hex("zz".repeat(32).as_str()).is_err());
}

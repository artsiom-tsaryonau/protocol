//! `did:solidus` identifiers and the W3C DID Document surface.

use solidus_crypto::hash::hash160;

const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

fn base58(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        let mut carry = byte as usize;
        for digit in digits.iter_mut() {
            carry += (*digit as usize) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    // Every leading zero byte encodes to one '1'.
    let leading_zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = String::with_capacity(leading_zeros + digits.len());
    out.extend(std::iter::repeat_n('1', leading_zeros));
    out.extend(digits.iter().rev().map(|&d| BASE58[d as usize] as char));
    out
}

/// `publicKeyMultibase` for a raw 32-byte Ed25519 public key: base58btc of the
/// `ed25519-pub` multicodec header followed by the key. Produces a `z6Mk…` string.
///
/// ⚠ RE-EXPORTED, NOT REIMPLEMENTED, since 2026-08-25. The body used to live here and
/// `solidus-rpc` needed the same value to serve a conformant DID document, which it could
/// not reach without inverting the crate layering. It now lives in `solidus-crypto`, the
/// common ancestor. A spec-critical encoder with two copies is a drift waiting to happen
/// and nothing to say which copy is right.
pub use solidus_crypto::keys::public_key_multibase;

/// The `did:solidus` identifier segment for a public key:
/// `base58(BLAKE3-256(public_key)[0..20])`.
pub fn identifier_for(public_key: &[u8; 32]) -> String {
    base58(&hash160(public_key))
}

/// Whether a string is a syntactically valid `did:solidus` identifier segment,
/// per SPEC v0.2.0 §4.1: `identifier = 20*28base58char`.
///
/// The length bound is arithmetic, not taste — a 20-byte payload cannot encode to
/// fewer than 20 characters (all-zero) or more than 28 (all-`0xFF`). v0.1.0 of the
/// spec allowed up to 33 and its ABNF admitted `0`, `O`, `I` and `l`, so a parser
/// generated from it accepted identifiers this method can never mint.
///
/// This is what separates `invalidDid` from `notFound`: "no such DID" implies the
/// identifier could have existed.
pub fn is_valid_identifier(identifier: &str) -> bool {
    let len = identifier.chars().count();
    (20..=28).contains(&len) && identifier.bytes().all(|b| BASE58.contains(&b))
}

/// Whether a full `did:solidus:<network>:<identifier>` is syntactically valid.
pub fn is_valid_did(did: &str) -> bool {
    let mut parts = did.split(':');
    matches!(
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next()),
        (Some("did"), Some("solidus"), Some("testnet" | "mainnet"), Some(id), None)
            if is_valid_identifier(id)
    )
}

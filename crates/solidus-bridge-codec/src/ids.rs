//! Identifiers shared by every chain (spec §4.4, registry §2.4).

use alloc::vec::Vec;

use crate::keccak256;

/// `keccak256(credential_id utf8 ‖ domain u32 BE ‖ holder)`. The domain makes
/// the id differ per chain, so exports of one credential are not linkable by id.
pub fn export_id(credential_id: &str, domain: u32, holder: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(credential_id.len() + 36);
    buf.extend_from_slice(credential_id.as_bytes());
    buf.extend_from_slice(&domain.to_be_bytes());
    buf.extend_from_slice(holder);
    keccak256(&buf)
}

pub fn issuer_did_hash(issuer_did: &str) -> [u8; 32] {
    keccak256(issuer_did.as_bytes())
}

/// Hash of the credential type's serde name, e.g. `"KycL2"`. Taking the name
/// rather than the enum keeps this crate free of `solidus-txns`.
pub fn credential_type_hash(serde_name: &str) -> [u8; 32] {
    keccak256(serde_name.as_bytes())
}

pub fn gate_key(
    holder: &[u8; 32],
    credential_type_hash: &[u8; 32],
    issuer_did_hash: &[u8; 32],
) -> [u8; 32] {
    let mut buf = [0u8; 96];
    buf[..32].copy_from_slice(holder);
    buf[32..64].copy_from_slice(credential_type_hash);
    buf[64..].copy_from_slice(issuer_did_hash);
    keccak256(&buf)
}

pub fn transfer_id(
    origin_domain: u32,
    deposit_nonce: u64,
    recipient: &[u8; 32],
    amount_u256_be: &[u8; 32],
    token: &[u8; 32],
    deadline: u64,
) -> [u8; 32] {
    let mut buf = [0u8; 116];
    buf[0..4].copy_from_slice(&origin_domain.to_be_bytes());
    buf[4..12].copy_from_slice(&deposit_nonce.to_be_bytes());
    buf[12..44].copy_from_slice(recipient);
    buf[44..76].copy_from_slice(amount_u256_be);
    buf[76..108].copy_from_slice(token);
    buf[108..116].copy_from_slice(&deadline.to_be_bytes());
    keccak256(&buf)
}

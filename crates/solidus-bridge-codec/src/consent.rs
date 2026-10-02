//! Holder consent to an export (spec §5.1 step 2). Solidus verifies these
//! signatures; the mirror contracts never see them.

use alloc::string::String;
use alloc::vec::Vec;

use crate::keccak256;

pub const EIP712_DOMAIN_NAME: &str = "SolidusBridge";
pub const EIP712_DOMAIN_VERSION: &str = "1";
pub const EIP712_DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
pub const EIP712_CONSENT_TYPE: &str =
    "ExportConsent(string credentialId,uint32 domain,bytes32 holder,uint64 consentExpiry)";
pub const ED25519_CONSENT_PREFIX: &[u8] = b"SOLIDUS_BRIDGE_CONSENT_V1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConsent {
    pub credential_id: String,
    pub domain: u32,
    pub holder: [u8; 32],
    pub consent_expiry: u64,
}

fn word_u64(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

/// EIP-712 digest: `keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash)`.
pub fn eip712_consent_digest(
    c: &ExportConsent,
    chain_id: u64,
    verifying_contract: &[u8; 20],
) -> [u8; 32] {
    let mut domain = Vec::with_capacity(160);
    domain.extend_from_slice(&keccak256(EIP712_DOMAIN_TYPE.as_bytes()));
    domain.extend_from_slice(&keccak256(EIP712_DOMAIN_NAME.as_bytes()));
    domain.extend_from_slice(&keccak256(EIP712_DOMAIN_VERSION.as_bytes()));
    domain.extend_from_slice(&word_u64(chain_id));
    let mut contract = [0u8; 32];
    contract[12..].copy_from_slice(verifying_contract);
    domain.extend_from_slice(&contract);
    let domain_separator = keccak256(&domain);

    let mut s = Vec::with_capacity(160);
    s.extend_from_slice(&keccak256(EIP712_CONSENT_TYPE.as_bytes()));
    s.extend_from_slice(&keccak256(c.credential_id.as_bytes()));
    s.extend_from_slice(&word_u64(u64::from(c.domain)));
    s.extend_from_slice(&c.holder);
    s.extend_from_slice(&word_u64(c.consent_expiry));
    let struct_hash = keccak256(&s);

    let mut m = [0u8; 66];
    m[0] = 0x19;
    m[1] = 0x01;
    m[2..34].copy_from_slice(&domain_separator);
    m[34..].copy_from_slice(&struct_hash);
    keccak256(&m)
}

/// Bytes an ed25519 (Solana) holder signs:
/// `prefix ‖ domain BE ‖ mirror program id ‖ keccak256(credential_id) ‖ holder ‖ consent_expiry BE`.
pub fn ed25519_consent_bytes(c: &ExportConsent, mirror_program_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ED25519_CONSENT_PREFIX.len() + 108);
    out.extend_from_slice(ED25519_CONSENT_PREFIX);
    out.extend_from_slice(&c.domain.to_be_bytes());
    out.extend_from_slice(mirror_program_id);
    out.extend_from_slice(&keccak256(c.credential_id.as_bytes()));
    out.extend_from_slice(&c.holder);
    out.extend_from_slice(&c.consent_expiry.to_be_bytes());
    out
}

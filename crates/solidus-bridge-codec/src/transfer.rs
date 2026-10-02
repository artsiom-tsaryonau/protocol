//! Metadata carried by value transfers (registry §2.4).

use crate::message::{arr32, be_u64, CodecError};

pub const TRANSFER_META_VERSION: u8 = 1;
pub const TRANSFER_META_LEN: usize = 49;
pub const USDC_HOOK_VERSION: u8 = 1;
pub const USDC_HOOK_LEN: usize = 145;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransferMeta {
    pub version: u8,
    pub transfer_id: [u8; 32],
    pub referral_code: [u8; 8],
    pub deadline: u64,
}

pub fn encode_transfer_meta(m: &TransferMeta) -> [u8; TRANSFER_META_LEN] {
    let mut out = [0u8; TRANSFER_META_LEN];
    out[0] = m.version;
    out[1..33].copy_from_slice(&m.transfer_id);
    out[33..41].copy_from_slice(&m.referral_code);
    out[41..49].copy_from_slice(&m.deadline.to_be_bytes());
    out
}

pub fn decode_transfer_meta(b: &[u8]) -> Result<TransferMeta, CodecError> {
    if b.len() != TRANSFER_META_LEN {
        return Err(CodecError::BadLength {
            expected: TRANSFER_META_LEN,
            got: b.len(),
        });
    }
    if b[0] != TRANSFER_META_VERSION {
        return Err(CodecError::BadVersion(b[0]));
    }
    let mut code = [0u8; 8];
    code.copy_from_slice(&b[33..41]);
    Ok(TransferMeta {
        version: b[0],
        transfer_id: arr32(&b[1..33]),
        referral_code: code,
        deadline: be_u64(&b[41..49]),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsdcHookData {
    pub version: u8,
    pub final_recipient: [u8; 32],
    pub credential_type_hash: [u8; 32],
    pub issuer_did_hash: [u8; 32],
    pub refund_address: [u8; 32],
    pub deadline: u64,
    pub referral_code: [u8; 8],
}

pub fn encode_usdc_hook(h: &UsdcHookData) -> [u8; USDC_HOOK_LEN] {
    let mut out = [0u8; USDC_HOOK_LEN];
    out[0] = h.version;
    out[1..33].copy_from_slice(&h.final_recipient);
    out[33..65].copy_from_slice(&h.credential_type_hash);
    out[65..97].copy_from_slice(&h.issuer_did_hash);
    out[97..129].copy_from_slice(&h.refund_address);
    out[129..137].copy_from_slice(&h.deadline.to_be_bytes());
    out[137..145].copy_from_slice(&h.referral_code);
    out
}

pub fn decode_usdc_hook(b: &[u8]) -> Result<UsdcHookData, CodecError> {
    if b.len() != USDC_HOOK_LEN {
        return Err(CodecError::BadLength {
            expected: USDC_HOOK_LEN,
            got: b.len(),
        });
    }
    if b[0] != USDC_HOOK_VERSION {
        return Err(CodecError::BadVersion(b[0]));
    }
    let mut code = [0u8; 8];
    code.copy_from_slice(&b[137..145]);
    Ok(UsdcHookData {
        version: b[0],
        final_recipient: arr32(&b[1..33]),
        credential_type_hash: arr32(&b[33..65]),
        issuer_did_hash: arr32(&b[65..97]),
        refund_address: arr32(&b[97..129]),
        deadline: be_u64(&b[129..137]),
        referral_code: code,
    })
}

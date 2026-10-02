use solidus_bridge_codec::{
    decode_transfer_meta, decode_usdc_hook, encode_transfer_meta, encode_usdc_hook, CodecError,
    TransferMeta, UsdcHookData, TRANSFER_META_VERSION, USDC_HOOK_VERSION,
};

fn meta() -> TransferMeta {
    TransferMeta {
        version: TRANSFER_META_VERSION,
        transfer_id: [0x0A; 32],
        referral_code: *b"SOLIDUS1",
        deadline: 1_900_000_000,
    }
}

fn hook() -> UsdcHookData {
    UsdcHookData {
        version: USDC_HOOK_VERSION,
        final_recipient: [0x0B; 32],
        credential_type_hash: [0x0C; 32],
        issuer_did_hash: [0x0D; 32],
        refund_address: [0x0E; 32],
        deadline: 1_900_000_000,
        referral_code: [0u8; 8],
    }
}

#[test]
fn transfer_meta_layout_is_version_id_code_deadline() {
    let b = encode_transfer_meta(&meta());
    assert_eq!(b.len(), 49);
    assert_eq!(b[0], 1);
    assert_eq!(&b[1..33], &[0x0A; 32]);
    assert_eq!(&b[33..41], b"SOLIDUS1");
    assert_eq!(&b[41..49], &1_900_000_000u64.to_be_bytes());
    assert_eq!(decode_transfer_meta(&b).unwrap(), meta());
}

#[test]
fn transfer_meta_rejects_wrong_length_and_version() {
    let b = encode_transfer_meta(&meta());
    assert_eq!(
        decode_transfer_meta(&b[..48]),
        Err(CodecError::BadLength {
            expected: 49,
            got: 48
        })
    );
    let mut v2 = b;
    v2[0] = 2;
    assert_eq!(decode_transfer_meta(&v2), Err(CodecError::BadVersion(2)));
}

#[test]
fn usdc_hook_layout_round_trips_at_145_bytes() {
    let b = encode_usdc_hook(&hook());
    assert_eq!(b.len(), 145);
    assert_eq!(&b[1..33], &[0x0B; 32]);
    assert_eq!(&b[129..137], &1_900_000_000u64.to_be_bytes());
    assert_eq!(decode_usdc_hook(&b).unwrap(), hook());
}

#[test]
fn usdc_hook_rejects_wrong_length_and_version() {
    let b = encode_usdc_hook(&hook());
    assert_eq!(
        decode_usdc_hook(&b[..144]),
        Err(CodecError::BadLength {
            expected: 145,
            got: 144
        })
    );
    let mut v = b;
    v[0] = 0;
    assert_eq!(decode_usdc_hook(&v), Err(CodecError::BadVersion(0)));
}

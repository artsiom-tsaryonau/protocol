//! Layout tests. The independent answer (a second implementation) is the viem
//! cross-check in Task 6; these pin the byte order and field boundaries.

use solidus_bridge_codec::{
    credential_type_hash, export_id, gate_key, issuer_did_hash, keccak256, transfer_id,
};

#[test]
fn export_id_hashes_id_then_big_endian_domain_then_holder() {
    let holder = [0x04u8; 32];
    let mut preimage = b"urn:solidus:credential:00ff".to_vec();
    preimage.extend_from_slice(&[0x00, 0xAA, 0x36, 0xA7]); // 11155111 big-endian
    preimage.extend_from_slice(&holder);
    assert_eq!(
        export_id("urn:solidus:credential:00ff", 11_155_111, &holder),
        keccak256(&preimage)
    );
}

#[test]
fn export_id_differs_per_domain_so_exports_are_unlinkable_by_id() {
    let holder = [0x04u8; 32];
    let a = export_id("urn:solidus:credential:00ff", 11_155_111, &holder);
    let b = export_id("urn:solidus:credential:00ff", 43_113, &holder);
    assert_ne!(a, b);
}

#[test]
fn issuer_and_type_hashes_are_keccak_of_utf8() {
    assert_eq!(
        issuer_did_hash("did:solidus:testnet:abc"),
        keccak256(b"did:solidus:testnet:abc")
    );
    assert_eq!(credential_type_hash("KycL2"), keccak256(b"KycL2"));
}

#[test]
fn gate_key_concatenates_holder_type_issuer_in_that_order() {
    let (h, t, i) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let mut pre = Vec::new();
    pre.extend_from_slice(&h);
    pre.extend_from_slice(&t);
    pre.extend_from_slice(&i);
    assert_eq!(gate_key(&h, &t, &i), keccak256(&pre));
    assert_ne!(
        gate_key(&h, &t, &i),
        gate_key(&h, &i, &t),
        "order must matter"
    );
}

#[test]
fn transfer_id_is_116_bytes_of_big_endian_fields() {
    let recipient = [0x05u8; 32];
    let mut amount = [0u8; 32];
    amount[31] = 0x64; // 100
    let token = [0x06u8; 32];
    let mut pre = Vec::new();
    pre.extend_from_slice(&50_002u32.to_be_bytes());
    pre.extend_from_slice(&7u64.to_be_bytes());
    pre.extend_from_slice(&recipient);
    pre.extend_from_slice(&amount);
    pre.extend_from_slice(&token);
    pre.extend_from_slice(&1_900_000_000u64.to_be_bytes());
    assert_eq!(pre.len(), 116);
    assert_eq!(
        transfer_id(50_002, 7, &recipient, &amount, &token, 1_900_000_000),
        keccak256(&pre)
    );
}

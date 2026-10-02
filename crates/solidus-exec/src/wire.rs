//! v2 wire format (R-WIRE pin) — binary signing bytes and tx hashes.
//!
//! ## The pinned change
//!
//! The live chain hashes and signs over **serde_json**:
//!
//! - `signing_bytes = BLAKE3(sender_pubkey || nonce_le || serde_json(payload))`
//! - `tx_hash       = BLAKE3(serde_json(transaction))`
//!
//! The v2 chain replaces `serde_json` with **bincode** in both:
//!
//! - `signing_bytes_v2 = BLAKE3(sender_pubkey || nonce_le || bincode(payload))`
//! - `tx_hash_v2       = BLAKE3(bincode(transaction))`
//!
//! This changes every transaction hash and signature relative to the live
//! chain. That is **intended and absorbed by the new chain-id** (BD-6):
//! the two networks never exchange transactions, and nothing in the
//! *state* root depends on tx hashes (credential ids derive from
//! issuer/subject/hash/height; receipts live outside the root), so the
//! Stage-0 parity anchor still demands byte-identical state roots.
//!
//! `solidus-txns` is reused unchanged, so its inherent
//! `Transaction::signing_bytes()/hash()` remain the legacy definitions;
//! all v2 code paths go through this module instead.

use ed25519_dalek::VerifyingKey;
use solidus_crypto::ed25519;
use solidus_crypto::hash::blake3_hash;
use solidus_txns::types::Transaction;

use crate::types::WireMode;

const V3_SIGN_DOMAIN: &[u8] = b"SLDS_TX_V3";
const V3_HASH_DOMAIN: &[u8] = b"SLDS_TXH_V3";

fn payload_bincode(tx: &Transaction) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    // TxPayload is a fixed-shape serde enum; bincode has no error path on it.
    bincode::serialize(&tx.payload).expect("TxPayload bincode serialization cannot fail")
}

/// `SLDS_TX_V3 ‖ chain_id LE ‖ sender_pubkey ‖ nonce LE ‖ bincode(payload)`.
pub fn signing_preimage_v3(tx: &Transaction, chain_id: u64) -> Vec<u8> {
    let payload = payload_bincode(tx);
    let mut buf = Vec::with_capacity(V3_SIGN_DOMAIN.len() + 8 + 32 + 8 + payload.len());
    buf.extend_from_slice(V3_SIGN_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&tx.sender_pubkey);
    buf.extend_from_slice(&tx.nonce.to_le_bytes());
    buf.extend_from_slice(&payload);
    buf
}

/// `SLDS_TXH_V3 ‖ chain_id LE ‖ bincode(transaction)`.
pub fn tx_hash_preimage_v3(tx: &Transaction, chain_id: u64) -> Vec<u8> {
    #[allow(clippy::expect_used)]
    let encoded = bincode::serialize(tx).expect("Transaction bincode serialization cannot fail");
    let mut buf = Vec::with_capacity(V3_HASH_DOMAIN.len() + 8 + encoded.len());
    buf.extend_from_slice(V3_HASH_DOMAIN);
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&encoded);
    buf
}

/// Message that must be signed, under the given wire mode.
pub fn signing_bytes(tx: &Transaction, mode: WireMode) -> [u8; 32] {
    match mode {
        WireMode::LegacyJson => tx.signing_bytes(),
        WireMode::BinaryV2 => {
            let payload_bin = payload_bincode(tx);
            let mut buf = Vec::with_capacity(32 + 8 + payload_bin.len());
            buf.extend_from_slice(&tx.sender_pubkey);
            buf.extend_from_slice(&tx.nonce.to_le_bytes());
            buf.extend_from_slice(&payload_bin);
            blake3_hash(&buf)
        }
        WireMode::BinaryV3 { chain_id } => blake3_hash(&signing_preimage_v3(tx, chain_id)),
    }
}

/// Content-address of the full signed transaction, under the given wire mode.
pub fn tx_hash(tx: &Transaction, mode: WireMode) -> [u8; 32] {
    match mode {
        WireMode::LegacyJson => tx.hash(),
        WireMode::BinaryV2 => {
            #[allow(clippy::expect_used)]
            let encoded =
                bincode::serialize(tx).expect("Transaction bincode serialization cannot fail");
            blake3_hash(&encoded)
        }
        WireMode::BinaryV3 { chain_id } => blake3_hash(&tx_hash_preimage_v3(tx, chain_id)),
    }
}

/// The wire mode that governs a block at `height`.
///
/// ⛔ HEIGHT ONLY. `BinaryV2` becomes `BinaryV3` at V2 heights; `LegacyJson`
/// (the parity anchor) never changes.
pub fn wire_for_height(base: WireMode, chain_id: u64, height: u64) -> WireMode {
    match base {
        WireMode::BinaryV2
            if crate::protocol::version_at(height) >= crate::protocol::ProtocolVersion::V2 =>
        {
            WireMode::BinaryV3 { chain_id }
        }
        other => other,
    }
}

/// Verify the envelope signature under the given wire mode.
pub fn verify_signature(tx: &Transaction, mode: WireMode) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(&tx.sender_pubkey) else {
        return false;
    };
    let msg = signing_bytes(tx, mode);
    ed25519::verify(&vk, &msg, &tx.signature)
}

#[cfg(test)]
mod tests {
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_txns::types::TxPayload;

    use super::*;

    fn make_tx(mode: WireMode) -> Transaction {
        let key = generate_signing_key();
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: 3,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([9u8; 20]),
                amount: 1_234,
            },
            signature: [0u8; 64],
        };
        let msg = signing_bytes(&tx, mode);
        tx.signature = sign(&key, &msg);
        tx
    }

    #[test]
    fn legacy_mode_delegates_to_live_definitions() {
        let tx = make_tx(WireMode::LegacyJson);
        assert_eq!(signing_bytes(&tx, WireMode::LegacyJson), tx.signing_bytes());
        assert_eq!(tx_hash(&tx, WireMode::LegacyJson), tx.hash());
        assert!(verify_signature(&tx, WireMode::LegacyJson));
        assert!(tx.verify_signature());
    }

    #[test]
    fn v2_mode_signs_and_verifies() {
        let tx = make_tx(WireMode::BinaryV2);
        assert!(verify_signature(&tx, WireMode::BinaryV2));
        // A v2 signature is NOT a valid legacy signature (different message).
        assert!(!verify_signature(&tx, WireMode::LegacyJson));
    }

    #[test]
    fn v2_hashes_differ_from_legacy_hashes_by_design() {
        // R-WIRE pin: if these ever collide the serialization change has
        // silently regressed to JSON somewhere.
        let tx = make_tx(WireMode::BinaryV2);
        assert_ne!(
            tx_hash(&tx, WireMode::BinaryV2),
            tx_hash(&tx, WireMode::LegacyJson)
        );
        assert_ne!(
            signing_bytes(&tx, WireMode::BinaryV2),
            signing_bytes(&tx, WireMode::LegacyJson)
        );
    }

    #[test]
    fn v2_hash_is_deterministic_and_signature_sensitive() {
        let tx = make_tx(WireMode::BinaryV2);
        assert_eq!(
            tx_hash(&tx, WireMode::BinaryV2),
            tx_hash(&tx, WireMode::BinaryV2)
        );

        let mut tampered = tx.clone();
        tampered.signature[0] ^= 0xFF;
        assert_ne!(
            tx_hash(&tampered, WireMode::BinaryV2),
            tx_hash(&tx, WireMode::BinaryV2)
        );
    }

    #[test]
    fn tampered_payload_fails_v2_verification() {
        let mut tx = make_tx(WireMode::BinaryV2);
        tx.payload = TxPayload::Transfer {
            to: Address::from_bytes([9u8; 20]),
            amount: 9_999,
        };
        assert!(!verify_signature(&tx, WireMode::BinaryV2));
    }

    #[test]
    fn v3_signs_and_verifies_and_binds_the_chain_id() {
        let tx = make_tx(WireMode::BinaryV3 { chain_id: 50_002 });
        assert!(verify_signature(
            &tx,
            WireMode::BinaryV3 { chain_id: 50_002 }
        ));
        assert!(
            !verify_signature(&tx, WireMode::BinaryV3 { chain_id: 50_003 }),
            "replay to another chain must fail"
        );
        assert!(
            !verify_signature(&tx, WireMode::BinaryV2),
            "a v3 signature is not a v2 signature"
        );
    }

    #[test]
    fn v3_preimage_layout_is_prefix_chain_pubkey_nonce_payload() {
        let tx = make_tx(WireMode::BinaryV3 { chain_id: 7 });
        let pre = signing_preimage_v3(&tx, 7);
        assert_eq!(&pre[..10], b"SLDS_TX_V3");
        assert_eq!(&pre[10..18], &7u64.to_le_bytes());
        assert_eq!(&pre[18..50], &tx.sender_pubkey);
        assert_eq!(&pre[50..58], &tx.nonce.to_le_bytes());
        assert_eq!(&pre[58..], &bincode::serialize(&tx.payload).unwrap()[..]);
        assert_eq!(
            signing_bytes(&tx, WireMode::BinaryV3 { chain_id: 7 }),
            blake3_hash(&pre)
        );
    }

    #[test]
    fn v3_hash_differs_per_chain_and_from_v2() {
        let tx = make_tx(WireMode::BinaryV3 { chain_id: 1 });
        assert_ne!(
            tx_hash(&tx, WireMode::BinaryV3 { chain_id: 1 }),
            tx_hash(&tx, WireMode::BinaryV3 { chain_id: 2 })
        );
        assert_ne!(
            tx_hash(&tx, WireMode::BinaryV3 { chain_id: 1 }),
            tx_hash(&tx, WireMode::BinaryV2)
        );
    }

    #[test]
    fn wire_for_height_upgrades_only_binary_v2_and_only_from_v2_heights() {
        use crate::protocol::V2_ACTIVATION_HEIGHT;
        assert_eq!(
            wire_for_height(WireMode::BinaryV2, 9, 0),
            WireMode::BinaryV2
        );
        assert_eq!(
            wire_for_height(WireMode::BinaryV2, 9, V2_ACTIVATION_HEIGHT),
            WireMode::BinaryV3 { chain_id: 9 }
        );
        assert_eq!(
            wire_for_height(
                WireMode::BinaryV2,
                9,
                V2_ACTIVATION_HEIGHT.saturating_sub(1)
            ),
            if V2_ACTIVATION_HEIGHT == 0 {
                WireMode::BinaryV3 { chain_id: 9 }
            } else {
                WireMode::BinaryV2
            }
        );
        assert_eq!(
            wire_for_height(WireMode::LegacyJson, 9, u64::MAX),
            WireMode::LegacyJson,
            "the parity anchor never changes wire"
        );
    }
}

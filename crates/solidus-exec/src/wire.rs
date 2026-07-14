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

/// Message that must be signed, under the given wire mode.
pub fn signing_bytes(tx: &Transaction, mode: WireMode) -> [u8; 32] {
    match mode {
        WireMode::LegacyJson => tx.signing_bytes(),
        WireMode::BinaryV2 => {
            #[allow(clippy::expect_used)]
            // TxPayload is a fixed-shape serde enum; bincode has no error
            // path on it (same reasoning as the live crate's JSON expect).
            let payload_bin = bincode::serialize(&tx.payload)
                .expect("TxPayload bincode serialization cannot fail");
            let mut buf = Vec::with_capacity(32 + 8 + payload_bin.len());
            buf.extend_from_slice(&tx.sender_pubkey);
            buf.extend_from_slice(&tx.nonce.to_le_bytes());
            buf.extend_from_slice(&payload_bin);
            blake3_hash(&buf)
        }
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
}

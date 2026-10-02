//! Committed vectors for the V3 (chain-bound) wire. Regenerate deliberately:
//!     UPDATE_VECTORS=1 cargo test -p solidus-exec --test binaryv3_vectors

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use solidus_exec::wire::{signing_preimage_v3, tx_hash_preimage_v3};
use solidus_txns::types::{Transaction, TxPayload};

fn vectors_dir() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let candidate = dir.join("test-fixtures");
        if candidate.is_dir() {
            return candidate;
        }
        dir = dir.parent().expect("test-vectors/ not found above the cwd");
    }
}

fn fixture(nonce: u64, payload: TxPayload) -> Transaction {
    Transaction {
        sender_pubkey: [0x11; 32],
        nonce,
        payload,
        signature: [0x22; 64],
    }
}

#[test]
fn binaryv3_vectors_match_the_committed_file() {
    let cases = [
        (
            "transfer-devnet",
            50_002u64,
            fixture(
                0,
                TxPayload::Transfer {
                    to: Address::from_bytes([0x33; 20]),
                    amount: 1_000_000,
                },
            ),
        ),
        (
            "transfer-other-chain",
            50_003u64,
            fixture(
                0,
                TxPayload::Transfer {
                    to: Address::from_bytes([0x33; 20]),
                    amount: 1_000_000,
                },
            ),
        ),
        (
            "revoke-high-nonce",
            50_002u64,
            fixture(
                258,
                TxPayload::CredentialRevoke {
                    credential_id: "urn:solidus:credential:00ff".into(),
                },
            ),
        ),
    ];
    let produced: Value = json!({ "version": 1, "cases": cases.iter().map(|(name, chain, tx)| {
        let sp = signing_preimage_v3(tx, *chain);
        let hp = tx_hash_preimage_v3(tx, *chain);
        json!({
            "name": name, "chainId": chain.to_string(),
            "encodedPayload": hex::encode(bincode::serialize(&tx.payload).unwrap()),
            "encodedTransaction": hex::encode(bincode::serialize(tx).unwrap()),
            "signingPreimage": hex::encode(&sp), "signingBytes": hex::encode(blake3_hash(&sp)),
            "txHashPreimage": hex::encode(&hp), "txHash": hex::encode(blake3_hash(&hp)),
        })
    }).collect::<Vec<_>>() });

    let path = vectors_dir().join("tx").join("binaryv3-v1.json");
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .expect("write");
        eprintln!("wrote {}", path.display());
        return;
    }
    let existing = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!("no vectors at {}. Generate deliberately:\n  UPDATE_VECTORS=1 cargo test -p solidus-exec --test binaryv3_vectors", path.display())
    });
    let committed: Value = serde_json::from_str(&existing).expect("valid json");
    assert_eq!(
        committed, produced,
        "binaryv3-v1.json drifted from the executor's wire"
    );
}

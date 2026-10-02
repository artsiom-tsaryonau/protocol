//! Bincode bytes of bridge payloads, for the SDK and the verify backend.
//! Regenerate deliberately: UPDATE_VECTORS=1 cargo test -p solidus-exec --test bridge_payload_vectors

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_txns::types::TxPayload;

fn path() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().unwrap();
    loop {
        let c = dir.join("test-fixtures");
        if c.is_dir() {
            return c.join("tx").join("bridge-payloads-v1.json");
        }
        dir = dir.parent().unwrap();
    }
}

#[test]
fn bridge_payload_vectors_match_the_committed_file() {
    let mut holder = [0u8; 32];
    holder[12..].copy_from_slice(&hex::decode("70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap());
    let cases = [
        (
            "export-evm",
            TxPayload::ExportCredential {
                credential_id: "urn:solidus:credential:00ff".into(),
                domain: 11_155_111,
                holder,
                valid_until: 0,
                consent_sig: vec![0xAB; 65],
                consent_expiry: 1_900_000_000,
            },
        ),
        (
            "export-valid-until",
            TxPayload::ExportCredential {
                credential_id: "urn:solidus:credential:00ff".into(),
                domain: 43_113,
                holder,
                valid_until: 1_950_000_000,
                consent_sig: vec![0xCD; 65],
                consent_expiry: 1_900_000_000,
            },
        ),
        (
            "unexport",
            TxPayload::UnexportCredential {
                credential_id: "urn:solidus:credential:00ff".into(),
                domain: 11_155_111,
                holder,
            },
        ),
    ];
    let produced = json!({ "version": 1, "cases": cases.iter().map(|(name, p)| {
        let fields = match p {
            TxPayload::ExportCredential { credential_id, domain, holder, valid_until, consent_sig, consent_expiry } => json!({
                "kind": "ExportCredential", "credentialId": credential_id, "domain": domain, "holder": hex::encode(holder),
                "validUntil": valid_until.to_string(), "consentSig": hex::encode(consent_sig), "consentExpiry": consent_expiry.to_string(),
            }),
            TxPayload::UnexportCredential { credential_id, domain, holder } => json!({
                "kind": "UnexportCredential", "credentialId": credential_id, "domain": domain, "holder": hex::encode(holder),
            }),
            _ => unreachable!(),
        };
        json!({ "name": name, "fields": fields, "payloadHex": hex::encode(bincode::serialize(p).unwrap()) })
    }).collect::<Vec<_>>() });
    let p = path();
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            &p,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .unwrap();
        return;
    }
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(&p).expect("bridge-payloads-v1.json missing"),
    )
    .unwrap();
    assert_eq!(committed, produced);
}

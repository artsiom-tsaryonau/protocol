//! Committed conformance vectors for the bridge codec.
//!
//! Same discipline as `solidus-exec/tests/binaryv2_vectors.rs`: the JSON is
//! COMMITTED, and this test holds it still. Regenerate deliberately and read
//! the diff as a wire change:
//!
//!     UPDATE_VECTORS=1 cargo test -p solidus-bridge-codec --test vectors

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_bridge_codec::*;

fn vectors_dir() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let candidate = dir.join("test-fixtures");
        if candidate.is_dir() {
            return candidate.join("bridge");
        }
        dir = dir.parent().expect("test-fixtures/ not found above the cwd");
    }
}

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn addr32(hex20: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&hex::decode(hex20).unwrap());
    out
}

const CREDENTIAL_TYPES: [&str; 11] = [
    "Email",
    "Phone",
    "KycL1",
    "KycL2",
    "KycL3",
    "Age",
    "Reputation",
    "OwnerBinding",
    "CapabilityScope",
    "SpendMandate",
    "AccreditedIssuer",
];

fn messages() -> Value {
    let body = CredentialStatusBody {
        export_id: [0x01; 32],
        issuer_did_hash: [0x02; 32],
        credential_type_hash: [0x03; 32],
        holder: [0x04; 32],
        status: ExportStatus::Active,
        valid_until: 1_900_000_000,
        issuer_accredited: true,
    };
    let cases = [
        (
            "credential-status-active",
            BridgeMessage::credential_status(1, 1234, body),
        ),
        (
            "credential-status-revoked-max",
            BridgeMessage::credential_status(
                u64::MAX,
                u64::MAX,
                CredentialStatusBody {
                    status: ExportStatus::Revoked,
                    valid_until: 0,
                    issuer_accredited: false,
                    ..body
                },
            ),
        ),
        (
            "credential-status-unbound",
            BridgeMessage::credential_status(
                3,
                99,
                CredentialStatusBody {
                    status: ExportStatus::Unbound,
                    ..body
                },
            ),
        ),
        (
            "issuer-status-not-accredited",
            BridgeMessage::issuer_status(
                2,
                1235,
                IssuerStatusBody {
                    issuer_did_hash: [0x09; 32],
                    accredited: false,
                },
            ),
        ),
        (
            "heartbeat",
            BridgeMessage::heartbeat(
                4,
                0,
                HeartbeatBody {
                    solidus_timestamp: 1_758_000_000,
                    global_root: [0xAB; 32],
                },
            ),
        ),
    ];
    let good: Vec<Value> = cases
        .iter()
        .map(|(name, m)| {
            let hd = m.header();
            let fields = match m {
                BridgeMessage::CredentialStatus { body, .. } => json!({
                    "kind": "credential_status", "domainSeq": hd.domain_seq.to_string(), "solidusHeight": hd.solidus_height.to_string(),
                    "exportId": h(&body.export_id), "issuerDidHash": h(&body.issuer_did_hash), "credentialTypeHash": h(&body.credential_type_hash),
                    "holder": h(&body.holder), "status": body.status as u8, "validUntil": body.valid_until.to_string(), "issuerAccredited": body.issuer_accredited,
                }),
                BridgeMessage::IssuerStatus { body, .. } => json!({
                    "kind": "issuer_status", "domainSeq": hd.domain_seq.to_string(), "solidusHeight": hd.solidus_height.to_string(),
                    "issuerDidHash": h(&body.issuer_did_hash), "accredited": body.accredited,
                }),
                BridgeMessage::Heartbeat { body, .. } => json!({
                    "kind": "heartbeat", "domainSeq": hd.domain_seq.to_string(), "solidusHeight": hd.solidus_height.to_string(),
                    "solidusTimestamp": body.solidus_timestamp.to_string(), "globalRoot": h(&body.global_root),
                }),
            };
            json!({ "name": name, "fields": fields, "hex": h(&encode(m)) })
        })
        .collect();

    let base = encode(&cases[0].1);
    let mut bad_version = base.clone();
    bad_version[0] = 2;
    let mut bad_kind = base.clone();
    bad_kind[1] = 9;
    let mut bad_status = base.clone();
    bad_status[146] = 5;
    let mut bad_bool = base.clone();
    bad_bool[155] = 2;
    let negative = vec![
        json!({ "name": "empty", "hex": "0x", "error": "BadLength" }),
        json!({ "name": "version-2", "hex": h(&bad_version), "error": "BadVersion" }),
        json!({ "name": "kind-9", "hex": h(&bad_kind), "error": "UnknownKind" }),
        json!({ "name": "truncated", "hex": h(&base[..155]), "error": "BadLength" }),
        json!({ "name": "status-5", "hex": h(&bad_status), "error": "BadStatus" }),
        json!({ "name": "bool-2", "hex": h(&bad_bool), "error": "BadBool" }),
    ];
    for n in &negative {
        let raw = hex::decode(n["hex"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        let err = decode(&raw).expect_err("negative vector must fail");
        let name = format!("{err:?}");
        assert!(
            name.starts_with(n["error"].as_str().unwrap()),
            "{} decoded as {name}",
            n["name"]
        );
    }
    json!({ "version": 1, "cases": good, "negative": negative })
}

fn ids() -> Value {
    let holder = addr32("70997970c51812dc3a010c7d01b50e0d17dc79c8");
    let export: Vec<Value> = [11_155_111u32, 43_113, 5_042_002]
        .iter()
        .map(|d| json!({ "credentialId": "urn:solidus:credential:00ff", "domain": d, "holder": h(&holder), "expected": h(&export_id("urn:solidus:credential:00ff", *d, &holder)) }))
        .collect();
    let issuers: Vec<Value> = ["did:solidus:testnet:verify", "did:solidus:testnet:abc", ""]
        .iter()
        .map(|d| json!({ "issuerDid": d, "expected": h(&issuer_did_hash(d)) }))
        .collect();
    let types: Vec<Value> = CREDENTIAL_TYPES
        .iter()
        .map(|t| json!({ "serdeName": t, "expected": h(&credential_type_hash(t)) }))
        .collect();
    let t = credential_type_hash("KycL2");
    let i = issuer_did_hash("did:solidus:testnet:verify");
    let gate = vec![
        json!({ "holder": h(&holder), "credentialTypeHash": h(&t), "issuerDidHash": h(&i), "expected": h(&gate_key(&holder, &t, &i)) }),
    ];
    let mut amount = [0u8; 32];
    amount[24..].copy_from_slice(&100_000_000u64.to_be_bytes());
    let token = addr32("e7f1725e7734ce288f8367e1bb143e90bb3f0512");
    let transfer = vec![
        json!({ "originDomain": 50_002, "depositNonce": "7", "recipient": h(&holder), "amount": h(&amount), "token": h(&token), "deadline": "1900000000",
                "expected": h(&transfer_id(50_002, 7, &holder, &amount, &token, 1_900_000_000)) }),
        json!({ "originDomain": 11_155_111u32, "depositNonce": "18446744073709551615", "recipient": h(&holder), "amount": h(&[0xFF; 32]), "token": h(&token), "deadline": "0",
                "expected": h(&transfer_id(11_155_111, u64::MAX, &holder, &[0xFF; 32], &token, 0)) }),
    ];
    json!({ "version": 1, "exportId": export, "issuerDidHash": issuers, "credentialTypeHash": types, "gateKey": gate, "transferId": transfer })
}

fn consent() -> Value {
    let holder = addr32("70997970c51812dc3a010c7d01b50e0d17dc79c8");
    let c = ExportConsent {
        credential_id: "urn:solidus:credential:00ff".into(),
        domain: 11_155_111,
        holder,
        consent_expiry: 1_900_000_000,
    };
    let mirror: [u8; 20] = hex::decode("5fbdb2315678afecb367f032d93f642f64180aa3")
        .unwrap()
        .try_into()
        .unwrap();
    let eip712: Vec<Value> = [11_155_111u64, 43_113, 5_042_002]
        .iter()
        .map(|chain| json!({
            "credentialId": c.credential_id, "domain": c.domain, "holder": h(&c.holder), "consentExpiry": c.consent_expiry.to_string(),
            "chainId": chain, "verifyingContract": h(&mirror), "digest": h(&eip712_consent_digest(&c, *chain, &mirror)),
        }))
        .collect();
    let program = [0x07u8; 32];
    let ed = vec![json!({
        "credentialId": c.credential_id, "domain": c.domain, "holder": h(&c.holder), "consentExpiry": c.consent_expiry.to_string(),
        "mirrorProgramId": h(&program), "bytes": h(&ed25519_consent_bytes(&c, &program)),
    })];
    json!({ "version": 1, "eip712": eip712, "ed25519": ed })
}

fn transfer_meta() -> Value {
    let cases = [
        (
            "with-referral",
            TransferMeta {
                version: 1,
                transfer_id: [0x0A; 32],
                referral_code: *b"SOLIDUS1",
                deadline: 1_900_000_000,
            },
        ),
        (
            "no-referral",
            TransferMeta {
                version: 1,
                transfer_id: [0x0B; 32],
                referral_code: [0; 8],
                deadline: 0,
            },
        ),
    ];
    let v: Vec<Value> = cases
        .iter()
        .map(|(name, m)| json!({ "name": name, "transferId": h(&m.transfer_id), "referralCode": h(&m.referral_code), "deadline": m.deadline.to_string(), "hex": h(&encode_transfer_meta(m)) }))
        .collect();
    json!({ "version": 1, "cases": v })
}

fn usdc_hook() -> Value {
    let hk = UsdcHookData {
        version: 1,
        final_recipient: addr32("70997970c51812dc3a010c7d01b50e0d17dc79c8"),
        credential_type_hash: credential_type_hash("KycL2"),
        issuer_did_hash: issuer_did_hash("did:solidus:testnet:verify"),
        refund_address: addr32("3c44cdddb6a900fa2b585dd299e03d12fa4293bc"),
        deadline: 1_900_000_000,
        referral_code: [0; 8],
    };
    json!({ "version": 1, "cases": [ {
        "name": "kycl2-gate", "finalRecipient": h(&hk.final_recipient), "credentialTypeHash": h(&hk.credential_type_hash),
        "issuerDidHash": h(&hk.issuer_did_hash), "refundAddress": h(&hk.refund_address), "deadline": hk.deadline.to_string(),
        "referralCode": h(&hk.referral_code), "hex": h(&encode_usdc_hook(&hk)),
    } ] })
}

#[test]
fn bridge_codec_vectors_match_the_committed_files() {
    let dir = vectors_dir();
    let produced = [
        ("messages-v1.json", messages()),
        ("ids-v1.json", ids()),
        ("consent-v1.json", consent()),
        ("transfer-meta-v1.json", transfer_meta()),
        ("usdc-hook-v1.json", usdc_hook()),
    ];
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(&dir).expect("mkdir");
        for (file, value) in &produced {
            std::fs::write(
                dir.join(file),
                format!("{}\n", serde_json::to_string_pretty(value).unwrap()),
            )
            .expect("write");
            eprintln!("wrote {}", dir.join(file).display());
        }
        return;
    }
    for (file, value) in &produced {
        let path = dir.join(file);
        let existing = std::fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!("no vectors at {}. Generate deliberately:\n  UPDATE_VECTORS=1 cargo test -p solidus-bridge-codec --test vectors", path.display())
        });
        let committed: Value = serde_json::from_str(&existing).expect("valid json");
        assert_eq!(
            &committed, value,
            "{file} drifted from the codec. If intended, regenerate and review the diff."
        );
    }
}

#[test]
fn ids_vectors_cover_every_credential_type_the_chain_knows() {
    use solidus_txns::credential::CredentialType::*;
    let all = [
        Email,
        Phone,
        KycL1,
        KycL2,
        KycL3,
        Age,
        Reputation,
        OwnerBinding,
        CapabilityScope,
        SpendMandate,
        AccreditedIssuer,
    ];
    for t in all {
        let name = serde_json::to_value(t)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        assert!(
            CREDENTIAL_TYPES.contains(&name.as_str()),
            "{name} is missing from ids-v1.json generation"
        );
    }
}

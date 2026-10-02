//! Conformance vectors for the v2 transaction wire format.
//!
//! ⛔ THESE EXIST BECAUSE THE SDK HAS TO REPRODUCE THEM IN TYPESCRIPT, AND A
//! HAND-ROLLED BINCODE ENCODER THAT MERELY LOOKS RIGHT IS THE SHAPE OF BUG THAT
//! SHIPS SILENTLY. v2 accepts `solidus_submitTransaction` with
//! `hex(bincode(tx))`; every product that writes to the chain has to produce
//! those exact bytes, and "I read the bincode spec" is not evidence.
//!
//! Rust is the reference implementation, so the bytes come from here. The file
//! is COMMITTED and reviewed, and this test then holds it still: regenerating on
//! every run would let a wire change rewrite its own expectations and pass.
//!
//! Regenerate deliberately, and read the diff as a wire-format change:
//!
//!     UPDATE_VECTORS=1 cargo test -p solidus-exec --test binaryv2_vectors
//!
//! ⚠ EVERY FIXTURE IS FIXED-KEY AND FIXED-NONCE ON PURPOSE. A vector built from
//! a random key is a vector nobody else can reproduce, which defeats the point
//! of handing it to a third party.

use std::path::{Path, PathBuf};

use solidus_crypto::keys::Address;
use solidus_exec::wire::{signing_bytes, tx_hash};
use solidus_exec::WireMode;
use solidus_txns::credential::CredentialType;
use solidus_txns::did::{DidPatch, GuardianApproval, RecoveryPolicy, Service};
use solidus_txns::types::{Transaction, TxPayload};

/// Walk up until `test-vectors/` appears, so this works from any cwd cargo picks.
fn vectors_dir() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let candidate = dir.join("test-vectors");
        if candidate.is_dir() {
            return candidate;
        }
        dir = dir.parent().expect("test-vectors/ not found above the cwd");
    }
}

/// A transaction with every byte pinned. No randomness, no clock.
fn fixture(nonce: u64, payload: TxPayload) -> Transaction {
    Transaction {
        sender_pubkey: [0x11; 32],
        nonce,
        payload,
        // Not a real signature: these vectors pin the ENCODING, and the encoder
        // must copy the 64 bytes through untouched whatever they are. Signature
        // verification has its own vectors.
        signature: [0x22; 64],
    }
}

fn cases() -> Vec<(&'static str, Transaction)> {
    vec![
        (
            "transfer",
            fixture(
                0,
                TxPayload::Transfer {
                    to: Address::from_bytes([0x33; 20]),
                    amount: 1_000_000,
                },
            ),
        ),
        (
            // Nonce chosen to span more than one byte, so a little-endian
            // encoder that happens to work for 0 does not pass by accident.
            "transfer-high-nonce",
            fixture(
                258,
                TxPayload::Transfer {
                    to: Address::from_bytes([0x44; 20]),
                    amount: u64::MAX,
                },
            ),
        ),
        (
            // An EMPTY Vec. bincode still writes its u64 length, so the payload
            // is eight bytes longer than "no services" suggests, and an encoder
            // that omits the prefix for an empty list passes every test that
            // only ever uses a populated one.
            "did-create-no-services",
            fixture(
                5,
                TxPayload::DidCreate {
                    public_key: [0x88; 32],
                    service_endpoints: Vec::new(),
                },
            ),
        ),
        (
            // ⛔ A Vec OF STRUCTS: length prefix, then each struct's fields in
            // declaration order with no per-element marker. Two entries, so an
            // encoder that writes the count but only one element is caught.
            "did-create-with-services",
            fixture(
                6,
                TxPayload::DidCreate {
                    public_key: [0x99; 32],
                    service_endpoints: vec![
                        Service {
                            id: "#pod".to_string(),
                            service_type: "SolidPod".to_string(),
                            service_endpoint: "https://pod.example/u/".to_string(),
                        },
                        Service {
                            id: "#hub".to_string(),
                            service_type: "LinkedDomains".to_string(),
                            service_endpoint: "https://example.test".to_string(),
                        },
                    ],
                },
            ),
        ),
        (
            // ⛔ THE ONLY WAY TO ACCREDIT AN ISSUER, AND IT HAD NO v2 ENCODING.
            // Accreditation is a `CredentialIssue` of type `AccreditedIssuer`,
            // which the chain accepts only at V2 and only through this variant
            // (its subject is an organisation's DID, published on purpose).
            // `wire-v2.ts` had no case for it and refused to guess, so every
            // bridge gate read `ISSUER_NOT_ACCREDITED` with the export present
            // and ACTIVE on the mirror. Measured on the harness 2026-09-26.
            //
            // ⚠ IT DIFFERS FROM `CredentialIssueV2` IN ONE FIELD: a
            // length-prefixed String where that one has 32 raw bytes. An encoder
            // that copied the v2 case and changed only the variant index passes
            // every other vector and fails this one.
            //
            // ⚠ `AccreditedIssuer` IS THE LAST CredentialType variant (index 10),
            // deliberately: an encoder that truncated the nested enum index to a
            // byte, or that fell back to `Email`, would be caught here.
            "credential-issue-accredited-issuer",
            fixture(
                3,
                TxPayload::CredentialIssue {
                    // A realistic DID, so the length prefix is not a round number.
                    subject_did: "did:solidus:testnet:6p61wDy9SFeM66svZhgP8QLHdgj".to_string(),
                    credential_type: CredentialType::AccreditedIssuer,
                    hash: [0x77; 32],
                },
            ),
        ),
        (
            // ⛔ THE VARIANT VERIFY WILL ACTUALLY ISSUE ON v2. It carries a
            // NESTED enum (`CredentialType`), which bincode encodes as its own
            // u32 index inline — a shape nothing else in these vectors has, and
            // one an encoder can get wrong while every flat variant passes.
            "credential-issue-v2",
            fixture(
                3,
                TxPayload::CredentialIssueV2 {
                    subject_commitment: [0x55; 32],
                    // Deliberately NOT the first variant: `Email` is index 0 and
                    // would pass under an encoder that forgets the nested index
                    // entirely.
                    credential_type: CredentialType::KycL2,
                    hash: [0x66; 32],
                },
            ),
        ),
        (
            "credential-revoke",
            fixture(
                4,
                TxPayload::CredentialRevoke {
                    // A realistic id, so the length prefix is not a round number.
                    credential_id: "urn:solidus:credential:9f2c4a".to_string(),
                },
            ),
        ),
        (
            // ⛔ WALLET'S SOCIAL RECOVERY, WHICH IS WHY THIS EXISTS. The browser
            // signs `DidUpdate{SetRecoveryPolicy}` with the user's own key, so
            // the encoding has to be right on the client side or a user cannot
            // set up recovery at all.
            //
            // ⚠ TWO NESTED ENUM INDICES, not one. `DidUpdate` is a TxPayload
            // variant AND `SetRecoveryPolicy` is a DidPatch variant, each written
            // as its own u32. An encoder that wrote only the outer index would
            // produce a patch list whose first element decodes as whatever
            // DidPatch variant 0 is, which is AddService — a completely different
            // operation on the same document.
            "did-update-set-recovery-policy",
            fixture(
                12,
                TxPayload::DidUpdate {
                    did: "did:solidus:testnet:2FDp7gH5qyb66jjsXAbFQYwLygqQ".to_string(),
                    patches: vec![DidPatch::SetRecoveryPolicy(RecoveryPolicy {
                        guardians: vec![
                            "did:solidus:testnet:guardianA".to_string(),
                            "did:solidus:testnet:guardianB".to_string(),
                        ],
                        // u8, NOT u32. bincode writes one byte here, and an
                        // encoder that assumed u32 shifts everything after it.
                        threshold: 2,
                        delay_blocks: 0,
                    })],
                },
            ),
        ),
        (
            // A patch list with MORE THAN ONE element, so a Vec length prefix
            // that happens to work for a single patch is exercised.
            "did-update-two-patches",
            fixture(
                13,
                TxPayload::DidUpdate {
                    did: "did:solidus:testnet:2FDp7gH5qyb66jjsXAbFQYwLygqQ".to_string(),
                    patches: vec![
                        DidPatch::SetController("did:solidus:testnet:controller".to_string()),
                        DidPatch::RemoveRecoveryPolicy,
                    ],
                },
            ),
        ),
        (
            // ⛔ THE OTHER HALF OF RECOVERY: rotating the key with guardian
            // approvals. `new_public_key` is a RAW [u8; 32] with no length
            // prefix, while each approval's `signature` is a Vec<u8> WITH one.
            // The same struct holds both, which is the asymmetry these vectors
            // exist to pin.
            "did-recover",
            fixture(
                14,
                TxPayload::DidRecover {
                    did: "did:solidus:testnet:2FDp7gH5qyb66jjsXAbFQYwLygqQ".to_string(),
                    new_public_key: [0x55; 32],
                    approvals: vec![
                        GuardianApproval {
                            guardian_did: "did:solidus:testnet:guardianA".to_string(),
                            signature: vec![0x66; 64],
                        },
                        GuardianApproval {
                            guardian_did: "did:solidus:testnet:guardianB".to_string(),
                            signature: vec![0x77; 64],
                        },
                    ],
                },
            ),
        ),
        (
            // An EMPTY approvals Vec. bincode still writes its u64 count, and an
            // encoder that skips the prefix when the list is empty is eight bytes
            // short while passing every populated case.
            "did-recover-no-approvals",
            fixture(
                15,
                TxPayload::DidRecover {
                    did: "did:solidus:testnet:2FDp7gH5qyb66jjsXAbFQYwLygqQ".to_string(),
                    new_public_key: [0x88; 32],
                    approvals: vec![],
                },
            ),
        ),
        (
            // ⚠ VARIANT INDEX 8, WHICH IS PAST THE SINGLE-BYTE-LOOKING RANGE.
            // bincode writes the index as a u32, so a TypeScript encoder that
            // emitted one byte would agree with Rust for every variant below 256
            // and this fixture would still catch nothing. What it DOES catch is a
            // wrong index: Stake is 8, and an encoder that counted the enum by
            // hand and missed CredentialIssueV2 would write 7 and produce a
            // CredentialRevoke.
            "stake",
            fixture(9, TxPayload::Stake { amount: 50_000_000 }),
        ),
        (
            // u64::MAX, so a JS encoder that routed the amount through a Number
            // loses precision and fails here rather than in production. 2^53 is
            // where that starts, and this is far past it.
            "stake-max-amount",
            fixture(10, TxPayload::Stake { amount: u64::MAX }),
        ),
        (
            // Adjacent to Stake, so a swapped pair is visible: the two payloads
            // are byte-identical apart from the variant index.
            "unstake",
            fixture(11, TxPayload::Unstake { amount: 1 }),
        ),
        (
            // A later enum variant, so the variant index is exercised rather
            // than assumed to be zero.
            "did-deactivate",
            fixture(
                7,
                TxPayload::DidDeactivate {
                    did: "did:solidus:2FDp7gH5qyb66jjsXAbFQYwLygqQ".to_string(),
                },
            ),
        ),
    ]
}

#[test]
fn the_v2_wire_encoding_matches_its_published_vectors() {
    let path = vectors_dir().join("tx").join("binaryv2-v1.json");

    let mut produced = serde_json::Map::new();
    for (name, tx) in cases() {
        let wire = bincode::serialize(&tx).expect("bincode");
        let mut entry = serde_json::Map::new();
        entry.insert("nonce".into(), tx.nonce.into());
        entry.insert("sender_pubkey".into(), hex::encode(tx.sender_pubkey).into());
        entry.insert("signature".into(), hex::encode(tx.signature).into());
        entry.insert(
            "payload_bincode".into(),
            hex::encode(bincode::serialize(&tx.payload).expect("bincode")).into(),
        );
        entry.insert("wire".into(), hex::encode(&wire).into());
        entry.insert(
            "signing_bytes".into(),
            hex::encode(signing_bytes(&tx, WireMode::BinaryV2)).into(),
        );
        entry.insert(
            "tx_hash".into(),
            hex::encode(tx_hash(&tx, WireMode::BinaryV2)).into(),
        );
        produced.insert(name.to_string(), entry.into());
    }
    // ⚠ THE `category` KEY IS NOT DECORATION. `solidus-vectors`' conformance
    // runner dispatches on it, and treats an unknown one as a FAILURE rather
    // than a skip — deliberately, so a vector published for third parties
    // cannot sit unchecked while the summary reports everything green.
    //
    // ⛔ THIS BRANCH LACKED THE WRAPPER AND I REGENERATED WITHOUT IT, producing a
    // flat map that would have broken the public runner. Ported from `main`,
    // which had already fixed it. Regenerating a published artefact with an
    // out-of-date generator is its own failure mode: the bytes were right and
    // the envelope was wrong.
    let mut wrapper = serde_json::Map::new();
    wrapper.insert("category".into(), "tx-wire-binaryv2".into());
    wrapper.insert("cases".into(), serde_json::Value::Object(produced));
    let produced = serde_json::Value::Object(wrapper);

    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&produced).expect("json")
            ),
        )
        .expect("write vectors");
        eprintln!("wrote {}", path.display());
        return;
    }

    let existing = std::fs::read_to_string(&path).unwrap_or_else(|_| {
        panic!(
            "no vectors at {}. Generate them deliberately and review the diff:\n  \
             UPDATE_VECTORS=1 cargo test -p solidus-exec --test binaryv2_vectors",
            path.display()
        )
    });
    let existing: serde_json::Value = serde_json::from_str(&existing).expect("vectors are json");

    assert_eq!(
        existing, produced,
        "the v2 wire encoding changed. This is a BREAKING WIRE CHANGE: every SDK \
         and every third party encoding transactions must be updated in the same \
         release. If the change is intended, regenerate with UPDATE_VECTORS=1 and \
         say so in the commit."
    );
}

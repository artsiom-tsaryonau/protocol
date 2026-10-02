//! `CredentialIssueV2` is accepted by v2, and it publishes no subject.
//!
//! The mirror of `compute_rejection.rs`. That file pins a payload the v2 chain
//! REFUSES; this one pins the payload v2 accepts and the live v1 chain refuses
//! (Rebuild #2 BD-6b). Asserted v2-only for the same reason: it is a deliberate
//! legacy↔v2 divergence, so the parity `Harness` would correctly refuse it at receipt
//! comparison.
//!
//! What is actually being proved here, and why it needs an integration test rather
//! than the unit tests in `solidus-txns`: those prove the RECORD carries no subject.
//! This proves the whole path does — dispatch, execution, state write and the emitted
//! EVENT. The event was the surface the 2026-08-20 measurement found the original plan
//! had missed entirely, and a unit test on the record cannot see it.

mod common;

use common::{sign_tx, GENESIS_TS, NETWORK};
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_reference, BlockCtx, ExecOptions, InMemoryState, StateKey, StateReader,
};
use solidus_txns::credential::{build_subject_commitment, CredentialRecord, CredentialType};
use solidus_txns::types::{Event, TxPayload, TxStatus};

/// Issuer DID registered, then one v2 issuance. Returns (state, receipts, issuer_did).
fn issue_v2(
    subject_commitment: [u8; 32],
) -> (InMemoryState, Vec<solidus_txns::types::Receipt>, String) {
    let key = generate_signing_key();
    let addr = Address::from_public_key(&key.verifying_key());

    // ⚠ DELIBERATELY UNFUNDED. `DidCreate` requires a pristine identity key (zero
    // balance, first transaction) because a DID anchor is value-free by construction
    // (a.1). Funding it first makes the anchor ineligible, which is what the executor
    // says when you try: "DidCreate requires a pristine identity key". Credential
    // issuance is fee-exempt in both executors, so a zero-balance issuer is correct
    // rather than a workaround.
    let mut state = InMemoryState::new();

    let opts = ExecOptions::legacy_anchor(
        Address::from_bytes([0xAA; 20]),
        vec![Address::from_bytes([0xB1; 20])],
    );

    // Block 1: the issuer's DID must exist and be active, because the ISSUER check
    // survives BD-6b even though the SUBJECT check does not.
    let ctx1 = BlockCtx {
        height: 1,
        timestamp_ms: GENESIS_TS + 1_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let out1 = execute_block_reference(
        &state,
        &[sign_tx(
            &key,
            0,
            TxPayload::DidCreate {
                public_key: key.verifying_key().to_bytes(),
                service_endpoints: vec![],
            },
        )],
        &ctx1,
        &opts,
    )
    .expect("block 1");
    assert_eq!(
        out1.receipts[0].status,
        TxStatus::Success,
        "issuer DID must register"
    );
    state.apply_delta(&out1.delta);

    // Block 2: the v2 issuance.
    let ctx2 = BlockCtx {
        height: 2,
        timestamp_ms: GENESIS_TS + 2_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let out2 = execute_block_reference(
        &state,
        &[sign_tx(
            &key,
            1,
            TxPayload::CredentialIssueV2 {
                subject_commitment,
                credential_type: CredentialType::KycL3,
                hash: [0x11; 32],
            },
        )],
        &ctx2,
        &opts,
    )
    .expect("block 2");
    state.apply_delta(&out2.delta);

    (
        state,
        out2.receipts,
        solidus_txns::did::build_did(NETWORK, &addr),
    )
}

#[test]
fn v2_accepts_the_payload_and_emits_no_subject() {
    let commitment = build_subject_commitment("did:solidus:testnet:alice", &[0x5a; 32]);
    let (state, receipts, issuer_did) = issue_v2(commitment);

    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "v2 must ACCEPT CredentialIssueV2: {:?}",
        receipts[0].status
    );

    // The event is the surface the original plan missed. It must be the V2 variant,
    // carrying the commitment, and it must not be the v1 event.
    let credential_id = match &receipts[0].events[..] {
        [Event::CredentialIssuedV2 {
            credential_id,
            issuer,
            subject_commitment: c,
        }] => {
            assert_eq!(
                *c, commitment,
                "the event must carry the commitment verbatim"
            );
            assert_eq!(issuer, &issuer_did);
            credential_id.clone()
        }
        other => panic!("expected exactly one CredentialIssuedV2, got {other:?}"),
    };

    // ⛔ The whole point: nothing anywhere in the emitted receipt is the subject DID.
    let receipt_json = serde_json::to_string(&receipts[0]).expect("serialize receipt");
    assert!(
        !receipt_json.contains("alice"),
        "the subject must not appear in the receipt: {receipt_json}"
    );

    // And the stored record agrees.
    let bytes = state
        .get(&StateKey::credential(&credential_id))
        .expect("state read")
        .expect("the credential must be written");
    let rec: CredentialRecord = serde_json::from_slice(&bytes).expect("decode record");
    assert!(
        rec.subject_did.is_empty(),
        "stored record must not carry a subject DID"
    );
    assert_eq!(rec.subject_commitment, Some(commitment));
}

/// CONTROL. The v1 payload on the SAME executor still publishes the subject.
///
/// Without this, `v2_accepts_the_payload_and_emits_no_subject` would pass just as well
/// against an executor that had quietly stopped recording subjects at all, or against
/// a harness whose receipts never contain anything. This shows the difference is the
/// PAYLOAD, not the machinery.
#[test]
fn control_v1_payload_on_the_same_executor_still_publishes_the_subject() {
    let key = generate_signing_key();
    let subject = generate_signing_key();
    let subject_addr = Address::from_public_key(&subject.verifying_key());

    // Unfunded for the same reason: both are DID anchors.
    let mut state = InMemoryState::new();
    let opts = ExecOptions::legacy_anchor(
        Address::from_bytes([0xAA; 20]),
        vec![Address::from_bytes([0xB1; 20])],
    );

    // Both DIDs, because the v1 path DOES check the subject.
    let ctx1 = BlockCtx {
        height: 1,
        timestamp_ms: GENESIS_TS + 1_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let out1 = execute_block_reference(
        &state,
        &[
            sign_tx(
                &key,
                0,
                TxPayload::DidCreate {
                    public_key: key.verifying_key().to_bytes(),
                    service_endpoints: vec![],
                },
            ),
            sign_tx(
                &subject,
                0,
                TxPayload::DidCreate {
                    public_key: subject.verifying_key().to_bytes(),
                    service_endpoints: vec![],
                },
            ),
        ],
        &ctx1,
        &opts,
    )
    .expect("block 1");
    state.apply_delta(&out1.delta);

    let subject_did = solidus_txns::did::build_did(NETWORK, &subject_addr);
    let ctx2 = BlockCtx {
        height: 2,
        timestamp_ms: GENESIS_TS + 2_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let out2 = execute_block_reference(
        &state,
        &[sign_tx(
            &key,
            1,
            TxPayload::CredentialIssue {
                subject_did: subject_did.clone(),
                credential_type: CredentialType::KycL3,
                hash: [0x11; 32],
            },
        )],
        &ctx2,
        &opts,
    )
    .expect("block 2");

    assert_eq!(out2.receipts[0].status, TxStatus::Success);
    let json = serde_json::to_string(&out2.receipts[0]).expect("serialize");
    assert!(
        json.contains(&subject_did),
        "v1 DOES publish the subject, so the v2 assertion is detecting the payload"
    );
}

// ---------------------------------------------------------------------------
// "Reveals nothing" asserted over the WHOLE state, not one field
// ---------------------------------------------------------------------------

/// Every state entry whose key or value mentions `needle`, rendered for the
/// failure message.
///
/// ⚠ SCANS KEYS AS WELL AS VALUES. A subject promoted into an INDEX key leaks
/// exactly as completely as one stored in a record, and a scan that only read
/// values would report that leak as clean.
fn state_entries_mentioning(state: &InMemoryState, needle: &str) -> Vec<String> {
    let n = needle.as_bytes();
    let contains = |h: &[u8]| h.len() >= n.len() && h.windows(n.len()).any(|w| w == n);
    state
        .iter()
        .filter(|(k, v)| contains(&k.key) || contains(v))
        .map(|(k, v)| {
            format!(
                "{:?}/{} = {}",
                k.space,
                hex::encode(&k.key),
                String::from_utf8_lossy(v)
            )
        })
        .collect()
}

/// v1 issuance with both DIDs anchored and every delta APPLIED, so committed
/// state really holds the credential. Split out because the state scan needs
/// committed state, and the receipt-level control above never applies its delta.
fn issue_v1_and_apply() -> (InMemoryState, String) {
    let key = generate_signing_key();
    let subject = generate_signing_key();
    let subject_addr = Address::from_public_key(&subject.verifying_key());

    let mut state = InMemoryState::new();
    let opts = ExecOptions::legacy_anchor(
        Address::from_bytes([0xAA; 20]),
        vec![Address::from_bytes([0xB1; 20])],
    );

    let out1 = execute_block_reference(
        &state,
        &[
            sign_tx(
                &key,
                0,
                TxPayload::DidCreate {
                    public_key: key.verifying_key().to_bytes(),
                    service_endpoints: vec![],
                },
            ),
            sign_tx(
                &subject,
                0,
                TxPayload::DidCreate {
                    public_key: subject.verifying_key().to_bytes(),
                    service_endpoints: vec![],
                },
            ),
        ],
        &BlockCtx {
            height: 1,
            timestamp_ms: GENESIS_TS + 1_000,
            network: NETWORK,
            parent_state_root: [0u8; 32],
        },
        &opts,
    )
    .expect("block 1");
    state.apply_delta(&out1.delta);

    let subject_did = solidus_txns::did::build_did(NETWORK, &subject_addr);
    let out2 = execute_block_reference(
        &state,
        &[sign_tx(
            &key,
            1,
            TxPayload::CredentialIssue {
                subject_did: subject_did.clone(),
                credential_type: CredentialType::KycL3,
                hash: [0x11; 32],
            },
        )],
        &BlockCtx {
            height: 2,
            timestamp_ms: GENESIS_TS + 2_000,
            network: NETWORK,
            parent_state_root: [0u8; 32],
        },
        &opts,
    )
    .expect("block 2");
    assert_eq!(out2.receipts[0].status, TxStatus::Success);
    state.apply_delta(&out2.delta);

    (state, subject_did)
}

/// ⛔ THE FIELD BEING EMPTY IS NOT THE PROPERTY. A leak that matters will not
/// politely appear in the field you are watching: it turns up in a derived id,
/// an index key, an event payload, or a field somebody adds next month "just for
/// debugging". So this asserts over EVERY entry the block wrote.
///
/// ⚠ THE V2 HALF IS WEAK ON ITS OWN, AND THE CONTROL IS WHAT MAKES IT MEAN
/// ANYTHING. A v2 payload never carries the subject at all: it is hashed into
/// the commitment before the transaction is built. So "the subject is not in
/// state" is close to true by construction, and this test would pass just as
/// happily against a scanner that finds nothing anywhere. The v1 half runs the
/// SAME scanner against a lane that really does publish the subject, so if that
/// half ever stops finding it, the v2 half is proving nothing and the failure
/// message says exactly that.
///
/// What this genuinely buys is a TRIPWIRE: the day someone adds a subject field
/// to the v2 record, an index keyed on the subject, or a debug value, it fails.
#[test]
fn v2_reveals_the_subject_in_no_state_entry_while_v1_reveals_it() {
    // ── v2 ──────────────────────────────────────────────────────────────────
    let v2_subject = "did:solidus:testnet:zSUBJECTMUSTNOTAPPEARANYWHERE";
    let commitment = build_subject_commitment(v2_subject, &[0x3c; 32]);
    let (v2_state, receipts, _issuer) = issue_v2(commitment);
    assert_eq!(receipts[0].status, TxStatus::Success);

    let leaked = state_entries_mentioning(&v2_state, v2_subject);
    assert!(
        leaked.is_empty(),
        "the v2 subject leaked into {} state entry/entries: {leaked:?}",
        leaked.len()
    );

    // And the record itself, serialised WHOLE rather than field by field.
    let credential_id = match &receipts[0].events[..] {
        [Event::CredentialIssuedV2 { credential_id, .. }] => credential_id.clone(),
        other => panic!("expected one CredentialIssuedV2, got {other:?}"),
    };
    let bytes = v2_state
        .get(&StateKey::credential(&credential_id))
        .expect("state read")
        .expect("record written");
    let rec: CredentialRecord = serde_json::from_slice(&bytes).expect("decode record");
    let blob = serde_json::to_string(&rec).expect("serialisable");
    assert!(
        !blob.contains(v2_subject),
        "subject leaked into the v2 record serialisation: {blob}"
    );
    assert!(
        rec.subject_did.is_empty(),
        "v2 must leave subject_did empty"
    );
    assert_eq!(rec.subject_commitment, Some(commitment));

    // ── CONTROL: the same scanner over v1, which DOES publish the subject ────
    let (v1_state, v1_subject_did) = issue_v1_and_apply();
    let found = state_entries_mentioning(&v1_state, &v1_subject_did);
    assert!(
        !found.is_empty(),
        "CONTROL FAILED: the scanner found the subject in NO v1 state entry, so the \
         v2 assertion above is vacuous and proves nothing"
    );
}

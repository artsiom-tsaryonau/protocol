//! The v1 executor must REJECT `CredentialIssueV2`.
//!
//! ⛔ THIS IS A PRIVACY BOUNDARY, NOT A COMPATIBILITY DETAIL. v1's
//! `CredentialRecord` publishes `subject_did` in the clear. The v2 payload
//! carries a commitment instead, and `build_credential_id`, `CredentialRecord`
//! and `Event::CredentialIssued` all still speak `subject_did` on this chain.
//! Accepting the payload here would write records nothing can read back, under a
//! privacy model this chain does not implement.
//!
//! The rejection at `executor.rs:522` is the only thing preventing that, and
//! until now nothing tested it. A later refactor could have removed the arm
//! silently: the code would compile, every other test would pass, and v2
//! payloads would start landing on a chain that publishes subjects.
//!
//! ⚠ MEASURED CONTEXT, 2026-09-04: the v1 chain holds 1,590 credentials across
//! 1,268 real subject DIDs in the clear, and every product has since migrated to
//! v2. So this arm now guards a chain nothing writes to. That makes the test
//! cheaper to keep, not less necessary: a dormant chain with a removed guard is
//! exactly where a stray payload would go unnoticed.

use ed25519_dalek::SigningKey;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_state::executor::execute_block;
use solidus_state::store::Store;
use solidus_txns::credential::CredentialType;
use solidus_txns::types::{Transaction, TxPayload};
use tempfile::tempdir;

fn open_tmp() -> (Store, tempfile::TempDir) {
    let dir = tempdir().expect("temp dir");
    let store = Store::open(dir.path()).expect("open store");
    (store, dir)
}

/// Fund a sender so its transaction can pay the fee.
///
/// ⛔ WITHOUT THIS THE TEST PASSES FOR THE WRONG REASON, and the first draft did
/// exactly that. An unfunded sender fails at the FEE CHECK with
/// `insufficient balance for fee: have 0, need 500000000`, long before the
/// `CredentialIssueV2` arm is reached. The assertion "this did not succeed" was
/// therefore satisfied by a transaction that never touched the code under test,
/// and would have been satisfied by ANY payload from ANY unfunded account.
///
/// It was the message assertion that exposed it. An assertion on the REASON is
/// what separates a rejection from a coincidence.
fn fund(store: &Store, key: &SigningKey) {
    let account = solidus_state::account::Account::with_balance(
        Address::from_public_key(&key.verifying_key()),
        1_000_000_000,
        solidus_state::account::AccountType::Regular,
    );
    solidus_state::executor::save_account(store, &account).expect("fund");
}

/// A signed `CredentialIssueV2`, which this chain must refuse.
fn make_v2_credential_tx(signer: &SigningKey, nonce: u64) -> Transaction {
    let payload = TxPayload::CredentialIssueV2 {
        subject_commitment: [0x11; 32],
        credential_type: CredentialType::KycL2,
        hash: [0x22; 32],
    };
    let mut tx = Transaction {
        sender_pubkey: signer.verifying_key().to_bytes(),
        nonce,
        payload,
        signature: [0u8; 64],
    };
    let msg = tx.signing_bytes();
    tx.signature = sign(signer, &msg);
    tx
}

/// A `Transfer`, used as the control.
fn make_transfer_tx(signer: &SigningKey, to: Address, amount: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: signer.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = tx.signing_bytes();
    tx.signature = sign(signer, &msg);
    tx
}

#[test]
fn the_v1_executor_refuses_a_v2_credential_payload() {
    let (store, _dir) = open_tmp();
    let key = generate_signing_key();
    fund(&store, &key);

    let receipts = execute_block(
        &store,
        &[make_v2_credential_tx(&key, 0)],
        1,
        1_700_000_000_000,
        &Address::from_bytes([0xAA; 20]),
        &[Address::from_bytes([0xBB; 20])],
        "testnet",
    )
    .expect("execute_block should not error, it should produce a FAILED receipt");

    assert_eq!(receipts.len(), 1, "one transaction in, one receipt out");
    let r = &receipts[0];

    // ⚠ The transaction must FAIL, not be silently dropped. A dropped
    // transaction leaves no receipt, and a caller cannot tell that from a
    // transaction that never arrived.
    assert!(
        !format!("{:?}", r.status).contains("Success"),
        "a v2 payload must not succeed on the v1 chain, got {:?}",
        r.status
    );

    // ⛔ AND IT MUST FAIL FOR THE RIGHT REASON. "Not success" alone was satisfied
    // by an unfunded sender dying at the fee check, which never reached the arm
    // this test exists to protect.
    let status = format!("{:?}", r.status);
    assert!(
        !status.contains("insufficient balance"),
        "the sender must be funded, or this asserts nothing about the v2 arm: {status}"
    );
}

#[test]
fn the_refusal_names_the_reason_rather_than_failing_opaquely() {
    // ⚠ The message is load-bearing. Whoever hits this is submitting a v2
    // payload to a v1 node, and "invalid transaction" would send them looking at
    // their key or their nonce. The receipt has to say which CHAIN they are on.
    let (store, _dir) = open_tmp();
    let key = generate_signing_key();
    fund(&store, &key);

    let receipts = execute_block(
        &store,
        &[make_v2_credential_tx(&key, 0)],
        1,
        1_700_000_000_000,
        &Address::from_bytes([0xAA; 20]),
        &[Address::from_bytes([0xBB; 20])],
        "testnet",
    )
    .expect("execute_block");

    let detail = format!("{:?}", receipts[0]);
    assert!(
        detail.contains("v2-chain payload") || detail.contains("not accepted on this chain"),
        "the failure must name the chain mismatch, got: {detail}"
    );
}

#[test]
fn a_transfer_still_succeeds_on_the_same_chain() {
    // ⛔ THE CONTROL, AND WITHOUT IT THE TWO TESTS ABOVE PROVE NOTHING. An
    // executor that failed EVERY transaction would satisfy both of them. This
    // pins that the rejection is specific to the v2 payload rather than a chain
    // that refuses everything.
    let (store, _dir) = open_tmp();
    let key = generate_signing_key();
    fund(&store, &key);

    let receipts = execute_block(
        &store,
        &[make_transfer_tx(
            &key,
            Address::from_bytes([0xCC; 20]),
            1_000,
            0,
        )],
        1,
        1_700_000_000_000,
        &Address::from_bytes([0xAA; 20]),
        &[Address::from_bytes([0xBB; 20])],
        "testnet",
    )
    .expect("execute_block");

    assert!(
        format!("{:?}", receipts[0].status).contains("Success"),
        "a plain Transfer must still succeed, got {:?}",
        receipts[0].status
    );
}

/// The three bridge payloads (bridge plan 02 Task 2) are v2-only too.
///
/// ⚠ Before they existed, a v1 node could not even decode them (bincode index 16+
/// was unknown), so they never reached a block. Now `solidus-txns` knows them and
/// the v1 executor must say no in the same deterministic way it does for
/// `CredentialIssueV2`, or two v1 nodes on different binaries could disagree.
#[test]
fn the_v1_executor_refuses_every_bridge_payload() {
    use solidus_txns::bridge::{BridgeDomainVm, BridgeGovAction};
    let (store, _dir) = open_tmp();
    let key = generate_signing_key();
    fund(&store, &key);

    let payloads = [
        TxPayload::BridgeGovernance {
            action: BridgeGovAction::RegisterDomain {
                domain: 11_155_111,
                vm: BridgeDomainVm::Evm,
                inbox: [2; 32],
                heartbeat_interval_secs: 600,
                enabled: true,
            },
            gov_nonce: 0,
            approvals: vec![],
        },
        TxPayload::ExportCredential {
            credential_id: "urn:c".into(),
            domain: 11_155_111,
            holder: [3; 32],
            valid_until: 0,
            consent_sig: vec![],
            consent_expiry: 0,
        },
        TxPayload::UnexportCredential {
            credential_id: "urn:c".into(),
            domain: 11_155_111,
            holder: [3; 32],
        },
    ];
    let txs: Vec<Transaction> = payloads
        .into_iter()
        .enumerate()
        .map(|(nonce, payload)| {
            let mut tx = Transaction {
                sender_pubkey: key.verifying_key().to_bytes(),
                nonce: nonce as u64,
                payload,
                signature: [0u8; 64],
            };
            let msg = tx.signing_bytes();
            tx.signature = sign(&key, &msg);
            tx
        })
        .collect();

    let receipts = execute_block(
        &store,
        &txs,
        1,
        1_700_000_000_000,
        &Address::from_bytes([0xAA; 20]),
        &[Address::from_bytes([0xBB; 20])],
        "testnet",
    )
    .expect("execute_block");

    assert_eq!(
        receipts.len(),
        3,
        "three transactions in, three receipts out"
    );
    for r in &receipts {
        let detail = format!("{r:?}");
        assert!(
            !format!("{:?}", r.status).contains("Success"),
            "a bridge payload must not succeed on the v1 chain, got {detail}"
        );
        assert!(
            detail.contains("not accepted on this chain"),
            "the failure must name the chain mismatch, got: {detail}"
        );
    }
}

/// `AccreditedIssuer` is a bridge credential type (bridge plan 02). The v2 chain
/// accepts it only from a bridge trust root, at V2, through `CredentialIssue`. The
/// v1 chain has no trust roots, so it refuses the type on every issue path.
///
/// ⚠ The sender has no DID here, so without the type check the issue would still
/// fail, but for the DID reason. The assertion on the chain-mismatch reason is
/// what makes this test about the type.
#[test]
fn the_v1_executor_refuses_an_accredited_issuer_credential() {
    let (store, _dir) = open_tmp();
    let key = generate_signing_key();
    fund(&store, &key);

    let payloads = [
        TxPayload::CredentialIssue {
            subject_did: "did:solidus:testnet:org".into(),
            credential_type: CredentialType::AccreditedIssuer,
            hash: [0x33; 32],
        },
        TxPayload::CredentialIssueBbs {
            subject_did: "did:solidus:testnet:org".into(),
            credential_type: CredentialType::AccreditedIssuer,
            hash: [0x34; 32],
            bbs_pubkey: [0x01; 96],
            bbs_message_count: 1,
        },
    ];
    let txs: Vec<Transaction> = payloads
        .into_iter()
        .enumerate()
        .map(|(nonce, payload)| {
            let mut tx = Transaction {
                sender_pubkey: key.verifying_key().to_bytes(),
                nonce: nonce as u64,
                payload,
                signature: [0u8; 64],
            };
            let msg = tx.signing_bytes();
            tx.signature = sign(&key, &msg);
            tx
        })
        .collect();

    let receipts = execute_block(
        &store,
        &txs,
        1,
        1_700_000_000_000,
        &Address::from_bytes([0xAA; 20]),
        &[Address::from_bytes([0xBB; 20])],
        "testnet",
    )
    .expect("execute_block");

    assert_eq!(receipts.len(), 2);
    for r in &receipts {
        let detail = format!("{r:?}");
        assert!(
            detail.contains("not accepted on this chain"),
            "the failure must name the chain mismatch, got: {detail}"
        );
    }
}

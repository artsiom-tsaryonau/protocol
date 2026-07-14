//! End-to-end integration test for DID social recovery.
//!
//! Verifies: DidCreate subject + guardians → SetRecoveryPolicy → DidRecover
//! rotates key and bumps recovery_nonce → stale approvals are rejected on replay.

use std::sync::Arc;

use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_state::account::{Account, AccountType};
use solidus_state::executor::{execute_block, load_did, save_account};
use solidus_state::store::Store;
use solidus_txns::did::{
    build_did, first_auth_key, recovery_signing_message, DidPatch, GuardianApproval, RecoveryPolicy,
};
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

const INITIAL_BALANCE: u64 = 10_000_000;
const NETWORK: &str = "testnet";

fn make_create_tx(key: &ed25519_dalek::SigningKey, nonce: u64) -> Transaction {
    let pubkey = key.verifying_key().to_bytes();
    let mut tx = Transaction {
        sender_pubkey: pubkey,
        nonce,
        payload: TxPayload::DidCreate {
            public_key: pubkey,
            service_endpoints: vec![],
        },
        signature: [0u8; 64],
    };
    tx.signature = sign(key, &tx.signing_bytes());
    tx
}

fn make_update_tx(
    key: &ed25519_dalek::SigningKey,
    nonce: u64,
    did: String,
    patches: Vec<DidPatch>,
) -> Transaction {
    let pubkey = key.verifying_key().to_bytes();
    let mut tx = Transaction {
        sender_pubkey: pubkey,
        nonce,
        payload: TxPayload::DidUpdate { did, patches },
        signature: [0u8; 64],
    };
    tx.signature = sign(key, &tx.signing_bytes());
    tx
}

fn make_recover_tx(
    new_key: &ed25519_dalek::SigningKey,
    nonce: u64,
    did: String,
    approvals: Vec<GuardianApproval>,
) -> Transaction {
    let new_pk = new_key.verifying_key().to_bytes();
    let mut tx = Transaction {
        sender_pubkey: new_pk,
        nonce,
        payload: TxPayload::DidRecover {
            did,
            new_public_key: new_pk,
            approvals,
        },
        signature: [0u8; 64],
    };
    tx.signature = sign(new_key, &tx.signing_bytes());
    tx
}

#[test]
fn recovery_rotates_key_end_to_end() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path()).expect("store"));

    let treasury = Address::from_bytes([0xAA; 20]);
    let validator = Address::from_bytes([0xBB; 20]);

    // -----------------------------------------------------------------------
    // 1. Generate keys — DIDs are created on PRISTINE identity keys (zero
    //    balance, first tx). DidCreate is fee-exempt under the value-decoupled
    //    model, so identity addresses are never funded.
    // -----------------------------------------------------------------------
    let subject_key = generate_signing_key();
    let g1_key = generate_signing_key();
    let g2_key = generate_signing_key();
    let g3_key = generate_signing_key();

    // -----------------------------------------------------------------------
    // 2. Compute DID strings
    // -----------------------------------------------------------------------
    let subject_addr = Address::from_public_key(&subject_key.verifying_key());
    let g1_addr = Address::from_public_key(&g1_key.verifying_key());
    let g2_addr = Address::from_public_key(&g2_key.verifying_key());
    let g3_addr = Address::from_public_key(&g3_key.verifying_key());

    let subject_did = build_did(NETWORK, &subject_addr);
    let g1_did = build_did(NETWORK, &g1_addr);
    let g2_did = build_did(NETWORK, &g2_addr);
    let g3_did = build_did(NETWORK, &g3_addr);

    // -----------------------------------------------------------------------
    // Block 1: DidCreate for subject + 3 guardians
    // -----------------------------------------------------------------------
    let receipts = execute_block(
        &store,
        &[
            make_create_tx(&subject_key, 0),
            make_create_tx(&g1_key, 0),
            make_create_tx(&g2_key, 0),
            make_create_tx(&g3_key, 0),
        ],
        1,
        1_700_000_000_000,
        &treasury,
        &[validator],
        NETWORK,
    )
    .expect("block 1 failed");
    assert!(
        receipts.iter().all(|r| r.status == TxStatus::Success),
        "all DidCreate must succeed: {:?}",
        receipts.iter().map(|r| &r.status).collect::<Vec<_>>()
    );

    // -----------------------------------------------------------------------
    // Block 2: DidUpdate subject — SetRecoveryPolicy(g1,g2,g3, threshold=2)
    // -----------------------------------------------------------------------
    let policy = RecoveryPolicy {
        guardians: vec![g1_did.clone(), g2_did.clone(), g3_did.clone()],
        threshold: 2,
        delay_blocks: 0,
    };
    let receipts = execute_block(
        &store,
        &[make_update_tx(
            &subject_key,
            1,
            subject_did.clone(),
            vec![DidPatch::SetRecoveryPolicy(policy)],
        )],
        2,
        1_700_000_000_000,
        &treasury,
        &[validator],
        NETWORK,
    )
    .expect("block 2 failed");
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "SetRecoveryPolicy must succeed: {:?}",
        receipts[0].status
    );

    // -----------------------------------------------------------------------
    // 3. Read recovery_nonce — must be 0 after SetRecoveryPolicy
    // -----------------------------------------------------------------------
    let subject_doc = load_did(&store, &subject_did)
        .expect("load_did failed")
        .expect("subject doc missing");
    assert_eq!(subject_doc.recovery_nonce, 0);

    // -----------------------------------------------------------------------
    // 4. Prepare new key and fund its account
    // -----------------------------------------------------------------------
    let new_key = generate_signing_key();
    let new_pk = new_key.verifying_key().to_bytes();
    let new_addr = Address::from_public_key(&new_key.verifying_key());
    let new_acct = Account::with_balance(new_addr, INITIAL_BALANCE, AccountType::Regular);
    save_account(&store, &new_acct).expect("fund new_key");

    // -----------------------------------------------------------------------
    // 5. Build guardian approvals for nonce=0
    // -----------------------------------------------------------------------
    let msg = recovery_signing_message(NETWORK, &subject_did, &new_pk, 0);
    let approvals = vec![
        GuardianApproval {
            guardian_did: g1_did.clone(),
            signature: sign(&g1_key, &msg).to_vec(),
        },
        GuardianApproval {
            guardian_did: g2_did.clone(),
            signature: sign(&g2_key, &msg).to_vec(),
        },
    ];

    // -----------------------------------------------------------------------
    // Block 3: DidRecover — sender_pubkey must equal new_public_key
    // -----------------------------------------------------------------------
    let receipts = execute_block(
        &store,
        &[make_recover_tx(
            &new_key,
            0,
            subject_did.clone(),
            approvals.clone(),
        )],
        3,
        1_700_000_000_000,
        &treasury,
        &[validator],
        NETWORK,
    )
    .expect("block 3 failed");
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "DidRecover must succeed: {:?}",
        receipts[0].status
    );

    // -----------------------------------------------------------------------
    // 6. Assert key rotated and recovery_nonce bumped to 1
    // -----------------------------------------------------------------------
    let rotated_doc = load_did(&store, &subject_did)
        .expect("load_did after recovery failed")
        .expect("subject doc missing after recovery");
    assert_eq!(
        first_auth_key(&rotated_doc),
        Some(new_pk),
        "first auth key must equal new_pk after recovery"
    );
    assert_eq!(
        rotated_doc.recovery_nonce, 1,
        "recovery_nonce must be bumped to 1"
    );

    // -----------------------------------------------------------------------
    // Block 4: replay the same approvals (signed for nonce=0, chain is now 1)
    // new_key account nonce is 1 after block 3
    // -----------------------------------------------------------------------
    let receipts = execute_block(
        &store,
        &[make_recover_tx(&new_key, 1, subject_did.clone(), approvals)],
        4,
        1_700_000_000_000,
        &treasury,
        &[validator],
        NETWORK,
    )
    .expect("block 4 failed");
    assert!(
        matches!(receipts[0].status, TxStatus::Failed(_)),
        "stale approvals must be rejected (replay): {:?}",
        receipts[0].status
    );
}

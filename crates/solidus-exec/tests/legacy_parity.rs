//! Stage-0 parity anchor: the v2 serial reference executor must be
//! **byte-identical** to the live chain's executor — receipts, all six
//! state namespaces, and the global state root — across randomized
//! multi-block streams over all 10 payloads plus the four adversarial
//! cross-lane scenarios from §5.6 of the rebuild plan.
//!
//! Scale knobs (defaults are CI-fast; the bounded fuzz run raises them):
//! - `SOLIDUS_PARITY_SEEDS`   — number of independent seeded streams (default 3)
//! - `SOLIDUS_PARITY_BLOCKS`  — blocks per stream (default 40)
//! - `SOLIDUS_PARITY_TXS`     — max txs per block (default 48)

mod common;

use common::{sign_tx, Harness, StreamGen, GENESIS_TS, NETWORK};
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType};
use solidus_txns::types::{TxPayload, TxStatus};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// Encoding pins
// ---------------------------------------------------------------------------

#[test]
fn v2_account_encoding_is_byte_identical_to_legacy() {
    for (balance, account_type, legacy_type) in [
        (
            0u64,
            AccountType::Regular,
            solidus_state::account::AccountType::Regular,
        ),
        (
            123_456_789,
            AccountType::Validator,
            solidus_state::account::AccountType::Validator,
        ),
        (
            u64::MAX,
            AccountType::Treasury,
            solidus_state::account::AccountType::Treasury,
        ),
    ] {
        let addr = Address::from_bytes([0x42; 20]);
        let v2 = Account::with_balance(addr, balance, account_type);
        let legacy = solidus_state::account::Account::with_balance(addr, balance, legacy_type);
        assert_eq!(v2.to_bytes(), legacy.to_bytes());
        // And cross-decode both ways.
        let decoded = Account::from_bytes(&legacy.to_bytes()).expect("cross decode");
        assert_eq!(decoded.balance, balance);
    }
}

// ---------------------------------------------------------------------------
// Randomized multi-block differential
// ---------------------------------------------------------------------------

#[test]
fn randomized_streams_have_zero_divergence() {
    let seeds = env_usize("SOLIDUS_PARITY_SEEDS", 3);
    let blocks = env_usize("SOLIDUS_PARITY_BLOCKS", 40);
    let max_txs = env_usize("SOLIDUS_PARITY_TXS", 48);

    let mut total_txs = 0u64;
    for seed_idx in 0..seeds {
        let seed = 0x5011_D05Fu64
            .wrapping_mul(seed_idx as u64 + 1)
            .wrapping_add(seed_idx as u64);
        let mut harness = Harness::new();
        let mut gen = StreamGen::new(seed, 48, &mut harness);

        for _ in 0..blocks {
            let txs = gen.gen_block(max_txs);
            if txs.is_empty() {
                continue;
            }
            let receipts = harness.run_block(&txs);
            gen.refresh(&harness, &receipts);
        }

        harness.assert_state_parity();
        total_txs += harness.txs_executed;
    }
    println!(
        "parity: {total_txs} transactions across {seeds} streams × {blocks} blocks — zero divergence"
    );
}

// ---------------------------------------------------------------------------
// §5.6 adversarial cross-lane scenarios (RawBlock parity vs the live chain
// here; the same scenario builders gate the two-lane executor in Stage 3)
// ---------------------------------------------------------------------------

/// (i) A sender with mixed Transfer + identity txs in one block.
#[test]
fn adversarial_mixed_sender_block() {
    let mut harness = Harness::new();
    let alice = generate_signing_key();
    let alice_addr = Address::from_public_key(&alice.verifying_key());
    harness.fund(alice_addr, solidus_txns::staking::MIN_STAKE * 2 + 1_000_000);

    let bob = Address::from_bytes([0x21; 20]);
    let carol = Address::from_bytes([0x22; 20]);

    let txs = vec![
        sign_tx(
            &alice,
            0,
            TxPayload::Transfer {
                to: bob,
                amount: 1_000,
            },
        ),
        sign_tx(
            &alice,
            1,
            TxPayload::Stake {
                amount: solidus_txns::staking::MIN_STAKE,
            },
        ),
        sign_tx(
            &alice,
            2,
            TxPayload::Transfer {
                to: carol,
                amount: 2_000,
            },
        ),
    ];
    let receipts = harness.run_block(&txs);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    harness.assert_state_parity();
}

/// (ii) A payment receiver who is an identity-lane sender — both orders.
#[test]
fn adversarial_receiver_is_identity_sender() {
    // Order A: Transfer(alice→dana) BEFORE Dana's DidCreate.
    // Raw semantics: the credit lands (dana not yet an anchor), then the
    // DidCreate fails the pristine rule (balance != 0).
    let mut harness = Harness::new();
    let alice = generate_signing_key();
    let alice_addr = Address::from_public_key(&alice.verifying_key());
    harness.fund(alice_addr, 1_000_000);
    let dana = generate_signing_key();
    let dana_addr = Address::from_public_key(&dana.verifying_key());
    let dana_pk = dana.verifying_key().to_bytes();

    let txs = vec![
        sign_tx(
            &alice,
            0,
            TxPayload::Transfer {
                to: dana_addr,
                amount: 777,
            },
        ),
        sign_tx(
            &dana,
            0,
            TxPayload::DidCreate {
                public_key: dana_pk,
                service_endpoints: vec![],
            },
        ),
    ];
    let receipts = harness.run_block(&txs);
    assert_eq!(receipts[0].status, TxStatus::Success);
    assert!(matches!(&receipts[1].status, TxStatus::Failed(r) if r.contains("pristine")));
    harness.assert_state_parity();

    // Order B: DidCreate BEFORE the transfer — the create succeeds and the
    // transfer is rejected by the anchor guard.
    let mut harness = Harness::new();
    let alice = generate_signing_key();
    let alice_addr = Address::from_public_key(&alice.verifying_key());
    harness.fund(alice_addr, 1_000_000);
    let erin = generate_signing_key();
    let erin_addr = Address::from_public_key(&erin.verifying_key());
    let erin_pk = erin.verifying_key().to_bytes();

    let txs = vec![
        sign_tx(
            &erin,
            0,
            TxPayload::DidCreate {
                public_key: erin_pk,
                service_endpoints: vec![],
            },
        ),
        sign_tx(
            &alice,
            0,
            TxPayload::Transfer {
                to: erin_addr,
                amount: 777,
            },
        ),
    ];
    let receipts = harness.run_block(&txs);
    assert_eq!(receipts[0].status, TxStatus::Success);
    assert!(matches!(&receipts[1].status, TxStatus::Failed(r) if r.contains("anchor")));
    harness.assert_state_parity();
}

/// (iii) An issuance burst from one hot issuer in a single block.
#[test]
fn adversarial_issuance_burst_single_hot_issuer() {
    let mut harness = Harness::new();

    let issuer = generate_signing_key();
    let issuer_pk = issuer.verifying_key().to_bytes();

    // Register the issuer + 40 subjects in setup blocks.
    let receipts = harness.run_block(&[sign_tx(
        &issuer,
        0,
        TxPayload::DidCreate {
            public_key: issuer_pk,
            service_endpoints: vec![],
        },
    )]);
    assert_eq!(receipts[0].status, TxStatus::Success);

    let mut subject_dids = Vec::new();
    for _ in 0..40 {
        let subject = generate_signing_key();
        let subject_addr = Address::from_public_key(&subject.verifying_key());
        let subject_pk = subject.verifying_key().to_bytes();
        let receipts = harness.run_block(&[sign_tx(
            &subject,
            0,
            TxPayload::DidCreate {
                public_key: subject_pk,
                service_endpoints: vec![],
            },
        )]);
        assert_eq!(receipts[0].status, TxStatus::Success);
        subject_dids.push(solidus_txns::did::build_did(NETWORK, &subject_addr));
    }

    // The burst: 40 sequential-nonce issues from the one issuer, one block.
    let burst: Vec<_> = subject_dids
        .iter()
        .enumerate()
        .map(|(i, subject_did)| {
            sign_tx(
                &issuer,
                1 + i as u64,
                TxPayload::CredentialIssue {
                    subject_did: subject_did.clone(),
                    credential_type: solidus_txns::credential::CredentialType::KycL1,
                    hash: [i as u8; 32],
                },
            )
        })
        .collect();
    let receipts = harness.run_block(&burst);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    harness.assert_state_parity();
}

/// (iv) Fee settlement under a wide all-payment block (rounding paths in
/// the 70/20/10 split against three validators).
#[test]
fn adversarial_fee_settlement_max_width() {
    let mut harness = Harness::new();
    let mut senders = Vec::new();
    for _ in 0..120 {
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        harness.fund(addr, 100_000);
        senders.push(key);
    }

    let txs: Vec<_> = senders
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let mut to = [0u8; 20];
            to[..8].copy_from_slice(&(i as u64).to_le_bytes());
            to[19] = 0xDD;
            sign_tx(
                key,
                0,
                TxPayload::Transfer {
                    to: Address::from_bytes(to),
                    amount: 1 + (i as u64 % 977), // odd amounts → rounding
                },
            )
        })
        .collect();

    let receipts = harness.run_block(&txs);
    assert!(receipts.iter().all(|r| r.status == TxStatus::Success));
    harness.assert_state_parity();
}

/// Timestamp determinism: the reference executor stamps DID documents from
/// the block context, so identical streams at identical heights produce
/// identical state on both executors even when wall-clock differs.
#[test]
fn did_timestamps_come_from_block_context() {
    let mut harness = Harness::new();
    let user = generate_signing_key();
    let user_addr = Address::from_public_key(&user.verifying_key());
    let user_pk = user.verifying_key().to_bytes();

    harness.run_block(&[sign_tx(
        &user,
        0,
        TxPayload::DidCreate {
            public_key: user_pk,
            service_endpoints: vec![],
        },
    )]);
    harness.assert_state_parity();

    // The document's created_ms equals the harness block timestamp exactly.
    use solidus_exec::{StateKey, StateReader};
    let did = solidus_txns::did::build_did(NETWORK, &user_addr);
    let bytes = harness
        .baseline
        .get(&StateKey::did(&did))
        .expect("read")
        .expect("did present");
    let doc = solidus_txns::did::DidDocument::from_bytes(&bytes).expect("decode");
    assert_eq!(doc.created_ms, GENESIS_TS + 1_000);
}

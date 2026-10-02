//! The v2 network does not carry the legacy chain's compute module
//! (rebuild #5): the v2 executor rejects every `Compute*` payload with a
//! normal failed receipt — fee debited, nonce advanced, account persisted —
//! never a panic (a dispatch panic would be a consensus-crash DoS one signed
//! tx away) and never a silent success. This is the one deliberate
//! legacy↔v2 divergence class, so it is asserted v2-only: the parity
//! `Harness` would (correctly) refuse it at receipt comparison.

mod common;

use common::{sign_tx, GENESIS_TS, NETWORK};
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_reference, Account, AccountType, BlockCtx, ExecOptions, InMemoryState, StateKey,
    StateReader,
};
use solidus_txns::types::{TxPayload, TxStatus};

#[test]
fn compute_payloads_fail_softly_fee_debited_nonce_advanced() {
    let key = generate_signing_key();
    let addr = Address::from_public_key(&key.verifying_key());

    let mut state = InMemoryState::new();
    let start: u64 = 1_000_000;
    state.set(
        StateKey::account(&addr),
        Account::with_balance(addr, start, AccountType::Regular).to_bytes(),
    );

    let treasury = Address::from_bytes([0xAA; 20]);
    let validators = vec![Address::from_bytes([0xB1; 20])];
    let opts = ExecOptions::legacy_anchor(treasury, validators);

    // One self-certifying and one governance-shaped payload; the executor
    // must not care which — all five variants share the grouped arm.
    let register = TxPayload::ComputeRegister {
        ed25519_pub: key.verifying_key().to_bytes(),
        x25519_pub: [7u8; 32],
        jurisdiction: "DE".to_string(),
    };
    let anchor = TxPayload::ComputeAnchor {
        merkle_root: [9u8; 32],
        batch_count: 3,
    };
    let fee_each = register.fee();
    assert_eq!(fee_each, anchor.fee());

    let txs = vec![sign_tx(&key, 0, register), sign_tx(&key, 1, anchor)];
    let ctx = BlockCtx {
        height: 1,
        timestamp_ms: GENESIS_TS + 1_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let outcome = execute_block_reference(&state, &txs, &ctx, &opts).expect("execute block 1");

    for r in &outcome.receipts {
        assert!(
            matches!(&r.status, TxStatus::Failed(reason)
                if reason.contains("not supported on this network")),
            "expected soft rejection, got {:?}",
            r.status
        );
        assert_eq!(r.fee_paid, fee_each);
    }
    state.apply_delta(&outcome.delta);

    // The nonce advanced through both rejections and the debited account was
    // persisted: a transfer at nonce 2 succeeds against the updated state.
    let to = Address::from_bytes([0xC1; 20]);
    let transfer = TxPayload::Transfer { to, amount: 1 };
    let transfer_fee = transfer.fee();
    let txs = vec![sign_tx(&key, 2, transfer)];
    let ctx = BlockCtx {
        height: 2,
        timestamp_ms: GENESIS_TS + 2_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let outcome = execute_block_reference(&state, &txs, &ctx, &opts).expect("execute block 2");
    assert_eq!(outcome.receipts[0].status, TxStatus::Success);
    state.apply_delta(&outcome.delta);

    let sender_bytes = state
        .get(&StateKey::account(&addr))
        .expect("state read")
        .expect("account exists");
    let sender = Account::from_bytes(&sender_bytes).expect("decode account");
    assert_eq!(sender.nonce, 3);
    assert_eq!(sender.balance, start - 2 * fee_each - transfer_fee - 1);
}

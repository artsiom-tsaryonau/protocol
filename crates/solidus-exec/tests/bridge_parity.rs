#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use ed25519_dalek::SigningKey;
use solidus_crypto::keys::Address;
use solidus_exec::{Account, StateKey};
use solidus_txns::credential::CredentialType;
use solidus_txns::types::TxPayload;

fn funded(chain: &mut Chain, seed: u8) -> SigningKey {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let addr = Address::from_public_key(&key.verifying_key());
    let mut account = Account::new(addr);
    account.balance = 50_000_000;
    chain
        .state
        .set(StateKey::account(&addr), account.to_bytes());
    key
}

/// `Chain::run` asserts both executors agree on receipts, writes and block events.
/// These blocks put bridge work in the serial lane beside parallel transfers.
#[test]
fn bridge_blocks_with_parallel_transfers_execute_identically_in_both_executors() {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let issuer = issuer(&mut chain, 0x51);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    let payers: Vec<SigningKey> = (0x60..0x66).map(|s| funded(&mut chain, s)).collect();

    let (key, holder) = evm_holder();
    let exp = chain.ts_ms / 1000 + 3_600;
    let mut block = vec![chain.tx(
        &issuer.key,
        export_payload(
            &credential,
            SEPOLIA,
            holder,
            evm_consent(&key, &credential, SEPOLIA, holder, exp),
            exp,
        ),
    )];
    block.extend(payers.iter().map(|p| {
        chain.tx(
            p,
            TxPayload::Transfer {
                to: Address::from_bytes([0xEE; 20]),
                amount: 1_000,
            },
        )
    }));
    let out = chain.run(block);
    assert!(
        out.receipts.iter().all(succeeded),
        "{:?}",
        out.receipts.iter().map(failure).collect::<Vec<_>>()
    );

    chain.advance_secs(600);
    let mut block = vec![chain.tx(
        &issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: credential.clone(),
        },
    )];
    block.extend(payers.iter().map(|p| {
        chain.tx(
            p,
            TxPayload::Transfer {
                to: Address::from_bytes([0xEF; 20]),
                amount: 1_000,
            },
        )
    }));
    let out = chain.run(block);
    assert!(out.receipts.iter().all(succeeded));
    assert!(
        !out.block_events.is_empty(),
        "the interval elapsed, so this block also carries a heartbeat"
    );
}

//! End-to-end integration test for staking operations.
//!
//! Verifies the full staking pipeline:
//!   fund account -> send Stake tx -> execute block ->
//!   query via solidus_getValidatorStake RPC -> assert active=true, staked=MIN_STAKE

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

use solidus_consensus::mempool::Mempool;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_rpc::server::start_rpc_server;
use solidus_state::account::{Account, AccountType};
use solidus_state::executor::{execute_block, save_account};
use solidus_state::store::Store;
use solidus_txns::staking::MIN_STAKE;
use solidus_txns::types::{Transaction, TxPayload, TxStatus, FEE_STAKE};

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

/// Build a signed Stake transaction.
fn make_stake_tx(
    sender_key: &ed25519_dalek::SigningKey,
    amount: u64,
    nonce: u64,
) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::Stake { amount };

    let mut tx = Transaction {
        sender_pubkey: pubkey,
        nonce,
        payload,
        signature: [0u8; 64],
    };

    let msg = tx.signing_bytes();
    tx.signature = sign(sender_key, &msg);
    tx
}

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stake_and_query_via_rpc() {
    // -----------------------------------------------------------------------
    // 1. Open temp store, create mempool and latest_height tracker
    // -----------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    // -----------------------------------------------------------------------
    // 2. Fund the validator account with 200K SOLID (in smallest units)
    //
    //    MIN_STAKE = 100_000_000_000 (1000 SOLID)
    //    We fund with 2 * MIN_STAKE + FEE_STAKE to cover: stake amount + fee.
    // -----------------------------------------------------------------------
    let validator_key = generate_signing_key();
    let validator_addr = Address::from_public_key(&validator_key.verifying_key());

    let initial_balance = MIN_STAKE * 2 + FEE_STAKE;
    {
        let account = Account::with_balance(validator_addr, initial_balance, AccountType::Regular);
        save_account(&store, &account).expect("fund validator failed");
    }

    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let block_validator_addr = Address::from_bytes([0xBB; 20]);

    // -----------------------------------------------------------------------
    // 3. Start RPC server on a random port
    // -----------------------------------------------------------------------
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_handle, local_addr) = start_rpc_server(
        listen_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
    )
    .await
    .expect("failed to start RPC server");

    assert_ne!(local_addr.port(), 0, "should bind to a real port");

    // -----------------------------------------------------------------------
    // 4. Stake MIN_STAKE via execute_block (block 1)
    // -----------------------------------------------------------------------
    let tx_stake = make_stake_tx(&validator_key, MIN_STAKE, 0);
    let receipts = execute_block(
        &store,
        &[tx_stake],
        1,
        &treasury_addr,
        &[block_validator_addr],
    )
    .expect("execute_block (stake) failed");

    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "Stake should succeed; got: {:?}",
        receipts[0].status
    );
    assert_eq!(receipts[0].fee_paid, FEE_STAKE);

    *latest_height.lock().unwrap() = 1;

    // -----------------------------------------------------------------------
    // 5. Query via RPC solidus_getValidatorStake
    // -----------------------------------------------------------------------
    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let result: Option<serde_json::Value> = client
        .request(
            "solidus_getValidatorStake",
            rpc_params![validator_addr.to_base58()],
        )
        .await
        .expect("solidus_getValidatorStake failed");

    let info = result.expect("validator should be found via RPC");

    // -----------------------------------------------------------------------
    // 6. Assert: active=true, staked=MIN_STAKE
    // -----------------------------------------------------------------------
    assert_eq!(
        info["active"], true,
        "validator should be active after staking"
    );
    assert_eq!(
        info["staked"],
        MIN_STAKE,
        "staked amount should equal MIN_STAKE"
    );
    assert_eq!(
        info["unbonding"], 0,
        "unbonding should be zero (no unstake yet)"
    );
    assert_eq!(
        info["address"],
        validator_addr.to_base58(),
        "address should match"
    );

    // -----------------------------------------------------------------------
    // 7. Verify solidus_getValidators also returns the active validator
    // -----------------------------------------------------------------------
    let validators: Vec<serde_json::Value> = client
        .request("solidus_getValidators", rpc_params![])
        .await
        .expect("solidus_getValidators failed");

    assert!(
        !validators.is_empty(),
        "should have at least one active validator"
    );
    let found = validators
        .iter()
        .any(|v| v["address"] == validator_addr.to_base58());
    assert!(found, "our validator should appear in get_validators result");

    // Graceful shutdown.
    server_handle.stop().expect("server should stop");
}

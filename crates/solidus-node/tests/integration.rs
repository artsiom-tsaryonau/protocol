//! End-to-end integration test for solidus-node.
//!
//! Verifies the full pipeline:
//!   submit Transfer via JSON-RPC -> proposer produces block -> balances update -> receipt queryable

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;

use solidus_consensus::mempool::Mempool;
use solidus_consensus::proposer::{Proposer, ProposerConfig};
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_rpc::server::start_rpc_server;
use solidus_rpc::types::{RpcBlock, RpcReceipt};
use solidus_state::account::{Account, AccountType};
use solidus_state::executor::save_account;
use solidus_state::store::Store;
use solidus_txns::types::{Transaction, TxPayload, FEE_TRANSFER};

/// Helper: build a signed Transfer transaction.
fn make_transfer_tx(
    sender_key: &ed25519_dalek::SigningKey,
    to: Address,
    amount: u64,
    nonce: u64,
) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::Transfer { to, amount };

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

#[tokio::test]
async fn transfer_via_rpc_updates_balance() {
    // -----------------------------------------------------------------------
    // 1. Setup
    // -----------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    // Create a funded sender.
    let sender_key = generate_signing_key();
    let sender_addr = Address::from_public_key(&sender_key.verifying_key());
    let initial_balance: u64 = 10_000_000;
    {
        let account = Account::with_balance(sender_addr, initial_balance, AccountType::Regular);
        save_account(&store, &account).expect("fund sender failed");
    }

    // Define auxiliary addresses.
    let recipient_addr = Address::from_bytes([0xCC; 20]);
    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let validator_addr = Address::from_bytes([0xBB; 20]);

    // Shared state.
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    // -----------------------------------------------------------------------
    // 2. Start RPC server (port 0 = OS picks a free port)
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
    // 3. Build and sign a Transfer transaction
    // -----------------------------------------------------------------------
    let transfer_amount: u64 = 1_000_000;
    let tx = make_transfer_tx(&sender_key, recipient_addr, transfer_amount, 0);
    let tx_json = serde_json::to_string(&tx).expect("tx serialization failed");

    // -----------------------------------------------------------------------
    // 4. Submit via RPC
    // -----------------------------------------------------------------------
    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let tx_hash: String = client
        .request("solidus_sendTransaction", rpc_params![tx_json])
        .await
        .expect("solidus_sendTransaction failed");

    assert!(!tx_hash.is_empty(), "tx_hash should be non-empty");
    assert_eq!(tx_hash.len(), 64, "tx_hash should be 64 hex chars (32 bytes)");

    // -----------------------------------------------------------------------
    // 5. Run proposer once
    // -----------------------------------------------------------------------
    let config = ProposerConfig {
        block_time_ms: 1000,
        max_block_txs: 100,
        treasury_address: treasury_addr,
        validator_addresses: vec![validator_addr],
        network: "testnet".to_string(),
    };

    let mut proposer = Proposer::new(
        Arc::clone(&store),
        Arc::clone(&mempool),
        config,
        0,           // genesis_height
        [0u8; 32],   // genesis_hash
    );

    let result = proposer
        .propose_block()
        .expect("propose_block failed")
        .expect("expected a block to be produced");

    let (block, receipts) = result;
    assert_eq!(block.header.height, 1);
    assert_eq!(block.header.tx_count, 1);
    assert_eq!(receipts.len(), 1);

    // Update the shared latest_height so RPC queries work.
    *latest_height.lock().unwrap() = 1;

    // -----------------------------------------------------------------------
    // 6. Verify via RPC
    // -----------------------------------------------------------------------

    // 6a. Sender balance: initial - transfer - fee
    let expected_sender_balance = initial_balance - transfer_amount - FEE_TRANSFER;
    let sender_balance: u64 = client
        .request("solidus_getBalance", rpc_params![sender_addr.to_base58()])
        .await
        .expect("solidus_getBalance(sender) failed");
    assert_eq!(
        sender_balance, expected_sender_balance,
        "sender balance should be {expected_sender_balance}, got {sender_balance}"
    );

    // 6b. Recipient balance: exactly the transfer amount
    let recipient_balance: u64 = client
        .request("solidus_getBalance", rpc_params![recipient_addr.to_base58()])
        .await
        .expect("solidus_getBalance(recipient) failed");
    assert_eq!(
        recipient_balance, transfer_amount,
        "recipient balance should be {transfer_amount}, got {recipient_balance}"
    );

    // 6c. Receipt should exist with status "success"
    let receipt: Option<RpcReceipt> = client
        .request("solidus_getReceipt", rpc_params![tx_hash.clone()])
        .await
        .expect("solidus_getReceipt failed");
    let receipt = receipt.expect("receipt should exist");
    assert_eq!(receipt.status, "success");
    assert_eq!(receipt.block_height, 1);
    assert_eq!(receipt.fee_paid, FEE_TRANSFER);

    // 6d. Block at height 1 should exist with 1 transaction
    let rpc_block: Option<RpcBlock> = client
        .request("solidus_getBlock", rpc_params![1u64])
        .await
        .expect("solidus_getBlock failed");
    let rpc_block = rpc_block.expect("block at height 1 should exist");
    assert_eq!(rpc_block.height, 1);
    assert_eq!(rpc_block.tx_count, 1);
    assert_eq!(rpc_block.transactions.len(), 1);

    // -----------------------------------------------------------------------
    // 7. Cleanup
    // -----------------------------------------------------------------------
    server_handle.stop().expect("failed to stop RPC server");
}

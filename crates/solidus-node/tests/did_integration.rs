//! End-to-end integration test for DID operations.
//!
//! Verifies the full DID pipeline:
//!   build DidCreate transaction -> execute block directly -> DID stored in
//!   state -> resolve via solidus_didResolve JSON-RPC -> W3C-compliant document

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
use solidus_txns::did::build_did;
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

/// Helper: build a signed DidCreate transaction.
fn make_did_create_tx(sender_key: &ed25519_dalek::SigningKey, nonce: u64) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::DidCreate {
        public_key: pubkey,
        service_endpoints: vec![],
    };

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
async fn create_did_and_resolve_via_rpc() {
    // -----------------------------------------------------------------------
    // 1. Open temp store, create mempool, latest_height tracker
    // -----------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    // -----------------------------------------------------------------------
    // 2. Fund an account (10M SOLID)
    // -----------------------------------------------------------------------
    let sender_key = generate_signing_key();
    let sender_addr = Address::from_public_key(&sender_key.verifying_key());
    let initial_balance: u64 = 10_000_000;
    {
        let account = Account::with_balance(sender_addr, initial_balance, AccountType::Regular);
        save_account(&store, &account).expect("fund sender failed");
    }

    // Auxiliary addresses for fee distribution.
    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let validator_addr = Address::from_bytes([0xBB; 20]);

    // -----------------------------------------------------------------------
    // 3. Start RPC server on port 0
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
    // 4. Build DidCreate transaction, sign it
    // -----------------------------------------------------------------------
    let tx = make_did_create_tx(&sender_key, 0);

    // Compute the expected DID string before executing the block.
    let did_str = build_did("testnet", &sender_addr);

    // -----------------------------------------------------------------------
    // 5. Execute block directly (simulates proposer)
    // -----------------------------------------------------------------------
    let receipts = execute_block(
        &store,
        &[tx],
        1,
        &treasury_addr,
        &[validator_addr],
    )
    .expect("execute_block failed");

    // Update the shared latest_height so RPC queries work.
    *latest_height.lock().unwrap() = 1;

    // -----------------------------------------------------------------------
    // 6. Verify receipt is Success
    // -----------------------------------------------------------------------
    assert_eq!(receipts.len(), 1, "expected exactly one receipt");
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "DidCreate should succeed; got: {:?}",
        receipts[0].status,
    );

    // -----------------------------------------------------------------------
    // 7. Resolve DID via RPC call (solidus_didResolve)
    // -----------------------------------------------------------------------
    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let result: Option<serde_json::Value> = client
        .request("solidus_didResolve", rpc_params![did_str.clone()])
        .await
        .expect("solidus_didResolve failed");

    // -----------------------------------------------------------------------
    // 8. Verify: id matches, active=true, W3C context, has verificationMethod
    // -----------------------------------------------------------------------
    let doc = result.expect("DID document should be present after creation");

    assert_eq!(doc["id"], did_str, "DID id mismatch");
    assert_eq!(doc["active"], true, "DID should be active");
    assert_eq!(
        doc["context"],
        "https://www.w3.org/ns/did/v1",
        "DID context should be W3C DID v1"
    );

    // The RPC struct field is `verification_method` (snake_case, no rename).
    let vm_array = doc["verification_method"]
        .as_array()
        .expect("verification_method should be an array");
    assert!(
        !vm_array.is_empty(),
        "verification_method should have at least one entry"
    );

    // -----------------------------------------------------------------------
    // 9. Stop RPC server
    // -----------------------------------------------------------------------
    server_handle.stop().expect("failed to stop RPC server");
}

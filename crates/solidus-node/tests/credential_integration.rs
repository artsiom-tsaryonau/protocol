//! End-to-end integration test for credential operations.
//!
//! Verifies the full credential pipeline:
//!   create issuer DID -> create subject DID -> issue CredentialIssue tx ->
//!   execute block -> verify via solidus_credentialVerify RPC ->
//!   query via solidus_credentialsBySubject RPC

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
use solidus_txns::credential::CredentialType;
use solidus_txns::did::build_did;
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a signed DidCreate transaction.
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

/// Build a signed CredentialIssue transaction.
fn make_credential_issue_tx(
    sender_key: &ed25519_dalek::SigningKey,
    subject_did: String,
    credential_type: CredentialType,
    hash: [u8; 32],
    nonce: u64,
) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::CredentialIssue {
        subject_did,
        credential_type,
        hash,
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

// ---------------------------------------------------------------------------
// Test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn issue_credential_and_verify_via_rpc() {
    // -----------------------------------------------------------------------
    // 1. Open temp store, create mempool and latest_height tracker
    // -----------------------------------------------------------------------
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    // -----------------------------------------------------------------------
    // 2. Fund two accounts (issuer and subject)
    // -----------------------------------------------------------------------
    let issuer_key = generate_signing_key();
    let subject_key = generate_signing_key();

    let issuer_addr = Address::from_public_key(&issuer_key.verifying_key());
    let subject_addr = Address::from_public_key(&subject_key.verifying_key());

    {
        // Issuer needs: DID create fee (100_000) + Email credential fee (1_000_000)
        let issuer_account = Account::with_balance(issuer_addr, 10_000_000, AccountType::Regular);
        save_account(&store, &issuer_account).expect("fund issuer failed");

        // Subject needs: DID create fee (100_000)
        let subject_account = Account::with_balance(subject_addr, 1_000_000, AccountType::Regular);
        save_account(&store, &subject_account).expect("fund subject failed");
    }

    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let validator_addr = Address::from_bytes([0xBB; 20]);

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
    // 4. Create issuer DID (block 1)
    // -----------------------------------------------------------------------
    let tx_issuer_did = make_did_create_tx(&issuer_key, 0);
    let receipts = execute_block(&store, &[tx_issuer_did], 1, &treasury_addr, &[validator_addr], "testnet")
        .expect("issuer DidCreate execute_block failed");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "issuer DidCreate should succeed; got: {:?}",
        receipts[0].status
    );
    *latest_height.lock().unwrap() = 1;

    // -----------------------------------------------------------------------
    // 5. Create subject DID (block 2)
    // -----------------------------------------------------------------------
    let tx_subject_did = make_did_create_tx(&subject_key, 0);
    let receipts = execute_block(&store, &[tx_subject_did], 2, &treasury_addr, &[validator_addr], "testnet")
        .expect("subject DidCreate execute_block failed");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "subject DidCreate should succeed; got: {:?}",
        receipts[0].status
    );
    *latest_height.lock().unwrap() = 2;

    // -----------------------------------------------------------------------
    // 6. Issue credential (block 3)
    // -----------------------------------------------------------------------
    let subject_did = build_did("testnet", &subject_addr);
    let issuer_did = build_did("testnet", &issuer_addr);
    let credential_hash = [0xdeu8; 32];

    let tx_issue = make_credential_issue_tx(
        &issuer_key,
        subject_did.clone(),
        CredentialType::Email,
        credential_hash,
        1, // issuer nonce=1 (after DidCreate)
    );

    let receipts = execute_block(&store, &[tx_issue], 3, &treasury_addr, &[validator_addr], "testnet")
        .expect("CredentialIssue execute_block failed");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "CredentialIssue should succeed; got: {:?}",
        receipts[0].status
    );
    *latest_height.lock().unwrap() = 3;

    // Extract credential ID from receipt event.
    let credential_id = match &receipts[0].events[0] {
        solidus_txns::types::Event::CredentialIssued { credential_id, .. } => credential_id.clone(),
        other => panic!("expected CredentialIssued event, got: {:?}", other),
    };

    // -----------------------------------------------------------------------
    // 7. Verify via RPC solidus_credentialVerify
    // -----------------------------------------------------------------------
    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let verify_result: Option<serde_json::Value> = client
        .request("solidus_credentialVerify", rpc_params![credential_id.clone()])
        .await
        .expect("solidus_credentialVerify failed");

    let verify = verify_result.expect("credential should be found via RPC");
    assert_eq!(verify["valid"], true, "credential should be valid");
    assert_eq!(verify["revoked"], false, "credential should not be revoked");

    let rpc_cred = &verify["credential"];
    assert_eq!(rpc_cred["id"], credential_id, "credential id should match");
    assert_eq!(rpc_cred["issuer_did"], issuer_did, "issuer_did should match");
    assert_eq!(rpc_cred["subject_did"], subject_did, "subject_did should match");
    assert_eq!(rpc_cred["credential_type"], "Email", "credential_type should be Email");

    // -----------------------------------------------------------------------
    // 8. Query via RPC solidus_credentialsBySubject
    // -----------------------------------------------------------------------
    let by_subject_result: Vec<serde_json::Value> = client
        .request("solidus_credentialsBySubject", rpc_params![subject_did.clone()])
        .await
        .expect("solidus_credentialsBySubject failed");

    assert_eq!(
        by_subject_result.len(),
        1,
        "should have exactly one credential for this subject"
    );
    assert_eq!(by_subject_result[0]["id"], credential_id, "credential id should match");
    assert_eq!(by_subject_result[0]["revoked"], false, "credential should not be revoked");

    // -----------------------------------------------------------------------
    // 9. Query via RPC solidus_credentialsByIssuer
    // -----------------------------------------------------------------------
    let by_issuer_result: Vec<serde_json::Value> = client
        .request("solidus_credentialsByIssuer", rpc_params![issuer_did.clone()])
        .await
        .expect("solidus_credentialsByIssuer failed");

    assert_eq!(
        by_issuer_result.len(),
        1,
        "should have exactly one credential for this issuer"
    );
    assert_eq!(by_issuer_result[0]["id"], credential_id, "credential id should match");

    // -----------------------------------------------------------------------
    // 10. Stop RPC server
    // -----------------------------------------------------------------------
    server_handle.stop().expect("failed to stop RPC server");
}

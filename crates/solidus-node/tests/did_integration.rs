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
use solidus_rpc::methods::ChainMeta;
use solidus_rpc::server::start_rpc_server;
use solidus_state::executor::execute_block;
use solidus_state::store::Store;
use solidus_txns::did::{build_did, DidPatch};
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
    // 2. Generate a pristine identity key (no funding — DidCreate is fee-exempt)
    // -----------------------------------------------------------------------
    let sender_key = generate_signing_key();
    let sender_addr = Address::from_public_key(&sender_key.verifying_key());

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
        Arc::new(Vec::new()),
        ChainMeta::default(),
        None,
        std::sync::Arc::new(tokio::sync::Notify::new()),
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
        1_700_000_000_000,
        &treasury_addr,
        &[validator_addr],
        "testnet",
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
        doc["@context"], "https://www.w3.org/ns/did/v1",
        "DID Core spells the context property `@context`"
    );

    // ⚠ CHANGED 2026-08-25: the RPC struct now carries `rename_all = "camelCase"`, so this is
    // `verificationMethod`. The old spelling was not a style choice — DID Core defines the JSON
    // property names, and this is an END-TO-END assertion that the rename reached the wire.
    let vm_array = doc["verificationMethod"]
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

/// Gap-7 integration test: after `DidCreate`, the resolved document
/// surfaces a `version_id` field that is a 64-character hex string,
/// confirming end-to-end visibility of the resolution metadata via
/// JSON-RPC.
#[tokio::test]
async fn version_id_visible_via_rpc() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    let sender_key = generate_signing_key();
    let sender_addr = Address::from_public_key(&sender_key.verifying_key());

    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let validator_addr = Address::from_bytes([0xBB; 20]);

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_handle, local_addr) = start_rpc_server(
        listen_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::new(Vec::new()),
        ChainMeta::default(),
        None,
        std::sync::Arc::new(tokio::sync::Notify::new()),
    )
    .await
    .expect("failed to start RPC server");

    let tx = make_did_create_tx(&sender_key, 0);
    let did_str = build_did("testnet", &sender_addr);

    let receipts = execute_block(
        &store,
        &[tx],
        1,
        1_700_000_000_000,
        &treasury_addr,
        &[validator_addr],
        "testnet",
    )
    .expect("execute_block failed");
    *latest_height.lock().unwrap() = 1;
    assert_eq!(receipts[0].status, TxStatus::Success);

    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let result: Option<serde_json::Value> = client
        .request("solidus_didResolve", rpc_params![did_str.clone()])
        .await
        .expect("solidus_didResolve failed");
    let doc = result.expect("DID document should be present after creation");

    // ⚠ BACK TO `version_id` 2026-08-25, and the flip-flop is the finding. A blanket
    // `rename_all = "camelCase"` briefly renamed this to `versionId`. `versionId` is not a DID Core
    // property — it is our own extension — so renaming it bought no conformance and broke every
    // published SDK that reads it. Only the DID Core names are camelCase now.
    let version_id = doc["version_id"]
        .as_str()
        .expect("version_id must be a string");
    assert_eq!(
        version_id.len(),
        64,
        "version_id must be a 64-char hex string, got: {version_id}"
    );
    assert!(
        version_id.chars().all(|c| c.is_ascii_hexdigit()),
        "version_id must be valid hex: {version_id}"
    );

    server_handle.stop().expect("failed to stop RPC server");
}

/// Helper: build a signed DidUpdate transaction.
fn make_did_update_tx(
    sender_key: &ed25519_dalek::SigningKey,
    nonce: u64,
    did: String,
    patches: Vec<DidPatch>,
) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::DidUpdate { did, patches };

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

/// Helper: build a signed DidDeactivate transaction.
fn make_did_deactivate_tx(
    sender_key: &ed25519_dalek::SigningKey,
    nonce: u64,
    did: String,
) -> Transaction {
    let pubkey = sender_key.verifying_key().to_bytes();
    let payload = TxPayload::DidDeactivate { did };

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

/// Gap-6 integration test: full controller-handover lifecycle.
///
/// 1. Alice creates DID-A.
/// 2. Bob creates DID-B.
/// 3. Alice issues `DidUpdate { patches: [SetController(B)] }` on A.
/// 4. Resolving A surfaces `controller == B`.
/// 5. Bob, the new controller, issues `DidDeactivate(A)` — it succeeds
///    because the chain re-checks authority against the post-handover
///    controller field.
/// 6. Resolving A again confirms `active == false`.
#[tokio::test]
async fn controller_handover_then_new_owner_can_deactivate() {
    let dir = tempfile::tempdir().expect("failed to create temp dir");
    let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height = Arc::new(Mutex::new(0u64));

    // Alice and Bob are pristine DID anchors (no funding — DidCreate fee-exempt).
    let alice_key = generate_signing_key();
    let alice_addr = Address::from_public_key(&alice_key.verifying_key());
    let bob_key = generate_signing_key();
    let bob_addr = Address::from_public_key(&bob_key.verifying_key());

    let treasury_addr = Address::from_bytes([0xAA; 20]);
    let validator_addr = Address::from_bytes([0xBB; 20]);

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (server_handle, local_addr) = start_rpc_server(
        listen_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::new(Vec::new()),
        ChainMeta::default(),
        None,
        std::sync::Arc::new(tokio::sync::Notify::new()),
    )
    .await
    .expect("failed to start RPC server");

    let did_a = build_did("testnet", &alice_addr);
    let did_b = build_did("testnet", &bob_addr);

    // Block 1: both DidCreate transactions in the same block. The
    // executor processes them in order, so `did_a` is in state before
    // `did_b` lands; either ordering is fine because neither references
    // the other yet.
    let create_a = make_did_create_tx(&alice_key, 0);
    let create_b = make_did_create_tx(&bob_key, 0);
    let receipts = execute_block(
        &store,
        &[create_a, create_b],
        1,
        1_700_000_000_000,
        &treasury_addr,
        &[validator_addr],
        "testnet",
    )
    .expect("execute_block (creates) failed");
    *latest_height.lock().unwrap() = 1;
    assert_eq!(receipts.len(), 2);
    for r in &receipts {
        assert_eq!(r.status, TxStatus::Success, "creates must both succeed");
    }

    // Block 2: Alice hands DID-A's controller over to Bob.
    let handover_tx = make_did_update_tx(
        &alice_key,
        1,
        did_a.clone(),
        vec![DidPatch::SetController(did_b.clone())],
    );
    let receipts = execute_block(
        &store,
        &[handover_tx],
        2,
        1_700_000_000_000,
        &treasury_addr,
        &[validator_addr],
        "testnet",
    )
    .expect("execute_block (handover) failed");
    *latest_height.lock().unwrap() = 2;
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "SetController must succeed; got: {:?}",
        receipts[0].status,
    );

    // Resolve A and confirm controller == B.
    let url = format!("http://{local_addr}");
    let client = HttpClientBuilder::default()
        .build(&url)
        .expect("failed to build HTTP client");

    let resolved: Option<serde_json::Value> = client
        .request("solidus_didResolve", rpc_params![did_a.clone()])
        .await
        .expect("solidus_didResolve failed");
    let doc = resolved.expect("DID-A should still resolve after handover");
    assert_eq!(
        doc["controller"], did_b,
        "post-handover controller should be DID-B; got: {}",
        doc["controller"],
    );

    // Block 3: Bob (the new controller) deactivates DID-A.
    let deactivate_tx = make_did_deactivate_tx(&bob_key, 1, did_a.clone());
    let receipts = execute_block(
        &store,
        &[deactivate_tx],
        3,
        1_700_000_000_000,
        &treasury_addr,
        &[validator_addr],
        "testnet",
    )
    .expect("execute_block (deactivate) failed");
    *latest_height.lock().unwrap() = 3;
    assert_eq!(
        receipts[0].status,
        TxStatus::Success,
        "new controller must be authorised to deactivate; got: {:?}",
        receipts[0].status,
    );

    // Resolve A and confirm active == false.
    let resolved: Option<serde_json::Value> = client
        .request("solidus_didResolve", rpc_params![did_a.clone()])
        .await
        .expect("solidus_didResolve failed");
    let doc = resolved.expect("DID-A should still resolve (deactivated, not deleted)");
    assert_eq!(
        doc["active"], false,
        "post-handover deactivation should set active=false",
    );

    server_handle.stop().expect("failed to stop RPC server");
}

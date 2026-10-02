//! The `jsonrpsee` HTTP binding: registers the [`crate::methods`] handlers
//! under the `solidus_` namespace and serves them. This is the only async
//! / transport code in the crate; all logic lives in the pure handlers.

use std::net::SocketAddr;
use std::sync::Arc;

use jsonrpsee::server::{RpcModule, Server, ServerHandle};
use jsonrpsee::types::error::ErrorObjectOwned;
use serde_json::Value;

use crate::backend::RpcBackend;
use crate::methods::{self, RpcError};

type Ctx = Arc<dyn RpcBackend>;

fn to_rpc_error(e: RpcError) -> ErrorObjectOwned {
    let code = match e {
        RpcError::InvalidParams(_) => -32602,
        RpcError::NotFound => -32004,
        RpcError::SubmitRejected(_) => -32003,
        // Its own code: a caller must be able to tell "this node refuses" from
        // "no such thing", which is why it is not folded into NotFound.
        RpcError::PolicyDisabled(_) => -32005,
        RpcError::NoEvidenceYet => -32006,
        RpcError::StateAdvancing => -32007,
    };
    ErrorObjectOwned::owned(code, e.to_string(), None::<()>)
}

/// Build the RPC module (registered methods) over a backend. Separated
/// from [`serve`] so it can be tested without binding a socket.
pub fn build_module(backend: Ctx) -> RpcModule<Ctx> {
    let mut module = RpcModule::new(backend);

    macro_rules! register {
        ($name:literal, $handler:path) => {
            module
                .register_method($name, |params, ctx, _| {
                    let value: Value = params.parse().unwrap_or(Value::Null);
                    $handler(ctx.as_ref(), &value).map_err(to_rpc_error)
                })
                .expect("method name is unique");
        };
    }

    register!("solidus_getBalance", methods::get_balance);
    register!("solidus_getNonce", methods::get_nonce);
    register!("solidus_getBlockHeight", methods::get_block_height);
    register!("solidus_getStateRoot", methods::get_state_root);
    register!("solidus_getReceipt", methods::get_receipt);
    register!("solidus_submitTransaction", methods::submit_transaction);
    // Phase 2: v1-compatible names the estate already calls.
    register!("solidus_canonHead", methods::canon_head);
    register!("solidus_blockNumber", methods::block_number);
    register!("solidus_chainInfo", methods::chain_info);
    register!("solidus_getBlock", methods::get_block);
    register!("solidus_getLatestBlock", methods::get_latest_block);
    register!("solidus_didResolve", methods::did_resolve);
    register!("solidus_credentialVerify", methods::credential_verify);
    register!("solidus_getValidators", methods::get_validators);
    register!("solidus_getValidatorStake", methods::get_validator_stake);
    register!(
        "solidus_credentialsBySubject",
        methods::credentials_by_subject
    );
    register!(
        "solidus_credentialsByCommitment",
        methods::credentials_by_commitment
    );
    register!(
        "solidus_credentialsByIssuer",
        methods::credentials_by_issuer
    );
    register!("solidus_bbsVerifyProof", methods::bbs_verify_proof);
    register!("solidus_nodeInfo", methods::node_info);
    register!("solidus_getTransaction", methods::get_transaction);
    register!("solidus_getBlockBySeq", methods::get_block_by_seq);
    register!(
        "solidus_bbsVerifyCredentialProof",
        methods::bbs_verify_credential_proof
    );
    register!("solidus_getBridgeDomains", methods::get_bridge_domains);
    register!("solidus_getBridgeMessages", methods::get_bridge_messages);
    register!(
        "solidus_getBridgeAttestation",
        methods::get_bridge_attestation
    );
    register!("solidus_getExports", methods::get_exports);
    register!(
        "solidus_getLatestCommittedHeight",
        methods::get_latest_committed_height
    );
    register!("solidus_getStateProof", methods::get_state_proof);
    register!("solidus_getCommittee", methods::get_committee);
    register!(
        "solidus_getFinalityEvidence",
        methods::get_finality_evidence
    );

    module
}

/// Bind and start the JSON-RPC server. Returns the bound address (useful
/// when `addr` used port 0) and the handle (drop or `.stop()` to shut
/// down).
pub async fn serve(
    addr: SocketAddr,
    backend: Ctx,
) -> Result<(SocketAddr, ServerHandle), std::io::Error> {
    let server = Server::builder().build(addr).await?;
    let bound = server.local_addr()?;
    let handle = server.start(build_module(backend));
    Ok((bound, handle))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use jsonrpsee::core::client::ClientT;
    use jsonrpsee::http_client::HttpClientBuilder;
    use jsonrpsee::rpc_params;
    use solidus_crypto::ed25519::{generate_signing_key, sign};
    use solidus_crypto::keys::Address;
    use solidus_exec::{Account, AccountType, StateKey, WireMode};
    use solidus_store2::{Profile, Store2};
    use solidus_txns::types::{Transaction, TxPayload};

    use super::*;
    use crate::backend::Store2Backend;

    /// End-to-end: a real Store2-backed backend behind a live HTTP server,
    /// queried by a real HTTP client. Proves the whole edge, not just the
    /// handlers.
    /// ⛔ THE ONE CHECK HANDLER TESTS STRUCTURALLY CANNOT MAKE. Every method in
    /// `methods.rs` is tested by calling it directly, which proves the handler
    /// is correct and proves NOTHING about whether it is reachable. A method
    /// registered under a typo, or implemented and never registered, passes
    /// every one of those tests while being invisible over JSON-RPC.
    ///
    /// So this pins the EXACT registered surface. It fails on a typo, on a
    /// forgotten registration, and on a method added without being declared
    /// here - the last of which is the point: adding to the wire surface should
    /// be a deliberate edit, not a side effect.
    ///
    /// ⚠ `solidus_sendTransaction` IS DELIBERATELY ABSENT. v1 and v2 use
    /// different transaction wire formats, so a v1-format transaction fails at
    /// decode whatever name it arrives under. Registering it would look
    /// migrated while breaking every caller, so its absence is asserted rather
    /// The committee fallback: a chain that is visibly producing must not report
    /// zero validators just because nobody has staked on-chain.
    ///
    /// ⛔ THIS IS THE DEFECT IT PINS, MEASURED 2026-09-07. `solidus_getValidators`
    /// returned `[]` while four validators produced a block every ~116ms, because
    /// genesis seeds accounts only and a v2 validator has no address anywhere:
    /// the config gives it a BLS pubkey and an index. The explorer rendered that
    /// faithfully as "ACTIVE VALIDATORS 0 · 0 of 0 active", which read as a broken
    /// explorer and was in fact a truthful answer to the wrong question.
    ///
    /// ⚠ Asserts the UNION, not just the fallback. An on-chain row must win over
    /// the derived committee entry for the same address, or a real staking record
    /// would be shadowed by a display placeholder once staking ships.
    #[test]
    fn validators_falls_back_to_the_live_committee_and_dedupes() {
        use solidus_crypto::keys::Address;
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store2::open(dir.path(), Profile::Testnet).expect("store"));
        let anchor = Arc::new(Mutex::new((0u64, [0u8; 32])));

        let staked_addr = Address::from_bytes([1u8; 20]);
        let committee_only = Address::from_bytes([2u8; 20]);

        // One genuinely staked, on-chain validator, ALSO in the committee.
        let on_chain = solidus_txns::staking::ValidatorInfo {
            address: staked_addr,
            staked: 500,
            unbonding: 0,
            unbonding_start_ms: None,
            reputation: 900,
            active: true,
        };
        store
            .seed_state(&StateKey::validator(&staked_addr), &on_chain.to_bytes())
            .expect("seed validator");

        let backend = Store2Backend::new(
            Arc::clone(&store),
            anchor,
            "committee-test".to_string(),
            [0u8; 32],
            50_002,
            vec![staked_addr, committee_only],
            |_h| None,
            |_x| None,
            |_tx| Err("unused".to_string()),
        );

        let got = RpcBackend::validators(&backend);
        assert_eq!(got.len(), 2, "one staked + one committee-only, deduped");

        let staked = got
            .iter()
            .find(|v| v.address == staked_addr)
            .expect("staked validator present");
        assert_eq!(
            staked.staked, 500,
            "the ON-CHAIN row must win; a derived committee entry must not shadow real stake"
        );

        let derived = got
            .iter()
            .find(|v| v.address == committee_only)
            .expect("committee-only validator present");
        assert!(derived.active, "a live voter is active");
        assert_eq!(
            derived.staked, 0,
            "committee entries report zero stake, which is the truth, not an invented number"
        );
    }

    /// Bridge plan 02 Task 14. The method tests use a stub backend, so they
    /// would pass with `Store2Backend::state_value` left at the trait's "not
    /// served" default. This reads bridge records through the real store.
    #[test]
    fn bridge_records_are_read_through_the_real_store() {
        use solidus_exec::StateKey;
        use solidus_txns::bridge::{BridgeDomain, BridgeDomainVm};

        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store2::open(dir.path(), Profile::Testnet).expect("store"));
        let domain = BridgeDomain {
            domain: 11_155_111,
            vm: BridgeDomainVm::Evm,
            inbox: [2; 32],
            heartbeat_interval_secs: 600,
            enabled: true,
        };
        store
            .seed_state(
                &StateKey::bridge_domains_index(),
                &bincode::serialize(&vec![11_155_111u32]).expect("encode"),
            )
            .expect("seed index");
        store
            .seed_state(
                &StateKey::bridge_domain(11_155_111),
                &bincode::serialize(&domain).expect("encode"),
            )
            .expect("seed domain");
        let backend: Ctx = Arc::new(Store2Backend::new(
            store,
            Arc::new(Mutex::new((0u64, [0u8; 32]))),
            "v2-bridge-read-test".to_string(),
            [0u8; 32],
            50_002,
            Vec::new(),
            |_height| None,
            |_hash| None,
            |_tx| Err("not used".to_string()),
        ));

        let v = methods::get_bridge_domains(&*backend, &serde_json::json!({})).expect("domains");
        assert_eq!(v["domains"][0]["domain"], 11_155_111);
        assert_eq!(v["domains"][0]["enabled"], true);
    }

    /// than merely tolerated.
    #[test]
    fn the_registered_method_surface_is_exactly_this() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store2::open(dir.path(), Profile::Testnet).expect("store"));
        let anchor = Arc::new(Mutex::new((0u64, [0u8; 32])));
        let backend: Ctx = Arc::new(Store2Backend::new(
            store,
            anchor,
            "v2-surface-test".to_string(),
            [0u8; 32],
            50_002,
            Vec::new(), // no committee: this test asserts the method SURFACE, not their answers
            |_height| None,
            |_hash| None,
            |_tx| Err("not used".to_string()),
        ));

        let module = build_module(backend);
        let mut got: Vec<&str> = module.method_names().collect();
        got.sort_unstable();

        let expected = vec![
            "solidus_bbsVerifyCredentialProof",
            "solidus_bbsVerifyProof",
            "solidus_blockNumber",
            "solidus_canonHead",
            "solidus_chainInfo",
            "solidus_credentialVerify",
            // Added deliberately 2026-09-03: the holder's own-credential lookup,
            // ungated because presenting a commitment is itself the proof.
            "solidus_credentialsByCommitment",
            "solidus_credentialsByIssuer",
            "solidus_credentialsBySubject",
            "solidus_didResolve",
            "solidus_getBalance",
            "solidus_getBlock",
            "solidus_getBlockBySeq",
            "solidus_getBlockHeight",
            // Added deliberately 2026-09-22 (bridge plan 02 Task 14): bridge
            // records the chain already holds in the Credentials tree, plus the
            // committed height a relayer waits on.
            // Added deliberately 2026-09-26 (bridge plan 11 Task 4): this node's own
            // attestation signatures, which a gateway collects from each validator.
            "solidus_getBridgeAttestation",
            "solidus_getBridgeDomains",
            "solidus_getBridgeMessages",
            // Added deliberately 2026-09-22 (bridge plan 02 Task 15): the
            // committee with proofs of possession, which a light client needs.
            "solidus_getCommittee",
            "solidus_getExports",
            // Added deliberately 2026-09-22 (bridge plan 02 Task 16): HotStuff-2
            // commit evidence assembled from stored blocks.
            "solidus_getFinalityEvidence",
            "solidus_getLatestBlock",
            "solidus_getLatestCommittedHeight",
            "solidus_getNonce",
            "solidus_getReceipt",
            // Added deliberately 2026-09-22 (bridge plan 02 Task 15): inclusion
            // proofs at the latest executed height only.
            "solidus_getStateProof",
            "solidus_getStateRoot",
            "solidus_getTransaction",
            "solidus_getValidatorStake",
            "solidus_getValidators",
            "solidus_nodeInfo",
            "solidus_submitTransaction",
        ];
        assert_eq!(
            got, expected,
            "the registered surface changed. If a method was ADDED, add it here \
             deliberately. If one is MISSING, it is unreachable over JSON-RPC no \
             matter how well its handler tests pass."
        );

        assert!(
            !got.contains(&"solidus_sendTransaction"),
            "sendTransaction must NOT be registered: v1 and v2 use different \
             transaction wire formats, so registering it would look migrated \
             while breaking every caller"
        );
    }

    #[tokio::test]
    async fn live_server_serves_reads_and_submit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(Store2::open(dir.path(), Profile::Testnet).expect("store"));

        // Seed one funded account into committed state.
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        let acct = Account::with_balance(addr, 5_000_000, AccountType::Regular);
        store
            .seed_state(&StateKey::account(&addr), &acct.to_bytes())
            .expect("seed");

        let anchor = Arc::new(Mutex::new((7u64, [0x42u8; 32])));
        let submitted = Arc::new(Mutex::new(Vec::<Transaction>::new()));
        let sink = Arc::clone(&submitted);
        let backend: Ctx = Arc::new(Store2Backend::new(
            Arc::clone(&store),
            Arc::clone(&anchor),
            "v2-rpc-test".to_string(),
            [0xCD; 32],
            50_002,
            Vec::new(), // no committee: this test covers reads and submit
            // This live-server test covers reads and submit, not block or tx serving.
            |_height| None,
            |_hash| None,
            move |tx| {
                let hash = solidus_exec::wire::tx_hash(&tx, WireMode::BinaryV2);
                sink.lock().expect("lock").push(tx);
                Ok(hash)
            },
        ));

        let (bound, handle) = serve("127.0.0.1:0".parse().unwrap(), backend)
            .await
            .expect("serve");
        let url = format!("http://{bound}");
        let client = HttpClientBuilder::default().build(&url).expect("client");

        // Reads.
        let balance: String = client
            .request("solidus_getBalance", rpc_params![addr.to_base58()])
            .await
            .expect("balance");
        assert_eq!(balance, "5000000");

        let height: u64 = client
            .request("solidus_getBlockHeight", rpc_params![])
            .await
            .expect("height");
        assert_eq!(height, 7);

        let root: String = client
            .request("solidus_getStateRoot", rpc_params![])
            .await
            .expect("root");
        assert_eq!(root, hex::encode([0x42u8; 32]));

        // Submit a genuine signed transfer.
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([9; 20]),
                amount: 1_000,
            },
            signature: [0u8; 64],
        };
        let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
        tx.signature = sign(&key, &msg);
        let hex_tx = hex::encode(bincode::serialize(&tx).unwrap());

        let returned_hash: String = client
            .request("solidus_submitTransaction", rpc_params![hex_tx])
            .await
            .expect("submit");
        assert_eq!(
            returned_hash,
            hex::encode(solidus_exec::wire::tx_hash(&tx, WireMode::BinaryV2))
        );
        assert_eq!(
            submitted.lock().expect("lock").len(),
            1,
            "tx reached the sink"
        );

        // A tampered (bad-signature) submit is rejected at the edge.
        let mut bad = tx.clone();
        bad.signature[0] ^= 0xFF;
        let bad_hex = hex::encode(bincode::serialize(&bad).unwrap());
        let err: Result<String, _> = client
            .request("solidus_submitTransaction", rpc_params![bad_hex])
            .await;
        assert!(err.is_err(), "bad-signature submit must be rejected");
        assert_eq!(
            submitted.lock().expect("lock").len(),
            1,
            "rejected tx never reached the sink"
        );

        handle.stop().expect("stop");
    }
}

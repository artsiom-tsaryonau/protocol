//! Stage-6 acceptance: identity precompiles answer through REAL EVM
//! execution (revm transact to the precompile addresses) against
//! L1 state produced by the REAL v2 executor, with roots delivered
//! through the subnet interface. Plus a bounded input fuzzer over the
//! proof-verifying decoder (never panics; mutations never verify).

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solidus_crypto::bbs::BbsSecretKey;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_evm::precompiles::{
    verify_bbs_disclosure, ADDR_IS_DID_ACTIVE, ADDR_VERIFY_BBS_DISCLOSURE, ADDR_VERIFY_CREDENTIAL,
};
use solidus_evm::subnet::precompile_address;
use solidus_evm::{bool_word, EvmSubnet, InputBuilder};
use solidus_exec::{
    execute_block_reference, BlockCtx, ExecOptions, InMemoryState, StateKey, StateReader, WireMode,
};
use solidus_state_tree::{StateForest, TreeId};
use solidus_subnet::{L1FinalizedRoots, Subnet};
use solidus_txns::credential::CredentialRecord;
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

const NETWORK: &str = "v2-evm-test";

fn sign_v2(key: &ed25519_dalek::SigningKey, nonce: u64, payload: TxPayload) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload,
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
    tx.signature = sign(key, &msg);
    tx
}

/// Run the REAL executor to produce: issuer DID + subject DID + one BBS
/// credential. Returns the baseline state, forest, and identifiers.
struct L1World {
    baseline: InMemoryState,
    forest: StateForest,
    issuer_did: String,
    credential_id: String,
    record_bytes: Vec<u8>,
    bbs_sk: BbsSecretKey,
    messages: Vec<Vec<u8>>,
}

fn build_l1_world() -> L1World {
    let mut baseline = InMemoryState::new();
    let opts = ExecOptions::v2_defaults(50_002);

    let issuer = generate_signing_key();
    let subject = generate_signing_key();
    let issuer_addr = Address::from_public_key(&issuer.verifying_key());
    let subject_addr = Address::from_public_key(&subject.verifying_key());
    let issuer_pk = issuer.verifying_key().to_bytes();
    let subject_pk = subject.verifying_key().to_bytes();

    let bbs_sk = BbsSecretKey::from_ikm(b"evm-e2e-bbs-ikm-32-bytes-or-more!!!!").expect("ikm");
    let bbs_pubkey = bbs_sk.public_key().to_bytes();
    let messages: Vec<Vec<u8>> = vec![
        b"name=Ada Lovelace".to_vec(),
        b"dob=1815-12-10".to_vec(),
        b"country=UK".to_vec(),
        b"kyc_level=2".to_vec(),
    ];

    let subject_did = solidus_txns::did::build_did(NETWORK, &subject_addr);
    let txs = vec![
        sign_v2(
            &issuer,
            0,
            TxPayload::DidCreate {
                public_key: issuer_pk,
                service_endpoints: vec![],
            },
        ),
        sign_v2(
            &subject,
            0,
            TxPayload::DidCreate {
                public_key: subject_pk,
                service_endpoints: vec![],
            },
        ),
        sign_v2(
            &issuer,
            1,
            TxPayload::CredentialIssueBbs {
                subject_did: subject_did.clone(),
                credential_type: solidus_txns::credential::CredentialType::KycL2,
                hash: [0xAB; 32],
                bbs_pubkey,
                bbs_message_count: messages.len() as u32,
            },
        ),
    ];

    let ctx = BlockCtx {
        height: 1,
        timestamp_ms: 1_700_000_001_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    };
    let outcome = execute_block_reference(&baseline, &txs, &ctx, &opts).expect("execute");
    assert!(outcome
        .receipts
        .iter()
        .all(|r| r.status == TxStatus::Success));
    let credential_id = outcome
        .receipts
        .iter()
        .flat_map(|r| r.events.iter())
        .find_map(|e| match e {
            solidus_txns::types::Event::CredentialIssued { credential_id, .. } => {
                Some(credential_id.clone())
            }
            _ => None,
        })
        .expect("credential issued");
    baseline.apply_delta(&outcome.delta);

    let mut forest = StateForest::new();
    baseline.seed_forest(&mut forest);

    let record_bytes = baseline
        .get(&StateKey::credential(&credential_id))
        .expect("read")
        .expect("record present");

    L1World {
        baseline,
        forest,
        issuer_did: solidus_txns::did::build_did(NETWORK, &issuer_addr),
        credential_id,
        record_bytes,
        bbs_sk,
        messages,
    }
}

fn bridged_subnet(world: &L1World) -> EvmSubnet {
    let mut subnet = EvmSubnet::new(7);
    subnet
        .on_l1_finalized(L1FinalizedRoots {
            l1_height: 1,
            global_root: world.forest.global_root(),
            accounts_root: world.forest.subtree_root(TreeId::Accounts),
            dids_root: world.forest.subtree_root(TreeId::Dids),
            credentials_root: world.forest.subtree_root(TreeId::Credentials),
            validators_root: world.forest.subtree_root(TreeId::Validators),
            commit_qc: vec![], // runtime-verified upstream; not re-checked by the subnet
        })
        .expect("roots");
    subnet
}

#[test]
fn precompiles_answer_through_real_evm_execution() {
    let world = build_l1_world();
    let mut subnet = bridged_subnet(&world);

    // ---- isDidActive over the issuer DID -----------------------------
    let did_bytes = world.issuer_did.as_bytes();
    let doc_bytes = world
        .baseline
        .get(&StateKey::did(&world.issuer_did))
        .expect("read")
        .expect("doc");
    let dids_root = world.forest.subtree_root(TreeId::Dids);
    let proof = world.forest.prove(TreeId::Dids, did_bytes).expect("leaf");
    let input = InputBuilder::new(&dids_root)
        .field(did_bytes)
        .field(&doc_bytes)
        .field(&bincode::serialize(&proof).expect("proof"))
        .build();
    let out = subnet
        .call(precompile_address(ADDR_IS_DID_ACTIVE), input)
        .expect("evm call");
    assert_eq!(out, bool_word(true).to_vec(), "issuer DID is active");

    // ---- verifyCredential (true; then wrong issuer → false) ----------
    let creds_root = world.forest.subtree_root(TreeId::Credentials);
    let cred_proof = world
        .forest
        .prove(TreeId::Credentials, world.credential_id.as_bytes())
        .expect("leaf");
    let cred_proof_bytes = bincode::serialize(&cred_proof).expect("proof");

    let input = InputBuilder::new(&creds_root)
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(world.issuer_did.as_bytes())
        .field(&cred_proof_bytes)
        .build();
    let out = subnet
        .call(precompile_address(ADDR_VERIFY_CREDENTIAL), input)
        .expect("evm call");
    assert_eq!(out, bool_word(true).to_vec());

    let input = InputBuilder::new(&creds_root)
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(b"did:solidus:v2:impostor")
        .field(&cred_proof_bytes)
        .build();
    let out = subnet
        .call(precompile_address(ADDR_VERIFY_CREDENTIAL), input)
        .expect("evm call");
    assert_eq!(out, bool_word(false).to_vec(), "impostor issuer → false");

    // ---- verifyBbsDisclosure (selective disclosure of 2 of 4) --------
    let record = CredentialRecord::from_bytes(&world.record_bytes).expect("decode");
    let bbs_pk = world.bbs_sk.public_key();
    assert_eq!(record.bbs_pubkey, Some(bbs_pk.to_bytes()));

    let header = b"solidus-credential-v1";
    let msg_refs: Vec<&[u8]> = world.messages.iter().map(|m| m.as_slice()).collect();
    let sig = world.bbs_sk.sign(header, &msg_refs).expect("sign");
    let ph = b"verifier-nonce-123";
    let disclosed = [0usize, 3]; // name + kyc_level
    let bbs_proof = sig
        .create_proof(&bbs_pk, header, ph, &msg_refs, &disclosed)
        .expect("proof");

    let mut builder = InputBuilder::new(&creds_root)
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(&cred_proof_bytes)
        .field(header)
        .field(ph)
        .u32(disclosed.len() as u32);
    for &i in &disclosed {
        builder = builder.u32(i as u32).field(&world.messages[i]);
    }
    let input = builder.field(&bbs_proof.to_bytes()).build();
    let out = subnet
        .call(precompile_address(ADDR_VERIFY_BBS_DISCLOSURE), input)
        .expect("evm call");
    assert_eq!(out, bool_word(true).to_vec(), "genuine disclosure verifies");

    // Tampered disclosed message → false (proof no longer matches).
    let mut builder = InputBuilder::new(&creds_root)
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(&cred_proof_bytes)
        .field(header)
        .field(ph)
        .u32(disclosed.len() as u32);
    builder = builder.u32(0).field(b"name=Forged Name");
    builder = builder.u32(3).field(&world.messages[3]);
    let input = builder.field(&bbs_proof.to_bytes()).build();
    let out = subnet
        .call(precompile_address(ADDR_VERIFY_BBS_DISCLOSURE), input)
        .expect("evm call");
    assert_eq!(out, bool_word(false).to_vec(), "forged attribute → false");

    // ---- Stale root → precompile error (revert), not false -----------
    let input = InputBuilder::new(&[9u8; 32])
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(world.issuer_did.as_bytes())
        .field(&cred_proof_bytes)
        .build();
    assert!(
        subnet
            .call(precompile_address(ADDR_VERIFY_CREDENTIAL), input)
            .is_err(),
        "wrong claimed root must revert, not return false"
    );
}

#[test]
fn fuzzed_inputs_never_panic_and_never_verify() {
    let world = build_l1_world();
    let creds_root = world.forest.subtree_root(TreeId::Credentials);
    let cred_proof = world
        .forest
        .prove(TreeId::Credentials, world.credential_id.as_bytes())
        .expect("leaf");
    let valid_input = InputBuilder::new(&creds_root)
        .field(world.credential_id.as_bytes())
        .field(&world.record_bytes)
        .field(&bincode::serialize(&cred_proof).expect("proof"))
        .field(b"header")
        .field(b"ph")
        .u32(0)
        .field(&[0u8; 80])
        .build();

    let mut rng = StdRng::seed_from_u64(0xF022);
    let mut rejected = 0u32;
    for _ in 0..5_000 {
        let mut mutated = valid_input.clone();
        match rng.gen_range(0u32..4) {
            0 => {
                // random truncation
                let cut = rng.gen_range(0..mutated.len());
                mutated.truncate(cut);
            }
            1 => {
                // random bit flips
                for _ in 0..rng.gen_range(1..=8) {
                    let i = rng.gen_range(0..mutated.len());
                    mutated[i] ^= 1 << rng.gen_range(0..8);
                }
            }
            2 => {
                // random splice of garbage
                let at = rng.gen_range(0..=mutated.len());
                let garbage: Vec<u8> = (0..rng.gen_range(1..64)).map(|_| rng.gen()).collect();
                mutated.splice(at..at, garbage);
            }
            _ => {
                // length-field lies: overwrite a random aligned u32 with a huge value
                if mutated.len() > 40 {
                    let at = 32 + 4 * rng.gen_range(0..(mutated.len() - 36) / 4);
                    mutated[at..at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
                }
            }
        }
        // Must never panic; a mutated input must never produce `true`.
        match verify_bbs_disclosure(&creds_root, &mutated) {
            Ok(word) => assert_ne!(word, bool_word(true), "mutation must not verify"),
            Err(_) => rejected += 1,
        }
    }
    println!("fuzz: 5000 mutations, {rejected} rejected as malformed, 0 panics, 0 false-verifies");
    assert!(
        rejected > 4_000,
        "mutations should overwhelmingly be rejected"
    );
}

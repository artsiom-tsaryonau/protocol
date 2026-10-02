//! Stage-6 acceptance bench: each identity precompile must answer in
//! <50ms. Local measurement (name the hardware when publishing). The
//! heavy one is BBS+ proof verification (pairing-based); DID/credential
//! checks are BLAKE3 Merkle walks + JSON decode.

use criterion::{criterion_group, criterion_main, Criterion};
use solidus_crypto::bbs::BbsSecretKey;
use solidus_evm::precompiles::{is_did_active, verify_bbs_disclosure, verify_credential};
use solidus_evm::InputBuilder;
use solidus_state_tree::{StateForest, TreeId};
use solidus_txns::credential::{CredentialRecord, CredentialType};

fn did_doc_bytes(active: bool) -> Vec<u8> {
    // A DidDocument leaf exactly as the executor stores it.
    let doc = solidus_txns::did::build_did_document(
        "did:solidus:v2:bench",
        &hex::encode([7u8; 32]),
        vec![],
        1_000,
    );
    let mut doc = doc;
    doc.active = active;
    doc.to_bytes()
}

fn bench_precompiles(c: &mut Criterion) {
    // ---- DID tree with one active DID --------------------------------
    let mut forest = StateForest::new();
    let did = b"did:solidus:v2:bench".to_vec();
    let doc = did_doc_bytes(true);
    forest.apply(TreeId::Dids, &did, &doc);
    for i in 0..1_000u32 {
        forest.apply(TreeId::Dids, format!("did:pad:{i}").as_bytes(), b"x");
    }
    let dids_root = forest.subtree_root(TreeId::Dids);
    let did_proof = forest.prove(TreeId::Dids, &did).expect("leaf");

    let did_input = InputBuilder::new(&dids_root)
        .field(&did)
        .field(&doc)
        .field(&bincode::serialize(&did_proof).expect("proof"))
        .build();
    c.bench_function("precompile_is_did_active", |b| {
        b.iter(|| is_did_active(&dids_root, &did_input).expect("ok"))
    });

    // ---- Credential tree with a BBS credential -----------------------
    let bbs_sk = BbsSecretKey::from_ikm(b"evm-bench-bbs-ikm-32-bytes-or-more!!").expect("ikm");
    let bbs_pk = bbs_sk.public_key();
    let messages: Vec<&[u8]> = vec![b"name=Ada", b"dob=1815", b"country=UK", b"kyc=L2"];
    let header = b"solidus-bbs-header";
    let sig = bbs_sk.sign(header, &messages).expect("sign");
    let ph = b"presentation-nonce";
    let disclosed = [1usize, 3];
    let proof = sig
        .create_proof(&bbs_pk, header, ph, &messages, &disclosed)
        .expect("proof");

    let record = CredentialRecord {
        id: "urn:solidus:credential:bench".to_string(),
        issuer_did: "did:solidus:v2:issuer".to_string(),
        subject_did: "did:solidus:v2:subject".to_string(),
        // v1 shape: the subject is PUBLISHED above, so there is no commitment to it.
        // `subject_commitment` is the BD-6b (v2) field and is `None` for a v1 record.
        subject_commitment: None,
        credential_type: CredentialType::KycL2,
        hash: [9u8; 32],
        issued_ms: 1_000,
        revoked: false,
        revoked_ms: None,
        bbs_pubkey: Some(bbs_pk.to_bytes()),
        bbs_message_count: Some(messages.len() as u32),
    };
    let record_bytes = record.to_bytes();
    forest.apply(TreeId::Credentials, record.id.as_bytes(), &record_bytes);
    let creds_root = forest.subtree_root(TreeId::Credentials);
    let cred_proof = forest
        .prove(TreeId::Credentials, record.id.as_bytes())
        .expect("leaf");
    let cred_proof_bytes = bincode::serialize(&cred_proof).expect("proof");

    let cred_input = InputBuilder::new(&creds_root)
        .field(record.id.as_bytes())
        .field(&record_bytes)
        .field(record.issuer_did.as_bytes())
        .field(&cred_proof_bytes)
        .build();
    c.bench_function("precompile_verify_credential", |b| {
        b.iter(|| verify_credential(&creds_root, &cred_input).expect("ok"))
    });

    let mut builder = InputBuilder::new(&creds_root)
        .field(record.id.as_bytes())
        .field(&record_bytes)
        .field(&cred_proof_bytes)
        .field(header)
        .field(ph)
        .u32(disclosed.len() as u32);
    for &i in &disclosed {
        builder = builder.u32(i as u32).field(messages[i]);
    }
    let bbs_input = builder.field(&proof.to_bytes()).build();
    c.bench_function("precompile_verify_bbs_disclosure", |b| {
        b.iter(|| verify_bbs_disclosure(&creds_root, &bbs_input).expect("ok"))
    });
}

criterion_group!(benches, bench_precompiles);
criterion_main!(benches);

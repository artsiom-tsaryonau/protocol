//! Criterion benches for the consensus hot path: BLS vote aggregation and
//! QC verification at live-committee scale (21 validators, quorum 14).
//! These are the ops §4.4 says must sit off the consensus thread — the
//! numbers here size that decision. Local measurements only.

use criterion::{criterion_group, criterion_main, Criterion};
use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
use solidus_hotstuff2::{vote_message, Committee, QuorumCert};

fn bench_qc_path(c: &mut Criterion) {
    let n = 21;
    let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
    let quorum = committee.quorum(); // 14

    let chain_id = 2;
    let view = 42;
    let block_hash = [7u8; 32];
    let msg = vote_message(chain_id, view, &block_hash);
    let sigs: Vec<BlsSignature> = keys[..quorum].iter().map(|k| k.sign(&msg)).collect();

    c.bench_function("bls_sign_vote", |b| b.iter(|| keys[0].sign(&msg)));

    c.bench_function("bls_verify_single_vote", |b| {
        let pk = keys[0].public_key();
        let sig = keys[0].sign(&msg);
        b.iter(|| assert!(sig.verify(&pk, &msg)))
    });

    c.bench_function("bls_aggregate_14_of_21", |b| {
        b.iter(|| {
            let refs: Vec<&BlsSignature> = sigs.iter().collect();
            BlsSignature::aggregate(&refs).expect("aggregate")
        })
    });

    let refs: Vec<&BlsSignature> = sigs.iter().collect();
    let agg = BlsSignature::aggregate(&refs).expect("aggregate");
    let qc = QuorumCert {
        view,
        block_hash,
        signers: (0..quorum as u32).collect(),
        agg_sig: agg,
    };
    let genesis = [0u8; 32];

    c.bench_function("qc_verify_14_of_21", |b| {
        b.iter(|| qc.verify(chain_id, &committee, &genesis).expect("valid"))
    });
}

criterion_group!(benches, bench_qc_path);
criterion_main!(benches);

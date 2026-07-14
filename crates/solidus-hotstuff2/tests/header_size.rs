//! Stage-2 acceptance: the consensus header stays ≤10KB per round at full
//! block capacity, and block bodies carry batch digests, never
//! transaction bodies.
//!
//! Capacity math being pinned: 50K TPS at ~0.5s blocks ≈ 25K txs/block.
//! At a modest 1,500-tx minimum batch fill that is ≤17 certificates per
//! block; healthy workers at 2–4K txs/batch need 7–12. We measure the
//! bincode header size at 17 (capacity) and 32 (2× headroom) certificates
//! with full 14-of-21 attestations.

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{BlockHeader2, QuorumCert};
use solidus_mempool_dag::{avail_message, BatchCertificate, BatchDigest};

const CHAIN_ID: u64 = 2;

fn realistic_cert(seed: u8, keys: &[BlsSecretKey]) -> BatchCertificate {
    let digest = BatchDigest([seed; 32]);
    let worker = 0;
    let msg = avail_message(CHAIN_ID, &digest, worker);
    // Full 14-of-21 attestation — worst realistic signer count.
    let signer_sigs: Vec<(u32, solidus_crypto::bls::BlsSignature)> = (0..14u32)
        .map(|i| (i, keys[i as usize].sign(&msg)))
        .collect();
    BatchCertificate::assemble(digest, worker, &signer_sigs).expect("assemble")
}

fn header_with(certs: Vec<BatchCertificate>) -> BlockHeader2 {
    BlockHeader2 {
        chain_id: CHAIN_ID,
        height: 1_000_000,
        view: 1_000_000,
        parent: [7u8; 32],
        batch_certs: certs,
        exec_height: 999_998,
        exec_state_root: [8u8; 32],
        timestamp_ms: 1_700_000_000_000,
        proposer: 20,
    }
}

#[test]
fn consensus_header_at_capacity_is_under_10kb() {
    let keys: Vec<BlsSecretKey> = (0..21).map(|_| BlsSecretKey::generate()).collect();

    for (label, n_certs, bound) in [
        ("capacity(17)", 17usize, 10_240usize),
        ("headroom(32)", 32, 20_480),
    ] {
        let certs: Vec<BatchCertificate> = (0..n_certs)
            .map(|i| realistic_cert(i as u8, &keys))
            .collect();
        let header = header_with(certs);
        let encoded = bincode::serialize(&header).expect("serialize header");
        println!(
            "header size {label}: {} bytes ({} certs, 14-of-21 attestations)",
            encoded.len(),
            n_certs
        );
        assert!(
            encoded.len() <= bound,
            "{label}: header {} bytes exceeds {bound}",
            encoded.len()
        );
    }
}

#[test]
fn block_body_is_digests_not_transactions() {
    // Structural acceptance: a proposal serialized at capacity contains no
    // transaction bodies — its size is orders of magnitude below the
    // ~12.5MB of raw txs it orders (25K txs × ~500B).
    let keys: Vec<BlsSecretKey> = (0..21).map(|_| BlsSecretKey::generate()).collect();
    let certs: Vec<BatchCertificate> = (0..17).map(|i| realistic_cert(i, &keys)).collect();
    let header = header_with(certs);

    let genesis_qc = QuorumCert::genesis([0u8; 32], keys[0].sign(b"g"));
    let block = solidus_hotstuff2::Block2 {
        header,
        justify: genesis_qc,
    };
    let encoded = bincode::serialize(&block).expect("serialize block");
    let raw_tx_equivalent = 25_000usize * 500;
    println!(
        "full proposal block: {} bytes vs ~{} bytes of raw txs it orders ({}x smaller)",
        encoded.len(),
        raw_tx_equivalent,
        raw_tx_equivalent / encoded.len().max(1)
    );
    assert!(encoded.len() * 100 < raw_tx_equivalent);
}

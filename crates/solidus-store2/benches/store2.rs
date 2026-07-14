//! Stage-4 acceptance bench: per-block durable state write at 50K-TPS
//! block shape. A 0.5s block at 50K TPS ≈ 25K transfers ≈ ~50K touched
//! account leaves + burn counter. The plan's bound: **< 50ms** per block.
//! Local measurement (state the hardware when publishing).

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solidus_exec::{DeltaSet, StateKey};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Receipt, TxStatus};

/// Build a delta shaped like a full 25K-transfer block: 50K account
/// leaves (73-byte bincode accounts) + one meta counter.
fn block_shaped_delta(rng: &mut StdRng, n_accounts: usize) -> DeltaSet {
    let mut delta = DeltaSet::new();
    for _ in 0..n_accounts {
        let mut addr = [0u8; 20];
        rng.fill(&mut addr);
        let mut value = vec![0u8; 73];
        rng.fill(value.as_mut_slice());
        delta
            .insert(
                StateKey {
                    space: solidus_exec::StateSpace::Tree(solidus_exec::types::TreeId::Accounts),
                    key: addr.to_vec(),
                },
                value,
            )
            .expect("insert");
    }
    delta
        .insert(StateKey::meta(b"fees_burned_total"), vec![1u8; 8])
        .expect("insert");
    delta
}

fn receipts_for(n: usize, rng: &mut StdRng) -> Vec<Receipt> {
    (0..n)
        .map(|_| {
            let mut tx_hash = [0u8; 32];
            rng.fill(&mut tx_hash);
            Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: 1,
                fee_paid: 10_000,
                events: vec![],
            }
        })
        .collect()
}

fn bench_persist_block(c: &mut Criterion) {
    let mut rng = StdRng::seed_from_u64(0x570e2);
    let delta = block_shaped_delta(&mut rng, 50_000);
    let receipts = receipts_for(25_000, &mut rng);

    for profile in [Profile::Testnet, Profile::Mainnet] {
        let mut group = c.benchmark_group(format!("persist_block_{profile:?}"));
        group.sample_size(10);
        group.throughput(Throughput::Elements(50_001));
        group.bench_function("50k_leaves_25k_receipts", |b| {
            b.iter_batched(
                || {
                    let dir = tempfile::tempdir().expect("tempdir");
                    let store = Store2::open(dir.path(), profile).expect("open");
                    (store, dir)
                },
                |(store, _dir)| {
                    store
                        .persist_block(1, [1u8; 32], b"block-bytes", &delta, &receipts)
                        .expect("persist")
                },
                BatchSize::PerIteration,
            )
        });
        group.finish();
    }
}

criterion_group!(benches, bench_persist_block);
criterion_main!(benches);

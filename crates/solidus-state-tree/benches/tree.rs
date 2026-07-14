//! Stage-4 acceptance evidence: root computation is O(touched · depth) —
//! the cost of applying a fixed-size delta must not grow with the size of
//! the pre-existing state. Local measurement; publish with hardware named.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use solidus_state_tree::{StateForest, TreeId};

fn seeded_forest(n_leaves: usize) -> StateForest {
    let mut rng = StdRng::seed_from_u64(0x0F0E);
    let mut forest = StateForest::new();
    for _ in 0..n_leaves {
        let mut key = [0u8; 20];
        rng.fill(&mut key);
        let mut value = vec![0u8; 73];
        rng.fill(value.as_mut_slice());
        forest.apply(TreeId::Accounts, &key, &value);
    }
    forest
}

fn delta(n: usize) -> Vec<([u8; 20], Vec<u8>)> {
    let mut rng = StdRng::seed_from_u64(0xDE17A);
    (0..n)
        .map(|_| {
            let mut key = [0u8; 20];
            rng.fill(&mut key);
            let mut value = vec![0u8; 73];
            rng.fill(value.as_mut_slice());
            (key, value)
        })
        .collect()
}

/// Apply the SAME 2,000-leaf delta to forests seeded at 10K vs 100K
/// leaves. O(touched) ⇒ roughly flat cost across the two sizes.
fn bench_root_apply_scaling(c: &mut Criterion) {
    let d = delta(2_000);
    for n_state in [10_000usize, 100_000] {
        let base = seeded_forest(n_state);
        let mut group = c.benchmark_group("root_apply_scaling");
        group.sample_size(10);
        group.throughput(Throughput::Elements(d.len() as u64));
        group.bench_function(format!("2k_delta_over_{n_state}_leaf_state"), |b| {
            b.iter_batched(
                || base.clone(),
                |mut forest| {
                    for (k, v) in &d {
                        forest.apply(TreeId::Accounts, k, v);
                    }
                    forest.global_root()
                },
                BatchSize::LargeInput,
            )
        });
        group.finish();
    }
}

criterion_group!(benches, bench_root_apply_scaling);
criterion_main!(benches);

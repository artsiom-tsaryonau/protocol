//! Criterion bench harness (Stage-0 deliverable — none existed in the
//! repo before this crate). Baseline numbers for the local dev box:
//!
//! - `reference_transfer_block/{256,1024}` — serial reference executor,
//!   Transfer-only blocks over disjoint accounts (the payment-lane shape).
//! - `legacy_transfer_block/256` — the live executor on the same logical
//!   workload (RocksDB tempdir), for an apples-to-oranges-but-honest
//!   baseline of what the live chain's per-block execution costs.
//! - `incremental_root_apply/1024` — forest apply + global root over a
//!   1024-leaf delta (the O(touched · depth) path replacing the live
//!   full-rescan).
//!
//! Every number this harness produces is a measurement on the machine it
//! ran on — never quote them as network throughput.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use ed25519_dalek::SigningKey;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_reference, Account, AccountType, BlockCtx, ExecOptions, InMemoryState, StateKey,
    WireMode,
};
use solidus_state_tree::StateForest;
use solidus_txns::types::{Transaction, TxPayload};

fn signed_transfer(
    key: &SigningKey,
    to: Address,
    amount: u64,
    nonce: u64,
    mode: WireMode,
) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, mode);
    tx.signature = sign(key, &msg);
    tx
}

/// Build `n` disjoint-sender Transfer txs + a funded in-memory baseline.
fn transfer_workload(n: usize, mode: WireMode) -> (InMemoryState, Vec<Transaction>) {
    let mut state = InMemoryState::new();
    let mut txs = Vec::with_capacity(n);
    for i in 0..n {
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        state.set(
            StateKey::account(&addr),
            Account::with_balance(addr, 1_000_000, AccountType::Regular).to_bytes(),
        );
        let mut to_bytes = [0u8; 20];
        to_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        to_bytes[19] = 0xEE;
        txs.push(signed_transfer(
            &key,
            Address::from_bytes(to_bytes),
            100,
            0,
            mode,
        ));
    }
    (state, txs)
}

fn bench_reference_transfer_block(c: &mut Criterion) {
    let mut group = c.benchmark_group("reference_transfer_block");
    for &n in &[256usize, 1024] {
        let (state, txs) = transfer_workload(n, WireMode::BinaryV2);
        let ctx = BlockCtx {
            height: 1,
            timestamp_ms: 1_700_000_000_000,
            network: "v2-bench",
            parent_state_root: [0u8; 32],
        };
        let opts = ExecOptions::v2_defaults(50_002);
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(format!("{n}"), |b| {
            b.iter(|| execute_block_reference(&state, &txs, &ctx, &opts).expect("execute"))
        });
    }
    group.finish();
}

fn bench_legacy_transfer_block(c: &mut Criterion) {
    use solidus_state::executor::execute_block as legacy_execute_block;
    use solidus_state::store::Store;

    let mut group = c.benchmark_group("legacy_transfer_block");
    group.sample_size(10); // RocksDB setup per iteration is expensive
    let n = 256usize;

    // Pre-build txs once (legacy wire).
    let keys: Vec<SigningKey> = (0..n).map(|_| generate_signing_key()).collect();
    let txs: Vec<Transaction> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let mut to_bytes = [0u8; 20];
            to_bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            to_bytes[19] = 0xEE;
            signed_transfer(
                key,
                Address::from_bytes(to_bytes),
                100,
                0,
                WireMode::LegacyJson,
            )
        })
        .collect();

    let treasury = Address::from_bytes([0xAA; 20]);
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function(format!("{n}"), |b| {
        b.iter_batched(
            || {
                // Fresh store, funded senders.
                let dir = tempfile::tempdir().expect("tempdir");
                let store = Store::open(dir.path()).expect("open");
                for key in &keys {
                    let addr = Address::from_public_key(&key.verifying_key());
                    let acct = solidus_state::account::Account::with_balance(
                        addr,
                        1_000_000,
                        solidus_state::account::AccountType::Regular,
                    );
                    store
                        .put(
                            solidus_state::store::CF_ACCOUNTS,
                            addr.as_bytes(),
                            &acct.to_bytes(),
                        )
                        .expect("fund");
                }
                (store, dir)
            },
            |(store, _dir)| {
                legacy_execute_block(
                    &store,
                    &txs,
                    1,
                    1_700_000_000_000,
                    &treasury,
                    &[],
                    "testnet",
                )
                .expect("legacy execute")
            },
            BatchSize::PerIteration,
        )
    });
    group.finish();
}

fn bench_incremental_root_apply(c: &mut Criterion) {
    let n = 1024usize;
    let (state, txs) = transfer_workload(n, WireMode::BinaryV2);
    let ctx = BlockCtx {
        height: 1,
        timestamp_ms: 1_700_000_000_000,
        network: "v2-bench",
        parent_state_root: [0u8; 32],
    };
    let opts = ExecOptions::v2_defaults(50_002);
    let outcome = execute_block_reference(&state, &txs, &ctx, &opts).expect("execute");

    let mut group = c.benchmark_group("incremental_root_apply");
    group.throughput(Throughput::Elements(outcome.delta.len() as u64));
    group.bench_function(format!("{n}tx_delta"), |b| {
        b.iter_batched(
            || {
                let mut forest = StateForest::new();
                state.seed_forest(&mut forest);
                forest
            },
            |mut forest| {
                outcome.delta.apply_to_forest(&mut forest);
                forest.global_root()
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

// ---------------------------------------------------------------------------
// Stage-3 lane benchmarks — acceptance (b), (c), (d). Local measurements on
// this box (Apple M4, 10 cores); the plan's numeric targets are specified
// for a 32-core validator, so publish these as "local box vs target".
// ---------------------------------------------------------------------------

use solidus_exec::execute_block_twolane;
use solidus_txns::credential::CredentialType;

/// Pre-register a hot issuer + `n_subjects` subject DIDs into the state
/// (one identity-lane setup block through the reference executor).
fn register_identities(state: &mut InMemoryState, n_subjects: usize) -> (SigningKey, Vec<String>) {
    let ctx = BlockCtx {
        height: 1,
        timestamp_ms: 1_700_000_000_000,
        network: "v2-bench",
        parent_state_root: [0u8; 32],
    };
    let opts = ExecOptions::v2_defaults(50_002);

    let issuer = generate_signing_key();
    let mut txs = Vec::with_capacity(n_subjects + 1);
    let mut subject_dids = Vec::with_capacity(n_subjects);

    let make_create = |key: &SigningKey| {
        let pk = key.verifying_key().to_bytes();
        let mut tx = Transaction {
            sender_pubkey: pk,
            nonce: 0,
            payload: TxPayload::DidCreate {
                public_key: pk,
                service_endpoints: vec![],
            },
            signature: [0u8; 64],
        };
        let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
        tx.signature = solidus_crypto::ed25519::sign(key, &msg);
        tx
    };

    txs.push(make_create(&issuer));
    for _ in 0..n_subjects {
        let subject = generate_signing_key();
        let addr = Address::from_public_key(&subject.verifying_key());
        subject_dids.push(solidus_txns::did::build_did("v2-bench", &addr));
        txs.push(make_create(&subject));
    }

    let outcome =
        solidus_exec::execute_block_reference(&*state, &txs, &ctx, &opts).expect("setup block");
    assert!(outcome
        .receipts
        .iter()
        .all(|r| matches!(r.status, solidus_txns::types::TxStatus::Success)));
    state.apply_delta(&outcome.delta);
    (issuer, subject_dids)
}

fn issue_tx(issuer: &SigningKey, nonce: u64, subject_did: &str, salt: u8) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: issuer.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::CredentialIssue {
            subject_did: subject_did.to_string(),
            credential_type: CredentialType::KycL1,
            hash: [salt; 32],
        },
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
    tx.signature = solidus_crypto::ed25519::sign(issuer, &msg);
    tx
}

/// (b) Payment lane: 10,000 disjoint transfers through the full two-lane
/// pipeline (rayon sig pre-pass + wave-OCC + merge + settle).
fn bench_twolane_payment_lane(c: &mut Criterion) {
    let n = 10_000usize;
    let (state, txs) = transfer_workload(n, WireMode::BinaryV2);
    let ctx = BlockCtx {
        height: 1,
        timestamp_ms: 1_700_000_000_000,
        network: "v2-bench",
        parent_state_root: [0u8; 32],
    };
    let opts = ExecOptions::v2_defaults(50_002);

    let mut group = c.benchmark_group("twolane_payment_lane");
    group.sample_size(10);
    group.throughput(Throughput::Elements(n as u64));
    group.bench_function(format!("{n}_disjoint_transfers"), |b| {
        b.iter(|| execute_block_twolane(&state, &txs, &ctx, &opts).expect("execute"))
    });
    group.finish();
}

/// (c) Identity lane: 500 serialized credential issues from ONE hot issuer
/// (contention deliberately maximal) through the full pipeline.
fn bench_twolane_identity_lane(c: &mut Criterion) {
    let mut state = InMemoryState::new();
    let (issuer, subjects) = register_identities(&mut state, 500);
    let txs: Vec<Transaction> = subjects
        .iter()
        .enumerate()
        .map(|(i, s)| issue_tx(&issuer, 1 + i as u64, s, i as u8))
        .collect();
    let ctx = BlockCtx {
        height: 2,
        timestamp_ms: 1_700_000_002_000,
        network: "v2-bench",
        parent_state_root: [0u8; 32],
    };
    let opts = ExecOptions::v2_defaults(50_002);

    let mut group = c.benchmark_group("twolane_identity_lane");
    group.sample_size(10);
    group.throughput(Throughput::Elements(txs.len() as u64));
    group.bench_function("500_hot_issuer_issues", |b| {
        b.iter(|| execute_block_twolane(&state, &txs, &ctx, &opts).expect("execute"))
    });
    group.finish();
}

/// (d) The number the split exists to protect: 95% transfers / 5% identity
/// with all identity ops hammering one hot issuer DID.
fn bench_twolane_mixed_95_5(c: &mut Criterion) {
    let n_pay = 9_500usize;
    let n_id = 500usize;
    let (mut state, mut txs) = transfer_workload(n_pay, WireMode::BinaryV2);
    let (issuer, subjects) = register_identities(&mut state, n_id);
    for (i, s) in subjects.iter().enumerate() {
        txs.push(issue_tx(&issuer, 1 + i as u64, s, i as u8));
    }
    let ctx = BlockCtx {
        height: 2,
        timestamp_ms: 1_700_000_002_000,
        network: "v2-bench",
        parent_state_root: [0u8; 32],
    };
    let opts = ExecOptions::v2_defaults(50_002);

    let mut group = c.benchmark_group("twolane_mixed_95_5");
    group.sample_size(10);
    group.throughput(Throughput::Elements((n_pay + n_id) as u64));
    group.bench_function("9500_transfers_500_hot_issues", |b| {
        b.iter(|| execute_block_twolane(&state, &txs, &ctx, &opts).expect("execute"))
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_reference_transfer_block,
    bench_legacy_transfer_block,
    bench_incremental_root_apply,
    bench_twolane_payment_lane,
    bench_twolane_identity_lane,
    bench_twolane_mixed_95_5
);
criterion_main!(benches);

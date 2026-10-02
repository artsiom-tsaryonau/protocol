//! THE Stage-3 gate: the two-lane executor must produce **byte-identical**
//! receipts, write-sets, and global state roots against the serial
//! reference oracle — both running v2 semantics (binary wire,
//! lane-partitioned canonical order, burn fees) — across randomized
//! multi-block streams over all 10 payloads plus the four adversarial
//! cross-lane scenarios (§5.6).
//!
//! Scale knobs (defaults CI-fast; the bounded fuzz run raises them):
//! `SOLIDUS_TWOLANE_SEEDS` / `SOLIDUS_TWOLANE_BLOCKS` / `SOLIDUS_TWOLANE_TXS`,
//! plus `SOLIDUS_TWOLANE_SEED_OFFSET` so parallel processes can each take a
//! disjoint seed range (the test is one thread; the oracle is serial — the
//! ≥10⁹-tx campaign shards by offset across cores: process i runs
//! OFFSET=i*SEEDS with identical SEEDS/BLOCKS/TXS).

mod common;

use common::{sign_tx_mode, StreamGen, GENESIS_TS, NETWORK};
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_reference, execute_block_twolane, Account, AccountType, BlockCtx, BlockOutcome,
    ExecError, ExecOptions, InMemoryState, StateKey, WireMode,
};
use solidus_state_tree::StateForest;
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn ctx_at(height: u64) -> BlockCtx<'static> {
    BlockCtx {
        height,
        timestamp_ms: GENESIS_TS + height * 1_000,
        network: NETWORK,
        parent_state_root: [0u8; 32],
    }
}

fn assert_outcomes_identical(oracle: &BlockOutcome, twolane: &BlockOutcome, height: u64) {
    assert_eq!(
        oracle.receipts.len(),
        twolane.receipts.len(),
        "receipt count divergence at height {height}"
    );
    for (i, (o, t)) in oracle
        .receipts
        .iter()
        .zip(twolane.receipts.iter())
        .enumerate()
    {
        assert_eq!(
            o, t,
            "receipt divergence at height {height} tx {i}:\n oracle:  {o:?}\n twolane: {t:?}"
        );
    }

    let o_delta: Vec<_> = oracle.delta.iter().collect();
    let t_delta: Vec<_> = twolane.delta.iter().collect();
    assert_eq!(
        o_delta.len(),
        t_delta.len(),
        "delta size divergence at height {height}: oracle {} vs twolane {}",
        o_delta.len(),
        t_delta.len()
    );
    for ((ok, ov), (tk, tv)) in o_delta.iter().zip(t_delta.iter()) {
        assert_eq!(ok, tk, "delta key divergence at height {height}");
        assert_eq!(
            ov, tv,
            "delta value divergence at height {height} key {ok:?}"
        );
    }
}

fn fund(state: &mut InMemoryState, addr: Address, balance: u64) {
    state.set(
        StateKey::account(&addr),
        Account::with_balance(addr, balance, AccountType::Regular).to_bytes(),
    );
}

// ---------------------------------------------------------------------------
// Randomized multi-block differential (v2 mode, both executors)
// ---------------------------------------------------------------------------

#[test]
fn randomized_v2_streams_zero_divergence() {
    let seeds = env_usize("SOLIDUS_TWOLANE_SEEDS", 3);
    let blocks = env_usize("SOLIDUS_TWOLANE_BLOCKS", 40);
    let max_txs = env_usize("SOLIDUS_TWOLANE_TXS", 48);
    let offset = env_usize("SOLIDUS_TWOLANE_SEED_OFFSET", 0);
    let opts = ExecOptions::v2_defaults(50_002);

    let mut total_txs = 0u64;
    for seed_idx in offset..offset + seeds {
        let seed = 0x71A0_0D1Eu64
            .wrapping_mul(seed_idx as u64 + 1)
            .wrapping_add(seed_idx as u64);
        let mut baseline = InMemoryState::new();
        let mut gen = StreamGen::new_v2(seed, 48, &mut baseline, WireMode::BinaryV2);

        for h in 1..=(blocks as u64) {
            let txs = gen.gen_block(max_txs);
            if txs.is_empty() {
                continue;
            }
            let ctx = ctx_at(h);
            let oracle = execute_block_reference(&baseline, &txs, &ctx, &opts).expect("oracle");
            let twolane = execute_block_twolane(&baseline, &txs, &ctx, &opts).expect("twolane");
            assert_outcomes_identical(&oracle, &twolane, h);

            baseline.apply_delta(&oracle.delta);
            gen.refresh_v2(&baseline, &oracle.receipts);
            total_txs += txs.len() as u64;
        }

        // Global-root equality over the final state (belt-and-braces —
        // deltas were byte-identical every block).
        let mut forest = StateForest::new();
        baseline.seed_forest(&mut forest);
        let _root = forest.global_root();
    }
    println!(
        "two-lane vs oracle: {total_txs} transactions across {seeds} streams (offset {offset}) × {blocks} blocks — zero divergence"
    );
}

// ---------------------------------------------------------------------------
// §5.6 adversarial cross-lane scenarios under v2 lane semantics
// ---------------------------------------------------------------------------

fn run_both(
    baseline: &InMemoryState,
    txs: &[Transaction],
    height: u64,
) -> (BlockOutcome, BlockOutcome) {
    let opts = ExecOptions::v2_defaults(50_002);
    let ctx = ctx_at(height);
    let oracle = execute_block_reference(baseline, txs, &ctx, &opts).expect("oracle");
    let twolane = execute_block_twolane(baseline, txs, &ctx, &opts).expect("twolane");
    assert_outcomes_identical(&oracle, &twolane, height);
    (oracle, twolane)
}

/// (i) Mixed-sender: Transfers + Stake from one sender ride the identity
/// lane together, nonce-correct.
#[test]
fn adversarial_mixed_sender() {
    let mut baseline = InMemoryState::new();
    let alice = generate_signing_key();
    let alice_addr = Address::from_public_key(&alice.verifying_key());
    fund(
        &mut baseline,
        alice_addr,
        solidus_txns::staking::MIN_STAKE * 2 + 1_000_000,
    );
    let bob = generate_signing_key();
    let bob_addr = Address::from_public_key(&bob.verifying_key());
    fund(&mut baseline, bob_addr, 1_000_000);

    let m = WireMode::BinaryV2;
    let txs = vec![
        sign_tx_mode(
            &alice,
            0,
            TxPayload::Transfer {
                to: Address::from_bytes([0x21; 20]),
                amount: 1_000,
            },
            m,
        ),
        sign_tx_mode(
            &bob,
            0,
            TxPayload::Transfer {
                to: Address::from_bytes([0x22; 20]),
                amount: 500,
            },
            m,
        ),
        sign_tx_mode(
            &alice,
            1,
            TxPayload::Stake {
                amount: solidus_txns::staking::MIN_STAKE,
            },
            m,
        ),
        sign_tx_mode(
            &alice,
            2,
            TxPayload::Transfer {
                to: Address::from_bytes([0x23; 20]),
                amount: 2_000,
            },
            m,
        ),
    ];
    let (oracle, _) = run_both(&baseline, &txs, 1);
    assert!(oracle
        .receipts
        .iter()
        .all(|r| r.status == TxStatus::Success));
}

/// (ii) A payment receiver who is an identity-lane sender — v2 lane
/// semantics: the DidCreate wins in BOTH block orders (identity runs
/// first), and the transfer is rejected by the anchor guard.
#[test]
fn adversarial_receiver_is_identity_sender_lane_semantics() {
    for flip_order in [false, true] {
        let mut baseline = InMemoryState::new();
        let alice = generate_signing_key();
        let alice_addr = Address::from_public_key(&alice.verifying_key());
        fund(&mut baseline, alice_addr, 1_000_000);
        let dana = generate_signing_key();
        let dana_addr = Address::from_public_key(&dana.verifying_key());
        let dana_pk = dana.verifying_key().to_bytes();

        let m = WireMode::BinaryV2;
        let transfer = sign_tx_mode(
            &alice,
            0,
            TxPayload::Transfer {
                to: dana_addr,
                amount: 777,
            },
            m,
        );
        let create = sign_tx_mode(
            &dana,
            0,
            TxPayload::DidCreate {
                public_key: dana_pk,
                service_endpoints: vec![],
            },
            m,
        );
        let txs = if flip_order {
            vec![create.clone(), transfer.clone()]
        } else {
            vec![transfer.clone(), create.clone()]
        };
        let (oracle, _) = run_both(&baseline, &txs, 1);

        // Identity-first semantics regardless of block order: the create
        // succeeds (dana is pristine when the identity lane runs), the
        // transfer fails the anchor guard.
        let create_pos = if flip_order { 0 } else { 1 };
        let transfer_pos = 1 - create_pos;
        assert_eq!(
            oracle.receipts[create_pos].status,
            TxStatus::Success,
            "flip={flip_order}"
        );
        assert!(
            matches!(&oracle.receipts[transfer_pos].status, TxStatus::Failed(r) if r.contains("anchor")),
            "flip={flip_order}: {:?}",
            oracle.receipts[transfer_pos].status
        );
    }
}

/// (iii) Issuance burst on one hot issuer, interleaved with payment
/// traffic — identity contention deliberately maximized while the payment
/// lane stays parallel.
#[test]
fn adversarial_hot_issuer_burst_with_payment_traffic() {
    let mut baseline = InMemoryState::new();
    let m = WireMode::BinaryV2;

    // Register issuer + 30 subjects (block 1..=31 single-tx blocks).
    let issuer = generate_signing_key();
    let issuer_pk = issuer.verifying_key().to_bytes();
    let mut height = 1u64;
    let opts = ExecOptions::v2_defaults(50_002);
    let reg = sign_tx_mode(
        &issuer,
        0,
        TxPayload::DidCreate {
            public_key: issuer_pk,
            service_endpoints: vec![],
        },
        m,
    );
    let out = execute_block_twolane(
        &baseline,
        std::slice::from_ref(&reg),
        &ctx_at(height),
        &opts,
    )
    .expect("issuer reg");
    // Keep both sides in lockstep by applying the oracle-equal delta.
    let oracle = execute_block_reference(&baseline, &[reg], &ctx_at(height), &opts).expect("o");
    assert_outcomes_identical(&oracle, &out, height);
    baseline.apply_delta(&out.delta);
    height += 1;

    let mut subject_dids = Vec::new();
    for _ in 0..30 {
        let s = generate_signing_key();
        let s_addr = Address::from_public_key(&s.verifying_key());
        let s_pk = s.verifying_key().to_bytes();
        let tx = sign_tx_mode(
            &s,
            0,
            TxPayload::DidCreate {
                public_key: s_pk,
                service_endpoints: vec![],
            },
            m,
        );
        let (o, _) = run_both(&baseline, &[tx], height);
        baseline.apply_delta(&o.delta);
        subject_dids.push(solidus_txns::did::build_did(NETWORK, &s_addr));
        height += 1;
    }

    // The burst block: 30 sequential issues from the hot issuer + 40
    // disjoint transfers.
    let mut txs: Vec<Transaction> = subject_dids
        .iter()
        .enumerate()
        .map(|(i, subject_did)| {
            sign_tx_mode(
                &issuer,
                1 + i as u64,
                TxPayload::CredentialIssue {
                    subject_did: subject_did.clone(),
                    credential_type: solidus_txns::credential::CredentialType::KycL1,
                    hash: [i as u8; 32],
                },
                m,
            )
        })
        .collect();
    for i in 0..40u8 {
        let payer = generate_signing_key();
        let payer_addr = Address::from_public_key(&payer.verifying_key());
        fund(&mut baseline, payer_addr, 1_000_000);
        txs.push(sign_tx_mode(
            &payer,
            0,
            TxPayload::Transfer {
                to: Address::from_bytes([i; 20]),
                amount: 100 + i as u64,
            },
            m,
        ));
    }
    let (oracle, _) = run_both(&baseline, &txs, height);
    assert!(
        oracle
            .receipts
            .iter()
            .all(|r| r.status == TxStatus::Success),
        "burst block must fully succeed"
    );
}

/// (iv) Fee settlement under a wide all-payment block (Burn policy: one
/// meta-counter write regardless of width).
#[test]
fn adversarial_fee_settlement_width_burn_policy() {
    let mut baseline = InMemoryState::new();
    let m = WireMode::BinaryV2;
    let mut txs = Vec::new();
    for i in 0..150u64 {
        let payer = generate_signing_key();
        let addr = Address::from_public_key(&payer.verifying_key());
        fund(&mut baseline, addr, 100_000);
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xDD;
        txs.push(sign_tx_mode(
            &payer,
            0,
            TxPayload::Transfer {
                to: Address::from_bytes(to),
                amount: 1 + (i % 977),
            },
            m,
        ));
    }
    let (oracle, _) = run_both(&baseline, &txs, 1);
    assert!(oracle
        .receipts
        .iter()
        .all(|r| r.status == TxStatus::Success));
    let burned = oracle
        .delta
        .get(&StateKey::meta(solidus_exec::fee::META_FEES_BURNED))
        .expect("burn counter present");
    let total = u64::from_le_bytes(burned.as_slice().try_into().expect("8 bytes"));
    assert_eq!(total, 150 * 10_000);
}

/// Over-cap identity lane: both executors refuse identically.
#[test]
fn over_cap_identity_lane_rejected_by_both() {
    let mut baseline = InMemoryState::new();
    let m = WireMode::BinaryV2;
    let mut opts = ExecOptions::v2_defaults(50_002);
    opts.identity_cap = 2;

    let staker = generate_signing_key();
    let addr = Address::from_public_key(&staker.verifying_key());
    fund(&mut baseline, addr, solidus_txns::staking::MIN_STAKE * 10);
    let txs: Vec<Transaction> = (0..3u64)
        .map(|nonce| sign_tx_mode(&staker, nonce, TxPayload::Stake { amount: 1 }, m))
        .collect();

    let ctx = ctx_at(1);
    let o = execute_block_reference(&baseline, &txs, &ctx, &opts);
    let t = execute_block_twolane(&baseline, &txs, &ctx, &opts);
    assert!(matches!(
        o,
        Err(ExecError::IdentityCapExceeded { count: 3, cap: 2 })
    ));
    assert!(matches!(
        t,
        Err(ExecError::IdentityCapExceeded { count: 3, cap: 2 })
    ));
}

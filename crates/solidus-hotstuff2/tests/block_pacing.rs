//! Block pacing: the safety properties, not the timing.
//!
//! ⛔ WHY PACING EXISTS. With none, `enter_view` proposes the instant this node
//! leads, and a view closes as soon as a QC forms. Measured on the live testnet
//! 2026-09-07: **8,60 blocks/s, one every 116ms**, three identical 30s windows,
//! every block empty, against the 2,0s target the explorer states. Four
//! validators on one box over loopback close a round in ~116ms, so the chain
//! produced ~743.000 empty blocks a day and the store grew with wall-clock time
//! rather than with use.
//!
//! ⛔ THE OBVIOUS IMPLEMENTATION IS WRONG AND THIS FILE GUARDS AGAINST IT.
//! Gating `propose()` on elapsed time and returning leaves the view with NO
//! proposal, so it times out, the pacemaker rotates leadership and backs off,
//! and blocks then arrive at the timeout rate with a timeout certificate each —
//! while the chain still commits and looks healthy from outside. The proposal is
//! DELAYED via `Action::SchedulePropose`, never skipped.
//!
//! ⚠ TIMING IS NOT TESTED HERE. `EmptyPayloads` has a fixed clock, which is what
//! makes these deterministic. The wall-clock behaviour is exercised by the
//! localnet harness, which drives real tokio timers for `SchedulePropose`.

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{
    Action, Committee, ConsensusCore, CoreConfig, EmptyPayloads, Pacemaker, RoundRobin,
};

const CHAIN_ID: u64 = 2;
const N: usize = 4;

fn core_with(interval_ms: u64, timeout_ms: u64) -> ConsensusCore<RoundRobin, EmptyPayloads> {
    let secrets: Vec<BlsSecretKey> = (0..N)
        .map(|i| BlsSecretKey::from_bytes(&[(i as u8) + 1; 32]).expect("secret"))
        .collect();
    let committee = Committee::new(secrets.iter().map(|s| s.public_key()).collect());
    ConsensusCore::new(
        CoreConfig {
            chain_id: CHAIN_ID,
            // ⚠ INDEX 1, NOT 0, AND THAT IS LOAD-BEARING. `start()` enters view
            // `cur_view + 1` = 1, and `RoundRobin::leader` is `view % n`, so view 1
            // is led by index 1. With index 0 this node leads views 0, 4, 8… and
            // `start()` emits no proposal at all — which is exactly how the first
            // draft of this file failed, with every test red and the control
            // pointing at the wrong assumption rather than at the feature.
            my_index: 1,
            secret: BlsSecretKey::from_bytes(&secrets[1].to_bytes()).expect("secret"),
            committee,
            pacemaker: Pacemaker::new(timeout_ms, timeout_ms * 8),
            min_block_interval_ms: interval_ms,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
        },
        RoundRobin::new(N),
        EmptyPayloads { ts_ms: 1 },
    )
}

fn proposals(actions: &[Action]) -> usize {
    actions
        .iter()
        .filter(|a| matches!(a, Action::BroadcastProposal(_)))
        .count()
}

/// Control: with pacing off the behaviour is exactly what it was before pacing
/// existed. If this ever fails, the feature has changed the default path.
#[test]
fn pacing_off_proposes_immediately() {
    let mut c = core_with(0, 400);
    let out = c.start();
    assert_eq!(
        proposals(&out),
        1,
        "with min_block_interval_ms = 0 the leader must propose on entering its view"
    );
    assert!(
        !out.iter()
            .any(|a| matches!(a, Action::SchedulePropose { .. })),
        "pacing is off; nothing should be scheduled"
    );
}

/// The FIRST proposal after boot is never delayed. A restarting validator must
/// rejoin at full speed rather than sitting out an interval it has no reason to
/// honour — it has not proposed anything to be paced against.
#[test]
fn the_first_proposal_after_boot_is_never_delayed() {
    let mut c = core_with(2_000, 6_000);
    let out = c.start();
    assert_eq!(
        proposals(&out),
        1,
        "first proposal must go out immediately even with a 2s interval"
    );
}

/// ⛔ THE EQUIVOCATION GUARD. The pacing delay is wall-clock time during which
/// consensus keeps moving, so by the time the timer fires the view may have
/// advanced or a proposal may already have gone out. Proposing anyway would put
/// a second block into a view — the slashable case.
#[test]
fn a_stale_pacing_timer_never_proposes() {
    let mut c = core_with(2_000, 6_000);
    let started = c.start();
    assert_eq!(proposals(&started), 1);
    let view = c.current_view();

    // Already proposed in this view: the timer must decline.
    let mut acts = Vec::new();
    c.on_propose_timer(view, &mut acts);
    assert_eq!(
        proposals(&acts),
        0,
        "a timer for a view we already proposed in must not propose again"
    );

    // A timer for a view that is not the current one must decline.
    let mut acts2 = Vec::new();
    c.on_propose_timer(view + 7, &mut acts2);
    assert_eq!(
        proposals(&acts2),
        0,
        "a timer for a view we are no longer in must not propose"
    );

    let mut acts3 = Vec::new();
    c.on_propose_timer(view.saturating_sub(1), &mut acts3);
    assert_eq!(
        proposals(&acts3),
        0,
        "a timer for a past view must not propose"
    );
}

/// ⛔ PACING AND LIVENESS MUST NOT FIGHT, and an incoherent pair is refused at
/// construction rather than degrading silently. A block interval at or above the
/// view timeout means the view expires before the leader proposes, so the chain
/// produces at the backoff rate with a timeout certificate per block while still
/// committing — invisible from outside, which is why this is a panic.
#[test]
#[should_panic(expected = "every view would time out")]
fn an_interval_without_timeout_headroom_is_refused() {
    // 2s blocks against the pacemaker's 400ms default: the exact mistake.
    let _ = core_with(2_000, 400);
}

/// The boundary is `MIN_TIMEOUT_HEADROOM`x, and exactly that must be accepted —
/// a guard that rejects its own documented limit is a guard nobody can satisfy.
#[test]
fn exactly_the_documented_headroom_is_accepted() {
    let headroom = u64::from(solidus_hotstuff2::MIN_TIMEOUT_HEADROOM);
    let mut c = core_with(1_000, 1_000 * headroom);
    assert_eq!(proposals(&c.start()), 1);
}

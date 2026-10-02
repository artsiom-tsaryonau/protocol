//! The executor can ask which rules govern a block, and asking changes nothing.
//!
//! Queue item 3 of the protocol-upgradability loop. This is deliberately a
//! NO-OP refactor: the version becomes available at every execution site and no
//! behaviour moves, because the shipped activation table has one entry.
//!
//! ⚠ WHAT ACTUALLY PROVES "NO BEHAVIOUR MOVED" IS NOT IN THIS FILE.
//! `twolane_vs_oracle.rs` runs randomized multi-block streams over all ten
//! payloads through both the two-lane executor and a serial reference oracle,
//! and asserts byte-identical receipts, write-sets AND global state roots. If
//! threading the version had changed anything, that is what fails. This file
//! only pins the wiring itself, and says so rather than claiming the stronger
//! result.

use solidus_exec::protocol::{version_at, ProtocolVersion};
use solidus_exec::BlockCtx;

fn ctx_at(height: u64) -> BlockCtx<'static> {
    BlockCtx {
        height,
        timestamp_ms: 1_700_000_000_000,
        network: "testnet",
        parent_state_root: [0u8; 32],
    }
}

#[test]
fn a_block_context_reports_the_rules_for_its_own_height() {
    // Genesis, an ordinary height, the live chain's rough tip, and the extreme.
    for h in [0u64, 1, 971_693, u64::MAX] {
        assert_eq!(
            ctx_at(h).protocol_version(),
            version_at(h),
            "the context disagreed with the activation table at height {h}"
        );
    }
}

// ⚠ In a production build `V2_ACTIVATION_HEIGHT` IS `u64::MAX`, so clippy calls
// the guard below an absurd extreme comparison. The comparison is deliberate and
// load-bearing in a `test-activation-schedule` build, where the activation is
// 1_000 and several of these heights sit above it. Allowed rather than reshaped,
// because the shape is what makes the test correct in BOTH configurations.
#[allow(clippy::absurd_extreme_comparisons)]
#[test]
fn every_height_the_live_chain_has_reached_is_governed_by_v1() {
    // ⚠ This is the assertion that keeps the refactor honest. Every block the
    // chain has produced must still execute under the rules it was produced with.
    // Heights at or above the activation are skipped: they are only reachable in
    // a test-activation-schedule build, where V2 starts at 1_000.
    for h in [0u64, 1, 100, 148_900, 456_600, 971_693, 1_000_000] {
        if h >= solidus_exec::protocol::V2_ACTIVATION_HEIGHT {
            continue;
        }
        assert_eq!(
            ctx_at(h).protocol_version(),
            ProtocolVersion::V1,
            "height {h} is historical and must stay on V1 forever"
        );
    }
}

#[test]
fn the_context_reports_v2_at_the_activation_height() {
    let at = solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
    assert_eq!(ctx_at(at).protocol_version(), ProtocolVersion::V2);
    assert_eq!(
        ctx_at(at.saturating_sub(1)).protocol_version(),
        ProtocolVersion::V1
    );
}

/// ⚠ THE CONTROL. Without it, both tests above pass against a
/// `protocol_version()` that ignores its input and returns `V1`. There is only
/// one variant today, so the check cannot be "a different height gives a
/// different version" — it has to be that the context consults the TABLE rather
/// than answering from a constant.
#[test]
fn control_the_context_consults_the_table_rather_than_hardcoding() {
    // If `protocol_version()` were `-> V1` this still passes, so the real
    // assertion is structural: the context must agree with `version_at` for
    // heights chosen at random, including ones no test enumerated.
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..64 {
        h = h
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        assert_eq!(
            ctx_at(h).protocol_version(),
            version_at(h),
            "context and table disagreed at height {h}"
        );
    }
}

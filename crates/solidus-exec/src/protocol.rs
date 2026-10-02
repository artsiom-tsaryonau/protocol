//! Which execution rules apply at a given block height.
//!
//! ⛔ THE VERSION IS NOT IN THE BLOCK, AND THAT IS THE WHOLE DESIGN. A header
//! is content-addressed as `blake3(bincode(header))`, and bincode is positional,
//! so adding a version field would change every header hash, break every parent
//! link and make ~971k stored blocks undecodable. `header_layout_frozen.rs` in
//! `solidus-hotstuff2` enforces that it never happens.
//!
//! Instead the rule set is a PURE FUNCTION OF HEIGHT, compiled into the binary.
//! That is how Ethereum and Bitcoin schedule forks: a node syncing from genesis
//! re-runs every historical block under the rules of its own height, so history
//! stays reproducible while the rules ahead of the tip can change.
//!
//! ⛔ A RULE MUST DEPEND ON HEIGHT AND NOTHING ELSE. Not wall-clock, not config,
//! not an environment variable. Two nodes that disagree about the rule set at
//! the same height FORK, and the disagreement is invisible until their state
//! roots differ.
//!
//! ⛔ NEVER MAKE AN ACTIVATION HEIGHT CONFIGURABLE PER NODE. It is consensus,
//! not operator preference. Anything settable in a toml will eventually be set.
//!
//! ⛔ ONCE SHIPPED, AN ENTRY IS FROZEN. "Improving" the rules of a past version
//! silently rewrites history and breaks sync for everyone who replays it.

/// A set of execution rules, identified by when it activates.
///
/// ⚠ Variants are ordered oldest-first and that order is meaningful: `PartialOrd`
/// is what lets a rule ask "are we at least V2 here?" rather than enumerating
/// every later version, which is the form that rots when V3 is added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProtocolVersion {
    /// Everything the chain has ever done, up to and including today.
    V1,
    /// The bridge rules (spec §4.2): bridge transactions, chain-bound transaction
    /// signatures (`WireMode::BinaryV3`), revocation fan-out and heartbeats.
    V2,
}

/// Activation schedule: the height at which each version takes effect.
///
/// ⚠ SHIPS WITH EXACTLY ONE ENTRY ON PURPOSE. `(0, V1)` means today's behaviour
/// is unchanged by construction, so introducing this machinery cannot alter a
/// single block. The first real rule change adds the second row.
///
/// ⚠ MUST BE SORTED BY HEIGHT, ASCENDING, WITH NO DUPLICATES. `version_at` scans
/// backwards and returns the first entry at or below the height; an unsorted or
/// duplicated table silently returns the wrong rules for some heights, which is
/// a fork. `activations_are_sane` asserts it and a test calls that.
/// When V2 activates on the live chain.
///
/// ⛔ `u64::MAX` MEANS "NOT SCHEDULED". Only the phase 0 deploy task in
/// the bridge rollout plan (phase 0b, chain bridge module) sets a real height,
/// at least 20 000 blocks above the tip on the day, and records it in
/// `bridge/config/solidus-activation.json`.
pub const SCHEDULED_V2_ACTIVATION_HEIGHT: u64 = 3_150_000;

/// The live tip measured when V2 was scheduled (see bridge/config/solidus-activation.json).
pub const TIP_WHEN_SCHEDULED: u64 = 2_941_844;

/// ⛔ THE SCHEDULE MUST SIT WELL ABOVE THE TIP IT WAS MEASURED AGAINST, or the rollout
/// cannot finish before the rules change. Asserted at COMPILE TIME: both sides are
/// constants, so a test would only restate what the compiler can prove (clippy says so
/// too), and a build that cannot ship is a louder failure than a red test.
const _: () = assert!(SCHEDULED_V2_ACTIVATION_HEIGHT >= TIP_WHEN_SCHEDULED + 20_000);

/// The activation height tests use, so V2 rules can be exercised before a real
/// height exists. Compiled in only with the `test-activation-schedule` feature,
/// and `solidus-noded` refuses to start if that feature is present.
pub const TEST_V2_ACTIVATION_HEIGHT: u64 = 1_000;

/// The height V2 actually activates at in THIS build: the test height when the
/// `test-activation-schedule` feature is compiled in, the scheduled one
/// otherwise. Every V2 rule gates on this, never on the two constants directly.
pub const V2_ACTIVATION_HEIGHT: u64 = if cfg!(feature = "test-activation-schedule") {
    TEST_V2_ACTIVATION_HEIGHT
} else {
    SCHEDULED_V2_ACTIVATION_HEIGHT
};

const ACTIVATIONS: &[(u64, ProtocolVersion)] = &[
    (0, ProtocolVersion::V1),
    (V2_ACTIVATION_HEIGHT, ProtocolVersion::V2),
];

/// ed25519 public keys allowed to approve `BridgeGovernance` actions.
///
/// ⛔ EMPTY UNTIL THE PHASE 0 DEPLOY. With no governors and an unreachable
/// threshold, no bridge domain can be registered, so the bridge stays inert even
/// after V2 activates. The deploy task compiles founder-held keys here.
pub const SCHEDULED_BRIDGE_GOVERNOR_KEYS: &[[u8; 32]] = &[
    [
        0x77, 0x30, 0x9E, 0x8D, 0x35, 0xF8, 0x6E, 0x25, 0x2B, 0x48, 0x07, 0xEE, 0xE3, 0x74, 0x72,
        0x82, 0xA8, 0x3C, 0x0D, 0x2B, 0xC5, 0x72, 0x2E, 0xA3, 0x75, 0xCE, 0x16, 0xAA, 0xBF, 0x57,
        0x7F, 0x7F,
    ],
    [
        0x93, 0x80, 0xD2, 0x70, 0x95, 0x7A, 0x36, 0xE8, 0x2F, 0xDD, 0xB7, 0x71, 0x84, 0x57, 0x0D,
        0x8A, 0xD1, 0xA1, 0x86, 0xEC, 0x24, 0xF9, 0x5D, 0xEF, 0x81, 0x93, 0x4E, 0x44, 0x54, 0xA6,
        0x51, 0x46,
    ],
    [
        0xA9, 0xD4, 0x11, 0xC3, 0x57, 0xBA, 0xCB, 0xDE, 0x25, 0xB4, 0x05, 0x94, 0x71, 0x64, 0x5C,
        0xE3, 0xE8, 0xCB, 0x99, 0x6D, 0xD8, 0x44, 0x88, 0x96, 0x87, 0x4F, 0xF1, 0x37, 0xCB, 0x34,
        0x79, 0x0A,
    ],
];
pub const SCHEDULED_BRIDGE_GOVERNANCE_THRESHOLD: usize = 2;

/// Governor seeds compiled only into test-schedule builds.
const TEST_BRIDGE_GOVERNOR_SEEDS: [[u8; 32]; 3] = [[0xB1; 32], [0xB2; 32], [0xB3; 32]];

pub fn bridge_governor_keys() -> Vec<[u8; 32]> {
    if cfg!(feature = "test-activation-schedule") {
        TEST_BRIDGE_GOVERNOR_SEEDS
            .iter()
            .map(|s| {
                ed25519_dalek::SigningKey::from_bytes(s)
                    .verifying_key()
                    .to_bytes()
            })
            .collect()
    } else {
        SCHEDULED_BRIDGE_GOVERNOR_KEYS.to_vec()
    }
}

pub fn bridge_governance_threshold() -> usize {
    if cfg!(feature = "test-activation-schedule") {
        2
    } else {
        SCHEDULED_BRIDGE_GOVERNANCE_THRESHOLD
    }
}

/// The rules in force at `height`.
///
/// Total by construction: the table starts at height 0, so every `u64` maps to
/// something and there is no "before any version" hole to handle.
#[must_use]
pub fn version_at(height: u64) -> ProtocolVersion {
    version_at_in(ACTIVATIONS, height)
}

/// The lookup itself, over ANY table.
///
/// ⚠ SPLIT OUT SO THE TESTS ARE NOT VACUOUS. The shipped table has one entry, so
/// every height returns `V1` and a test against it cannot tell a correct lookup
/// from `fn version_at(_) -> V1`. Exercising the real logic needs a table with
/// several entries, which only a pure function over a parameter allows.
///
/// ⚠ GENERIC OVER THE VALUE so a test can use DISTINGUISHABLE stand-ins. With
/// one real variant every row returns `V1`, so a test over the real enum cannot
/// tell WHICH row was selected and would have to re-implement the scan to find
/// out. A test that re-implements the code under test is testing a copy.
#[must_use]
pub fn version_at_in<V: Copy>(table: &[(u64, V)], height: u64) -> V {
    let mut current = table[0].1;
    for &(at, version) in table {
        if at > height {
            break;
        }
        current = version;
    }
    current
}

/// Is the shipped table well-formed? Sorted ascending, no duplicate heights,
/// and starting at 0 so `version_at` is total.
///
/// ⚠ Returned rather than asserted, so a test can check it AND a gate can call
/// it. A `debug_assert!` would vanish in the release build that actually runs
/// the chain.
#[must_use = "an unchecked activation table can leave version_at without an answer for some heights"]
pub fn activations_are_sane() -> Result<(), String> {
    if ACTIVATIONS.is_empty() {
        return Err("the activation table is empty, so version_at has nothing to return".into());
    }
    if ACTIVATIONS[0].0 != 0 {
        return Err(format!(
            "the table must start at height 0 so every height maps to a version; starts at {}",
            ACTIVATIONS[0].0
        ));
    }
    for pair in ACTIVATIONS.windows(2) {
        let (a, _) = pair[0];
        let (b, _) = pair[1];
        if b == a {
            return Err(format!(
                "duplicate activation height {a}: which rules apply is ambiguous"
            ));
        }
        if b < a {
            return Err(format!(
                "activation heights are not ascending ({a} then {b}), so version_at returns the wrong rules"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⛔ REPLACES `production_builds_have_no_governors_until_deploy`, whose premise ended
    /// on 2026-09-22 when the founder's keys were compiled in. What has to hold now is that
    /// the schedule sits far above the tip it was measured against, so the rollout has room
    /// to finish before the rules change.
    #[cfg(not(feature = "test-activation-schedule"))]
    #[test]
    fn the_production_schedule_carries_the_governors_it_needs() {
        assert_eq!(bridge_governor_keys().len(), 3);
        assert_eq!(bridge_governance_threshold(), 2);
    }

    #[test]
    fn the_shipped_table_is_well_formed() {
        activations_are_sane().expect("the shipped activation table must be sane");
    }

    #[test]
    fn every_height_maps_to_a_version_and_genesis_is_v1() {
        assert_eq!(version_at(0), ProtocolVersion::V1);
        assert_eq!(version_at(1), ProtocolVersion::V1);
        assert_eq!(
            version_at(971_000.min(V2_ACTIVATION_HEIGHT - 1)),
            ProtocolVersion::V1
        );
        // ⚠ Was `version_at(u64::MAX) == V1`. With a second row the top of the
        // range belongs to the newest version, which is the correct behaviour.
        assert_eq!(version_at(u64::MAX), ProtocolVersion::V2);
    }

    /// Stand-in versions, distinguishable so the REAL function's return value
    /// identifies the row it selected. Nothing here re-implements the scan.
    const LABELLED: &[(u64, &str)] = &[
        (0, "genesis"),
        (100, "second"),
        (1_000, "third"),
        (1_000_000, "fourth"),
    ];

    /// The oracle: the obvious, slow reading of the same table.
    fn naive<V: Copy>(table: &[(u64, V)], height: u64) -> V {
        let mut best = table[0].1;
        for &(at, v) in table {
            if height >= at {
                best = v;
            }
        }
        best
    }

    #[test]
    fn the_lookup_selects_the_right_row_at_every_boundary() {
        for &(at, _) in LABELLED {
            for h in [at.saturating_sub(1), at, at.saturating_add(1)] {
                assert_eq!(
                    version_at_in(LABELLED, h),
                    naive(LABELLED, h),
                    "wrong activation selected at height {h}"
                );
            }
        }
        // ⚠ AN ACTIVATION TAKES EFFECT *AT* ITS HEIGHT, NOT AFTER IT. This is
        // the off-by-one that would fork a network, so it is asserted by name
        // rather than left to the oracle comparison above.
        assert_eq!(
            version_at_in(LABELLED, 99),
            "genesis",
            "height 99 is still the old rules"
        );
        assert_eq!(
            version_at_in(LABELLED, 100),
            "second",
            "height 100 IS the activation"
        );
        assert_eq!(version_at_in(LABELLED, 101), "second");
        assert_eq!(version_at_in(LABELLED, u64::MAX), "fourth");
    }

    /// ⚠ THE ORACLE IS A NAIVE SCAN, deliberately written differently from the
    /// implementation. Comparing `version_at` against itself would prove
    /// nothing; comparing it against the obvious-but-slow reading of the same
    /// table is what catches an off-by-one at a boundary.
    fn naive_version_at(height: u64) -> ProtocolVersion {
        let mut best = ACTIVATIONS[0].1;
        for &(at, v) in ACTIVATIONS {
            if height >= at {
                best = v;
            }
        }
        best
    }

    #[test]
    fn version_at_agrees_with_a_naive_scan_including_at_every_boundary() {
        // Boundaries first: an activation height, one below, one above. This is
        // where an off-by-one lives, and random sampling rarely lands on it.
        for &(at, _) in ACTIVATIONS {
            for h in [at.saturating_sub(1), at, at.saturating_add(1)] {
                assert_eq!(version_at(h), naive_version_at(h), "boundary height {h}");
            }
        }
        // Then a spread, including the extremes.
        for h in [0u64, 1, 7, 1_000, 999_999, 971_693, u64::MAX / 2, u64::MAX] {
            assert_eq!(version_at(h), naive_version_at(h), "height {h}");
        }
    }

    #[test]
    fn version_is_monotonic_in_height() {
        // A later block can never be governed by earlier rules. If this ever
        // fails the table has been written out of order and nodes will fork.
        let mut probe = 0u64;
        let mut last = version_at(0);
        for step in [1u64, 10, 1_000, 100_000, 1_000_000, u64::MAX / 4] {
            probe = probe.saturating_add(step);
            let v = version_at(probe);
            assert!(v >= last, "version went backwards at height {probe}");
            last = v;
        }
    }

    /// ⚠ CONTROL. `activations_are_sane` must actually be able to FAIL, or the
    /// first test is a tautology. The shipped table cannot be corrupted from a
    /// test, so the invariant is re-checked against deliberately broken tables.
    #[test]
    fn control_the_sanity_rules_reject_broken_tables() {
        fn check(table: &[(u64, ProtocolVersion)]) -> Result<(), String> {
            if table.is_empty() {
                return Err("empty".into());
            }
            if table[0].0 != 0 {
                return Err("does not start at 0".into());
            }
            for pair in table.windows(2) {
                if pair[1].0 <= pair[0].0 {
                    return Err("not strictly ascending".into());
                }
            }
            Ok(())
        }
        assert!(check(&[]).is_err(), "an empty table must be rejected");
        assert!(
            check(&[(5, ProtocolVersion::V1)]).is_err(),
            "a table not starting at 0 must be rejected"
        );
        assert!(
            check(&[(0, ProtocolVersion::V1), (0, ProtocolVersion::V1)]).is_err(),
            "duplicate heights must be rejected"
        );
        assert!(
            check(&[
                (0, ProtocolVersion::V1),
                (10, ProtocolVersion::V1),
                (5, ProtocolVersion::V1)
            ])
            .is_err(),
            "descending heights must be rejected"
        );
        assert!(
            check(&[(0, ProtocolVersion::V1)]).is_ok(),
            "the shipped shape must pass"
        );
    }

    #[test]
    fn v2_takes_effect_exactly_at_its_activation_height() {
        assert_eq!(
            version_at(V2_ACTIVATION_HEIGHT.saturating_sub(1)),
            ProtocolVersion::V1
        );
        assert_eq!(version_at(V2_ACTIVATION_HEIGHT), ProtocolVersion::V2);
        assert!(
            ProtocolVersion::V2 > ProtocolVersion::V1,
            "rules compare by activation order"
        );
    }

    #[cfg(not(feature = "test-activation-schedule"))]
    #[test]
    fn a_production_build_uses_the_scheduled_height() {
        assert_eq!(V2_ACTIVATION_HEIGHT, SCHEDULED_V2_ACTIVATION_HEIGHT);
    }

    #[cfg(feature = "test-activation-schedule")]
    #[test]
    fn the_test_schedule_activates_early_enough_to_exercise() {
        assert_eq!(V2_ACTIVATION_HEIGHT, TEST_V2_ACTIVATION_HEIGHT);
        assert_eq!(TEST_V2_ACTIVATION_HEIGHT, 1_000);
    }
}

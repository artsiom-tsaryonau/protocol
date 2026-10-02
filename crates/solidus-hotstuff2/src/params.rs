//! Consensus parameters compiled into the binary.
//!
//! ⛔ NEVER CONFIGURABLE PER NODE. Two nodes disagreeing about a value here fork.

use crate::types::View;

/// First view signed and verified under the PoP ciphersuite.
///
/// ⛔ `u64::MAX` MEANS "NOT SCHEDULED". Only the phase 0 deploy task in
/// the bridge rollout plan (phase 0b, chain bridge module) sets a real view,
/// after every validator runs a binary that has this code and a PoP in config.
pub const POP_ACTIVATION_VIEW: View = 3_150_000;

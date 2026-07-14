// Production hardening: forbid panic-via-unwrap/expect outside tests. Lifted
// in #[cfg(test)] modules because tests use `.unwrap()` extensively. Sites
// that DELIBERATELY use expect for infallible POD serialization (types.rs
// header/QC serde; account.rs Account serde) carry a per-line
// `#[allow(clippy::expect_used)]` with a doc-comment justification.
//
// Aligned with the workspace consensus/ coding rule:
// "Never .unwrap() or .expect() outside of tests — use ? or handle explicitly."
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

pub mod hotstuff;
pub mod leader;
pub mod ledger;
pub mod mempool;
pub mod pacemaker;
pub mod proposer;
pub mod slashing;
pub mod types;

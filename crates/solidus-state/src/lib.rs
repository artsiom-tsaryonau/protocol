// Production hardening: forbid panic-via-unwrap/expect outside tests. Sites
// that DELIBERATELY use expect for infallible POD bincode serialization
// (account.rs Account serde) carry a per-line `#[allow(clippy::expect_used)]`
// with a doc-comment justification.
#![cfg_attr(not(test), warn(clippy::unwrap_used, clippy::expect_used))]

pub mod account;
pub mod executor;
pub mod store;
pub mod tree;

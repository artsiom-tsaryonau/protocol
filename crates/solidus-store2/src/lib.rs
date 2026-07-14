//! # solidus-store2 — v2 storage hardening (Stage 4)
//!
//! Per §4.6 of the rebuild plan:
//! - **Binary end-to-end**: every record bincode/raw bytes; serde_json
//!   never enters this crate (state-record leaf encodings are whatever
//!   the executor wrote — see the R-WIRE boundary note in
//!   `docs/v2-wire-format.md`).
//! - **One `WriteBatch` per block** ([`Store2::persist_block`]): the
//!   block's whole delta + receipts + block bytes + canon pointer land
//!   atomically — never a per-tx `put`.
//! - **Hot/cold split**: state spaces (accounts, DIDs, credentials,
//!   validators, indexes, meta) are hot CFs tuned for point reads; blocks
//!   / receipts / batches are cold, tuned for bulk writes, and prunable
//!   past a block-age horizon ([`Store2::prune_cold_before`]).
//! - **`Profile::Testnet` vs `Profile::Mainnet`** tuning switch — the
//!   live chain's conservative small-VPS numbers stop being the default.
//!
//! The store implements the executor's [`solidus_exec::StateReader`], so
//! blocks execute directly against RocksDB; the boot path rebuilds the
//! in-memory root forest from the hot CFs (documented trade-off: O(state)
//! once at startup; incremental node persistence is a later optimization
//! and does not change any interface).

pub mod profile;
pub mod store;

pub use profile::Profile;
pub use store::{Store2, StoreError2, CF_COLD, CF_HOT};

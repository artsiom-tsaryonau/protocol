//! # solidus-state-tree — incremental 4-sub-tree state root (v2)
//!
//! Part of the v2 rebuild (parallel network, new chain-id). Ports the hashing
//! of the live `solidus-state::tree` sparse Merkle tree **exactly** — same
//! BLAKE3 leaf/node formulas, same canonical internal-node paths, same
//! precomputed empty-hash ladder — so a v2 tree over the same final
//! `key → value` map produces a **byte-identical root** to the live chain's
//! tree. That equality is differential-tested against the legacy crate in
//! `tests/legacy_tree_parity.rs` and is the foundation of the Stage-0 parity
//! anchor.
//!
//! What changes vs the live implementation:
//! - **In-memory node store** instead of RocksDB-backed nodes. Persistence
//!   is a `solidus-store2` concern (Stage 4); the root math lives here.
//! - **Used incrementally.** The live block path rescans whole column
//!   families and rebuilds all four trees every block — O(state). The v2
//!   executor calls [`StateForest::apply`] per *touched* leaf, O(touched ·
//!   256), and the root reflects every leaf ever applied.
//!
//! The global root combines the four sub-tree roots (accounts, DIDs,
//! credentials, validators) exactly like the live `global_state_root`.

pub mod global_root;
pub mod proof;
pub mod tree;

pub use global_root::{global_state_root, StateForest};
pub use proof::{verify_inclusion, InclusionProof};
pub use tree::{flip_bit, get_bit, zero_bits_below, SparseMerkleTree, TreeId, EMPTY_ROOT};

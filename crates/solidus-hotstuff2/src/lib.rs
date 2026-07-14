//! # solidus-hotstuff2 — HotStuff-2 two-chain BFT (Stage 1)
//!
//! Implements, per BD-3 / §4.4 of the rebuild plan:
//!
//! - **2-chain consecutive-view commit** — `commit(B@v) ⇔ QC(B@v) ∧
//!   QC(child(B)@v+1)` — with the Jolteon-style lock (`high_qc`) and
//!   one-vote-per-view rule. Safety argument in `docs/v2-consensus.md`;
//!   spec in `tla+/HotStuff2Commit.tla`.
//! - **Sub-second pacemaker**: 400ms base, ×2 backoff capped at 3200ms
//!   (replaces the live 2000→16000ms ladder).
//! - **Gossip-shaped dissemination by construction**: the core's action
//!   vocabulary has `BroadcastProposal` and point-to-point `SendVote`
//!   only — there is no way to express an O(N) per-peer proposal path.
//! - **Batch-certificate blocks**: bodies are `Vec<BatchCertificate>`
//!   digests (`solidus-mempool-dag`), never transactions.
//! - **Pure, event-driven core** (no I/O, no timers, no wall-clock):
//!   the node layer owns sockets/timers and can place CPU-heavy handlers
//!   (BLS aggregation/verification) on a blocking pool at 21-validator
//!   scale.
//!
//! Stage-1 acceptance tracking: 4-node finality measured in
//! `tests/four_node.rs`; TLA+ spec completed alongside this code, TLC run
//! **pending TLC install** (gate logged in the plan).

pub mod aggregate;
pub mod core;
pub mod error;
pub mod leader;
pub mod pacemaker;
pub mod safety;
pub mod slashing;
pub mod types;

pub use crate::core::{
    Action, CommittedBlock, ConsensusCore, CoreConfig, EmptyPayloads, PayloadProvider,
};
pub use error::ConsensusError;
pub use leader::{LeaderElector, RoundRobin};
pub use pacemaker::{Pacemaker, BASE_TIMEOUT_MS, MAX_TIMEOUT_MS};
pub use safety::SafetyState;
pub use slashing::{Equivocation, EquivocationDetector, EvidenceError};
pub use types::{
    proposal_message, timeout_message, vote_message, Block2, BlockHeader2, Committee, Proposal,
    QuorumCert, TimeoutCert, TimeoutVote, ValidatorIndex, View, Vote,
};

/// The frozen commit-rule statement, mirrored by the TLA+ spec.
pub const COMMIT_RULE: &str =
    "commit(B@v) ⇔ QC(B@v) ∧ QC(child(B)@v+1) — consecutive-view two-chain";

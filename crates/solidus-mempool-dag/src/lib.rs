//! # solidus-mempool-dag — Narwhal-style mempool (Stage 2)
//!
//! The load-bearing decision (frozen at Stage 0): **consensus orders
//! 32-byte batch digests, never transaction bodies.** A v2 block body is
//! `Vec<BatchCertificate>`; the executor resolves bodies from worker-local
//! storage via [`BatchResolver`] at execution time (BD-4). Consensus
//! messages stay in the kilobytes at full block capacity — measured in
//! `solidus-hotstuff2/tests/header_size.rs`.
//!
//! Stage-2 machinery (this code):
//! - [`worker::Worker`] — event-driven batcher: seals batches at
//!   size/count thresholds (or flush timers), disseminates bodies to peer
//!   workers, collects BLS availability acks, and emits
//!   [`BatchCertificate`]s at quorum. Own-ack counted first
//!   (regression-guarded).
//! - [`store::BatchStore`] — digest-verified worker-local storage; the
//!   executor's [`BatchResolver`] view. (RocksDB persistence: Stage 4.)
//! - [`primary::CertPool`] — certified digests awaiting ordering, with
//!   draft/requeue/retire lifecycle wired to consensus commits.
//! - Attestations aggregate over a shared per-batch message
//!   ([`avail_message`]), so certificates verify with
//!   `fast_aggregate_verify` — one aggregation pattern across the stack.
//!
//! Availability quorum = the consensus quorum (`⌈(n+f+1)/2⌉` ≥ 2f+1), so
//! every certified batch is held by ≥ f+1 honest validators.

pub mod primary;
pub mod store;
pub mod types;
pub mod worker;

pub use primary::{CertPool, DraftId};
pub use store::{BatchStore, SharedBatchStore, SharedResolver};
pub use types::{
    avail_message, availability_quorum, Attestation, Batch, BatchAck, BatchCertificate,
    BatchDigest, BatchResolver, MempoolError, ResolveError,
};
pub use worker::{Worker, WorkerAction, WorkerConfig};

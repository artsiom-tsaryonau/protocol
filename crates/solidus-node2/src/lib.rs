//! # solidus-node2 — the integrated v2 validator node (node-wiring stage)
//!
//! Ties the v2 crate set into one runnable object: HotStuff-2 consensus
//! (`solidus-hotstuff2`) + Narwhal DAG mempool (`solidus-mempool-dag`) +
//! the two-lane executor (`solidus-exec`) + storage (`solidus-store2`),
//! plus the mainnet-candidate topology config (§4.9).
//!
//! The [`Node`] is event-driven and I/O-free (same shape as the
//! sub-crate cores): it consumes [`NodeInput`] and emits [`NodeOutput`].
//! The real network binding is `solidus-p2p2` (libp2p gossipsub for
//! proposals/QCs/TCs/batches, point-to-point for votes/acks) and the RPC
//! edge is `solidus-rpc2` — both flagged as the remaining mechanical
//! node-layer work. The in-process `tests/localnet.rs` harness routes the
//! outputs over tokio loopback channels and measures end-to-end
//! throughput + finality on this box.

pub mod config;
pub mod node;

pub use config::{NodeTuning, TopologyConfig, ValidatorSpec};
pub use node::{ExecAnchor, Node, NodeInput, NodeOutput};

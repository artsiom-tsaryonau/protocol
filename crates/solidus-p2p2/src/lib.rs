//! # solidus-p2p2 — the v2 networking layer (node-layer)
//!
//! Gossipsub for the broadcast classes (proposals, QCs, TCs, timeout
//! votes, batches), point-to-point request/response for votes and acks
//! (§4.4 — the proposer needs N-of-N, not broadcast). Three layers:
//!
//! - [`wire`] — the bincode `NetMessage` envelope + chain-scoped gossip
//!   topics. Deterministic, fully unit-tested.
//! - [`router`] — pure mapping between [`solidus_node2`]'s effects/inputs
//!   and network actions. Tested against a real consensus core's effects.
//! - [`behaviour`] — the real libp2p 0.54 swarm (gossipsub +
//!   request/response); a 2-node TCP-loopback test proves the gossip layer
//!   actually delivers a round-tripped `NetMessage`.
//!
//! The design intentionally keeps `Node` transport-free: the swarm's event
//! loop calls `router::route_output` on each `NodeOutput` and feeds
//! `router::route_inbound` on each received frame into `Node::step`. That
//! event-loop glue + a live N-validator multi-process run is the mechanical
//! remainder (the `solidus-node2` localnet harness stands in for it
//! in-process).

pub mod behaviour;
pub mod router;
pub mod runner;
pub mod wire;

pub use behaviour::{
    build_swarm, build_swarm_with_keypair, dial, publish, send_direct, PeerDirectory,
    SolidusBehaviour,
};
pub use router::{route_inbound, route_output, Outbound};
pub use runner::{warm_up, Executed, P2pRunner};
pub use wire::{NetMessage, Topic};

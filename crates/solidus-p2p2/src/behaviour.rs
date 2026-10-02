//! The real libp2p transport: gossipsub for broadcast topics +
//! request/response for point-to-point votes/acks. A thin [`Network`]
//! handle wraps the swarm with publish / send-to / next-event.
//!
//! Scope honesty: a full N-validator consensus run over this transport is
//! multi-process (each node a real OS process with its own listener) — the
//! `solidus-node2` localnet harness substitutes loopback channels for
//! exactly that reason. What IS verified in-process here (`tests` +
//! `two_node_gossip.rs`) is that the gossipsub layer actually delivers and
//! round-trips a `NetMessage` between two real swarms over TCP loopback —
//! the load-bearing "does the wire work" check. Wiring the swarm's event
//! stream to `Node::step` is the mechanical remainder.

use std::collections::HashMap;
use std::time::Duration;

use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use libp2p::request_response::{self, ProtocolSupport};
use libp2p::swarm::NetworkBehaviour;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};

use crate::wire::Topic;

/// Point-to-point protocol id for votes/acks.
const P2P_PROTOCOL: &str = "/solidus-v2/direct/1";

/// The composed behaviour: gossip + direct request/response (bytes both
/// ways; the response is an empty ack).
#[derive(NetworkBehaviour)]
pub struct SolidusBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub direct: request_response::cbor::Behaviour<Vec<u8>, Vec<u8>>,
}

/// Errors constructing the transport.
#[derive(thiserror::Error, Debug)]
pub enum P2pError {
    #[error("transport build error: {0}")]
    Build(String),
    #[error("gossipsub error: {0}")]
    Gossipsub(String),
}

/// Build a swarm for one validator with a fresh random identity.
/// `chain_id` scopes the gossip topics; the node subscribes to every
/// broadcast topic.
pub fn build_swarm(chain_id: u64) -> Result<Swarm<SolidusBehaviour>, P2pError> {
    build_swarm_with_keypair(chain_id, libp2p::identity::Keypair::generate_ed25519())
}

/// Build a swarm with a **specific** libp2p keypair — so the caller knows
/// this validator's `PeerId` in advance (the topology config maps
/// validator index → peer id, and point-to-point routing needs it).
pub fn build_swarm_with_keypair(
    chain_id: u64,
    keypair: libp2p::identity::Keypair,
) -> Result<Swarm<SolidusBehaviour>, P2pError> {
    let mut swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )
        .map_err(|e| P2pError::Build(e.to_string()))?
        .with_behaviour(|key| {
            let gossip_cfg = gossipsub::ConfigBuilder::default()
                .validation_mode(ValidationMode::Strict)
                // Small mesh so a modest committee (4–21) forms a full mesh
                // instead of stalling below the default mesh_n_low of 5.
                .mesh_n_low(2)
                .mesh_n(3)
                .mesh_n_high(6)
                .mesh_outbound_min(1)
                .heartbeat_interval(std::time::Duration::from_millis(200))
                .build()
                .map_err(|e| e.to_string())?;
            let gossipsub =
                gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossip_cfg)?;
            let direct = request_response::cbor::Behaviour::new(
                [(StreamProtocol::new(P2P_PROTOCOL), ProtocolSupport::Full)],
                request_response::Config::default(),
            );
            Ok(SolidusBehaviour { gossipsub, direct })
        })
        .map_err(|e| P2pError::Build(e.to_string()))?
        // ⛔ WITHOUT THIS, libp2p 0.54 CLOSES AN IDLE CONNECTION IMMEDIATELY.
        // `PoolConfig`'s default is `Duration::ZERO` (measured in
        // libp2p-swarm-0.45.1/src/connection/pool.rs), so a connection survives
        // only while some behaviour actively reports keep-alive. Gossipsub does
        // that for explicit/mesh peers, which is the ONLY reason the committee
        // stays connected today — a transport property held up by a side effect
        // of the gossip layer.
        //
        // The request/response paths cannot rely on that. A block-body or
        // block-range fetch is a round trip on a connection that carries no
        // gossip traffic of its own, and it is issued exactly when a node is
        // behind and least likely to be in anyone's mesh. Measured: a fetch
        // over a freshly dialled connection lost the connection to
        // `KeepAliveTimeout` before the request was dispatched.
        //
        // 30s is chosen to outlast a fetch round trip plus retries, not to keep
        // idle strangers around; committee links are held open by gossip anyway.
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    // Subscribe to every broadcast topic.
    for topic in Topic::ALL {
        let t = gossipsub::IdentTopic::new(topic.ident(chain_id));
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&t)
            .map_err(|e| P2pError::Gossipsub(e.to_string()))?;
    }

    Ok(swarm)
}

/// Committee-index ↔ PeerId directory for point-to-point routing. The
/// node layer fills this from the topology config as peers connect.
#[derive(Default)]
pub struct PeerDirectory {
    by_index: HashMap<u32, PeerId>,
}

impl PeerDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&mut self, index: u32, peer: PeerId) {
        self.by_index.insert(index, peer);
    }

    pub fn peer(&self, index: u32) -> Option<&PeerId> {
        self.by_index.get(&index)
    }

    /// Known committee indices, ascending.
    ///
    /// Sorted deliberately: `HashMap` iteration order varies per process, and a
    /// backfill that picks a different peer on every attempt for no reason is
    /// harder to reason about than one that rotates predictably.
    pub fn indices(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.by_index.keys().copied().collect();
        v.sort_unstable();
        v
    }
}

/// Publish `bytes` to a gossip topic on `swarm`. Ignores the
/// "no peers subscribed" transient (a lone node has no one to publish to
/// yet) - those messages simply have no audience.
///
/// The variant was named `InsufficientPeers` until gossipsub 0.50 renamed it to
/// `NoPeersSubscribedToTopic`. Same condition, clearer name: it means nobody is subscribed to THIS
/// topic, not that the swarm has too few peers overall.
pub fn publish(
    swarm: &mut Swarm<SolidusBehaviour>,
    chain_id: u64,
    topic: Topic,
    bytes: Vec<u8>,
) -> Result<(), P2pError> {
    let t = gossipsub::IdentTopic::new(topic.ident(chain_id));
    match swarm.behaviour_mut().gossipsub.publish(t, bytes) {
        Ok(_) => Ok(()),
        Err(gossipsub::PublishError::NoPeersSubscribedToTopic) => Ok(()),
        Err(e) => Err(P2pError::Gossipsub(e.to_string())),
    }
}

/// Send `bytes` point-to-point to a committee member (votes/acks).
pub fn send_direct(
    swarm: &mut Swarm<SolidusBehaviour>,
    directory: &PeerDirectory,
    peer_index: u32,
    bytes: Vec<u8>,
) {
    if let Some(peer) = directory.peer(peer_index) {
        swarm.behaviour_mut().direct.send_request(peer, bytes);
    }
    // No mapping yet ⇒ drop (the peer hasn't connected); consensus
    // liveness tolerates a missed vote and re-drives via the pacemaker.
}

/// Send `bytes` to a peer we are already talking to, addressed by the
/// transport's own `PeerId` rather than by anything the message claimed.
///
/// ⛔ USE THIS TO ANSWER A REQUEST. Replying to an index carried INSIDE an
/// untrusted frame is a reflection amplifier; the transport-level sender is not
/// forgeable by the sender.
pub fn send_direct_to_peer(swarm: &mut Swarm<SolidusBehaviour>, peer: PeerId, bytes: Vec<u8>) {
    swarm.behaviour_mut().direct.send_request(&peer, bytes);
}

/// Dial a peer's listen address.
pub fn dial(swarm: &mut Swarm<SolidusBehaviour>, addr: Multiaddr) -> Result<(), P2pError> {
    swarm.dial(addr).map_err(|e| P2pError::Build(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swarm_builds_and_subscribes_all_topics() {
        // Construction alone exercises the whole behaviour composition +
        // topic subscription against real libp2p 0.54.
        let swarm = build_swarm(2).expect("swarm builds");
        // A fresh swarm has a stable local peer id.
        let _peer: PeerId = *swarm.local_peer_id();
    }

    #[test]
    fn peer_directory_roundtrip() {
        let mut dir = PeerDirectory::new();
        let id = PeerId::random();
        dir.set(3, id);
        assert_eq!(dir.peer(3), Some(&id));
        assert_eq!(dir.peer(9), None);
    }
}

//! Production libp2p transport backend for the consensus engine.
//!
//! # Architecture
//!
//! A background tokio task drives the libp2p [`Swarm`].  The public
//! [`LibP2PTransport`] communicates with it through a pair of channels:
//!
//! * `cmd_tx` — sends [`SwarmCmd`]s (Send/Broadcast) **to** the swarm task.
//! * `msg_rx` — receives decoded [`ConsensusMessage`]s **from** the swarm task.
//!
//! # Message routing
//!
//! * `NewBlock` / `NewTransaction` — published on gossipsub topic
//!   `/solidus/blocks/1.0.0` or `/solidus/txs/1.0.0` respectively.
//! * `Proposal` / `VoteMsg` / `TimeoutVoteMsg` — sent point-to-point via the
//!   custom request-response behaviour on `/solidus/consensus/1.0.0`.
//!
//! For broadcast of consensus messages (Proposal / Vote / Timeout), the
//! transport iterates over all known peers and sends an individual
//! request-response message to each one.

use crate::message::ConsensusMessage;
use crate::transport::{ConsensusTransport, PeerId, TransportError};

use async_trait::async_trait;
use libp2p::{
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt},
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identity::Keypair,
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    str::FromStr,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Public configuration types
// ---------------------------------------------------------------------------

/// Peer description used when bootstrapping the libp2p swarm.
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// The consensus peer index (maps to [`PeerId`] in the transport trait).
    pub index: usize,
    /// The libp2p [`PeerId`](libp2p::PeerId) encoded as a base58 string.
    pub peer_id: String,
    /// The multiaddr on which this peer is reachable.
    pub address: String,
}

/// Configuration for the [`LibP2PTransport`].
#[derive(Debug, Clone)]
pub struct LibP2PConfig {
    /// The address this node should listen on (e.g. `/ip4/0.0.0.0/tcp/0`).
    pub listen_addr: Multiaddr,
    /// Known peers in the validator set.
    pub peers: Vec<PeerConfig>,
    /// This node's own consensus index.
    pub node_index: usize,
}

// ---------------------------------------------------------------------------
// Request / Response payload
// ---------------------------------------------------------------------------

/// Wrapper that carries a consensus index alongside the message so the
/// receiver can reconstruct which consensus peer sent it.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsensusEnvelope {
    /// Sender's consensus peer index.
    from: usize,
    /// The actual consensus message.
    msg: ConsensusMessage,
}

/// The response we send back after receiving a request (an ACK).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Ack;

// ---------------------------------------------------------------------------
// Custom request-response codec
// ---------------------------------------------------------------------------

/// A length-prefixed JSON codec for [`ConsensusEnvelope`] / [`Ack`].
///
/// Wire format: `[u32 big-endian length][JSON bytes]`
#[derive(Debug, Clone, Default)]
struct ConsensusCodec;

/// Protocol name used during negotiation.
#[derive(Debug, Clone)]
struct ConsensusProtocol;

impl AsRef<str> for ConsensusProtocol {
    fn as_ref(&self) -> &str {
        "/solidus/consensus/1.0.0"
    }
}

#[async_trait]
impl Codec for ConsensusCodec {
    type Protocol = ConsensusProtocol;
    type Request = ConsensusEnvelope;
    type Response = Ack;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed_json(io).await
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        read_length_prefixed_json(io).await
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed_json(io, &req).await
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_length_prefixed_json(io, &res).await
    }
}

async fn read_length_prefixed_json<T, V>(io: &mut T) -> io::Result<V>
where
    T: AsyncRead + Unpin + Send,
    V: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Guard against absurdly large allocations.
    const MAX: usize = 4 * 1024 * 1024; // 4 MiB
    if len > MAX {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message too large: {len} bytes"),
        ));
    }

    let mut buf = vec![0u8; len];
    io.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

async fn write_length_prefixed_json<T, V>(io: &mut T, value: &V) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
    V: Serialize,
{
    let bytes =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = bytes.len() as u32;
    io.write_all(&len.to_be_bytes()).await?;
    io.write_all(&bytes).await?;
    io.flush().await
}

// ---------------------------------------------------------------------------
// Combined NetworkBehaviour
// ---------------------------------------------------------------------------

#[derive(NetworkBehaviour)]
struct SolidusBehaviour {
    gossipsub: gossipsub::Behaviour,
    rr: request_response::Behaviour<ConsensusCodec>,
}

// ---------------------------------------------------------------------------
// Internal swarm commands
// ---------------------------------------------------------------------------

enum SwarmCmd {
    /// Send a targeted message to a specific libp2p peer.
    Send {
        peer_id: libp2p::PeerId,
        from_index: usize,
        msg: ConsensusMessage,
    },
    /// Publish a message to a gossipsub topic.
    Publish {
        topic: IdentTopic,
        data: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// LibP2PTransport
// ---------------------------------------------------------------------------

/// Production transport that wires the consensus engine to a real libp2p swarm.
///
/// Created via [`LibP2PTransport::start`].
pub struct LibP2PTransport {
    /// Our own consensus peer index.
    node_index: usize,
    /// Channel for sending commands to the background swarm task.
    cmd_tx: mpsc::UnboundedSender<SwarmCmd>,
    /// Channel for receiving decoded messages from the background swarm task.
    msg_rx: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage)>,
    /// Map from consensus index → libp2p PeerId for outbound `send`.
    peer_map: HashMap<usize, libp2p::PeerId>,
}

impl LibP2PTransport {
    /// Start the swarm, connect to all known peers, and return the transport.
    ///
    /// This spawns a background tokio task that owns the [`Swarm`].
    pub async fn start(config: LibP2PConfig) -> Result<Self, Box<dyn std::error::Error>> {
        // Build the peer map (consensus index → libp2p PeerId).
        let mut peer_map: HashMap<usize, libp2p::PeerId> = HashMap::new();
        for pc in &config.peers {
            if pc.index == config.node_index {
                continue; // skip self
            }
            let pid = libp2p::PeerId::from_str(&pc.peer_id)
                .map_err(|e| format!("invalid peer_id '{}': {e}", pc.peer_id))?;
            peer_map.insert(pc.index, pid);
        }

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<SwarmCmd>();
        let (msg_tx, msg_rx) = mpsc::unbounded_channel::<(PeerId, ConsensusMessage)>();

        let node_index = config.node_index;

        // Build the swarm inside an async block so all the libp2p builder
        // machinery runs in the correct async context.
        let mut swarm = build_swarm()?;

        // Listen on the configured address.
        swarm.listen_on(config.listen_addr.clone())?;

        // Register peer addresses so the swarm can dial them.
        for pc in &config.peers {
            if pc.index == config.node_index {
                continue;
            }
            let pid = libp2p::PeerId::from_str(&pc.peer_id)?;
            let addr: Multiaddr = pc.address.parse()?;
            swarm.add_peer_address(pid, addr);
        }

        // Subscribe to gossipsub topics.
        let blocks_topic = IdentTopic::new("/solidus/blocks/1.0.0");
        let txs_topic = IdentTopic::new("/solidus/txs/1.0.0");
        swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

        // Spawn the swarm event loop.
        tokio::spawn(swarm_task(
            swarm,
            cmd_rx,
            msg_tx,
            node_index,
            blocks_topic,
            txs_topic,
        ));

        Ok(Self {
            node_index,
            cmd_tx,
            msg_rx,
            peer_map,
        })
    }

    fn libp2p_peer_id(&self, peer: PeerId) -> Result<libp2p::PeerId, TransportError> {
        self.peer_map
            .get(&peer)
            .copied()
            .ok_or(TransportError::PeerDisconnected(peer))
    }
}

// ---------------------------------------------------------------------------
// ConsensusTransport impl
// ---------------------------------------------------------------------------

#[async_trait]
impl ConsensusTransport for LibP2PTransport {
    async fn send(&self, peer: PeerId, msg: ConsensusMessage) -> Result<(), TransportError> {
        let peer_id = self.libp2p_peer_id(peer)?;
        self.cmd_tx
            .send(SwarmCmd::Send {
                peer_id,
                from_index: self.node_index,
                msg,
            })
            .map_err(|_| TransportError::Closed)
    }

    async fn broadcast(&self, msg: ConsensusMessage) -> Result<(), TransportError> {
        match &msg {
            ConsensusMessage::NewBlock(_) => {
                let data = serde_json::to_vec(&msg)
                    .map_err(|e| TransportError::Serde(e.to_string()))?;
                let topic = IdentTopic::new("/solidus/blocks/1.0.0");
                self.cmd_tx
                    .send(SwarmCmd::Publish { topic, data })
                    .map_err(|_| TransportError::Closed)?;
            }
            ConsensusMessage::NewTransaction(_) => {
                let data = serde_json::to_vec(&msg)
                    .map_err(|e| TransportError::Serde(e.to_string()))?;
                let topic = IdentTopic::new("/solidus/txs/1.0.0");
                self.cmd_tx
                    .send(SwarmCmd::Publish { topic, data })
                    .map_err(|_| TransportError::Closed)?;
            }
            // Targeted consensus messages: send individually to all peers.
            ConsensusMessage::Proposal { .. }
            | ConsensusMessage::VoteMsg(_)
            | ConsensusMessage::TimeoutVoteMsg(_) => {
                for (&_idx, &peer_id) in &self.peer_map {
                    self.cmd_tx
                        .send(SwarmCmd::Send {
                            peer_id,
                            from_index: self.node_index,
                            msg: msg.clone(),
                        })
                        .map_err(|_| TransportError::Closed)?;
                }
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<(PeerId, ConsensusMessage), TransportError> {
        self.msg_rx.recv().await.ok_or(TransportError::Closed)
    }
}

// ---------------------------------------------------------------------------
// Swarm builder helper
// ---------------------------------------------------------------------------

fn build_swarm(
) -> Result<libp2p::Swarm<SolidusBehaviour>, Box<dyn std::error::Error>> {
    // Generate a random Ed25519 identity for this session.
    let keypair = Keypair::generate_ed25519();

    // Gossipsub configuration — anonymous (no signing required for validators
    // that rotate keys; message integrity is handled at the consensus layer).
    let gossipsub_cfg = gossipsub::ConfigBuilder::default()
        .build()
        .map_err(|e| format!("gossipsub config error: {e}"))?;
    let gossipsub = gossipsub::Behaviour::new(
        MessageAuthenticity::RandomAuthor,
        gossipsub_cfg,
    )
    .map_err(|e| format!("gossipsub init error: {e}"))?;

    // Request-response configuration with our custom JSON codec.
    let rr = request_response::Behaviour::new(
        [(ConsensusProtocol, ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    let behaviour = SolidusBehaviour { gossipsub, rr };

    let swarm = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_key| behaviour)?
        .build();

    Ok(swarm)
}

// ---------------------------------------------------------------------------
// Background swarm event loop
// ---------------------------------------------------------------------------

async fn swarm_task(
    mut swarm: libp2p::Swarm<SolidusBehaviour>,
    mut cmd_rx: mpsc::UnboundedReceiver<SwarmCmd>,
    msg_tx: mpsc::UnboundedSender<(PeerId, ConsensusMessage)>,
    node_index: usize,
    blocks_topic: IdentTopic,
    txs_topic: IdentTopic,
) {
    loop {
        tokio::select! {
            // ── inbound commands from the transport handle ──────────────
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    SwarmCmd::Send { peer_id, from_index, msg } => {
                        let envelope = ConsensusEnvelope { from: from_index, msg };
                        swarm.behaviour_mut().rr.send_request(&peer_id, envelope);
                    }
                    SwarmCmd::Publish { topic, data } => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic, data) {
                            warn!(node = node_index, "gossipsub publish error: {e}");
                        }
                    }
                }
            }

            // ── swarm events ────────────────────────────────────────────
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. }
                    )) => {
                        // Determine source from topic.
                        let topic_str = message.topic.as_str();
                        let is_block = topic_str == blocks_topic.hash().as_str();
                        let is_tx = topic_str == txs_topic.hash().as_str();

                        if is_block || is_tx {
                            match serde_json::from_slice::<ConsensusMessage>(&message.data) {
                                Ok(msg) => {
                                    // Gossipsub source is optional; use a sentinel 0 when absent.
                                    let from_peer: PeerId = 0;
                                    if msg_tx.send((from_peer, msg)).is_err() {
                                        return; // receiver dropped — shut down
                                    }
                                }
                                Err(e) => {
                                    warn!(node = node_index, "failed to deserialize gossipsub message: {e}");
                                }
                            }
                        }
                    }

                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Rr(
                        request_response::Event::Message {
                            peer: _,
                            message: request_response::Message::Request { request, channel, .. },
                        }
                    )) => {
                        let from_index = request.from;
                        let msg = request.msg;

                        // Send ACK back (fire-and-forget; ignore error).
                        let _ = swarm.behaviour_mut().rr.send_response(channel, Ack);

                        if msg_tx.send((from_index, msg)).is_err() {
                            return; // receiver dropped — shut down
                        }
                    }

                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Rr(
                        request_response::Event::OutboundFailure { peer, error, .. }
                    )) => {
                        debug!(node = node_index, %peer, "request-response outbound failure: {error}");
                    }

                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Rr(
                        request_response::Event::InboundFailure { peer, error, .. }
                    )) => {
                        debug!(node = node_index, %peer, "request-response inbound failure: {error}");
                    }

                    // All other swarm events (connection established/closed, etc.)
                    // are intentionally ignored — the consensus layer doesn't need them.
                    _ => {}
                }
            }
        }
    }
}

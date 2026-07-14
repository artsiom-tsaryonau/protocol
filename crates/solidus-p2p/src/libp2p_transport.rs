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
use crate::transport::{ConsensusTransport, PeerId, SourcePeer, TransportError};

use async_trait::async_trait;
use libp2p::{
    futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt},
    gossipsub::{self, IdentTopic, MessageAuthenticity},
    identify,
    identity::Keypair,
    kad::{self, store::MemoryStore},
    request_response::{self, Codec, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
    Multiaddr, SwarmBuilder,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Dial-retry backoff parameters
// ---------------------------------------------------------------------------

/// Initial backoff for the first dial retry after an OutgoingConnectionError.
const DIAL_RETRY_INITIAL: Duration = Duration::from_millis(250);
/// Cap on exponential backoff between retries — peers come back eventually,
/// so a long-tail backoff is cheaper than continued probing.
const DIAL_RETRY_MAX: Duration = Duration::from_secs(30);
/// Maximum number of retries before giving up on a peer (~20 doubling from
/// 250ms hits the 30s cap by attempt 8 → ~12 attempts at the cap before
/// giving up). After this we stop probing the peer at the application layer;
/// libp2p's own routing/discovery layer may re-introduce it.
const DIAL_RETRY_CAP: u32 = 20;

#[derive(Debug, Clone, Copy)]
struct DialRetryState {
    attempts: u32,
    next_at: Instant,
}

impl DialRetryState {
    fn new() -> Self {
        Self {
            attempts: 0,
            next_at: Instant::now(),
        }
    }

    /// Should this dial attempt fire NOW, or are we still backing off?
    fn ready(&self, now: Instant) -> bool {
        now >= self.next_at
    }

    /// Schedule the NEXT retry, applying exponential backoff with cap.
    /// Caller is responsible for checking `ready` before reading `attempts`
    /// to enforce `DIAL_RETRY_CAP`.
    fn schedule_next(&mut self, now: Instant) {
        // 250ms × 2^attempts, capped at DIAL_RETRY_MAX.
        let shift = self.attempts.min(20);
        let backoff = DIAL_RETRY_INITIAL.saturating_mul(1u32 << shift);
        let backoff = backoff.min(DIAL_RETRY_MAX);
        self.next_at = now + backoff;
        self.attempts = self.attempts.saturating_add(1);
    }
}

/// An inbound decoded message as delivered from the swarm task to the transport
/// handle: `(sender index, optional network source, message)`.
///
/// The source `libp2p::PeerId` is `Some` for point-to-point request-response
/// messages (so a responder can reply to an index-less requester) and `None`
/// for gossipsub messages (gossip carries no reliable per-message origin).
type InboundMsg = (PeerId, Option<libp2p::PeerId>, ConsensusMessage);

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
    /// This node's libp2p identity keypair (derive via
    /// [`crate::identity::libp2p_keypair_from_node_seed`]).
    pub keypair: libp2p::identity::Keypair,
    /// Kademlia bootstrap peers (dialable). Additive: empty = static-only
    /// behaviour (existing validators). Each entry seeds the routing table and
    /// is dialed at startup; a DHT `bootstrap()` then discovers further peers.
    pub bootstrap_peers: Vec<(libp2p::PeerId, Multiaddr)>,
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
    let len: u32 = bytes.len().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame too large: {} bytes exceeds u32::MAX", bytes.len()),
        )
    })?;
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
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<MemoryStore>,
}

// ---------------------------------------------------------------------------
// Internal swarm commands
// ---------------------------------------------------------------------------

// Variants differ significantly in size (Send carries a full
// ConsensusMessage; Publish carries a Vec<u8>). Boxing the larger
// variant would force an extra allocation per send on the hot path —
// not worth the savings for a channel-bounded internal command type.
#[allow(clippy::large_enum_variant)]
enum SwarmCmd {
    /// Send a targeted message to a specific libp2p peer.
    Send {
        peer_id: libp2p::PeerId,
        from_index: usize,
        msg: ConsensusMessage,
    },
    /// Publish a message to a gossipsub topic.
    Publish { topic: IdentTopic, data: Vec<u8> },
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
    /// This node's own libp2p PeerId (derived from its identity keypair).
    local_peer_id: libp2p::PeerId,
    /// Channel for sending commands to the background swarm task.
    cmd_tx: mpsc::UnboundedSender<SwarmCmd>,
    /// Channel for receiving decoded messages from the background swarm task.
    msg_rx: mpsc::UnboundedReceiver<InboundMsg>,
    /// Map from consensus index → libp2p PeerId for outbound `send`.
    peer_map: HashMap<usize, libp2p::PeerId>,
    /// Current count of connected libp2p peers (updated by the swarm task).
    peer_count_rx: tokio::sync::watch::Receiver<usize>,
    /// Current set of connected libp2p PeerIds (updated by the swarm task). Lets
    /// an index-less full node enumerate sync targets (`connected_peer_ids`).
    connected_peers_rx: tokio::sync::watch::Receiver<Vec<libp2p::PeerId>>,
    /// This node's first bound listen address (set by the swarm task on
    /// `NewListenAddr`). Lets ephemeral-port nodes learn their own dialable
    /// multiaddr — e.g. to advertise as a bootstrap, or for tests to avoid
    /// fixed ports.
    listen_addr_rx: tokio::sync::watch::Receiver<Option<Multiaddr>>,
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
        let (msg_tx, msg_rx) = mpsc::unbounded_channel::<InboundMsg>();

        let node_index = config.node_index;

        // Derive the local PeerId before moving the keypair into build_swarm.
        let local_peer_id = config.keypair.public().to_peer_id();

        // Build the swarm.
        let mut swarm = build_swarm(config.keypair)?;

        // Subscribe to gossipsub topics (fail fast on a subscription error).
        let blocks_topic = IdentTopic::new("/solidus/blocks/1.0.0");
        let txs_topic = IdentTopic::new("/solidus/txs/1.0.0");
        swarm.behaviour_mut().gossipsub.subscribe(&blocks_topic)?;
        swarm.behaviour_mut().gossipsub.subscribe(&txs_topic)?;

        // Register peer addresses so request-response can (re)dial them on
        // demand. This is also the reconnect path: after a peer drops, the next
        // outbound consensus message lazily re-dials the address registered
        // here. A malformed peer_id/address fails start() rather than being
        // silently skipped.
        // Validate + register every peer's address once. While here, collect the
        // peers this node proactively dials at startup.
        let mut peers_to_dial: Vec<(libp2p::PeerId, Multiaddr)> = Vec::new();
        for pc in &config.peers {
            if pc.index == config.node_index {
                continue;
            }
            let pid = libp2p::PeerId::from_str(&pc.peer_id)
                .map_err(|e| format!("invalid peer_id '{}': {e}", pc.peer_id))?;
            let addr: Multiaddr = pc
                .address
                .parse()
                .map_err(|e| format!("invalid peer address '{}': {e}", pc.address))?;
            swarm.add_peer_address(pid, addr.clone());
            // Only the lower-indexed side dials (avoids simultaneous TCP open,
            // which can fail the noise handshake); the higher side just listens.
            // Drops reconnect lazily via request-response using the address
            // registered above.
            if pc.index > config.node_index {
                peers_to_dial.push((pid, addr));
            }
        }

        // Register Kademlia bootstrap peers (additive; empty for validators).
        let mut bootstrap_to_dial: Vec<(libp2p::PeerId, Multiaddr)> = Vec::new();
        for (pid, addr) in &config.bootstrap_peers {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(pid, addr.clone());
            bootstrap_to_dial.push((*pid, addr.clone()));
        }

        // Listen now so a bad listen address fails start() instead of silently
        // killing the spawned task.
        swarm.listen_on(config.listen_addr)?;

        let (peer_count_tx, peer_count_rx) = tokio::sync::watch::channel(0usize);
        let (connected_peers_tx, connected_peers_rx) =
            tokio::sync::watch::channel::<Vec<libp2p::PeerId>>(Vec::new());
        let (listen_addr_tx, listen_addr_rx) =
            tokio::sync::watch::channel::<Option<Multiaddr>>(None);

        // Spawn the swarm event loop. It dials `peers_to_dial` once it observes
        // its own NewListenAddr (socket bound), then drives consensus messaging.
        tokio::spawn(swarm_task(
            swarm,
            SwarmTaskArgs {
                cmd_rx,
                msg_tx,
                node_index,
                blocks_topic,
                txs_topic,
                peer_count_tx,
                connected_peers_tx,
                peers_to_dial,
                bootstrap_to_dial,
                listen_addr_tx,
            },
        ));

        Ok(Self {
            node_index,
            local_peer_id,
            cmd_tx,
            msg_rx,
            peer_map,
            peer_count_rx,
            connected_peers_rx,
            listen_addr_rx,
        })
    }

    fn libp2p_peer_id(&self, peer: PeerId) -> Result<libp2p::PeerId, TransportError> {
        self.peer_map
            .get(&peer)
            .copied()
            .ok_or(TransportError::PeerDisconnected(peer))
    }

    /// This node's own libp2p PeerId.
    pub fn local_peer_id(&self) -> libp2p::PeerId {
        self.local_peer_id
    }

    /// A receiver for the live connected-peer count (also reused later by
    /// `solidus_peerCount`).
    pub fn peer_count_receiver(&self) -> tokio::sync::watch::Receiver<usize> {
        self.peer_count_rx.clone()
    }

    /// Snapshot of the currently-connected peers' libp2p PeerIds.
    ///
    /// Used by the C2 full-node sync path to enumerate sync targets when the
    /// node has no validator index. The snapshot may briefly lag a disconnect;
    /// a send to a just-dropped peer simply fails and the caller rotates.
    pub fn connected_peer_ids(&self) -> Vec<SourcePeer> {
        self.connected_peers_rx
            .borrow()
            .iter()
            .copied()
            .map(SourcePeer)
            .collect()
    }

    /// Wait until the swarm reports its first bound listen address, or `timeout`
    /// elapses. Returns the dialable multiaddr (without the `/p2p/...` suffix).
    /// Lets an ephemeral-port node learn its own address to advertise as a
    /// bootstrap (and lets tests avoid fixed ports).
    pub async fn listen_addr(&self, timeout: std::time::Duration) -> Option<Multiaddr> {
        let mut rx = self.listen_addr_rx.clone();
        if let Some(a) = rx.borrow().clone() {
            return Some(a);
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return None;
            }
            if let Some(a) = rx.borrow().clone() {
                return Some(a);
            }
        }
    }

    /// Wait until at least `min` peers are connected, or `timeout` elapses.
    /// Returns the connected count observed at return time.
    pub async fn wait_for_peers(&self, min: usize, timeout: std::time::Duration) -> usize {
        let mut rx = self.peer_count_rx.clone();
        if *rx.borrow() >= min {
            return *rx.borrow();
        }
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return *rx.borrow();
            }
            if tokio::time::timeout(remaining, rx.changed()).await.is_err() {
                return *rx.borrow(); // timed out
            }
            if *rx.borrow() >= min {
                return *rx.borrow();
            }
        }
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
                let data =
                    serde_json::to_vec(&msg).map_err(|e| TransportError::Serde(e.to_string()))?;
                let topic = IdentTopic::new("/solidus/blocks/1.0.0");
                self.cmd_tx
                    .send(SwarmCmd::Publish { topic, data })
                    .map_err(|_| TransportError::Closed)?;
            }
            ConsensusMessage::NewTransaction(_) => {
                let data =
                    serde_json::to_vec(&msg).map_err(|e| TransportError::Serde(e.to_string()))?;
                let topic = IdentTopic::new("/solidus/txs/1.0.0");
                self.cmd_tx
                    .send(SwarmCmd::Publish { topic, data })
                    .map_err(|_| TransportError::Closed)?;
            }
            // Targeted consensus messages: send individually to all peers.
            ConsensusMessage::Proposal { .. }
            | ConsensusMessage::VoteMsg(_)
            | ConsensusMessage::TimeoutVoteMsg(_)
            | ConsensusMessage::NewQC(_) => {
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
            // Sync messages are point-to-point only; broadcasting them is a bug.
            ConsensusMessage::GetBlockByHash { .. }
            | ConsensusMessage::BlockByHash(_)
            | ConsensusMessage::GetTip
            | ConsensusMessage::Tip { .. }
            | ConsensusMessage::GetBlockRange { .. }
            | ConsensusMessage::BlockRange { .. } => {
                return Err(TransportError::Serde(
                    "sync messages must be sent point-to-point, not broadcast".to_string(),
                ));
            }
        }
        Ok(())
    }

    async fn recv(&mut self) -> Result<(PeerId, ConsensusMessage), TransportError> {
        let (peer, _src, msg) = self.msg_rx.recv().await.ok_or(TransportError::Closed)?;
        Ok((peer, msg))
    }

    fn try_recv(&mut self) -> Option<(PeerId, ConsensusMessage)> {
        self.msg_rx
            .try_recv()
            .ok()
            .map(|(peer, _src, msg)| (peer, msg))
    }

    /// Send `msg` directly to a discovered peer by its libp2p PeerId, bypassing
    /// the validator index `peer_map`. Tags the message with the sentinel
    /// `from_index = usize::MAX` so the responder knows the sender is index-less
    /// and must reply via [`send_to_peer_id`](Self::send_to_peer_id) using the
    /// captured source PeerId rather than an index lookup.
    async fn send_to_peer_id(
        &self,
        peer: SourcePeer,
        msg: ConsensusMessage,
    ) -> Result<(), TransportError> {
        self.cmd_tx
            .send(SwarmCmd::Send {
                peer_id: peer.0,
                from_index: usize::MAX,
                msg,
            })
            .map_err(|_| TransportError::Closed)
    }

    async fn recv_with_source(
        &mut self,
    ) -> Result<(PeerId, Option<SourcePeer>, ConsensusMessage), TransportError> {
        let (peer, src, msg) = self.msg_rx.recv().await.ok_or(TransportError::Closed)?;
        Ok((peer, src.map(SourcePeer), msg))
    }
}

// ---------------------------------------------------------------------------
// Swarm builder helper
// ---------------------------------------------------------------------------

fn build_swarm(
    keypair: Keypair,
) -> Result<libp2p::Swarm<SolidusBehaviour>, Box<dyn std::error::Error>> {
    // Derive identity material before the keypair moves into the builder.
    let local_peer_id = keypair.public().to_peer_id();
    let local_public_key = keypair.public();

    // Gossipsub configuration — anonymous (no signing required for validators
    // that rotate keys; message integrity is handled at the consensus layer).
    // ValidationMode::Permissive is required when using RandomAuthor (unsigned)
    // authenticity; Strict (the default) rejects unsigned messages outright.
    let gossipsub_cfg = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Permissive)
        .build()
        .map_err(|e| format!("gossipsub config error: {e}"))?;
    let gossipsub = gossipsub::Behaviour::new(MessageAuthenticity::RandomAuthor, gossipsub_cfg)
        .map_err(|e| format!("gossipsub init error: {e}"))?;

    // Request-response configuration with our custom JSON codec.
    let rr = request_response::Behaviour::new(
        [(ConsensusProtocol, ProtocolSupport::Full)],
        request_response::Config::default(),
    );

    // Identify — supplies Kademlia with dialable peer addresses.
    let identify = identify::Behaviour::new(identify::Config::new(
        "/solidus/id/1.0.0".to_string(),
        local_public_key,
    ));

    // Kademlia — peer routing only (MemoryStore, no value records). Server mode
    // so nodes answer routing queries, letting joiners discover the mesh.
    let mut kademlia = kad::Behaviour::new(local_peer_id, MemoryStore::new(local_peer_id));
    kademlia.set_mode(Some(kad::Mode::Server));

    let behaviour = SolidusBehaviour {
        gossipsub,
        rr,
        identify,
        kademlia,
    };

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

struct SwarmTaskArgs {
    cmd_rx: mpsc::UnboundedReceiver<SwarmCmd>,
    msg_tx: mpsc::UnboundedSender<InboundMsg>,
    node_index: usize,
    blocks_topic: IdentTopic,
    txs_topic: IdentTopic,
    peer_count_tx: tokio::sync::watch::Sender<usize>,
    connected_peers_tx: tokio::sync::watch::Sender<Vec<libp2p::PeerId>>,
    peers_to_dial: Vec<(libp2p::PeerId, Multiaddr)>,
    bootstrap_to_dial: Vec<(libp2p::PeerId, Multiaddr)>,
    listen_addr_tx: tokio::sync::watch::Sender<Option<Multiaddr>>,
}

async fn swarm_task(mut swarm: libp2p::Swarm<SolidusBehaviour>, args: SwarmTaskArgs) {
    let SwarmTaskArgs {
        mut cmd_rx,
        msg_tx,
        node_index,
        blocks_topic,
        txs_topic,
        peer_count_tx,
        connected_peers_tx,
        peers_to_dial,
        bootstrap_to_dial,
        listen_addr_tx,
    } = args;

    let mut connected: std::collections::HashSet<libp2p::PeerId> = std::collections::HashSet::new();
    // Per-peer dial-retry backoff state. Populated on the first
    // `OutgoingConnectionError`; cleared on `ConnectionEstablished` so a
    // peer that reboots gets a fresh retry budget.
    let mut dial_retries: HashMap<libp2p::PeerId, DialRetryState> = HashMap::new();
    let mut dialed = false;

    // Periodic ticker that scans `dial_retries` for peers whose backoff has
    // expired and re-issues a dial. Required because libp2p does NOT auto-
    // retry after an OutgoingConnectionError — without this ticker, a peer
    // we deferred via backoff would never be re-attempted. 100ms cadence
    // is fine-grained enough that the first retry (initial 250ms backoff)
    // is honoured within 2-3 ticks.
    let mut retry_ticker = tokio::time::interval(Duration::from_millis(100));
    retry_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── retry ticker: re-dial peers whose backoff has elapsed ───
            _ = retry_ticker.tick() => {
                let now = Instant::now();
                // Snapshot peers ready for a retry to avoid mutating
                // dial_retries while iterating.
                let ready: Vec<libp2p::PeerId> = dial_retries
                    .iter()
                    .filter(|(pid, st)| {
                        !connected.contains(pid)
                            && st.attempts < DIAL_RETRY_CAP
                            && st.ready(now)
                    })
                    .map(|(pid, _)| *pid)
                    .collect();
                for pid in ready {
                    if let Some((_, addr)) = peers_to_dial.iter().find(|(p, _)| p == &pid) {
                        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(pid)
                            .addresses(vec![addr.clone()])
                            .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
                            .build();
                        if let Err(e) = swarm.dial(opts) {
                            debug!(node = node_index, "backoff-driven retry dial error: {e}");
                        }
                        if let Some(state) = dial_retries.get_mut(&pid) {
                            state.schedule_next(now);
                        }
                    }
                }
            }

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
                                    // Gossip carries no reliable per-message origin -> source None.
                                    let from_peer: PeerId = 0;
                                    if msg_tx.send((from_peer, None, msg)).is_err() {
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
                            peer,
                            message: request_response::Message::Request { request, channel, .. },
                        }
                    )) => {
                        let from_index = request.from;
                        let msg = request.msg;

                        // Send ACK back (fire-and-forget; ignore error).
                        let _ = swarm.behaviour_mut().rr.send_response(channel, Ack);

                        // Capture the real network source so a responder can reply
                        // to an index-less requester (`from == usize::MAX`).
                        if msg_tx.send((from_index, Some(peer), msg)).is_err() {
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

                    SwarmEvent::NewListenAddr { address, .. } => {
                        // Publish the bound address so callers can learn their
                        // own dialable multiaddr (advertise as bootstrap; tests
                        // read it instead of relying on fixed ports).
                        let _ = listen_addr_tx.send(Some(address.clone()));
                        if !dialed {
                            dialed = true;
                            for (pid, addr) in &peers_to_dial {
                                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(*pid)
                                    .addresses(vec![addr.clone()])
                                    .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
                                    .build();
                                if let Err(e) = swarm.dial(opts) {
                                    debug!(node = node_index, "initial dial error: {e}");
                                }
                            }
                            // Dial Kademlia bootstrap peers, then kick off a DHT
                            // bootstrap query to discover peers beyond them.
                            for (pid, addr) in &bootstrap_to_dial {
                                let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(*pid)
                                    .addresses(vec![addr.clone()])
                                    .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
                                    .build();
                                if let Err(e) = swarm.dial(opts) {
                                    debug!(node = node_index, "bootstrap dial error: {e}");
                                }
                            }
                            if !bootstrap_to_dial.is_empty() {
                                if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
                                    debug!(node = node_index, "kademlia bootstrap error: {e}");
                                }
                            }
                        }
                    }
                    SwarmEvent::OutgoingConnectionError { peer_id: Some(pid), error, .. }
                        if peers_to_dial.iter().any(|(p, _)| p == &pid)
                            && !connected.contains(&pid) =>
                    {
                        debug!(node = node_index, "outgoing connection error to {pid}: {error}");
                        // Record the failure; the periodic retry_ticker
                        // above is the SINGLE driver of subsequent dial
                        // attempts (libp2p does not auto-retry, and a
                        // tight in-arm retry would compete with the
                        // ticker's backoff schedule). The state starts
                        // with attempts = 0 + next_at = now, so the first
                        // retry fires on the next ticker tick (≤100ms).
                        let entry = dial_retries.entry(pid).or_insert_with(DialRetryState::new);
                        if entry.attempts >= DIAL_RETRY_CAP {
                            warn!(
                                node = node_index,
                                %pid,
                                attempts = entry.attempts,
                                "dial retry cap reached; giving up on peer at app layer"
                            );
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        connected.insert(peer_id);
                        // Peer is back — clear its retry budget so a future
                        // disconnect-and-reconnect cycle starts fresh.
                        dial_retries.remove(&peer_id);
                        let _ = peer_count_tx.send(connected.len());
                        let _ = connected_peers_tx.send(connected.iter().copied().collect());
                    }
                    SwarmEvent::ConnectionClosed { peer_id, num_established, .. } => {
                        if num_established == 0 {
                            connected.remove(&peer_id);
                        }
                        let _ = peer_count_tx.send(connected.len());
                        let _ = connected_peers_tx.send(connected.iter().copied().collect());
                    }

                    // Identify supplies dialable addresses -> feed Kademlia.
                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Identify(
                        identify::Event::Received { peer_id, info, .. },
                    )) => {
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }

                    // Kademlia discovered/updated a peer -> dial it so it joins
                    // the gossipsub mesh (skip if already connected).
                    SwarmEvent::Behaviour(SolidusBehaviourEvent::Kademlia(
                        kad::Event::RoutingUpdated {
                            peer, addresses, ..
                        },
                    )) if !connected.contains(&peer) => {
                        let addrs: Vec<Multiaddr> = addresses.iter().cloned().collect();
                        let opts = libp2p::swarm::dial_opts::DialOpts::peer_id(peer)
                            .addresses(addrs)
                            .condition(libp2p::swarm::dial_opts::PeerCondition::NotDialing)
                            .build();
                        if let Err(e) = swarm.dial(opts) {
                            debug!(node = node_index, "kad-discovered dial error: {e}");
                        }
                    }

                    // All other swarm events are intentionally ignored.
                    _ => {}
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Bootstrap-address parsing
// ---------------------------------------------------------------------------

/// Parse a bootstrap multiaddr string of the form
/// `/ip4/.../tcp/.../p2p/<base58-peerid>` into its dialable
/// `(PeerId, base Multiaddr)` components (the `/p2p/...` suffix stripped).
///
/// Returns a descriptive error for a malformed multiaddr or one missing the
/// trailing `/p2p/<peerid>` component.
pub fn parse_bootstrap_addr(s: &str) -> Result<(libp2p::PeerId, Multiaddr), String> {
    let mut addr: Multiaddr = s
        .parse()
        .map_err(|e| format!("invalid bootstrap multiaddr '{s}': {e}"))?;
    match addr.pop() {
        Some(libp2p::multiaddr::Protocol::P2p(peer_id)) => Ok((peer_id, addr)),
        _ => Err(format!("bootstrap addr '{s}' must end with /p2p/<peerid>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::libp2p_keypair_from_node_seed;

    #[tokio::test]
    async fn local_peer_id_matches_derived_identity() {
        let keypair = libp2p_keypair_from_node_seed(&[42u8; 32]).unwrap();
        let expected = keypair.public().to_peer_id();

        let config = LibP2PConfig {
            listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
            peers: vec![],
            node_index: 0,
            keypair,
            bootstrap_peers: vec![],
        };
        let transport = LibP2PTransport::start(config).await.unwrap();
        assert_eq!(transport.local_peer_id(), expected);
    }

    #[test]
    fn parse_bootstrap_addr_splits_peerid() {
        let kp = libp2p_keypair_from_node_seed(&[5u8; 32]).unwrap();
        let pid = kp.public().to_peer_id();
        let s = format!("/ip4/127.0.0.1/tcp/30300/p2p/{}", pid.to_base58());
        let (parsed_pid, base) = parse_bootstrap_addr(&s).unwrap();
        assert_eq!(parsed_pid, pid);
        assert_eq!(base.to_string(), "/ip4/127.0.0.1/tcp/30300");
    }

    #[test]
    fn parse_bootstrap_addr_requires_p2p_suffix() {
        let err = parse_bootstrap_addr("/ip4/127.0.0.1/tcp/30300").unwrap_err();
        assert!(
            err.contains("/p2p/"),
            "error should mention the /p2p/ requirement: {err}"
        );
    }

    #[test]
    fn parse_bootstrap_addr_rejects_garbage() {
        assert!(parse_bootstrap_addr("not-a-multiaddr").is_err());
    }

    // -----------------------------------------------------------------------
    // DialRetryState — pure logic, no libp2p required
    // -----------------------------------------------------------------------

    #[test]
    fn dial_retry_state_starts_ready_immediately() {
        let state = DialRetryState::new();
        let now = Instant::now();
        assert!(state.ready(now));
        assert_eq!(state.attempts, 0);
    }

    #[test]
    fn dial_retry_state_schedule_next_applies_initial_backoff() {
        let mut state = DialRetryState::new();
        let now = Instant::now();
        state.schedule_next(now);
        assert_eq!(state.attempts, 1);
        // Initial backoff is DIAL_RETRY_INITIAL (250ms).
        assert!(state.next_at >= now + DIAL_RETRY_INITIAL);
        // Not ready at `now`.
        assert!(!state.ready(now));
        // Ready after the backoff has elapsed.
        assert!(state.ready(now + DIAL_RETRY_INITIAL + Duration::from_millis(1)));
    }

    #[test]
    fn dial_retry_state_schedule_next_caps_at_max() {
        let mut state = DialRetryState::new();
        let now = Instant::now();
        // Burn through many doublings — should cap at DIAL_RETRY_MAX.
        for _ in 0..15 {
            state.schedule_next(now);
        }
        // After many doublings, the gap from `now` must equal DIAL_RETRY_MAX
        // (we keep calling schedule_next from the same `now` so each call
        // resets next_at to now + capped_backoff; the LAST call sets the
        // visible state).
        let gap = state.next_at - now;
        assert!(
            gap <= DIAL_RETRY_MAX,
            "backoff should not exceed DIAL_RETRY_MAX, got {gap:?}"
        );
        assert_eq!(gap, DIAL_RETRY_MAX);
    }

    #[test]
    fn dial_retry_state_attempts_counter_saturates() {
        let mut state = DialRetryState::new();
        let now = Instant::now();
        // Push past DIAL_RETRY_CAP to exercise the saturating_add path.
        for _ in 0..(DIAL_RETRY_CAP as usize + 5) {
            state.schedule_next(now);
        }
        // attempts should be >= CAP — the loop above is the place where
        // app-level callers stop dialing.
        assert!(state.attempts >= DIAL_RETRY_CAP);
    }
}

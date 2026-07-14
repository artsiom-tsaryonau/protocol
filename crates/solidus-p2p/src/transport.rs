use crate::message::ConsensusMessage;
use async_trait::async_trait;
use std::fmt;

/// Opaque identifier for a peer in the network (index-based for the channel
/// backend; the libp2p backend will map `PeerId` ↔ `libp2p::PeerId`).
pub type PeerId = usize;

/// Opaque network-level identity of a peer, used by the PeerId-addressed sync
/// path (C2 full-node mode).
///
/// A full node has no validator index, so it cannot use the index-based
/// [`PeerId`] / `peer_map` send path. It addresses discovered peers by their
/// libp2p identity instead. This newtype wraps `libp2p::PeerId` so the
/// transport trait stays backend-agnostic: the channel backend treats
/// `SourcePeer` as opaque and its sync methods default to no-ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourcePeer(pub libp2p::PeerId);

// ---------------------------------------------------------------------------
// TransportError
// ---------------------------------------------------------------------------

/// Errors that can occur when sending or receiving consensus messages.
#[derive(Debug, Clone)]
pub enum TransportError {
    /// The remote peer with the given ID has disconnected.
    PeerDisconnected(PeerId),
    /// The transport has been shut down.
    Closed,
    /// A serialization / deserialization error occurred.
    Serde(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::PeerDisconnected(id) => {
                write!(f, "peer {id} disconnected")
            }
            TransportError::Closed => write!(f, "transport closed"),
            TransportError::Serde(msg) => write!(f, "serde error: {msg}"),
        }
    }
}

impl std::error::Error for TransportError {}

// ---------------------------------------------------------------------------
// ConsensusTransport
// ---------------------------------------------------------------------------

/// Abstraction over the network layer used by the consensus engine.
///
/// Implementations include the in-process [`crate::channel::ChannelTransport`]
/// (for tests) and the libp2p backend (for production).
#[async_trait]
pub trait ConsensusTransport: Send + Sync + 'static {
    /// Send `msg` to a specific peer identified by `peer`.
    async fn send(&self, peer: PeerId, msg: ConsensusMessage) -> Result<(), TransportError>;

    /// Broadcast `msg` to all connected peers except ourselves.
    async fn broadcast(&self, msg: ConsensusMessage) -> Result<(), TransportError>;

    /// Receive the next incoming message (blocks until one is available).
    ///
    /// Returns `(sender_peer_id, message)`.
    async fn recv(&mut self) -> Result<(PeerId, ConsensusMessage), TransportError>;

    /// Non-blocking receive — returns immediately with `None` if no message is
    /// queued.  Used by the consensus loop to drain buffered messages before
    /// re-entering the pacemaker timeout.
    fn try_recv(&mut self) -> Option<(PeerId, ConsensusMessage)>;

    // -----------------------------------------------------------------------
    // PeerId-addressed sync path (C2 full-node mode) — additive.
    //
    // The validator path above (index `send`/`recv`/`peer_map`) is unchanged.
    // These methods let an index-less full node send to, and a validator reply
    // to, a peer identified only by its network-level [`SourcePeer`]. Default
    // implementations make this a no-op for backends without PeerIds (the
    // in-process channel backend), so existing implementors need no changes.
    // -----------------------------------------------------------------------

    /// Send `msg` to a peer identified by its network-level [`SourcePeer`],
    /// bypassing the validator index `peer_map`. Used by the full-node sync
    /// path and by responders replying to an index-less requester.
    ///
    /// The default errors: backends without PeerIds (the channel backend)
    /// cannot address peers this way and are never asked to.
    async fn send_to_peer_id(
        &self,
        _peer: SourcePeer,
        _msg: ConsensusMessage,
    ) -> Result<(), TransportError> {
        Err(TransportError::Closed)
    }

    /// Like [`recv`](Self::recv) but also surfaces the inbound message's
    /// network-level source ([`SourcePeer`]) when one is available, so a
    /// responder can reply to an index-less requester via
    /// [`send_to_peer_id`](Self::send_to_peer_id).
    ///
    /// The default delegates to [`recv`](Self::recv) and reports no source —
    /// correct for backends without PeerIds.
    async fn recv_with_source(
        &mut self,
    ) -> Result<(PeerId, Option<SourcePeer>, ConsensusMessage), TransportError> {
        let (peer, msg) = self.recv().await?;
        Ok((peer, None, msg))
    }
}

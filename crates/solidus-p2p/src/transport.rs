use crate::message::ConsensusMessage;
use async_trait::async_trait;
use std::fmt;

/// Opaque identifier for a peer in the network (index-based for the channel
/// backend; the libp2p backend will map `PeerId` ↔ `libp2p::PeerId`).
pub type PeerId = usize;

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

    /// Receive the next incoming message.
    ///
    /// Returns `(sender_peer_id, message)`.
    async fn recv(&mut self) -> Result<(PeerId, ConsensusMessage), TransportError>;
}

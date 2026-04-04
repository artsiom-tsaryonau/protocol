use crate::message::ConsensusMessage;
use crate::transport::{ConsensusTransport, PeerId, TransportError};
use async_trait::async_trait;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// ChannelTransport
// ---------------------------------------------------------------------------

/// In-process transport backed by Tokio unbounded channels.
///
/// Used exclusively for testing — zero network overhead, fully deterministic.
pub struct ChannelTransport {
    /// This node's index in the network.
    node_id: usize,
    /// One sender per node in the network (including self, which is unused
    /// for `send` but kept to simplify indexing).
    senders: Vec<mpsc::UnboundedSender<(PeerId, ConsensusMessage)>>,
    /// Receives messages addressed to this node.
    receiver: mpsc::UnboundedReceiver<(PeerId, ConsensusMessage)>,
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/// Create a fully-connected network of `n` channel transports.
///
/// Each node gets its own [`ChannelTransport`].  Every other node has a clone
/// of its sender, so `send(peer, msg)` costs O(1) and `broadcast` costs O(n).
pub fn create_channel_network(n: usize) -> Vec<ChannelTransport> {
    // Build one (tx, rx) pair per node.
    let mut txs: Vec<mpsc::UnboundedSender<(PeerId, ConsensusMessage)>> = Vec::with_capacity(n);
    let mut rxs: Vec<mpsc::UnboundedReceiver<(PeerId, ConsensusMessage)>> = Vec::with_capacity(n);

    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        txs.push(tx);
        rxs.push(rx);
    }

    // Assemble one ChannelTransport per node.  Each transport holds clones of
    // ALL senders so it can address any peer directly.
    rxs.into_iter()
        .enumerate()
        .map(|(node_id, receiver)| ChannelTransport {
            node_id,
            senders: txs.clone(),
            receiver,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// ConsensusTransport impl
// ---------------------------------------------------------------------------

#[async_trait]
impl ConsensusTransport for ChannelTransport {
    /// Send `msg` to `peer` (identified by node index).
    async fn send(&self, peer: PeerId, msg: ConsensusMessage) -> Result<(), TransportError> {
        let sender = self
            .senders
            .get(peer)
            .ok_or(TransportError::PeerDisconnected(peer))?;

        sender
            .send((self.node_id, msg))
            .map_err(|_| TransportError::PeerDisconnected(peer))
    }

    /// Broadcast `msg` to every node except ourselves.
    async fn broadcast(&self, msg: ConsensusMessage) -> Result<(), TransportError> {
        for (i, sender) in self.senders.iter().enumerate() {
            if i == self.node_id {
                continue;
            }
            sender
                .send((self.node_id, msg.clone()))
                .map_err(|_| TransportError::PeerDisconnected(i))?;
        }
        Ok(())
    }

    /// Receive the next message delivered to this node.
    async fn recv(&mut self) -> Result<(PeerId, ConsensusMessage), TransportError> {
        self.receiver.recv().await.ok_or(TransportError::Closed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_consensus::types::{Block, BlockHeader};
    use solidus_crypto::keys::Address;

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    fn test_tx() -> solidus_txns::types::Transaction {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let payload = solidus_txns::types::TxPayload::Transfer {
            to: Address::from_bytes([0u8; 20]),
            amount: 100,
        };
        let mut tx = solidus_txns::types::Transaction {
            sender_pubkey: sk.verifying_key().to_bytes(),
            nonce: 0,
            payload,
            signature: [0u8; 64],
        };
        let sig = solidus_crypto::ed25519::sign(&sk, &tx.signing_bytes());
        tx.signature = sig;
        tx
    }

    fn test_block() -> Block {
        Block {
            header: BlockHeader {
                height: 1,
                round: 0,
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 0,
                tx_count: 0,
                proposer: Address::from_bytes([0u8; 20]),
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        }
    }

    // ------------------------------------------------------------------
    // Test 1: send and receive
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn send_and_receive() {
        let mut nodes = create_channel_network(2);

        // Node 0 sends a NewTransaction to node 1.
        let msg = ConsensusMessage::NewTransaction(test_tx());
        nodes[0].send(1, msg).await.expect("send failed");

        // Destructure into the two transports so we can call recv() on node 1.
        let [_, ref mut node1] = nodes[..] else {
            panic!("expected exactly 2 nodes");
        };

        let (from, received) = node1.recv().await.expect("recv failed");
        assert_eq!(from, 0, "message should come from node 0");
        assert!(
            matches!(received, ConsensusMessage::NewTransaction(_)),
            "wrong message variant"
        );
    }

    // ------------------------------------------------------------------
    // Test 2: broadcast reaches all peers except sender
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn broadcast_reaches_all_except_sender() {
        let mut nodes = create_channel_network(4);

        // Split off node 0 so we can mutably borrow both it and the rest.
        let (node0, rest) = nodes.split_at_mut(1);
        let node0 = &node0[0];

        let msg = ConsensusMessage::NewBlock(test_block());
        node0.broadcast(msg).await.expect("broadcast failed");

        // Nodes 1, 2, 3 should each receive the message from node 0.
        for (idx, node) in rest.iter_mut().enumerate() {
            let peer_index = idx + 1; // actual index in the network
            let (from, received) = node.recv().await.expect("recv failed");
            assert_eq!(from, 0, "node {peer_index} expected message from node 0");
            assert!(
                matches!(received, ConsensusMessage::NewBlock(_)),
                "node {peer_index} received wrong variant"
            );
        }
    }

    // ------------------------------------------------------------------
    // Test 3: send to invalid peer returns an error
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn send_to_invalid_peer_fails() {
        let nodes = create_channel_network(2);

        let msg = ConsensusMessage::NewTransaction(test_tx());
        let result = nodes[0].send(99, msg).await;

        assert!(
            result.is_err(),
            "sending to a non-existent peer should fail"
        );
        assert!(
            matches!(result.unwrap_err(), TransportError::PeerDisconnected(99)),
            "expected PeerDisconnected(99)"
        );
    }
}

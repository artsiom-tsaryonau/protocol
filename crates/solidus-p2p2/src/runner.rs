//! The swarm ↔ node event loop: the glue that makes a
//! [`solidus_node2::Node`] talk over real libp2p — the "mechanical
//! remainder" the earlier stages flagged, now BUILT and driven by real
//! swarms in `tests/four_node_libp2p.rs` (which commits an agreeing chain
//! over the real stack when the gossip mesh forms; see that file for why
//! it is a demonstration rather than a CI gate).
//!
//! Per event: inbound gossip/direct frame → [`route_inbound`] →
//! `Node::step` → the resulting [`NodeOutput`]s → [`route_output`] →
//! publish / point-to-point / arm-a-timer. Two behaviours it adds on top
//! of the pure router: **gated boot** (don't start consensus until the
//! node has enough peers, so the leader's first proposal isn't published
//! into an empty mesh and lost) and a **periodic worker flush** (seal
//! partial batches so the mempool keeps producing certificates).
//!
//! Batches are stamped with this node's own index on the way out (the
//! emitting node doesn't tag origin; the transport does).

use std::collections::HashSet;
use std::time::Duration;

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{request_response, Multiaddr, PeerId, Swarm};
use solidus_hotstuff2::{Action, ValidatorIndex};
use solidus_node2::{Node, NodeInput, NodeOutput};
use tokio::sync::mpsc;

use crate::behaviour::{
    publish, send_direct, PeerDirectory, SolidusBehaviour, SolidusBehaviourEvent,
};
use crate::router::{route_inbound, route_output, Outbound};
use crate::wire::{NetMessage, Topic};

/// An executed-block notification the harness/monitoring can observe.
#[derive(Debug, Clone, Copy)]
pub struct Executed {
    pub height: u64,
    pub tx_count: usize,
    pub state_root: [u8; 32],
}

/// One validator's runtime: a Node + its swarm + the committee directory.
pub struct P2pRunner {
    index: ValidatorIndex,
    chain_id: u64,
    node: Node,
    swarm: Swarm<SolidusBehaviour>,
    directory: PeerDirectory,
    self_tx: mpsc::UnboundedSender<NodeInput>,
    self_rx: mpsc::UnboundedReceiver<NodeInput>,
    executed_tx: Option<mpsc::UnboundedSender<Executed>>,
}

impl P2pRunner {
    pub fn new(
        index: ValidatorIndex,
        chain_id: u64,
        node: Node,
        swarm: Swarm<SolidusBehaviour>,
    ) -> Self {
        let (self_tx, self_rx) = mpsc::unbounded_channel();
        Self {
            index,
            chain_id,
            node,
            swarm,
            directory: PeerDirectory::new(),
            self_tx,
            self_rx,
            executed_tx: None,
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Push executed-block notifications to `tx` (harness observation).
    pub fn set_executed_sink(&mut self, tx: mpsc::UnboundedSender<Executed>) {
        self.executed_tx = Some(tx);
    }

    /// Start listening; pump until the bound address is known and return
    /// it. Safe to call before any peer wiring (no connection events yet).
    pub async fn listen(&mut self, addr: Multiaddr) -> Multiaddr {
        self.swarm.listen_on(addr).expect("listen_on");
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = self.swarm.select_next_some().await {
                return address;
            }
        }
    }

    /// Register a peer: directory entry + dial + gossip explicit-peer.
    pub fn add_peer(&mut self, index: ValidatorIndex, peer: PeerId, addr: Multiaddr) {
        self.directory.set(index, peer);
        let _ = self.swarm.dial(addr);
        self.swarm
            .behaviour_mut()
            .gossipsub
            .add_explicit_peer(&peer);
    }

    /// Feed the node a client transaction (RPC/mempool entry point).
    pub fn submit(&self, tx: solidus_txns::types::Transaction) {
        let _ = self.self_tx.send(NodeInput::SubmitTx(tx));
    }

    /// A cloneable input handle — lets a caller keep submitting after
    /// [`run`](Self::run) has taken ownership of the runner.
    pub fn input_sender(&self) -> mpsc::UnboundedSender<NodeInput> {
        self.self_tx.clone()
    }

    /// Drive the runtime forever (until the input channel closes).
    ///
    /// Consensus is NOT booted until this node has established
    /// `expected_peers` connections — otherwise the leader's first
    /// proposal publishes into an empty gossip mesh and is lost, wedging
    /// the round until a pacemaker timeout. Gating the boot on
    /// connectivity is the transport-layer analogue of the own-vote rule:
    /// don't emit into the network before the network exists.
    pub async fn run(mut self, expected_peers: usize) {
        let mut connected: HashSet<PeerId> = HashSet::new();
        let mut started = expected_peers == 0;
        if started {
            let boot = self.node.start();
            self.handle_outputs(boot);
        }

        // Periodic worker flush: seals partial batches so transactions
        // don't sit unsealed below the count threshold under light or
        // bursty load (the same ticker the node2 localnet harness runs —
        // without it a batch only seals when it fills, which starves the
        // mempool of certificates and produces empty blocks).
        let mut flush = tokio::time::interval(Duration::from_millis(25));

        loop {
            tokio::select! {
                maybe_input = self.self_rx.recv() => {
                    match maybe_input {
                        Some(input) => {
                            let out = self.node.step(input);
                            self.handle_outputs(out);
                        }
                        None => break,
                    }
                }
                _ = flush.tick() => {
                    if started {
                        let out = self.node.step(NodeInput::Flush);
                        self.handle_outputs(out);
                    }
                }
                event = self.swarm.select_next_some() => {
                    if let SwarmEvent::ConnectionEstablished { peer_id, .. } = &event {
                        connected.insert(*peer_id);
                    }
                    self.handle_swarm_event(event);
                    if !started && connected.len() >= expected_peers {
                        started = true;
                        let boot = self.node.start();
                        self.handle_outputs(boot);
                    }
                }
            }
        }
    }

    fn handle_swarm_event(&mut self, event: SwarmEvent<SolidusBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                // Re-affirm the gossip mesh (idempotent).
                self.swarm
                    .behaviour_mut()
                    .gossipsub
                    .add_explicit_peer(&peer_id);
            }
            SwarmEvent::Behaviour(SolidusBehaviourEvent::Gossipsub(
                libp2p::gossipsub::Event::Message { message, .. },
            )) => {
                if let Ok(net) = NetMessage::decode(&message.data) {
                    let out = self.node.step(route_inbound(net));
                    self.handle_outputs(out);
                }
            }
            SwarmEvent::Behaviour(SolidusBehaviourEvent::Direct(
                request_response::Event::Message { message, .. },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    // Empty ack response (point-to-point is fire-and-forget
                    // at the protocol level; the response just closes the
                    // stream).
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .direct
                        .send_response(channel, Vec::new());
                    if let Ok(net) = NetMessage::decode(&request) {
                        let out = self.node.step(route_inbound(net));
                        self.handle_outputs(out);
                    }
                }
                request_response::Message::Response { .. } => {}
            },
            _ => {}
        }
    }

    fn handle_outputs(&mut self, outputs: Vec<NodeOutput>) {
        for output in outputs {
            // Timers carry (view, delay) that route_output collapses to
            // Local — handle them here before routing the rest.
            if let NodeOutput::Consensus(Action::ScheduleTimeout { view, delay }) = &output {
                let (view, delay) = (*view, *delay);
                let tx = self.self_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(NodeInput::ConsensusTimer(view));
                });
                continue;
            }
            if let NodeOutput::BlockExecuted {
                height,
                tx_count,
                state_root,
            } = &output
            {
                if let Some(sink) = &self.executed_tx {
                    let _ = sink.send(Executed {
                        height: *height,
                        tx_count: *tx_count,
                        state_root: *state_root,
                    });
                }
                continue;
            }

            match route_output(&output) {
                Outbound::Publish { topic, message } => {
                    let bytes = self.stamp_and_encode(topic, message);
                    let _ = publish(&mut self.swarm, self.chain_id, topic, bytes);
                }
                Outbound::SendTo { peer, message } => {
                    send_direct(&mut self.swarm, &self.directory, peer, message.encode());
                }
                Outbound::Local => {}
            }
        }
    }

    /// Stamp a batch broadcast with this node's own index (the router
    /// leaves a `u32::MAX` sentinel), then encode.
    fn stamp_and_encode(&self, topic: Topic, message: NetMessage) -> Vec<u8> {
        match (topic, message) {
            (Topic::Batches, NetMessage::Batch { batch, .. }) => NetMessage::Batch {
                batch,
                from: self.index,
            }
            .encode(),
            (_, other) => other.encode(),
        }
    }
}

/// A brief driver used to pump a swarm's background work (mesh
/// maintenance) for `dur` without feeding node inputs — lets a freshly
/// wired committee establish connections before load starts.
pub async fn warm_up(runners: &mut [P2pRunner], dur: Duration) {
    let deadline = tokio::time::Instant::now() + dur;
    while tokio::time::Instant::now() < deadline {
        // Round-robin a single event per runner, bounded by a short sleep.
        for r in runners.iter_mut() {
            tokio::select! {
                event = r.swarm.select_next_some() => r.handle_swarm_event(event),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
    }
}

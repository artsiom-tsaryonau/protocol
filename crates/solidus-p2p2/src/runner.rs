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

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::swarm::SwarmEvent;
use libp2p::{request_response, Multiaddr, PeerId, Swarm};
use solidus_hotstuff2::{Action, ValidatorIndex};
use solidus_node2::{Node, NodeInput, NodeOutput};
use tokio::sync::mpsc;

use crate::behaviour::{
    publish, send_direct, send_direct_to_peer, PeerDirectory, SolidusBehaviour,
    SolidusBehaviourEvent,
};
use crate::router::{route_inbound, route_output, Outbound};
use crate::wire::{NetMessage, Topic, MAX_BLOCK_RANGE};

/// Minimum gap between range requests served to one peer.
const RANGE_REQUEST_MIN_INTERVAL: Duration = Duration::from_millis(250);

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
    /// Last time each peer was served a block range (rate limiting).
    last_range_served: HashMap<PeerId, Instant>,
    /// Rotates which peer a backfill request goes to.
    next_sync_peer: usize,
    /// Committee addresses, kept so a lost peer can be dialled AGAIN.
    ///
    /// ⛔ THE ADDRESS USED TO BE DISCARDED AFTER ONE DIAL. libp2p does not
    /// redial by itself, so a peer that was down at boot, or that restarted
    /// later, was gone for the lifetime of the process.
    peer_addrs: HashMap<ValidatorIndex, Multiaddr>,
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
            last_range_served: HashMap::new(),
            next_sync_peer: 0,
            peer_addrs: HashMap::new(),
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
        self.peer_addrs.insert(index, addr.clone());
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

        // ⛔ RE-DIAL, BECAUSE NOTHING ELSE WILL. libp2p does not reconnect on
        // its own and `add_peer` dials once. A committee restarting together is
        // the worst case for that: every validator dials peers that are
        // themselves still starting, so most of those dials fail, and before
        // this the failures were permanent. Measured on the restart
        // reproduction: one validator of four reached the two connections it
        // needed to boot consensus, and the other three never tried again.
        let mut redial = tokio::time::interval(Duration::from_secs(2));

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
                _ = redial.tick() => {
                    // Dialling a peer we are already connected to is wasteful,
                    // not harmful, but the directory is small and the check is
                    // free.
                    let missing: Vec<(ValidatorIndex, Multiaddr)> = self
                        .peer_addrs
                        .iter()
                        .filter(|(index, _)| {
                            self.directory
                                .peer(**index)
                                .is_none_or(|p| !connected.contains(p))
                        })
                        .map(|(index, addr)| (*index, addr.clone()))
                        .collect();
                    for (_, addr) in missing {
                        let _ = self.swarm.dial(addr);
                    }
                }
                event = self.swarm.select_next_some() => {
                    match &event {
                        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                            connected.insert(*peer_id);
                        }
                        // ⚠ WITHOUT THIS THE REDIAL NEVER FIRES FOR A PEER THAT
                        // DROPS. `connected` would keep reporting it as present
                        // and the validator would sit talking to nobody.
                        SwarmEvent::ConnectionClosed {
                            peer_id,
                            num_established: 0,
                            ..
                        } => {
                            connected.remove(peer_id);
                        }
                        _ => {}
                    }
                    self.handle_swarm_event(event);
                    // ⚠ CONNECTIONS, NOT MESH MEMBERSHIP, AND THAT IS NOT AN
                    // OVERSIGHT. Gating on `gossipsub.mesh_peers()` was tried on
                    // 2026-09-03 and NOT ONE VALIDATOR EVER BOOTED: this crate
                    // wires peers with `add_explicit_peer`, and gossipsub
                    // delivers to explicit peers DIRECTLY rather than through
                    // the mesh, so the mesh count can sit at zero while delivery
                    // works perfectly. A readiness check that reads zero on a
                    // healthy node is worse than none — it would have shipped a
                    // validator that never starts consensus.
                    if !started && connected.len() >= expected_peers {
                        started = true;
                        // One line, once, and it is the answer to "why is this
                        // validator silent": either it never appears, and the
                        // node is still waiting for a delivery path, or it does
                        // and the silence is consensus rather than transport.
                        eprintln!(
                            "solidus-p2p2: validator {} starting consensus ({} peers connected)",
                            self.index,
                            connected.len()
                        );
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
                    // `None` = arrived over GOSSIP, i.e. the whole mesh saw it.
                    self.handle_net(net, None);
                }
            }
            SwarmEvent::Behaviour(SolidusBehaviourEvent::Direct(
                request_response::Event::Message { peer, message, .. },
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
                        self.handle_net(net, Some(peer));
                    }
                }
                request_response::Message::Response { .. } => {}
            },
            _ => {}
        }
    }

    /// Inbound frame dispatch. Block-range traffic is a TRANSPORT concern and
    /// is answered from the store here; it never enters the consensus input
    /// channel, because a peer asking for old history is not a consensus event.
    fn handle_net(&mut self, net: NetMessage, from_peer: Option<PeerId>) {
        match net {
            NetMessage::GetBlockRange { from, to } => {
                // ⛔ DIRECT ONLY. `handle_net` serves both the gossip and the
                // direct path. A range request accepted from GOSSIP would be
                // answered by EVERY validator in the mesh at once — one small
                // frame, N large replies. `gossip_topic()` returning `None`
                // governs what we SEND; this governs what we ACCEPT, and only
                // the second one is a defence.
                let Some(peer) = from_peer else {
                    eprintln!(
                        "solidus-p2p2: ignoring a GetBlockRange received over \
                         gossip — range requests are point-to-point only"
                    );
                    return;
                };
                if !self.allow_range_request(peer) {
                    return;
                }
                let (blocks, batches) = self.node.read_block_range(from, to);
                let reply = NetMessage::BlockRange { blocks, batches }.encode();
                // Answer the TRANSPORT-level sender, never an index inside the
                // frame. See `NetMessage::GetBlockRange`.
                send_direct_to_peer(&mut self.swarm, peer, reply);
            }
            NetMessage::GetBlockBody { hash } => {
                // Direct only and rate limited, same as a range request: a
                // gossiped body request would draw a reply from every peer.
                let Some(peer) = from_peer else {
                    eprintln!("solidus-p2p2: ignoring a GetBlockBody received over gossip");
                    return;
                };
                if !self.allow_range_request(peer) {
                    return;
                }
                // ⛔ SERVED FROM THE STORE AND ANSWERED TO THE TRANSPORT SENDER.
                // Never to an index inside the frame — that is the reflection
                // amplifier this crate already had once.
                if let Ok(Some(bytes)) = self.node.store().block_by_hash(&hash) {
                    if !bytes.is_empty() {
                        let reply = NetMessage::BlockBody { bytes }.encode();
                        send_direct_to_peer(&mut self.swarm, peer, reply);
                    }
                }
            }
            NetMessage::BlockBody { .. } if from_peer.is_none() => {
                eprintln!("solidus-p2p2: ignoring a BlockBody received over gossip");
            }
            NetMessage::BlockBody { bytes } => {
                // The node accepts it only if it matches a QC it already
                // verified, so an unsolicited body is rejected there.
                let out = self.node.step(NodeInput::BlockBody(bytes));
                self.handle_outputs(out);
            }
            NetMessage::BlockRange { .. } if from_peer.is_none() => {
                // Same reasoning as above: a gossiped "response" is unsolicited
                // by definition, and nobody asked the whole mesh.
                eprintln!("solidus-p2p2: ignoring a BlockRange received over gossip");
            }
            NetMessage::BlockRange { blocks, batches } => {
                // ⚠ NOT APPLIED YET. Serving is built; consuming is not. The
                // apply path has to execute each block, persist it, and advance
                // consensus, which is the backfill loop and the remaining piece
                // of Phase 1. Counted and logged rather than dropped in silence,
                // so a response that arrives with nothing to consume it is
                // visible instead of looking like packet loss.
                if blocks.is_empty() {
                    return;
                }
                // Everything that decides whether to trust these blocks lives
                // inside the node: its committee, its own stored head, and a QC
                // it verified through live consensus. Nothing that arrived in
                // this message is used to judge this message.
                let out = self.node.apply_synced_blocks(&blocks, &batches);
                if out.is_empty() {
                    eprintln!(
                        "solidus-p2p2: a fetched range of {} block(s) was rejected \
                         or applied nothing",
                        blocks.len()
                    );
                }
                self.handle_outputs(out);
            }
            other => {
                if let Some(input) = route_inbound(other) {
                    let out = self.node.step(input);
                    self.handle_outputs(out);
                }
            }
        }
    }

    /// Ask one peer for a single block body, rotating targets.
    ///
    /// ⚠ THIS RESOLVES A LOCK, WHICH IS WHY IT IS WORTH A ROUND TRIP. A
    /// validator holding a QC whose body it lacks can neither propose nor vote,
    /// so it contributes nothing until this is answered.
    fn request_block_body(&mut self, hash: [u8; 32]) {
        let candidates: Vec<u32> = self
            .directory
            .indices()
            .into_iter()
            .filter(|i| *i != self.index)
            .collect();
        if candidates.is_empty() {
            return;
        }
        let target = candidates[self.next_sync_peer % candidates.len()];
        self.next_sync_peer = self.next_sync_peer.wrapping_add(1);
        let msg = NetMessage::GetBlockBody { hash }.encode();
        send_direct(&mut self.swarm, &self.directory, target, msg);
    }

    /// Ask ONE peer for `[from, to]`, rotating targets between attempts.
    ///
    /// ⚠ ONE PEER, NOT A BROADCAST. Asking everyone would multiply a local gap
    /// into N large replies — the same amplification the responder side already
    /// refuses to serve over gossip.
    ///
    /// ⚠ ROTATES so a persistent gap does not hammer a single peer, and so a
    /// peer that is itself missing the range cannot block progress forever.
    ///
    /// ⛔ NOTHING CONSUMES THE ANSWER YET. `handle_net` logs and discards an
    /// inbound `BlockRange`, because applying it must go through
    /// `solidus_node2::verify_fetched_range` against a QC verified by live
    /// consensus, and that path is not built. This asks; it does not catch up.
    fn request_block_range(&mut self, from: u64, to: u64) {
        let peers = self.directory.indices();
        let candidates: Vec<u32> = peers.into_iter().filter(|i| *i != self.index).collect();
        if candidates.is_empty() {
            return;
        }
        let target = candidates[self.next_sync_peer % candidates.len()];
        self.next_sync_peer = self.next_sync_peer.wrapping_add(1);

        // Clamp here too. The responder clamps independently, but asking for
        // more than can be served just wastes a round trip.
        let span = to
            .saturating_sub(from)
            .saturating_add(1)
            .min(MAX_BLOCK_RANGE);
        let message = NetMessage::GetBlockRange {
            from,
            to: from.saturating_add(span).saturating_sub(1),
        };
        send_direct(&mut self.swarm, &self.directory, target, message.encode());
    }

    /// Per-peer rate limit for range requests.
    ///
    /// ⚠ SERVING IS FAR MORE EXPENSIVE THAN ASKING — a tiny frame triggers up to
    /// `MAX_BLOCK_RANGE` store reads — so an unlimited responder is a DoS
    /// amplifier against ITSELF. the workspace's p2p rules require a per-peer rate
    /// limit; this is the block-sync one.
    ///
    /// Deliberately coarse: one served range per peer per interval. Honest
    /// backfill walks in strides of up to 512 blocks, so it does not need to ask
    /// more often than this, and a peer that does is not backfilling.
    fn allow_range_request(&mut self, peer: PeerId) -> bool {
        let now = Instant::now();
        // Bounded memory: only peers we are connected to can reach this, and the
        // committee is fixed-size.
        match self.last_range_served.get(&peer) {
            Some(prev) if now.duration_since(*prev) < RANGE_REQUEST_MIN_INTERVAL => false,
            _ => {
                self.last_range_served.insert(peer, now);
                true
            }
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
            // Same shape as the view timer above. The delay is wall-clock, so by the
            // time it fires the view may have moved on; `on_propose_timer` re-checks
            // every precondition rather than trusting this.
            if let NodeOutput::Consensus(Action::SchedulePropose { view, delay }) = &output {
                let (view, delay) = (*view, *delay);
                let tx = self.self_tx.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(NodeInput::ProposeTimer(view));
                });
                continue;
            }
            if let NodeOutput::NeedBlockBody { hash } = &output {
                self.request_block_body(*hash);
                continue;
            }
            if let NodeOutput::SendBlockRange { .. } = &output {
                // Same as SendBlockBody: the runner answers range requests
                // itself, BEFORE the store is touched, because the rate limit
                // belongs where peer identity lives. This node-level reply path
                // is the in-process harness's route, not the swarm's.
                continue;
            }
            if let NodeOutput::SendBlockBody { .. } = &output {
                // The runner answers body requests directly from the store, so
                // this node-level reply path is unused here. It exists for the
                // in-process test harness, which has no per-node store access.
                continue;
            }
            if let NodeOutput::NeedBlocks { from, to } = &output {
                self.request_block_range(*from, *to);
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

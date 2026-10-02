//! Pure routing: node effects → network actions, and received frames →
//! node inputs. No async, no libp2p — the deterministic glue between the
//! I/O-free [`solidus_node2::Node`] and the swarm.

use solidus_hotstuff2::Action;
use solidus_node2::{NodeInput, NodeOutput};

use crate::wire::{NetMessage, Topic};

/// What the swarm must do with one node effect.
#[allow(clippy::large_enum_variant)] // transient per-effect value; boxing buys nothing
#[derive(Debug, Clone, PartialEq)]
pub enum Outbound {
    /// Gossip on a topic.
    Publish { topic: Topic, message: NetMessage },
    /// Send point-to-point to a committee member.
    SendTo { peer: u32, message: NetMessage },
    /// Purely local (commit bookkeeping, timers, telemetry) — no network.
    Local,
}

/// Map one node output to its network action.
pub fn route_output(output: &NodeOutput) -> Outbound {
    match output {
        NodeOutput::Consensus(action) => route_action(action),
        NodeOutput::BroadcastBatch(batch) => Outbound::Publish {
            topic: Topic::Batches,
            // `from` is filled by the swarm (it knows its own index); the
            // node emits the batch, the transport tags the origin. We carry
            // a placeholder here and let the swarm set it — but to keep this
            // function total and testable we encode index-agnostic and the
            // swarm overrides. Represent with a sentinel the swarm replaces.
            message: NetMessage::Batch {
                batch: batch.clone(),
                from: u32::MAX,
            },
        },
        NodeOutput::BroadcastCert(cert) => Outbound::Publish {
            topic: Topic::Certs,
            message: NetMessage::Cert(cert.clone()),
        },
        NodeOutput::SendAck { to, ack } => Outbound::SendTo {
            peer: *to,
            message: NetMessage::Ack(ack.clone()),
        },
        NodeOutput::BlockExecuted { .. } => Outbound::Local,
        // The runner handles these directly: they need the peer directory to
        // choose a target, which the router has no access to and should not.
        NodeOutput::NeedBlocks { .. }
        | NodeOutput::NeedBlockBody { .. }
        | NodeOutput::SendBlockBody { .. }
        | NodeOutput::SendBlockRange { .. } => Outbound::Local,
    }
}

fn route_action(action: &Action) -> Outbound {
    match action {
        Action::BroadcastProposal(p) => Outbound::Publish {
            topic: Topic::Proposals,
            message: NetMessage::Proposal(p.clone()),
        },
        Action::BroadcastQc(qc) => Outbound::Publish {
            topic: Topic::Qcs,
            message: NetMessage::Qc(qc.clone()),
        },
        Action::BroadcastTc(tc) => Outbound::Publish {
            topic: Topic::Tcs,
            message: NetMessage::Tc(tc.clone()),
        },
        Action::BroadcastTimeoutVote(tv) => Outbound::Publish {
            topic: Topic::TimeoutVotes,
            message: NetMessage::TimeoutVote(tv.clone()),
        },
        Action::SendVote { to, vote } => Outbound::SendTo {
            peer: *to,
            message: NetMessage::Vote(vote.clone()),
        },
        // Local effects the swarm handles without the network: commit
        // bookkeeping, arming the view timer, telemetry.
        Action::Commit(_)
        | Action::ScheduleTimeout { .. }
        | Action::SchedulePropose { .. }
        | Action::EnteredView(_) => Outbound::Local,
    }
}

/// Map a received frame to the node input it should be fed as.
/// Map a received frame to a consensus input.
///
/// Returns `None` for frames the CONSENSUS core has no opinion about — today
/// the block-range pair and the block-body pair, both of which the runner
/// answers from the store rather than from consensus state. Making this
/// an `Option` rather than inventing a no-op `NodeInput` keeps "not a consensus
/// event" explicit at the type level, so the next transport-only message class
/// cannot be quietly fed into the state machine.
pub fn route_inbound(message: NetMessage) -> Option<NodeInput> {
    Some(match message {
        NetMessage::Proposal(p) => NodeInput::Proposal(p),
        NetMessage::Qc(qc) => NodeInput::Qc(qc),
        NetMessage::Tc(tc) => NodeInput::Tc(tc),
        NetMessage::TimeoutVote(tv) => NodeInput::TimeoutVote(tv),
        NetMessage::Vote(v) => NodeInput::Vote(v),
        NetMessage::Batch { batch, from } => NodeInput::Batch { batch, from },
        NetMessage::Ack(ack) => NodeInput::Ack(ack),
        NetMessage::Cert(cert) => NodeInput::Cert(cert),
        NetMessage::GetBlockRange { .. }
        | NetMessage::BlockRange { .. }
        | NetMessage::GetBlockBody { .. }
        | NetMessage::BlockBody { .. } => return None,
    })
}

#[cfg(test)]
mod tests {
    use solidus_hotstuff2::{
        Committee, ConsensusCore, CoreConfig, EmptyPayloads, Pacemaker, RoundRobin,
    };

    use super::*;

    /// Boot a real consensus core and route the leader's boot effects —
    /// proves the mapping against genuine Action values, not hand-built
    /// ones. Uses a realistic 4-validator committee (BFT minimum; a
    /// 1-validator committee is degenerate — quorum 1 makes every proposal
    /// self-commit and synchronously propose the next view without an I/O
    /// boundary, an unbounded recursion that never occurs at n≥4 where the
    /// QC waits on async remote votes).
    #[test]
    fn leader_boot_effects_route_correctly() {
        let sks: Vec<_> = (0..4)
            .map(|_| solidus_crypto::bls::BlsSecretKey::generate())
            .collect();
        let committee = Committee::new(sks.iter().map(|k| k.public_key()).collect());
        // RoundRobin: leader(view 1) = 1 % 4 = validator 1 — so my_index=1
        // is the boot-view leader and proposes exactly once.
        let mut core = ConsensusCore::new(
            CoreConfig {
                chain_id: 2,
                my_index: 1,
                secret: solidus_crypto::bls::BlsSecretKey::from_bytes(&sks[1].to_bytes()).unwrap(),
                committee,
                pacemaker: Pacemaker::default(),
                // Pacing off in tests: these assert on block PRODUCTION,
                // and a wall-clock gate would make them time-dependent.
                min_block_interval_ms: 0,
                idle_heartbeat_ms: 0,
                idle_grace_ms: 0,
            },
            RoundRobin::new(4),
            EmptyPayloads { ts_ms: 1 },
        );
        let actions = core.start();
        let mut saw_proposal_gossip = false;
        let mut saw_vote_p2p = false;
        for action in actions {
            match route_output(&NodeOutput::Consensus(action)) {
                Outbound::Publish {
                    topic: Topic::Proposals,
                    message: NetMessage::Proposal(_),
                } => saw_proposal_gossip = true,
                Outbound::SendTo {
                    message: NetMessage::Vote(_),
                    ..
                } => saw_vote_p2p = true,
                _ => {}
            }
        }
        assert!(
            saw_proposal_gossip,
            "a leader's proposal must gossip on Proposals"
        );
        assert!(
            saw_vote_p2p,
            "the leader's own vote goes point-to-point to the next leader (no QC forms synchronously at n=4)"
        );
    }

    #[test]
    fn ack_and_batch_route_to_p2p_and_gossip() {
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        let ack = solidus_mempool_dag::BatchAck {
            digest: solidus_mempool_dag::BatchDigest([1; 32]),
            worker: 0,
            signer: 1,
            sig: sk.sign(b"a"),
        };
        assert_eq!(
            route_output(&NodeOutput::SendAck {
                to: 2,
                ack: ack.clone()
            }),
            Outbound::SendTo {
                peer: 2,
                message: NetMessage::Ack(ack)
            }
        );
        let batch = solidus_mempool_dag::Batch {
            transactions: vec![],
        };
        assert!(matches!(
            route_output(&NodeOutput::BroadcastBatch(batch)),
            Outbound::Publish {
                topic: Topic::Batches,
                ..
            }
        ));
        assert_eq!(
            route_output(&NodeOutput::BlockExecuted {
                height: 1,
                tx_count: 0,
                state_root: [0; 32]
            }),
            Outbound::Local
        );
    }

    #[test]
    fn inbound_maps_to_matching_node_input() {
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        let qc = solidus_hotstuff2::QuorumCert::genesis([3; 32], sk.sign(b"g"));
        assert!(matches!(
            route_inbound(NetMessage::Qc(qc)),
            Some(NodeInput::Qc(_))
        ));
        assert!(matches!(
            route_inbound(NetMessage::Batch {
                batch: solidus_mempool_dag::Batch {
                    transactions: vec![]
                },
                from: 5
            }),
            Some(NodeInput::Batch { from: 5, .. })
        ));
    }

    /// Body-fetch frames are TRANSPORT too. A peer must not be able to drive
    /// the consensus state machine by asking for, or supplying, a block body:
    /// the node accepts a body only when it matches a QC it already verified,
    /// and that check lives in `solidus-node2`, not here.
    #[test]
    fn block_body_frames_are_not_consensus_inputs() {
        assert!(
            route_inbound(NetMessage::GetBlockBody { hash: [1u8; 32] }).is_none(),
            "a body REQUEST must never reach the consensus core"
        );
        assert!(
            route_inbound(NetMessage::BlockBody {
                bytes: vec![1, 2, 3]
            })
            .is_none(),
            "a body RESPONSE must never reach the consensus core"
        );
    }

    /// Block-range frames are TRANSPORT, not consensus. If either ever routes
    /// to a `NodeInput`, a peer could drive the state machine by asking for
    /// history, so this asserts the boundary rather than trusting it.
    #[test]
    fn block_range_frames_are_not_consensus_inputs() {
        assert!(
            route_inbound(NetMessage::GetBlockRange { from: 1, to: 10 }).is_none(),
            "a range REQUEST must never reach the consensus core"
        );
        assert!(
            route_inbound(NetMessage::BlockRange {
                blocks: vec![vec![1, 2, 3]],
                batches: vec![vec![4, 5, 6]],
            })
            .is_none(),
            "a range RESPONSE must never reach the consensus core"
        );
    }
}

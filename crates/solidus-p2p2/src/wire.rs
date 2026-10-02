//! The network wire: one bincode envelope for every message that crosses
//! the network, and the gossip-topic taxonomy. Deterministic and
//! transport-free — fully unit-testable without a swarm.

use serde::{Deserialize, Serialize};
use solidus_hotstuff2::{Proposal, QuorumCert, TimeoutCert, TimeoutVote, Vote};
use solidus_mempool_dag::{Batch, BatchAck, BatchCertificate};

/// Everything that travels between validators. Consensus certificates and
/// proposals + worker batches are gossiped; votes + acks are point-to-point.
// The Proposal variant is inherently the largest (a full block); it is
// serialized on every hop regardless, so boxing only adds an indirection
// without shrinking the wire.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetMessage {
    Proposal(Proposal),
    Qc(QuorumCert),
    Tc(TimeoutCert),
    TimeoutVote(TimeoutVote),
    Vote(Vote),
    Batch {
        batch: Batch,
        from: u32,
    },
    Ack(BatchAck),

    // ⛔ APPEND-ONLY BELOW THIS LINE. bincode encodes an enum variant by its
    // INDEX, so inserting or reordering a variant silently reinterprets every
    // message an older peer sends. This is the bincode equivalent of the
    // workspace protobuf rule: never change a field number.
    /// Ask a peer for committed blocks in `[from, to]` inclusive.
    ///
    /// ⛔ THERE IS DELIBERATELY NO `requester` FIELD. An earlier version carried
    /// one and the responder replied to whatever index the message named. That
    /// is a REFLECTION AMPLIFIER: a ~24-byte request with a forged `requester`
    /// would aim up to `MAX_BLOCK_RANGE` blocks at a third party. The reply now
    /// goes to the peer that actually sent the frame, which the transport knows
    /// and the sender cannot forge, so the attack is removed BY CONSTRUCTION
    /// rather than validated against.
    GetBlockRange {
        from: u64,
        to: u64,
    },
    /// Encoded blocks in ascending height order, plus the batch bodies those
    /// blocks certify.
    ///
    /// ⛔ THE BATCHES ARE NOT OPTIONAL. A v2 block carries `batch_certs` — the
    /// body BY DIGEST — so blocks alone are NOT EXECUTABLE. Shipping them
    /// together is what makes a range usable; a second round trip for bodies
    /// would be the same bytes with more latency and more failure modes.
    ///
    /// MAY BE SHORT or empty in either field: the responder returns what it
    /// holds and what fits its byte budget, and a pruned or unknown height is
    /// simply absent rather than an error. The requester must cope.
    BlockRange {
        blocks: Vec<Vec<u8>>,
        batches: Vec<Vec<u8>>,
    },

    /// Ask a peer for ONE block body by hash.
    ///
    /// ⛔ BY HASH, NOT HEIGHT, AND THAT IS THE POINT. This resolves a block a
    /// validator is LOCKED on, which may never have been committed and so has
    /// no height to ask for. Without it a restarted node holding a QC it cannot
    /// resolve falls silent in both `propose` and `on_proposal`, and the chain
    /// wedges around it.
    ///
    /// No requester field: the answer goes to the transport-level sender, for
    /// the same reason `GetBlockRange` has none.
    GetBlockBody {
        hash: [u8; 32],
    },
    /// One encoded block body, in answer to `GetBlockBody`.
    BlockBody {
        bytes: Vec<u8>,
    },
    /// A formed batch certificate, gossiped to the whole committee.
    ///
    /// ⛔ WITHOUT THIS, EMPTY-BLOCK SUPPRESSION CANNOT WORK, AND THAT IS WHY IT
    /// FAILED THREE TIMES. A certificate used to live ONLY in the pool of the
    /// node that assembled it: `CertFormed` fired locally and nothing carried it
    /// further. With round-robin leadership a leader therefore held roughly
    /// 1/committee_size of the committee's work, so suppressing on
    /// `pending() == 0` silenced the leader in most views even while the
    /// committee had plenty to do. Without suppression that is invisible — the
    /// leader proposes an empty block and the work waits its turn — which is
    /// exactly why the gap was never obvious from the outside.
    ///
    /// ⚠ Appended, not inserted. bincode encodes a variant by INDEX.
    Cert(BatchCertificate),
}

// The range limits live in `solidus-node2` beside the store read they bound:
// the responder that must obey them is `Node::read_block_range`, and a limit
// defined away from its enforcement is a limit that drifts. Re-exported here
// because they are equally the wire's contract.
pub use solidus_node2::{MAX_BLOCK_RANGE, MAX_RANGE_REPLY_BYTES};

impl NetMessage {
    /// Encode for the wire (v2 binary — bincode, R-WIRE).
    pub fn encode(&self) -> Vec<u8> {
        #[allow(clippy::expect_used)]
        bincode::serialize(self).expect("NetMessage bincode cannot fail")
    }

    /// Decode a received frame.
    pub fn decode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// The gossip topic a *broadcast* message belongs on, or `None` for
    /// point-to-point messages (votes, acks).
    pub fn gossip_topic(&self) -> Option<Topic> {
        match self {
            NetMessage::Proposal(_) => Some(Topic::Proposals),
            NetMessage::Qc(_) => Some(Topic::Qcs),
            NetMessage::Tc(_) => Some(Topic::Tcs),
            NetMessage::TimeoutVote(_) => Some(Topic::TimeoutVotes),
            NetMessage::Batch { .. } => Some(Topic::Batches),
            NetMessage::Cert(_) => Some(Topic::Certs),
            // Point-to-point only. A block range is addressed to ONE peer that
            // asked for it; gossiping history to the whole mesh would multiply
            // a backfill into a broadcast storm.
            NetMessage::Vote(_)
            | NetMessage::Ack(_)
            | NetMessage::GetBlockRange { .. }
            | NetMessage::BlockRange { .. }
            | NetMessage::GetBlockBody { .. }
            | NetMessage::BlockBody { .. } => None,
        }
    }
}

/// Gossipsub topics. One per broadcast message class so a subscriber can
/// filter, and so topic scoring/rate-limits can differ per class later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topic {
    Proposals,
    Qcs,
    Tcs,
    TimeoutVotes,
    Batches,
    /// Formed batch certificates. Separate from `Batches` so a node can carry
    /// certificate gossip without re-receiving batch bodies it already has.
    Certs,
}

impl Topic {
    /// The chain-scoped topic string (distinct chain-ids never cross-talk).
    pub fn ident(self, chain_id: u64) -> String {
        let name = match self {
            Topic::Certs => "certs",
            Topic::Proposals => "proposals",
            Topic::Qcs => "qcs",
            Topic::Tcs => "tcs",
            Topic::TimeoutVotes => "timeout-votes",
            Topic::Batches => "batches",
        };
        format!("/solidus-v2/{chain_id}/{name}")
    }

    /// All broadcast topics (a node subscribes to every one).
    pub const ALL: [Topic; 6] = [
        Topic::Proposals,
        Topic::Qcs,
        Topic::Tcs,
        Topic::TimeoutVotes,
        Topic::Batches,
        Topic::Certs,
    ];
}

#[cfg(test)]
mod tests {
    use solidus_hotstuff2::ValidatorIndex;

    use super::*;

    fn sample_vote() -> Vote {
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        Vote {
            view: 3,
            block_hash: [7u8; 32],
            voter: 1 as ValidatorIndex,
            sig: sk.sign(b"x"),
        }
    }

    #[test]
    /// ⚠ NOT ALL VARIANTS, DESPITE WHAT THIS TEST USED TO BE CALLED. It covered
    /// 4 of 9: `Proposal`, `Tc` and `TimeoutVote` need a signed committee to
    /// construct and are exercised by the router's `leader_boot_effects` test
    /// against a real consensus core instead. Renamed rather than left claiming
    /// coverage it does not have — a lying test name is worse than a gap,
    /// because it stops anyone looking.
    fn encode_decode_roundtrip_covered_variants() {
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        let qc = QuorumCert::genesis([9u8; 32], sk.sign(b"g"));
        let messages = vec![
            NetMessage::Qc(qc.clone()),
            NetMessage::Vote(sample_vote()),
            NetMessage::Ack(solidus_mempool_dag::BatchAck {
                digest: solidus_mempool_dag::BatchDigest([1u8; 32]),
                worker: 0,
                signer: 2,
                sig: sk.sign(b"a"),
            }),
            NetMessage::Batch {
                batch: Batch {
                    transactions: vec![],
                },
                from: 3,
            },
            // The block-range pair. These matter more than most for wire
            // stability: bincode encodes a variant by INDEX, so a roundtrip on
            // the newest variants is what catches an accidental reorder of the
            // enum before it silently reinterprets a peer's messages.
            NetMessage::GetBlockRange { from: 1, to: 512 },
            NetMessage::BlockRange {
                blocks: vec![vec![1, 2, 3], vec![], vec![9; 64]],
                batches: vec![vec![4, 5, 6]],
            },
            NetMessage::GetBlockBody { hash: [7u8; 32] },
            NetMessage::BlockBody {
                bytes: vec![1, 2, 3, 4],
            },
        ];
        for m in messages {
            let bytes = m.encode();
            let back = NetMessage::decode(&bytes).expect("decode");
            assert_eq!(m, back);
        }
    }

    #[test]
    fn topic_assignment_matches_broadcast_vs_p2p() {
        let sk = solidus_crypto::bls::BlsSecretKey::generate();
        assert_eq!(
            NetMessage::Qc(QuorumCert::genesis([0; 32], sk.sign(b"g"))).gossip_topic(),
            Some(Topic::Qcs)
        );
        assert_eq!(
            NetMessage::Batch {
                batch: Batch {
                    transactions: vec![]
                },
                from: 0
            }
            .gossip_topic(),
            Some(Topic::Batches)
        );
        // Votes and acks are point-to-point (no gossip topic).
        assert_eq!(NetMessage::Vote(sample_vote()).gossip_topic(), None);
    }

    #[test]
    fn topics_are_chain_scoped_and_distinct() {
        let idents: Vec<String> = Topic::ALL.iter().map(|t| t.ident(2)).collect();
        // All distinct.
        for i in 0..idents.len() {
            for j in (i + 1)..idents.len() {
                assert_ne!(idents[i], idents[j]);
            }
        }
        // Chain-scoped: a different chain-id never collides.
        assert_ne!(Topic::Proposals.ident(2), Topic::Proposals.ident(3));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(NetMessage::decode(&[0xFF; 3]).is_err());
    }
}

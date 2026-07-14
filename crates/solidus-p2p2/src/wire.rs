//! The network wire: one bincode envelope for every message that crosses
//! the network, and the gossip-topic taxonomy. Deterministic and
//! transport-free — fully unit-testable without a swarm.

use serde::{Deserialize, Serialize};
use solidus_hotstuff2::{Proposal, QuorumCert, TimeoutCert, TimeoutVote, Vote};
use solidus_mempool_dag::{Batch, BatchAck};

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
    Batch { batch: Batch, from: u32 },
    Ack(BatchAck),
}

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
            NetMessage::Vote(_) | NetMessage::Ack(_) => None,
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
}

impl Topic {
    /// The chain-scoped topic string (distinct chain-ids never cross-talk).
    pub fn ident(self, chain_id: u64) -> String {
        let name = match self {
            Topic::Proposals => "proposals",
            Topic::Qcs => "qcs",
            Topic::Tcs => "tcs",
            Topic::TimeoutVotes => "timeout-votes",
            Topic::Batches => "batches",
        };
        format!("/solidus-v2/{chain_id}/{name}")
    }

    /// All broadcast topics (a node subscribes to every one).
    pub const ALL: [Topic; 5] = [
        Topic::Proposals,
        Topic::Qcs,
        Topic::Tcs,
        Topic::TimeoutVotes,
        Topic::Batches,
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
    fn encode_decode_roundtrip_all_variants() {
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

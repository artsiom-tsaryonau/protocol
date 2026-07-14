use serde::{Deserialize, Serialize};
use solidus_consensus::types::{Block, QuorumCertificate, TimeoutVote, Vote};
use solidus_txns::types::Transaction;

/// All messages that flow between consensus nodes.
// `Proposal` is dominated by an embedded Block (kilobytes) while votes
// are tens of bytes. Boxing Proposal would add an allocation per
// message on the consensus hot path; the wire format is the same after
// serde, so accepting the variant-size delta is the right tradeoff.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Leader proposes a new block.
    Proposal {
        block: Block,
        justify_qc: Option<QuorumCertificate>,
    },
    /// A validator's vote on a proposed block.
    VoteMsg(Vote),
    /// A validator's timeout vote when no QC arrives in time.
    TimeoutVoteMsg(TimeoutVote),
    /// A newly formed quorum certificate — broadcast so all nodes advance to
    /// the next round and the new leader can propose.
    NewQC(QuorumCertificate),
    /// A committed block gossiped to the network.
    NewBlock(Block),
    /// A new transaction gossiped to the network.
    NewTransaction(Transaction),
    /// Sync: request the committed block with this content hash.
    GetBlockByHash { hash: [u8; 32] },
    /// Sync: response carrying the requested block, or None if the peer lacks it.
    BlockByHash(Option<Block>),
    /// Sync: request the responder's committed tip hash.
    GetTip,
    /// Sync: response carrying the committed tip hash.
    Tip { hash: [u8; 32] },
    /// Sync (batch): request up to `count` contiguous canonical blocks
    /// starting at canon `seq = from_seq`. Caller bounds `count` to keep
    /// individual responses under the 4 MiB read cap (~50 blocks of
    /// modest size at testnet rates is comfortable; the responder caps
    /// further on its end).
    GetBlockRange { from_seq: u64, count: u16 },
    /// Sync (batch): response carrying contiguous canonical blocks. May
    /// be shorter than the requested `count` if the responder's canon
    /// head is below `from_seq + count` or if the responder is capping
    /// the per-response size. Empty `blocks` is a legal "I have nothing
    /// at that seq" reply (vs. dropping the request silently).
    BlockRange { blocks: Vec<Block> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_sync_variants_roundtrip() {
        let g = ConsensusMessage::GetBlockByHash { hash: [7u8; 32] };
        let bytes = serde_json::to_vec(&g).unwrap();
        match serde_json::from_slice::<ConsensusMessage>(&bytes).unwrap() {
            ConsensusMessage::GetBlockByHash { hash } => assert_eq!(hash, [7u8; 32]),
            _ => panic!("wrong variant"),
        }
        let none = ConsensusMessage::BlockByHash(None);
        let bytes = serde_json::to_vec(&none).unwrap();
        assert!(matches!(
            serde_json::from_slice::<ConsensusMessage>(&bytes).unwrap(),
            ConsensusMessage::BlockByHash(None)
        ));
        let tip = ConsensusMessage::Tip { hash: [3u8; 32] };
        let bytes = serde_json::to_vec(&tip).unwrap();
        assert!(matches!(
            serde_json::from_slice::<ConsensusMessage>(&bytes).unwrap(),
            ConsensusMessage::Tip { hash } if hash == [3u8; 32]
        ));
    }

    #[test]
    fn block_range_variants_roundtrip() {
        let req = ConsensusMessage::GetBlockRange {
            from_seq: 42,
            count: 32,
        };
        let bytes = serde_json::to_vec(&req).unwrap();
        match serde_json::from_slice::<ConsensusMessage>(&bytes).unwrap() {
            ConsensusMessage::GetBlockRange { from_seq, count } => {
                assert_eq!(from_seq, 42);
                assert_eq!(count, 32);
            }
            _ => panic!("wrong variant"),
        }
        // Empty BlockRange (legal: "I have nothing at that seq")
        let empty = ConsensusMessage::BlockRange { blocks: vec![] };
        let bytes = serde_json::to_vec(&empty).unwrap();
        assert!(matches!(
            serde_json::from_slice::<ConsensusMessage>(&bytes).unwrap(),
            ConsensusMessage::BlockRange { blocks } if blocks.is_empty()
        ));
    }
}

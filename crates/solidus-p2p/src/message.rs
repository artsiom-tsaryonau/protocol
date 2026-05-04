use serde::{Deserialize, Serialize};
use solidus_consensus::types::{Block, QuorumCertificate, TimeoutVote, Vote};
use solidus_txns::types::Transaction;

/// All messages that flow between consensus nodes.
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
}

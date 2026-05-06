//! HotStuff BFT consensus engine.
//!
//! Implements the core HotStuff consensus logic: block proposal, vote
//! collection, QC/TC formation, and 3-chain finality. The engine operates on
//! `Vote`, `Block`, and `QuorumCertificate` objects; the transport layer is
//! handled externally by the node main loop.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitvec::prelude::*;
use ed25519_dalek::SigningKey;
use tracing::{debug, info, warn};

use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use solidus_crypto::vrf::VrfOutput;
use solidus_state::executor::compute_state_root;
use solidus_state::store::{Store, CF_BLOCKS, CF_RECEIPTS};
use solidus_txns::types::Receipt;

use crate::leader::{elect_leader, verify_leader};
use crate::mempool::Mempool;
use crate::pacemaker::Pacemaker;
use crate::types::*;

// ---------------------------------------------------------------------------
// HotStuffConfig
// ---------------------------------------------------------------------------

/// Configuration for the HotStuff BFT consensus engine.
pub struct HotStuffConfig {
    /// Maximum number of transactions to include per block.
    pub max_block_txs: usize,
    /// Target block time in milliseconds.
    pub block_time_ms: u64,
    /// Minimum number of votes required to form a quorum (e.g., 3 out of 4).
    pub quorum_threshold: usize,
    /// Address that receives the treasury share of fees.
    pub treasury_address: Address,
    /// Skip VRF proof generation and verification (for dev/round-robin mode).
    pub skip_vrf: bool,
}

// ---------------------------------------------------------------------------
// HotStuffEngine
// ---------------------------------------------------------------------------

/// The core HotStuff BFT consensus engine.
///
/// Manages block proposals, vote collection, QC/TC aggregation, and the
/// 3-chain commit rule. Does not directly interact with the network transport;
/// messages are passed in and out by the caller.
pub struct HotStuffEngine {
    // Identity
    /// This validator's index in the committee.
    pub node_index: usize,
    /// This validator's Ed25519 signing key (used for VRF).
    pub ed25519_sk: SigningKey,
    /// This validator's BLS secret key (used for voting).
    pub bls_sk: BlsSecretKey,

    // Validator set
    /// The full ordered committee of validators.
    pub validators: Vec<ValidatorIdentity>,

    // Consensus state
    /// The pacemaker managing round timeouts.
    pub pacemaker: Pacemaker,
    /// The QC for the locked block (safety rule).
    pub locked_qc: Option<QuorumCertificate>,
    /// The highest QC this node has seen.
    pub highest_qc: Option<QuorumCertificate>,
    /// The height of the last committed block.
    pub last_committed_height: u64,

    // Vote/timeout collection
    /// Pending votes indexed by block hash.
    pub pending_votes: HashMap<[u8; 32], Vec<Vote>>,
    /// Pending timeout votes indexed by round.
    pub pending_timeout_votes: HashMap<u64, Vec<TimeoutVote>>,

    // VRF
    /// Seed for VRF leader election, derived from the previous round's VRF output.
    pub round_seed: [u8; 32],

    // Dependencies
    /// The persistent key-value store.
    pub store: Arc<Store>,
    /// The transaction mempool.
    pub mempool: Arc<Mutex<Mempool>>,
    /// Engine configuration.
    pub config: HotStuffConfig,

    // Uncommitted blocks for 3-chain finality
    /// Blocks that have been proposed/voted on but not yet committed, indexed by round.
    pub uncommitted_blocks: HashMap<u64, (Block, Vec<Receipt>)>,
}

impl HotStuffEngine {
    /// Create a new HotStuff consensus engine.
    pub fn new(
        node_index: usize,
        ed25519_sk: SigningKey,
        bls_sk: BlsSecretKey,
        validators: Vec<ValidatorIdentity>,
        store: Arc<Store>,
        mempool: Arc<Mutex<Mempool>>,
        config: HotStuffConfig,
    ) -> Self {
        Self {
            node_index,
            ed25519_sk,
            bls_sk,
            validators,
            pacemaker: Pacemaker::new(0),
            locked_qc: None,
            highest_qc: None,
            last_committed_height: 0,
            pending_votes: HashMap::new(),
            pending_timeout_votes: HashMap::new(),
            round_seed: [0u8; 32],
            store,
            mempool,
            config,
            uncommitted_blocks: HashMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Block construction
    // -----------------------------------------------------------------------

    /// Build a new block proposal from the mempool.
    ///
    /// Takes up to `max_block_txs` transactions, constructs the block header
    /// with the current round, proposer address, parent QC, and VRF proof.
    pub fn build_block(&self) -> Block {
        let round = self.pacemaker.current_round();
        let height = self.last_committed_height + 1 + self.uncommitted_blocks.len() as u64;

        // Take transactions from the mempool.
        let txs = {
            let mut pool = self.mempool.lock().expect("mempool lock poisoned");
            pool.take(self.config.max_block_txs)
        };

        // Compute transactions root.
        let transactions_root = compute_transactions_root(&txs);

        // Compute parent hash from highest QC's block hash, or zeros for genesis.
        let parent_hash = self
            .highest_qc
            .as_ref()
            .map(|qc| qc.block_hash)
            .unwrap_or([0u8; 32]);

        // Produce VRF proof for leader election (skipped in round-robin mode).
        let vrf_proof = if self.config.skip_vrf {
            None
        } else {
            let election = elect_leader(
                &self.ed25519_sk,
                self.node_index,
                &self.validators,
                &self.round_seed,
                round,
            );
            Some(election.vrf_proof)
        };

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as u64;

        // State root from current (pre-execution) store state.
        // TODO: for full correctness, proposer should execute speculatively
        // and include the post-execution state root. This requires separating
        // proposer vs. validator execution paths in the consensus loop.
        let state_root = compute_state_root(&self.store).unwrap_or([0u8; 32]);

        let header = BlockHeader {
            height,
            round,
            parent_hash,
            state_root,
            transactions_root,
            timestamp_ms,
            tx_count: txs.len() as u32,
            proposer: self.validators[self.node_index].address,
        };

        Block {
            header,
            transactions: txs,
            parent_qc: self.highest_qc.clone(),
            vrf_proof,
        }
    }

    // -----------------------------------------------------------------------
    // Vote processing
    // -----------------------------------------------------------------------

    /// Process an incoming vote.
    ///
    /// Collects votes per block hash. Ignores duplicate votes (same
    /// `voter_index`) and votes for the wrong round. When `quorum_threshold`
    /// votes are collected, aggregates BLS signatures and returns a QC.
    pub fn process_vote(&mut self, vote: Vote) -> Option<QuorumCertificate> {
        let current_round = self.pacemaker.current_round();

        // Reject votes from wrong round.
        if vote.round != current_round {
            warn!(
                vote_round = vote.round,
                current_round = current_round,
                "ignoring vote for wrong round"
            );
            return None;
        }

        let block_hash = vote.block_hash;

        let votes = self
            .pending_votes
            .entry(block_hash)
            .or_insert_with(Vec::new);

        // Reject duplicate votes from the same voter.
        if votes.iter().any(|v| v.voter_index == vote.voter_index) {
            debug!(
                voter_index = vote.voter_index,
                "ignoring duplicate vote"
            );
            return None;
        }

        votes.push(vote);

        // Check if we have reached quorum.
        if votes.len() < self.config.quorum_threshold {
            return None;
        }

        // We have quorum -- aggregate BLS signatures.
        let round = votes[0].round;

        let sig_refs: Vec<&BlsSignature> = votes.iter().map(|v| &v.bls_signature).collect();
        let aggregate_sig = match BlsSignature::aggregate(&sig_refs) {
            Ok(agg) => agg,
            Err(e) => {
                warn!(error = %e, "BLS aggregation failed");
                return None;
            }
        };

        // Build the signer bitvector.
        let n = self.validators.len();
        let mut signers = bitvec![u8, Msb0; 0; n];
        for v in votes {
            if v.voter_index < n {
                signers.set(v.voter_index, true);
            }
        }

        let qc = QuorumCertificate {
            block_hash,
            round,
            aggregate_sig,
            signers,
        };

        info!(
            round = qc.round,
            signer_count = qc.signer_count(),
            "quorum certificate formed"
        );

        // Clean up pending votes for this block.
        self.pending_votes.remove(&block_hash);

        Some(qc)
    }

    // -----------------------------------------------------------------------
    // Timeout vote processing
    // -----------------------------------------------------------------------

    /// Process an incoming timeout vote.
    ///
    /// Collects timeout votes per round. Ignores duplicate votes (same
    /// `voter_index`). When `quorum_threshold` votes are collected, aggregates
    /// BLS signatures and returns a TC carrying the highest QC seen among
    /// all timeout voters.
    pub fn process_timeout_vote(&mut self, tv: TimeoutVote) -> Option<TimeoutCertificate> {
        let tvs = self
            .pending_timeout_votes
            .entry(tv.round)
            .or_insert_with(Vec::new);

        // Reject duplicate timeout votes from the same voter.
        if tvs.iter().any(|t| t.voter_index == tv.voter_index) {
            debug!(
                voter_index = tv.voter_index,
                "ignoring duplicate timeout vote"
            );
            return None;
        }

        let round = tv.round;
        tvs.push(tv);

        let tvs = self.pending_timeout_votes.get(&round)?;
        if tvs.len() < self.config.quorum_threshold {
            return None;
        }

        // We have quorum -- aggregate BLS signatures.
        let sig_refs: Vec<&BlsSignature> = tvs.iter().map(|t| &t.bls_signature).collect();
        let aggregate_sig = match BlsSignature::aggregate(&sig_refs) {
            Ok(agg) => agg,
            Err(e) => {
                warn!(error = %e, "BLS aggregation for timeout failed");
                return None;
            }
        };

        // Build the signer bitvector.
        let n = self.validators.len();
        let mut signers = bitvec![u8, Msb0; 0; n];
        for t in tvs {
            if t.voter_index < n {
                signers.set(t.voter_index, true);
            }
        }

        // The TC carries the highest QC seen among all timeout voters.
        let highest_qc = tvs
            .iter()
            .filter_map(|t| t.highest_qc.as_ref())
            .max_by_key(|qc| qc.round)
            .cloned();

        let tc = TimeoutCertificate {
            round,
            aggregate_sig,
            signers,
            highest_qc,
        };

        info!(
            round = tc.round,
            signer_count = tc.signers.count_ones(),
            "timeout certificate formed"
        );

        // Clean up pending timeout votes for this round.
        self.pending_timeout_votes.remove(&round);

        Some(tc)
    }

    // -----------------------------------------------------------------------
    // Block validation and voting
    // -----------------------------------------------------------------------

    /// Validate an incoming block proposal and produce a vote if valid.
    ///
    /// Checks:
    /// 1. Block round matches the pacemaker's current round.
    /// 2. VRF proof is valid (if present).
    /// 3. Safety rule: if a `locked_qc` exists, the block's parent QC must
    ///    have round >= `locked_qc.round`, or the block extends the locked
    ///    QC's block.
    ///
    /// If valid, signs the block hash with BLS and returns a `Vote`.
    pub fn validate_and_vote(&self, block: &Block) -> Option<Vote> {
        let current_round = self.pacemaker.current_round();

        // 1. Round check.
        if block.header.round != current_round {
            warn!(
                block_round = block.header.round,
                current_round = current_round,
                "rejecting proposal: round mismatch"
            );
            return None;
        }

        // 2. VRF proof verification.
        if let Some(ref vrf_proof) = block.vrf_proof {
            // Find the proposer in the validator set.
            let proposer_index = self
                .validators
                .iter()
                .position(|v| v.address == block.header.proposer);

            match proposer_index {
                Some(idx) => {
                    // Recompute VRF output from proof bytes via BLAKE3.
                    let vrf_output = VrfOutput(blake3_hash(&vrf_proof.0));

                    if !verify_leader(
                        &self.validators[idx],
                        &self.round_seed,
                        block.header.round,
                        &vrf_output,
                        vrf_proof,
                    ) {
                        warn!(
                            proposer_index = idx,
                            round = block.header.round,
                            "rejecting proposal: invalid VRF proof"
                        );
                        return None;
                    }
                }
                None => {
                    warn!(
                        proposer = ?block.header.proposer,
                        "rejecting proposal: proposer not in validator set"
                    );
                    return None;
                }
            }
        }

        // 3. Safety check: locked_qc constraint.
        if let Some(ref locked_qc) = self.locked_qc {
            let parent_qc_ok = match &block.parent_qc {
                Some(parent_qc) => {
                    // Parent QC round >= locked QC round (liveness rule).
                    parent_qc.round >= locked_qc.round
                        // OR block extends the locked QC's block (safety rule).
                        || block.header.parent_hash == locked_qc.block_hash
                }
                None => {
                    // No parent QC but we have a locked QC -- only safe if
                    // the block extends the locked QC's block.
                    block.header.parent_hash == locked_qc.block_hash
                }
            };

            if !parent_qc_ok {
                warn!(
                    locked_round = locked_qc.round,
                    "rejecting proposal: fails safety check against locked QC"
                );
                return None;
            }
        }

        // Block is valid -- sign with BLS and return vote.
        let block_hash = block.hash();
        let bls_signature = self.bls_sk.sign(&block_hash);

        debug!(
            round = current_round,
            voter_index = self.node_index,
            "casting vote"
        );

        Some(Vote {
            block_hash,
            round: current_round,
            voter_index: self.node_index,
            bls_signature,
        })
    }

    // -----------------------------------------------------------------------
    // QC state management
    // -----------------------------------------------------------------------

    /// Update consensus state when a new QC is formed.
    ///
    /// - Updates `highest_qc` if the new QC has a higher round.
    /// - Updates `locked_qc`: the previous `highest_qc` becomes the new
    ///   `locked_qc` (one-behind locking rule).
    pub fn on_new_qc(&mut self, qc: &QuorumCertificate) {
        let new_round = qc.round;

        let current_highest = self.highest_qc.as_ref().map(|q| q.round).unwrap_or(0);

        if new_round > current_highest {
            // The old highest becomes the new locked QC.
            if self.highest_qc.is_some() {
                self.locked_qc = self.highest_qc.clone();
            }
            self.highest_qc = Some(qc.clone());

            debug!(
                new_highest_round = new_round,
                locked_round = self.locked_qc.as_ref().map(|q| q.round),
                "updated QC state"
            );
        }
    }

    // -----------------------------------------------------------------------
    // 3-chain commit
    // -----------------------------------------------------------------------

    /// Attempt to commit blocks using the 3-chain finality rule.
    ///
    /// Blocks whose `round + 2 <= highest_qc.round` are considered finalized.
    /// Committed blocks are removed from `uncommitted_blocks`, persisted to
    /// the store, and `last_committed_height` is updated.
    pub fn try_commit(&mut self) -> Vec<(Block, Vec<Receipt>)> {
        let highest_round = match self.highest_qc.as_ref() {
            Some(qc) => qc.round,
            None => return vec![],
        };

        // Collect rounds that are ready to commit: round + 2 <= highest_round.
        let mut committable_rounds: Vec<u64> = self
            .uncommitted_blocks
            .keys()
            .filter(|&&r| r + 2 <= highest_round)
            .copied()
            .collect();

        // Sort so we commit in order.
        committable_rounds.sort();

        let mut committed = Vec::new();

        for round in committable_rounds {
            if let Some((block, receipts)) = self.uncommitted_blocks.remove(&round) {
                let height = block.header.height;

                // Persist the block to the store.
                if let Ok(block_bytes) = serde_json::to_vec(&block) {
                    if let Err(e) =
                        self.store
                            .put(CF_BLOCKS, &height.to_le_bytes(), &block_bytes)
                    {
                        warn!(height = height, error = %e, "failed to persist block");
                    }
                }

                // Persist each receipt to the store.
                for receipt in &receipts {
                    if let Ok(receipt_bytes) = serde_json::to_vec(receipt) {
                        if let Err(e) =
                            self.store
                                .put(CF_RECEIPTS, &receipt.tx_hash, &receipt_bytes)
                        {
                            warn!(
                                tx_hash = ?receipt.tx_hash,
                                error = %e,
                                "failed to persist receipt"
                            );
                        }
                    }
                }

                if height > self.last_committed_height {
                    self.last_committed_height = height;
                }

                info!(
                    height = height,
                    round = round,
                    tx_count = block.header.tx_count,
                    "committed block via 3-chain finality"
                );

                committed.push((block, receipts));
            }
        }

        committed
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::bls::BlsSecretKey;
    use solidus_crypto::ed25519::generate_signing_key;
    use solidus_crypto::keys::Address;
    use tempfile::tempdir;

    /// Create `n` HotStuff engines sharing a mempool (for unit testing).
    ///
    /// Each engine has unique Ed25519/BLS keys and its own store.
    /// `quorum_threshold = (n * 2 / 3) + 1`.
    fn setup_engines(n: usize) -> Vec<HotStuffEngine> {
        let mempool = Arc::new(Mutex::new(Mempool::new()));

        // Generate keys for all validators.
        let mut ed_keys = Vec::with_capacity(n);
        let mut bls_keys = Vec::with_capacity(n);
        let mut validators = Vec::with_capacity(n);

        for _ in 0..n {
            let ed_sk = generate_signing_key();
            let bls_sk = BlsSecretKey::generate();
            validators.push(ValidatorIdentity {
                address: Address::from_public_key(&ed_sk.verifying_key()),
                ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
                bls_pubkey: bls_sk.public_key(),
            });
            ed_keys.push(ed_sk);
            bls_keys.push(bls_sk);
        }

        let quorum_threshold = (n * 2 / 3) + 1;

        let mut engines = Vec::with_capacity(n);

        for i in 0..n {
            let dir = tempdir().expect("failed to create temp dir");
            let store = Arc::new(
                Store::open(dir.path()).expect("failed to open store"),
            );

            // We need the tempdir to outlive the store, so we leak it.
            // In real code the tempdir would be managed by the test harness.
            // For unit tests this is acceptable.
            std::mem::forget(dir);

            let config = HotStuffConfig {
                max_block_txs: 100,
                block_time_ms: 1000,
                quorum_threshold,
                treasury_address: Address::from_bytes([0xAAu8; 20]),
                skip_vrf: false,
            };

            engines.push(HotStuffEngine::new(
                i,
                ed_keys[i].clone(),
                bls_keys.remove(0),
                validators.clone(),
                store,
                Arc::clone(&mempool),
                config,
            ));
        }

        engines
    }

    // -----------------------------------------------------------------------
    // Test 1: process_vote reaches quorum
    // -----------------------------------------------------------------------

    #[test]
    fn process_vote_reaches_quorum() {
        let mut engines = setup_engines(4);
        // quorum_threshold = (4 * 2 / 3) + 1 = 3

        // Engine 0 builds a block.
        let block = engines[0].build_block();

        // Engines 1, 2, 3 validate and vote on it.
        let vote1 = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");
        let vote2 = engines[2]
            .validate_and_vote(&block)
            .expect("engine 2 should vote");
        let vote3 = engines[3]
            .validate_and_vote(&block)
            .expect("engine 3 should vote");

        // Engine 0 processes votes. QC should form on the 3rd vote.
        let result1 = engines[0].process_vote(vote1);
        assert!(result1.is_none(), "QC should not form with 1 vote");

        let result2 = engines[0].process_vote(vote2);
        assert!(result2.is_none(), "QC should not form with 2 votes");

        let result3 = engines[0].process_vote(vote3);
        assert!(result3.is_some(), "QC should form with 3 votes");

        let qc = result3.unwrap();
        assert_eq!(qc.round, 0);
        assert_eq!(qc.block_hash, block.hash());
        assert_eq!(qc.signer_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Test 2: duplicate vote ignored
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_vote_ignored() {
        let mut engines = setup_engines(4);

        let block = engines[0].build_block();

        let vote1 = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        // Process the same vote twice.
        let result1 = engines[0].process_vote(vote1.clone());
        assert!(result1.is_none());

        let result2 = engines[0].process_vote(vote1);
        assert!(result2.is_none(), "duplicate vote should be ignored");

        // Only 1 unique vote should be recorded.
        let votes = engines[0]
            .pending_votes
            .get(&block.hash())
            .expect("should have pending votes");
        assert_eq!(votes.len(), 1, "only one unique vote should be recorded");
    }

    // -----------------------------------------------------------------------
    // Test 3: vote for wrong round ignored
    // -----------------------------------------------------------------------

    #[test]
    fn vote_for_wrong_round_ignored() {
        let mut engines = setup_engines(4);

        let block = engines[0].build_block();

        let mut vote = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        // Tamper with the round.
        vote.round = 999;

        let result = engines[0].process_vote(vote);
        assert!(result.is_none(), "vote for wrong round should be ignored");

        // No votes should be recorded for the block.
        assert!(
            engines[0].pending_votes.get(&block.hash()).is_none(),
            "no votes should be recorded for tampered-round vote"
        );
    }

    // -----------------------------------------------------------------------
    // Test 4: timeout vote reaches quorum
    // -----------------------------------------------------------------------

    #[test]
    fn timeout_vote_reaches_quorum() {
        let mut engines = setup_engines(4);
        // quorum_threshold = 3

        let round = engines[0].pacemaker.current_round();

        // Create timeout votes from engines 0, 1, 2.
        let tv0 = TimeoutVote {
            round,
            voter_index: 0,
            highest_qc: None,
            bls_signature: engines[0].bls_sk.sign(&round.to_le_bytes()),
        };
        let tv1 = TimeoutVote {
            round,
            voter_index: 1,
            highest_qc: None,
            bls_signature: engines[1].bls_sk.sign(&round.to_le_bytes()),
        };
        let tv2 = TimeoutVote {
            round,
            voter_index: 2,
            highest_qc: None,
            bls_signature: engines[2].bls_sk.sign(&round.to_le_bytes()),
        };

        // Process timeout votes on engine 0.
        let result0 = engines[0].process_timeout_vote(tv0);
        assert!(result0.is_none(), "TC should not form with 1 timeout vote");

        let result1 = engines[0].process_timeout_vote(tv1);
        assert!(result1.is_none(), "TC should not form with 2 timeout votes");

        let result2 = engines[0].process_timeout_vote(tv2);
        assert!(result2.is_some(), "TC should form with 3 timeout votes");

        let tc = result2.unwrap();
        assert_eq!(tc.round, round);
        assert_eq!(tc.signers.count_ones(), 3);
        assert!(tc.highest_qc.is_none());
    }
}

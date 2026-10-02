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
use solidus_state::executor::{
    block_touched_accounts, compute_state_root, execute_block, mirror_account_to_committed,
};
use solidus_state::store::{Store, CF_BLOCKS, CF_RECEIPTS};
use solidus_txns::types::Receipt;

use crate::leader::{elect_leader, verify_leader};
use crate::mempool::Mempool;
use crate::pacemaker::Pacemaker;
use crate::types::*;

// ---------------------------------------------------------------------------
// SyncError
// ---------------------------------------------------------------------------

/// Errors returned when applying a batch of synced blocks.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("empty sync batch")]
    Empty,
    #[error("block {height} parent_hash does not link to the chain")]
    BrokenLink { height: u64 },
    #[error("block {height} has no/invalid certifying QC")]
    BadQc { height: u64 },
    #[error("block {height} state_root mismatch after re-execution")]
    StateRootMismatch { height: u64 },
}

// ---------------------------------------------------------------------------
// HotStuffConfig
// ---------------------------------------------------------------------------

/// Configuration for the HotStuff BFT consensus engine.
///
/// Note: there is deliberately NO `block_time_ms` here. Proposals are
/// event-driven (new transactions, finalization padding, idle heartbeat),
/// not clock-driven. A `block_time_ms` field existed until 2026-07-13 but
/// was never read by anything — a dead knob that invited no-op "fixes".
pub struct HotStuffConfig {
    /// Maximum number of transactions to include per block.
    pub max_block_txs: usize,
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
    /// A QC this node formed from its OWN vote (only possible when its vote
    /// alone reaches quorum, i.e. a single-validator committee). The node's
    /// event loop applies it on its next turn rather than inline, which avoids
    /// a propose -> apply_qc -> propose recursion. `None` otherwise.
    pub pending_self_qc: Option<QuorumCertificate>,
    /// The height of the last committed block.
    pub last_committed_height: u64,
    /// Hash of the last committed block (the finalized tip). [0;32] until first commit.
    pub last_committed_hash: [u8; 32],

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

    /// The last round this node proposed in. Event-driven proposing can be
    /// triggered by several signals (tx wake, gossip, QC/TC advance,
    /// heartbeat) that may fire more than once within a round; a second
    /// same-round proposal would re-drain the mempool and EVICT the
    /// in-flight block from `uncommitted_blocks`, silently losing its
    /// transactions. One proposal per round, ever.
    pub last_proposed_round: Option<u64>,
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
            pending_self_qc: None,
            last_committed_height: 0,
            last_committed_hash: [0u8; 32],
            pending_votes: HashMap::new(),
            pending_timeout_votes: HashMap::new(),
            round_seed: [0u8; 32],
            store,
            mempool,
            config,
            uncommitted_blocks: HashMap::new(),
            last_proposed_round: None,
        }
    }

    // -----------------------------------------------------------------------
    // Block construction
    // -----------------------------------------------------------------------

    /// Build a new block proposal from the mempool.
    ///
    /// Takes up to `max_block_txs` transactions, **executes them
    /// speculatively against the store**, computes the post-execution
    /// state root, and constructs the block header with the current
    /// round, proposer address, parent QC, and VRF proof.
    ///
    /// Speculative execution at propose time (added 2026-05-19) means
    /// the header commits to the POST-execution state root — the
    /// correct semantics. Validators receiving the proposal re-execute
    /// (idempotently, via the `CF_RECEIPTS[tx_hash]` short-circuit
    /// added 2026-05-18 to `execute_block`) and verify that their
    /// resulting state root matches the proposer's claim. A proposer
    /// that lies about its state root no longer wins votes.
    ///
    /// In production with per-validator stores: each validator executes
    /// against its own state, all converge on the same state root. In
    /// dev-testnet with a shared store: the proposer's writes are
    /// immediately visible to all validators; idempotency makes the
    /// receiver-side execute_block a no-op; everyone's
    /// `compute_state_root` returns the same value.
    ///
    /// Returns the block together with its speculative-execution receipts
    /// so the proposer can track its own proposal in `uncommitted_blocks`
    /// (symmetric with receivers) and commit it via 3-chain finality.
    pub fn build_block(&self) -> (Block, Vec<Receipt>) {
        let round = self.pacemaker.current_round();
        let height = self.last_committed_height + 1 + self.uncommitted_blocks.len() as u64;

        // Take transactions from the mempool. Recover from a poisoned mutex
        // by extracting the inner Mempool — poisoning means a previous holder
        // panicked, but the mempool's internal state (Vec of txs + HashSet of
        // hashes) is plain data that's safe to read. Logging instead of
        // panicking keeps the node up; the next round can re-attempt.
        let txs = {
            let mut pool = match self.mempool.lock() {
                Ok(p) => p,
                Err(poisoned) => {
                    warn!("mempool lock poisoned; recovering inner state");
                    poisoned.into_inner()
                }
            };
            pool.take(self.config.max_block_txs)
        };

        // Compute transactions root.
        let transactions_root = compute_transactions_root(&txs);

        // Compute parent hash from the highest QC's block hash. With no QC
        // yet (fresh process), fall back to the last committed hash so a
        // restart with a surviving datadir EXTENDS the canonical chain
        // instead of forking a second chain from the genesis sentinel —
        // the backfill walker links the new block to canon via its parent.
        // At true genesis `last_committed_hash` is [0; 32], preserving the
        // original behavior.
        let parent_hash = self
            .highest_qc
            .as_ref()
            .map(|qc| qc.block_hash)
            .unwrap_or(self.last_committed_hash);

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

        // Block timestamp in ms since UNIX epoch. A clock before 1970 is
        // physically impossible on real hardware, but we defensively fall
        // back to 0 rather than panic: a header timestamp of 0 is clearly
        // invalid and observable, vs. a panic that crashes the proposer.
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Speculatively execute the block's transactions so the header
        // can commit to the post-execution state root. Receipts are
        // returned to the caller so the proposer can track its own block
        // for 3-chain commit. `network = "testnet"` matches what the
        // receiver-side execute_block call passes; the network string is
        // only used inside DID-handler payloads to build the DID prefix
        // and the HotStuff config doesn't currently plumb it through
        // (separate TODO).
        let receipts = execute_block(
            &self.store,
            &txs,
            height,
            timestamp_ms,
            &self.config.treasury_address,
            &[],
            "testnet",
        )
        .unwrap_or_default();

        // State root AFTER executing the block — committing to this
        // value in the header is what makes the validator-side
        // state_root check in `handle_consensus_message` meaningful.
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

        (
            Block {
                header,
                transactions: txs,
                parent_qc: self.highest_qc.clone(),
                vrf_proof,
            },
            receipts,
        )
    }

    /// Whether this engine has consensus work that justifies proposing:
    /// pending mempool transactions, or an uncommitted tx-bearing block
    /// whose 3-chain finalization still needs follow-up rounds.
    ///
    /// Uncommitted EMPTY blocks (finalization padding / heartbeats) are
    /// deliberately NOT work: committing padding requires proposing more
    /// padding, so counting them would make the proposer run forever —
    /// the exact free-run this gate exists to stop. Leftover padding
    /// commits as rounds advance on the next burst or heartbeat.
    pub fn has_proposable_work(&self) -> bool {
        let pool_pending = match self.mempool.lock() {
            Ok(p) => !p.is_empty(),
            Err(poisoned) => !poisoned.into_inner().is_empty(),
        };
        pool_pending
            || self
                .uncommitted_blocks
                .values()
                .any(|(b, _)| b.header.tx_count > 0)
    }

    /// Adopt the canonical-ledger tip as this engine's committed state.
    ///
    /// STARTUP-ONLY. On a process restart with a surviving datadir, the
    /// engine would otherwise start at `last_committed_height = 0` and
    /// propose a second height-1 chain into the same store. Reading the
    /// canon head restores height/hash continuity; account/DID state needs
    /// no replay here because dev-testnet executes into the same store the
    /// process just reopened (full nodes replay via
    /// [`Self::rebuild_state_from_canon`] instead).
    ///
    /// Returns the adopted tip height, or `None` when canon is empty
    /// (fresh chain — genesis behavior unchanged).
    ///
    /// Uses `canon_tip_scan` (forward-scan past the head pointer), not the
    /// raw pointer: engine/walker interleaving on the shared store could
    /// leave the pointer behind the real entries, and resuming from a
    /// stale tip orphans the blocks past it.
    pub fn adopt_canon_tip(&mut self) -> Option<u64> {
        let (_, hash) = crate::ledger::canon_tip_scan(&self.store).ok().flatten()?;
        let block = crate::ledger::get_block_by_hash(&self.store, &hash)
            .ok()
            .flatten()?;
        let height = block.header.height;
        if height > self.last_committed_height {
            self.last_committed_height = height;
            self.last_committed_hash = hash;
        }
        Some(height)
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

        // Reject votes from outside the committee. The bitvector loop below
        // already skipped an out-of-range index, which silently dropped the
        // signer while its signature still entered the aggregate: a QC that
        // cannot verify. Rejecting at intake is the only place that helps.
        let Some(voter) = self.validators.get(vote.voter_index) else {
            warn!(
                voter_index = vote.voter_index,
                committee_size = self.validators.len(),
                "ignoring vote from outside the committee"
            );
            return None;
        };

        // Verify the vote's signature against that validator's key.
        //
        // ⚠ This is INDIVIDUAL verification, deliberately, and not the
        // aggregate path. `QuorumCertificate::verify` uses
        // `fast_aggregate_verify`, which is a proof-of-possession scheme
        // operation being run under a basic-scheme (`_NUL_`) DST with no PoP
        // registered anywhere: unsafe for same-message aggregation, filed
        // separately as the BLS scheme mismatch. `BlsSignature::verify` on a
        // single key carries none of that, and checking each vote here blunts
        // the rogue-key attack as a side effect, because a rogue key's
        // INDIVIDUAL signature does not verify.
        if !vote
            .bls_signature
            .verify(&voter.bls_pubkey, &vote.block_hash)
        {
            warn!(
                voter_index = vote.voter_index,
                round = vote.round,
                "ignoring vote whose BLS signature does not verify"
            );
            return None;
        }

        let block_hash = vote.block_hash;

        let votes = self.pending_votes.entry(block_hash).or_default();

        // Reject duplicate votes from the same voter.
        if votes.iter().any(|v| v.voter_index == vote.voter_index) {
            debug!(voter_index = vote.voter_index, "ignoring duplicate vote");
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

    /// Record this node's own vote on a block it is proposing.
    ///
    /// The proposer broadcasts its proposal to peers but does NOT receive its
    /// own proposal back (broadcast skips the sender), so without this the
    /// proposer's vote would never be counted and a QC would require ALL
    /// `n - 1` peer votes — leaving zero fault margin (and making `n < 4` unable
    /// to form a QC at all). Recording the proposer's own vote means a QC needs
    /// only `quorum - 1` peer votes, matching how every replica counts its own
    /// vote. This is the proposal-vote analogue of
    /// [`Self::record_own_timeout_vote`].
    ///
    /// Returns a QC immediately if the proposer's own vote already reaches
    /// quorum (e.g. a single-validator network).
    pub fn record_own_vote(&mut self, vote: Vote) -> Option<QuorumCertificate> {
        debug_assert_eq!(vote.voter_index, self.node_index, "must be our own vote");
        self.process_vote(vote)
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
    ///
    /// On a duplicate vote we still re-check whether the bucket already meets
    /// quorum and, if so, attempt TC formation again — this protects against
    /// a wedge where a prior aggregation attempt failed transiently and the
    /// bucket was left at quorum size with no way to re-trigger formation
    /// (every subsequent vote from a known voter would otherwise short-circuit
    /// out at the dedup check).
    pub fn process_timeout_vote(&mut self, tv: TimeoutVote) -> Option<TimeoutCertificate> {
        // Reject a voter index outside the committee BEFORE anything else.
        // `try_form_tc`'s bitvector loop skips such an index while its
        // signature still enters the aggregate, so the TC's signer set would
        // not match what was aggregated -- the same mismatch the vote path
        // had. Rejecting at intake is the only place that helps.
        let Some(voter) = self.validators.get(tv.voter_index) else {
            warn!(
                voter_index = tv.voter_index,
                committee = self.validators.len(),
                "rejected timeout vote: voter index outside the committee"
            );
            return None;
        };

        // Verify the signature against that committee member's key. Until
        // 2026-08-24 a timeout vote was accumulated on trust, so quorum-many
        // forged votes from any peer forced a TC, which advances the round and
        // rotates the leader. That is a liveness attack, repeatable at will.
        if !tv
            .bls_signature
            .verify(&voter.bls_pubkey, &TimeoutVote::signing_bytes(tv.round))
        {
            warn!(
                voter_index = tv.voter_index,
                round = tv.round,
                "rejected timeout vote: BLS signature does not verify"
            );
            return None;
        }

        let tvs = self.pending_timeout_votes.entry(tv.round).or_default();
        let round = tv.round;

        // Dedup against a known voter — but if the bucket already meets
        // quorum, fall through to TC formation rather than silently dropping.
        let is_duplicate = tvs.iter().any(|t| t.voter_index == tv.voter_index);
        if is_duplicate {
            if tvs.len() < self.config.quorum_threshold {
                debug!(
                    voter_index = tv.voter_index,
                    round = round,
                    "ignoring duplicate timeout vote (below quorum)"
                );
                return None;
            }
            debug!(
                voter_index = tv.voter_index,
                round = round,
                len = tvs.len(),
                "duplicate timeout vote, bucket already at quorum — re-attempting TC formation"
            );
        } else {
            tvs.push(tv);
        }

        self.try_form_tc(round)
    }

    /// Attempt to form a TC from the votes currently buffered for `round`.
    ///
    /// Returns `Some(tc)` when the bucket meets quorum and BLS aggregation
    /// succeeds; on success the bucket is cleared. Returns `None` when below
    /// quorum, when no bucket exists for the round, or when aggregation fails
    /// (in which case the bucket is left intact so a subsequent call can
    /// retry — see `process_timeout_vote`'s duplicate-vote handling).
    fn try_form_tc(&mut self, round: u64) -> Option<TimeoutCertificate> {
        let tvs = self.pending_timeout_votes.get(&round)?;
        if tvs.len() < self.config.quorum_threshold {
            return None;
        }

        // We have quorum -- aggregate BLS signatures.
        let sig_refs: Vec<&BlsSignature> = tvs.iter().map(|t| &t.bls_signature).collect();
        let aggregate_sig = match BlsSignature::aggregate(&sig_refs) {
            Ok(agg) => agg,
            Err(e) => {
                warn!(error = %e, round = round, "BLS aggregation for timeout failed");
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

    /// Record this node's own timeout vote.
    ///
    /// The local pacemaker timeout broadcasts a [`TimeoutVote`] to peers, but
    /// the in-process channel transport (and any reasonable libp2p impl) does
    /// not loop the broadcast back to the sender. Without this method the
    /// local node would never include its own vote in `pending_timeout_votes`,
    /// and would need ALL `n - 1` peer votes to reach quorum — a fragile
    /// 1-message-loss-equals-wedge condition. By inserting our own vote we
    /// only need `quorum - 1` peer votes, which matches every other node's
    /// view of the same round.
    ///
    /// Idempotent: calling twice for the same round is a no-op (the dedup
    /// check still applies).
    pub fn record_own_timeout_vote(&mut self, tv: TimeoutVote) -> Option<TimeoutCertificate> {
        debug_assert_eq!(tv.voter_index, self.node_index, "must be our own vote");
        self.process_timeout_vote(tv)
    }

    /// Drop pending-timeout-vote buckets for any round strictly less than
    /// `new_round`. Call this whenever the pacemaker advances so we don't
    /// leak memory and — more importantly — so a stale bucket cannot wedge
    /// the engine if dedup hits later.
    pub fn prune_stale_timeout_votes(&mut self, new_round: u64) {
        self.pending_timeout_votes.retain(|&r, _| r >= new_round);
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

        // 2. Proposer legitimacy.
        //
        // ⚠ THIS USED TO LIVE ENTIRELY INSIDE `if let Some(vrf_proof)` WITH NO `else`, and the
        // deployment runs `skip_vrf: true`, so its blocks carry no proof and the whole section was
        // SKIPPED -- including the check that the proposer is a validator at all. Any peer could
        // propose a block and every honest node would vote on it.
        //
        // The set membership check is unconditional now. What "legitimate" means then depends on
        // the mode, and both branches end in a decision rather than a fall-through.
        if self.validators.is_empty() {
            warn!("rejecting proposal: empty validator set");
            return None;
        }
        let Some(proposer_index) = self
            .validators
            .iter()
            .position(|v| v.address == block.header.proposer)
        else {
            warn!(
                proposer = ?block.header.proposer,
                "rejecting proposal: proposer not in validator set"
            );
            return None;
        };

        if self.config.skip_vrf {
            // Round-robin mode. The leader is `round % n`, which is EXACTLY the rule
            // `try_propose_if_leader` uses to decide whether to propose; if these two ever
            // disagree the chain stops producing blocks, so they must be read together.
            let leader_index = (block.header.round as usize) % self.validators.len();
            if proposer_index != leader_index {
                warn!(
                    proposer_index,
                    leader_index,
                    round = block.header.round,
                    "rejecting proposal: proposer is not this round's leader"
                );
                return None;
            }
        } else {
            // VRF mode. An ABSENT proof is now a rejection rather than a skip.
            let Some(ref vrf_proof) = block.vrf_proof else {
                warn!(
                    round = block.header.round,
                    "rejecting proposal: VRF is required and the block carries no proof"
                );
                return None;
            };

            // Recompute VRF output from proof bytes via BLAKE3.
            let vrf_output = VrfOutput(blake3_hash(&vrf_proof.0));

            if !verify_leader(
                &self.validators[proposer_index],
                &self.round_seed,
                block.header.round,
                &vrf_output,
                vrf_proof,
            ) {
                warn!(
                    proposer_index,
                    round = block.header.round,
                    "rejecting proposal: invalid VRF proof"
                );
                return None;
            }

            // ⚠ WHAT THIS STILL DOES NOT ESTABLISH, stated so nobody reads it as more than it is:
            // a valid proof proves "you are a validator and you computed a correct VRF output for
            // this round". It does NOT prove you WON. Deciding the winner means comparing outputs
            // via `select_leader_from_outputs`, which needs EVERY validator's output, and a
            // Byzantine-tolerant protocol cannot wait on all n. That quorum rule is a protocol
            // design decision and is filed, not guessed at here.
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
    pub fn on_new_qc(&mut self, qc: &QuorumCertificate) -> bool {
        // A QC reaches here from three directions -- a proposal's `justify_qc`,
        // a relayed `NewQC`, and the one this node forms from votes it has
        // already verified. Only the third is trustworthy by construction, and
        // until 2026-08-24 none of them was checked: `QuorumCertificate::verify`
        // was written, complete, and called by nothing outside its own unit
        // tests. Adopting an unverified QC moves `locked_qc` and feeds
        // `try_commit`, so the cost of skipping this is a finalised block that
        // no validator voted for.
        //
        // Return `false` rather than panicking: a bad QC is an untrusted peer's
        // message, not a local invariant violation.
        //
        // ⚠ This closes forgery by a party holding NO committee key. It does
        // NOT close the rogue-key attack, because `verify` reaches
        // `fast_aggregate_verify` under a basic-scheme `_NUL_` DST with no
        // proof of possession anywhere in the workspace. That is the separately
        // filed BLS SCHEME MISMATCH [critical] [pre-mainnet], held by the fact
        // that validator BLS keys are operator config on a permissioned
        // committee and cannot be registered permissionlessly.
        // `check-bls-rogue-key-tripwire.mjs` fails the day that changes.
        if !qc.verify(&self.validators, self.config.quorum_threshold) {
            warn!(
                round = qc.round,
                signer_count = qc.signer_count(),
                "rejected QC: aggregate signature does not verify for the signer set"
            );
            return false;
        }

        let new_round = qc.round;

        // Compare against the Option, not an unwrap_or(0) sentinel: with the
        // sentinel, a ROUND-0 QC (every fresh chain start, and every restart
        // since rounds reset) was silently dropped — `0 > 0` is false — so
        // the round-1 proposer built on `highest_qc = None`, parenting its
        // block on the genesis sentinel and ORPHANING the round-0 block from
        // the canonical chain. Under the pre-2026-07-13 free-run that block
        // was an empty throwaway; under event-driven proposing it is the
        // first transaction-bearing block after every restart.
        let current_highest = self.highest_qc.as_ref().map(|q| q.round);

        if current_highest.is_none_or(|r| new_round > r) {
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

        true
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
                    if let Err(e) = self
                        .store
                        .put(CF_BLOCKS, &height.to_le_bytes(), &block_bytes)
                    {
                        warn!(height = height, error = %e, "failed to persist block");
                    }
                }

                // Canonical ledger: append SYNCHRONOUSLY with the commit when
                // the block extends the current canon head (or starts canon at
                // genesis). Before 2026-07-13 canon was written only by the
                // asynchronous backfill walker (500ms tick), so a crash inside
                // that lag window left canon behind the committed tip — and
                // restart-resume (`adopt_canon_tip`) reads canon, so it would
                // resume from a stale tip and orphan committed blocks. The
                // walker remains for full nodes and gap-fill; this append is
                // contiguity-guarded and idempotent, so walker/engine overlap
                // rewrites the same (seq, hash) pairs.
                let canon_extend = match crate::ledger::canon_tip_scan(&self.store) {
                    Ok(Some((seq, head_hash))) => {
                        (block.header.parent_hash == head_hash).then_some(seq + 1)
                    }
                    Ok(None) => (block.header.parent_hash == [0u8; 32]).then_some(0),
                    Err(_) => None,
                };
                if let Some(seq) = canon_extend {
                    if let Err(e) = crate::ledger::canon_append(&self.store, seq, &block.hash()) {
                        warn!(height = height, seq = seq, error = %e, "failed to append block to canon");
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

                // Canonical-ledger store: persist the block by hash (storage-only).
                if let Err(e) = crate::ledger::put_block_by_hash(&self.store, &block) {
                    warn!(height = height, error = %e, "failed to persist block by hash");
                }
                if height > self.last_committed_height {
                    self.last_committed_height = height;
                    self.last_committed_hash = block.hash();
                }

                // Mirror touched accounts from CF_ACCOUNTS (live/speculative)
                // to CF_COMMITTED_ACCOUNTS (finalized view). RPC reads against
                // the committed view see this block's state effects only now
                // — never the speculative effects of validated-but-uncommitted
                // blocks. Derived syntactically from block.transactions; see
                // executor::block_touched_accounts for the over-approximation
                // rationale.
                let validator_addresses: Vec<Address> =
                    self.validators.iter().map(|v| v.address).collect();
                let touched = block_touched_accounts(
                    &block.transactions,
                    &self.config.treasury_address,
                    &validator_addresses,
                );
                for addr in &touched {
                    if let Err(e) = mirror_account_to_committed(&self.store, addr) {
                        warn!(
                            height = height,
                            addr = %addr,
                            error = %e,
                            "failed to mirror account to committed view"
                        );
                    }
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

    /// Hash of the finalized (committed) tip — the backfill walker's target.
    pub fn committed_tip_hash(&self) -> [u8; 32] {
        self.last_committed_hash
    }

    /// Re-execute the canonical chain (seq 0..=head) to rebuild state, advancing
    /// committed height/hash. Returns the tip seq. STARTUP/PRE-LOOP USE ONLY —
    /// callers must NOT run this concurrently with the live consensus loop.
    pub fn rebuild_state_from_canon(&mut self) -> Result<u64, SyncError> {
        let (head, _) = match crate::ledger::canon_head(&self.store) {
            Ok(Some(h)) => h,
            _ => return Ok(0),
        };
        for seq in 0..=head {
            let hash = crate::ledger::canon_get(&self.store, seq)
                .ok()
                .flatten()
                .ok_or(SyncError::BrokenLink { height: seq })?;
            let block = crate::ledger::get_block_by_hash(&self.store, &hash)
                .ok()
                .flatten()
                .ok_or(SyncError::BrokenLink { height: seq })?;
            // Re-execute (executor is idempotent on tx_hash) to adopt block state.
            let _ = execute_block(
                &self.store,
                &block.transactions,
                block.header.height,
                block.header.timestamp_ms,
                &self.config.treasury_address,
                &[],
                "testnet",
            );
            // Mirror this block's touched accounts to the committed view.
            // Full nodes never call try_commit, but they DO reach RPC reads —
            // without this, getBalance on a sync'd full node would return 0
            // for every account until the next live commit.
            let validator_addresses: Vec<Address> =
                self.validators.iter().map(|v| v.address).collect();
            let touched = block_touched_accounts(
                &block.transactions,
                &self.config.treasury_address,
                &validator_addresses,
            );
            for addr in &touched {
                if let Err(e) = mirror_account_to_committed(&self.store, addr) {
                    warn!(
                        height = block.header.height,
                        addr = %addr,
                        error = %e,
                        "rebuild: failed to mirror account to committed view"
                    );
                }
            }
            // STORAGE-ONLY (C2 Task 6): index the block by height in CF_BLOCKS so
            // the RPC `getLatestBlock`/`getBlock` path works on a pure-sync full
            // node, which never runs `try_commit` (the validator path's only
            // CF_BLOCKS writer). Validators reach this rebuild only at startup
            // catch-up and re-write the same bytes they already committed, so the
            // live consensus path is unaffected.
            if let Ok(block_bytes) = serde_json::to_vec(&block) {
                if let Err(e) =
                    self.store
                        .put(CF_BLOCKS, &block.header.height.to_le_bytes(), &block_bytes)
                {
                    warn!(height = block.header.height, error = %e, "failed to index block by height");
                }
            }
            self.last_committed_height = block.header.height;
            self.last_committed_hash = block.hash();
        }
        Ok(head)
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

        // The body uses `i` as the validator index, indexes ed_keys, and
        // drains bls_keys destructively — clippy::needless_range_loop's
        // suggestion would obscure that, so silence it here.
        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            let dir = tempdir().expect("failed to create temp dir");
            let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

            // We need the tempdir to outlive the store, so we leak it.
            // In real code the tempdir would be managed by the test harness.
            // For unit tests this is acceptable.
            std::mem::forget(dir);

            let config = HotStuffConfig {
                max_block_txs: 100,
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
        let (block, _) = engines[0].build_block();

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
    // Test 1a: a vote whose BLS signature does not verify is rejected
    //
    // The network handler passes a VoteMsg straight into process_vote after a
    // stale-round check, so anything accepted here was accepted from the wire.
    // Until this landed, nothing on that path checked the signature at all:
    // QuorumCertificate::verify existed but its only callers were tests.
    // -----------------------------------------------------------------------

    #[test]
    fn process_vote_rejects_a_signature_that_does_not_verify() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let honest = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        // Same block, same round, same voter index -- but signed by a key that
        // is not validator 1's. This is what an attacker can produce.
        let forged = Vote {
            bls_signature: BlsSecretKey::generate().sign(&block.hash()),
            ..honest.clone()
        };

        assert!(
            engines[0].process_vote(forged).is_none(),
            "a forged vote must not form a QC"
        );
        assert!(
            engines[0]
                .pending_votes
                .get(&block.hash())
                .is_none_or(|v| v.is_empty()),
            "a forged vote must not be accumulated at all"
        );
    }

    #[test]
    fn forged_votes_cannot_reach_quorum() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        // Three forged votes, one per committee slot, each signed by a key the
        // committee does not hold. Under the unverified path these reached the
        // quorum threshold and produced a QC.
        for voter_index in 1..4 {
            let vote = Vote {
                block_hash: block.hash(),
                round: engines[0].pacemaker.current_round(),
                voter_index,
                bls_signature: BlsSecretKey::generate().sign(&block.hash()),
            };
            assert!(
                engines[0].process_vote(vote).is_none(),
                "forged vote {voter_index} must not form a QC"
            );
        }
    }

    #[test]
    fn process_vote_rejects_a_voter_index_outside_the_committee() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let honest = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        // Out of range for a 4-member committee. The bitvector loop already
        // skipped such an index, which silently dropped the signer while its
        // signature still entered the aggregate -- a QC that cannot verify.
        let out_of_range = Vote {
            voter_index: 9,
            ..honest.clone()
        };

        assert!(
            engines[0].process_vote(out_of_range).is_none(),
            "a vote from outside the committee must not form a QC"
        );
        assert!(
            engines[0]
                .pending_votes
                .get(&block.hash())
                .is_none_or(|v| v.is_empty()),
            "a vote from outside the committee must not be accumulated"
        );
    }

    // CONTROL: an honest vote must still be accepted, or the check above is
    // just a mute button. This asserts accumulation, which the quorum test
    // covers only indirectly.
    #[test]
    fn process_vote_still_accepts_an_honest_vote() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let honest = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        assert!(
            engines[0].process_vote(honest).is_none(),
            "one vote is not a quorum"
        );
        assert_eq!(
            engines[0]
                .pending_votes
                .get(&block.hash())
                .map(|v| v.len())
                .unwrap_or(0),
            1,
            "the honest vote must be accumulated"
        );
    }

    // -----------------------------------------------------------------------
    // A QUORUM CERTIFICATE ARRIVING FROM THE NETWORK IS ALSO A SIGNATURE
    //
    // Closing the vote path alone left the certificate path open: a QC reaches
    // `on_new_qc` from THREE directions -- a proposal's `justify_qc`, a
    // relayed `NewQC`, and the QC this node forms itself -- and only the third
    // is verified by construction. `QuorumCertificate::verify` was already
    // written and complete; nothing outside its own unit tests ever called it.
    //
    // These assert on STATE, not on a return value: adopting a forged QC as
    // `highest_qc` is what moves the lock and lets `try_commit` finalise a
    // block, so state is the property that matters.
    // -----------------------------------------------------------------------

    /// Build a QC whose aggregate signature is genuine but covers `signed_over`
    /// rather than the block hash the QC claims to certify.
    fn qc_over(
        engines: &[HotStuffEngine],
        claimed_hash: [u8; 32],
        signed_over: &[u8],
        signer_indices: &[usize],
        bitvec_len: usize,
    ) -> QuorumCertificate {
        let sigs: Vec<_> = signer_indices
            .iter()
            .map(|&i| engines[i].bls_sk.sign(signed_over))
            .collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        let mut signers = bitvec![u8, Msb0; 0; bitvec_len];
        for &i in signer_indices {
            signers.set(i, true);
        }
        QuorumCertificate {
            block_hash: claimed_hash,
            round: 0,
            aggregate_sig: BlsSignature::aggregate(&refs).expect("aggregate"),
            signers,
        }
    }

    #[test]
    fn forged_qc_is_not_adopted_as_highest() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        // Quorum-many committee members, a real aggregate signature -- over the
        // wrong message. This is the shape an attacker can produce without
        // holding any committee key at all, using signatures replayed from
        // anywhere else.
        let forged = qc_over(
            &engines,
            block.hash(),
            b"a different message",
            &[0, 1, 2],
            4,
        );

        engines[0].on_new_qc(&forged);
        assert!(
            engines[0].highest_qc.is_none(),
            "a QC whose aggregate does not cover the block hash must not be adopted"
        );
        assert!(
            engines[0].locked_qc.is_none(),
            "and it must not move the lock"
        );
    }

    #[test]
    fn qc_with_a_signer_outside_the_committee_is_not_adopted() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        // Bit 4 of a 4-member committee: `validators.get(4)` is None, so the
        // signer set cannot even be resolved to keys.
        let sigs: Vec<_> = (0..3)
            .map(|i| engines[i].bls_sk.sign(&block.hash()))
            .collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        let mut signers = bitvec![u8, Msb0; 0; 5];
        for i in [0usize, 1, 4] {
            signers.set(i, true);
        }
        let out_of_committee = QuorumCertificate {
            block_hash: block.hash(),
            round: 0,
            aggregate_sig: BlsSignature::aggregate(&refs).expect("aggregate"),
            signers,
        };

        engines[0].on_new_qc(&out_of_committee);
        assert!(
            engines[0].highest_qc.is_none(),
            "a QC naming a signer outside the committee must not be adopted"
        );
    }

    #[test]
    fn qc_below_quorum_is_not_adopted() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        // Two genuine signatures over the right message. Everything about this
        // QC is honest except that 2 < quorum 3.
        let short = qc_over(&engines, block.hash(), &block.hash(), &[0, 1], 4);

        engines[0].on_new_qc(&short);
        assert!(
            engines[0].highest_qc.is_none(),
            "a QC below the quorum threshold must not be adopted"
        );
    }

    // CONTROL: the guard must not be a mute button. An honest QC -- quorum-many
    // real signatures over the real block hash -- must still be adopted, or
    // every node stops advancing and the chain wedges.
    #[test]
    fn honest_qc_is_still_adopted() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let honest = qc_over(&engines, block.hash(), &block.hash(), &[0, 1, 2], 4);

        engines[0].on_new_qc(&honest);
        assert_eq!(
            engines[0].highest_qc.as_ref().map(|q| q.block_hash),
            Some(block.hash()),
            "an honest QC must still become highest_qc"
        );
    }

    // CONTROL: the node's OWN QC must verify under its own rule, and a QC
    // carrying MORE than quorum signers must verify too.
    //
    // ⚠ MEASURED, and it corrected this test's first premise: a locally formed
    // QC always carries EXACTLY quorum signers. `try_form_qc` removes the
    // pending-vote bucket at formation, so a fourth vote arriving afterwards
    // starts a fresh bucket and forms nothing. The >quorum case therefore has
    // to be constructed to be tested at all -- it is reachable from a peer, not
    // from this node's own aggregation.
    #[test]
    fn locally_formed_and_larger_than_quorum_qcs_both_verify() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let own = engines[0].validate_and_vote(&block).expect("self-vote");
        let v1 = engines[1].validate_and_vote(&block).expect("peer 1");
        let v2 = engines[2].validate_and_vote(&block).expect("peer 2");
        engines[0].record_own_vote(own);
        engines[0].process_vote(v1);
        let qc = engines[0].process_vote(v2).expect("QC at quorum");
        assert_eq!(
            qc.signer_count(),
            3,
            "a locally formed QC carries exactly quorum signers"
        );
        assert!(
            engines[0].on_new_qc(&qc),
            "the QC this node just formed must verify under its own rule"
        );

        // All four committee members, genuine signatures over the block hash.
        let four = qc_over(&engines, block.hash(), &block.hash(), &[0, 1, 2, 3], 4);
        assert!(
            engines[1].on_new_qc(&four),
            "a QC with more signers than quorum must verify, not wedge the node"
        );
    }

    // -----------------------------------------------------------------------
    // Test 1b: proposer self-vote gives one fault of margin
    // -----------------------------------------------------------------------

    #[test]
    fn proposer_self_vote_forms_qc_with_quorum_minus_one_peers() {
        // 4 validators, quorum = 3. When the proposer records its OWN vote, a QC
        // forms after only 2 PEER votes (proposer + 2 = 3), so the chain
        // tolerates one missing/faulty peer instead of needing all n-1 peers.
        let mut engines = setup_engines(4);

        let (block, _) = engines[0].build_block();

        // Proposer self-votes for its own block.
        let own = engines[0]
            .validate_and_vote(&block)
            .expect("proposer votes for its own block");
        assert!(
            engines[0].record_own_vote(own).is_none(),
            "no QC from the proposer's vote alone (1 < 3)"
        );

        // Two peer votes are now enough to reach quorum.
        let v1 = engines[1].validate_and_vote(&block).expect("peer 1 votes");
        let v2 = engines[2].validate_and_vote(&block).expect("peer 2 votes");
        assert!(
            engines[0].process_vote(v1).is_none(),
            "no QC after proposer + 1 peer (2 < 3)"
        );
        let qc = engines[0]
            .process_vote(v2)
            .expect("QC forms at proposer + 2 peers = quorum 3");
        assert_eq!(qc.round, 0);
        assert_eq!(qc.block_hash, block.hash());
        assert_eq!(qc.signer_count(), 3);
    }

    // -----------------------------------------------------------------------
    // Test 1c: two validators can form a QC (degenerate case fixed)
    // -----------------------------------------------------------------------

    #[test]
    fn two_validators_form_qc_via_proposer_self_vote() {
        // n=2, quorum=2. Without the proposer self-voting this is unreachable:
        // the leader could only ever collect the single peer's vote (1 < 2) and
        // the chain would stall. With the self-vote, proposer + 1 peer = quorum.
        let mut engines = setup_engines(2);

        let (block, _) = engines[0].build_block();

        let own = engines[0]
            .validate_and_vote(&block)
            .expect("proposer self-votes");
        assert!(
            engines[0].record_own_vote(own).is_none(),
            "proposer's vote alone is 1 < quorum 2"
        );

        let peer = engines[1].validate_and_vote(&block).expect("peer votes");
        let qc = engines[0]
            .process_vote(peer)
            .expect("proposer + 1 peer = quorum 2 -> QC");
        assert_eq!(qc.signer_count(), 2);
    }

    // -----------------------------------------------------------------------
    // Test 2: duplicate vote ignored
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_vote_ignored() {
        let mut engines = setup_engines(4);

        let (block, _) = engines[0].build_block();

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

        let (block, _) = engines[0].build_block();

        let mut vote = engines[1]
            .validate_and_vote(&block)
            .expect("engine 1 should vote");

        // Tamper with the round.
        vote.round = 999;

        let result = engines[0].process_vote(vote);
        assert!(result.is_none(), "vote for wrong round should be ignored");

        // No votes should be recorded for the block.
        assert!(
            !engines[0].pending_votes.contains_key(&block.hash()),
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
            bls_signature: engines[0].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };
        let tv1 = TimeoutVote {
            round,
            voter_index: 1,
            highest_qc: None,
            bls_signature: engines[1].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };
        let tv2 = TimeoutVote {
            round,
            voter_index: 2,
            highest_qc: None,
            bls_signature: engines[2].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
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

    // -----------------------------------------------------------------------
    // A TIMEOUT VOTE IS A SIGNATURE TOO
    //
    // The vote path and the QC path were closed on 2026-08-23 and 08-24. The
    // timeout path was the same shape and was still open: dedup on
    // `voter_index`, push, aggregate. Any peer could send quorum-many forged
    // timeout votes and force a TIMEOUT CERTIFICATE, which advances the round
    // and rotates the leader -- a liveness attack, repeatable at will.
    //
    // Not a safety break: a TC is never transmitted (there is no `NewTC`
    // message) and its `highest_qc` is not adopted, so a forged timeout vote
    // cannot smuggle in a commit.
    // -----------------------------------------------------------------------

    #[test]
    fn forged_timeout_vote_is_not_accumulated() {
        let mut engines = setup_engines(4);
        let round = engines[0].pacemaker.current_round();

        // Correct message, correct round, committee slot 1 -- signed by a key
        // the committee does not hold.
        let forged = TimeoutVote {
            round,
            voter_index: 1,
            highest_qc: None,
            bls_signature: BlsSecretKey::generate().sign(&TimeoutVote::signing_bytes(round)),
        };

        assert!(
            engines[0].process_timeout_vote(forged).is_none(),
            "a forged timeout vote must not form a TC"
        );
        assert!(
            engines[0]
                .pending_timeout_votes
                .get(&round)
                .is_none_or(|v| v.is_empty()),
            "a forged timeout vote must not be accumulated at all"
        );
    }

    #[test]
    fn forged_timeout_votes_cannot_force_a_round_change() {
        let mut engines = setup_engines(4);
        let round = engines[0].pacemaker.current_round();

        for voter_index in 0..4 {
            let forged = TimeoutVote {
                round,
                voter_index,
                highest_qc: None,
                bls_signature: BlsSecretKey::generate().sign(&TimeoutVote::signing_bytes(round)),
            };
            assert!(
                engines[0].process_timeout_vote(forged).is_none(),
                "forged timeout vote {voter_index} must not form a TC"
            );
        }
    }

    #[test]
    fn timeout_vote_from_outside_the_committee_is_rejected() {
        let mut engines = setup_engines(4);
        let round = engines[0].pacemaker.current_round();

        // Index 9 in a 4-member committee. The bitvector loop already skipped
        // such an index while its signature still entered the aggregate --
        // the same signer-set mismatch the vote path had.
        let out_of_range = TimeoutVote {
            round,
            voter_index: 9,
            highest_qc: None,
            bls_signature: engines[1].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };

        assert!(
            engines[0].process_timeout_vote(out_of_range).is_none(),
            "a timeout vote from outside the committee must not form a TC"
        );
        assert!(
            engines[0]
                .pending_timeout_votes
                .get(&round)
                .is_none_or(|v| v.is_empty()),
            "a timeout vote from outside the committee must not be accumulated"
        );
    }

    // CONTROL: an honest timeout vote must still be accumulated. Without this
    // the three tests above pass just as well against a node that ignores
    // every timeout vote and can never change round.
    #[test]
    fn honest_timeout_vote_is_still_accumulated() {
        let mut engines = setup_engines(4);
        let round = engines[0].pacemaker.current_round();

        let honest = TimeoutVote {
            round,
            voter_index: 1,
            highest_qc: None,
            bls_signature: engines[1].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };

        assert!(
            engines[0].process_timeout_vote(honest).is_none(),
            "one timeout vote is not a quorum"
        );
        assert_eq!(
            engines[0]
                .pending_timeout_votes
                .get(&round)
                .map(|v| v.len())
                .unwrap_or(0),
            1,
            "the honest timeout vote must be accumulated"
        );
    }

    // -----------------------------------------------------------------------
    // Test 5: Local node forms TC from its OWN vote + (quorum - 1) peer votes
    //
    // Reproduces the production wedge from 2026-05-11: in a 4-node testnet
    // the channel transport's `broadcast` skips the sender, so the local
    // engine's pending_timeout_votes only ever contained peer votes. With
    // n=4 and quorum=3, the local engine then needed ALL three peer votes to
    // form a TC — a single lost or late peer vote wedged the round forever
    // because no further votes from that voter would be accepted (dedup
    // short-circuits) and the local node's own vote was never recorded.
    //
    // The fix (`record_own_timeout_vote`) means the local engine only needs
    // `quorum - 1 = 2` peer votes plus its own.
    // -----------------------------------------------------------------------

    #[test]
    fn local_timeout_vote_plus_two_peers_forms_tc() {
        let mut engines = setup_engines(4);
        // quorum_threshold = 3, local = engine 1 (any non-zero index works)

        let local = 1;
        let round = engines[local].pacemaker.current_round();

        // Build the local node's OWN timeout vote — this is what the
        // consensus loop would broadcast.
        let own_tv = TimeoutVote {
            round,
            voter_index: local,
            highest_qc: None,
            bls_signature: engines[local]
                .bls_sk
                .sign(&TimeoutVote::signing_bytes(round)),
        };

        // Two peer votes (out of three peers) — simulating the third peer
        // being slow / dropped / not received in time.
        let peer_tv_a = TimeoutVote {
            round,
            voter_index: 0,
            highest_qc: None,
            bls_signature: engines[0].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };
        let peer_tv_b = TimeoutVote {
            round,
            voter_index: 2,
            highest_qc: None,
            bls_signature: engines[2].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };

        // Step 1 — local records its own vote first (mirrors the consensus
        // loop ordering: record-then-broadcast). Should not yet form TC
        // (1 < 3).
        let r0 = engines[local].record_own_timeout_vote(own_tv);
        assert!(
            r0.is_none(),
            "TC should not form from just our own vote (1 of 3)"
        );

        // Step 2 — first peer vote arrives. 2 < 3, still no TC.
        let r1 = engines[local].process_timeout_vote(peer_tv_a);
        assert!(
            r1.is_none(),
            "TC should not form with 2 votes (own + 1 peer)"
        );

        // Step 3 — second peer vote arrives. Quorum reached.
        let r2 = engines[local].process_timeout_vote(peer_tv_b);
        let tc = r2.expect(
            "TC must form with own vote + 2 peer votes (3 of 4 = quorum). \
             Without record_own_timeout_vote the local node would need ALL \
             three peer votes — the wedge condition this test guards against.",
        );

        assert_eq!(tc.round, round, "TC round should match the timed-out round");
        assert!(
            tc.signers.count_ones() >= 3,
            "TC should have ≥ 3 signers, got {}",
            tc.signers.count_ones()
        );
        // The local node's bit AND both peers' bits must be set; peer 3 (who
        // never voted) must remain unset. We compare against the expected
        // bitvector to avoid bitvec API ergonomics in assertions.
        let mut expected = bitvec![u8, Msb0; 0; 4];
        expected.set(local, true);
        expected.set(0, true);
        expected.set(2, true);
        assert_eq!(
            tc.signers, expected,
            "expected exactly local + peer 0 + peer 2 to be set"
        );

        // Bucket should be cleared after TC formation so the next round's
        // votes start fresh.
        assert!(
            !engines[local].pending_timeout_votes.contains_key(&round),
            "pending_timeout_votes for round {round} should be cleared after TC formation"
        );
    }

    // -----------------------------------------------------------------------
    // Test 6: Stale-bucket wedge — duplicate vote at quorum size triggers
    // re-aggregation rather than silently dropping.
    //
    // If a prior aggregation attempt failed transiently (or the bucket was
    // somehow left at quorum size without a TC being returned), every
    // subsequent vote from a known voter would short-circuit at the dedup
    // check and the round would wedge forever. The fix re-attempts TC
    // formation on duplicates when the bucket is already at quorum.
    // -----------------------------------------------------------------------

    #[test]
    fn duplicate_vote_at_quorum_retries_tc_formation() {
        let mut engines = setup_engines(4);
        let round = engines[0].pacemaker.current_round();

        // Manually pre-populate the bucket at quorum size — simulating the
        // post-failed-aggregation state where 3 votes are present but no TC
        // was returned to the caller.
        let presumed_quorum: Vec<TimeoutVote> = (0..3)
            .map(|i| TimeoutVote {
                round,
                voter_index: i,
                highest_qc: None,
                bls_signature: engines[i].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
            })
            .collect();
        engines[3]
            .pending_timeout_votes
            .insert(round, presumed_quorum);

        // Now feed the engine a duplicate of voter 0's vote — without the
        // fix this returns None and the round is wedged.
        let dup = TimeoutVote {
            round,
            voter_index: 0,
            highest_qc: None,
            bls_signature: engines[0].bls_sk.sign(&TimeoutVote::signing_bytes(round)),
        };
        let tc = engines[3]
            .process_timeout_vote(dup)
            .expect("duplicate vote at quorum size must re-attempt TC formation");

        assert_eq!(tc.signers.count_ones(), 3);
        assert!(
            !engines[3].pending_timeout_votes.contains_key(&round),
            "bucket should be cleared after successful TC formation"
        );
    }

    // -----------------------------------------------------------------------
    // Test 7: prune_stale_timeout_votes drops only past-round buckets.
    // -----------------------------------------------------------------------

    #[test]
    fn prune_stale_timeout_votes_drops_only_past_rounds() {
        let mut engines = setup_engines(4);

        let round = 100u64;

        // Pre-build votes (need immutable engines borrow) before mutating.
        let votes: Vec<(u64, TimeoutVote)> = [round - 2, round - 1, round, round + 1]
            .into_iter()
            .map(|r| {
                (
                    r,
                    TimeoutVote {
                        round: r,
                        voter_index: 0,
                        highest_qc: None,
                        bls_signature: engines[0].bls_sk.sign(&TimeoutVote::signing_bytes(r)),
                    },
                )
            })
            .collect();

        for (r, tv) in votes {
            engines[0].pending_timeout_votes.insert(r, vec![tv]);
        }

        engines[0].prune_stale_timeout_votes(round);

        assert!(!engines[0].pending_timeout_votes.contains_key(&(round - 2)));
        assert!(!engines[0].pending_timeout_votes.contains_key(&(round - 1)));
        assert!(
            engines[0].pending_timeout_votes.contains_key(&round),
            "current round must be preserved"
        );
        assert!(
            engines[0].pending_timeout_votes.contains_key(&(round + 1)),
            "future round must be preserved"
        );
    }

    // -----------------------------------------------------------------------
    // Shared test helpers
    // -----------------------------------------------------------------------

    /// Build a valid certified chain of `count` empty-tx blocks starting at
    /// height 1 (genesis parent), all sharing the genesis state_root of `store`,
    /// signed by validators 0..quorum. Returns the blocks in height order.
    fn certified_chain(
        count: usize,
        validators: &[ValidatorIdentity],
        bls: &[BlsSecretKey],
        quorum: usize,
        store: &Arc<Store>,
    ) -> Vec<Block> {
        use solidus_state::executor::compute_state_root;

        let genesis_root = compute_state_root(store).unwrap_or([0u8; 32]);
        let tx_root = compute_transactions_root(&[]);
        let proposer = validators[0].address;

        let make_qc = |block_hash: [u8; 32], round: u64| -> QuorumCertificate {
            let sigs: Vec<_> = (0..quorum).map(|i| bls[i].sign(&block_hash)).collect();
            let refs: Vec<&BlsSignature> = sigs.iter().collect();
            let aggregate_sig = BlsSignature::aggregate(&refs).expect("aggregate");
            let mut signers = bitvec![u8, Msb0; 0; validators.len()];
            for i in 0..quorum {
                signers.set(i, true);
            }
            QuorumCertificate {
                block_hash,
                round,
                aggregate_sig,
                signers,
            }
        };

        let mut blocks: Vec<Block> = Vec::new();
        let mut prev_hash = [0u8; 32]; // genesis parent
        let mut prev_qc: Option<QuorumCertificate> = None;
        for h in 1..=count as u64 {
            let round = h - 1;
            let header = BlockHeader {
                height: h,
                round,
                parent_hash: prev_hash,
                state_root: genesis_root,
                transactions_root: tx_root,
                timestamp_ms: 0,
                tx_count: 0,
                proposer,
            };
            let block = Block {
                header,
                transactions: vec![],
                parent_qc: prev_qc.clone(),
                vrf_proof: None,
            };
            let bh = block.hash();
            prev_qc = Some(make_qc(bh, round));
            prev_hash = bh;
            blocks.push(block);
        }
        blocks
    }

    /// A throwaway 4-validator committee whose BLS keys we control for signing.
    fn sync_committee() -> (Vec<ValidatorIdentity>, Vec<BlsSecretKey>) {
        let mut vals = Vec::new();
        let mut bls = Vec::new();
        for _ in 0..4 {
            let ed = solidus_crypto::ed25519::generate_signing_key();
            let bsk = BlsSecretKey::generate();
            vals.push(ValidatorIdentity {
                address: Address::from_public_key(&ed.verifying_key()),
                ed25519_pubkey: ed.verifying_key().to_bytes(),
                bls_pubkey: bsk.public_key(),
            });
            bls.push(bsk);
        }
        (vals, bls)
    }

    // -----------------------------------------------------------------------
    // Test: try_commit persists blocks by hash and tracks committed_tip_hash
    // -----------------------------------------------------------------------

    #[test]
    fn try_commit_persists_by_hash_and_sets_tip() {
        // Build 3 blocks at rounds 0, 1, 2 (heights 1, 2, 3).
        // Set highest_qc.round = 4 so the 3-chain rule (r + 2 <= 4) fires on
        // all three rounds. At least the last committed block must be
        // retrievable by hash, and committed_tip_hash() must equal that hash.
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();

        // Build 3 blocks using the existing helper (rounds 0, 1, 2).
        let chain = certified_chain(3, &vals, &bls, 3, &engines[0].store);

        // Stage them in uncommitted_blocks keyed by round.
        for block in &chain {
            engines[0]
                .uncommitted_blocks
                .insert(block.header.round, (block.clone(), vec![]));
        }

        // Build a synthetic highest_qc at round 4 (no signature verification
        // in try_commit — only the round is inspected there).
        let dummy_sig = engines[0].bls_sk.sign(b"dummy");
        let mut signers = bitvec![u8, Msb0; 0; 4];
        signers.set(0, true);
        engines[0].highest_qc = Some(QuorumCertificate {
            block_hash: [0u8; 32],
            round: 4,
            aggregate_sig: dummy_sig,
            signers,
        });

        let committed = engines[0].try_commit();
        assert!(!committed.is_empty(), "expected at least one commit");

        let tip = committed.last().unwrap().0.clone();
        let tip_hash = tip.hash();

        // Field accessor must track the committed tip.
        assert_eq!(
            engines[0].committed_tip_hash(),
            tip_hash,
            "committed_tip_hash must equal the last committed block's hash"
        );

        // Block must be retrievable from the ledger by hash.
        let stored = crate::ledger::get_block_by_hash(&engines[0].store, &tip_hash)
            .unwrap()
            .expect("block must be stored by hash after try_commit");
        assert_eq!(stored.hash(), tip_hash, "retrieved block hash must match");
    }

    // -----------------------------------------------------------------------
    // Task 8: rebuild_state_from_canon
    // -----------------------------------------------------------------------

    #[test]
    fn rebuild_state_from_canon_replays_blocks() {
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();
        let chain = certified_chain(3, &vals, &bls, 3, &engines[0].store);
        for (i, b) in chain.iter().enumerate() {
            crate::ledger::put_block_by_hash(&engines[0].store, b).unwrap();
            crate::ledger::canon_append(&engines[0].store, i as u64, &b.hash()).unwrap();
        }
        let tip_seq = engines[0].rebuild_state_from_canon().unwrap();
        assert_eq!(tip_seq, 2);
        assert_eq!(engines[0].committed_tip_hash(), chain[2].hash());
    }

    /// C2 Task 6: a full node never runs `try_commit`, so its only path to a
    /// height-keyed block index (CF_BLOCKS) is `rebuild_state_from_canon`. The
    /// RPC `getLatestBlock`/`getBlock` read CF_BLOCKS by height, so the rebuild
    /// must additively write each canon block there by `block.header.height`.
    #[test]
    fn rebuild_state_from_canon_writes_blocks_by_height() {
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();
        let chain = certified_chain(3, &vals, &bls, 3, &engines[0].store);
        for (i, b) in chain.iter().enumerate() {
            crate::ledger::put_block_by_hash(&engines[0].store, b).unwrap();
            crate::ledger::canon_append(&engines[0].store, i as u64, &b.hash()).unwrap();
        }
        // CF_BLOCKS is empty before the rebuild (no try_commit was ever run).
        for b in &chain {
            assert!(
                engines[0]
                    .store
                    .get(CF_BLOCKS, &b.header.height.to_le_bytes())
                    .unwrap()
                    .is_none(),
                "CF_BLOCKS should be empty before rebuild for height {}",
                b.header.height
            );
        }

        engines[0].rebuild_state_from_canon().unwrap();

        // After the rebuild every canon block is indexed by its height, so the
        // RPC height path works on a pure-sync full node.
        for b in &chain {
            let bytes = engines[0]
                .store
                .get(CF_BLOCKS, &b.header.height.to_le_bytes())
                .unwrap()
                .unwrap_or_else(|| panic!("CF_BLOCKS missing height {}", b.header.height));
            let stored: Block = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(stored.hash(), b.hash(), "wrong block at height");
        }
    }

    // -----------------------------------------------------------------------
    // Empty-block suppression: has_proposable_work
    // -----------------------------------------------------------------------

    /// Helper: a validly-signed Transfer from a throwaway (unfunded) key.
    /// Suppression logic only reads presence/tx_count, so funding is
    /// irrelevant here.
    fn throwaway_transfer() -> solidus_txns::types::Transaction {
        use solidus_txns::types::{Transaction, TxPayload};
        let sk = generate_signing_key();
        let mut tx = Transaction {
            sender_pubkey: sk.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([0xBBu8; 20]),
                amount: 1,
            },
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = solidus_crypto::ed25519::sign(&sk, &msg);
        tx
    }

    #[test]
    fn has_proposable_work_sees_mempool_txs() {
        let engines = setup_engines(4);
        assert!(
            !engines[0].has_proposable_work(),
            "fresh engine must have no work"
        );
        engines[0]
            .mempool
            .lock()
            .unwrap()
            .insert(throwaway_transfer());
        assert!(
            engines[0].has_proposable_work(),
            "a pending mempool tx is work"
        );
    }

    #[test]
    fn has_proposable_work_ignores_empty_uncommitted_blocks() {
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();
        let chain = certified_chain(2, &vals, &bls, 3, &engines[0].store);

        // An uncommitted EMPTY block (finalization padding / heartbeat) is
        // NOT work — counting it would make the proposer run forever, since
        // committing padding requires proposing more padding.
        engines[0]
            .uncommitted_blocks
            .insert(0, (chain[0].clone(), vec![]));
        assert!(
            !engines[0].has_proposable_work(),
            "empty uncommitted blocks must not count as work"
        );

        // An uncommitted TX-BEARING block IS work: its 3-chain finalization
        // still needs follow-up rounds.
        let mut tx_block = chain[1].clone();
        tx_block.header.tx_count = 1;
        engines[0].uncommitted_blocks.insert(1, (tx_block, vec![]));
        assert!(
            engines[0].has_proposable_work(),
            "an unfinalized tx-bearing block is work"
        );
    }

    // -----------------------------------------------------------------------
    // Restart-resume: adopt_canon_tip + build_block parent fallback
    // -----------------------------------------------------------------------

    #[test]
    fn adopt_canon_tip_resumes_and_next_block_extends_it() {
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();
        let chain = certified_chain(3, &vals, &bls, 3, &engines[0].store);
        for (i, b) in chain.iter().enumerate() {
            crate::ledger::put_block_by_hash(&engines[0].store, b).unwrap();
            crate::ledger::canon_append(&engines[0].store, i as u64, &b.hash()).unwrap();
        }

        // The restart case: a fresh engine opens a store with a surviving
        // canon. It must adopt the tip...
        let adopted = engines[0]
            .adopt_canon_tip()
            .expect("surviving canon tip must be adopted");
        assert_eq!(adopted, 3);
        assert_eq!(engines[0].last_committed_height, 3);
        assert_eq!(engines[0].last_committed_hash, chain[2].hash());

        // ...and, with no QC formed yet, the first post-restart proposal
        // must EXTEND that tip — not fork a second height-1 chain from the
        // genesis sentinel into the same store.
        let (block, _) = engines[0].build_block();
        assert_eq!(
            block.header.parent_hash,
            chain[2].hash(),
            "first post-restart block must extend the surviving tip"
        );
        assert_eq!(block.header.height, 4);
    }

    // -----------------------------------------------------------------------
    // LEADER LEGITIMACY: "you are a validator" is not "you won this round"
    //
    // The VRF section of `validate_and_vote` sat inside `if let Some(vrf_proof)`
    // with no `else`. The deployed node runs `skip_vrf: true`, so its blocks
    // carry no proof and that whole section was SKIPPED -- including the check
    // that the proposer is in the validator set at all. Any peer could propose.
    // -----------------------------------------------------------------------

    /// Put a committee into the round-robin mode the deployment actually runs.
    fn round_robin(engines: &mut [HotStuffEngine]) {
        for e in engines.iter_mut() {
            e.config.skip_vrf = true;
        }
    }

    #[test]
    fn a_proposal_from_a_non_leader_is_rejected() {
        let mut engines = setup_engines(4);
        round_robin(&mut engines);

        // Round 0, so the leader is validator 0 (round % n), the same rule
        // `try_propose_if_leader` uses to decide who may propose.
        assert_eq!(engines[0].pacemaker.current_round(), 0);
        let (block, _) = engines[1].build_block();
        assert_eq!(block.header.proposer, engines[1].validators[1].address);

        assert!(
            engines[0].validate_and_vote(&block).is_none(),
            "a block proposed by validator 1 in round 0 must not be voted on"
        );
    }

    #[test]
    fn a_proposal_from_outside_the_committee_is_rejected() {
        let mut engines = setup_engines(4);
        round_robin(&mut engines);

        let (mut block, _) = engines[0].build_block();
        // Someone who is not a validator at all, wearing the leader's slot.
        block.header.proposer = Address::from_public_key(&generate_signing_key().verifying_key());

        assert!(
            engines[0].validate_and_vote(&block).is_none(),
            "a proposer outside the validator set must not be voted on"
        );
    }

    #[test]
    fn a_missing_vrf_proof_is_rejected_when_vrf_is_required() {
        let engines = setup_engines(4);
        // setup_engines leaves skip_vrf = false, i.e. VRF is REQUIRED here.
        let (mut block, _) = engines[0].build_block();
        assert!(block.vrf_proof.is_some(), "VRF mode must produce a proof");
        block.vrf_proof = None;

        assert!(
            engines[0].validate_and_vote(&block).is_none(),
            "with VRF required, an absent proof must be a decision, not a skip"
        );
    }

    // CONTROL: the legitimate leader must still be voted on. Without this the
    // three tests above pass just as well against a node that votes on nothing,
    // which halts the chain.
    #[test]
    fn the_round_leader_is_still_accepted() {
        let mut engines = setup_engines(4);
        round_robin(&mut engines);

        let (block, _) = engines[0].build_block();
        assert!(
            engines[1].validate_and_vote(&block).is_some(),
            "the round-0 leader's proposal must still be accepted"
        );
    }

    // CONTROL: and the VRF path, which every other test in this file exercises,
    // must be unaffected -- a proposal carrying a valid proof is still accepted.
    #[test]
    fn a_valid_vrf_proposal_is_still_accepted() {
        let engines = setup_engines(4);
        let (block, _) = engines[0].build_block();
        assert!(block.vrf_proof.is_some());
        assert!(
            engines[1].validate_and_vote(&block).is_some(),
            "a valid VRF proposal must still be accepted"
        );
    }

    /// A round-0 QC must be ADOPTED as highest_qc. The old unwrap_or(0)
    /// sentinel dropped it (0 > 0 is false), so the round-1 proposer built
    /// on None and orphaned the round-0 block — the first tx-bearing block
    /// after every restart under event-driven proposing (found live
    /// 2026-07-13: canon started at the empty round-1 block, parent [0;32],
    /// while the round-0 tx block never became canonical).
    #[test]
    fn round_zero_qc_is_adopted_as_highest() {
        let mut engines = setup_engines(4);
        let (block, _) = engines[0].build_block();

        let own = engines[0].validate_and_vote(&block).expect("self-vote");
        let v1 = engines[1].validate_and_vote(&block).expect("peer 1");
        let v2 = engines[2].validate_and_vote(&block).expect("peer 2");
        engines[0].record_own_vote(own);
        engines[0].process_vote(v1);
        let qc = engines[0].process_vote(v2).expect("QC at round 0");
        assert_eq!(qc.round, 0);

        engines[0].on_new_qc(&qc);
        assert_eq!(
            engines[0].highest_qc.as_ref().map(|q| q.block_hash),
            Some(block.hash()),
            "round-0 QC must become highest_qc so round 1 builds on block 1"
        );
    }

    /// Canon must be written AT COMMIT TIME, not (only) by the asynchronous
    /// backfill walker — restart-resume reads canon, so a canon that lags
    /// the committed tip by a walker tick would resume from a stale tip and
    /// orphan committed blocks after a crash inside that window.
    #[test]
    fn try_commit_appends_canon_synchronously_and_resume_sees_it() {
        let mut engines = setup_engines(4);
        let (vals, bls) = sync_committee();
        let chain = certified_chain(3, &vals, &bls, 3, &engines[0].store);
        for block in &chain {
            engines[0]
                .uncommitted_blocks
                .insert(block.header.round, (block.clone(), vec![]));
        }
        let dummy_sig = engines[0].bls_sk.sign(b"dummy");
        let mut signers = bitvec![u8, Msb0; 0; 4];
        signers.set(0, true);
        engines[0].highest_qc = Some(QuorumCertificate {
            block_hash: [0u8; 32],
            round: 4,
            aggregate_sig: dummy_sig,
            signers,
        });

        let committed = engines[0].try_commit();
        assert_eq!(committed.len(), 3);

        // Canon is current IMMEDIATELY — no walker involved in this test.
        let (head_seq, head_hash) = crate::ledger::canon_head(&engines[0].store)
            .unwrap()
            .expect("canon must be appended synchronously at commit");
        assert_eq!(head_seq, 2, "three blocks → canon seqs 0..=2");
        assert_eq!(head_hash, chain[2].hash());

        // Simulated restart: zeroed committed state resumes at the tip.
        engines[0].last_committed_height = 0;
        engines[0].last_committed_hash = [0u8; 32];
        assert_eq!(engines[0].adopt_canon_tip(), Some(3));
        assert_eq!(engines[0].last_committed_hash, chain[2].hash());
    }

    #[test]
    fn adopt_canon_tip_is_none_on_fresh_store_and_genesis_unchanged() {
        let mut engines = setup_engines(4);
        assert!(
            engines[0].adopt_canon_tip().is_none(),
            "fresh store has no canon tip"
        );
        let (block, _) = engines[0].build_block();
        assert_eq!(
            block.header.parent_hash, [0u8; 32],
            "true genesis keeps the zero parent sentinel"
        );
        assert_eq!(block.header.height, 1);
    }
}

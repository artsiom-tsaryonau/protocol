//! The integrated validator node: HotStuff-2 consensus + Narwhal DAG
//! mempool + the two-lane executor + store2, wired into one event-driven
//! object. Like the sub-crate cores it is pure w.r.t. I/O — it consumes
//! [`NodeInput`] events and emits [`NodeOutput`] effects; the harness (and,
//! later, the p2p2/rpc2 layer) owns sockets and timers.
//!
//! The load-bearing wiring:
//! - Client txs → worker → batches (broadcast) → acks → certificates →
//!   the shared [`CertPool`].
//! - When the node is leader, the consensus core's [`PayloadProvider`]
//!   drafts certificate digests from that pool into the proposal, and
//!   reports the node's newest-executed (height, root) as the block's
//!   exec anchor.
//! - On a consensus `Commit`, the node resolves the block's batch
//!   certificates to transactions, runs the **two-lane executor** against
//!   **store2**, persists the block atomically, and advances the exec
//!   anchor + cert-pool retirement.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use solidus_exec::{
    execute_block_twolane, BlockCtx, ExecOptions, StateKey, StateReader, StateSpace,
};
use solidus_hotstuff2::{
    Action, CommittedBlock, ConsensusCore, CoreConfig, LeaderElector, PayloadProvider, Proposal,
    QuorumCert, TimeoutCert, TimeoutVote, ValidatorIndex, View, Vote,
};
use solidus_mempool_dag::{
    Batch, BatchAck, BatchCertificate, BatchResolver, BatchStore, CertPool, Worker, WorkerAction,
    WorkerConfig,
};
use solidus_state_tree::StateForest;
use solidus_store2::Store2;
use solidus_txns::types::Transaction;

use crate::config::NodeTuning;
use crate::sync::{MAX_BLOCK_RANGE, MAX_RANGE_REPLY_BYTES};

/// Boot-time failures. Constructing a node reads committed state from the
/// store, and a node that cannot read its own state must not start: booting
/// anyway would rebuild an incomplete forest and anchor consensus to a state
/// root this validator does not have.
///
/// ⚠ This is an ERROR rather than a panic on purpose. the workspace rules:
/// "Panics in consensus = node crash = slashable downtime."
#[derive(thiserror::Error, Debug)]
pub enum NodeError {
    #[error("cannot read state space {space} from the store at boot: {source}")]
    RecoverState {
        space: String,
        #[source]
        source: solidus_store2::StoreError2,
    },

    /// The store holds committed blocks but consensus cannot resume onto them.
    ///
    /// ⛔ REFUSING TO START IS THE POINT. The old behaviour was to log the
    /// refusal and boot a FRESH chain onto the existing store, which is the
    /// worst of both: the new chain overwrites heights from genesis while every
    /// height above its tip still returns blocks from the old one. Measured on
    /// devnet-v2 on 2026-09-03 — tip at 20774, and heights 25000, 30000 and
    /// 44497 all still served old-chain blocks. Querying by height silently
    /// mixed two chains, and `read_block_range` would hand those stale blocks
    /// to a syncing peer.
    ///
    /// A node that cannot resume has exactly two honest options, and starting
    /// fresh on top of old data is neither: resume, or stop and let an operator
    /// decide. Stopping is loud and recoverable; the mix is silent and is not.
    #[error(
        "REFUSING TO START at height {height}: {reason}. This node cannot resume onto its \
         existing chain, and starting fresh would leave old blocks above the new tip — two \
         chains in one store, which no query can tell apart. Move or delete the data directory \
         to start clean, or restore a store this binary can resume."
    )]
    CannotResume { height: u64, reason: String },

    #[error("cannot read the canonical head at boot: {source}")]
    RecoverHead {
        #[source]
        source: solidus_store2::StoreError2,
    },
}

/// How many committed blocks to reload into the consensus block cache.
///
/// The MINIMUM is 1, the last committed block: `on_proposal` needs it as the
/// parent of the next proposal, and `commit_chain` walks back to it and must
/// find it to terminate. The window is larger only for margin, and each block
/// is small because it carries certificates rather than transactions.
const RESUME_BLOCK_WINDOW: u64 = 8;

/// Shortest gap between two range requests from this node.
///
/// ⚠ THIS IS WHAT STOPS THE BROADCAST STORM, and it has to be here rather than
/// only in the transport. Without it a validator asks every peer for a range on
/// every proposal it receives, each peer answers with a store read, and the
/// feedback is positive: the storm slows the round, the round times out,
/// nothing commits, the head stops while proposal heights climb, and the gap
/// that triggered it grows. Measured before the limit: 104 timeout certificates
/// against 50 quorum certificates, so no two certified views were ever
/// consecutive and the 2-chain rule could never fire.
const SYNC_REQUEST_COOLDOWN: std::time::Duration = std::time::Duration::from_millis(300);

/// Whether a node can link a certified tip back to its own committed head.
///
/// ⛔ THREE STATES, NOT AN `Option`, AND THAT IS THE WHOLE POINT. This used to be
/// `Option<u64>`, where `None` meant BOTH "linked, nothing missing" and "ran out
/// of blocks, the gap is real". The caller read `None` as up to date, so a
/// validator too far behind to hold the tip block failed on the walk's first step
/// and never asked for anything. Measured 2026-09-11 on the rolling-restart gate:
/// zero range requests and zero blocks executed in 90 seconds while the committee
/// went from 6 to 87.
///
/// ⚠ THE COMMENT WAS RIGHT AND THE CODE WAS WRONG. The line above the `?` said
/// "the gap is real" while the `?` returned the value meaning the opposite. An
/// enum makes that disagreement unrepresentable, and makes the compiler ask every
/// caller what it does about each case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TipLink {
    /// Reached our committed head: nothing is missing.
    Linked,
    /// History is missing, and the tip is at this height.
    Missing { tip_height: u64 },
    /// History is missing and we cannot even see the tip, so we have no height
    /// to ask for. Being further behind must not mean asking for less.
    Unresolvable,
}

impl TipLink {
    /// A walk that ran out: `Missing` if it saw the tip, `Unresolvable` if not.
    fn from_walk(tip_height: Option<u64>) -> Self {
        match tip_height {
            Some(tip_height) => TipLink::Missing { tip_height },
            None => TipLink::Unresolvable,
        }
    }
}

/// Newest block this node has executed: (height, global state root).
/// `(height, global_root)` of the newest executed block — shared with the
/// consensus payload builder and (via [`Node::exec_anchor`]) the RPC edge.
pub type ExecAnchor = Arc<Mutex<(u64, [u8; 32])>>;

/// How often cold pruning runs, in blocks.
///
/// Pruning used to run on EVERY commit. The horizon moves by the same amount
/// either way, so an interval reclaims identical disk while writing 1/1000 of the
/// range tombstones. Tombstones are what made the WAL unbootable on 2026-09-06.
const PRUNE_INTERVAL: u64 = 1_000;

/// Shared cert pool: the worker/ack path fills it, the proposer drafts it.
type SharedCertPool = Arc<Mutex<CertPool>>;

/// The consensus core's payload source, backed by shared node state.
pub struct NodePayloads {
    pool: SharedCertPool,
    exec_anchor: ExecAnchor,
    max_certs: usize,
    clock_ms: Arc<Mutex<u64>>,
}

impl PayloadProvider for NodePayloads {
    fn next_payload(&mut self) -> Vec<BatchCertificate> {
        #[allow(clippy::expect_used)]
        let mut pool = self.pool.lock().expect("cert pool poisoned");
        let (_draft, certs) = pool.draft(self.max_certs);
        certs
    }

    /// Proposer timestamp: wall clock, floored to be strictly monotonic per node.
    ///
    /// ⛔ THIS USED TO BE `*c += 1` AND THAT SHIPPED TO PRODUCTION. Seeded at
    /// 1_700_000_000_000, it made `timestamp_ms` a per-validator COUNTER that
    /// advanced one millisecond per proposal and RESET to 2023-11-14 on every
    /// boot. Measured through the public RPC on 2026-09-06, across a million
    /// heights, every block sat within ~35 s of that constant and the series was
    /// NOT monotonic: height 1.000.000 carried an EARLIER timestamp than height
    /// 500.000, because a different validator proposed it with its own freshly
    /// reset counter.
    ///
    /// ⚠ WHAT IT BROKE. Any credential `validFrom`/`validUntil` evaluated against
    /// block time was evaluated against November 2023, so time-bounded credentials
    /// were uniformly valid or uniformly expired and never correct. Head-age
    /// freeze detection was impossible. Explorer and receipt timestamps read 2023.
    ///
    /// ⚠ THE TRAIT DOC IS STILL RIGHT: the clock stays outside the consensus core
    /// so tests stay deterministic. The bug was that the PRODUCTION provider was
    /// also a counter, so a test seam became the shipped behaviour. Deterministic
    /// tests use `EmptyPayloads`, which has a fixed `ts_ms`, or build headers
    /// directly.
    ///
    /// The `max(*c + 1)` floor keeps timestamps strictly increasing per node even
    /// if the system clock steps backwards (NTP correction, VM migration, a
    /// suspended host). It does not make timestamps monotonic ACROSS proposers;
    /// that is a consensus validation rule and is deliberately not decided here.
    /// Anything in the pool worth a block. NON-CONSUMING, unlike `next_payload`.
    ///
    /// ⚠ This is only a fact about the CHAIN because certificates are gossiped.
    /// Before that, it was a fact about this node, and suppressing on it silenced
    /// leaders that simply had not assembled the work themselves.
    fn has_work(&mut self) -> bool {
        #[allow(clippy::expect_used)]
        let pool = self.pool.lock().expect("cert pool poisoned");
        pool.pending() > 0
    }

    fn now_ms(&mut self) -> u64 {
        #[allow(clippy::expect_used)]
        let mut c = self.clock_ms.lock().expect("clock poisoned");
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        *c = wall.max(c.saturating_add(1));
        *c
    }

    fn exec_anchor(&mut self) -> (u64, [u8; 32]) {
        #[allow(clippy::expect_used)]
        *self.exec_anchor.lock().expect("anchor poisoned")
    }
}

/// Events the node consumes.
#[allow(clippy::large_enum_variant)] // transient, moved through an mpsc; boxing buys nothing
pub enum NodeInput {
    /// A peer asks us for a block body by hash, because it holds a QC it cannot
    /// resolve. Answered from our store if we have it.
    BlockBodyRequest {
        hash: [u8; 32],
        from: u32,
    },
    /// A peer supplies a block body we asked for.
    BlockBody(Vec<u8>),
    /// A peer asks us for committed blocks `[from, to]`, because it fell behind.
    ///
    /// ⚠ NO RATE LIMIT HERE, AND THAT IS DELIBERATE. Answering costs up to
    /// `MAX_BLOCK_RANGE` store reads, so a transport that can receive this from
    /// an untrusted peer MUST limit before it arrives; `solidus-p2p2` does that
    /// at the swarm, where the peer identity lives. The node knows committee
    /// indices, not peers, and cannot make that judgement.
    BlockRangeRequest {
        from: u64,
        to: u64,
        requester: u32,
    },
    /// Blocks a peer sent in answer to our request, with the batch bodies they
    /// certify. Nothing here is trusted: see `apply_synced_blocks`.
    BlockRange {
        blocks: Vec<Vec<u8>>,
        batches: Vec<Vec<u8>>,
    },
    SubmitTx(Transaction),
    Proposal(Proposal),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    Tc(TimeoutCert),
    Qc(QuorumCert),
    Batch {
        batch: Batch,
        from: u32,
    },
    Ack(BatchAck),
    /// A certificate a peer assembled. Verified before it is admitted.
    Cert(BatchCertificate),
    ConsensusTimer(View),
    /// The pacing timer for `view` fired: we may now propose. See
    /// `Action::SchedulePropose`.
    ProposeTimer(View),
    Flush,
}

/// Effects the node emits (the harness/p2p routes them).
#[allow(clippy::large_enum_variant)] // transient effect list; boxing buys nothing
#[derive(Debug, Clone)]
pub enum NodeOutput {
    Consensus(Action),
    BroadcastBatch(Batch),
    /// A certificate this node assembled, for the whole committee.
    ///
    /// ⛔ THE MISSING LINK BEHIND THREE FAILED SUPPRESSION ATTEMPTS. Certificates
    /// used to stay in the pool of the node that formed them, so a leader held
    /// only its own share of the committee's work and `pending() == 0` was a
    /// statement about ONE node, not about the chain.
    BroadcastCert(BatchCertificate),
    SendAck {
        to: u32,
        ack: BatchAck,
    },
    /// A block executed + persisted: (height, tx count, state root).
    BlockExecuted {
        height: u64,
        tx_count: usize,
        state_root: [u8; 32],
    },
    /// This node holds a quorum certificate whose BLOCK BODY it does not have,
    /// so it can neither propose nor vote and the chain wedges around it.
    ///
    /// ⚠ BY HASH, NOT HEIGHT. A lock names a block that may never have been
    /// committed, so it has no height to ask for.
    NeedBlockBody {
        hash: [u8; 32],
    },
    /// Answer a peer's body request.
    SendBlockBody {
        to: u32,
        bytes: Vec<u8>,
    },
    /// Answer a peer's range request.
    SendBlockRange {
        to: u32,
        blocks: Vec<Vec<u8>>,
        batches: Vec<Vec<u8>>,
    },
    /// This node is behind and cannot execute what consensus committed: it is
    /// missing block bodies in `[from, to]` inclusive.
    ///
    /// ⚠ EMITTED, NOT ACTED ON BY THE NODE. The node has no network: a
    /// transport turns this into a range request, and the answer comes back as
    /// `NodeInput::BlockRange`, which goes through `sync::verify_fetched_range`
    /// before any of it executes.
    NeedBlocks {
        from: u64,
        to: u64,
    },
}

/// Signs this node's view of a committed block's bridge messages.
///
/// ⚠ A TRAIT, NOT THE KEY ITSELF, AND THE REASON IS A DEPENDENCY BOUNDARY. `solidus-crypto`'s
/// `attest` feature pulls in k256, and its own comment says only `solidus-exec` and
/// `solidus-noded` may ask for it. Holding an attestation key here would pull secp256k1 into
/// consensus and, through it, into `solidus-p2p2`. The signer lives in `solidus-noded`; this is
/// the hole it reaches through.
///
/// ⛔ IMPLEMENTATIONS MUST NOT FAIL THE BLOCK. A missing signature delays one bridge message and
/// the start-up pass regenerates it; a panicking node halts the chain.
pub trait BlockAttestor: Send + Sync {
    fn sign_committed(
        &self,
        height: u64,
        block_events: &[solidus_txns::types::Event],
        receipts: &[solidus_txns::types::Receipt],
    ) -> Vec<(u32, u64, [u8; 65])>;
}

pub struct Node {
    index: ValidatorIndex,
    chain_id: u64,
    consensus: ConsensusCore<Box<dyn LeaderElector>, NodePayloads>,
    worker: Worker,
    batch_store: Arc<std::sync::RwLock<BatchStore>>,
    pool: SharedCertPool,
    store: Arc<Store2>,
    /// Shared with the RPC edge for proofs (`forest_handle`).
    forest: Arc<RwLock<StateForest>>,
    exec_anchor: ExecAnchor,
    opts: ExecOptions,
    network: String,
    block_retention: u64,
    /// Set by `solidus-noded` when a bridge attestation key is configured. `None` on every node
    /// until the key is deployed, which is a supported configuration and not a degraded one.
    attestor: Option<Arc<dyn BlockAttestor>>,
    /// Highest QC this node has verified through live consensus.
    ///
    /// ⛔ THIS IS THE ANCHOR FOR BLOCK SYNC AND ITS PROVENANCE IS THE WHOLE
    /// POINT. It is recorded only where `ConsensusCore::on_qc` returned `Ok`,
    /// and that function's FIRST statement is
    /// `qc.verify(chain_id, committee, genesis_hash)?`. So acceptance here
    /// implies verification against the committee.
    ///
    /// ⚠ It must NEVER be set from a QC that arrived alongside fetched blocks.
    /// A peer can fabricate an internally-consistent range; the only thing
    /// distinguishing the real chain is a certificate this node verified
    /// independently, through consensus, before the fetch.
    highest_verified_qc: Option<solidus_hotstuff2::QuorumCert>,
    /// Recently verified QCs, by the hash of the block each certifies.
    ///
    /// ⛔ THE SYNC ANCHOR SET, AND EVERY MEMBER EARNED ITS PLACE. A QC is
    /// inserted only after `ConsensusCore::on_qc` returned `Ok`, which verifies
    /// the aggregate signature against this node's own committee. Nothing that
    /// arrives with a fetched range can add to it.
    verified_qc_by_block: HashMap<[u8; 32], solidus_hotstuff2::QuorumCert>,
    /// Insertion order for `verified_qc_by_block`, so it stays bounded. Oldest
    /// out first: a sync anchor older than this is useless anyway, since the
    /// blocks it would certify are further back than any range we would ask for.
    verified_qc_order: VecDeque<[u8; 32]>,
    /// Head and time of the last range request, so lag is asked about at a
    /// bounded RATE rather than on every proposal. See
    /// [`SYNC_REQUEST_COOLDOWN`].
    last_range_request: Option<(u64, std::time::Instant)>,
    /// The committee, kept for sync verification (`ConsensusCore` does not
    /// expose it, and this crate must not reach into hotstuff2's internals).
    committee: solidus_hotstuff2::Committee,
    /// Validator BLS keys, kept to verify certificates arriving over gossip.
    /// The worker owns its own copy for the acks it signs; this is the inbound
    /// side, and a certificate admitted unverified would be a proposal a peer
    /// chose for us.
    committee_pubkeys: Vec<solidus_crypto::bls::BlsPublicKey>,
    /// Backfill traffic, counted rather than logged. See [`SyncCounters`].
    sync_counters: SyncCounters,
    /// The last lock body we asked for, and when. See `may_request_body`.
    last_body_request: Option<([u8; 32], std::time::Instant)>,
}

/// Block-range traffic through one node, as plain counters.
///
/// ⚠ COUNTERS, NOT TRACE LINES, BECAUSE TRACING MOVES THE RESULT. Measured
/// 2026-09-13 on the rolling-restart gate: untraced, a lagging validator froze
/// at 25 of 116; traced, it reached 71 of 78. An increment costs nothing a
/// scheduler can see, so these stay on and the harness samples them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncCounters {
    /// `NeedBlocks` outputs this node emitted.
    pub ranges_requested: u64,
    /// Range replies this node served to a peer.
    pub ranges_served: u64,
    /// Range replies this node received.
    pub ranges_received: u64,
    /// Received replies holding nothing above our head.
    pub ranges_stale: u64,
    /// Received replies refused: undecodable, no verified QC yet, an unreadable
    /// head, or a failed `verify_fetched_range`.
    pub ranges_rejected: u64,
    /// Blocks that could not execute because a batch body they certify is not
    /// held here. Each one is a hole the node must fetch before it can move.
    pub blocks_blocked_on_body: u64,
    /// `NeedBlockBody` outputs this node emitted.
    pub body_requests: u64,
    /// Block bodies that re-drove consensus. Each costs an aggregate BLS check.
    pub bodies_redriven: u64,
}

impl Node {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        index: ValidatorIndex,
        chain_id: u64,
        secret: solidus_crypto::bls::BlsSecretKey,
        committee: solidus_hotstuff2::Committee,
        validator_keys: Vec<solidus_crypto::bls::BlsPublicKey>,
        pacemaker: solidus_hotstuff2::Pacemaker,
        elector: Box<dyn LeaderElector>,
        store: Store2,
        tuning: NodeTuning,
        network: String,
    ) -> Result<Self, NodeError> {
        let pool: SharedCertPool = Arc::new(Mutex::new(CertPool::new()));

        // ⛔ RECOVER FROM THE STORE. This line used to be
        //     `Arc::new(Mutex::new((0, [0u8; 32])))`
        // and that single hardcoded pair halted the v2 devnet for a month.
        // The anchor feeds consensus (`hotstuff2/core.rs` reads it as the state
        // anchor for proposals and votes), so a restarted validator rejoined at
        // height 0 with a zero root, could not agree with peers that had not
        // restarted, and the chain lost quorum. Measured 2026-09-02: a validator
        // holding 1,835,001 blocks came back reporting 0.
        //
        // Both primitives already existed and neither was ever called:
        // `Store2::iter_space` is documented "boot-time forest rebuild", and
        // `Store2::canon_head` is tested across a reopen.
        //
        // ⚠ THE FOREST MUST BE REBUILT TOO, NOT JUST THE HEIGHT. The in-memory
        // forest starts empty, so seeding only the height would pair a real
        // height with an empty state root — worse than the bug, because it
        // looks recovered.
        // ⛔ THESE READS MUST NOT FAIL OPEN. An earlier draft of this block wrote
        // `if let Ok(entries) = ...` and `canon_head().ok().flatten().unwrap_or(0)`,
        // which silently degrade a store-read failure into "empty forest" and
        // "height 0" — reinstating the exact defect this code exists to fix, but
        // quietly. A node that cannot read its own committed state must REFUSE TO
        // START. Panicking at boot is loud, systemd surfaces it, and an operator
        // sees a stopped validator instead of a lying one.
        //
        // ⚠ An EMPTY space is not an error. A fresh chain legitimately returns
        // zero entries, and that is `Ok(vec![])`, not `Err`.
        let mut forest = StateForest::new();
        for tree in [
            solidus_exec::types::TreeId::Accounts,
            solidus_exec::types::TreeId::Dids,
            solidus_exec::types::TreeId::Credentials,
            solidus_exec::types::TreeId::Validators,
        ] {
            // ⚠ STREAMED, NOT COLLECTED. `iter_space` copies the entire space into
            // a Vec first, which doubled peak boot memory and OOM-killed every
            // validator on the 4 GB box before consensus could start. The pairs are
            // consumed once, in order, so the intermediate Vec was pure waste.
            store
                .for_each_in_space(StateSpace::Tree(tree), |k, v| forest.apply(tree, k, v))
                .map_err(|source| NodeError::RecoverState {
                    space: format!("{tree:?}"),
                    source,
                })?;
        }
        let recovered_height = store
            .canon_head()
            .map_err(|source| NodeError::RecoverHead { source })?
            // A genuinely ABSENT head is a fresh chain, which really is height 0.
            // Only a read ERROR is fatal.
            .unwrap_or(0);
        let exec_anchor: ExecAnchor =
            Arc::new(Mutex::new((recovered_height, forest.global_root())));
        // Floor for the strictly-monotonic proposer clock. Starts at 0 so the first
        // `now_ms()` returns wall clock; see `NodePayloads::now_ms`. It used to start
        // at 1_700_000_000_000, which is what made block timestamps a 2023 counter.
        let clock_ms = Arc::new(Mutex::new(0u64));

        let payloads = NodePayloads {
            pool: Arc::clone(&pool),
            exec_anchor: Arc::clone(&exec_anchor),
            max_certs: tuning.max_certs_per_block,
            clock_ms,
        };
        let committee_for_sync = committee.clone();
        let mut consensus = ConsensusCore::new(
            CoreConfig {
                chain_id,
                my_index: index,
                secret: clone_secret(&secret),
                committee,
                pacemaker,
                min_block_interval_ms: tuning.min_block_interval_ms,
                idle_heartbeat_ms: tuning.idle_heartbeat_ms,
                idle_grace_ms: tuning.idle_grace_ms,
            },
            elector,
            payloads,
        );

        // ⛔ RESUME CONSENSUS, OR REFUSE LOUDLY. Recovering the exec anchor
        // alone is not enough: ConsensusCore boots at height 0 and overwrites
        // it on the first commit, which is how a devnet at 56,035 came back at
        // 264 on 2026-09-02.
        //
        // Three things must all be present, and a missing one is a refusal
        // rather than a partial resume:
        //   · a canon head            - nothing to resume to without it
        //   · a safety record         - resuming without it can equivocate,
        //                               which is slashable and permanent
        //   · the committed block     - on_proposal looks up header.parent and
        //                               returns NO VOTE on a miss, so a node
        //                               without it declines every proposal and
        //                               wedges the chain silently
        // Returns Ok(None) only when there is nothing to resume onto (a fresh
        // store). A store WITH committed blocks either resumes or refuses; it
        // never falls through to a fresh chain. See `NodeError::CannotResume`.
        let resume = (|| -> Result<Option<solidus_hotstuff2::ResumeState>, (u64, String)> {
            let Some(height) = store.canon_head().ok().flatten() else {
                return Ok(None);
            };
            let (last_voted_view, qc_bytes) = match store.safety().ok().flatten() {
                Some(v) => v,
                None => {
                    return Err((
                        height,
                        "committed blocks but NO safety record, so this node cannot prove which \
                         views it already voted in; resuming could equivocate, which is slashable \
                         and permanent"
                            .to_string(),
                    ));
                }
            };
            let high_qc = match bincode::deserialize::<solidus_hotstuff2::QuorumCert>(&qc_bytes) {
                Ok(qc) => qc,
                Err(e) => {
                    return Err((
                        height,
                        format!("the stored high QC will not decode ({e:?})"),
                    ));
                }
            };
            let Some(last_committed_hash) = store.canon_hash(height).ok().flatten() else {
                return Err((height, "no canonical hash for the head height".to_string()));
            };

            // Recent committed blocks. The minimum is the last committed one;
            // a small window costs little and gives margin if the tip is ahead.
            let mut blocks = Vec::new();
            let from = height.saturating_sub(RESUME_BLOCK_WINDOW);
            for h in from..=height {
                let Some(hash) = store.canon_hash(h).ok().flatten() else {
                    continue;
                };
                let Some(bytes) = store.block_by_hash(&hash).ok().flatten() else {
                    continue;
                };
                if let Ok(b) = bincode::deserialize::<solidus_hotstuff2::Block2>(&bytes) {
                    blocks.push(b);
                }
            }
            // ⭐ THE LOCKED BLOCK, WHICH IS THE ONE THAT WAS MISSING. It sits
            // above the committed head and so is not in the canon window above;
            // it is fetched by hash from the pending write on the proposal path.
            if let Ok(Some(bytes)) = store.block_by_hash(&high_qc.block_hash) {
                if let Ok(b) = bincode::deserialize::<solidus_hotstuff2::Block2>(&bytes) {
                    if !blocks.iter().any(|x| x.hash() == b.hash()) {
                        blocks.push(b);
                    }
                }
            }

            if !blocks.iter().any(|b| b.hash() == last_committed_hash) {
                // ⚠ THE UPGRADE CASE. Blocks committed before block bytes were
                // persisted decode to nothing, so the head cannot be reloaded.
                return Err((
                    height,
                    "the committed block could not be reloaded, so consensus would decline every \
                     proposal and wedge; this is a node upgraded from a build that stored empty \
                     block bodies"
                        .to_string(),
                ));
            }
            Ok(Some(solidus_hotstuff2::ResumeState {
                last_voted_view,
                high_qc,
                last_committed_hash,
                last_committed_height: height,
                blocks,
            }))
        })();

        // ⛔ A STORE WITH COMMITTED BLOCKS EITHER RESUMES OR STOPS THE NODE.
        // Booting a fresh chain onto it is what put two chains in one store on
        // devnet-v2: heights below the new tip were the new chain and every
        // height above it still answered with the old one.
        let resume = match resume {
            Ok(r) => r,
            Err((height, reason)) => return Err(NodeError::CannotResume { height, reason }),
        };
        if let Some(r) = resume {
            // ⚠ ONE LINE, AT BOOT, AND IT IS THE ONE NUMBER THAT MATTERS AFTER
            // A RESTART. `resume_view` is derived from THIS validator's own
            // last_voted_view, so two nodes that stopped at different moments
            // resume into different views. Timeout votes only aggregate within
            // a single view, so a committee that resumes scattered has no path
            // back together. Logging it makes that visible from the journal
            // instead of requiring a rebuild to find out.
            let (last_voted, qc_view, height) =
                (r.last_voted_view, r.high_qc.view, r.last_committed_height);
            consensus.resume(r);
            // ⛔ READ THE VIEW BACK OUT OF THE CORE, NEVER RECOMPUTE IT HERE.
            // The first version of this line duplicated `resume`'s formula and
            // was left behind when that formula changed, so it printed 1654
            // while the validator actually resumed at 1653 — an instrument
            // added to make a scatter visible, reporting the wrong number for
            // the scatter. `start()` enters `cur_view + 1`, so that is the view
            // this validator comes back into.
            eprintln!(
                "solidus-node2: resuming at view {} (last_voted {last_voted}, \
                 high_qc view {qc_view}, height {height})",
                consensus.current_view().saturating_add(1)
            );
        }

        let batch_store = Arc::new(std::sync::RwLock::new(BatchStore::new()));
        let worker = Worker::new(
            WorkerConfig {
                chain_id,
                my_index: index,
                worker_id: index,
                batch_max_bytes: tuning.batch_max_bytes,
                batch_max_txs: tuning.batch_max_txs,
                inbound_max_bytes: tuning.batch_max_bytes * 4,
                keys: validator_keys.clone(),
                secret,
            },
            Arc::clone(&batch_store),
        );

        // `forest` is whatever was recovered above: empty on a fresh store,
        // the committed state on a restart. Genesis seeding stays a node-layer
        // concern via `seed_account`, but the caller must only do it for a
        // FRESH chain — re-seeding a recovered chain resets live balances to
        // their genesis values. See `solidus-noded/src/run.rs`.
        Ok(Node {
            index,
            chain_id,
            consensus,
            worker,
            batch_store,
            pool,
            store: Arc::new(store),
            forest: Arc::new(RwLock::new(forest)),
            exec_anchor,
            opts: ExecOptions::v2_defaults(chain_id),
            network,
            block_retention: tuning.block_retention,
            attestor: None,
            highest_verified_qc: None,
            verified_qc_by_block: HashMap::new(),
            verified_qc_order: VecDeque::new(),
            last_range_request: None,
            committee: committee_for_sync,
            committee_pubkeys: validator_keys,
            sync_counters: SyncCounters::default(),
            last_body_request: None,
        })
    }

    /// Install the bridge attestation signer. Called once at start-up, before the node runs.
    pub fn set_attestor(&mut self, attestor: Arc<dyn BlockAttestor>) {
        self.attestor = Some(attestor);
    }

    pub fn index(&self) -> ValidatorIndex {
        self.index
    }

    /// Block-range traffic so far. See [`SyncCounters`].
    pub fn sync_counters(&self) -> SyncCounters {
        self.sync_counters
    }

    /// The view consensus is in.
    pub fn current_view(&self) -> solidus_hotstuff2::View {
        self.consensus.current_view()
    }

    /// The height consensus has committed, which the store may trail.
    pub fn committed_height(&self) -> u64 {
        self.consensus.last_committed().1
    }

    /// A shared handle to the node's committed-state store — the read side
    /// of the JSON-RPC edge (`rpc2::Store2Backend`) binds to this while the
    /// node keeps writing through it (every Store2 method takes `&self`;
    /// RocksDB is internally synchronized, so concurrent node-writes +
    /// RPC-reads are safe).
    pub fn store(&self) -> Arc<Store2> {
        Arc::clone(&self.store)
    }

    /// The `(height, global_root)` of the node's newest executed block —
    /// updated at genesis and on each committed block (D-EXEC-DEFER). This is
    /// the anchor `rpc2::Store2Backend` reports as block height + state root.
    pub fn exec_anchor(&self) -> ExecAnchor {
        Arc::clone(&self.exec_anchor)
    }

    /// The executed state forest, shared with the RPC edge for proofs. Readers
    /// must compare its global root with the exec anchor (see solidus_getStateProof).
    pub fn forest_handle(&self) -> Arc<RwLock<StateForest>> {
        Arc::clone(&self.forest)
    }

    /// Seed a genesis account into both store2 and the in-memory forest.
    pub fn seed_account(&mut self, key: &StateKey, value: &[u8]) {
        #[allow(clippy::expect_used)]
        self.store.seed_state(key, value).expect("seed");
        #[allow(clippy::expect_used)]
        let mut forest = self.forest.write().expect("forest lock");
        if let solidus_exec::StateSpace::Tree(tree) = key.space {
            forest.apply(tree, &key.key, value);
        }
        let root = forest.global_root();
        drop(forest);
        // Genesis root becomes the exec anchor at height 0.
        #[allow(clippy::expect_used)]
        let mut anchor = self.exec_anchor.lock().expect("anchor");
        anchor.1 = root;
    }

    /// Boot consensus (enter view 1).
    pub fn start(&mut self) -> Vec<NodeOutput> {
        let actions = self.consensus.start();
        actions.into_iter().map(NodeOutput::Consensus).collect()
    }

    /// Drive one input event, returning the effects to route.
    pub fn step(&mut self, input: NodeInput) -> Vec<NodeOutput> {
        if matches!(input, NodeInput::BlockRange { .. }) {
            self.sync_counters.ranges_received += 1;
        }
        let out = self.step_inner(input);
        // Counted here, once, rather than at each of the five sites that emit
        // a request: a site added later is counted without anyone remembering.
        for o in &out {
            match o {
                NodeOutput::NeedBlocks { .. } => self.sync_counters.ranges_requested += 1,
                NodeOutput::SendBlockRange { .. } => self.sync_counters.ranges_served += 1,
                NodeOutput::NeedBlockBody { .. } => self.sync_counters.body_requests += 1,
                _ => {}
            }
        }
        out
    }

    fn step_inner(&mut self, input: NodeInput) -> Vec<NodeOutput> {
        match input {
            NodeInput::SubmitTx(tx) => {
                let out = self.worker.on_submit_tx(tx);
                self.worker_out(out)
            }
            NodeInput::BlockBodyRequest { hash, from } => {
                // Serve from the store, which now holds proposed blocks and not
                // only committed ones. A miss is silence rather than an error:
                // the requester asks another peer.
                match self.store.block_by_hash(&hash) {
                    Ok(Some(bytes)) if !bytes.is_empty() => {
                        vec![NodeOutput::SendBlockBody { to: from, bytes }]
                    }
                    _ => Vec::new(),
                }
            }
            NodeInput::BlockRangeRequest {
                from,
                to,
                requester,
            } => {
                let (blocks, batches) = self.read_block_range(from, to);
                if blocks.is_empty() {
                    // A short answer is normal; an EMPTY one carries nothing and
                    // would only cost the requester a round of parsing.
                    Vec::new()
                } else {
                    vec![NodeOutput::SendBlockRange {
                        to: requester,
                        blocks,
                        batches,
                    }]
                }
            }
            NodeInput::BlockRange { blocks, batches } => {
                // Everything that decides whether to trust these blocks lives
                // inside `apply_synced_blocks`: this node's own committee, its
                // own head, and a QC it verified through live consensus.
                // Nothing that arrived in this message judges this message.
                self.apply_synced_blocks(&blocks, &batches)
            }
            NodeInput::BlockBody(bytes) => {
                // ⛔ Accepted only if it matches the lock we already verified.
                if self.accept_block_body(&bytes) {
                    // The body may unblock a proposal or a vote, so re-drive the
                    // core with the QC it was already holding.
                    self.sync_counters.bodies_redriven += 1;
                    let qc = self.consensus.high_qc().clone();
                    let out = self.consensus.on_qc(qc);
                    self.consensus_out(out)
                } else {
                    Vec::new()
                }
            }
            NodeInput::Batch { batch, from } => {
                // Persist BEFORE the worker may ack it. `insert_verified`'s own
                // comment is "never ack what you cannot re-serve", and until now
                // that promise died at the next restart because batch bodies
                // lived only in an in-memory HashMap.
                self.persist_batch(&batch);
                let out = self.worker.on_batch(batch, from);
                self.worker_out(out)
            }
            NodeInput::Ack(ack) => {
                let out = self.worker.on_ack(ack);
                self.worker_out(out)
            }
            NodeInput::Flush => {
                let out = self.worker.on_flush();
                self.worker_out(out)
            }
            NodeInput::Proposal(p) => {
                // ⛔ PERSIST BEFORE CONSENSUS SEES IT. This node may lock onto
                // this block, and a lock always sits above the committed head,
                // so `persist_block` (which runs on COMMIT) would never keep it.
                // Without this the validator cannot reload what it resumes from
                // and the chain wedges after a restart — measured, 4 of 4.
                match bincode::serialize(&p.block) {
                    Ok(bytes) => {
                        if let Err(e) = self.store.put_pending_block(&p.block.hash(), &bytes) {
                            eprintln!(
                                "solidus-node2: could not persist proposed block ({e:?}); a \
                                 restart may be unable to resume from it"
                            );
                        }
                    }
                    Err(e) => eprintln!("solidus-node2: cannot encode proposed block: {e:?}"),
                }
                let out = self.consensus.on_proposal(p);
                self.consensus_out(out)
            }
            NodeInput::Vote(v) => {
                let out = self.consensus.on_vote(v);
                self.consensus_out(out)
            }
            NodeInput::TimeoutVote(tv) => {
                let out = self.consensus.on_timeout_vote(tv);
                self.consensus_out(out)
            }
            NodeInput::Tc(tc) => {
                let out = self.consensus.on_tc(tc);
                self.consensus_out(out)
            }
            NodeInput::Qc(qc) => {
                // Record BEFORE moving it in, but only keep it if the core
                // accepted — `on_qc` verifies as its first statement, so an
                // `Ok` is what makes this QC trustworthy as a sync anchor.
                let candidate = qc.clone();
                let mut need_range: Option<(u64, u64)> = None;
                let out = self.consensus.on_qc(qc);
                if out.is_ok() {
                    let better = self
                        .highest_verified_qc
                        .as_ref()
                        .is_none_or(|cur| candidate.view > cur.view);
                    if better {
                        self.highest_verified_qc = Some(candidate.clone());
                    }
                    let tip = candidate.block_hash;
                    self.remember_verified_qc(candidate);
                    // A QC arrives every round, so this retries itself while
                    // history is missing and goes quiet the moment it is not.
                    let head = self.store.canon_head().ok().flatten().unwrap_or(0);
                    match self.unlinked_tip(&tip) {
                        TipLink::Linked => {}
                        TipLink::Missing { tip_height } => {
                            if tip_height > head && self.may_request_range(head) {
                                need_range = Some((head.saturating_add(1), tip_height));
                            }
                        }
                        // ⛔ ASK ANYWAY. We cannot see how far ahead the tip is,
                        // because a QuorumCert carries a view and a block hash
                        // and NO height, so there is no number to ask `to`. That
                        // is why this case used to give up, and giving up is what
                        // froze a restarted validator for the whole run.
                        //
                        // A blind forward chunk is the cheap, safe answer: the
                        // responder serves only what it holds, and
                        // `verify_fetched_range` still gates acceptance, so
                        // asking for more than exists costs one short reply
                        // rather than any correctness.
                        TipLink::Unresolvable => {
                            if self.may_request_range(head) {
                                need_range = Some((
                                    head.saturating_add(1),
                                    head.saturating_add(MAX_BLOCK_RANGE),
                                ));
                            }
                        }
                    }
                }
                let mut outputs = self.consensus_out(out);
                if let Some((from, to)) = need_range {
                    outputs.push(NodeOutput::NeedBlocks { from, to });
                }
                outputs
            }
            NodeInput::Cert(cert) => {
                // ⛔ VERIFY BEFORE ADMITTING. This arrives over gossip from an
                // unauthenticated topic, and a certificate is a claim that a
                // quorum found a batch available. `verify` checks the signer set
                // is sorted, unique and at least the availability quorum, against
                // THIS chain id, so a certificate from another chain or a forged
                // signer list is rejected rather than queued for proposal.
                //
                // ⚠ `CertPool::add` is already deduped by digest and refuses
                // retired ones, so gossip re-delivery is free and a certificate
                // for an already-committed batch cannot re-enter.
                // ⛔ DEDUP BEFORE VERIFYING. Gossip delivers each certificate
                // N-1 times on a committee of N, and `verify` is an aggregate BLS
                // check. Verifying every copy slowed the net enough to fail the
                // rolling-restart test, which feeds ~10.000 tx/s. The pool
                // already dedups on `add`; this moves that check in front of the
                // expensive part instead of behind it.
                let known = {
                    #[allow(clippy::expect_used)]
                    let pool = self.pool.lock().expect("pool");
                    pool.knows(&cert.digest)
                };
                if !known && cert.verify(self.chain_id, &self.committee_pubkeys).is_ok() {
                    #[allow(clippy::expect_used)]
                    self.pool.lock().expect("pool").add(cert);
                    // Work just arrived. If we lead the current view and have not
                    // proposed, propose now rather than waiting for a view change.
                    let mut actions = Vec::new();
                    self.consensus.on_work_available(&mut actions);
                    return self.consensus_out(Ok(actions));
                }
                Vec::new()
            }
            NodeInput::ConsensusTimer(view) => {
                let out = self.consensus.on_local_timeout(view);
                self.consensus_out(out)
            }
            NodeInput::ProposeTimer(view) => {
                let mut actions = Vec::new();
                self.consensus.on_propose_timer(view, &mut actions);
                self.consensus_out(Ok(actions))
            }
        }
    }

    /// Persist a batch body so it survives a restart and can be re-served.
    ///
    /// ⚠ KEYED BY THE DIGEST WE COMPUTE, never one a peer claimed. `Batch`
    /// is content-addressed — `blake3(bincode(transactions))` — so a forged
    /// digest cannot poison the store: it would simply key the bytes under
    /// their own true hash.
    fn persist_batch(&self, batch: &solidus_mempool_dag::Batch) {
        let digest = batch.digest();
        let bytes = match bincode::serialize(batch) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("solidus-node2: cannot encode batch for persistence: {e:?}");
                return;
            }
        };
        if let Err(e) = self.store.put_batch(&digest.0, &bytes) {
            // Loud, because the consequence is remote and delayed: a peer will
            // fail to backfill a block that certifies this batch, long after the
            // write failed here.
            eprintln!(
                "solidus-node2: cannot persist batch {}: {e:?} — peers may be \
                 unable to backfill blocks certifying it",
                hex_digest(&digest.0)
            );
        }
    }

    /// A batch body from store2, if this node persisted it.
    ///
    /// ⚠ RE-HASHED BEFORE USE. The key is the digest `persist_batch` computed,
    /// so a match is expected; checking costs one hash and turns a corrupt or
    /// mis-keyed record into a missing body rather than wrong transactions.
    fn batch_from_disk(
        &self,
        digest: &solidus_mempool_dag::BatchDigest,
    ) -> Option<solidus_mempool_dag::Batch> {
        let bytes = self.store.batch_by_digest(&digest.0).ok().flatten()?;
        let batch: solidus_mempool_dag::Batch = bincode::deserialize(&bytes).ok()?;
        (batch.digest() == *digest).then_some(batch)
    }

    fn worker_out(
        &mut self,
        result: Result<Vec<WorkerAction>, solidus_mempool_dag::MempoolError>,
    ) -> Vec<NodeOutput> {
        let mut out = Vec::new();
        let mut formed = false;
        if let Ok(actions) = result {
            for action in actions {
                match action {
                    WorkerAction::BroadcastBatch(b) => {
                        // Our own sealed batch. If we cannot re-serve it, a peer
                        // that missed the broadcast can never execute the block
                        // that certifies it.
                        self.persist_batch(&b);
                        out.push(NodeOutput::BroadcastBatch(b))
                    }
                    WorkerAction::SendAck { to, ack } => out.push(NodeOutput::SendAck { to, ack }),
                    WorkerAction::CertFormed(cert) => {
                        #[allow(clippy::expect_used)]
                        self.pool.lock().expect("pool").add(cert.clone());
                        // ⚠ Gossip it. Keeping it local is what made a leader's
                        // `pending()` a fact about itself rather than the chain.
                        out.push(NodeOutput::BroadcastCert(cert));
                        formed = true;
                    }
                }
            }
        }
        // A certificate we assembled ourselves is work arriving too, and the
        // leader may be us. Without this a node that seals its own batch waits
        // for the next view it leads, which under suppression is a full rotation.
        if formed {
            let mut acts = Vec::new();
            self.consensus.on_work_available(&mut acts);
            out.extend(self.consensus_out(Ok(acts)));
        }
        out
    }

    fn consensus_out(
        &mut self,
        result: Result<Vec<Action>, solidus_hotstuff2::ConsensusError>,
    ) -> Vec<NodeOutput> {
        let mut out = Vec::new();
        let Ok(actions) = result else {
            return out; // invalid consensus message: drop per protocol
        };
        // ⛔ SURFACE A LOCK WE CANNOT RESOLVE. Both `propose` and `on_proposal`
        // fall silent on this condition, so without asking for the body the
        // node simply stops participating and nothing says why.
        //
        // ⛔ ONCE PER COOLDOWN, NOT ONCE PER STEP. This ran on every consensus
        // step, so a node busy catching up sent hundreds of requests for ONE body
        // before the first reply landed, and every reply cost a BLS re-check.
        // Measured 2026-09-15: a frozen validator spent 1260 ms of 2 s on 156
        // bodies. The cooldown still re-asks, so a lost reply cannot strand it.
        if let Some(hash) = self.consensus.missing_lock_body() {
            if self.may_request_body(hash) {
                out.push(NodeOutput::NeedBlockBody { hash });
            }
        }

        for action in actions {
            if let Action::Commit(committed) = &action {
                self.execute_committed(committed, &mut out);
            }

            // ⛔ WRITE-AHEAD: THE VOTE MUST NOT LEAVE BEFORE THE RECORD OF IT
            // IS DURABLE. A vote that reached the network while the record did
            // not is exactly what lets a restarted validator vote twice in one
            // view - equivocation, which this repo's own EquivocationDetector
            // catches, and which is slashable.
            //
            // ⛔ AND IT FAILS CLOSED. If the write fails the vote is DROPPED,
            // not sent. Dropping a vote costs liveness for one round, which the
            // pacemaker recovers from. Sending one we cannot prove we sent
            // risks a slashing this node can never undo.
            // ⛔ A PROPOSER MUST PERSIST ITS OWN BLOCK. The receive path covers
            // blocks that arrive as proposals, but the proposer never receives
            // its own — and it locks onto it like everyone else. Measured: with
            // only the receive hook, 3 of 4 validators could reload their lock
            // and the proposer could not.
            if let Action::BroadcastProposal(p) = &action {
                if let Ok(bytes) = bincode::serialize(&p.block) {
                    if let Err(e) = self.store.put_pending_block(&p.block.hash(), &bytes) {
                        eprintln!(
                            "solidus-node2: could not persist our own proposed block ({e:?}); a \
                             restart may be unable to resume from it"
                        );
                    }
                }
            }

            if let Action::SendVote { vote, .. } = &action {
                let qc_bytes = bincode::serialize(self.consensus.high_qc()).unwrap_or_default();
                if let Err(e) = self.store.put_safety(vote.view, &qc_bytes) {
                    eprintln!(
                        "solidus-node2: DROPPING our vote in view {} - could not record it \
                         durably ({e:?}). Sending it anyway would risk equivocating after a \
                         restart.",
                        vote.view
                    );
                    continue;
                }
            }

            out.push(NodeOutput::Consensus(action));
        }
        out
    }

    /// Resolve a committed block's batch certs → txs, run the two-lane
    /// executor against store2, persist, advance the exec anchor, retire
    /// the digests from the cert pool.
    fn execute_committed(&mut self, committed: &CommittedBlock, out: &mut Vec<NodeOutput>) {
        let head = self.store.canon_head().ok().flatten().unwrap_or(0);

        let Some(block) = self.consensus.block(&committed.hash).cloned() else {
            // Consensus committed a block whose body never arrived. The
            // range request is the only way forward, and unlike the walk in
            // `unlinked_tip` this case has no block to walk from.
            if committed.height > head && self.may_request_range(head) {
                out.push(NodeOutput::NeedBlocks {
                    from: head.saturating_add(1),
                    to: committed.height,
                });
            }
            return;
        };

        // ⚠ A BLOCK IS ONLY EXECUTABLE IF IT FOLLOWS OUR HEAD. Executing a
        // committed block over a gap would advance the state root past history
        // this node never applied, and a wrong root is worse than a late one.
        //
        // ⛔ BUT REFUSING IS ONLY HALF THE JOB, AND THE MISSING HALF WEDGED THE
        // CHAIN. The gap has to be ASKED FOR here. Nowhere else can see it:
        // `unlinked_tip` walks the CONSENSUS block cache, and consensus is
        // perfectly happy — it holds every block it certified and its own commit
        // pointer keeps advancing. The gap that matters is between that pointer
        // and the STORE head, and this is the only place both are in view.
        //
        // ⚠ MEASURED, and it is permanent without this. A restarted validator
        // committed h=1647 with head=1645, skipped it, and therefore never moved
        // its head; every later commit had a larger gap still. Consensus mean-
        // while certified ~1750 proposals every 25 seconds. The chain was
        // healthy and the validator executed nothing for 300 seconds.
        //
        // The gap opens because the 2-chain rule commits a block whose ancestors
        // this node never committed itself: after a resume its block cache holds
        // only a window, so `commit_chain` stops walking before it reaches the
        // stored head.
        if committed.height > head.saturating_add(1) {
            // ⛔ TRY THE ANCESTORS WE ALREADY HOLD BEFORE ASKING ANYONE. This
            // gap is usually TWO blocks, not a sync backlog, and asking the
            // network for it is worse than useless: every validator restarts
            // into the same state, so the block nobody executed is in nobody's
            // canon and NO PEER CAN SERVE IT. Measured on a failing restart —
            // committed 1647, every validator's head at 1645 or 1644, and the
            // missing 1646 certified but uncommitted everywhere.
            //
            // It is not lost, though. A certified block was persisted when it
            // was proposed or received, so it is reachable BY HASH even though
            // it is absent from the height index that `read_block_range` walks.
            // Following `header.parent` finds it locally.
            if self.execute_missing_ancestors(&block, committed, head, out) {
                return;
            }
            // Genuinely behind, or stopped at a batch body we do not hold: ask
            // the network. ⚠ RE-READ THE HEAD. The walk may have executed a
            // prefix before stopping, and asking from the old head would re-fetch
            // blocks we just applied.
            let head = self.store.canon_head().ok().flatten().unwrap_or(0);
            if self.may_request_range(head) {
                out.push(NodeOutput::NeedBlocks {
                    from: head.saturating_add(1),
                    to: committed.height,
                });
            }
            return;
        }

        // ⛔ A BLOCK THAT CANNOT EXECUTE MUST ASK, NOT FALL SILENT. `execute_block`
        // stops when a batch body is missing, and this used to ignore that, so
        // the store froze while consensus kept committing and nothing requested
        // the body. A range reply carries batch bodies; nothing else will.
        if !self.execute_block(
            &block,
            committed.height,
            committed.hash,
            committed.timestamp_ms,
            out,
        ) && self.may_request_range(head)
        {
            out.push(NodeOutput::NeedBlocks {
                from: head.saturating_add(1),
                to: committed.height,
            });
        }
    }

    /// Sign and store this node's attestation for every bridge message the block queued.
    ///
    /// ⛔ INFALLIBLE FROM CONSENSUS'S POINT OF VIEW. Every error here is logged and swallowed: the
    /// start-up pass re-signs anything missing, so the cost of a failure is latency on one bridge
    /// message, while the cost of propagating it would be a halted validator.
    fn attest_committed(
        &self,
        height: u64,
        block_events: &[solidus_txns::types::Event],
        receipts: &[solidus_txns::types::Receipt],
    ) {
        let Some(attestor) = self.attestor.as_ref() else {
            return;
        };
        for (domain, seq, sig) in attestor.sign_committed(height, block_events, receipts) {
            if let Err(e) = self.store.put_attestation(domain, seq, &sig) {
                eprintln!(
                    "solidus-node2: cannot store attestation for domain {domain} seq {seq} \
                     ({e:?}); the start-up pass will re-sign it"
                );
            }
        }
    }

    /// Look up a block by hash: consensus first, then the store's
    /// certified-but-uncommitted blocks.
    ///
    /// ⚠ THE STORE HALF IS WHAT MAKES THIS WORK AFTER A RESTART. Consensus
    /// reloads only a window of blocks, so the ancestor a resumed validator
    /// needs is frequently absent from memory and present on disk.
    fn block_anywhere(&self, hash: &[u8; 32]) -> Option<solidus_hotstuff2::Block2> {
        if let Some(b) = self.consensus.block(hash) {
            return Some(b.clone());
        }
        let bytes = self.store.block_by_hash(hash).ok().flatten()?;
        bincode::deserialize(&bytes).ok()
    }

    /// Execute the ancestors between our head and `block`, if this node holds
    /// all of them. Returns whether the gap was closed locally.
    ///
    /// ⚠ ALL OR NOTHING, DELIBERATELY. A partial walk would execute a prefix and
    /// leave the same gap one block further along, turning one clean failure
    /// into a slow loop. If any ancestor is missing this reports false and the
    /// caller asks the network, which is the right answer for a real backlog.
    fn execute_missing_ancestors(
        &mut self,
        block: &solidus_hotstuff2::Block2,
        committed: &CommittedBlock,
        head: u64,
        out: &mut Vec<NodeOutput>,
    ) -> bool {
        // Bounded: beyond this a range request is genuinely the cheaper route,
        // and an unbounded walk over attacker-influenced parent links is not
        // something to do on the commit path.
        const MAX_LOCAL_CATCHUP: u64 = 64;
        if committed.height.saturating_sub(head) > MAX_LOCAL_CATCHUP {
            return false;
        }

        let mut chain = Vec::new();
        let mut cursor = block.header.parent;
        let mut height = committed.height.saturating_sub(1);
        while height > head {
            let Some(ancestor) = self.block_anywhere(&cursor) else {
                return false;
            };
            if ancestor.header.height != height {
                return false;
            }
            cursor = ancestor.header.parent;
            chain.push(ancestor);
            height -= 1;
        }

        // The walk must land exactly on our head, or this is a different chain
        // and executing it would fork us.
        match self.store.canon_hash(head) {
            Ok(Some(head_hash)) if head_hash == cursor => {}
            // Height 0 has no stored hash: genesis is the parent by definition.
            Ok(None) if head == 0 => {}
            _ => return false,
        }

        // ⛔ STOP AT THE FIRST BLOCK THAT DID NOT EXECUTE. This loop used to
        // ignore the result, so a block whose batch body was missing was skipped
        // and every block after it executed over the hole: a state root computed
        // from history this node never applied. Measured by
        // `a_commit_over_a_missing_batch_body_asks_for_the_range_and_skips_nothing`,
        // which reached head 3 over a hole at 1. And returning `true` regardless
        // told the caller the gap was closed, so it never asked for the body.
        for ancestor in chain.into_iter().rev() {
            let hash = ancestor.hash();
            let height = ancestor.header.height;
            let ts = ancestor.header.timestamp_ms;
            if !self.execute_block(&ancestor, height, hash, ts, out) {
                return false;
            }
        }
        self.execute_block(
            block,
            committed.height,
            committed.hash,
            committed.timestamp_ms,
            out,
        )
    }

    /// Execute one block whose body this node holds: resolve its transactions,
    /// run them, persist, advance the anchor, prune.
    ///
    /// ⚠ SHARED BY LIVE CONSENSUS AND BACKFILL ON PURPOSE. A synced block must
    /// take exactly the path a committed one takes, or the two can diverge on
    /// state — which is precisely the failure a chain cannot detect from inside.
    /// The trust decision happens BEFORE this is called: consensus for the live
    /// path, `sync::verify_fetched_range` for the backfill path.
    ///
    /// Returns whether the block executed. ⛔ A `false` IS A HOLE: nothing after
    /// this block may execute until it does, and the caller must ask for it.
    fn execute_block(
        &mut self,
        block: &solidus_hotstuff2::Block2,
        height: u64,
        block_hash: [u8; 32],
        timestamp_ms: u64,
        out: &mut Vec<NodeOutput>,
    ) -> bool {
        // Resolve tx bodies from worker-local storage in canonical order.
        let mut txs: Vec<Transaction> = Vec::new();
        let mut digests = Vec::new();
        {
            #[allow(clippy::expect_used)]
            let store = self.batch_store.read().expect("batch store");
            for cert in &block.header.batch_certs {
                // ⛔ MEMORY FIRST, THEN OUR OWN DISK. Boot starts this store
                // EMPTY, so without the disk read a restarted validator could not
                // execute any batch from before its restart, although
                // `persist_batch` wrote every one to store2. In a whole-set
                // restart no peer holds it in memory either, and the chain stops.
                let batch = match store.resolve(&cert.digest) {
                    Ok(batch) => Some(batch),
                    Err(_) => self.batch_from_disk(&cert.digest),
                };
                match batch {
                    Some(batch) => {
                        txs.extend(batch.transactions);
                        digests.push(cert.digest);
                    }
                    None => {
                        // Missing batch body: cannot execute yet.
                        self.sync_counters.blocks_blocked_on_body += 1;
                        return false;
                    }
                }
            }
        }

        #[allow(clippy::expect_used)]
        let parent_state_root = self.forest.read().expect("forest lock").global_root();
        let ctx = BlockCtx {
            height,
            timestamp_ms,
            network: &self.network,
            parent_state_root,
        };
        let Ok(outcome) = execute_block_twolane(&*self.store, &txs, &ctx, &self.opts) else {
            return false;
        };

        // Incremental root over the committed delta, and the four sub-roots
        // persisted beside the block for finality evidence.
        #[allow(clippy::expect_used)]
        let (root, sub_roots) = {
            let mut forest = self.forest.write().expect("forest lock");
            outcome.delta.apply_to_forest(&mut forest);
            (forest.global_root(), forest.sub_roots())
        };

        // ⛔ THE BLOCK BYTES USED TO BE `b""`, MARKED "the consensus encoding
        // (later)". A node cannot serve a block it never stored, which is why
        // `Store2::block_by_hash` had zero callers and zero tests, and why block
        // sync could not be built at all. Storing the encoded block is the
        // prerequisite for serving a range request to a lagging peer.
        //
        // A serialization failure must not stop the chain committing. It
        // degrades to the previous behaviour — an unservable height — and says
        // so loudly, rather than taking the validator down. `Block2` derives
        // Serialize with no custom logic, so this branch is not expected to run.
        let block_bytes = match bincode::serialize(&block) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!(
                    "solidus-node2: cannot encode block at height {height} ({e:?}); \
                     storing it empty, so peers cannot backfill this height"
                );
                Vec::new()
            }
        };

        #[allow(clippy::expect_used)]
        self.store
            .persist_block(
                height,
                block_hash,
                &block_bytes,
                &outcome.delta,
                &outcome.receipts,
                // The digests this block certifies, so pruning can drop their
                // bodies in step with the block itself.
                &digests.iter().map(|d| d.0).collect::<Vec<_>>(),
                sub_roots,
            )
            .expect("persist");

        // ⚠ AFTER PERSIST, AND THE ORDER IS THE POINT. A crash between the two costs a signature,
        // which the start-up pass regenerates from the outbox. The other order would leave a
        // signature for a block this node never stored, which is a claim it cannot back.
        self.attest_committed(height, &outcome.block_events, &outcome.receipts);

        {
            #[allow(clippy::expect_used)]
            let mut anchor = self.exec_anchor.lock().expect("anchor");
            *anchor = (height, root);
        }
        {
            #[allow(clippy::expect_used)]
            self.pool.lock().expect("pool").on_committed(&digests);
        }

        // Bound cold growth. `Store2::prune_cold_before` existed, was tested, and
        // was called by nothing, so v2 disk grew without limit — ~0.1 KB/block,
        // measured, which is ~34 MB/day across four validators.
        //
        // ⚠ PRUNES STRICTLY BELOW THE HEAD, AND THE GUARD BELOW GUARANTEES IT:
        // `height > retention` makes `horizon = height - retention` at least 1
        // and always less than `height`.
        //
        // ⚠ AN EARLIER COMMENT HERE CLAIMED THIS PROTECTS `canon_head()` FROM
        // BEING PRUNED INTO LOOKING LIKE A FRESH CHAIN. THAT WAS WRONG, and a
        // seeded test is what proved it: `canon_head()` reads a dedicated
        // `META_CANON_HEAD` key in `s_meta`, while `prune_cold_before` only
        // touches the `canon` and `blocks` families. The head pointer cannot be
        // pruned at all, so that failure mode does not exist.
        //
        // The REAL reason to stay below the head: pruning at or above it deletes
        // the head's own block and canon entry, leaving `canon_head()` pointing
        // at a block the store no longer holds. And a peer backfilling from a
        // height below the horizon cannot be served, so retention must exceed
        // the block-sync window.
        //
        // ⚠ STATE IS NEVER PRUNED — only blocks, receipts and canon entries — so
        // the boot-time forest rebuild still sees a complete state tree.
        // ⚠ PRUNE ON AN INTERVAL, NOT ON EVERY COMMIT. Each prune issues range
        // deletes, and running one per block wrote a tombstone every ~3 seconds on
        // the live chain. Pruning every `PRUNE_INTERVAL` blocks reclaims the same
        // disk, because the horizon moves by exactly as much either way, while
        // writing 1/PRUNE_INTERVAL of the tombstones.
        //
        // ⚠ THIS ONLY STARTS AT ALL ONCE `height > block_retention`, which defaults
        // to 1.000.000. Before that height v2 wrote ZERO range tombstones, which is
        // why the chain ran for months and then began OOM-killing its validators
        // the week it crossed the horizon. It did not degrade; it crossed a
        // threshold, and mainnet inherits this the moment it passes its own.
        if self.block_retention > 0
            && height > self.block_retention
            && height.is_multiple_of(PRUNE_INTERVAL)
        {
            let horizon = height - self.block_retention;
            if let Err(e) = self.store.prune_cold_before(horizon) {
                // Pruning is an optimisation, never a correctness requirement:
                // failing to reclaim disk must not stop the chain committing.
                // Disk exhaustion surfaces through monitoring, not by halting here.
                eprintln!("solidus-node2: prune below {horizon} failed: {e:?}");
            }
        }

        out.push(NodeOutput::BlockExecuted {
            height,
            tx_count: txs.len(),
            state_root: root,
        });
        true
    }

    /// This chain's genesis block hash, as consensus computed it.
    ///
    /// Exposed so the RPC edge can serve `chainInfo.genesis_hash` from the same
    /// source consensus uses, rather than recomputing the header and risking
    /// two answers to one question.
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.consensus.genesis_hash()
    }

    /// Most verified QCs kept as candidate sync anchors.
    ///
    /// One per committed block, and a node that has fallen further behind than
    /// this asks for a range it cannot anchor anyway, since
    /// [`MAX_BLOCK_RANGE`] caps a single fetch well below it.
    const MAX_ANCHORS: usize = 4096;

    /// Can this node link `tip` back to its own committed head?
    ///
    /// ⛔ THE WALK IS THE WHOLE POINT: IT HAS NO THRESHOLD TO GET WRONG. Every
    /// height-based test for lag is ambiguous, because a proposal or a
    /// certificate legitimately runs ahead of the committed head whenever the
    /// chain is pipelining or merely stalled. Whether the blocks in between are
    /// PRESENT is not ambiguous. A healthy validator reaches its committed head
    /// in two or three steps; one missing history runs out of blocks.
    ///
    /// Bounded so a long unlinked chain costs a fixed walk rather than an
    /// unbounded one; running out of budget is treated as missing, which is the
    /// safe direction (it asks for blocks it may already have).
    fn unlinked_tip(&self, tip: &[u8; 32]) -> TipLink {
        const WALK_LIMIT: usize = 64;
        let (committed_hash, committed_height) = self.consensus.last_committed();
        let mut cursor = *tip;
        let mut tip_height = None;
        for _ in 0..WALK_LIMIT {
            let Some(block) = self.consensus.block(&cursor) else {
                // Ran out of blocks before reaching what we committed: the gap
                // is real. ⛔ THIS ARM USED TO SHARE ITS RETURN VALUE WITH THE
                // "linked" ARM BELOW, via a `?`, and the two mean opposite
                // things. See `TipLink`.
                return TipLink::from_walk(tip_height);
            };
            let height = block.header.height;
            if tip_height.is_none() {
                tip_height = Some(height);
            }
            if cursor == committed_hash || height <= committed_height {
                return TipLink::Linked;
            }
            cursor = block.header.parent;
        }
        // Ran out of WALK_LIMIT rather than out of blocks: still a real gap.
        TipLink::from_walk(tip_height)
    }

    /// May this node ask for a range now?
    ///
    /// Yes if our head MOVED since the last request, because that is progress
    /// and the next chunk is genuinely the next question. Otherwise only after
    /// the cooldown, which covers the case where the answer never came.
    /// May this node ask for the body of `hash` now? A different hash may always
    /// be asked for; the same one waits out `SYNC_REQUEST_COOLDOWN`.
    fn may_request_body(&mut self, hash: [u8; 32]) -> bool {
        let now = std::time::Instant::now();
        let allowed = match self.last_body_request {
            Some((prev, at)) if prev == hash => now.duration_since(at) >= SYNC_REQUEST_COOLDOWN,
            _ => true,
        };
        if allowed {
            self.last_body_request = Some((hash, now));
        }
        allowed
    }

    fn may_request_range(&mut self, head: u64) -> bool {
        let now = std::time::Instant::now();
        let allowed = match self.last_range_request {
            None => true,
            Some((prev_head, at)) => {
                head != prev_head || now.duration_since(at) >= SYNC_REQUEST_COOLDOWN
            }
        };
        if allowed {
            self.last_range_request = Some((head, now));
        }
        allowed
    }

    fn remember_verified_qc(&mut self, qc: solidus_hotstuff2::QuorumCert) {
        let hash = qc.block_hash;
        if self.verified_qc_by_block.insert(hash, qc).is_none() {
            self.verified_qc_order.push_back(hash);
            while self.verified_qc_order.len() > Self::MAX_ANCHORS {
                if let Some(old) = self.verified_qc_order.pop_front() {
                    self.verified_qc_by_block.remove(&old);
                }
            }
        }
    }

    /// The highest QC this node verified through live consensus, if any.
    ///
    /// The block-sync apply path must use this as its anchor and must not
    /// accept one supplied by the peer serving the blocks.
    pub fn highest_verified_qc(&self) -> Option<&solidus_hotstuff2::QuorumCert> {
        self.highest_verified_qc.as_ref()
    }

    /// Read `[from, to]` from the store, clamped to [`MAX_BLOCK_RANGE`].
    ///
    /// ⚠ THE REQUESTED SPAN IS UNTRUSTED and drives an allocation, so it is
    /// clamped rather than believed. A height that is pruned, unknown, or was
    /// stored before blocks were persisted ENDS the reply: the range is always
    /// contiguous from `from`, and a short answer is normal rather than an error.
    ///
    /// ⛔ THIS USED TO SAY such a height "is simply ABSENT from the reply [...]
    /// and the requester must cope", and the loop skipped it. The requester
    /// cannot cope and never could: `verify_fetched_range` demands
    /// `height == expected_first_height + index` and discards the whole reply on
    /// the first mismatch. Responder and requester disagreed about the contract
    /// and the requester's side is the one that is enforced.
    pub fn read_block_range(&self, from: u64, to: u64) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let store = &self.store;
        let span = to
            .saturating_sub(from)
            .saturating_add(1)
            .min(MAX_BLOCK_RANGE);
        let mut blocks = Vec::new();
        let mut batches = Vec::new();
        let mut seen: HashSet<[u8; 32]> = HashSet::new();
        let mut budget = MAX_RANGE_REPLY_BYTES;

        for height in from..from.saturating_add(span) {
            // ⛔ STOP AT A HOLE, NEVER SKIP PAST IT. These three were `continue`,
            // which produced a reply with a GAP in it, and a gapped reply is
            // unusable: `verify_fetched_range` requires
            // `height == expected_first_height + index` and rejects the WHOLE
            // reply on the first mismatch. The comment above this function used
            // to promise the opposite, that "a pruned or unknown height is simply
            // ABSENT from the reply [...] and the requester must cope". It
            // cannot, and never could.
            //
            // ⚠ MEASURED 2026-09-13 on a validator past the recovery cliff: 45
            // requests, 7 usable replies, and every rejection the same shape,
            // "block at index 0 has height 103, expected 99". A responder missing
            // 99..102 was answering a request for 99 with a reply starting at
            // 103, and the requester threw all of it away.
            //
            // ⚠ IT BITES A FAR-BEHIND NODE SPECIFICALLY. Requests rotate peers,
            // and after a rolling restart validators hold different ranges, so a
            // 512-block span is far likelier to land on a peer with a hole than
            // a two-block one. The node that most needs backfill is the one most
            // likely to be handed something it must discard.
            //
            // A SHORT reply is normal and already handled: the requester asks
            // again from where it got to. Stopping is what makes it short rather
            // than gapped.
            let Ok(Some(hash)) = store.canon_hash(height) else {
                break;
            };
            // An empty body is a block persisted before block bytes were stored.
            // Serving it would hand the peer nothing decodable.
            let Ok(Some(block_bytes)) = store.block_by_hash(&hash) else {
                break;
            };
            if block_bytes.is_empty() {
                break;
            }

            // Gather this block's bodies FIRST, so a block is never sent without
            // the batches it needs. A block whose bodies do not fit is skipped
            // whole rather than sent unexecutable.
            let mut this_batches = Vec::new();
            let mut needed = block_bytes.len();
            if let Ok(digests) = store.block_batch_digests(height) {
                for d in digests {
                    if !seen.insert(d) {
                        continue; // already included for an earlier height
                    }
                    if let Ok(Some(body)) = store.batch_by_digest(&d) {
                        needed += body.len();
                        this_batches.push(body);
                    }
                }
            }

            // ⛔ NEVER STOP AT EXACTLY ONE BLOCK. A requester that holds no QC
            // for the newest block in a reply anchors it by TRIMMING that tip and
            // certifying the rest by their in-range successors, so a one-block
            // reply has nothing left after the trim and is rejected whole. Near
            // the chain tip, where one block plus its batch bodies can fill the
            // 2 MB budget by itself, that is what the cutoff below produced:
            // measured 2026-09-11, a node backfilled 11 -> 50 and then stalled on
            // four consecutive one-block replies it could not use.
            //
            // So the second block goes out even if it overruns. The overrun is
            // bounded by one block and its bodies, the budget is a DoS guard
            // rather than a protocol limit, and sending a reply the peer is
            // guaranteed to discard costs strictly more than overshooting once.
            //
            // ⚠ THE ANCHOR IS UNTOUCHED ON PURPOSE. It is what stands between
            // this path and a well-formed fork from a peer holding a quorum of
            // old keys. Making a one-block reply acceptable is a fork-safety
            // decision; making it not happen is not.
            if needed > budget && blocks.len() >= 2 {
                // Out of budget: stop cleanly on a block boundary. A short
                // answer is expected, and the requester asks again from where
                // it got to.
                break;
            }
            budget = budget.saturating_sub(needed);
            blocks.push(block_bytes);
            batches.append(&mut this_batches);
        }
        (blocks, batches)
    }

    /// Accept a block body a peer supplied for a certificate this node holds.
    ///
    /// ⛔ ACCEPTED ONLY IF IT MATCHES THE LOCK WE ALREADY VERIFIED. The QC was
    /// checked against the committee when it arrived, so supplying its body adds
    /// no trust: a peer can at most fill in a block a quorum already certified.
    /// Anything else is rejected and reported.
    ///
    /// It is also persisted, so the next restart does not need to ask again.
    pub fn accept_block_body(&mut self, bytes: &[u8]) -> bool {
        let Ok(block) = bincode::deserialize::<solidus_hotstuff2::Block2>(bytes) else {
            return false;
        };
        let hash = block.hash();
        // ⛔ DROP A BODY WE ALREADY HOLD BEFORE ANY WORK. Each request can be
        // answered by several peers, and re-accepting a copy re-drove consensus,
        // which re-verifies an aggregate BLS signature for nothing. Not a
        // rejection either, so it is not logged as one.
        if self.consensus.block(&hash).is_some() {
            return false;
        }
        if !self.consensus.accept_certified_block(block) {
            eprintln!(
                "solidus-node2: rejecting a block body for a lock we never held \
                 (hash {})",
                hex_digest(&hash)
            );
            return false;
        }
        let _ = self.store.put_pending_block(&hash, bytes);
        true
    }

    /// Decode, verify and apply blocks a peer sent in answer to a range
    /// request. Returns the outputs of whatever executed, empty if nothing did.
    ///
    /// ⛔ THIS IS THE TRUST BOUNDARY'S ENTRY POINT. It sources every
    /// verification input from THIS NODE — the committee it was configured
    /// with, its own stored head, and a QC it verified through live consensus.
    /// Nothing that arrived with the blocks is used to judge the blocks.
    ///
    /// ⚠ A range is applied whole or not at all. There is no partial accept.
    pub fn apply_synced_blocks(
        &mut self,
        block_bytes: &[Vec<u8>],
        batch_bytes: &[Vec<u8>],
    ) -> Vec<NodeOutput> {
        let mut blocks = Vec::with_capacity(block_bytes.len());
        for bytes in block_bytes {
            match bincode::deserialize::<solidus_hotstuff2::Block2>(bytes) {
                Ok(b) => blocks.push(b),
                Err(_) => {
                    // undecodable: reject the range
                    self.sync_counters.ranges_rejected += 1;
                    return Vec::new();
                }
            }
        }

        let head = match self.store.canon_head() {
            Ok(h) => h.unwrap_or(0),
            Err(_) => {
                self.sync_counters.ranges_rejected += 1;
                return Vec::new();
            }
        };

        // ⛔ DROP WHAT WE ALREADY HAVE INSTEAD OF DROPPING THE WHOLE REPLY. The
        // request named head+1, but the head moves while the reply is in
        // flight, so by the time it lands it usually starts BELOW our head.
        // Requiring an exact first height then threw away the blocks past our
        // head that we still needed, and the faster a node catches up the more
        // often it lost that race: measured 25 discarded replies in one run,
        // with the expected height climbing 10, 12, 17, 35.
        //
        // ⚠ SAFETY IS UNCHANGED. `verify_fetched_range` still walks the chain
        // from OUR head's hash and still requires the anchor to certify the
        // tip, so a trimmed reply proves exactly what an untrimmed one did.
        // Trimming from the FRONT cannot weaken the anchor, which checks the
        // LAST block. A reply that starts above head+1 still fails the
        // contiguity check, because that is a real gap rather than an overlap.
        let first_useful = blocks
            .iter()
            .position(|b| b.header.height > head)
            .unwrap_or(blocks.len());
        blocks.drain(..first_useful);
        if blocks.is_empty() {
            // Entirely stale: every block in it is already ours. Not an error,
            // and not worth a line of log on a node that is catching up well.
            self.sync_counters.ranges_stale += 1;
            return Vec::new();
        }

        // ⛔ PICK THE ANCHOR THAT CERTIFIES THIS RANGE'S NEWEST BLOCK, from the
        // QCs this node verified itself. Anchoring on `highest_verified_qc`
        // alone is a race a syncing node cannot win: the chain advances while
        // the fetch is in flight, so the newest anchor names a block newer than
        // the one we asked for, and genuine history is rejected.
        //
        // ⚠ THE PEER CHOOSES WHICH ANCHOR, AND THAT IS SAFE. It chooses only
        // among QCs this node already verified against its own committee, so
        // the worst it can do is hand us an OLDER piece of real history, which
        // costs a round trip and is corrected by the next proposal. It cannot
        // add an anchor, and a range with no matching anchor is refused.
        if self.highest_verified_qc.is_none() {
            // Nothing verified through consensus yet, so this node has no way
            // to tell the real chain from a fabricated one at all. Refuse
            // before looking at the blocks.
            self.sync_counters.ranges_rejected += 1;
            return Vec::new();
        }
        // ⛔ SEARCH THE WHOLE RANGE FOR AN ANCHOR, NOT JUST THE LAST BLOCK. This
        // used to look at `blocks.last()` alone, so a QC this node had ALREADY
        // VERIFIED for an earlier block in the same reply was ignored and the
        // range fell back to TrimTip. Trimming is the weaker path: it drops the
        // tip and leans on in-range successors, and a reply that is one block
        // after trimming cannot be anchored at all.
        //
        // ⚠ THIS IS STRICTLY STRONGER, NOT A LOOSENING. It anchors on a real
        // certificate the node verified through live consensus, which is exactly
        // what `highest_verified_qc`'s contract asks for, and it never accepts an
        // anchor supplied by the peer serving the blocks. Blocks above the
        // anchor are discarded rather than trusted.
        let anchor_at = blocks
            .iter()
            .rposition(|b| self.verified_qc_by_block.contains_key(&b.hash()));
        if let Some(i) = anchor_at {
            blocks.truncate(i + 1);
        }
        let tip_qc = blocks
            .last()
            .and_then(|newest| self.verified_qc_by_block.get(&newest.hash()))
            .cloned();
        // ⛔ THE LAST CHUNK IS ANCHORED; AN INTERMEDIATE ONE IS TRIMMED. A node
        // hundreds of blocks behind holds no QC for history that old, and the
        // reply cap truncates its chunks there, so demanding an anchored tip on
        // every chunk makes backfill impossible rather than safe. Trimming
        // gives the same guarantee by a different certificate: see
        // `sync::RangeAnchor`.
        let anchor = match &tip_qc {
            Some(qc) => crate::sync::RangeAnchor::Verified(qc),
            None => crate::sync::RangeAnchor::TrimTip,
        };

        // The parent the range must chain onto: our stored head's hash, or
        // genesis when we have nothing.
        let expected_parent = if head == 0 {
            self.consensus.genesis_hash()
        } else {
            match self.store.canon_hash(head) {
                Ok(Some(h)) => h,
                _ => {
                    self.sync_counters.ranges_rejected += 1;
                    return Vec::new();
                }
            }
        };

        let genesis = self.consensus.genesis_hash();
        let verified = match crate::sync::verify_fetched_range(
            &blocks,
            self.chain_id,
            &self.committee,
            &genesis,
            expected_parent,
            head + 1,
            anchor,
        ) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("solidus-node2: rejecting a fetched range: {e}");
                self.sync_counters.ranges_rejected += 1;
                // ⛔ A REJECTED REPLY MUST NOT END THE BACKFILL. This used to
                // return empty, which never reaches the re-request at the bottom
                // of this function, so one unusable reply stopped the chain until
                // a QC happened to arrive. Measured 2026-09-11: a node ran 11 ->
                // 50 through the pipeline and then stopped dead on four
                // consecutive unanchored replies.
                //
                // ⚠ IT CANNOT SPIN. `may_request_range` still gates it, and with
                // the head unmoved that is the 300ms cooldown, so this is about
                // three requests a second while genuinely stuck and silent the
                // moment a reply lands.
                let mut out = Vec::new();
                if self.may_request_range(head) {
                    out.push(NodeOutput::NeedBlocks {
                        from: head.saturating_add(1),
                        to: head.saturating_add(MAX_BLOCK_RANGE),
                    });
                }
                return out;
            }
        };

        let mut batches = Vec::with_capacity(batch_bytes.len());
        for bytes in batch_bytes {
            if let Ok(b) = bincode::deserialize::<solidus_mempool_dag::Batch>(bytes) {
                batches.push(b);
            }
            // A body that will not decode is simply absent; if a block needed
            // it, execution stops there rather than producing wrong state.
        }

        let mut out = self.apply_verified_range(verified, batches);

        // ⛔ KEEP GOING WHILE THE HEAD IS STILL MOVING. A range request is only
        // ever emitted when a QC arrives, and a node that has fallen behind
        // receives far fewer QCs than a healthy one: measured 21 against 86 on
        // this gate. A reply is also capped by MAX_RANGE_REPLY_BYTES rather than
        // by block count, and under this load a 512-block request comes back
        // holding one to five blocks. Multiply the two and the node that most
        // needs to catch up is the one that asks least often, which is the same
        // shape as the other wedges on this branch: being further behind must
        // not mean asking for less.
        //
        // ⚠ IT TERMINATES BY CONSTRUCTION, which is what makes this safe to do
        // unconditionally. The next request is emitted only if the head ACTUALLY
        // MOVED, so a reply that adds nothing ends the chain. There is no timer
        // to leak and no retry counter to tune.
        //
        // ⚠ A REJECTED REPLY STILL BREAKS THE CHAIN, and that is the next known
        // defect rather than an oversight here: the early return above never
        // reaches this point. Measured, node1 ran 11 -> 50 through this path and
        // then stopped dead on four consecutive unanchored replies.
        let head_after = self.store.canon_head().ok().flatten().unwrap_or(0);
        if head_after > head && self.may_request_range(head_after) {
            out.push(NodeOutput::NeedBlocks {
                from: head_after.saturating_add(1),
                to: head_after.saturating_add(MAX_BLOCK_RANGE),
            });
        }
        out
    }

    /// Apply a range of blocks fetched from a peer, in order.
    ///
    /// ⛔ TAKES A [`VerifiedRange`], NOT BLOCKS. That token can only be produced
    /// by [`crate::sync::verify_fetched_range`], so this function CANNOT be
    /// handed unverified blocks — not by mistake, not by a later refactor. The
    /// trust decision is made before the call and the type carries the proof.
    ///
    /// `batches` are the bodies the blocks certify, shipped with them because a
    /// v2 block carries only digests. Each is re-hashed on insert, so a peer
    /// cannot substitute a body for a digest it does not match.
    ///
    /// ⚠ EXECUTION USES THE SAME PATH AS LIVE CONSENSUS. A synced block must not
    /// take a shortcut a committed block does not, or the two can diverge on
    /// state, which is the one failure a chain cannot detect from inside.
    pub fn apply_verified_range(
        &mut self,
        range: crate::sync::VerifiedRange,
        batches: Vec<solidus_mempool_dag::Batch>,
    ) -> Vec<NodeOutput> {
        let mut out = Vec::new();

        // Bodies first: a block cannot resolve its transactions without them.
        for batch in batches {
            let digest = batch.digest();
            self.persist_batch(&batch);
            #[allow(clippy::expect_used)]
            let mut store = self.batch_store.write().expect("batch store");
            // `insert_verified` re-hashes and rejects a mismatch, so a peer
            // cannot pass off arbitrary bytes as a certified body.
            let _ = store.insert_verified(batch, digest);
        }

        // ⛔ STOP AT THE FIRST BLOCK THAT DID NOT EXECUTE, and remember the last
        // one that did. A reply can arrive without a body its first block needs,
        // and executing the rest would apply them over the hole.
        let mut executed_tip: Option<([u8; 32], u64)> = None;
        for block in range.blocks() {
            if !self.execute_block(
                block,
                block.header.height,
                block.hash(),
                block.header.timestamp_ms,
                &mut out,
            ) {
                break;
            }
            executed_tip = Some((block.hash(), block.header.height));
        }

        // ⛔ TELL CONSENSUS WHAT BACKFILL DECIDED, OR THE NODE NEVER REJOINS.
        // The 2-chain rule cannot commit across a gap, so a validator resuming
        // into a live chain commits nothing through consensus. Its store climbs
        // by backfill while the core's commit pointer stays where the restart
        // left it, and it therefore believes itself permanently behind: it keeps
        // asking for ranges, tracks the chain one step short, and never returns
        // to normal operation. Measured: store at 104, core still reporting 6.
        //
        // Safe because `range` is a `VerifiedRange`, which cannot be built
        // without passing `sync::verify_fetched_range`.
        //
        // ⚠ ONLY WHAT EXECUTED. Noting the range's tip when execution stopped
        // short moved the commit pointer past the store head, which is the split
        // the 2026-09-15 run measured (committed 239, store 213).
        if let Some((hash, height)) = executed_tip {
            self.consensus.note_synced_commit(hash, height);
        }
        out
    }

    /// Read committed account state (harness assertions).
    pub fn state_get(&self, key: &StateKey) -> Option<Vec<u8>> {
        self.store.get(key).ok().flatten()
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

/// BLS secret keys aren't `Clone`; round-trip through bytes (the node needs
/// the key in both the consensus core and the worker).
fn clone_secret(sk: &solidus_crypto::bls::BlsSecretKey) -> solidus_crypto::bls::BlsSecretKey {
    #[allow(clippy::expect_used)]
    solidus_crypto::bls::BlsSecretKey::from_bytes(&sk.to_bytes()).expect("valid bls key clone")
}

/// First 8 bytes of a digest, for log lines.
fn hex_digest(d: &[u8; 32]) -> String {
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod sync_apply_tests {
    use super::*;
    use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
    use solidus_hotstuff2::{
        vote_message, Block2, BlockHeader2, Committee, LeaderElector, Pacemaker, QuorumCert,
        RoundRobin,
    };
    use solidus_store2::{Profile, Store2};

    const CHAIN: u64 = 77;

    /// The genesis header `ConsensusCore` builds is fully determined by
    /// `chain_id`, so a test can reproduce its hash without reaching inside.
    fn genesis_hash() -> [u8; 32] {
        BlockHeader2 {
            chain_id: CHAIN,
            height: 0,
            view: 0,
            parent: [0u8; 32],
            batch_certs: vec![],
            exec_height: 0,
            exec_state_root: [0u8; 32],
            timestamp_ms: 0,
            proposer: 0,
        }
        .hash()
    }

    fn qc(keys: &[BlsSecretKey], view: u64, block_hash: [u8; 32]) -> QuorumCert {
        let msg = vote_message(CHAIN, view, &block_hash);
        let sigs: Vec<BlsSignature> = keys[..3].iter().map(|k| k.sign(&msg)).collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        QuorumCert {
            view,
            block_hash,
            signers: vec![0, 1, 2],
            #[allow(clippy::expect_used)]
            agg_sig: BlsSignature::aggregate(&refs).expect("aggregate"),
        }
    }

    /// A node with a fresh store, plus the committee keys that can sign QCs it
    /// will accept. The tempdir is held so RocksDB outlives the test.
    struct Harness {
        keys: Vec<BlsSecretKey>,
        node: Node,
        _dir: tempfile::TempDir,
    }

    #[allow(clippy::expect_used)]
    fn harness() -> Harness {
        let keys: Vec<BlsSecretKey> = (0..4).map(|_| BlsSecretKey::generate()).collect();
        let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let committee = Committee::new(pubkeys.clone());
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Store2::open(dir.path(), Profile::Testnet).expect("store");
        let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(4));
        let node = Node::new(
            0,
            CHAIN,
            BlsSecretKey::generate(),
            committee,
            pubkeys,
            Pacemaker::default(),
            elector,
            store,
            NodeTuning {
                block_retention: 0,
                ..NodeTuning::default()
            },
            "v2-sync-apply-test".to_string(),
        )
        .expect("node boots");
        Harness {
            keys,
            node,
            _dir: dir,
        }
    }

    /// `n` empty blocks from `first_height` chaining onto `parent`, plus an
    /// anchor QC over the newest.
    fn build_chain(
        keys: &[BlsSecretKey],
        parent: [u8; 32],
        first_height: u64,
        n: u64,
    ) -> (Vec<Block2>, QuorumCert) {
        let mut blocks = Vec::new();
        let mut prev = parent;
        for i in 0..n {
            let height = first_height + i;
            let b = Block2 {
                header: BlockHeader2 {
                    chain_id: CHAIN,
                    height,
                    view: height,
                    parent: prev,
                    batch_certs: vec![],
                    exec_height: height - 1,
                    exec_state_root: [0u8; 32],
                    timestamp_ms: 1_700_000_000_000 + height,
                    proposer: 0,
                },
                justify: qc(keys, height, prev),
            };
            prev = b.hash();
            blocks.push(b);
        }
        (blocks, qc(keys, first_height + n, prev))
    }

    /// Like `build_chain`, but block `i` certifies the batches in `certs[i]`.
    /// The certificates are built BEFORE hashing, so parents and justifies link.
    fn build_chain_with_certs(
        keys: &[BlsSecretKey],
        parent: [u8; 32],
        first_height: u64,
        certs: Vec<Vec<BatchCertificate>>,
    ) -> Vec<Block2> {
        let mut blocks = Vec::new();
        let mut prev = parent;
        for (i, batch_certs) in certs.into_iter().enumerate() {
            let height = first_height + i as u64;
            let b = Block2 {
                header: BlockHeader2 {
                    chain_id: CHAIN,
                    height,
                    view: height,
                    parent: prev,
                    batch_certs,
                    exec_height: height - 1,
                    exec_state_root: [0u8; 32],
                    timestamp_ms: 1_700_000_000_000 + height,
                    proposer: 0,
                },
                justify: qc(keys, height, prev),
            };
            prev = b.hash();
            blocks.push(b);
        }
        blocks
    }

    /// ⛔ THE RESTART CLIFF, REDUCED TO ONE COMMIT. Measured 2026-09-15 on the
    /// rolling-restart gate: a freshly restarted validator's store froze at 213
    /// while consensus kept committing to 239, and it sent no range request for
    /// 300 seconds. A block it committed certified a batch it never received.
    ///
    /// Two things must hold. It must not execute PAST the hole, because a later
    /// block applied over a missing one is a wrong state root. And it must ASK
    /// for the range, because a range reply carries batch bodies and nothing
    /// else will ever deliver this one.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_commit_over_a_missing_batch_body_asks_for_the_range_and_skips_nothing() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        let absent = BatchCertificate {
            digest: solidus_mempool_dag::BatchDigest([0xAB; 32]),
            worker: 0,
            attestation: vec![],
        };
        let blocks =
            build_chain_with_certs(keys, genesis_hash(), 1, vec![vec![absent], vec![], vec![]]);

        // Blocks 1 and 2 on disk, as a validator holds certified blocks it
        // received as proposals. Block 3 in consensus, as a committed tip is.
        for b in &blocks[..2] {
            node.store()
                .put_pending_block(&b.hash(), &bincode::serialize(b).expect("encode"))
                .expect("persist pending");
        }
        let tip = &blocks[2];
        let _ = node.step(NodeInput::Qc(qc(keys, 4, tip.hash())));
        assert!(
            node.accept_block_body(&bincode::serialize(tip).expect("encode")),
            "the tip must be in consensus, or this test exercises the wrong branch"
        );
        // ⚠ The QC above already asked for a range, so the 300ms cooldown is
        // running. Without waiting it out, the assertion below would measure
        // the rate limiter rather than the commit path.
        std::thread::sleep(SYNC_REQUEST_COOLDOWN + std::time::Duration::from_millis(50));

        let mut out = Vec::new();
        node.execute_committed(
            &CommittedBlock {
                hash: tip.hash(),
                height: 3,
                view: 3,
                timestamp_ms: tip.header.timestamp_ms,
            },
            &mut out,
        );

        let head = node.store().canon_head().expect("head").unwrap_or(0);
        assert_eq!(
            head, 0,
            "the node executed past a block whose batch body it does not hold"
        );
        assert!(
            out.iter()
                .any(|o| matches!(o, NodeOutput::NeedBlocks { from: 1, .. })),
            "a missing batch body must produce a range request from the hole, got {} outputs \
             and no NeedBlocks from 1",
            out.len()
        );
    }

    /// The same hole on the BACKFILL path. A range whose first block certifies
    /// a batch the reply did not carry must execute nothing past it, and must
    /// not tell consensus the range's tip is committed: that is what split the
    /// commit pointer from the store head in the 2026-09-15 run.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_synced_range_missing_a_body_stops_at_the_hole() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        let absent = BatchCertificate {
            digest: solidus_mempool_dag::BatchDigest([0xCD; 32]),
            worker: 0,
            attestation: vec![],
        };
        let blocks =
            build_chain_with_certs(keys, genesis_hash(), 1, vec![vec![absent], vec![], vec![]]);
        let _ = node.step(NodeInput::Qc(qc(keys, 4, blocks[2].hash())));

        // No batch bodies in the reply: the body for block 1 is simply absent.
        let _ = node.apply_synced_blocks(&encode(&blocks), &[]);

        let head = node.store().canon_head().expect("head").unwrap_or(0);
        assert_eq!(
            head, 0,
            "backfill executed past a block whose batch body is missing"
        );
        assert_eq!(
            node.committed_height(),
            0,
            "consensus was told a tip is committed that the store never executed"
        );
    }

    /// How many blocks an apply executed.
    ///
    /// ⚠ COUNT EXECUTIONS, NOT OUTPUTS. These tests asserted `out.len() == 3`,
    /// and they went red when `3a170ba83` made a successful range also emit the
    /// next `NeedBlocks` while the head is moving. Nobody noticed, because only
    /// the localnet binary was run on that branch. Any output other than those
    /// two kinds still fails, so the looser count cannot hide a new one.
    fn executed(out: &[NodeOutput]) -> usize {
        assert!(
            out.iter().all(|o| matches!(
                o,
                NodeOutput::BlockExecuted { .. } | NodeOutput::NeedBlocks { .. }
            )),
            "an apply emitted something other than executions and a follow-up request"
        );
        out.iter()
            .filter(|o| matches!(o, NodeOutput::BlockExecuted { .. }))
            .count()
    }

    /// ⛔ THE RESTART FLOOD, PART ONE. Measured 2026-09-15, run 3: a frozen
    /// validator spent 1260 ms of a 2 s window on 156 `BlockBody` messages and
    /// handled 241 inputs where a healthy one handled ~2000. The same body
    /// arrives many times, and every copy re-drove consensus, which re-verifies
    /// an aggregate BLS signature. A body consensus already holds adds nothing.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_duplicate_block_body_is_dropped_before_any_work() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        let (blocks, _) = build_chain(keys, genesis_hash(), 1, 1);
        let block = &blocks[0];
        let _ = node.step(NodeInput::Qc(qc(keys, 2, block.hash())));
        let bytes = bincode::serialize(block).expect("encode");

        let _ = node.step(NodeInput::BlockBody(bytes.clone()));
        assert_eq!(
            node.sync_counters().bodies_redriven,
            1,
            "the first body must be accepted and re-drive consensus, or this test proves nothing"
        );
        let _ = node.step(NodeInput::BlockBody(bytes));
        assert_eq!(
            node.sync_counters().bodies_redriven,
            1,
            "a body consensus already holds must not re-drive consensus again"
        );
    }

    /// ⛔ THE RESTART FLOOD, PART TWO. `consensus_out` asked for a missing lock
    /// body on EVERY consensus step, so hundreds of requests left before the
    /// first reply landed, and each one came back from every peer asked.
    #[test]
    fn a_missing_lock_body_is_requested_once_per_cooldown() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        let (blocks, _) = build_chain(keys, genesis_hash(), 1, 1);
        let hash = blocks[0].hash();

        // Two verified QCs for a block this node does not hold.
        let _ = node.step(NodeInput::Qc(qc(keys, 2, hash)));
        let _ = node.step(NodeInput::Qc(qc(keys, 3, hash)));
        assert_eq!(
            node.sync_counters().body_requests,
            1,
            "the same missing body must be requested once, not once per consensus step"
        );

        // CONTROL that must pass: after the cooldown the node asks again, so a
        // lost request or a silent peer cannot leave it waiting forever.
        std::thread::sleep(SYNC_REQUEST_COOLDOWN + std::time::Duration::from_millis(50));
        let _ = node.step(NodeInput::Qc(qc(keys, 4, hash)));
        assert_eq!(
            node.sync_counters().body_requests,
            2,
            "after the cooldown the missing body must be requested again"
        );
    }

    /// ⛔ THE BODY WAS ON DISK ALL ALONG. Boot builds an EMPTY in-memory
    /// `BatchStore`, and `execute_block` resolved only from it, so after any
    /// restart a validator could not execute a batch from before the restart
    /// even though `persist_batch` had written it to store2. Measured 2026-09-15:
    /// `the_whole_validator_set_restarts_without_losing_the_chain` failed 3 of 3
    /// once execution stopped skipping missing bodies, because in a whole-set
    /// restart no peer holds the batch in memory either.
    #[test]
    #[allow(clippy::expect_used)]
    fn a_batch_body_on_disk_executes_after_a_restart_without_asking_the_network() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        // A batch that exists ONLY on disk, as it does for a restarted node.
        let batch = solidus_mempool_dag::Batch {
            transactions: vec![],
        };
        let digest = batch.digest();
        node.store()
            .put_batch(&digest.0, &bincode::serialize(&batch).expect("encode"))
            .expect("persist batch");
        let cert = BatchCertificate {
            digest,
            worker: 0,
            attestation: vec![],
        };
        let blocks = build_chain_with_certs(keys, genesis_hash(), 1, vec![vec![cert]]);
        let block = &blocks[0];
        let _ = node.step(NodeInput::Qc(qc(keys, 2, block.hash())));
        assert!(node.accept_block_body(&bincode::serialize(block).expect("encode")));

        let mut out = Vec::new();
        node.execute_committed(
            &CommittedBlock {
                hash: block.hash(),
                height: 1,
                view: 1,
                timestamp_ms: block.header.timestamp_ms,
            },
            &mut out,
        );

        assert_eq!(
            node.store().canon_head().expect("head"),
            Some(1),
            "a batch body this node holds on disk must be enough to execute the block"
        );
        assert_eq!(
            node.sync_counters().blocks_blocked_on_body,
            0,
            "a body on disk is not a missing body"
        );
    }

    #[allow(clippy::expect_used)]
    fn encode(blocks: &[Block2]) -> Vec<Vec<u8>> {
        blocks
            .iter()
            .map(|b| bincode::serialize(b).expect("encode"))
            .collect()
    }

    /// ⛔ THE TEST THE APPLY PATH EXISTS FOR: a node holding nothing is handed a
    /// range a peer sent, and must end up at the right height — verified,
    /// executed and persisted, not merely accepted.
    #[test]
    fn a_node_with_no_history_catches_up_from_a_fetched_range() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        // Three empty blocks chaining off genesis. Each block's justify
        // certifies its PARENT, which is what the verifier walks forward.
        let (blocks, anchor) = build_chain(keys, genesis_hash(), 1, 3);

        // Without an anchor verified through live consensus, the range must be
        // refused — there is nothing to distinguish it from a fabricated one.
        #[allow(clippy::expect_used)]
        let encoded: Vec<Vec<u8>> = blocks
            .iter()
            .map(|b| bincode::serialize(b).expect("encode"))
            .collect();
        assert!(
            node.apply_synced_blocks(&encoded, &[]).is_empty(),
            "a range must be refused while the node has no anchor of its own"
        );

        // Feed the anchor the way live consensus would. `on_qc` verifies before
        // accepting, which is what makes it usable as an anchor.
        let _ = node.step(NodeInput::Qc(anchor));
        assert!(
            node.highest_verified_qc().is_some(),
            "a verified QC must be recorded, else the anchor path is dead and \
             the catch-up below would be proving nothing"
        );

        let out = node.apply_synced_blocks(&encoded, &[]);

        assert_eq!(executed(&out), 3, "every block in the range must execute");
        #[allow(clippy::expect_used)]
        let (height, _root) = *node.exec_anchor().lock().expect("anchor");
        assert_eq!(height, 3, "the node must END UP at the range's tip");
        #[allow(clippy::expect_used)]
        let head = node.store().canon_head().expect("head");
        assert_eq!(
            head,
            Some(3),
            "and it must be PERSISTED, not just held in memory — otherwise the \
             next restart loses the catch-up"
        );
    }

    /// Bridge plan 02 Task 13. Finality evidence reads the sub-roots persisted
    /// beside each block, so they must be the ones the node executed, not
    /// placeholders. Combining them must give the committed root, and they must
    /// match the forest the RPC edge is handed.
    #[test]
    fn each_executed_height_persists_the_sub_roots_that_combine_to_its_root() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;
        let (blocks, anchor) = build_chain(keys, genesis_hash(), 1, 3);
        let _ = node.step(NodeInput::Qc(anchor));
        assert_eq!(
            executed(&node.apply_synced_blocks(&encode(&blocks), &[])),
            3
        );

        #[allow(clippy::expect_used)]
        let (height, root) = *node.exec_anchor().lock().expect("anchor");
        #[allow(clippy::expect_used)]
        let stored = node
            .store()
            .sub_roots(height)
            .expect("read")
            .expect("persisted");
        assert_eq!(
            solidus_state_tree::global_state_root(&stored[0], &stored[1], &stored[2], &stored[3]),
            root,
            "the persisted sub-roots must combine to the committed root"
        );
        #[allow(clippy::expect_used)]
        let shared = node
            .forest_handle()
            .read()
            .expect("forest lock")
            .sub_roots();
        assert_eq!(
            stored, shared,
            "and match the forest handed to the RPC edge"
        );
    }

    /// ⛔ THE CASE THAT ACTUALLY HAPPENS. The empty-node test exercises the
    /// genesis branch of `expected_parent`; a real lagging validator has
    /// history, so the range must chain onto its STORED HEAD instead. That is a
    /// different code path and it was untested until now — node2 on the devnet
    /// was in exactly this state, holding 188 MB and unable to rejoin.
    #[test]
    fn a_node_stopped_mid_chain_resumes_from_its_own_head() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        // Catch up to 3, the same way the empty-node test does.
        let (first, anchor1) = build_chain(keys, genesis_hash(), 1, 3);
        let _ = node.step(NodeInput::Qc(anchor1));
        assert_eq!(executed(&node.apply_synced_blocks(&encode(&first), &[])), 3);

        // Now the node has history. A second range must chain onto block 3, not
        // genesis, and the verifier must source that parent from the store.
        let head_hash = first[2].hash();
        let (second, anchor2) = build_chain(keys, head_hash, 4, 3);
        let _ = node.step(NodeInput::Qc(anchor2));
        let out = node.apply_synced_blocks(&encode(&second), &[]);

        assert_eq!(executed(&out), 3, "the second range must execute too");
        #[allow(clippy::expect_used)]
        let head = node.store().canon_head().expect("head");
        assert_eq!(head, Some(6), "the node must reach the newer tip");
    }

    /// A range that chains onto the wrong parent must be refused even when it
    /// is internally perfect and carries a matching anchor. Otherwise a peer
    /// could replace history a node already has.
    #[test]
    fn a_range_that_forks_below_our_head_is_refused() {
        let mut h = harness();
        let keys = &h.keys;
        let node = &mut h.node;

        let (first, anchor1) = build_chain(keys, genesis_hash(), 1, 3);
        let _ = node.step(NodeInput::Qc(anchor1));
        assert_eq!(executed(&node.apply_synced_blocks(&encode(&first), &[])), 3);

        // A well-formed range built on GENESIS again, i.e. a fork below our
        // head, with its own valid anchor.
        let (fork, fork_anchor) = build_chain(keys, genesis_hash(), 4, 3);
        let _ = node.step(NodeInput::Qc(fork_anchor));
        // A refused reply may still ask for the next range, which is the
        // backfill staying alive, so "refused" means nothing EXECUTED.
        assert_eq!(
            executed(&node.apply_synced_blocks(&encode(&fork), &[])),
            0,
            "a range that does not chain onto our stored head must be refused"
        );
        #[allow(clippy::expect_used)]
        let head = node.store().canon_head().expect("head");
        assert_eq!(head, Some(3), "and our history must be untouched");
    }
}

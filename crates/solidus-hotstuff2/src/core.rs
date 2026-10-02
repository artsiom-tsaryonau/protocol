//! The event-driven HotStuff-2 core: a pure state machine with no I/O and
//! no timers. The node layer feeds it network messages and timer firings;
//! it returns the [`Action`]s to perform. This shape is what makes the
//! protocol unit-testable, deterministic, and mirrorable by the TLA+ spec
//! — and it structurally enforces the no-O(N)-proposal-fan-out rule: the
//! action vocabulary has `BroadcastProposal` (gossip) and point-to-point
//! `SendVote`, and nothing that could send a proposal per-peer.
//!
//! Thread placement note (§4.4 "BLS off the consensus thread"): the core
//! is synchronous and pure; the node layer runs CPU-heavy handlers
//! (`on_vote` at quorum → aggregation; QC verification in `on_proposal`)
//! on a blocking pool at 21-validator scale. At the Stage-1 4-node
//! harness scale the cost is microseconds and measured inline.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use solidus_crypto::bls::BlsSecretKey;
use solidus_mempool_dag::BatchCertificate;

use crate::aggregate::{TimeoutAggregator, VoteAggregator};
use crate::error::ConsensusError;
use crate::leader::LeaderElector;
use crate::pacemaker::Pacemaker;
use crate::safety::SafetyState;
use crate::types::{
    proposal_message, timeout_message, vote_message, Block2, BlockHeader2, Committee, Proposal,
    QuorumCert, TimeoutCert, TimeoutVote, ValidatorIndex, View, Vote,
};

// ---------------------------------------------------------------------------
// Actions & supporting traits
// ---------------------------------------------------------------------------

/// A block the core has finalized (2-chain rule satisfied).
#[derive(Debug, Clone, PartialEq)]
pub struct CommittedBlock {
    pub hash: [u8; 32],
    pub height: u64,
    pub view: View,
    pub timestamp_ms: u64,
}

/// What the node layer must do after feeding the core an event.
#[allow(clippy::large_enum_variant)] // transient, ≤4 per event; boxing Proposal buys nothing
#[derive(Debug, Clone)]
pub enum Action {
    /// Gossip the proposal to the whole network (gossipsub topic — never
    /// per-peer request/response).
    BroadcastProposal(Proposal),
    /// Send a vote point-to-point to the next view's leader.
    SendVote { to: ValidatorIndex, vote: Vote },
    /// Gossip a timeout vote (any replica may assemble the TC).
    BroadcastTimeoutVote(TimeoutVote),
    /// Gossip a freshly formed TC.
    BroadcastTc(TimeoutCert),
    /// Gossip a freshly formed QC (latency: followers learn commit one
    /// gossip hop after the leader instead of one full view later).
    BroadcastQc(QuorumCert),
    /// A block is final. Emitted in chain order, exactly once per block.
    Commit(CommittedBlock),
    /// Arm (or re-arm) the view timer.
    ScheduleTimeout { view: View, delay: Duration },
    /// We are the leader of `view` and want to propose, but the minimum block
    /// interval has not elapsed. Call `on_propose_timer(view)` after `delay`.
    ///
    /// ⛔ THIS EXISTS BECAUSE SKIPPING THE PROPOSAL IS NOT PACING. Gating
    /// `propose()` on elapsed time inside `enter_view` and returning would leave
    /// the view with no proposal at all, so it times out, the pacemaker rotates
    /// leadership and backs off, and blocks then arrive at the TIMEOUT rate with
    /// a timeout certificate each. Delaying the proposal keeps this leader, this
    /// view, and one block.
    SchedulePropose { view: View, delay: Duration },
    /// Telemetry: the core entered a view.
    EnteredView(View),
}

/// Supplies block payloads + proposer timestamps (kept outside the core so
/// tests stay deterministic — no wall-clock inside the state machine).
pub trait PayloadProvider {
    fn next_payload(&mut self) -> Vec<BatchCertificate>;
    /// Is there anything worth putting in a block? NON-CONSUMING.
    ///
    /// ⛔ THIS IS ONLY MEANINGFUL BECAUSE CERTIFICATES ARE NOW GOSSIPED. It used
    /// to be a fact about ONE node: `CertFormed` added to the local pool and
    /// nothing carried it further, so a leader held roughly
    /// 1/committee_size of the committee's work and answering `false` here
    /// silenced it in most views while the chain had plenty to do. Three
    /// suppression attempts failed on exactly that, and none of them was a
    /// wiring bug. Do not reintroduce suppression without certificate gossip.
    fn has_work(&mut self) -> bool {
        true
    }
    fn now_ms(&mut self) -> u64;
    /// The proposer's newest-executed (height, global root) — the header's
    /// exec anchor (see `BlockHeader2` docs).
    fn exec_anchor(&mut self) -> (u64, [u8; 32]);
}

/// Empty payloads with a fixed logical clock — consensus bring-up harness.
pub struct EmptyPayloads {
    pub ts_ms: u64,
}

impl PayloadProvider for EmptyPayloads {
    fn next_payload(&mut self) -> Vec<BatchCertificate> {
        Vec::new()
    }
    fn now_ms(&mut self) -> u64 {
        self.ts_ms
    }
    /// Always true, deliberately: this harness exists to drive views with no
    /// mempool at all, and answering `false` would make every core test that
    /// uses it stop producing blocks.
    fn has_work(&mut self) -> bool {
        true
    }
    fn exec_anchor(&mut self) -> (u64, [u8; 32]) {
        (0, [0u8; 32])
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

pub struct CoreConfig {
    pub chain_id: u64,
    pub my_index: ValidatorIndex,
    pub secret: BlsSecretKey,
    pub committee: Committee,
    pub pacemaker: Pacemaker,
    /// Minimum wall-clock gap between this node's own proposals, in ms.
    ///
    /// ⛔ IT MUST STAY WELL BELOW THE VIEW TIMEOUT OR THE CHAIN THRASHES. A view
    /// that has not seen a proposal by `Pacemaker::current_timeout()` times out
    /// and rotates leadership, so an interval at or above the timeout makes every
    /// view time out and blocks arrive at the backoff rate instead. The pacemaker
    /// base was 400ms when this landed; `MIN_TIMEOUT_HEADROOM` below is what keeps
    /// the two coherent, and `Core::new` panics rather than ship a config where a
    /// paced chain would silently degrade into a timing-out one.
    ///
    /// 0 disables pacing, which is the behaviour before this existed: propose the
    /// instant this node leads. Measured on the live testnet at that setting:
    /// **8,60 blocks/s, one every 116ms**, every one of them empty, against a
    /// stated 2,0s target.
    pub min_block_interval_ms: u64,
    /// Propose an empty block if this long has passed with nothing to include.
    /// `0` disables suppression entirely: every view produces a block.
    ///
    /// ⚠ KEEP IT LONG. v1 uses 600s. Shortening it walks straight back toward
    /// the ~69 MB/day of empty blocks this exists to remove.
    pub idle_heartbeat_ms: u64,
    /// Work must be absent CONTINUOUSLY for this long before a view is
    /// suppressed. Bounds the cost of a momentary gap.
    ///
    /// ⚠ IT MUST EXCEED THE TIME IT TAKES WORK TO APPEAR: batch flush interval
    /// plus an ack round trip. Too small and a busy chain pays a view timeout in
    /// every gap between certificates, which is strictly worse than the empty
    /// block suppression was meant to avoid.
    pub idle_grace_ms: u64,
}

/// A view must be allowed at least this multiple of the block interval before it
/// times out, or pacing and liveness fight each other.
pub const MIN_TIMEOUT_HEADROOM: u32 = 2;

// ---------------------------------------------------------------------------
// The core
// ---------------------------------------------------------------------------

/// Durable state a restarting validator must restore before rejoining.
///
/// ⛔ ALL FIELDS OR NONE. Restoring the committed height without the voted view
/// produces a node that rejoins a live chain having forgotten its votes, which
/// is the slashable case; restoring both without `blocks` produces a node that
/// silently never votes. `resume` takes them together so no caller can ask for
/// part of it.
#[derive(Debug, Clone)]
pub struct ResumeState {
    pub last_voted_view: View,
    pub high_qc: QuorumCert,
    pub last_committed_hash: [u8; 32],
    pub last_committed_height: u64,
    /// Recent committed blocks, newest last.
    ///
    /// ⛔ WITHOUT THESE THE NODE WEDGES SILENTLY, and that is measured rather
    /// than feared. `on_proposal` looks up `header.parent` and returns NO VOTE
    /// when it misses; a resumed node whose map holds only genesis therefore
    /// declines every proposal, no QC forms, and the chain stops. The minimum
    /// is the last committed block, because `commit_chain` also walks back to
    /// it and must find it to terminate.
    pub blocks: Vec<Block2>,
}

/// Committed blocks kept in the in-memory map after the commit boundary moves.
///
/// ⚠ **THIS MAP WAS BOUNDED BY NOTHING AND THAT IS WHAT KILLED THE TESTNET BOX.**
/// `blocks` is inserted at five sites and, before this, removed at none: not on
/// commit, not ever. So it grew for the life of the process on a HEALTHY chain as
/// well as a stalled one. Measured 2026-09-05 on solidus-rpc (4 GB): a validator
/// running 34h of normal operation peaked at 1.1 GB against a 207 MB resting set,
/// and one replaying blocks after a restart reached 1.9 GB in 81 seconds and was
/// OOM-killed, which cost quorum, which stalled the chain, which grew the map on
/// the survivors. 2.715 kernel OOM lines and the loss of sshd and nginx.
///
/// ⚠ **THE REST OF THIS FILE ALREADY KNEW TO DO THIS.** `votes` and `timeouts` are
/// garbage-collected on every view change (`enter_view`), and the node layer prunes
/// cold storage with `prune_cold_before`. `blocks` was the one that was missed.
///
/// The core needs a block only to walk parents while committing and to validate a
/// proposal whose parent is recent. Everything below the boundary is durable in the
/// store, persisted by node2 on `Action::Commit`, so keeping it here is dead weight.
/// The window is generous on purpose: it must exceed any fork the pacemaker can
/// still resolve, and reclaiming memory is never worth risking a missing parent.
const IN_MEMORY_BLOCK_RETENTION: u64 = 256;

pub struct ConsensusCore<L: LeaderElector, P: PayloadProvider> {
    chain_id: u64,
    my_index: ValidatorIndex,
    secret: BlsSecretKey,
    committee: Committee,
    elector: L,
    payloads: P,

    cur_view: View,
    safety: SafetyState,
    pacemaker: Pacemaker,

    genesis_hash: [u8; 32],
    blocks: HashMap<[u8; 32], Block2>,
    votes: VoteAggregator,
    timeouts: TimeoutAggregator,

    last_committed_hash: [u8; 32],
    last_committed_height: u64,

    /// TC that admitted us into `cur_view` (attach to our proposal there).
    entry_tc: Option<TimeoutCert>,
    /// Highest view we have proposed in (never double-propose).
    proposed_up_to: View,
    /// Minimum gap between our own proposals; 0 disables pacing.
    min_block_interval_ms: u64,
    idle_heartbeat_ms: u64,
    idle_grace_ms: u64,
    /// `now_ms()` when we last SAW work. Not when we last used it.
    last_work_ms: u64,
    /// `now_ms()` at our last proposal. 0 means we have not proposed yet, so the
    /// first proposal after boot is never delayed.
    last_proposal_ms: u64,

    /// Every block hash `high_qc` has held, newest last, bounded.
    ///
    /// ⛔ THIS EXISTS BECAUSE A LOCK MOVES FASTER THAN A ROUND TRIP. Asking for
    /// a body and then accepting it only if it still matches the CURRENT
    /// `high_qc` is a race the network wins: measured 2026-09-11, 239 of 239
    /// rejections were the body we had asked for one step earlier, arriving
    /// after a newer QC had already moved the lock. The node then asked for the
    /// new hash and lost the same race again, so it never executed and its
    /// height never moved while the committee ran on.
    ///
    /// ⚠ IT IS NOT A TRUST WEAKENING. Every hash in here came from a QC that
    /// `process_qc` had already verified against the committee, so accepting a
    /// body for any of them still means "a peer can at most supply the body for
    /// a block a quorum already certified". Only the freshness requirement is
    /// dropped, and freshness was never the safety property.
    ///
    /// Bounded because it only has to cover a round trip. It is a ring, not a
    /// history: an unbounded set here would be a slow leak on a long-running
    /// validator for no benefit.
    certified_locks: VecDeque<[u8; 32]>,
}

/// How many past locks stay acceptable. One round trip is a handful of views;
/// 64 is generous and costs 2 KiB.
const CERTIFIED_LOCK_MEMORY: usize = 64;

impl<L: LeaderElector, P: PayloadProvider> ConsensusCore<L, P> {
    pub fn new(config: CoreConfig, elector: L, payloads: P) -> Self {
        let genesis_header = BlockHeader2 {
            chain_id: config.chain_id,
            height: 0,
            view: 0,
            parent: [0u8; 32],
            batch_certs: vec![],
            exec_height: 0,
            exec_state_root: [0u8; 32],
            timestamp_ms: 0,
            proposer: 0,
        };
        let genesis_hash = genesis_header.hash();
        // The genesis QC is axiomatic; its signature bytes are a
        // placeholder that the view-0 verification path never checks.
        let genesis_qc =
            QuorumCert::genesis(genesis_hash, config.secret.sign(b"solidus-v2-genesis"));
        let genesis_block = Block2 {
            header: genesis_header,
            justify: genesis_qc.clone(),
        };

        // ⛔ REFUSE A CONFIG WHERE PACING AND LIVENESS FIGHT. A block interval at or
        // near the view timeout means the view expires before this leader proposes,
        // so the pacemaker rotates and backs off and the chain produces at the
        // TIMEOUT rate with a timeout certificate per block. That degradation is
        // silent from outside — the chain still commits — which is exactly why it
        // is a panic at construction and not a log line.
        if config.min_block_interval_ms > 0 {
            let timeout_ms = config.pacemaker.current_timeout().as_millis() as u64;
            let needed = config
                .min_block_interval_ms
                .saturating_mul(u64::from(MIN_TIMEOUT_HEADROOM));
            assert!(
                timeout_ms >= needed,
                "block interval {}ms needs a view timeout of at least {}ms ({}x headroom), \
                 but the pacemaker's is {}ms: every view would time out",
                config.min_block_interval_ms,
                needed,
                MIN_TIMEOUT_HEADROOM,
                timeout_ms,
            );
        }

        let mut blocks = HashMap::new();
        blocks.insert(genesis_hash, genesis_block);

        Self {
            chain_id: config.chain_id,
            my_index: config.my_index,
            secret: config.secret,
            committee: config.committee,
            elector,
            payloads,
            cur_view: 0,
            safety: SafetyState::new(genesis_qc),
            certified_locks: VecDeque::new(),
            pacemaker: config.pacemaker,
            genesis_hash,
            blocks,
            votes: VoteAggregator::new(),
            timeouts: TimeoutAggregator::new(),
            last_committed_hash: genesis_hash,
            last_committed_height: 0,
            entry_tc: None,
            proposed_up_to: 0,
            min_block_interval_ms: config.min_block_interval_ms,
            idle_heartbeat_ms: config.idle_heartbeat_ms,
            idle_grace_ms: config.idle_grace_ms,
            last_work_ms: 0,
            last_proposal_ms: 0,
        }
    }

    /// Resume from persisted state instead of starting at genesis.
    ///
    /// ⛔ THE VIEW IT RESUMES INTO IS THE SAFETY PROPERTY. `cur_view` becomes
    /// strictly greater than BOTH the highest view this validator voted in and
    /// the view of its lock, so it can never re-enter a view it already voted
    /// in. That is what makes resuming safe rather than merely correct.
    ///
    /// ⚠ `proposed_up_to` is set to the resumed view deliberately: this node
    /// does not propose in its first view back. `proposed_up_to` is not
    /// persisted, so its true value is unknown after a restart, and skipping
    /// one proposal costs a pacemaker round the committee absorbs.
    pub fn resume(&mut self, r: ResumeState) {
        // ⛔ RESUME INTO THE VIEW THE COMMITTEE SHARES, NOT THIS VALIDATOR'S
        // PRIVATE ONE. `last_voted_view` is per-validator: nodes stopped a
        // moment apart persist different values, so deriving `cur_view` from it
        // brings the committee back SCATTERED across several views. Timeout
        // votes only aggregate within one view, so scattered validators each
        // time out alone, no view ever reaches f+1 let alone a quorum, and the
        // chain is wedged with every node healthy. The v2 devnet did exactly
        // that on 2026-09-02: every validator resumed, the height held at 811,
        // and not one block followed.
        //
        // `high_qc` is the opposite kind of state - it is a CERTIFICATE, so
        // every validator that stopped on the same chain holds the same one, and
        // resuming from it puts them back together by construction.
        //
        // ⚠ SAFETY DOES NOT DEPEND ON THIS BEING ABOVE `last_voted_view`, and
        // that is the point worth checking rather than assuming. Voting is gated
        // by `SafetyState::safe_to_vote`, which refuses any view at or below
        // `last_voted_view` no matter what `cur_view` says. Resuming lower can
        // cost this validator a skipped vote in a view it already voted in; it
        // cannot produce a second vote in one view.
        let resume_view = r.high_qc.view.saturating_add(1);
        // ⚠ ONE BELOW THE TARGET ON PURPOSE, so `start()`'s `enter_view` is a
        // real transition rather than a no-op that schedules no timer.
        self.cur_view = resume_view.saturating_sub(1);
        self.proposed_up_to = resume_view;
        // ⛔ SEED THE RING FROM THE RESUMED LOCK. A restarted node asks for this
        // body first, and without the seed the answer races the next QC and is
        // rejected, which is the exact wedge this whole mechanism exists for,
        // and a restart is precisely when it bites.
        self.remember_lock(r.high_qc.block_hash);
        self.safety = SafetyState::resumed(r.last_voted_view, r.high_qc);
        self.last_committed_hash = r.last_committed_hash;
        self.last_committed_height = r.last_committed_height;
        for block in r.blocks {
            self.blocks.insert(block.hash(), block);
        }
    }

    pub fn current_view(&self) -> View {
        self.cur_view
    }

    /// Record that blocks up to `height` are committed, because BACKFILL
    /// applied them rather than this core deciding them.
    ///
    /// ⛔ WITHOUT THIS A SYNCED NODE NEVER REJOINS. The 2-chain rule cannot
    /// commit across a gap, so a validator that resumes into a live chain
    /// commits nothing through consensus; its store advances by backfill while
    /// this pointer stays where the restart left it. It then looks permanently
    /// behind to itself, keeps asking for ranges, and never returns to normal
    /// operation. Measured: store at 104, consensus still reporting 6.
    ///
    /// ⚠ ONLY FOR BLOCKS THAT PASSED `sync::verify_fetched_range`. This moves
    /// the commit pointer without a commit rule having fired, so the caller
    /// carries the proof. It refuses to move BACKWARDS, which is the one
    /// mistake that would rewrite decided history.
    pub fn note_synced_commit(&mut self, hash: [u8; 32], height: View) {
        if height > self.last_committed_height {
            self.last_committed_hash = hash;
            self.last_committed_height = height;
            // ⚠ THE SYNC PATH NEEDS THIS AS MUCH AS THE COMMIT PATH, AND IT IS THE
            // ACUTE ONE. A validator replaying a range after a restart inserts
            // bodies as fast as peers serve them; measured 2026-09-05, that reached
            // 1.9 GB in 81 seconds and was OOM-killed before it could finish, so it
            // never caught up and never stopped trying.
            self.gc_blocks();
        }
    }

    /// Drop committed blocks the core can no longer need. Mirrors `votes.gc()` and
    /// `timeouts.gc()`, which bound the other two view-keyed maps on every view
    /// change. Called from every path that advances the commit boundary.
    ///
    /// Genesis is kept unconditionally: `genesis_hash` is a fixed reference the
    /// view-0 paths still resolve against.
    fn gc_blocks(&mut self) {
        if self.last_committed_height <= IN_MEMORY_BLOCK_RETENTION {
            return;
        }
        let horizon = self.last_committed_height - IN_MEMORY_BLOCK_RETENTION;
        let genesis = self.genesis_hash;
        self.blocks
            .retain(|hash, b| b.header.height >= horizon || *hash == genesis);
    }

    /// Number of blocks held in memory. Exposed so the bound is observable: a
    /// value that climbs with chain height means the retention above regressed.
    pub fn tracked_blocks(&self) -> usize {
        self.blocks.len()
    }

    pub fn last_committed(&self) -> ([u8; 32], u64) {
        (self.last_committed_hash, self.last_committed_height)
    }

    /// The current locked high QC.
    ///
    /// Exposed so the node layer can persist safety state alongside the voted
    /// view. The commit rule depends on this lock, so recovering the voted view
    /// without it would restore half the safety state.
    pub fn high_qc(&self) -> &QuorumCert {
        self.safety.high_qc()
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Fetch a stored block by hash (the node layer resolves committed
    /// blocks' batch certificates for execution).
    /// The block this node is locked on but does NOT hold, if any.
    ///
    /// ⛔ THIS IS THE CONDITION THAT WEDGES A RESTARTED CHAIN, and until now
    /// nothing could see it. `propose` and `on_proposal` both return silently
    /// when `blocks` lacks `high_qc.block_hash` — the comments in each say
    /// "Block sync: node layer", and this is what lets the node layer act on it
    /// rather than guess.
    ///
    /// A resumed validator reloads the block its OWN lock certifies, but
    /// processing a TC advances the lock to a peer's higher QC whose body it
    /// never had. Every leader then falls silent and the pacemaker rotates
    /// forever, which is exactly what 334 recorded actions showed.
    pub fn missing_lock_body(&self) -> Option<[u8; 32]> {
        let hash = self.safety.high_qc().block_hash;
        (!self.blocks.contains_key(&hash)).then_some(hash)
    }

    /// Insert a block this node already holds a QC for.
    ///
    /// ⛔ THE QC CHECK IS THE WHOLE SAFETY ARGUMENT. The block is accepted only
    /// when its hash matches a certificate this node has ALREADY verified, so a
    /// peer cannot inject arbitrary bodies: it can at most supply the body for a
    /// block a quorum already certified.
    ///
    /// ⚠ "ALREADY VERIFIED" MEANS ANY LOCK WE HAVE HELD, NOT ONLY THE CURRENT
    /// ONE, and the difference is the whole bug this function once had. See
    /// `certified_locks`. Returns false only for a hash no verified QC of ours
    /// has ever named, which the caller should treat as a peer sending
    /// something unasked for.
    pub fn accept_certified_block(&mut self, block: Block2) -> bool {
        let hash = block.hash();
        // ⛔ ANY LOCK WE HAVE VERIFIED, NOT ONLY THE CURRENT ONE. See
        // `certified_locks`: pinning this to `high_qc` made the node reject the
        // very body it had just asked for, because a newer QC had moved the lock
        // while the request was in flight.
        if hash != self.safety.high_qc().block_hash && !self.certified_locks.contains(&hash) {
            return false;
        }
        self.blocks.insert(hash, block);
        true
    }

    /// Record a block hash a verified QC has locked us onto.
    fn remember_lock(&mut self, hash: [u8; 32]) {
        if self.certified_locks.contains(&hash) {
            return;
        }
        if self.certified_locks.len() == CERTIFIED_LOCK_MEMORY {
            self.certified_locks.pop_front();
        }
        self.certified_locks.push_back(hash);
    }

    pub fn block(&self, hash: &[u8; 32]) -> Option<&Block2> {
        self.blocks.get(hash)
    }

    /// Boot the core into view 1.
    pub fn start(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        // ⛔ NEVER ENTER A VIEW BELOW THE CURRENT ONE. This used to enter view 1
        // unconditionally, which silently undid `resume()`: a validator restored
        // to view 33 was dragged back to view 1, and its own safety rule then
        // correctly refused every proposal, because `safe_to_vote` requires
        // `proposal_view > last_voted_view` and 1 > 32 is false. All four nodes
        // refused everything and the chain wedged - the safety rule working as
        // designed against a node that had been sent backwards.
        //
        // ⛔ ENTER THE NEXT VIEW, NOT A FIXED ONE. This used to be
        // `enter_view(1)` unconditionally, which dragged a resumed validator
        // back to view 1 where its own safety rule then refused every proposal.
        // The first repair passed `cur_view.max(1)`, which was worse in a
        // quieter way: `enter_view` returns early when `view <= cur_view`, so a
        // node resumed INTO view 33 asked to enter 33, hit the guard, and
        // emitted NOTHING — no timer, no view, so the pacemaker never fired and
        // the set sat forever. Measured: `start()` returned an empty action
        // list on all four validators.
        //
        // `cur_view + 1` is a real transition in both paths. A fresh node has
        // `cur_view == 0` and still enters view 1; `resume` leaves `cur_view`
        // one below its target so this enters exactly that target.
        let next = self.cur_view.saturating_add(1);
        self.enter_view(next, None, &mut actions);
        actions
    }

    // -----------------------------------------------------------------
    // Event: proposal received (gossip)
    // -----------------------------------------------------------------

    pub fn on_proposal(&mut self, proposal: Proposal) -> Result<Vec<Action>, ConsensusError> {
        let mut actions = Vec::new();
        let header = &proposal.block.header;

        if header.chain_id != self.chain_id {
            return Err(ConsensusError::InvalidProposal("wrong chain id".into()));
        }

        // Authenticate the proposer before anything else.
        let proposer_key = self.committee.key(header.proposer)?;
        let header_hash = proposal.block.hash();
        if !proposal.sig.verify_with_dst(
            proposer_key,
            &proposal_message(self.chain_id, &header_hash),
            self.committee.dst_for_view(header.view),
        ) {
            return Err(ConsensusError::InvalidSignature(header.proposer));
        }
        if self.elector.leader(header.view) != header.proposer {
            return Err(ConsensusError::InvalidProposal(format!(
                "validator {} is not the leader of view {}",
                header.proposer, header.view
            )));
        }

        // Verify and absorb the justify QC (may advance our view), then
        // the TC if present.
        proposal
            .block
            .justify
            .verify(self.chain_id, &self.committee, &self.genesis_hash)?;
        self.process_qc(&proposal.block.justify, &mut actions);
        if let Some(tc) = &proposal.tc {
            tc.verify(self.chain_id, &self.committee, &self.genesis_hash)?;
            self.process_tc(tc.clone(), &mut actions);
        }

        // We only vote for proposals in our (possibly just-advanced) view.
        if header.view != self.cur_view {
            return Ok(actions); // stale or unreachable-future: no vote
        }

        // R2 — view continuity: happy path (justify from the immediately
        // preceding view) or a TC for the preceding view whose reported
        // high QC the justify matches-or-beats.
        let justify_view = proposal.block.justify.view;
        let continuity_ok = justify_view + 1 == header.view
            || matches!(&proposal.tc, Some(tc)
                if tc.view + 1 == header.view && justify_view >= tc.high_qc.view);
        if !continuity_ok {
            return Err(ConsensusError::InvalidProposal(format!(
                "view discontinuity: justify {} → proposal {} without a matching TC",
                justify_view, header.view
            )));
        }

        // Structural: parent linkage + height.
        if header.parent != proposal.block.justify.block_hash {
            return Err(ConsensusError::InvalidProposal(
                "header.parent != justify.block_hash".into(),
            ));
        }
        let Some(parent) = self.blocks.get(&header.parent) else {
            // Parent body unknown (QC known without block). Block sync is
            // the node layer's job (Stage 4+); without the parent we can
            // neither check height nor execute later — do not vote.
            return Ok(actions);
        };
        if header.height != parent.header.height + 1 {
            return Err(ConsensusError::InvalidProposal(format!(
                "height {} does not extend parent height {}",
                header.height, parent.header.height
            )));
        }

        self.blocks.insert(header_hash, proposal.block.clone());

        // Vote decision (R1 + R3 live in SafetyState).
        if self.safety.safe_to_vote(header.view, justify_view) {
            self.safety.record_vote(header.view);
            let vote = self.make_vote(header.view, header_hash);
            self.route_vote(vote, &mut actions)?;
        }

        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Event: vote received (point-to-point; we are leader of view+1)
    // -----------------------------------------------------------------

    pub fn on_vote(&mut self, vote: Vote) -> Result<Vec<Action>, ConsensusError> {
        let mut actions = Vec::new();
        if self.elector.leader(vote.view + 1) != self.my_index {
            return Ok(actions); // misdirected; not ours to aggregate
        }
        if let Some(qc) = self.votes.add_vote(self.chain_id, &self.committee, &vote)? {
            actions.push(Action::BroadcastQc(qc.clone()));
            self.process_qc(&qc, &mut actions);
        }
        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Event: gossiped QC received
    // -----------------------------------------------------------------

    pub fn on_qc(&mut self, qc: QuorumCert) -> Result<Vec<Action>, ConsensusError> {
        qc.verify(self.chain_id, &self.committee, &self.genesis_hash)?;
        let mut actions = Vec::new();
        self.process_qc(&qc, &mut actions);
        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Event: timeout vote received (gossip)
    // -----------------------------------------------------------------

    pub fn on_timeout_vote(&mut self, tv: TimeoutVote) -> Result<Vec<Action>, ConsensusError> {
        let mut actions = Vec::new();
        tv.high_qc
            .verify(self.chain_id, &self.committee, &self.genesis_hash)?;
        // The reported high QC may itself teach us about progress.
        self.process_qc(&tv.high_qc, &mut actions);
        if let Some(tc) = self
            .timeouts
            .add_timeout(self.chain_id, &self.committee, &tv)?
        {
            actions.push(Action::BroadcastTc(tc.clone()));
            self.process_tc(tc, &mut actions);
        }

        // ⛔ VIEW SYNCHRONISATION, AND WITHOUT IT A RESTARTED COMMITTEE NEVER
        // RECOVERS. A validator resumes into `max(last_voted_view,
        // high_qc.view) + 1`, which is derived from its OWN persisted state, so
        // validators stopped at slightly different moments come back in
        // different views. Timeout votes only aggregate within one view, so
        // each of them times out alone, no view ever reaches a quorum, and no
        // TC is ever built. Nothing above moves a node toward where the others
        // are.
        //
        // ⚠ MEASURED, NOT REASONED. `tests/resume_view_sync.rs` puts four
        // validators one view apart on a LOSSLESS ordered network with every
        // timer firing: without this they sit at [20, 21, 22, 23] forever and
        // commit nothing. The v2 devnet did exactly that in production on
        // 2026-09-02 — every validator resumed correctly, the height held, and
        // not one block followed.
        //
        // f+1 is the right threshold and a quorum is not: f+1 votes guarantee at
        // least one HONEST validator is in that view, which is what makes
        // following it safe. Waiting for a quorum is circular, because reaching
        // one is the very thing the scattered committee cannot do.
        //
        // ⚠ SAFETY IS UNAFFECTED. Entering a higher view cannot cause a double
        // vote: voting is gated by `safe_to_vote` against `last_voted_view`,
        // which only ever increases. This buys LIVENESS and spends nothing.
        if tv.view > self.cur_view && self.timeouts.votes_for(tv.view) > self.committee.max_faulty()
        {
            self.enter_view(tv.view, None, &mut actions);
        }

        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Event: gossiped TC received
    // -----------------------------------------------------------------

    pub fn on_tc(&mut self, tc: TimeoutCert) -> Result<Vec<Action>, ConsensusError> {
        tc.verify(self.chain_id, &self.committee, &self.genesis_hash)?;
        let mut actions = Vec::new();
        self.process_tc(tc, &mut actions);
        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Event: local view timer fired
    // -----------------------------------------------------------------

    pub fn on_local_timeout(&mut self, view: View) -> Result<Vec<Action>, ConsensusError> {
        let mut actions = Vec::new();
        if view != self.cur_view {
            return Ok(actions); // stale timer
        }
        self.pacemaker.on_local_timeout();

        let tv = TimeoutVote {
            view,
            voter: self.my_index,
            sig: self.secret.sign_with_dst(
                &timeout_message(self.chain_id, view),
                self.committee.dst_for_view(view),
            ),
            high_qc: self.safety.high_qc().clone(),
        };
        actions.push(Action::BroadcastTimeoutVote(tv.clone()));
        // Own-vote rule: our timeout vote must enter our own aggregator —
        // broadcast alone never advances local state (live-chain TC-wedge
        // lesson, commit 6921d4f).
        if let Some(tc) = self
            .timeouts
            .add_timeout(self.chain_id, &self.committee, &tv)?
        {
            actions.push(Action::BroadcastTc(tc.clone()));
            self.process_tc(tc, &mut actions);
        }
        // Re-arm for the same view with backoff so the timeout vote is
        // re-broadcast if the network stays quiet.
        actions.push(Action::ScheduleTimeout {
            view: self.cur_view,
            delay: self.pacemaker.current_timeout(),
        });
        Ok(actions)
    }

    // -----------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------

    fn make_vote(&self, view: View, block_hash: [u8; 32]) -> Vote {
        Vote {
            view,
            block_hash,
            voter: self.my_index,
            sig: self.secret.sign_with_dst(
                &vote_message(self.chain_id, view, &block_hash),
                self.committee.dst_for_view(view),
            ),
        }
    }

    /// Deliver a vote to the next view's leader — through our own
    /// aggregator when that leader is us (own-vote rule), point-to-point
    /// otherwise.
    fn route_vote(&mut self, vote: Vote, actions: &mut Vec<Action>) -> Result<(), ConsensusError> {
        let next_leader = self.elector.leader(vote.view + 1);
        if next_leader == self.my_index {
            if let Some(qc) = self.votes.add_vote(self.chain_id, &self.committee, &vote)? {
                actions.push(Action::BroadcastQc(qc.clone()));
                self.process_qc(&qc, actions);
            }
        } else {
            actions.push(Action::SendVote {
                to: next_leader,
                vote,
            });
        }
        Ok(())
    }

    /// Absorb a verified QC: commit-rule check, lock update, view advance.
    fn process_qc(&mut self, qc: &QuorumCert, actions: &mut Vec<Action>) {
        // 2-chain commit rule: QC(B', w) with B'.justify.view == w−1
        // finalizes B'.parent (and its ancestors).
        let commit_parent = self.blocks.get(&qc.block_hash).and_then(|child| {
            (child.justify.view + 1 == qc.view).then_some(child.justify.block_hash)
        });
        if let Some(parent_hash) = commit_parent {
            self.commit_chain(parent_hash, actions);
        }

        if self.safety.observe_qc(qc) {
            self.remember_lock(qc.block_hash);
        }

        if qc.view >= self.cur_view {
            self.pacemaker.on_qc_progress();
            self.enter_view(qc.view + 1, None, actions);
        }
    }

    /// Absorb a verified TC.
    fn process_tc(&mut self, tc: TimeoutCert, actions: &mut Vec<Action>) {
        let high_qc = tc.high_qc.clone();
        self.process_qc(&high_qc, actions);
        if tc.view >= self.cur_view {
            // No pacemaker reset on the timeout path — backoff keeps
            // growing until a QC lands.
            let view = tc.view + 1;
            self.enter_view(view, Some(tc), actions);
        }
    }

    /// Enter `view` (monotone). Arms the timer and proposes if leader.
    fn enter_view(&mut self, view: View, via_tc: Option<TimeoutCert>, actions: &mut Vec<Action>) {
        if view <= self.cur_view {
            return;
        }
        self.cur_view = view;
        self.entry_tc = via_tc;
        self.votes.gc(view.saturating_sub(1));
        self.timeouts.gc(view.saturating_sub(1));

        actions.push(Action::EnteredView(view));
        actions.push(Action::ScheduleTimeout {
            view,
            delay: self.pacemaker.current_timeout(),
        });

        if self.elector.leader(view) == self.my_index && self.proposed_up_to < view {
            self.propose_or_schedule(view, actions);
        }
    }

    /// Propose now, or ask the node layer to call us back when the minimum block
    /// interval has elapsed.
    ///
    /// ⚠ THE FIRST PROPOSAL AFTER BOOT IS NEVER DELAYED (`last_proposal_ms == 0`),
    /// so a restarting validator rejoins at full speed instead of sitting out an
    /// interval it has no reason to honour.
    fn propose_or_schedule(&mut self, view: View, actions: &mut Vec<Action>) {
        // ⛔ SUPPRESSION IS CHECKED BEFORE PACING, and the order matters: a node
        // with nothing to say should not schedule a timer to say it later.
        //
        // ⚠ THE FIRST PROPOSAL AFTER BOOT IS NEVER SUPPRESSED either. A restarted
        // committee has committed everything it holds, so NO node has work, and
        // suppressing there left the whole set silent until the heartbeat — a
        // restarted chain that looks DEAD for ten minutes. One block per restart
        // is the price, and it is the right one.
        if self.idle_heartbeat_ms > 0 && self.last_proposal_ms != 0 {
            let now = self.payloads.now_ms();
            if self.payloads.has_work() {
                self.last_work_ms = now;
            }
            // ⛔ A MOMENTARY ABSENCE OF WORK IS NOT AN IDLE CHAIN, AND CONFLATING
            // THE TWO IS WHY THE FIRST FOUR ATTEMPTS STALLED. Views turn over in
            // ~100ms; a batch has to be sealed (flush interval) and then acked by
            // a quorum before a certificate exists. So on a BUSY chain there are
            // constant sub-second gaps where `has_work()` is false — measured 17
            // of them in a 60s run with 2.000 transactions in flight — and
            // suppressing in a gap costs a full view TIMEOUT, which is far more
            // expensive than the empty block it avoided. The chain crawled at
            // ~0,5 views/s.
            //
            // So suppress only after work has been absent CONTINUOUSLY for longer
            // than it takes work to appear. `idle_grace_ms` is that bound.
            // ⛔ TIME SINCE WORK WAS LAST SEEN, NOT SINCE WE LAST PROPOSED. An
            // earlier version took `max(last_work_ms, last_proposal_ms)`, which
            // made suppression a NO-OP: every proposal reset the clock, so the
            // grace period could never be reached and the chain kept producing.
            // Measured by the idle test: 2914 empty blocks in 12 seconds with
            // suppression "enabled". Passing the restart gate proved only that it
            // did no harm; it took a test asserting the chain GOES QUIET to show
            // it did no work either.
            let quiet_for = now.saturating_sub(self.last_work_ms);
            let idle_for = now.saturating_sub(self.last_proposal_ms);
            if std::env::var("SOLIDUS_TRACE_SUPPRESS").is_ok() {
                eprintln!(
                    "SUPPRESS? node={} view={} quiet_for={} idle_for={}",
                    self.my_index, view, quiet_for, idle_for
                );
            }
            if quiet_for >= self.idle_grace_ms && idle_for < self.idle_heartbeat_ms {
                // Say nothing. The view will time out and leadership rotates,
                // which is how an idle chain stays quiet: the pacemaker backs
                // off exponentially, so idle traffic shrinks rather than grows.
                return;
            }
        }
        if std::env::var("SOLIDUS_TRACE_SUPPRESS").is_ok() {
            eprintln!("PROPOSE node={} view={}", self.my_index, view);
        }
        if self.min_block_interval_ms == 0 || self.last_proposal_ms == 0 {
            self.propose(actions);
            return;
        }
        let now = self.payloads.now_ms();
        let elapsed = now.saturating_sub(self.last_proposal_ms);
        if elapsed >= self.min_block_interval_ms {
            self.propose(actions);
        } else {
            actions.push(Action::SchedulePropose {
                view,
                delay: Duration::from_millis(self.min_block_interval_ms - elapsed),
            });
        }
    }

    /// The node layer's pacing timer fired for `view`.
    ///
    /// ⚠ EVERY PRECONDITION IS RE-CHECKED, because the delay is wall-clock time
    /// during which consensus keeps moving. By the time this fires the view may
    /// have advanced, leadership may have rotated on a timeout certificate, or a
    /// proposal may already have gone out. Proposing anyway would put a second
    /// block into a view we no longer lead, which is the equivocation case.
    /// Work arrived while we already hold this view. Propose if we lead it and
    /// have not yet.
    ///
    /// ⛔ WITHOUT THIS, SUPPRESSION ADDS A FULL VIEW OF LATENCY TO EVERY
    /// TRANSACTION THAT ARRIVES AFTER ITS LEADER ENTERED THE VIEW. `enter_view`
    /// is otherwise the only place a leader consults its pool, so a certificate
    /// landing one millisecond later waits for the next view that node leads.
    pub fn on_work_available(&mut self, actions: &mut Vec<Action>) {
        let view = self.cur_view;
        if view == 0 || self.elector.leader(view) != self.my_index || self.proposed_up_to >= view {
            return;
        }
        self.propose_or_schedule(view, actions);
    }

    pub fn on_propose_timer(&mut self, view: View, actions: &mut Vec<Action>) {
        if view != self.cur_view {
            return;
        }
        if self.elector.leader(view) != self.my_index {
            return;
        }
        if self.proposed_up_to >= view {
            return;
        }
        self.propose(actions);
    }

    /// Build, sign, gossip — and vote for — our own proposal.
    fn propose(&mut self, actions: &mut Vec<Action>) {
        let view = self.cur_view;
        let justify = self.safety.high_qc().clone();
        let Some(parent) = self.blocks.get(&justify.block_hash) else {
            // We hold a QC whose block body we never received. Without the
            // parent we cannot extend the chain; stay silent and let the
            // pacemaker rotate leadership. (Block sync: node layer.)
            return;
        };

        let parent_height = parent.header.height;
        let (exec_height, exec_state_root) = self.payloads.exec_anchor();
        let header = BlockHeader2 {
            chain_id: self.chain_id,
            height: parent_height + 1,
            view,
            parent: justify.block_hash,
            batch_certs: self.payloads.next_payload(),
            exec_height,
            exec_state_root,
            timestamp_ms: self.payloads.now_ms(),
            proposer: self.my_index,
        };
        let header_hash = header.hash();
        let block = Block2 { header, justify };
        self.blocks.insert(header_hash, block.clone());
        self.proposed_up_to = view;
        // Pacing is measured from when we PROPOSED, not from when the view opened,
        // so a slow round does not earn the next one a shorter gap.
        self.last_proposal_ms = self.payloads.now_ms();

        // Attach the TC when this view was entered via timeout AND it is
        // the immediately preceding view's TC (R2 continuity evidence).
        let tc = self.entry_tc.clone().filter(|tc| tc.view + 1 == view);

        let proposal = Proposal {
            sig: self.secret.sign_with_dst(
                &proposal_message(self.chain_id, &header_hash),
                self.committee.dst_for_view(view),
            ),
            block,
            tc,
        };
        actions.push(Action::BroadcastProposal(proposal));

        // Vote for our own proposal (a leader is also a replica) — through
        // the same safety gate as everyone else.
        if self.safety.safe_to_vote(view, self.safety.high_qc().view) {
            self.safety.record_vote(view);
            let vote = self.make_vote(view, header_hash);
            // route_vote only errs on our own malformed vote — impossible.
            let _ = self.route_vote(vote, actions);
        }
    }

    /// Finalize `tip` and every uncommitted ancestor, oldest-first.
    fn commit_chain(&mut self, tip: [u8; 32], actions: &mut Vec<Action>) {
        let Some(tip_block) = self.blocks.get(&tip) else {
            return; // body unknown; node-layer sync will replay commit
        };
        if tip_block.header.height <= self.last_committed_height {
            return; // already final (idempotent)
        }

        // Walk back to the last committed block.
        let mut chain = Vec::new();
        let mut cursor = tip;
        loop {
            let Some(block) = self.blocks.get(&cursor) else {
                return; // gap in bodies; commit will replay after sync
            };
            if block.header.height <= self.last_committed_height {
                debug_assert_eq!(
                    cursor, self.last_committed_hash,
                    "2-chain safety violation: committed fork"
                );
                break;
            }
            chain.push(cursor);
            cursor = block.header.parent;
        }

        for hash in chain.into_iter().rev() {
            #[allow(clippy::expect_used)]
            let block = self.blocks.get(&hash).expect("walked above");
            actions.push(Action::Commit(CommittedBlock {
                hash,
                height: block.header.height,
                view: block.header.view,
                timestamp_ms: block.header.timestamp_ms,
            }));
            self.last_committed_hash = hash;
            self.last_committed_height = block.header.height;
        }

        self.gc_blocks();
    }
}

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

use std::collections::HashMap;
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
    /// Telemetry: the core entered a view.
    EnteredView(View),
}

/// Supplies block payloads + proposer timestamps (kept outside the core so
/// tests stay deterministic — no wall-clock inside the state machine).
pub trait PayloadProvider {
    fn next_payload(&mut self) -> Vec<BatchCertificate>;
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
}

// ---------------------------------------------------------------------------
// The core
// ---------------------------------------------------------------------------

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
}

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
            pacemaker: config.pacemaker,
            genesis_hash,
            blocks,
            votes: VoteAggregator::new(),
            timeouts: TimeoutAggregator::new(),
            last_committed_hash: genesis_hash,
            last_committed_height: 0,
            entry_tc: None,
            proposed_up_to: 0,
        }
    }

    pub fn current_view(&self) -> View {
        self.cur_view
    }

    pub fn last_committed(&self) -> ([u8; 32], u64) {
        (self.last_committed_hash, self.last_committed_height)
    }

    pub fn genesis_hash(&self) -> [u8; 32] {
        self.genesis_hash
    }

    /// Fetch a stored block by hash (the node layer resolves committed
    /// blocks' batch certificates for execution).
    pub fn block(&self, hash: &[u8; 32]) -> Option<&Block2> {
        self.blocks.get(hash)
    }

    /// Boot the core into view 1.
    pub fn start(&mut self) -> Vec<Action> {
        let mut actions = Vec::new();
        self.enter_view(1, None, &mut actions);
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
        if !proposal
            .sig
            .verify(proposer_key, &proposal_message(self.chain_id, &header_hash))
        {
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
            sig: self.secret.sign(&timeout_message(self.chain_id, view)),
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
            sig: self
                .secret
                .sign(&vote_message(self.chain_id, view, &block_hash)),
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

        self.safety.observe_qc(qc);

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
            self.propose(actions);
        }
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

        // Attach the TC when this view was entered via timeout AND it is
        // the immediately preceding view's TC (R2 continuity evidence).
        let tc = self.entry_tc.clone().filter(|tc| tc.view + 1 == view);

        let proposal = Proposal {
            sig: self
                .secret
                .sign(&proposal_message(self.chain_id, &header_hash)),
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
    }
}

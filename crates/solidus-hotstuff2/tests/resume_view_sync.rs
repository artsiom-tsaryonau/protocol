//! Can a committee that RESUMES INTO DIFFERENT VIEWS find its way back
//! together?
//!
//! ⛔ THIS IS THE DEVNET FAILURE, REDUCED TO A DETERMINISTIC QUESTION. On
//! 2026-09-02 the v2 devnet restarted, every validator resumed correctly (height
//! held at 811, zero refusals), and the chain never produced another block. The
//! same restart passes through in-process channels and wedges over libp2p, so
//! the difference is timing, and timing decides ONE thing on resume: which view
//! each validator comes back into.
//!
//! `resume_view` is `max(last_voted_view, high_qc.view) + 1`, and
//! `last_voted_view` is per-validator. Nodes stopped at the same instant resume
//! together; nodes stopped mid-round resume scattered. Under channels the stop
//! is uniform, and over a real network it is not.
//!
//! ⚠ TIMEOUT VOTES ONLY AGGREGATE WITHIN ONE VIEW. `on_timeout_vote` builds a TC
//! from a quorum of votes for the SAME view, and nothing in the core moves a
//! node's view because OTHER nodes are voting somewhere higher. So if the answer
//! below is "no", a scattered committee has no path back together and the chain
//! is wedged until an operator intervenes.
//!
//! This test asserts the property either way. If the core gains view
//! synchronisation it stays green; if the property is absent it says exactly
//! what is missing, deterministically, in under a second.

use std::collections::VecDeque;

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{
    Action, Committee, ConsensusCore, CoreConfig, EmptyPayloads, Pacemaker, QuorumCert,
    ResumeState, RoundRobin,
};

const CHAIN_ID: u64 = 9;
const N: usize = 4;

/// One frame in flight between cores.
// A proposal carries a whole block and the other variants are certificates, so
// the variants differ in size by design. Boxing to even them out would buy
// nothing in a test harness that holds a few hundred of them at a time.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum Msg {
    Proposal(solidus_hotstuff2::Proposal),
    Vote(solidus_hotstuff2::Vote),
    Qc(QuorumCert),
    Tc(solidus_hotstuff2::TimeoutCert),
    TimeoutVote(solidus_hotstuff2::TimeoutVote),
}

struct Sim {
    cores: Vec<ConsensusCore<RoundRobin, EmptyPayloads>>,
    /// Raw secrets and the shared QC, so a test can mint a signed frame that
    /// the cores would not emit on their own. Nothing production needs this, so
    /// nothing production gains an API for it.
    secret_bytes: Vec<[u8; 32]>,
    high_qc: QuorumCert,
    queue: VecDeque<(usize, Msg)>,
    commits: Vec<usize>,
    /// Views each node has a live timer for, fired when the queue drains.
    pending_timeout: Vec<Option<u64>>,
    /// Every QC the run produced, by view, so a later fixture can hand
    /// different validators genuinely different certificates.
    seen_qcs: Vec<QuorumCert>,
    /// Every block proposed, so a resumed validator can be given the block its
    /// certificate justifies. Without it `propose` returns silently and the
    /// committee looks wedged for a reason belonging to the fixture.
    seen_blocks: Vec<solidus_hotstuff2::Block2>,
}

impl Sim {
    /// Route one core's actions, exactly as a transport would.
    fn absorb(&mut self, from: usize, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::BroadcastProposal(p) => {
                    self.seen_blocks.push(p.block.clone());
                    self.broadcast(from, Msg::Proposal(p))
                }
                Action::BroadcastQc(qc) => {
                    self.seen_qcs.push(qc.clone());
                    self.broadcast(from, Msg::Qc(qc))
                }
                Action::BroadcastTc(tc) => self.broadcast(from, Msg::Tc(tc)),
                Action::BroadcastTimeoutVote(tv) => self.broadcast(from, Msg::TimeoutVote(tv)),
                Action::SendVote { to, vote } => {
                    self.queue.push_back((to as usize, Msg::Vote(vote)));
                }
                Action::Commit(_) => self.commits[from] += 1,
                Action::ScheduleTimeout { view, .. } => self.pending_timeout[from] = Some(view),
                // These harnesses construct the core with `min_block_interval_ms: 0`, so
                // pacing is off and this cannot be emitted. Panicking rather than
                // ignoring it: if someone enables pacing here later, a silently
                // swallowed proposal would look like a liveness bug in consensus
                // instead of a harness that never drives the pacing timer.
                Action::SchedulePropose { .. } => {
                    unreachable!("pacing is disabled in this harness (min_block_interval_ms: 0)")
                }
                Action::EnteredView(_) => {}
            }
        }
    }

    fn broadcast(&mut self, from: usize, msg: Msg) {
        for i in 0..N {
            if i != from {
                self.queue.push_back((i, msg.clone()));
            }
        }
    }

    /// Deliver everything queued, then fire every live timer. Repeat `rounds`
    /// times. Delivery is lossless and ordered, which is the FRIENDLIEST
    /// possible network: if the committee cannot converge here, no transport
    /// will save it.
    fn run(&mut self, rounds: usize) {
        // ⚠ BOUNDED PER ROUND, OR THE SIMULATOR HANGS. Lossless delivery means
        // every frame a core emits fans out to three peers, each of which can
        // emit more, so draining "until empty" is not guaranteed to terminate.
        // The first version of this loop ran past a 600s timeout on a test that
        // takes 0.18s when bounded.
        const PER_ROUND: usize = 600;
        for _ in 0..rounds {
            let mut budget = PER_ROUND;
            while let Some((to, msg)) = self.queue.pop_front() {
                if budget == 0 {
                    break;
                }
                budget -= 1;
                let out = match msg {
                    Msg::Proposal(p) => self.cores[to].on_proposal(p),
                    Msg::Vote(v) => self.cores[to].on_vote(v),
                    Msg::Qc(qc) => self.cores[to].on_qc(qc),
                    Msg::Tc(tc) => self.cores[to].on_tc(tc),
                    Msg::TimeoutVote(tv) => self.cores[to].on_timeout_vote(tv),
                };
                // A rejected frame is normal (stale view, duplicate); the core
                // reports it and the network moves on.
                if let Ok(actions) = out {
                    self.absorb(to, actions);
                }
            }
            for i in 0..N {
                if let Some(view) = self.pending_timeout[i].take() {
                    if let Ok(actions) = self.cores[i].on_local_timeout(view) {
                        self.absorb(i, actions);
                    }
                }
            }
        }
    }

    fn views(&self) -> Vec<u64> {
        self.cores.iter().map(|c| c.current_view()).collect()
    }
}

fn build(last_voted: &[u64]) -> Sim {
    let secrets: Vec<BlsSecretKey> = (0..N).map(|_| BlsSecretKey::generate()).collect();
    let secret_bytes: Vec<[u8; 32]> = secrets.iter().map(|k| k.to_bytes()).collect();
    let committee = Committee::new(secrets.iter().map(|k| k.public_key()).collect());
    // ⛔ THE QC MUST CERTIFY THE BLOCK THE CORE ACTUALLY KNOWS. A QC over an
    // invented hash makes `propose` return silently, because it cannot find the
    // justified block, and the whole committee then looks wedged for a reason
    // that belongs to the fixture. The control test exists to catch exactly
    // this, and it did.
    let genesis_hash = {
        let probe = ConsensusCore::new(
            CoreConfig {
                chain_id: CHAIN_ID,
                my_index: 0,
                secret: BlsSecretKey::from_bytes(&secrets[0].to_bytes()).expect("secret"),
                committee: committee.clone(),
                pacemaker: Pacemaker::default(),
                // Pacing off in tests: these assert on block PRODUCTION,
                // and a wall-clock gate would make them time-dependent.
                min_block_interval_ms: 0,
                idle_heartbeat_ms: 0,
                idle_grace_ms: 0,
            },
            RoundRobin::new(N),
            EmptyPayloads { ts_ms: 1 },
        );
        probe.genesis_hash()
    };
    // Every validator shares the same high QC, which is the realistic case: they
    // all stopped agreeing on the same chain. Only `last_voted_view` differs,
    // which is what a non-uniform stop produces.
    let high_qc = QuorumCert::genesis(genesis_hash, secrets[0].sign(b"genesis"));

    let mut cores = Vec::new();
    for (index, secret) in secrets.into_iter().enumerate() {
        let mut core = ConsensusCore::new(
            CoreConfig {
                chain_id: CHAIN_ID,
                my_index: index as u32,
                secret,
                committee: committee.clone(),
                pacemaker: Pacemaker::default(),
                // Pacing off in tests: these assert on block PRODUCTION,
                // and a wall-clock gate would make them time-dependent.
                min_block_interval_ms: 0,
                idle_heartbeat_ms: 0,
                idle_grace_ms: 0,
            },
            RoundRobin::new(N),
            EmptyPayloads { ts_ms: 1 },
        );
        core.resume(ResumeState {
            // ⚠ THE ARGUMENT IS `last_voted_view`, WHICH IS THE ONLY THING THAT
            // DIFFERS BETWEEN VALIDATORS ON A REAL BOX. They share the chain, so
            // they share `high_qc`; they stop at slightly different moments, so
            // they persist different last-voted views.
            last_voted_view: last_voted[index],
            high_qc: high_qc.clone(),
            last_committed_hash: genesis_hash,
            last_committed_height: 0,
            blocks: Vec::new(),
        });
        cores.push(core);
    }

    let mut sim = Sim {
        cores,
        secret_bytes: secret_bytes.clone(),
        high_qc: high_qc.clone(),
        queue: VecDeque::new(),
        commits: vec![0; N],
        pending_timeout: vec![None; N],
        seen_qcs: Vec::new(),
        seen_blocks: Vec::new(),
    };
    for i in 0..N {
        let boot = sim.cores[i].start();
        sim.absorb(i, boot);
    }
    sim
}

/// Resume a committee where validator `i` holds the QC at `qc_offsets[i]`
/// positions back from the newest one the chain produced.
///
/// ⛔ THIS IS THE SCATTER THAT SURVIVES. `high_qc` is persisted at vote time, so
/// a validator stopped a moment earlier holds an OLDER certificate and, since
/// `resume` now derives the view from it, comes back a view lower. Varying
/// `last_voted_view` can no longer produce any spread at all.
fn resume_from_different_qcs(qc_offsets: &[usize]) -> Sim {
    // A chain that actually ran, so the certificates are real and verify
    // against this committee.
    let mut first = build(&[0, 0, 0, 0]);
    first.run(30);
    assert!(
        first.seen_qcs.len() > 6,
        "the fixture needs a chain with several certificates to hand out; got {}",
        first.seen_qcs.len()
    );

    // Newest first, so offset 0 is the freshest certificate.
    let mut qcs = first.seen_qcs.clone();
    qcs.sort_by_key(|qc| std::cmp::Reverse(qc.view));
    qcs.dedup_by_key(|qc| qc.view);

    let committee = Committee::new(
        first
            .secret_bytes
            .iter()
            .map(|b| BlsSecretKey::from_bytes(b).expect("secret").public_key())
            .collect(),
    );

    let mut cores = Vec::new();
    for (index, offset) in qc_offsets.iter().enumerate() {
        let secret = BlsSecretKey::from_bytes(&first.secret_bytes[index]).expect("secret");
        let mut core = ConsensusCore::new(
            CoreConfig {
                chain_id: CHAIN_ID,
                my_index: index as u32,
                secret,
                committee: committee.clone(),
                pacemaker: Pacemaker::default(),
                // Pacing off in tests: these assert on block PRODUCTION,
                // and a wall-clock gate would make them time-dependent.
                min_block_interval_ms: 0,
                idle_heartbeat_ms: 0,
                idle_grace_ms: 0,
            },
            RoundRobin::new(N),
            EmptyPayloads { ts_ms: 1 },
        );
        let high_qc = qcs[*offset].clone();
        core.resume(ResumeState {
            // ⛔ MEASURED, NOT ASSUMED: every validator on a failing devnet run
            // reported `last_voted` exactly ONE ABOVE its `high_qc` view. That
            // is the normal shape - a validator votes in view V, and the QC for
            // V is what it holds when it stops - and it means a resumed
            // validator comes back into precisely the view it last voted in,
            // where `safe_to_vote` forbids it from voting. The earlier fixture
            // set these equal, which quietly removed the constraint under test
            // and made the model disagree with production while looking
            // authoritative.
            last_voted_view: high_qc.view.saturating_add(1),
            high_qc: high_qc.clone(),
            last_committed_hash: core.genesis_hash(),
            last_committed_height: 0,
            // Every block the chain produced. A real validator reloads a window
            // of them from its store, and without them `propose` cannot find
            // the block its own justify names.
            blocks: first.seen_blocks.clone(),
        });
        cores.push(core);
    }

    let mut sim = Sim {
        cores,
        secret_bytes: first.secret_bytes.clone(),
        high_qc: qcs[0].clone(),
        queue: VecDeque::new(),
        commits: vec![0; N],
        pending_timeout: vec![None; N],
        seen_qcs: Vec::new(),
        seen_blocks: Vec::new(),
    };
    for i in 0..N {
        let boot = sim.cores[i].start();
        sim.absorb(i, boot);
    }
    sim
}

/// The shape the libp2p reproduction PASSED on: three validators on the older
/// certificate, one ahead.
#[test]
fn three_on_the_older_certificate_and_one_ahead_recovers() {
    let mut sim = resume_from_different_qcs(&[1, 1, 1, 0]);
    sim.run(30);
    assert!(
        sim.commits.iter().sum::<usize>() > 0,
        "three validators sharing a certificate are a quorum and must make \
         progress. views {:?}",
        sim.views()
    );
}

/// ⛔ The shape the libp2p reproduction FAILED on: ONE validator on the older
/// certificate, three ahead.
///
/// ⚠ IN THE libp2p BATCH THIS SHAPE CORRELATED WITH FAILURE AND THE OTHER WITH
/// SUCCESS — but free disk correlated just as well, and that test runs on
/// wall-clock deadlines. This one has no clock and no disk, so whatever it says
/// is about the consensus shape alone.
#[test]
fn one_on_the_older_certificate_and_three_ahead_recovers() {
    let mut sim = resume_from_different_qcs(&[1, 0, 0, 0]);
    sim.run(30);
    assert!(
        sim.commits.iter().sum::<usize>() > 0,
        "three validators sharing the NEWER certificate are also a quorum, so \
         this must recover too. If it does not, the view shape is the real \
         cause of the libp2p failures and disk was a coincidence. views {:?}",
        sim.views()
    );
}

/// Control: a committee whose validators all stopped at the same instant makes
/// progress. Without this, a failure in the scattered case could just mean the
/// simulator cannot drive consensus at all — which is exactly what it caught
/// the first time this file was written.
#[test]
fn a_committee_that_resumes_into_the_same_view_makes_progress() {
    let mut sim = build(&[1, 1, 1, 1]);
    sim.run(20);
    assert!(
        sim.commits.iter().sum::<usize>() > 0,
        "the simulator cannot drive consensus even when every validator resumes \
         into the same view, so it cannot answer the scattered question either. \
         views: {:?}",
        sim.views()
    );
}

/// The f+1 rule in `on_timeout_vote`, exercised on its own.
///
/// ⚠ IT DID NOT FIX THE SCATTERED CASE AND IS NOT DEAD CODE. With four
/// validators in four DISTINCT views, no view ever collects two votes, so the
/// rule cannot fire — that case is fixed by resuming from the shared
/// certificate instead. This rule covers the other shape: a validator that has
/// fallen behind while the rest of the committee moved on together. Without a
/// test it would be exactly the kind of unproven consensus code this repo warns
/// about, so here it is proven directly.
#[test]
fn a_validator_follows_f_plus_one_peers_into_a_higher_view() {
    let mut sim = build(&[1, 1, 1, 1]);
    // Everyone starts together; node 0 is the one we drag forward.
    let start_view = sim.cores[0].current_view();
    let target = start_view + 7;

    // Two peers (f+1 for n=4) time out in a view well ahead of node 0. The votes
    // are minted here rather than driven out of those cores, because getting a
    // core to time out in a distant view means simulating the very view change
    // this test is about.
    let votes: Vec<solidus_hotstuff2::TimeoutVote> = [1usize, 2usize]
        .iter()
        .map(|&peer| {
            let secret = BlsSecretKey::from_bytes(&sim.secret_bytes[peer]).expect("secret");
            solidus_hotstuff2::TimeoutVote {
                view: target,
                voter: peer as u32,
                sig: secret.sign(&solidus_hotstuff2::timeout_message(CHAIN_ID, target)),
                high_qc: sim.high_qc.clone(),
            }
        })
        .collect();

    for tv in votes {
        let _ = sim.cores[0].on_timeout_vote(tv);
    }

    assert_eq!(
        sim.cores[0].current_view(),
        target,
        "a validator that sees f+1 peers timing out in a higher view must \
         follow them there. f+1 guarantees at least one of them is honest, \
         which is what makes following safe; waiting for a quorum is circular, \
         because forming one is what the lagging validator is blocking"
    );
}

/// ⛔ THE QUESTION. Four validators stopped one view apart, which is what any
/// non-uniform stop produces on a real box, and is the ONLY difference between
/// a restart over in-process channels and a restart over a network.
#[test]
fn a_committee_that_resumes_scattered_finds_its_way_back_together() {
    let mut sim = build(&[1, 2, 3, 4]);
    sim.run(20);

    let views = sim.views();
    let spread =
        views.iter().max().copied().unwrap_or(0) - views.iter().min().copied().unwrap_or(0);
    assert!(
        sim.commits.iter().sum::<usize>() > 0,
        "⛔ WEDGED. Four validators resumed one view apart and never committed \
         anything, over a LOSSLESS ordered network with every timer firing. \
         Final views {views:?}, spread {spread}. Timeout votes aggregate only \
         within a single view, so each node times out alone and no quorum ever \
         forms for any one view. This is the devnet failure: height held, zero \
         refusals, and not one block afterwards. The missing rule is view \
         synchronisation — a node that sees f+1 timeout votes for a HIGHER view \
         must move to it."
    );
}

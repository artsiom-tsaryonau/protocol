//! Local integrated network: N validator [`Node`]s over tokio loopback
//! channels, streaming REAL transfer transactions through the whole v2
//! stack — worker → batch certificates → HotStuff-2 → two-lane executor →
//! store2 — and measuring end-to-end throughput, finality, and cross-node
//! state agreement.
//!
//! Honest scope note (R-TOPOLOGY): loopback delivery is µs and this box is
//! one machine. The numbers below are what a single-box local network
//! achieves — protocol + execution + storage overhead — NOT a
//! network-realistic 50K-TPS / sub-1s-finality reading. The 21-node
//! 3-region 72h geo-soak that produces those numbers needs multi-region
//! hardware and is the Stage-7 founder follow-up. What this harness proves
//! is *integration correctness* (the pieces compose, execute committed
//! blocks deterministically, agree on state) plus a local throughput floor.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType, StateKey, WireMode};
use solidus_hotstuff2::{Action, Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeInput, NodeOutput, NodeTuning, SyncCounters};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Transaction, TxPayload};
use tokio::sync::mpsc;

/// Serialises the heavy localnet tests against each other.
///
/// ⛔ THEY CANNOT SHARE A MACHINE. Each one boots four to seven validators, each
/// with its own RocksDB and its own tokio runtime, and asserts against wall-clock
/// deadlines. Run in parallel by cargo's default harness they starve one another:
/// measured 2026-09-03, two of four failed together and every one of them passed
/// alone and passed again with `--test-threads=1`. A suite that only passes when
/// invoked a particular way is a suite people learn to re-run rather than trust,
/// so the serialisation lives HERE rather than in a flag someone has to remember.
///
/// Poisoning is ignored on purpose: one test panicking must not cascade into
/// failures in the others, which would hide the real one.
/// ⚠ A TOKIO MUTEX, NOT A STD ONE. These tests are async and hold the guard for
/// their whole body, which a `std` guard cannot do across an await point — clippy
/// rejects it, and it would be a genuine deadlock risk rather than a lint.
static HEAVY: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn heavy() -> tokio::sync::MutexGuard<'static, ()> {
    HEAVY.lock().await
}

const CHAIN_ID: u64 = 2;
const NETWORK: &str = "v2-localnet";

fn transfer(key: &SigningKey, to: Address, amount: u64, nonce: u64) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
    tx.signature = sign(key, &msg);
    tx
}

/// Per-block executed record: (height, state root, tx count, wall instant).
type ExecRecord = (u64, [u8; 32], usize, Instant);

/// Shared, optional record of consensus actions, keyed by node index.
type ActionLog = Arc<Mutex<Vec<(usize, String)>>>;

#[derive(Clone)]
struct Metrics {
    /// node index → its executed blocks.
    executed: Arc<Mutex<Vec<Vec<ExecRecord>>>>,
    /// Every consensus action each node emits, for restart diagnostics.
    ///
    /// ⚠ OFF UNLESS EXPLICITLY ENABLED. Recording takes a mutex on every
    /// consensus action, which is contention on the hot path — with it always
    /// on, the 40k-transaction throughput test missed its target. An
    /// observation tool must not change what it observes.
    actions: Option<ActionLog>,
    /// node index → what it has broadcast, by kind.
    ///
    /// ⛔ THE SHARPEST TEST OF A RESTART. Height convergence proves a validator
    /// FOLLOWS the chain; only this proves it LEADS one. A node that resumes,
    /// executes everything and never proposes again looks perfectly healthy on
    /// every height measurement while the committee quietly loses a leader.
    /// One lock per proposal, so roughly one per block: not the hot path the
    /// action log sits on.
    counts: Arc<Mutex<Vec<ActionCounts>>>,
    /// node index → its latest sampled sync state. Written on each worker flush
    /// (every 25ms), read by the `LOCALNET_SAMPLE` sampler.
    snapshots: Arc<Mutex<Vec<NodeSnapshot>>>,
    /// node index → cumulative per-input-kind cost, published on each flush.
    ///
    /// ⚠ ACCUMULATED IN THE TASK, PUBLISHED ON FLUSH. A lock per message is
    /// contention on the path being measured.
    costs: Arc<Mutex<Vec<InputCosts>>>,
}

/// One validator's sync state at a moment, for telling a node that is behind
/// and closing from one that is frozen.
///
/// ⚠ `inbox` IS THE MEASUREMENT THE 2026-09-13 TRACES LACKED. The frozen node
/// there was processing QCs for view ~370 while the committee was at ~630, which
/// reads as a backlog of old messages rather than missing history.
/// Input kinds, in the index order `input_kind` returns.
const INPUT_KINDS: [&str; 16] = [
    "BodyReq",
    "Body",
    "RangeReq",
    "Range",
    "SubmitTx",
    "Proposal",
    "Vote",
    "TimeoutVote",
    "Tc",
    "Qc",
    "Batch",
    "Ack",
    "Cert",
    "Timer",
    "ProposeTimer",
    "Flush",
];

/// Per input kind: (messages, nanoseconds in `Node::step`, nanoseconds routing its outputs).
type InputCosts = [(u64, u64, u64); 16];

fn input_kind(input: &NodeInput) -> usize {
    match input {
        NodeInput::BlockBodyRequest { .. } => 0,
        NodeInput::BlockBody(_) => 1,
        NodeInput::BlockRangeRequest { .. } => 2,
        NodeInput::BlockRange { .. } => 3,
        NodeInput::SubmitTx(_) => 4,
        NodeInput::Proposal(_) => 5,
        NodeInput::Vote(_) => 6,
        NodeInput::TimeoutVote(_) => 7,
        NodeInput::Tc(_) => 8,
        NodeInput::Qc(_) => 9,
        NodeInput::Batch { .. } => 10,
        NodeInput::Ack(_) => 11,
        NodeInput::Cert(_) => 12,
        NodeInput::ConsensusTimer(_) => 13,
        NodeInput::ProposeTimer(_) => 14,
        NodeInput::Flush => 15,
    }
}

#[derive(Clone, Copy, Default, Debug)]
struct NodeSnapshot {
    view: u64,
    committed: u64,
    inbox: usize,
    sync: SyncCounters,
}

/// What a validator emitted, by kind.
///
/// ⛔ QCs VERSUS TCs IS THE DIAGNOSIS, NOT A STATISTIC. A view that ends in a
/// quorum certificate is a view that COMMITTED something; a view that ends in a
/// timeout certificate is a view that gave up. The 2-chain rule needs two
/// consecutive certified views, so a committee whose views all end in timeouts
/// spins forever, proposing constantly and committing nothing - which looks
/// identical to a healthy busy chain on any height-only measurement.
#[derive(Clone, Copy, Default, Debug)]
struct ActionCounts {
    proposals: usize,
    qcs: usize,
    tcs: usize,
    timeout_votes: usize,
}

/// Everything a running validator needs to rebuild ITSELF from its own data
/// directory, without the test harness taking it apart first.
#[derive(Clone)]
struct RebuildSpec {
    dir: std::path::PathBuf,
    secret_bytes: [u8; 32],
    committee: Committee,
    pubkeys: Vec<solidus_crypto::bls::BlsPublicKey>,
    n: usize,
}

/// Out-of-band instruction to a running validator.
enum Control {
    /// Die and come back from disk, exactly as `systemctl restart` does, while
    /// the rest of the committee keeps producing.
    ///
    /// ⚠ RESTART IN PLACE RATHER THAN ABORT-AND-RESPAWN, and the reason is the
    /// channel, not the node. Aborting a task drops the receiver its peers send
    /// to, so a respawned validator would need a NEW address that four already
    /// running peers have no way to learn. Keeping the mailbox and replacing
    /// only the `Node` behind it models a process restart on a fixed port.
    Restart {
        /// How far the REST of the committee must advance before this validator
        /// is allowed back.
        ///
        /// ⚠ MEASURED IN BLOCKS, NOT SECONDS, and that is what makes the test an
        /// assertion instead of a sleep. A wall-clock down window says nothing
        /// about whether the chain kept moving; requiring the others to commit
        /// N more blocks before the restart completes means a stalled chain
        /// cannot silently pass as a fast one.
        down_blocks: u64,
        done: tokio::sync::oneshot::Sender<()>,
    },
}

struct NodeTask {
    index: usize,
    /// `Option` so a restart can DROP the node before reopening its store.
    /// RocksDB holds an exclusive lock on the directory, so building the
    /// replacement first would block on a lock the old node still owns, and the
    /// test would read that as a recovery bug rather than a harness mistake.
    node: Option<Node>,
    rx: mpsc::UnboundedReceiver<NodeInput>,
    control: mpsc::UnboundedReceiver<Control>,
    peers: Vec<mpsc::UnboundedSender<NodeInput>>,
    metrics: Metrics,
    rebuild: RebuildSpec,
    /// This task's running per-input-kind cost. See `Metrics::costs`.
    cost: InputCosts,
}

impl NodeTask {
    fn route(&mut self, outputs: Vec<NodeOutput>) {
        for out in outputs {
            match out {
                NodeOutput::Consensus(action) => self.route_consensus(action),
                NodeOutput::BroadcastBatch(batch) => {
                    for (i, peer) in self.peers.iter().enumerate() {
                        if i != self.index {
                            let _ = peer.send(NodeInput::Batch {
                                batch: batch.clone(),
                                from: self.index as u32,
                            });
                        }
                    }
                }
                // ⛔ THE HARNESS MUST DELIVER CERTIFICATES OR SUPPRESSION CANNOT
                // BE TESTED. Certificates used to stay on the node that formed
                // them, which is precisely the defect suppression tripped over:
                // a leader saw only its own share of the work.
                NodeOutput::BroadcastCert(cert) => {
                    for (i, peer) in self.peers.iter().enumerate() {
                        if i != self.index {
                            let _ = peer.send(NodeInput::Cert(cert.clone()));
                        }
                    }
                }
                NodeOutput::SendAck { to, ack } => {
                    let _ = self.peers[to as usize].send(NodeInput::Ack(ack));
                }
                NodeOutput::BlockExecuted {
                    height,
                    tx_count,
                    state_root,
                } => {
                    self.metrics.executed.lock().expect("lock")[self.index].push((
                        height,
                        state_root,
                        tx_count,
                        Instant::now(),
                    ));
                }
                // ⛔ THE RANGE PROTOCOL. This used to be dropped on the floor,
                // with a comment saying catching up was the transport's job —
                // which meant the ROLLING RESTART case, one validator stopped
                // while its peers keep producing, had no test anywhere. It is
                // the mainnet case. Serving now lives on `Node`, so this
                // harness and the libp2p runner ask the same code the same
                // question.
                NodeOutput::NeedBlocks { from, to } => {
                    let me = self.index as u32;
                    self.broadcast(|| NodeInput::BlockRangeRequest {
                        from,
                        to,
                        requester: me,
                    });
                }
                NodeOutput::SendBlockRange {
                    to,
                    blocks,
                    batches,
                } => {
                    let _ = self.peers[to as usize].send(NodeInput::BlockRange { blocks, batches });
                }

                // ⛔ THE BODY-FETCH PROTOCOL, routed the same way the libp2p
                // runner will route it. Without this a restarted node holding a
                // QC it cannot resolve stays silent forever: `propose` and
                // `on_proposal` both return early on a missing lock body.
                NodeOutput::NeedBlockBody { hash } => {
                    let me = self.index as u32;
                    self.broadcast(|| NodeInput::BlockBodyRequest { hash, from: me });
                }
                NodeOutput::SendBlockBody { to, bytes } => {
                    let _ = self.peers[to as usize].send(NodeInput::BlockBody(bytes));
                }
            }
        }
    }

    fn count(&self, f: impl FnOnce(&mut ActionCounts)) {
        f(&mut self.metrics.counts.lock().expect("lock")[self.index]);
    }

    fn route_consensus(&mut self, action: solidus_hotstuff2::Action) {
        use solidus_hotstuff2::Action;
        if let Some(actions) = &self.metrics.actions {
            // Restart diagnostics: what each node actually emits. Bounded so a
            // wedged run cannot exhaust memory while it is being observed.
            let mut log = actions.lock().expect("actions");
            if log.len() < 400 {
                let label = match &action {
                    Action::BroadcastProposal(p) => {
                        format!("Proposal(v{})", p.block.header.view)
                    }
                    Action::SendVote { vote, .. } => format!("Vote(v{})", vote.view),
                    Action::BroadcastQc(q) => format!("Qc(v{})", q.view),
                    Action::BroadcastTc(t) => format!("Tc(v{})", t.view),
                    Action::BroadcastTimeoutVote(t) => format!("TimeoutVote(v{})", t.view),
                    Action::EnteredView(v) => format!("EnteredView({v})"),
                    Action::ScheduleTimeout { view, .. } => format!("Timer({view})"),
                    Action::SchedulePropose { view, .. } => format!("ProposeTimer({view})"),
                    Action::Commit(c) => format!("Commit(h{})", c.height),
                };
                log.push((self.index, label));
            }
        }
        match action {
            Action::BroadcastProposal(p) => {
                self.count(|c| c.proposals += 1);
                self.broadcast(|| NodeInput::Proposal(p.clone()))
            }
            Action::BroadcastQc(qc) => {
                self.count(|c| c.qcs += 1);
                self.broadcast(|| NodeInput::Qc(qc.clone()))
            }
            Action::BroadcastTc(tc) => {
                self.count(|c| c.tcs += 1);
                self.broadcast(|| NodeInput::Tc(tc.clone()))
            }
            Action::BroadcastTimeoutVote(tv) => {
                self.count(|c| c.timeout_votes += 1);
                self.broadcast(|| NodeInput::TimeoutVote(tv.clone()))
            }
            Action::SendVote { to, vote } => {
                let _ = self.peers[to as usize].send(NodeInput::Vote(vote));
            }
            Action::ScheduleTimeout { view, delay } => {
                let tx = self.peers[self.index].clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(NodeInput::ConsensusTimer(view));
                });
            }
            // This harness drives real tokio timers, so pacing is genuinely exercised
            // here rather than stubbed: a paced localnet behaves as the node does.
            Action::SchedulePropose { view, delay } => {
                let tx = self.peers[self.index].clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let _ = tx.send(NodeInput::ProposeTimer(view));
                });
            }
            Action::Commit(_) | Action::EnteredView(_) => {}
        }
    }

    fn broadcast(&self, mut make: impl FnMut() -> NodeInput) {
        for (i, peer) in self.peers.iter().enumerate() {
            if i != self.index {
                let _ = peer.send(make());
            }
        }
    }

    /// Record this validator's sync state for the sampler. One lock per flush.
    fn snapshot(&mut self) {
        let inbox = self.rx.len();
        let Some(node) = self.node.as_ref() else {
            return;
        };
        let snap = NodeSnapshot {
            view: node.current_view(),
            committed: node.committed_height(),
            inbox,
            sync: node.sync_counters(),
        };
        self.metrics.snapshots.lock().expect("lock")[self.index] = snap;
        self.metrics.costs.lock().expect("lock")[self.index] = self.cost;
    }

    fn node(&mut self) -> &mut Node {
        self.node
            .as_mut()
            .expect("a node is present between restarts")
    }

    /// Highest height any validator other than this one has executed.
    fn others_height(&self) -> u64 {
        let ex = self.metrics.executed.lock().expect("lock");
        ex.iter()
            .enumerate()
            .filter(|(i, _)| *i != self.index)
            .filter_map(|(_, rows)| rows.last().map(|(h, _, _, _)| *h))
            .max()
            .unwrap_or(0)
    }

    /// Stop this validator, stay down until the rest of the committee has moved
    /// on, then bring it back from its own data directory.
    async fn restart_in_place(&mut self, down_blocks: u64) {
        // ⛔ DROP FIRST, THEN REOPEN. See the `node` field.
        self.node = None;

        // Stay down. Nothing is served, nothing is voted, and the inbox fills
        // with messages this validator will never see - which is the situation
        // a real restart leaves behind.
        let target = self.others_height().saturating_add(down_blocks);
        let deadline = Instant::now() + Duration::from_secs(60);
        while self.others_height() < target && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // ⛔ EVERYTHING QUEUED WHILE WE WERE DOWN IS GONE, AND THAT IS THE
        // POINT. Delivering the backlog on restart would test a validator that
        // never actually missed anything, which is the easy case and not the
        // one that wedged the devnet. A real node comes back having lost every
        // proposal, vote and batch sent while it was off.
        while self.rx.try_recv().is_ok() {}

        let store = Store2::open(&self.rebuild.dir, Profile::Testnet).expect("reopen store");
        let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(self.rebuild.n));
        let node = Node::new(
            self.index as u32,
            CHAIN_ID,
            BlsSecretKey::from_bytes(&self.rebuild.secret_bytes).expect("secret"),
            self.rebuild.committee.clone(),
            self.rebuild.pubkeys.clone(),
            Pacemaker::default(),
            elector,
            store,
            NodeTuning {
                max_certs_per_block: 64,
                batch_max_bytes: 512 * 1024,
                batch_max_txs: 400,
                flush_interval_ms: 25,
                min_block_interval_ms: 0,
                // Suppression ON, with v1's 600s heartbeat: this gate exists to catch
                // exactly the stalls the three previous attempts produced.
                idle_heartbeat_ms: 600_000,
                idle_grace_ms: 2_000,
                view_timeout_ms: 0,
                block_retention: 0,
            },
            NETWORK.to_string(),
        )
        .expect("a restarted validator boots");
        self.node = Some(node);
        let boot = self.node().start();
        self.route(boot);
    }

    async fn run(mut self) {
        let boot = self.node().start();
        self.route(boot);
        // Periodic worker flush so partial batches seal under light load.
        let flush_tx = self.peers[self.index].clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(25)).await;
                if flush_tx.send(NodeInput::Flush).is_err() {
                    break;
                }
            }
        });
        loop {
            tokio::select! {
                // Biased so a pending restart is not starved by a busy inbox:
                // under load the node channel always has something ready, and
                // a fair select could defer the restart indefinitely.
                biased;
                Some(Control::Restart { down_blocks, done }) = self.control.recv() => {
                    self.restart_in_place(down_blocks).await;
                    let _ = done.send(());
                }
                maybe = self.rx.recv() => {
                    let Some(input) = maybe else { break };
                    let flush = matches!(input, NodeInput::Flush);
                    let kind = input_kind(&input);
                    let t0 = Instant::now();
                    let out = self.node().step(input);
                    let t1 = Instant::now();
                    self.route(out);
                    let t2 = Instant::now();
                    let c = &mut self.cost[kind];
                    c.0 += 1;
                    c.1 += (t1 - t0).as_nanos() as u64;
                    c.2 += (t2 - t1).as_nanos() as u64;
                    if flush {
                        self.snapshot();
                    }
                }
            }
        }
    }
}

struct LocalNet {
    submit: Vec<mpsc::UnboundedSender<NodeInput>>,
    metrics: Metrics,
    funded: Vec<SigningKey>,
    /// Each node's data directory, so a restart test can reopen one.
    dirs: Vec<std::path::PathBuf>,
    /// Owns those directories, purely so they are DELETED when the test ends.
    ///
    /// ⛔ THIS EXISTS BECAUSE THE HARNESS USED TO LEAK THEM AND IT TOOK THE
    /// MACHINE TO ZERO FREE DISK. `TempDir::keep` was called to stop the
    /// directory vanishing while a node still needed to reopen it, which fixed
    /// the reopen and made every run leave one RocksDB store per validator
    /// behind forever. Measured 2026-09-02: 703 stores, 4.1 GB, and at zero
    /// free disk every shell command fails BEFORE it runs, so the session
    /// cannot clean up after itself. Holding the handle keeps the directory
    /// alive exactly as long as some `LocalNet` needs it, and no longer.
    ///
    /// `Arc` because a restart shares the same directories with a second
    /// `LocalNet`: whichever outlives the other does the deleting.
    _tempdirs: Vec<Arc<tempfile::TempDir>>,
    /// Task handles, so a node can be STOPPED. Aborting drops the future and
    /// with it the `Node`, which releases RocksDB's lock on the directory —
    /// without that a reopen fails and the test would look like a recovery bug.
    handles: Vec<tokio::task::JoinHandle<()>>,
    /// The committee's keys, so a reopened node can be built identically.
    bls_pubkeys: Vec<solidus_crypto::bls::BlsPublicKey>,
    /// Raw secret bytes, because `BlsSecretKey` is not `Clone` and moves into
    /// the `Node`. Without these a restarted validator cannot sign as itself.
    bls_secret_bytes: Vec<[u8; 32]>,
    /// Restart ONE validator without disturbing the others.
    control: Vec<mpsc::UnboundedSender<Control>>,
}

impl LocalNet {
    /// Take validator `index` down until the rest of the committee has
    /// committed `down_blocks` more, then bring it back and wait until it is
    /// serving again.
    async fn restart_one(&self, index: usize, down_blocks: u64) {
        let (done, wait) = tokio::sync::oneshot::channel();
        self.control[index]
            .send(Control::Restart { down_blocks, done })
            .expect("the validator is still running");
        wait.await.expect("the validator restarted");
    }

    /// Highest height any validator OTHER than `index` has executed.
    ///
    /// ⚠ EXCLUDING THE ONE UNDER TEST IS THE WHOLE MEASUREMENT. "The chain kept
    /// producing" is a claim about the rest of the committee; reading the
    /// restarted node's own height instead would answer a different question.
    fn height_excluding(&self, index: usize) -> u64 {
        let ex = self.metrics.executed.lock().expect("lock");
        ex.iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .filter_map(|(_, rows)| rows.last().map(|(h, _, _, _)| *h))
            .max()
            .unwrap_or(0)
    }

    fn height_of(&self, index: usize) -> u64 {
        let ex = self.metrics.executed.lock().expect("lock");
        ex[index].last().map(|(h, _, _, _)| *h).unwrap_or(0)
    }

    fn counts(&self) -> Vec<ActionCounts> {
        self.metrics.counts.lock().expect("lock").clone()
    }

    fn proposals(&self) -> Vec<usize> {
        self.counts().iter().map(|c| c.proposals).collect()
    }

    /// Every validator's inbox depth at its last flush, in index order.
    ///
    /// ⛔ THIS IS WHAT SEPARATES A SATURATED COMMITTEE FROM AN IDLE ONE, and
    /// both look the same on heights and counts. Timers, votes and proposals
    /// share one FIFO with the mempool traffic, so a validator thousands of
    /// messages behind handles its view timer seconds late: few timeouts, few
    /// proposals, flat heights. Measured 2026-09-22 under CPU pressure: ~2.000
    /// queued per node while Cert/Ack/Batch steps filled each 2s window.
    /// A stopped validator's entry is stale: it last flushed before it went down.
    fn inboxes(&self) -> Vec<usize> {
        self.metrics
            .snapshots
            .lock()
            .expect("lock")
            .iter()
            .map(|s| s.inbox)
            .collect()
    }

    /// Every validator's latest executed height, in index order.
    fn heights(&self) -> Vec<u64> {
        let ex = self.metrics.executed.lock().expect("lock");
        ex.iter()
            .map(|rows| rows.last().map(|(h, _, _, _)| *h).unwrap_or(0))
            .collect()
    }
}

fn spawn_localnet(n: usize, n_accounts: usize) -> LocalNet {
    let bls_secrets: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let bls_pubkeys: Vec<_> = bls_secrets.iter().map(|k| k.public_key()).collect();
    let bls_secret_bytes: Vec<[u8; 32]> = bls_secrets.iter().map(|k| k.to_bytes()).collect();
    let committee = Committee::new(bls_pubkeys.clone());

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        receivers.push(rx);
    }

    // Genesis accounts (funded), identical on every node.
    let funded: Vec<SigningKey> = (0..n_accounts).map(|_| generate_signing_key()).collect();

    let metrics = Metrics {
        executed: Arc::new(Mutex::new(vec![Vec::new(); n])),
        actions: None,
        counts: Arc::new(Mutex::new(vec![ActionCounts::default(); n])),
        snapshots: Arc::new(Mutex::new(vec![NodeSnapshot::default(); n])),
        costs: Arc::new(Mutex::new(vec![[(0, 0, 0); 16]; n])),
    };
    let mut dirs: Vec<std::path::PathBuf> = Vec::new();
    let mut handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut controls: Vec<mpsc::UnboundedSender<Control>> = Vec::new();
    let mut tempdirs: Vec<Arc<tempfile::TempDir>> = Vec::new();

    for (index, (secret, rx)) in bls_secrets.into_iter().zip(receivers).enumerate() {
        let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
        let path = dir.path().to_path_buf();
        let dir_path = path.clone();
        tempdirs.push(Arc::clone(&dir));
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));

        let mut node = Node::new(
            index as u32,
            CHAIN_ID,
            secret,
            committee.clone(),
            bls_pubkeys.clone(),
            Pacemaker::default(),
            elector,
            store,
            NodeTuning {
                max_certs_per_block: 64,
                batch_max_bytes: 512 * 1024,
                batch_max_txs: 400,
                flush_interval_ms: 25,
                min_block_interval_ms: 0,
                // Suppression ON, with v1's 600s heartbeat: this gate exists to catch
                // exactly the stalls the three previous attempts produced.
                idle_heartbeat_ms: 600_000,
                idle_grace_ms: 2_000,
                view_timeout_ms: 0,
                block_retention: 0, // pruning off: these tests assert on history
            },
            NETWORK.to_string(),
        )
        .expect("node boots");
        for key in &funded {
            let addr = Address::from_public_key(&key.verifying_key());
            let acct = Account::with_balance(addr, 1_000_000_000, AccountType::Regular);
            node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        }

        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let task = NodeTask {
            index,
            node: Some(node),
            rx,
            control: ctl_rx,
            peers: senders.clone(),
            metrics: metrics.clone(),
            cost: [(0, 0, 0); 16],
            rebuild: RebuildSpec {
                dir: dir_path.clone(),
                secret_bytes: bls_secret_bytes[index],
                committee: committee.clone(),
                pubkeys: bls_pubkeys.clone(),
                n,
            },
        };
        handles.push(tokio::spawn(task.run()));
        controls.push(ctl_tx);
        dirs.push(dir_path);
    }

    LocalNet {
        submit: senders,
        metrics,
        funded,
        dirs,
        handles,
        bls_pubkeys,
        bls_secret_bytes,
        control: controls,
        _tempdirs: tempdirs,
    }
}

fn executed_tx_totals(metrics: &Metrics, n: usize) -> Vec<usize> {
    let ex = metrics.executed.lock().expect("lock");
    (0..n)
        .map(|i| ex[i].iter().map(|(_, _, c, _)| *c).sum())
        .collect()
}

/// Does an RPC transaction flood against ONE validator push that validator's own
/// view timers behind? Filed 2026-09-22 as INFERENCE FROM SOURCE, unmeasured.
///
/// ⛔ WHY THE QUESTION IS SHARP. `solidus-p2p2/src/runner.rs` gives each node ONE
/// unbounded `self_tx` channel. RPC `SubmitTx` arrives on it
/// (`solidus-noded/src/run.rs:265`) and so does `NodeInput::ConsensusTimer`, and
/// `solidus-mempool-dag`'s `on_submit_tx` has no admission limit. Gossip arrives on
/// the swarm branch of the same unbiased `select!`, so it is NOT behind this queue.
/// Only the node's own timers are. `solidus_submitTransaction` is reachable
/// unauthenticated on rpc.solidus.network, so the attacker needs no credential.
///
/// ⚠ THE CONTROL IS THE OTHER THREE VALIDATORS IN THE SAME RUN, not a second run.
/// CPU pressure moves every number here, so a baseline taken at a different moment
/// proves nothing. Flooding one node and reading all four under identical load is
/// the only comparison that isolates the queue from the machine.
///
/// ⚠ REPORTS, IT DOES NOT ASSERT A THRESHOLD, and that is deliberate. Two localnet
/// tests already fail on CI's runner and pass on this Mac; a third timing-sensitive
/// assertion would add flake rather than knowledge. `#[ignore]` keeps it on demand:
///     cargo test -p solidus-node2 --test localnet -- --ignored --nocapture flood
#[ignore = "measurement, not a gate: run on demand with --nocapture"]
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_rpc_flood_against_one_validator_delays_its_own_view_timers() {
    let _serialised = heavy().await;
    let n = 4;
    let net = spawn_localnet(n, 400);
    let victim = 0usize;

    // Let real consensus establish itself before the flood, so what follows is a
    // perturbation of a running committee rather than a cold start.
    tokio::time::sleep(Duration::from_secs(6)).await;
    let before_counts = net.counts();
    let before_heights = net.heights();
    println!(
        "  settled: heights {before_heights:?} inbox {:?}",
        net.inboxes()
    );

    // Flood ONE node as fast as the channel accepts, with no pacing at all. This is
    // the shape of the attack: an unauthenticated client posting faster than the
    // node seals. Every other node stays untouched.
    let submit = net.submit.clone();
    let funded = net.funded.clone();
    let flood = tokio::spawn(async move {
        for i in 0..200_000u64 {
            let payer = &funded[(i as usize) % funded.len()];
            let nonce = i / funded.len() as u64;
            let mut to = [0u8; 20];
            to[..8].copy_from_slice(&i.to_le_bytes());
            to[19] = 0xFD;
            let tx = transfer(payer, Address::from_bytes(to), 1, nonce);
            if submit[victim].send(NodeInput::SubmitTx(tx)).is_err() {
                break;
            }
            // Yield occasionally so this task cannot starve the runtime itself,
            // which would measure the harness rather than the node.
            if i % 2_000 == 1_999 {
                tokio::task::yield_now().await;
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(20)).await;
    let after_counts = net.counts();
    let after_heights = net.heights();
    let inbox = net.inboxes();
    flood.abort();

    let d_timeouts: Vec<usize> = (0..n)
        .map(|i| after_counts[i].timeout_votes - before_counts[i].timeout_votes)
        .collect();
    let d_proposals: Vec<usize> = (0..n)
        .map(|i| after_counts[i].proposals - before_counts[i].proposals)
        .collect();
    let d_heights: Vec<u64> = (0..n)
        .map(|i| after_heights[i] - before_heights[i])
        .collect();

    println!("\n  === RPC flood against validator {victim}, 20s window, n={n} ===");
    println!("  inbox depth      {inbox:?}");
    println!("  timeout votes +  {d_timeouts:?}");
    println!("  proposals     +  {d_proposals:?}");
    println!("  heights       +  {d_heights:?}");
    println!(
        "  victim inbox {} vs peer max {}",
        inbox[victim],
        inbox
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != victim)
            .map(|(_, v)| *v)
            .max()
            .unwrap_or(0),
    );
    println!(
        "  READ IT LIKE THIS: a victim inbox far above its peers with DEPRESSED timeout\n\
         votes and proposals is the queued-timer signature (canon:\n\
         timeout-votes-below-the-re-arm-rate-mean-the-timers-were-queued). A victim\n\
         inbox no larger than its peers means the node seals faster than one client\n\
         can post, and the filed inference does not hold at this offered load.",
    );

    // The only assertion: the committee must still be producing. If a single
    // client's flood can stop the CHAIN, that is a finding regardless of timers.
    let progressed = (0..n).filter(|i| d_heights[*i] > 0).count();
    assert!(
        progressed >= 3,
        "flood stopped the committee: only {progressed} of {n} validators advanced, \
         heights +{d_heights:?}, inbox {inbox:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn integrated_localnet_executes_and_agrees() {
    let _serialised = heavy().await;
    let n = 4;
    let net = spawn_localnet(n, 400);

    // Stream real transfers continuously (paced) so proposals keep packing
    // certificate-backed blocks rather than draining one burst. Each funded
    // account pays a fresh address; round-robin across nodes so every
    // worker batches.
    let n_txs = 40_000u64;
    let submit = net.submit.clone();
    let funded = net.funded.clone();
    let feeder = tokio::spawn(async move {
        for i in 0..n_txs {
            let payer = &funded[(i as usize) % funded.len()];
            let nonce = i / funded.len() as u64;
            let mut to = [0u8; 20];
            to[..8].copy_from_slice(&i.to_le_bytes());
            to[19] = 0xEE;
            let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
            let target = (i as usize) % n;
            let _ = submit[target].send(NodeInput::SubmitTx(tx));
            // Small pacing every 500 txs keeps the pipeline fed without
            // dumping everything before the first block.
            if i % 500 == 499 {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        }
    });

    // Wait until every node has EXECUTED ≥ target transactions (inclusion
    // count — includes nonce-order failures, which are real committed
    // outcomes). The target is deliberately well below the 40k submitted:
    // this test proves integration correctness + cross-node root agreement,
    // NOT throughput, and it must stay green even when a full parallel
    // `cargo test` sweep starves it of CPU (the isolated run does far more).
    // Generous deadline for the same reason.
    //
    // ⚠ THE NUMBERS ARE ENVIRONMENT-DEPENDENT, and "generous" was calibrated on developer
    // hardware. On GitHub's 2-core runner, 2026-09-02, the four nodes reached
    // [1052, 474, 1052, 1052] in the full 120s: the slowest managed 474, so 8_000 is roughly
    // sixteen times out of reach there, not marginally. Since this test's own claim is
    // correctness and cross-node root agreement rather than throughput, the fix is to ask for
    // a number that is still plenty of blocks to agree over, not to keep a target the
    // environment cannot meet.
    //
    // 500 in 300s against a measured worst case of 474 in 120s is about a 2.4x margin. That
    // margin comes from ONE observation, so if this flakes, widen the deadline before lowering
    // the target: fewer transactions weakens the agreement claim, more time does not.
    let shared_runner = std::env::var_os("CI").is_some();
    let (target_txs, deadline) = if shared_runner {
        (500usize, Duration::from_secs(300))
    } else {
        (8_000usize, Duration::from_secs(120))
    };
    println!(
        "localnet target: {target_txs} txs within {deadline:?} ({})",
        if shared_runner {
            "CI is set, shared runner"
        } else {
            "dedicated hardware"
        }
    );
    let start = Instant::now();
    loop {
        let totals = executed_tx_totals(&net.metrics, n);
        if totals.iter().all(|&t| t >= target_txs) {
            break;
        }
        assert!(
            start.elapsed() < deadline,
            "localnet did not execute {target_txs} txs on every node: {totals:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    feeder.abort();

    let ex = net.metrics.executed.lock().expect("lock").clone();

    // Cross-node agreement: at every height any two nodes both executed,
    // the executed state root must be identical.
    let mut roots_by_height: HashMap<u64, [u8; 32]> = HashMap::new();
    for (node, chain) in ex.iter().enumerate() {
        for (height, root, _tx_count, _) in chain {
            match roots_by_height.get(height) {
                Some(prev) => assert_eq!(
                    prev, root,
                    "state-root divergence at height {height} on node {node}"
                ),
                None => {
                    roots_by_height.insert(*height, *root);
                }
            }
        }
    }

    // Throughput: total txs executed on node 0 over the executing window
    // (first→last non-empty block wall time), the honest denominator.
    let node0 = &ex[0];
    let nonempty: Vec<_> = node0.iter().filter(|(_, _, c, _)| *c > 0).collect();
    let total_txs: usize = nonempty.iter().map(|(_, _, c, _)| *c).sum();
    let window = nonempty
        .last()
        .zip(nonempty.first())
        .map(|((_, _, _, last), (_, _, _, first))| last.duration_since(*first))
        .unwrap_or_default()
        .as_secs_f64()
        .max(1e-3);
    let tps = total_txs as f64 / window;
    let common = (0..n).map(|i| ex[i].len()).min().unwrap_or(0);

    println!(
        "localnet: {n} nodes, {common} common committed blocks, {} distinct heights agreed, \
         {total_txs} txs executed on node 0 over a {window:.2}s executing window → ~{tps:.0} tx/s \
         (single-box loopback: integration floor + protocol/exec/storage overhead, \
         NOT a network 50K-TPS / sub-1s reading — that is the Stage-7 geo-soak)",
        roots_by_height.len()
    );
    assert!(total_txs >= target_txs, "must execute the target tx volume");
    assert!(common >= 5, "sustained multi-block production expected");
}

/// ⛔ THE MAINNET SCENARIO, AT THE SCALE THIS HARNESS CAN REACH. Every other
/// restart-recovery test uses blocks a test wrote by hand. This one uses blocks
/// produced by REAL CONSENSUS — four nodes, real transactions, real batch
/// certificates — then stops a validator and reopens it.
///
/// It is the case that actually broke: on 2026-08-02 the devnet's validators
/// restarted and every one came back at height 0.
///
/// ⚠ WHAT IT DOES NOT COVER, stated so nobody reads more into a green tick:
/// the restarted node does not REJOIN here. Rejoining needs the libp2p
/// request/response path in `solidus-p2p2`, which this channel-based harness
/// does not use, and a true rolling restart with the chain still producing
/// needs the multi-process soak the Stage-7 plan calls hardware-gated.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_validator_stopped_after_real_consensus_reopens_at_its_committed_height() {
    let _serialised = heavy().await;
    let n = 4;
    let net = spawn_localnet(n, 20);

    let submit = net.submit.clone();
    let funded = net.funded.clone();
    for i in 0..2_000u64 {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = submit[(i as usize) % n].send(NodeInput::SubmitTx(tx));
        if i % 250 == 249 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    // Wait for node 0 to actually commit. A height of 0 would make the
    // assertion below vacuous.
    let deadline = Duration::from_secs(60);
    let start = Instant::now();
    let committed_height = loop {
        let h = {
            let ex = net.metrics.executed.lock().expect("lock");
            ex[0].last().map(|(height, _, _, _)| *height).unwrap_or(0)
        };
        if h > 0 {
            break h;
        }
        assert!(
            start.elapsed() < deadline,
            "node 0 committed nothing in {deadline:?}; the restart assertion would prove nothing against an empty chain"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Stop node 0. Aborting drops the task, the Node, and RocksDB's lock —
    // without that the reopen fails and looks like a recovery bug.
    net.handles[0].abort();

    // ⚠ WAIT FOR THE LOCK, DO NOT GUESS HOW LONG IT TAKES. This used to sleep a fixed 300 ms, and on
    // 2026-09-29 the pre-push run (turbo and cargo sharing the machine) reopened before the aborted
    // task had dropped RocksDB's LOCK: "lock hold by current process ... No locks available". That
    // reads as a recovery bug and is only a scheduler delay, so retry until the lock is free.
    let store = open_store_waiting(&net.dirs[0], "node 0's store").await;
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));
    let reopened = Node::new(
        0,
        CHAIN_ID,
        BlsSecretKey::generate(),
        Committee::new(net.bls_pubkeys.clone()),
        net.bls_pubkeys.clone(),
        Pacemaker::default(),
        elector,
        store,
        NodeTuning {
            max_certs_per_block: 64,
            batch_max_bytes: 512 * 1024,
            batch_max_txs: 400,
            flush_interval_ms: 25,
            min_block_interval_ms: 0,
            // Suppression ON, with v1's 600s heartbeat: this gate exists to catch
            // exactly the stalls the three previous attempts produced.
            idle_heartbeat_ms: 600_000,
            idle_grace_ms: 2_000,
            view_timeout_ms: 0,
            block_retention: 0,
        },
        NETWORK.to_string(),
    )
    .expect("node boots");

    let (recovered, root) = *reopened.exec_anchor().lock().expect("anchor");
    assert!(
        recovered > 0,
        "a reopened validator must not come back at height 0 — that is the defect that halted the devnet for a month"
    );
    // ⚠ `>=`, NOT `==`, AND THE DIFFERENCE IS A REAL RACE RATHER THAN SLOPPINESS.
    // `committed_height` is read from the metrics snapshot, and the node keeps
    // committing until `abort()` lands, so the STORE can legitimately be a block
    // or two ahead of the last metric recorded. An `==` here passed for a while
    // and then failed with left 8 right 7, which is the assertion being wrong,
    // not the code. What must hold is that recovery never goes BACKWARDS.
    assert!(
        recovered >= committed_height,
        "a reopened validator must not come back BELOW the height it committed: \
         recovered {recovered}, metrics last saw {committed_height}"
    );
    assert_ne!(
        root, [0u8; 32],
        "with the state it had, not an empty forest — a real height paired with a zero root looks recovered while agreeing with nobody"
    );
}

/// Rebuild the whole validator set from its existing data directories, exactly
/// as `systemctl restart` does on the box.
///
/// ⚠ DELIBERATELY DOES NOT RE-SEED GENESIS. `solidus-noded` seeds genesis only
/// when `canon_head()` is None, so re-seeding here would test something the
/// daemon does not do - and would overwrite live balances, which is the defect
/// that conditional exists to prevent.
fn respawn_localnet(net: &LocalNet, n: usize) -> LocalNet {
    let bls_secrets: Vec<BlsSecretKey> = net
        .bls_secret_bytes
        .iter()
        .map(|b| BlsSecretKey::from_bytes(b).expect("secret"))
        .collect();
    let committee = Committee::new(net.bls_pubkeys.clone());

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        receivers.push(rx);
    }
    // ⚠ Enabled ONLY on the respawned net: this is where the restart behaviour
    // is under investigation, and the original run must stay unobserved so its
    // throughput is not affected by the observation.
    let metrics = Metrics {
        executed: Arc::new(Mutex::new(vec![Vec::new(); n])),
        actions: Some(Arc::new(Mutex::new(Vec::new()))),
        counts: Arc::new(Mutex::new(vec![ActionCounts::default(); n])),
        snapshots: Arc::new(Mutex::new(vec![NodeSnapshot::default(); n])),
        costs: Arc::new(Mutex::new(vec![[(0, 0, 0); 16]; n])),
    };
    let mut handles = Vec::new();
    let mut controls: Vec<mpsc::UnboundedSender<Control>> = Vec::new();

    for (index, (secret, rx)) in bls_secrets.into_iter().zip(receivers).enumerate() {
        // ⚠ THE SAME LOCK RACE AS THE SINGLE-NODE RESTART ABOVE, at the whole-set restart: on
        // 2026-10-01 the pre-push run failed here with "lock hold by current process".
        let store = open_store_waiting_blocking(&net.dirs[index], "a restarted node's store");
        let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));
        let node = Node::new(
            index as u32,
            CHAIN_ID,
            secret,
            committee.clone(),
            net.bls_pubkeys.clone(),
            Pacemaker::default(),
            elector,
            store,
            NodeTuning {
                max_certs_per_block: 64,
                batch_max_bytes: 512 * 1024,
                batch_max_txs: 400,
                flush_interval_ms: 25,
                min_block_interval_ms: 0,
                // Suppression ON, with v1's 600s heartbeat: this gate exists to catch
                // exactly the stalls the three previous attempts produced.
                idle_heartbeat_ms: 600_000,
                idle_grace_ms: 2_000,
                view_timeout_ms: 0,
                block_retention: 0,
            },
            NETWORK.to_string(),
        )
        .expect("node boots");

        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let task = NodeTask {
            index,
            node: Some(node),
            rx,
            control: ctl_rx,
            peers: senders.clone(),
            metrics: metrics.clone(),
            cost: [(0, 0, 0); 16],
            rebuild: RebuildSpec {
                dir: net.dirs[index].clone(),
                secret_bytes: net.bls_secret_bytes[index],
                committee: committee.clone(),
                pubkeys: net.bls_pubkeys.clone(),
                n,
            },
        };
        handles.push(tokio::spawn(task.run()));
        controls.push(ctl_tx);
    }

    LocalNet {
        submit: senders,
        metrics,
        funded: net.funded.clone(),
        dirs: net.dirs.clone(),
        handles,
        bls_pubkeys: net.bls_pubkeys.clone(),
        bls_secret_bytes: net.bls_secret_bytes.clone(),
        control: controls,
        _tempdirs: net._tempdirs.clone(),
    }
}

/// ⛔ THE ROLLING RESTART. THE OTHER ACCEPTANCE CRITERION, AND THE MAINNET CASE.
///
/// `the_whole_validator_set_restarts_without_losing_the_chain` stops everything
/// at once, which is an outage. The upgrade case is the opposite: take ONE
/// validator down while the rest keep committing, bring it back, let it catch
/// up, and move to the next. Nothing tested that until now, and the plan
/// recorded it as hardware-gated because the in-process harness had no
/// request/response path. It has one now - the body pair and the range pair
/// both route here - so the gate was the harness, not the hardware.
///
/// Three things are asserted per validator, and each one fails differently:
///
/// 1. **The chain kept producing while it was down.** The down window is
///    defined as "the others commit N more blocks", so a stalled committee
///    cannot pass: the restart never completes and the test times out.
/// 2. **It came back where it left off.** Its first height after the restart
///    must exceed its last height before, which is what separates a resume from
///    a reset. "Its height is high now" is satisfied by a node that started at
///    genesis and climbed, which is exactly what the devnet did in August.
/// 3. **It caught up to the committee.** A validator that resumes but never
///    closes the gap is a validator that contributes nothing.
///
/// ⚠ SEVEN VALIDATORS, NOT FOUR, AND THAT IS NOT ARBITRARY. Quorum is 3 of 4
/// and 5 of 7. With four, taking one down leaves exactly quorum and ZERO fault
/// tolerance, so any scheduling hiccup stalls the chain and the test reports a
/// liveness bug that is really an artefact of the committee size. Seven leaves
/// one spare.
///
/// ⭐ GREEN SINCE 2026-09-03, AND IT COST FOUR DEFECTS TO GET HERE. Two runs of
/// the full seven-validator sweep, ~5 minutes each, every validator rejoining a
/// chain that never stopped committing. It is slow and it stays in the default
/// suite anyway: this is the mainnet upgrade case, and an acceptance test nobody
/// runs is worth nothing.
///
/// The four, each with its own regression test where it lives:
/// `sync::RangeAnchor` (chunked backfill cannot anchor every chunk's tip),
/// `Node::unlinked_tip` (every height-based test for lag is ambiguous; presence
/// is not), `ConsensusCore::note_synced_commit` (a synced node that never tells
/// its core what backfill decided can never rejoin), and
/// `Node::execute_missing_ancestors` (refusing to execute across a gap is only
/// half the job — the gap has to be closed, and usually it can be closed from
/// blocks this node already holds).
/// How long a node more than 3 behind may go without a new lowest gap.
/// Measured, see the settle comment in the rolling-restart test.
const SETTLE_STALL_MS: u64 = 30_000;

/// The rolling-restart settle rule, kept pure so it is tested on real series.
///
/// A node more than 3 behind must reach a NEW LOWEST gap at least every
/// `stall_ms`. Being within 3 clears its history.
struct GapTrend {
    stall_ms: u64,
    /// Per node: the lowest gap seen while more than 3 behind, and when (ms).
    lowest: Vec<Option<(u64, u64)>>,
}

impl GapTrend {
    fn new(n: usize, stall_ms: u64) -> Self {
        Self {
            stall_ms,
            lowest: vec![None; n],
        }
    }

    /// `Err((best, for_ms))` when node `i` has not been closer than `best` for
    /// at least `stall_ms`.
    fn observe(&mut self, i: usize, gap: u64, now_ms: u64) -> Result<(), (u64, u64)> {
        if gap <= 3 {
            self.lowest[i] = None;
            return Ok(());
        }
        match self.lowest[i] {
            Some((best, since)) if gap >= best => {
                let for_ms = now_ms.saturating_sub(since);
                if for_ms >= self.stall_ms {
                    Err((best, for_ms))
                } else {
                    Ok(())
                }
            }
            _ => {
                self.lowest[i] = Some((gap, now_ms));
                Ok(())
            }
        }
    }
}

/// The settle rule, run on real gap series. It must fail the frozen node and
/// pass the recovering one, or the gate proves nothing either way.
#[test]
fn the_settle_trend_fails_a_frozen_node_and_passes_a_recovering_one() {
    fn first_stall(series: &[(u64, u64)]) -> Option<u64> {
        let mut trend = GapTrend::new(1, SETTLE_STALL_MS);
        series
            .iter()
            .find(|(t, gap)| trend.observe(0, *gap, t * 1000).is_err())
            .map(|(t, _)| *t)
    }

    // node2 in the 2026-09-15 run 1, before the fixes: it froze at 213 while
    // the committee climbed. Samples every 2s, (seconds, gap).
    let frozen = [
        (262, 1),
        (264, 3),
        (266, 5),
        (268, 2),
        (270, 3),
        (272, 3),
        (274, 1),
        (276, 1),
        (278, 3),
        (280, 5),
        (282, 5),
        (284, 7),
        (286, 9),
        (288, 9),
        (290, 9),
        (292, 12),
        (294, 13),
        (296, 13),
        (298, 16),
        (300, 17),
        (302, 17),
        (304, 20),
        (306, 21),
        (308, 21),
        (310, 23),
        (312, 25),
        (314, 25),
        (316, 27),
        (318, 29),
        (320, 29),
    ];
    assert_eq!(
        first_stall(&frozen),
        Some(310),
        "the frozen node must fail 30s after it last got closer (t=280), not later and not never"
    );

    // The 2026-09-13 recovering shape: 16 behind and closing, unevenly.
    let recovering = [
        (0, 16),
        (2, 17),
        (4, 15),
        (6, 16),
        (8, 14),
        (10, 15),
        (12, 12),
        (14, 13),
        (16, 10),
        (18, 11),
        (20, 8),
        (22, 6),
        (24, 7),
        (26, 4),
        (28, 3),
    ];
    assert_eq!(
        first_stall(&recovering),
        None,
        "a node that keeps closing must pass"
    );

    // CONTROL at the boundary: no new low for 28s, then one. Must pass.
    let slow_but_closing = [(0, 10), (10, 12), (20, 11), (28, 10), (29, 9), (40, 3)];
    assert_eq!(
        first_stall(&slow_but_closing),
        None,
        "28s without a new low is inside the rule and must not fail"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_rolling_restart_of_every_validator_leaves_the_chain_producing() {
    let _serialised = heavy().await;
    const N: usize = 7;
    const DOWN_BLOCKS: u64 = 3;

    let net = spawn_localnet(N, 20);

    // Opt-in time series: `LOCALNET_SAMPLE=1 cargo test ... -- --nocapture`.
    // Every 2s, per validator: its gap to the top, committed height, view, inbox
    // depth and block-range traffic. Off by default so the gate's own output
    // stays readable. Reads shared metrics only; it never touches a `Node`.
    let run_start = Instant::now();
    let sampling = std::env::var_os("LOCALNET_SAMPLE").is_some();
    let sampler = sampling.then(|| {
        let executed = Arc::clone(&net.metrics.executed);
        let snapshots = Arc::clone(&net.metrics.snapshots);
        let costs = Arc::clone(&net.metrics.costs);
        tokio::spawn(async move {
            let mut prev: Vec<InputCosts> = vec![[(0, 0, 0); 16]; N];
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let hs: Vec<u64> = executed
                    .lock()
                    .expect("lock")
                    .iter()
                    .map(|rows| rows.last().map(|(h, _, _, _)| *h).unwrap_or(0))
                    .collect();
                let snaps = snapshots.lock().expect("lock").clone();
                let top = hs.iter().copied().max().unwrap_or(0);
                let t = run_start.elapsed().as_secs();
                for (i, (h, s)) in hs.iter().zip(snaps.iter()).enumerate() {
                    println!(
                        "SAMPLE t={t} node{i} gap={} h={h} c={} v={} inbox={} req={} srv={} rx={} stale={} rej={} blocked={}",
                        top - h,
                        s.committed,
                        s.view,
                        s.inbox,
                        s.sync.ranges_requested,
                        s.sync.ranges_served,
                        s.sync.ranges_received,
                        s.sync.ranges_stale,
                        s.sync.ranges_rejected,
                        s.sync.blocks_blocked_on_body,
                    );
                }
                // Where each node's time went in the last 2s: messages handled,
                // then the three input kinds that cost the most.
                let now = costs.lock().expect("lock").clone();
                for (i, (cur, old)) in now.iter().zip(prev.iter()).enumerate() {
                    let mut kinds: Vec<(usize, u64, u64, u64)> = (0..16)
                        .map(|k| (k, cur[k].0 - old[k].0, cur[k].1 - old[k].1, cur[k].2 - old[k].2))
                        .collect();
                    let handled: u64 = kinds.iter().map(|k| k.1).sum();
                    kinds.sort_by_key(|k| std::cmp::Reverse(k.2 + k.3));
                    let top3: Vec<String> = kinds
                        .iter()
                        .take(3)
                        .map(|(k, n, step, route)| {
                            format!(
                                "{}:n={n},step={}ms,route={}ms",
                                INPUT_KINDS[*k],
                                step / 1_000_000,
                                route / 1_000_000
                            )
                        })
                        .collect();
                    println!("COST t={t} node{i} handled={handled} {}", top3.join(" "));
                }
                prev = now;
            }
        })
    });

    // Keep real transactions flowing for the whole run. A restarted validator
    // must catch up on blocks that CERTIFY BATCHES, not on empty ones: an empty
    // block needs no bodies, so a broken body path would pass unnoticed.
    let submit = net.submit.clone();
    let funded = net.funded.clone();
    let feeder = tokio::spawn(async move {
        let mut i = 0u64;
        loop {
            let payer = &funded[(i as usize) % funded.len()];
            let nonce = i / funded.len() as u64;
            let mut to = [0u8; 20];
            to[..8].copy_from_slice(&i.to_le_bytes());
            to[19] = 0xEE;
            let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
            if submit[(i as usize) % N]
                .send(NodeInput::SubmitTx(tx))
                .is_err()
            {
                break;
            }
            i += 1;
            if i.is_multiple_of(50) {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    });

    // Do not start restarting until the chain is genuinely producing, or the
    // first restart measures a chain that had not begun.
    let start = Instant::now();
    while net.height_excluding(usize::MAX) < 5 {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "the committee never started producing, so the rolling restart \
             would measure nothing"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for k in 0..N {
        let others_before = net.height_excluding(k);
        let own_before = net.height_of(k);
        let proposals_before = net.proposals();

        if sampling {
            println!(
                "PHASE t={} restarting node{k}",
                run_start.elapsed().as_secs()
            );
        }
        // Returns only once the rest of the committee has moved DOWN_BLOCKS
        // ahead and this validator has reopened from its own directory.
        net.restart_one(k, DOWN_BLOCKS).await;

        let others_after_down = net.height_excluding(k);
        assert!(
            others_after_down >= others_before + DOWN_BLOCKS,
            "node{k} was down and the rest of the committee stopped with it: \
             {others_before} -> {others_after_down}. A rolling restart that \
             halts the chain is an outage, not an upgrade.\n  \
             heights   {:?}\n  proposals {:?} -> {:?}\n  \
             (proposals rising with heights flat means views advance but \
             nothing commits; both flat means nobody is leading)\n  \
             inbox     {:?}\n  \
             (thousands means saturated: timers queue behind the backlog; \
             near zero with both flat means idle or wedged)\n  \
             counts    {:#?}",
            net.heights(),
            proposals_before,
            net.proposals(),
            net.inboxes(),
            net.counts()
        );

        // It must rejoin, and it must rejoin ABOVE where it left off.
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            let own = net.height_of(k);
            let others = net.height_excluding(k);
            // Within two blocks is caught up: the committee keeps committing
            // while we measure, so demanding equality races the chain.
            if own > own_before && own + 2 >= others {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "node{k} did not rejoin in 90s: it left at {own_before}, is at \
                 {own}, and the committee is at {others}. A validator that \
                 resumes but never closes the gap contributes nothing.\n  \
                 heights {:?}\n  its counts {:?}\n  inbox {:?}\n  \
                 (qcs at zero means it is not even voting; qcs rising with \
                 height flat means it follows but cannot execute)",
                net.heights(),
                net.counts()[k],
                net.inboxes()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // ⛔ THE WHOLE COMMITTEE MUST BE HEALTHY BEFORE THE NEXT ONE GOES DOWN,
        // and this is what a rolling upgrade actually requires. Checking only
        // the node just restarted hides cumulative damage: each restart can
        // leave a validator limping, and the failure then appears at whichever
        // one happens to push the live set below quorum — blaming the last
        // restart for the state the previous six left behind.
        // ⭐ A TREND GATE, FOUNDER DECISION 2026-09-15: EVERY NODE'S GAP MUST
        // KEEP SHRINKING. This used to ask only "is every node within 3 of the
        // top right now" before a deadline (90s, then 300s). That question
        // could not tell a recovering node from a frozen one until the deadline
        // passed, because at any moment before it both answer "no":
        //
        //     recovering   16 behind and closing       (2026-09-13)
        //     frozen       188 behind and static       (2026-09-13, and 2026-09-15
        //                                               runs 1-3 before the fixes)
        //
        // So the rule is now: a node more than 3 behind must reach a NEW LOWEST
        // gap at least every STALL. A frozen node never does and fails STALL
        // after it stops closing. A recovering node keeps setting new lows.
        //
        // ⚠ STALL IS MEASURED, NOT CHOSEN. With e16fbaeee and 2ec57e294, three
        // runs (2026-09-15, runs 4-6, 37-45s each) never kept a node more than 3
        // behind without a new low for longer than 2s, the sampling resolution.
        // Applied to unfixed run 1, a 30s rule fails the frozen node at t=310,
        // 30s after it froze; the old absolute gate failed it at t=584. 30s is
        // 15x the worst healthy stretch, so it does not fail a working system.
        //
        // ⚠ THE CEILING STAYS AS A BACKSTOP, NOT AS THE QUESTION. A node closing
        // by one block every 29s would satisfy the trend forever, so a hard 300s
        // limit remains. It is the measured 2026-09-13 window, unchanged.
        //
        // ⚠ THE REJOIN DEADLINE ABOVE STAYS AT 90s ON PURPOSE. It passed at 90 in
        // every run measured, so there is no evidence it is wrong.
        let settle_start = Instant::now();
        let settle = settle_start + Duration::from_secs(300);
        let mut trend = GapTrend::new(N, SETTLE_STALL_MS);
        loop {
            let hs = net.heights();
            let top = hs.iter().copied().max().unwrap_or(0);
            if hs.iter().all(|h| h + 3 >= top) {
                println!(
                    "after restarting node{k}: heights {hs:?} proposals {:?}",
                    net.proposals()
                );
                break;
            }
            let now = Instant::now();
            let now_ms = now.duration_since(settle_start).as_millis() as u64;
            for (i, h) in hs.iter().enumerate() {
                let gap = top - h;
                if let Err((best, for_ms)) = trend.observe(i, gap, now_ms) {
                    panic!(
                        "node{i} stopped closing its gap after restarting node{k}: {gap} \
                         behind, and it has not been closer than {best} for {}s. heights \
                         {hs:?}. A validator that falls behind and stays behind is frozen, \
                         not recovering.",
                        for_ms / 1000
                    );
                }
            }
            assert!(
                now < settle,
                "the committee did not converge within 300s after restarting node{k}: \
                 heights {hs:?}. Every node kept closing, but not fast enough."
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    feeder.abort();
    if let Some(sampler) = sampler {
        sampler.abort();
    }

    // Every validator, at a height they all reached, must agree on the state
    // root. Heights alone would pass for seven nodes on seven different forks.
    let common = {
        let ex = net.metrics.executed.lock().expect("lock");
        ex.iter()
            .filter_map(|rows| rows.last().map(|(h, _, _, _)| *h))
            .min()
            .expect("every validator executed something")
    };
    let roots: Vec<[u8; 32]> = {
        let ex = net.metrics.executed.lock().expect("lock");
        (0..N)
            .map(|i| {
                ex[i]
                    .iter()
                    .find(|(h, _, _, _)| *h == common)
                    .map(|(_, root, _, _)| *root)
                    .unwrap_or([0u8; 32])
            })
            .collect()
    };
    for (i, root) in roots.iter().enumerate() {
        assert_ne!(
            *root, [0u8; 32],
            "node{i} has no record of height {common}, which every validator \
             reached — it executed a different chain"
        );
        assert_eq!(
            *root, roots[0],
            "node{i} disagrees with node0 on the state root at height {common} \
             after the rolling restart"
        );
    }

    for h in &net.handles {
        h.abort();
    }
}

/// ⛔ THE TEST THAT REPRODUCES THE PRODUCTION FAILURE, WITH CONSENSUS RUNNING.
///
/// On 2026-09-02 the devnet sat at 56,035, the fixed binary was deployed, and
/// it came back at 264. Four restart tests passed anyway, because every one of
/// them reads the exec anchor immediately after `Node::new` and never starts
/// consensus - so all four observed the anchor at the single moment it was
/// correct.
///
/// This restarts the WHOLE validator set from its data directories and lets
/// consensus run again, which is what `systemctl restart` does and what the
/// mainnet rolling-upgrade case looks like.
///
/// ⚠ EXPECTED TO FAIL UNTIL CONSENSUS STATE IS RECOVERED. `ConsensusCore`
/// holds no store reference, boots at `last_committed_height: 0`, and
/// `execute_committed` writes over whatever `Node::new` recovered. Recovering
/// the exec anchor is necessary and not sufficient.
///
/// ⭐ THIS RAN RED FROM THE MOMENT IT WAS WRITTEN UNTIL THE FIX WAS COMPLETE,
/// and every one of its failures named a different real defect: "began again at
/// height 1", then "committed nothing in 45s" twice for two different reasons.
/// It is green now, and it is the acceptance criterion for restart recovery -
/// if it goes red again, a validator cannot survive a restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn the_whole_validator_set_restarts_without_losing_the_chain() {
    let _serialised = heavy().await;
    let n = 4;
    let net = spawn_localnet(n, 20);

    let submit = net.submit.clone();
    let funded = net.funded.clone();
    for i in 0..2_000u64 {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = submit[(i as usize) % n].send(NodeInput::SubmitTx(tx));
        if i % 250 == 249 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    // Let it commit real blocks.
    //
    // ⛔ THE WORK MUST KEEP COMING, AND THAT IS A REAL CHANGE TO THIS TEST.
    // Height 20 used to be reached partly by EMPTY blocks: the chain produced one
    // per view whether or not anything was pending, so the burst above plus idle
    // filler got there easily. Empty-block suppression removes the filler by
    // design, and measured here the burst alone yields ~14 blocks before the
    // chain correctly goes quiet — short of 20, and the test failed on its own
    // precondition rather than on the property it exists to check.
    //
    // ⚠ THIS IS NOT A WEAKENED GATE. The assertion below is unchanged: a
    // restarted set must resume at `before + 1`, not reset to 1. What changed is
    // that its precondition is now met by REAL TRANSACTIONS instead of by filler,
    // which is a more faithful setup for the same property — and it means the
    // test now exercises a busy chain, which is where suppression is hardest.
    //
    // ⚠ A TRICKLE, NOT A FLOOD. A first attempt fed 38.000 transactions as fast
    // as the channel accepted them and the net got SLOWER, not faster: 18 views
    // in 70s, because the workers spent their time sealing and certifying batches
    // nobody had capacity to propose. The point is to keep `has_work()` true, not
    // to saturate. ~400 tx/s does that.
    let keep_feeding = {
        let submit = net.submit.clone();
        let funded = net.funded.clone();
        tokio::spawn(async move {
            for i in 2_000u64.. {
                let payer = &funded[(i as usize) % funded.len()];
                let nonce = i / funded.len() as u64;
                let mut to = [0u8; 20];
                to[..8].copy_from_slice(&i.to_le_bytes());
                to[19] = 0xEE;
                let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
                if submit[(i as usize) % n]
                    .send(NodeInput::SubmitTx(tx))
                    .is_err()
                {
                    return;
                }
                if i % 20 == 19 {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        })
    };

    let deadline = Duration::from_secs(60);
    let start = Instant::now();
    let before = loop {
        let h = {
            let ex = net.metrics.executed.lock().expect("lock");
            ex[0].last().map(|(height, _, _, _)| *height).unwrap_or(0)
        };
        if h >= 20 {
            keep_feeding.abort();
            break h;
        }
        assert!(
            start.elapsed() < deadline,
            "the net committed too little to make the restart assertion meaningful"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };

    // Stop every validator, releasing each RocksDB lock.
    for h in &net.handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    let restarted = respawn_localnet(&net, n);

    // Poll rather than sleep a fixed interval. A restarted node deliberately
    // does NOT propose in its first view (`proposed_up_to` is set to the
    // resumed view, so it cannot re-propose in a view it may already have
    // proposed in), which costs one pacemaker timeout before the next leader
    // produces a block. A fixed 5s wait raced that and reported "committed
    // nothing", which proves neither resume nor reset.
    let restart_deadline = Duration::from_secs(45);
    let restart_start = Instant::now();
    loop {
        let has = {
            let ex = restarted.metrics.executed.lock().expect("lock");
            !ex[0].is_empty()
        };
        if has || restart_start.elapsed() > restart_deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // ⛔ ASSERT ON THE FIRST BLOCK THE RESTARTED SET COMMITS, NOT ITS LATEST.
    // "latest >= before" is satisfiable by a chain that reset to genesis and
    // then climbed past the old height, which is exactly what the devnet did.
    // The first commit distinguishes the two without ambiguity: `before + 1`
    // means it RESUMED, `1` means it started over.
    let first_after = {
        let ex = restarted.metrics.executed.lock().expect("lock");
        ex[0].first().map(|(height, _, _, _)| *height)
    };

    // Print what the restarted set actually did, so a failure names the stall
    // point instead of only reporting silence.
    {
        if let Some(actions) = &restarted.metrics.actions {
            let log = actions.lock().expect("actions");
            println!("\n── restarted-set actions ({} recorded) ──", log.len());
            for (i, a) in log.iter().take(40) {
                println!("  node{i}: {a}");
            }
            println!("── end ──\n");
        }
    }

    let first = first_after.expect(
        "the restarted set committed nothing in 45s, so this proves neither \
         resume nor reset. Check the boot logs for a REFUSING TO RESUME line.",
    );
    assert!(
        first > before,
        "the restarted validator set began again at height {first} with a \
         stored head of {before}. It restarted from genesis instead of \
         resuming, which is the production failure: the devnet was at 56,035 \
         and came back at 264. ConsensusCore holds no store reference and boots \
         at last_committed_height 0."
    );
}

/// ⭐ INSTRUMENTATION BEFORE THE NEXT DESIGN ATTEMPT, NOT ANOTHER GUESS.
///
/// Step 3 of the restart fix wedged the chain and was reverted. The recorded
/// hypothesis was that each validator computes its resume view from its OWN
/// `last_voted_view`, so a committee that stops at slightly different points
/// scatters into different views on restart. That was never verified, and
/// guessing between causes is what produced the revert.
///
/// This measures it. It runs a real four-node network, stops it, and reads what
/// each node persisted — then reports the resume view each WOULD compute. It
/// touches no consensus code, so it cannot wedge anything.
///
/// ⚠ It asserts only what it can prove: that every node recorded safety state
/// at all. The spread is PRINTED rather than asserted, because there is no
/// known-correct spread yet and a threshold invented here would be a number
/// somebody later tunes to make a red test green.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
// ⚠ ON DEMAND, NOT IN THE SUITE. This is instrumentation rather than a
// regression test: it prints and asserts almost nothing. It also spins a whole
// 4-node localnet, and running several of those beside the 40k-transaction
// throughput test starves it of CPU — which is how it made a passing test fail.
// A diagnostic that destabilises the suite is a net negative.
//   cargo test -p solidus-node2 --test localnet -- --ignored --nocapture
#[ignore = "diagnostic; run on demand with --ignored --nocapture"]
async fn measure_what_each_validator_would_resume_to() {
    let n = 4;
    let net = spawn_localnet(n, 20);

    let submit = net.submit.clone();
    let funded = net.funded.clone();
    for i in 0..2_000u64 {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = submit[(i as usize) % n].send(NodeInput::SubmitTx(tx));
        if i % 250 == 249 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    let deadline = Duration::from_secs(60);
    let start = Instant::now();
    loop {
        let h = {
            let ex = net.metrics.executed.lock().expect("lock");
            ex[0].last().map(|(height, _, _, _)| *height).unwrap_or(0)
        };
        if h >= 20 || start.elapsed() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for h in &net.handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    println!("\n── what each validator persisted ──");
    let mut resume_views = Vec::new();
    let mut heads = Vec::new();
    for (i, dir) in net.dirs.iter().enumerate() {
        let store = Store2::open(dir, Profile::Testnet).expect("reopen");
        let head = store.canon_head().expect("head");
        let safety = store.safety().expect("safety");
        match safety {
            Some((last_voted_view, qc_bytes)) => {
                let qc_view = bincode::deserialize::<solidus_hotstuff2::QuorumCert>(&qc_bytes)
                    .map(|q| q.view)
                    .unwrap_or(u64::MAX);
                let resume = last_voted_view.max(qc_view).saturating_add(1);
                println!(
                    "  node{i}: head={head:?} last_voted_view={last_voted_view} \
                     high_qc.view={qc_view} -> would resume at view {resume}"
                );
                resume_views.push(resume);
                heads.push(head);
            }
            None => println!("  node{i}: head={head:?} NO SAFETY RECORD"),
        }
    }

    assert_eq!(
        resume_views.len(),
        n,
        "every validator must have persisted safety state; without it none of \
         them may safely resume, and the spread below is unmeasurable"
    );

    let lo = resume_views.iter().min().copied().unwrap_or(0);
    let hi = resume_views.iter().max().copied().unwrap_or(0);
    println!("  resume-view spread: {lo}..={hi}  (delta {})", hi - lo);
    println!("  canon heads: {heads:?}");
    println!("── end ──\n");
}

/// ⭐ IS THE LOCKED BLOCK RELOADABLE? The remaining suspect, measured.
///
/// A resumed node reloads committed blocks from `canon`. Its `high_qc` may
/// certify a block that was QC'd but never committed, which is therefore NOT in
/// the store at all. A proposer builds on its locked block, so if receivers
/// cannot reload that block they cannot find `header.parent`, cannot vote, and
/// the set wedges — the same shape as the first defect, one level up.
///
/// Store-level only: no consensus internals, so this cannot itself wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
#[ignore = "diagnostic; run on demand with --ignored --nocapture"]
async fn is_the_locked_block_reloadable_after_a_restart() {
    let n = 4;
    let net = spawn_localnet(n, 20);

    let submit = net.submit.clone();
    let funded = net.funded.clone();
    for i in 0..2_000u64 {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = submit[(i as usize) % n].send(NodeInput::SubmitTx(tx));
        if i % 250 == 249 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }
    let deadline = Duration::from_secs(60);
    let t0 = Instant::now();
    loop {
        let h = {
            let ex = net.metrics.executed.lock().expect("lock");
            ex[0].last().map(|(height, _, _, _)| *height).unwrap_or(0)
        };
        if h >= 20 || t0.elapsed() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for h in &net.handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    println!("\n── can each validator reload the block its lock certifies? ──");
    let mut missing = 0;
    for (i, dir) in net.dirs.iter().enumerate() {
        let store = Store2::open(dir, Profile::Testnet).expect("reopen");
        let head = store.canon_head().expect("head").unwrap_or(0);
        let Some((last_voted, qc_bytes)) = store.safety().expect("safety") else {
            println!("  node{i}: NO SAFETY RECORD");
            continue;
        };
        let qc =
            bincode::deserialize::<solidus_hotstuff2::QuorumCert>(&qc_bytes).expect("decode qc");

        // Is the locked block among the committed ones we could reload?
        let mut found_at = None;
        let from = head.saturating_sub(16);
        for h in from..=head {
            if let Ok(Some(hash)) = store.canon_hash(h) {
                if hash == qc.block_hash {
                    found_at = Some(h);
                    break;
                }
            }
        }
        // ⚠ ALSO CHECK block_by_hash. The pending-block write stores the locked
        // block by HASH with no canon entry, deliberately, because it is not
        // canonical yet. A probe that only walks canon reports it missing even
        // when it is present — this instrument said exactly that once.
        let by_hash = store
            .block_by_hash(&qc.block_hash)
            .ok()
            .flatten()
            .is_some_and(|b| !b.is_empty());

        match found_at {
            Some(h) => println!(
                "  node{i}: head={head} last_voted={last_voted} lock@view{} -> \
                 locked block IS committed at height {h}",
                qc.view
            ),
            None if by_hash => println!(
                "  node{i}: head={head} last_voted={last_voted} lock@view{} -> \
                 not in canon (correct, it is uncommitted) but RELOADABLE by hash",
                qc.view
            ),
            None => {
                missing += 1;
                println!(
                    "  node{i}: head={head} last_voted={last_voted} lock@view{} -> \
                     ⛔ LOCKED BLOCK UNRELOADABLE: absent from canon AND by hash",
                    qc.view
                );
            }
        }
    }
    println!("  validators whose lock is unreloadable: {missing} of {n}");
    println!("── end ──\n");
}

/// ⭐ PRINT WHAT A RESUMED NODE DOES, INSTEAD OF ARGUING ABOUT IT.
///
/// Two hypotheses about the remaining wedge were argued convincingly and both
/// were wrong. This one emits no opinion: it runs a network, stops it, reopens
/// every validator, calls `start()`, and reports the actions each emits.
///
/// The three questions from the plan, answered directly:
///   1. does the leader of the resumed view propose?
///   2. is a timeout scheduled, so the set can advance at all?
///   3. what view does each node actually end up in?
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
// ⚠ ON DEMAND, NOT IN THE SUITE. This is instrumentation rather than a
// regression test: it prints and asserts almost nothing. It also spins a whole
// 4-node localnet, and running several of those beside the 40k-transaction
// throughput test starves it of CPU — which is how it made a passing test fail.
// A diagnostic that destabilises the suite is a net negative.
//   cargo test -p solidus-node2 --test localnet -- --ignored --nocapture
#[ignore = "diagnostic; run on demand with --ignored --nocapture"]
async fn print_what_a_resumed_node_emits() {
    let n = 4;
    let net = spawn_localnet(n, 20);

    let submit = net.submit.clone();
    let funded = net.funded.clone();
    for i in 0..2_000u64 {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = submit[(i as usize) % n].send(NodeInput::SubmitTx(tx));
        if i % 250 == 249 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    let deadline = Duration::from_secs(60);
    let start_t = Instant::now();
    loop {
        let h = {
            let ex = net.metrics.executed.lock().expect("lock");
            ex[0].last().map(|(height, _, _, _)| *height).unwrap_or(0)
        };
        if h >= 20 || start_t.elapsed() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for h in &net.handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(400)).await;

    println!("\n── what each resumed validator emits from start() ──");
    let bls_secrets: Vec<BlsSecretKey> = net
        .bls_secret_bytes
        .iter()
        .map(|b| BlsSecretKey::from_bytes(b).expect("secret"))
        .collect();
    let committee = Committee::new(net.bls_pubkeys.clone());

    for (index, secret) in bls_secrets.into_iter().enumerate() {
        let store = Store2::open(&net.dirs[index], Profile::Testnet).expect("reopen");
        let head = store.canon_head().expect("head");
        let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));
        let mut node = Node::new(
            index as u32,
            CHAIN_ID,
            secret,
            committee.clone(),
            net.bls_pubkeys.clone(),
            Pacemaker::default(),
            elector,
            store,
            NodeTuning {
                max_certs_per_block: 64,
                batch_max_bytes: 512 * 1024,
                batch_max_txs: 400,
                flush_interval_ms: 25,
                min_block_interval_ms: 0,
                // Suppression ON, with v1's 600s heartbeat: this gate exists to catch
                // exactly the stalls the three previous attempts produced.
                idle_heartbeat_ms: 600_000,
                idle_grace_ms: 2_000,
                view_timeout_ms: 0,
                block_retention: 0,
            },
            NETWORK.to_string(),
        )
        .expect("node boots");

        let boot = node.start();
        let mut names: Vec<String> = Vec::new();
        for o in &boot {
            names.push(match o {
                NodeOutput::Consensus(a) => match a {
                    Action::BroadcastProposal(p) => {
                        format!("BroadcastProposal(view={})", p.block.header.view)
                    }
                    Action::SendVote { vote, .. } => format!("SendVote(view={})", vote.view),
                    Action::BroadcastQc(q) => format!("BroadcastQc(view={})", q.view),
                    Action::BroadcastTc(t) => format!("BroadcastTc(view={})", t.view),
                    Action::BroadcastTimeoutVote(t) => {
                        format!("BroadcastTimeoutVote(view={})", t.view)
                    }
                    Action::ScheduleTimeout { view, delay } => {
                        format!("ScheduleTimeout(view={view}, {delay:?})")
                    }
                    Action::SchedulePropose { view, delay } => {
                        format!("SchedulePropose(view={view}, {delay:?})")
                    }
                    Action::EnteredView(v) => format!("EnteredView({v})"),
                    Action::Commit(c) => format!("Commit(h={})", c.height),
                },
                other => format!("{other:?}"),
            });
        }
        println!("  node{index}: head={head:?} -> start() emitted {names:?}");

        // Drive the timeout the boot just scheduled and report what comes back.
        // This answers whether the timeout path works after a resume, which
        // decides whether the set can advance at all.
        let view = boot.iter().find_map(|o| match o {
            NodeOutput::Consensus(Action::ScheduleTimeout { view, .. }) => Some(*view),
            _ => None,
        });
        if let Some(v) = view {
            let after = node.step(NodeInput::ConsensusTimer(v));
            let a: Vec<String> = after
                .iter()
                .map(|o| match o {
                    NodeOutput::Consensus(Action::BroadcastTimeoutVote(t)) => {
                        format!("BroadcastTimeoutVote(view={})", t.view)
                    }
                    NodeOutput::Consensus(Action::ScheduleTimeout { view, .. }) => {
                        format!("ScheduleTimeout({view})")
                    }
                    NodeOutput::Consensus(Action::EnteredView(v)) => format!("EnteredView({v})"),
                    NodeOutput::Consensus(Action::BroadcastProposal(p)) => {
                        format!("BroadcastProposal(view={})", p.block.header.view)
                    }
                    other => format!("{other:?}"),
                })
                .collect();
            println!("           timer(view={v}) -> {a:?}");
        }
    }
    println!("── end ──\n");
}

/// ⭐ SUPPRESSION MUST ACTUALLY SUPPRESS. The restart gate proves suppression does
/// no HARM; this proves it does the WORK, and without it the feature could be a
/// no-op and every other test would still be green.
///
/// ⛔ THE DEFECT THIS PINS, MEASURED ON THE LIVE TESTNET. v2 proposed on every
/// view whether or not anything was pending: 1.015.487 blocks, every one
/// `tx_count: 0`, ~334 bytes each, ~69 MB/day and ~25 GB/year on a chain with no
/// users. The chain grew with WALL-CLOCK TIME rather than with use.
///
/// ⚠ IT ASSERTS A RATIO, NOT A COUNT. An idle chain is allowed to produce a few
/// blocks: the first proposal after boot is deliberately never suppressed (a
/// restarted set must not look dead), and the grace period lets a momentary gap
/// through. What must NOT happen is a block per view forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn an_idle_chain_stops_producing_empty_blocks() {
    let n = 4;
    let net = spawn_localnet(n, 20);

    // No transactions at all. Let it run well past several view timeouts.
    tokio::time::sleep(Duration::from_secs(12)).await;

    let heights: Vec<u64> = {
        let ex = net.metrics.executed.lock().expect("lock");
        (0..n)
            .map(|i| ex[i].last().map(|(h, _, _, _)| *h).unwrap_or(0))
            .collect()
    };
    let tip = heights.iter().copied().max().unwrap_or(0);

    // Unsuppressed, this chain produced a block per view: at a 400ms base timeout
    // that is ~30 blocks in 12s, and on the live testnet it was ~9 per SECOND.
    assert!(
        tip <= 5,
        "an idle chain must stop producing: reached height {tip} in 12s with no \
         transactions at all (heights {heights:?}). Suppression is not working."
    );

    for h in &net.handles {
        h.abort();
    }
}

/// Reopen a node's store, waiting for the stopped node to release RocksDB's lock.
///
/// ⚠ WAIT FOR THE LOCK, DO NOT GUESS HOW LONG IT TAKES. An aborted task drops its store when the
/// scheduler gets to it, and under a loaded machine (turbo and cargo sharing the pre-push run) that
/// lands after a fixed sleep: "lock hold by current process ... No locks available". That reads as a
/// recovery bug and is only a scheduler delay. Bounded at 15 s, so a real leak still fails.
async fn open_store_waiting(dir: &std::path::Path, what: &str) -> Store2 {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Store2::open(dir, Profile::Testnet) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await
            }
            Err(e) => panic!("reopen {what}: {e:?}"),
        }
    }
}

/// The same wait for a caller that is not async. Blocking is fine here: nothing else runs on this
/// thread while the set is being rebuilt.
fn open_store_waiting_blocking(dir: &std::path::Path, what: &str) -> Store2 {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match Store2::open(dir, Profile::Testnet) {
            Ok(s) => return s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("reopen {what}: {e:?}"),
        }
    }
}

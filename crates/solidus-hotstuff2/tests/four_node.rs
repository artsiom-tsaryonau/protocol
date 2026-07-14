//! Four-validator integration harness: real tokio tasks, real timers,
//! in-process loopback channels. Measures end-to-end finality latency
//! (proposal broadcast → commit observed per node) and exercises the
//! leader-failure / TC path and chain consistency.
//!
//! Honest scope note: loopback channel RTT is microseconds — better than
//! any LAN. The measured p50/p99 below demonstrate protocol overhead on
//! this machine (Apple-silicon dev box), not network-realistic finality;
//! the Stage-7 geo-soak owns that number.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{
    Action, Committee, ConsensusCore, CoreConfig, EmptyPayloads, Pacemaker, Proposal, QuorumCert,
    RoundRobin, TimeoutCert, TimeoutVote, ValidatorIndex, View, Vote,
};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 2;

/// One node's committed chain: (height, hash, proposal→commit latency).
type CommitLog = Vec<(u64, [u8; 32], Duration)>;

#[allow(clippy::large_enum_variant)] // in-process harness messages
#[derive(Debug)]
enum Input {
    Proposal(Proposal),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    Tc(TimeoutCert),
    Qc(QuorumCert),
    Timer(View),
}

#[derive(Clone)]
struct Shared {
    /// block hash → instant its proposal was broadcast (proposer-side).
    proposed_at: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    /// per-node committed chains.
    commits: Arc<Mutex<Vec<CommitLog>>>,
}

struct Node {
    index: usize,
    core: ConsensusCore<RoundRobin, EmptyPayloads>,
    rx: mpsc::UnboundedReceiver<Input>,
    txs: Vec<mpsc::UnboundedSender<Input>>,
    shared: Shared,
    dead: Arc<AtomicBool>,
}

impl Node {
    fn dispatch(&mut self, actions: Vec<Action>) {
        for action in actions {
            match action {
                Action::BroadcastProposal(p) => {
                    self.shared
                        .proposed_at
                        .lock()
                        .expect("lock")
                        .insert(p.block.hash(), Instant::now());
                    for (i, tx) in self.txs.iter().enumerate() {
                        if i != self.index {
                            let _ = tx.send(Input::Proposal(p.clone()));
                        }
                    }
                }
                Action::SendVote { to, vote } => {
                    let _ = self.txs[to as usize].send(Input::Vote(vote));
                }
                Action::BroadcastTimeoutVote(tv) => {
                    for (i, tx) in self.txs.iter().enumerate() {
                        if i != self.index {
                            let _ = tx.send(Input::TimeoutVote(tv.clone()));
                        }
                    }
                }
                Action::BroadcastTc(tc) => {
                    for (i, tx) in self.txs.iter().enumerate() {
                        if i != self.index {
                            let _ = tx.send(Input::Tc(tc.clone()));
                        }
                    }
                }
                Action::BroadcastQc(qc) => {
                    for (i, tx) in self.txs.iter().enumerate() {
                        if i != self.index {
                            let _ = tx.send(Input::Qc(qc.clone()));
                        }
                    }
                }
                Action::Commit(c) => {
                    let latency = self
                        .shared
                        .proposed_at
                        .lock()
                        .expect("lock")
                        .get(&c.hash)
                        .map(|t| t.elapsed())
                        .unwrap_or_default();
                    self.shared.commits.lock().expect("lock")[self.index]
                        .push((c.height, c.hash, latency));
                }
                Action::ScheduleTimeout { view, delay } => {
                    let tx = self.txs[self.index].clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = tx.send(Input::Timer(view));
                    });
                }
                Action::EnteredView(_) => {}
            }
        }
    }

    async fn run(mut self) {
        let actions = self.core.start();
        self.dispatch(actions);
        while let Some(input) = self.rx.recv().await {
            if self.dead.load(Ordering::Relaxed) {
                continue; // crashed node: swallow everything
            }
            let result = match input {
                Input::Proposal(p) => self.core.on_proposal(p),
                Input::Vote(v) => self.core.on_vote(v),
                Input::TimeoutVote(tv) => self.core.on_timeout_vote(tv),
                Input::Tc(tc) => self.core.on_tc(tc),
                Input::Qc(qc) => self.core.on_qc(qc),
                Input::Timer(view) => self.core.on_local_timeout(view),
            };
            match result {
                Ok(actions) => self.dispatch(actions),
                Err(_e) => { /* invalid message: protocol says drop */ }
            }
        }
    }
}

struct Net {
    shared: Shared,
    kill_switches: Vec<Arc<AtomicBool>>,
}

fn spawn_network(n: usize, pacemaker: Pacemaker) -> Net {
    let secrets: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let committee = Committee::new(secrets.iter().map(|k| k.public_key()).collect());

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        receivers.push(rx);
    }

    let shared = Shared {
        proposed_at: Arc::new(Mutex::new(HashMap::new())),
        commits: Arc::new(Mutex::new(vec![Vec::new(); n])),
    };
    let mut kill_switches = Vec::new();

    for (index, (secret, rx)) in secrets.into_iter().zip(receivers).enumerate() {
        let core = ConsensusCore::new(
            CoreConfig {
                chain_id: CHAIN_ID,
                my_index: index as ValidatorIndex,
                secret,
                committee: committee.clone(),
                pacemaker: pacemaker.clone(),
            },
            RoundRobin::new(n),
            EmptyPayloads { ts_ms: 1 },
        );
        let dead = Arc::new(AtomicBool::new(false));
        kill_switches.push(Arc::clone(&dead));
        let node = Node {
            index,
            core,
            rx,
            txs: senders.clone(),
            shared: shared.clone(),
            dead,
        };
        tokio::spawn(node.run());
    }

    Net {
        shared,
        kill_switches,
    }
}

/// Wait until every node has committed ≥ `target` blocks (or panic after
/// `deadline`).
async fn wait_for_commits(shared: &Shared, n: usize, target: usize, deadline: Duration) {
    let start = Instant::now();
    loop {
        {
            let commits = shared.commits.lock().expect("lock");
            if (0..n).all(|i| commits[i].len() >= target) {
                return;
            }
        }
        assert!(
            start.elapsed() < deadline,
            "network failed to commit {target} blocks within {deadline:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn assert_chains_consistent(shared: &Shared, n: usize) -> usize {
    let commits = shared.commits.lock().expect("lock");
    let min_len = (0..n).map(|i| commits[i].len()).min().unwrap_or(0);
    for pos in 0..min_len {
        let (h0, hash0, _) = commits[0][pos];
        for node in 1..n {
            let (h, hash, _) = commits[node][pos];
            assert_eq!(
                (h0, hash0),
                (h, hash),
                "chain divergence at commit position {pos} between node 0 and node {node}"
            );
        }
    }
    min_len
}

fn latency_stats(shared: &Shared, n: usize) -> (Duration, Duration, usize) {
    let commits = shared.commits.lock().expect("lock");
    let mut latencies: Vec<Duration> = (0..n)
        .flat_map(|i| commits[i].iter().map(|(_, _, l)| *l))
        .filter(|l| !l.is_zero())
        .collect();
    latencies.sort();
    let count = latencies.len();
    let p50 = latencies[count / 2];
    let p99 = latencies[(count * 99) / 100];
    (p50, p99, count)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn happy_path_commits_and_measures_finality() {
    let net = spawn_network(4, Pacemaker::default());

    // 150 committed blocks on every node.
    wait_for_commits(&net.shared, 4, 150, Duration::from_secs(30)).await;

    let common = assert_chains_consistent(&net.shared, 4);
    assert!(common >= 150);

    let (p50, p99, samples) = latency_stats(&net.shared, 4);
    println!(
        "four_node happy path: {samples} commit observations, finality p50={p50:?} p99={p99:?} \
         (in-process loopback on this machine — protocol overhead, not network finality)"
    );
    // Generous structural bound: loopback finality must be well under the
    // 400ms base timeout — if it is not, the pipeline is stalling on
    // timeouts instead of QCs.
    assert!(
        p50 < Duration::from_millis(400),
        "p50 {p50:?} suggests the happy path is timing out"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn leader_crash_rotates_via_timeout_certificates() {
    // Faster pacemaker so the TC path exercises quickly.
    let net = spawn_network(4, Pacemaker::new(100, 800));

    // Let the chain establish itself.
    wait_for_commits(&net.shared, 4, 20, Duration::from_secs(15)).await;

    // Kill node 2: its leader views (and vote-aggregation views) now
    // require timeout certificates to pass.
    net.kill_switches[2].store(true, Ordering::Relaxed);

    let live = [0usize, 1, 3];
    let before: usize = {
        let commits = net.shared.commits.lock().expect("lock");
        live.iter().map(|&i| commits[i].len()).min().unwrap_or(0)
    };

    // The three live nodes must keep committing (≥25 more each).
    let target = before + 25;
    let start = Instant::now();
    loop {
        {
            let commits = net.shared.commits.lock().expect("lock");
            if live.iter().all(|&i| commits[i].len() >= target) {
                break;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "live nodes failed to progress past a crashed leader"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Consistency across the three live nodes.
    let commits = net.shared.commits.lock().expect("lock");
    let min_len = live.iter().map(|&i| commits[i].len()).min().unwrap_or(0);
    for pos in 0..min_len {
        let (h0, hash0, _) = commits[0][pos];
        for &node in &live[1..] {
            let (h, hash, _) = commits[node][pos];
            assert_eq!((h0, hash0), (h, hash), "divergence at position {pos}");
        }
    }
}

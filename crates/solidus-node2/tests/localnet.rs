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
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeInput, NodeOutput, NodeTuning};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Transaction, TxPayload};
use tokio::sync::mpsc;

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

#[derive(Clone)]
struct Metrics {
    /// node index → its executed blocks.
    executed: Arc<Mutex<Vec<Vec<ExecRecord>>>>,
}

struct NodeTask {
    index: usize,
    node: Node,
    rx: mpsc::UnboundedReceiver<NodeInput>,
    peers: Vec<mpsc::UnboundedSender<NodeInput>>,
    metrics: Metrics,
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
            }
        }
    }

    fn route_consensus(&mut self, action: solidus_hotstuff2::Action) {
        use solidus_hotstuff2::Action;
        match action {
            Action::BroadcastProposal(p) => self.broadcast(|| NodeInput::Proposal(p.clone())),
            Action::BroadcastQc(qc) => self.broadcast(|| NodeInput::Qc(qc.clone())),
            Action::BroadcastTc(tc) => self.broadcast(|| NodeInput::Tc(tc.clone())),
            Action::BroadcastTimeoutVote(tv) => {
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

    async fn run(mut self) {
        let boot = self.node.start();
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
        while let Some(input) = self.rx.recv().await {
            let out = self.node.step(input);
            self.route(out);
        }
    }
}

struct LocalNet {
    submit: Vec<mpsc::UnboundedSender<NodeInput>>,
    metrics: Metrics,
    funded: Vec<SigningKey>,
}

fn spawn_localnet(n: usize, n_accounts: usize) -> LocalNet {
    let bls_secrets: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let bls_pubkeys: Vec<_> = bls_secrets.iter().map(|k| k.public_key()).collect();
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
    };

    for (index, (secret, rx)) in bls_secrets.into_iter().zip(receivers).enumerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Leak the tempdir so RocksDB files outlive the node for the test.
        let path = dir.keep();
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
            },
            NETWORK.to_string(),
        );
        for key in &funded {
            let addr = Address::from_public_key(&key.verifying_key());
            let acct = Account::with_balance(addr, 1_000_000_000, AccountType::Regular);
            node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        }

        let task = NodeTask {
            index,
            node,
            rx,
            peers: senders.clone(),
            metrics: metrics.clone(),
        };
        tokio::spawn(task.run());
    }

    LocalNet {
        submit: senders,
        metrics,
        funded,
    }
}

fn executed_tx_totals(metrics: &Metrics, n: usize) -> Vec<usize> {
    let ex = metrics.executed.lock().expect("lock");
    (0..n)
        .map(|i| ex[i].iter().map(|(_, _, c, _)| *c).sum())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn integrated_localnet_executes_and_agrees() {
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
    let target_txs = 8_000usize;
    let deadline = Duration::from_secs(120);
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

//! Four-validator worker network over tokio loopback channels: streams
//! transactions through batching → dissemination → availability acks →
//! certificates, and measures seal→certificate latency (the Stage-2
//! "batch availability" acceptance metric).
//!
//! Honest scope note: loopback delivery is microseconds; the p95 measured
//! here is protocol/crypto overhead on this machine, not a network
//! number. The <250ms acceptance bound gets its network-realistic reading
//! at Stage 7 (R-TOPOLOGY).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::keys::Address;
use solidus_mempool_dag::{
    Batch, BatchAck, BatchCertificate, BatchResolver, BatchStore, SharedBatchStore, Worker,
    WorkerAction, WorkerConfig,
};
use solidus_txns::types::{Transaction, TxPayload};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 2;

#[derive(Debug)]
enum Input {
    SubmitTx(Transaction),
    Batch { batch: Batch, from: u32 },
    Ack(BatchAck),
    Flush,
}

#[derive(Clone)]
struct Shared {
    sealed_at: Arc<Mutex<HashMap<[u8; 32], Instant>>>,
    certs: Arc<Mutex<Vec<(BatchCertificate, Duration)>>>,
}

struct WorkerNode {
    index: usize,
    worker: Worker,
    rx: mpsc::UnboundedReceiver<Input>,
    txs: Vec<mpsc::UnboundedSender<Input>>,
    shared: Shared,
}

impl WorkerNode {
    fn dispatch(&mut self, actions: Vec<WorkerAction>) {
        for action in actions {
            match action {
                WorkerAction::BroadcastBatch(batch) => {
                    self.shared
                        .sealed_at
                        .lock()
                        .expect("lock")
                        .insert(batch.digest().0, Instant::now());
                    for (i, tx) in self.txs.iter().enumerate() {
                        if i != self.index {
                            let _ = tx.send(Input::Batch {
                                batch: batch.clone(),
                                from: self.index as u32,
                            });
                        }
                    }
                }
                WorkerAction::SendAck { to, ack } => {
                    let _ = self.txs[to as usize].send(Input::Ack(ack));
                }
                WorkerAction::CertFormed(cert) => {
                    let latency = self
                        .shared
                        .sealed_at
                        .lock()
                        .expect("lock")
                        .get(&cert.digest.0)
                        .map(|t| t.elapsed())
                        .unwrap_or_default();
                    self.shared
                        .certs
                        .lock()
                        .expect("lock")
                        .push((cert, latency));
                }
            }
        }
    }

    async fn run(mut self) {
        while let Some(input) = self.rx.recv().await {
            let result = match input {
                Input::SubmitTx(tx) => self.worker.on_submit_tx(tx),
                Input::Batch { batch, from } => self.worker.on_batch(batch, from),
                Input::Ack(ack) => self.worker.on_ack(ack),
                Input::Flush => self.worker.on_flush(),
            };
            match result {
                Ok(actions) => self.dispatch(actions),
                Err(_e) => { /* malformed input: drop, per protocol */ }
            }
        }
    }
}

fn make_tx(nonce: u64, salt: u8) -> Transaction {
    Transaction {
        sender_pubkey: [salt; 32],
        nonce,
        payload: TxPayload::Transfer {
            to: Address::from_bytes([9u8; 20]),
            amount: nonce + 1,
        },
        signature: [0u8; 64],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn four_worker_availability_flow_measured() {
    let n = 4;
    let secrets: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let pks: Vec<_> = secrets.iter().map(|k| k.public_key()).collect();

    let mut senders = Vec::new();
    let mut receivers = Vec::new();
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        receivers.push(rx);
    }

    let shared = Shared {
        sealed_at: Arc::new(Mutex::new(HashMap::new())),
        certs: Arc::new(Mutex::new(Vec::new())),
    };
    let mut stores: Vec<SharedBatchStore> = Vec::new();

    for (index, (secret, rx)) in secrets.into_iter().zip(receivers).enumerate() {
        let store: SharedBatchStore = Arc::new(RwLock::new(BatchStore::new()));
        stores.push(Arc::clone(&store));
        let worker = Worker::new(
            WorkerConfig {
                chain_id: CHAIN_ID,
                my_index: index as u32,
                worker_id: index as u32,
                batch_max_bytes: 64 * 1024,
                batch_max_txs: 250,
                inbound_max_bytes: 2_000_000,
                keys: pks.clone(),
                secret,
            },
            store,
        );
        let node = WorkerNode {
            index,
            worker,
            rx,
            txs: senders.clone(),
            shared: shared.clone(),
        };
        tokio::spawn(node.run());
    }

    // Stream 8,000 txs round-robin into the four workers (→ 32 batches at
    // 250 txs/batch), then flush stragglers.
    for i in 0..8_000u64 {
        let target = (i % n as u64) as usize;
        let _ = senders[target].send(Input::SubmitTx(make_tx(i, (i % 251) as u8)));
    }
    for s in &senders {
        let _ = s.send(Input::Flush);
    }

    // Wait for all certificates.
    let expected_min = 32;
    let start = Instant::now();
    loop {
        if shared.certs.lock().expect("lock").len() >= expected_min {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "availability flow stalled: {} certs",
            shared.certs.lock().expect("lock").len()
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let certs = shared.certs.lock().expect("lock").clone();

    // Every certificate verifies and its body resolves from every store
    // that acked it — spot-check via the originator's own store (index =
    // worker id) plus one peer store.
    let mut latencies: Vec<Duration> = Vec::new();
    for (cert, latency) in &certs {
        cert.verify(CHAIN_ID, &pks).expect("cert must verify");
        let own = stores[cert.worker as usize]
            .read()
            .expect("lock")
            .resolve(&cert.digest)
            .expect("originator resolves");
        assert_eq!(own.digest(), cert.digest);
        let peer = stores[(cert.worker as usize + 1) % n]
            .read()
            .expect("lock")
            .resolve(&cert.digest)
            .expect("peer that acked resolves");
        assert_eq!(peer.digest(), cert.digest);
        latencies.push(*latency);
    }

    latencies.sort();
    let p50 = latencies[latencies.len() / 2];
    let p95 = latencies[(latencies.len() * 95) / 100];
    println!(
        "availability: {} certs, seal→certificate p50={p50:?} p95={p95:?} \
         (in-process loopback on this machine — protocol overhead, not a network number)",
        latencies.len()
    );
    // Structural bound: on loopback this must be far under the 250ms
    // acceptance target; a miss means the ack/cert pipeline is stalling.
    assert!(
        p95 < Duration::from_millis(250),
        "loopback availability p95 {p95:?} exceeds the acceptance bound"
    );
}

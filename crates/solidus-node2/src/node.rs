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

use std::sync::{Arc, Mutex};

use solidus_exec::{execute_block_twolane, BlockCtx, ExecOptions, StateKey, StateReader};
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

/// Newest block this node has executed: (height, global state root).
/// `(height, global_root)` of the newest executed block — shared with the
/// consensus payload builder and (via [`Node::exec_anchor`]) the RPC edge.
pub type ExecAnchor = Arc<Mutex<(u64, [u8; 32])>>;

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

    fn now_ms(&mut self) -> u64 {
        #[allow(clippy::expect_used)]
        let mut c = self.clock_ms.lock().expect("clock poisoned");
        *c += 1;
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
    SubmitTx(Transaction),
    Proposal(Proposal),
    Vote(Vote),
    TimeoutVote(TimeoutVote),
    Tc(TimeoutCert),
    Qc(QuorumCert),
    Batch { batch: Batch, from: u32 },
    Ack(BatchAck),
    ConsensusTimer(View),
    Flush,
}

/// Effects the node emits (the harness/p2p routes them).
#[allow(clippy::large_enum_variant)] // transient effect list; boxing buys nothing
#[derive(Debug, Clone)]
pub enum NodeOutput {
    Consensus(Action),
    BroadcastBatch(Batch),
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
}

pub struct Node {
    index: ValidatorIndex,
    chain_id: u64,
    consensus: ConsensusCore<Box<dyn LeaderElector>, NodePayloads>,
    worker: Worker,
    batch_store: Arc<std::sync::RwLock<BatchStore>>,
    pool: SharedCertPool,
    store: Arc<Store2>,
    forest: StateForest,
    exec_anchor: ExecAnchor,
    opts: ExecOptions,
    network: String,
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
    ) -> Self {
        let pool: SharedCertPool = Arc::new(Mutex::new(CertPool::new()));
        let exec_anchor: ExecAnchor = Arc::new(Mutex::new((0, [0u8; 32])));
        let clock_ms = Arc::new(Mutex::new(1_700_000_000_000u64));

        let payloads = NodePayloads {
            pool: Arc::clone(&pool),
            exec_anchor: Arc::clone(&exec_anchor),
            max_certs: tuning.max_certs_per_block,
            clock_ms,
        };
        let consensus = ConsensusCore::new(
            CoreConfig {
                chain_id,
                my_index: index,
                secret: clone_secret(&secret),
                committee,
                pacemaker,
            },
            elector,
            payloads,
        );

        let batch_store = Arc::new(std::sync::RwLock::new(BatchStore::new()));
        let worker = Worker::new(
            WorkerConfig {
                chain_id,
                my_index: index,
                worker_id: index,
                batch_max_bytes: tuning.batch_max_bytes,
                batch_max_txs: tuning.batch_max_txs,
                inbound_max_bytes: tuning.batch_max_bytes * 4,
                keys: validator_keys,
                secret,
            },
            Arc::clone(&batch_store),
        );

        // The initial forest is empty; genesis seeding is a node-layer
        // concern the harness performs via `seed_account`.
        Node {
            index,
            chain_id,
            consensus,
            worker,
            batch_store,
            pool,
            store: Arc::new(store),
            forest: StateForest::new(),
            exec_anchor,
            opts: ExecOptions::v2_defaults(),
            network,
        }
    }

    pub fn index(&self) -> ValidatorIndex {
        self.index
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

    /// Seed a genesis account into both store2 and the in-memory forest.
    pub fn seed_account(&mut self, key: &StateKey, value: &[u8]) {
        #[allow(clippy::expect_used)]
        self.store.seed_state(key, value).expect("seed");
        if let solidus_exec::StateSpace::Tree(tree) = key.space {
            self.forest.apply(tree, &key.key, value);
        }
        // Genesis root becomes the exec anchor at height 0.
        #[allow(clippy::expect_used)]
        let mut anchor = self.exec_anchor.lock().expect("anchor");
        anchor.1 = self.forest.global_root();
    }

    /// Boot consensus (enter view 1).
    pub fn start(&mut self) -> Vec<NodeOutput> {
        let actions = self.consensus.start();
        actions.into_iter().map(NodeOutput::Consensus).collect()
    }

    /// Drive one input event, returning the effects to route.
    pub fn step(&mut self, input: NodeInput) -> Vec<NodeOutput> {
        match input {
            NodeInput::SubmitTx(tx) => {
                let out = self.worker.on_submit_tx(tx);
                self.worker_out(out)
            }
            NodeInput::Batch { batch, from } => {
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
                let out = self.consensus.on_qc(qc);
                self.consensus_out(out)
            }
            NodeInput::ConsensusTimer(view) => {
                let out = self.consensus.on_local_timeout(view);
                self.consensus_out(out)
            }
        }
    }

    fn worker_out(
        &mut self,
        result: Result<Vec<WorkerAction>, solidus_mempool_dag::MempoolError>,
    ) -> Vec<NodeOutput> {
        let mut out = Vec::new();
        if let Ok(actions) = result {
            for action in actions {
                match action {
                    WorkerAction::BroadcastBatch(b) => out.push(NodeOutput::BroadcastBatch(b)),
                    WorkerAction::SendAck { to, ack } => out.push(NodeOutput::SendAck { to, ack }),
                    WorkerAction::CertFormed(cert) => {
                        #[allow(clippy::expect_used)]
                        self.pool.lock().expect("pool").add(cert);
                    }
                }
            }
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
        for action in actions {
            if let Action::Commit(committed) = &action {
                self.execute_committed(committed, &mut out);
            }
            out.push(NodeOutput::Consensus(action));
        }
        out
    }

    /// Resolve a committed block's batch certs → txs, run the two-lane
    /// executor against store2, persist, advance the exec anchor, retire
    /// the digests from the cert pool.
    fn execute_committed(&mut self, committed: &CommittedBlock, out: &mut Vec<NodeOutput>) {
        let Some(block) = self.consensus.block(&committed.hash).cloned() else {
            return; // body not present (sync gap) — node-layer fetch (later)
        };

        // Resolve tx bodies from worker-local storage in canonical order.
        let mut txs: Vec<Transaction> = Vec::new();
        let mut digests = Vec::new();
        {
            #[allow(clippy::expect_used)]
            let store = self.batch_store.read().expect("batch store");
            for cert in &block.header.batch_certs {
                match store.resolve(&cert.digest) {
                    Ok(batch) => {
                        txs.extend(batch.transactions);
                        digests.push(cert.digest);
                    }
                    Err(_) => return, // missing batch body — cannot execute yet
                }
            }
        }

        let ctx = BlockCtx {
            height: committed.height,
            timestamp_ms: committed.timestamp_ms,
            network: &self.network,
        };
        let Ok(outcome) = execute_block_twolane(&*self.store, &txs, &ctx, &self.opts) else {
            return;
        };

        // Incremental root over the committed delta.
        outcome.delta.apply_to_forest(&mut self.forest);
        let root = self.forest.global_root();

        #[allow(clippy::expect_used)]
        self.store
            .persist_block(
                committed.height,
                committed.hash,
                b"", // opaque block bytes: the consensus encoding (later)
                &outcome.delta,
                &outcome.receipts,
            )
            .expect("persist");

        {
            #[allow(clippy::expect_used)]
            let mut anchor = self.exec_anchor.lock().expect("anchor");
            *anchor = (committed.height, root);
        }
        {
            #[allow(clippy::expect_used)]
            self.pool.lock().expect("pool").on_committed(&digests);
        }

        out.push(NodeOutput::BlockExecuted {
            height: committed.height,
            tx_count: txs.len(),
            state_root: root,
        });
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

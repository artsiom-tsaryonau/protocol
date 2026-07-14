//! The event-driven worker: batches raw transactions, disseminates batch
//! bodies to peer workers, collects availability acks, and emits batch
//! certificates. Pure state machine — the node layer owns sockets and
//! flush timers (same shape as the consensus core).
//!
//! **Own-ack rule (regression-guarded):** sealing a batch immediately
//! records the worker's own availability signature — a quorum must never
//! depend on the originator's ack arriving over the network (the live
//! chain's own-vote TC-wedge lesson, generalized).

use std::collections::{BTreeMap, HashMap, HashSet};

use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey, BlsSignature};
use solidus_txns::types::Transaction;

use crate::store::SharedBatchStore;
use crate::types::{
    avail_message, availability_quorum, Batch, BatchAck, BatchCertificate, BatchDigest,
    MempoolError,
};

/// Worker configuration. One worker lane per validator at launch
/// (multi-lane scaling is a config change, not a design change).
pub struct WorkerConfig {
    pub chain_id: u64,
    /// This validator's committee index (signs acks with its BLS key).
    pub my_index: u32,
    /// Worker lane id.
    pub worker_id: u32,
    /// Seal a batch when its encoded size reaches this (target 1–2 MB).
    pub batch_max_bytes: usize,
    /// ... or when it holds this many transactions.
    pub batch_max_txs: usize,
    /// Reject peer batches larger than this (DoS bound).
    pub inbound_max_bytes: usize,
    /// Validator BLS public keys, committee-indexed.
    pub keys: Vec<BlsPublicKey>,
    pub secret: BlsSecretKey,
}

/// Network-facing effects of one worker event.
#[derive(Debug, Clone)]
pub enum WorkerAction {
    /// Send the sealed batch body to every peer worker (gossip/broadcast).
    BroadcastBatch(Batch),
    /// Ack a stored peer batch back to its originating worker.
    SendAck { to: u32, ack: BatchAck },
    /// A batch reached availability quorum — hand its certificate to the
    /// primary (local, in-process).
    CertFormed(BatchCertificate),
}

pub struct Worker {
    config: WorkerConfig,
    store: SharedBatchStore,
    /// Accumulating batch.
    current: Vec<Transaction>,
    current_bytes: usize,
    /// digest → collected (signer → sig) for batches we originated.
    pending_acks: HashMap<BatchDigest, BTreeMap<u32, BlsSignature>>,
    /// Batches we already certified (late acks are dropped).
    certified: HashSet<BatchDigest>,
}

impl Worker {
    pub fn new(config: WorkerConfig, store: SharedBatchStore) -> Self {
        Self {
            config,
            store,
            current: Vec::new(),
            current_bytes: 0,
            pending_acks: HashMap::new(),
            certified: HashSet::new(),
        }
    }

    /// Client-submitted transaction. Seals and disseminates a batch when a
    /// threshold trips.
    pub fn on_submit_tx(&mut self, tx: Transaction) -> Result<Vec<WorkerAction>, MempoolError> {
        #[allow(clippy::expect_used)]
        let tx_len =
            bincode::serialized_size(&tx).expect("Transaction bincode sizing cannot fail") as usize;
        self.current.push(tx);
        self.current_bytes += tx_len;

        if self.current_bytes >= self.config.batch_max_bytes
            || self.current.len() >= self.config.batch_max_txs
        {
            self.seal_batch()
        } else {
            Ok(vec![])
        }
    }

    /// Flush timer fired: seal whatever is pending (bounds batch latency
    /// under light load).
    pub fn on_flush(&mut self) -> Result<Vec<WorkerAction>, MempoolError> {
        if self.current.is_empty() {
            return Ok(vec![]);
        }
        self.seal_batch()
    }

    /// A peer worker's batch arrived: verify size + digest, store, ack.
    pub fn on_batch(
        &mut self,
        batch: Batch,
        from_validator: u32,
    ) -> Result<Vec<WorkerAction>, MempoolError> {
        let len = batch.encoded_len();
        if len > self.config.inbound_max_bytes {
            return Err(MempoolError::BatchTooLarge {
                got: len,
                max: self.config.inbound_max_bytes,
            });
        }
        let digest = batch.digest();
        {
            #[allow(clippy::expect_used)]
            let mut store = self.store.write().expect("batch store lock poisoned");
            store.insert_verified(batch, digest)?;
        }
        // The ack attests availability of the ORIGINATOR's batch, so it is
        // signed over the originating worker's lane — not ours. (Single
        // lane per validator at launch: lane id == originator index; a
        // multi-lane wire adds an explicit lane field alongside the batch.)
        let ack = self.make_ack(digest, from_validator);
        Ok(vec![WorkerAction::SendAck {
            to: from_validator,
            ack,
        }])
    }

    /// An availability ack for a batch we originated.
    pub fn on_ack(&mut self, ack: BatchAck) -> Result<Vec<WorkerAction>, MempoolError> {
        if self.certified.contains(&ack.digest) {
            return Ok(vec![]); // already certified; late ack
        }
        let Some(slot) = self.pending_acks.get_mut(&ack.digest) else {
            return Ok(vec![]); // not ours / unknown — ignore
        };

        let pk = self
            .config
            .keys
            .get(ack.signer as usize)
            .ok_or(MempoolError::UnknownValidator(ack.signer))?;
        let msg = avail_message(self.config.chain_id, &ack.digest, ack.worker);
        if !ack.sig.verify(pk, &msg) {
            return Err(MempoolError::InvalidAttestation(format!(
                "bad ack signature from validator {}",
                ack.signer
            )));
        }

        slot.insert(ack.signer, ack.sig);
        let quorum = availability_quorum(self.config.keys.len());
        if slot.len() < quorum {
            return Ok(vec![]);
        }

        let signer_sigs: Vec<(u32, BlsSignature)> =
            slot.iter().map(|(i, s)| (*i, s.clone())).collect();
        let cert = BatchCertificate::assemble(ack.digest, self.config.worker_id, &signer_sigs)?;
        self.pending_acks.remove(&ack.digest);
        self.certified.insert(ack.digest);
        Ok(vec![WorkerAction::CertFormed(cert)])
    }

    /// Sign an availability ack for `digest` on the given ORIGINATING
    /// worker lane.
    fn make_ack(&self, digest: BatchDigest, origin_worker: u32) -> BatchAck {
        let msg = avail_message(self.config.chain_id, &digest, origin_worker);
        BatchAck {
            digest,
            worker: origin_worker,
            signer: self.config.my_index,
            sig: self.config.secret.sign(&msg),
        }
    }

    fn seal_batch(&mut self) -> Result<Vec<WorkerAction>, MempoolError> {
        let batch = Batch {
            transactions: std::mem::take(&mut self.current),
        };
        self.current_bytes = 0;
        let digest = batch.digest();

        {
            #[allow(clippy::expect_used)]
            let mut store = self.store.write().expect("batch store lock poisoned");
            store.insert_verified(batch.clone(), digest)?;
        }

        // Own-ack first: our storage counts toward the quorum immediately.
        let own_ack = self.make_ack(digest, self.config.worker_id);
        let mut slot = BTreeMap::new();
        slot.insert(own_ack.signer, own_ack.sig);
        self.pending_acks.insert(digest, slot);

        Ok(vec![WorkerAction::BroadcastBatch(batch)])
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use solidus_crypto::keys::Address;
    use solidus_txns::types::TxPayload;

    use super::*;
    use crate::store::BatchStore;
    use crate::types::BatchResolver;

    fn tx(nonce: u64) -> Transaction {
        Transaction {
            sender_pubkey: [1u8; 32],
            nonce,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([2u8; 20]),
                amount: nonce + 1,
            },
            signature: [0u8; 64],
        }
    }

    fn setup(n: usize) -> (Vec<BlsSecretKey>, Vec<BlsPublicKey>) {
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let pks = keys.iter().map(|k| k.public_key()).collect();
        (keys, pks)
    }

    fn worker(i: u32, keys: &[BlsSecretKey], pks: &[BlsPublicKey]) -> (Worker, SharedBatchStore) {
        let store: SharedBatchStore = Arc::new(RwLock::new(BatchStore::new()));
        let w = Worker::new(
            WorkerConfig {
                chain_id: 2,
                my_index: i,
                worker_id: i,
                batch_max_bytes: 1_000_000,
                batch_max_txs: 4,
                inbound_max_bytes: 2_000_000,
                keys: pks.to_vec(),
                secret: BlsSecretKey::from_bytes(&keys[i as usize].to_bytes()).expect("clone key"),
            },
            Arc::clone(&store),
        );
        (w, store)
    }

    #[test]
    fn batch_seals_at_tx_threshold_and_certifies_with_own_ack_plus_quorum() {
        let (keys, pks) = setup(4);
        let (mut w0, store0) = worker(0, &keys, &pks);
        let (mut w1, _s1) = worker(1, &keys, &pks);
        let (mut w2, _s2) = worker(2, &keys, &pks);

        // 4 txs → seal.
        let mut actions = vec![];
        for i in 0..4 {
            actions = w0.on_submit_tx(tx(i)).expect("submit");
        }
        let batch = match &actions[..] {
            [WorkerAction::BroadcastBatch(b)] => b.clone(),
            other => panic!("expected BroadcastBatch, got {other:?}"),
        };
        let digest = batch.digest();
        assert!(
            store0.read().expect("lock").contains(&digest),
            "own store holds it"
        );

        // Peers store + ack.
        let a1 = match w1.on_batch(batch.clone(), 0).expect("peer 1")[..] {
            [WorkerAction::SendAck { to: 0, ref ack }] => ack.clone(),
            ref other => panic!("expected ack, got {other:?}"),
        };
        let a2 = match w2.on_batch(batch.clone(), 0).expect("peer 2")[..] {
            [WorkerAction::SendAck { to: 0, ref ack }] => ack.clone(),
            ref other => panic!("expected ack, got {other:?}"),
        };

        // Own ack + 2 remote = quorum 3 of 4 → cert forms on the 2nd
        // remote ack (the own-ack pin: only TWO network acks needed).
        assert!(w0.on_ack(a1).expect("ack1").is_empty());
        let cert = match w0.on_ack(a2).expect("ack2")[..] {
            [WorkerAction::CertFormed(ref c)] => c.clone(),
            ref other => panic!("expected cert, got {other:?}"),
        };
        cert.verify(2, &pks).expect("cert verifies");
        assert_eq!(cert.digest, digest);

        // The certified batch resolves from the shared store (BD-4 path).
        let resolved = store0
            .read()
            .expect("lock")
            .resolve(&digest)
            .expect("resolve");
        assert_eq!(resolved, batch);
    }

    #[test]
    fn flush_seals_partial_batch() {
        let (keys, pks) = setup(4);
        let (mut w0, _s) = worker(0, &keys, &pks);
        assert!(w0.on_flush().expect("empty flush").is_empty());
        w0.on_submit_tx(tx(0)).expect("submit");
        let actions = w0.on_flush().expect("flush");
        assert!(
            matches!(&actions[..], [WorkerAction::BroadcastBatch(b)] if b.transactions.len() == 1)
        );
    }

    #[test]
    fn oversized_inbound_batch_rejected() {
        let (keys, pks) = setup(4);
        let (w1, _s) = worker(1, &keys, &pks);
        let big = Batch {
            transactions: (0..10_000).map(tx).collect(),
        };
        let mut w1_small_limit = w1;
        w1_small_limit.config.inbound_max_bytes = 1_000;
        assert!(matches!(
            w1_small_limit.on_batch(big, 0),
            Err(MempoolError::BatchTooLarge { .. })
        ));
    }

    #[test]
    fn bad_ack_signature_rejected_and_duplicates_ignored() {
        let (keys, pks) = setup(4);
        let (mut w0, _s) = worker(0, &keys, &pks);
        let (mut w1, _s1) = worker(1, &keys, &pks);

        let mut actions = vec![];
        for i in 0..4 {
            actions = w0.on_submit_tx(tx(i)).expect("submit");
        }
        let batch = match &actions[..] {
            [WorkerAction::BroadcastBatch(b)] => b.clone(),
            other => panic!("unexpected {other:?}"),
        };
        let ack = match w1.on_batch(batch, 0).expect("peer")[..] {
            [WorkerAction::SendAck { ref ack, .. }] => ack.clone(),
            ref other => panic!("unexpected {other:?}"),
        };

        // Tampered signer claim → signature check fails.
        let mut forged = ack.clone();
        forged.signer = 2;
        assert!(w0.on_ack(forged).is_err());

        // Genuine ack, duplicated: second copy adds nothing.
        assert!(w0.on_ack(ack.clone()).expect("ok").is_empty());
        assert!(w0.on_ack(ack).expect("dup").is_empty());
    }
}

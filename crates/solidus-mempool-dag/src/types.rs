//! Frozen Stage-0 types (batch-certificate block format) + the Stage-2
//! availability-attestation format that fills the previously-opaque
//! `attestation` bytes.

use serde::{Deserialize, Serialize};
use solidus_crypto::bls::{BlsPublicKey, BlsSignature};
use solidus_crypto::hash::blake3_hash;
use solidus_txns::types::Transaction;

/// Content address of a worker batch: `BLAKE3(bincode(transactions))`.
/// This is what consensus orders — 32 bytes per batch, not the bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BatchDigest(pub [u8; 32]);

/// A worker batch of raw transactions (target size 1–2 MB serialized).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Batch {
    pub transactions: Vec<Transaction>,
}

impl Batch {
    /// Compute this batch's digest (v2 binary wire — bincode, R-WIRE).
    pub fn digest(&self) -> BatchDigest {
        #[allow(clippy::expect_used)]
        let bytes = bincode::serialize(&self.transactions)
            .expect("Vec<Transaction> bincode serialization cannot fail");
        BatchDigest(blake3_hash(&bytes))
    }

    /// Serialized size in bytes (worker batching threshold input).
    pub fn encoded_len(&self) -> usize {
        #[allow(clippy::expect_used)]
        let n = bincode::serialized_size(&self.transactions)
            .expect("Vec<Transaction> bincode sizing cannot fail");
        n as usize
    }
}

// ---------------------------------------------------------------------------
// Availability attestation (Stage-2 final format)
// ---------------------------------------------------------------------------

/// Message a validator BLS-signs to attest it durably stores `digest`
/// from `worker`. Identical for every attester of a given batch, so the
/// certificate aggregate verifies with `fast_aggregate_verify` (same
/// pattern as consensus votes/timeouts).
pub fn avail_message(chain_id: u64, digest: &BatchDigest, worker: u32) -> [u8; 32] {
    let mut buf = Vec::with_capacity(16 + 8 + 32 + 4);
    buf.extend_from_slice(b"SLDS2_AVAIL::");
    buf.extend_from_slice(&chain_id.to_le_bytes());
    buf.extend_from_slice(&digest.0);
    buf.extend_from_slice(&worker.to_le_bytes());
    blake3_hash(&buf)
}

/// The decoded content of `BatchCertificate::attestation`: sorted unique
/// validator indices + their BLS aggregate over [`avail_message`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub signers: Vec<u32>,
    pub agg_sig: BlsSignature,
}

/// Availability quorum: same BFT quorum as consensus, `⌈(n+f+1)/2⌉` with
/// `f = ⌊(n−1)/3⌋`. This is ≥ 2f+1 for every n, so a certified batch is
/// held by ≥ f+1 honest validators — retrievability is guaranteed. One
/// quorum concept across the stack keeps the audit story simple.
pub fn availability_quorum(n: usize) -> usize {
    let f = n.saturating_sub(1) / 3;
    (n + f + 2) / 2
}

/// Errors from certificate verification / batch handling.
#[derive(thiserror::Error, Debug)]
pub enum MempoolError {
    #[error("attestation malformed: {0}")]
    InvalidAttestation(String),

    #[error("unknown validator index {0}")]
    UnknownValidator(u32),

    #[error("batch exceeds size limit: {got} > {max} bytes")]
    BatchTooLarge { got: usize, max: usize },

    #[error("batch bytes do not match declared digest")]
    DigestMismatch,

    #[error("bls error: {0}")]
    Bls(#[from] solidus_crypto::bls::BlsError),
}

/// Availability certificate for one batch: proof that a quorum of
/// validators holds the batch bytes, so ordering its digest cannot point
/// at unavailable data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchCertificate {
    pub digest: BatchDigest,
    /// Worker lane that produced the batch.
    pub worker: u32,
    /// bincode-encoded [`Attestation`] (kept as bytes at the consensus
    /// boundary so consensus never depends on the attestation internals).
    pub attestation: Vec<u8>,
}

impl BatchCertificate {
    /// Assemble a certificate from collected `(signer, sig)` pairs
    /// (sorted by signer index; caller guarantees quorum).
    pub fn assemble(
        digest: BatchDigest,
        worker: u32,
        signer_sigs: &[(u32, BlsSignature)],
    ) -> Result<Self, MempoolError> {
        if signer_sigs.is_empty() {
            return Err(MempoolError::InvalidAttestation("no signers".into()));
        }
        let signers: Vec<u32> = signer_sigs.iter().map(|(i, _)| *i).collect();
        let sigs: Vec<&BlsSignature> = signer_sigs.iter().map(|(_, s)| s).collect();
        let agg_sig = BlsSignature::aggregate(&sigs)?;
        let attestation = Attestation { signers, agg_sig };
        #[allow(clippy::expect_used)]
        let bytes = bincode::serialize(&attestation).expect("Attestation bincode cannot fail");
        Ok(Self {
            digest,
            worker,
            attestation: bytes,
        })
    }

    /// Verify the availability attestation against the validator set.
    pub fn verify(&self, chain_id: u64, keys: &[BlsPublicKey]) -> Result<(), MempoolError> {
        let attestation: Attestation = bincode::deserialize(&self.attestation)
            .map_err(|e| MempoolError::InvalidAttestation(e.to_string()))?;

        if attestation.signers.windows(2).any(|w| w[0] >= w[1]) {
            return Err(MempoolError::InvalidAttestation(
                "signers not sorted/unique".into(),
            ));
        }
        let quorum = availability_quorum(keys.len());
        if attestation.signers.len() < quorum {
            return Err(MempoolError::InvalidAttestation(format!(
                "{} signers < availability quorum {}",
                attestation.signers.len(),
                quorum
            )));
        }
        let mut pks = Vec::with_capacity(attestation.signers.len());
        for &idx in &attestation.signers {
            pks.push(
                keys.get(idx as usize)
                    .ok_or(MempoolError::UnknownValidator(idx))?,
            );
        }
        let msg = avail_message(chain_id, &self.digest, self.worker);
        if !attestation.agg_sig.fast_aggregate_verify(&pks, &msg) {
            return Err(MempoolError::InvalidAttestation(
                "aggregate verification failed".into(),
            ));
        }
        Ok(())
    }
}

/// A single validator's availability acknowledgement, sent back to the
/// batch's originating worker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchAck {
    pub digest: BatchDigest,
    pub worker: u32,
    pub signer: u32,
    pub sig: BlsSignature,
}

/// Errors surfaced when resolving batch bodies for execution.
#[derive(thiserror::Error, Debug)]
pub enum ResolveError {
    /// The digest is not present in worker-local storage (availability
    /// violation — a certified batch must be fetchable; triggers repair
    /// from peers in the node layer).
    #[error("certified batch not found locally: {0:?}")]
    NotFound(BatchDigest),
}

/// The executor's read interface into the mempool's batch store (BD-4).
/// `execute_block` resolves each certificate's body in canonical order and
/// concatenates the transactions into the block's tx list.
pub trait BatchResolver {
    fn resolve(&self, digest: &BatchDigest) -> Result<Batch, ResolveError>;
}

#[cfg(test)]
mod tests {
    use solidus_crypto::bls::BlsSecretKey;

    use super::*;

    #[test]
    fn batch_digest_is_deterministic_and_content_sensitive() {
        let batch = Batch {
            transactions: vec![],
        };
        assert_eq!(batch.digest(), batch.digest());

        let batch2 = Batch {
            transactions: vec![Transaction {
                sender_pubkey: [1u8; 32],
                nonce: 0,
                payload: solidus_txns::types::TxPayload::Stake { amount: 1 },
                signature: [0u8; 64],
            }],
        };
        assert_ne!(batch.digest(), batch2.digest());
    }

    #[test]
    fn certificate_roundtrips_bincode() {
        let cert = BatchCertificate {
            digest: BatchDigest([7u8; 32]),
            worker: 3,
            attestation: vec![1, 2, 3],
        };
        let bytes = bincode::serialize(&cert).expect("serialize");
        let back: BatchCertificate = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(cert, back);
    }

    #[test]
    fn availability_quorum_matches_consensus_quorum_and_covers_retrievability() {
        for (n, q) in [(4usize, 3usize), (7, 5), (10, 7), (21, 14)] {
            assert_eq!(availability_quorum(n), q, "n={n}");
            let f = (n - 1) / 3;
            assert!(q > 2 * f, "n={n}: q={q} must guarantee f+1 honest holders");
        }
    }

    #[test]
    fn attestation_assemble_verify_roundtrip() {
        let n = 4;
        let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
        let pks: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let chain_id = 2;
        let digest = BatchDigest([9u8; 32]);
        let worker = 0;

        let msg = avail_message(chain_id, &digest, worker);
        let signer_sigs: Vec<(u32, BlsSignature)> = (0..3u32)
            .map(|i| (i, keys[i as usize].sign(&msg)))
            .collect();
        let cert = BatchCertificate::assemble(digest, worker, &signer_sigs).expect("assemble");
        cert.verify(chain_id, &pks).expect("verify");

        // Wrong chain id → different message → fail.
        assert!(cert.verify(9, &pks).is_err());

        // Sub-quorum rejected.
        let small = BatchCertificate::assemble(digest, worker, &signer_sigs[..2]).expect("ok");
        assert!(small.verify(chain_id, &pks).is_err());
    }
}

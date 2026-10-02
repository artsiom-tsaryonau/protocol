use bitvec::prelude::*;
use serde::{Deserialize, Serialize};
use solidus_crypto::bls::{BlsPublicKey, BlsSignature};
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use solidus_crypto::vrf::VrfProof;
use solidus_txns::types::Transaction;

// ---------------------------------------------------------------------------
// BlockHeader
// ---------------------------------------------------------------------------

/// Header of a committed block. Contains metadata sufficient to verify block
/// integrity without downloading the full transaction list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// The sequential block number (0 = genesis).
    pub height: u64,
    /// The consensus round in which this block was proposed.
    pub round: u64,
    /// Hash of the parent block header (all zeros for genesis).
    pub parent_hash: [u8; 32],
    /// Global state root after executing all transactions in this block.
    pub state_root: [u8; 32],
    /// Merkle root of the transaction hashes in this block.
    pub transactions_root: [u8; 32],
    /// Unix timestamp in milliseconds when the block was proposed.
    pub timestamp_ms: u64,
    /// Number of transactions included in this block.
    pub tx_count: u32,
    /// Address of the validator that proposed this block.
    pub proposer: Address,
}

impl BlockHeader {
    /// Compute the content-address of this header.
    ///
    /// `BLAKE3(serde_json(self))`
    pub fn hash(&self) -> [u8; 32] {
        // Infallible: BlockHeader is a fixed-shape POD struct (u64s,
        // [u8;32]s, Address newtype, u32). No serde impl on its fields
        // can return an error. The `expect` is documenting an invariant
        // and acts as a tripwire if the struct ever widens to include a
        // fallible-to-serialize type.
        #[allow(clippy::expect_used)]
        let bytes = serde_json::to_vec(self).expect("header serialization (POD)");
        blake3_hash(&bytes)
    }
}

// ---------------------------------------------------------------------------
// Block
// ---------------------------------------------------------------------------

/// A complete block: header + ordered list of transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block metadata.
    pub header: BlockHeader,
    /// Ordered list of transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// Quorum certificate from the parent block (None for genesis).
    pub parent_qc: Option<QuorumCertificate>,
    /// VRF proof from the proposer for leader election (None for genesis / single-node).
    pub vrf_proof: Option<VrfProof>,
}

impl Block {
    /// Content-address of the block (delegates to header hash).
    pub fn hash(&self) -> [u8; 32] {
        self.header.hash()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute the transactions root from an ordered slice of transactions.
///
/// The root is `BLAKE3(tx0_hash || tx1_hash || ... || txN_hash)`.
/// Returns `[0u8; 32]` for an empty slice.
pub fn compute_transactions_root(transactions: &[Transaction]) -> [u8; 32] {
    let mut data = Vec::new();
    for tx in transactions {
        data.extend_from_slice(&tx.hash());
    }
    if data.is_empty() {
        [0u8; 32]
    } else {
        blake3_hash(&data)
    }
}

// ---------------------------------------------------------------------------
// ValidatorIdentity
// ---------------------------------------------------------------------------

/// Identity of a validator in the consensus committee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorIdentity {
    /// The validator's on-chain address.
    pub address: Address,
    /// The validator's Ed25519 public key (32 bytes).
    pub ed25519_pubkey: [u8; 32],
    /// The validator's BLS12-381 public key for aggregate signatures.
    pub bls_pubkey: BlsPublicKey,
}

// ---------------------------------------------------------------------------
// Vote
// ---------------------------------------------------------------------------

/// A validator's vote on a proposed block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Hash of the block being voted on.
    pub block_hash: [u8; 32],
    /// The consensus round of the vote.
    pub round: u64,
    /// Index of the voter in the committee.
    pub voter_index: usize,
    /// BLS signature over the block hash.
    pub bls_signature: BlsSignature,
}

// ---------------------------------------------------------------------------
// QuorumCertificate
// ---------------------------------------------------------------------------

/// Quorum Certificate — aggregated proof that >= quorum validators voted for a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Hash of the certified block.
    pub block_hash: [u8; 32],
    /// The consensus round.
    pub round: u64,
    /// Aggregated BLS signature from all signers.
    pub aggregate_sig: BlsSignature,
    /// Bitvector indicating which committee members signed.
    pub signers: BitVec<u8, Msb0>,
}

impl QuorumCertificate {
    /// Return the number of validators that signed this QC.
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }

    /// Verify this QC: the aggregate signature is valid over `block_hash` for the
    /// pubkeys of the signers indicated by `signers`, and at least `quorum`
    /// validators signed. `validators` is the committee, indexed by signer bit.
    pub fn verify(&self, validators: &[ValidatorIdentity], quorum: usize) -> bool {
        if self.signer_count() < quorum {
            return false;
        }
        let mut signer_pks: Vec<&BlsPublicKey> = Vec::with_capacity(self.signer_count());
        for i in self.signers.iter_ones() {
            match validators.get(i) {
                Some(v) => signer_pks.push(&v.bls_pubkey),
                None => return false, // signer index out of range
            }
        }
        if signer_pks.is_empty() {
            return false;
        }
        self.aggregate_sig
            .fast_aggregate_verify(&signer_pks, &self.block_hash)
    }

    /// Compute the content-address of this QC.
    pub fn hash(&self) -> [u8; 32] {
        // Infallible: QuorumCertificate's serde shape (block_hash + round +
        // aggregate_sig bytes + signers bitvec) is POD. Same tripwire
        // rationale as `BlockHeader::hash`.
        #[allow(clippy::expect_used)]
        let bytes = serde_json::to_vec(self).expect("QC serializable (POD)");
        blake3_hash(&bytes)
    }
}

// ---------------------------------------------------------------------------
// TimeoutVote
// ---------------------------------------------------------------------------

/// A validator's timeout vote when no QC is received in time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutVote {
    /// The round that timed out.
    pub round: u64,
    /// Index of the voter in the committee.
    pub voter_index: usize,
    /// The highest QC the voter has seen (if any).
    pub highest_qc: Option<QuorumCertificate>,
    /// BLS signature over the timeout message.
    pub bls_signature: BlsSignature,
}

impl TimeoutVote {
    /// The exact bytes a validator signs when it times out on `round`.
    ///
    /// This existed only as a `format!` literal inside the node's pacemaker
    /// loop, so the message was defined by whoever produced it and the unit
    /// tests signed something else entirely (`round.to_le_bytes()`). Nothing
    /// noticed, because nothing verified. A signature scheme needs ONE
    /// definition of what is signed, in the type that carries it.
    pub fn signing_bytes(round: u64) -> Vec<u8> {
        format!("timeout_{round}").into_bytes()
    }
}

// ---------------------------------------------------------------------------
// TimeoutCertificate
// ---------------------------------------------------------------------------

/// Timeout Certificate — proof that >= quorum validators timed out on a round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutCertificate {
    /// The round that timed out.
    pub round: u64,
    /// Aggregated BLS signature from all timeout voters.
    pub aggregate_sig: BlsSignature,
    /// Bitvector indicating which committee members sent timeout votes.
    pub signers: BitVec<u8, Msb0>,
    /// The highest QC seen among timeout voters (if any).
    pub highest_qc: Option<QuorumCertificate>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::bls::BlsSecretKey;
    use solidus_crypto::ed25519::generate_signing_key;
    use solidus_crypto::keys::Address;

    #[test]
    fn empty_transactions_root() {
        let root = compute_transactions_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn block_header_hash_deterministic() {
        let header = BlockHeader {
            height: 1,
            round: 0,
            parent_hash: [0u8; 32],
            state_root: [1u8; 32],
            transactions_root: [2u8; 32],
            timestamp_ms: 1_700_000_000_000,
            tx_count: 5,
            proposer: Address::from_bytes([0u8; 20]),
        };

        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2);

        // Changing any field should change the hash.
        let mut header2 = header.clone();
        header2.height = 2;
        assert_ne!(header.hash(), header2.hash());
    }

    #[test]
    fn qc_signer_count() {
        use solidus_crypto::bls::BlsSecretKey;

        let sk = BlsSecretKey::generate();
        let sig = sk.sign(b"test");

        // 4-member committee, 3 of which signed
        let mut signers = bitvec![u8, Msb0; 0; 4];
        signers.set(0, true);
        signers.set(1, true);
        signers.set(2, true);
        // index 3 did not sign

        let qc = QuorumCertificate {
            block_hash: [0xAA; 32],
            round: 1,
            aggregate_sig: sig,
            signers,
        };

        assert_eq!(qc.signer_count(), 3);
    }

    #[test]
    fn qc_hash_deterministic() {
        use solidus_crypto::bls::BlsSecretKey;

        let sk = BlsSecretKey::generate();
        let sig = sk.sign(b"determinism");

        let mut signers = bitvec![u8, Msb0; 0; 4];
        signers.set(0, true);
        signers.set(2, true);

        let qc = QuorumCertificate {
            block_hash: [0xBB; 32],
            round: 5,
            aggregate_sig: sig,
            signers,
        };

        let h1 = qc.hash();
        let h2 = qc.hash();
        assert_eq!(h1, h2);
    }

    fn validators_and_keys(n: usize) -> (Vec<ValidatorIdentity>, Vec<BlsSecretKey>) {
        let mut vals = Vec::new();
        let mut bls = Vec::new();
        for _ in 0..n {
            let ed = generate_signing_key();
            let bsk = BlsSecretKey::generate();
            vals.push(ValidatorIdentity {
                address: Address::from_public_key(&ed.verifying_key()),
                ed25519_pubkey: ed.verifying_key().to_bytes(),
                bls_pubkey: bsk.public_key(),
            });
            bls.push(bsk);
        }
        (vals, bls)
    }

    fn qc_over(
        block_hash: [u8; 32],
        round: u64,
        signers_idx: &[usize],
        bls: &[BlsSecretKey],
        n: usize,
    ) -> QuorumCertificate {
        let sigs: Vec<_> = signers_idx
            .iter()
            .map(|&i| bls[i].sign(&block_hash))
            .collect();
        let refs: Vec<&BlsSignature> = sigs.iter().collect();
        let aggregate_sig = BlsSignature::aggregate(&refs).expect("aggregate");
        let mut signers = bitvec![u8, Msb0; 0; n];
        for &i in signers_idx {
            signers.set(i, true);
        }
        QuorumCertificate {
            block_hash,
            round,
            aggregate_sig,
            signers,
        }
    }

    // The bytes a validator signs on timeout are a WIRE FORMAT: every node must
    // produce the identical string or their signatures stop aggregating and the
    // network cannot change round. It lived as a `format!` literal in the
    // node's pacemaker loop until 2026-08-24, so pin it here -- a refactor that
    // "tidies" this string desyncs a mixed-version network silently.
    #[test]
    fn timeout_signing_bytes_are_the_deployed_format() {
        assert_eq!(
            TimeoutVote::signing_bytes(7),
            b"timeout_7".to_vec(),
            "the signed message must stay byte-identical to the deployed literal"
        );
        assert_ne!(
            TimeoutVote::signing_bytes(7),
            TimeoutVote::signing_bytes(8),
            "the round must be bound into the signature"
        );
    }

    #[test]
    fn qc_verify_accepts_quorum_signed() {
        let (vals, bls) = validators_and_keys(4);
        let qc = qc_over([7u8; 32], 0, &[0, 1, 2], &bls, 4);
        assert!(qc.verify(&vals, 3), "valid 3-of-4 QC must verify");
    }

    #[test]
    fn qc_verify_rejects_below_quorum() {
        let (vals, bls) = validators_and_keys(4);
        let qc = qc_over([7u8; 32], 0, &[0, 1], &bls, 4);
        assert!(!qc.verify(&vals, 3), "2 signers < quorum 3 must fail");
    }

    #[test]
    fn qc_verify_rejects_wrong_block_hash() {
        let (vals, bls) = validators_and_keys(4);
        let mut qc = qc_over([7u8; 32], 0, &[0, 1, 2], &bls, 4);
        qc.block_hash = [9u8; 32];
        assert!(
            !qc.verify(&vals, 3),
            "aggregate over a different hash must fail"
        );
    }

    #[test]
    fn vote_serialization_roundtrip() {
        use solidus_crypto::bls::BlsSecretKey;

        let sk = BlsSecretKey::generate();
        let sig = sk.sign(b"vote message");

        let vote = Vote {
            block_hash: [0xCC; 32],
            round: 42,
            voter_index: 7,
            bls_signature: sig,
        };

        let json = serde_json::to_string(&vote).expect("serialize vote");
        let deserialized: Vote = serde_json::from_str(&json).expect("deserialize vote");

        assert_eq!(deserialized.block_hash, vote.block_hash);
        assert_eq!(deserialized.round, vote.round);
        assert_eq!(deserialized.voter_index, vote.voter_index);
        assert_eq!(deserialized.bls_signature, vote.bls_signature);
    }
}

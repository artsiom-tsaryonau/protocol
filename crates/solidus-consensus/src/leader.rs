//! VRF-based leader election for the Solidus consensus engine.
//!
//! Each validator computes a VRF output for a given round using its Ed25519
//! signing key. The validator with the lowest u64-decoded output wins the
//! round and becomes the block proposer.

use ed25519_dalek::SigningKey;
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::vrf::{vrf_output_to_u64, vrf_prove, vrf_verify, VrfOutput, VrfProof};

use crate::types::ValidatorIdentity;

// ---------------------------------------------------------------------------
// Output type
// ---------------------------------------------------------------------------

/// Result of a local VRF leader election computation.
pub struct LeaderElection {
    /// Index of this validator in the committee (not necessarily the winner).
    pub leader_index: usize,
    /// This validator's VRF output for the round.
    pub vrf_output: VrfOutput,
    /// Proof that the VRF output was computed correctly.
    pub vrf_proof: VrfProof,
}

// ---------------------------------------------------------------------------
// VRF input derivation
// ---------------------------------------------------------------------------

/// Compute the VRF input for a given round.
///
/// `input = BLAKE3(round_seed || round_le_bytes)`
///
/// Using both the seed (derived from the previous block's VRF output or
/// genesis seed) and the round number ensures inputs are unique across rounds
/// even if the seed does not change (e.g., during view changes).
pub fn vrf_input(round_seed: &[u8; 32], round: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(40);
    buf.extend_from_slice(round_seed);
    buf.extend_from_slice(&round.to_le_bytes());
    blake3_hash(&buf)
}

// ---------------------------------------------------------------------------
// Local election — called by the node to produce its own VRF output
// ---------------------------------------------------------------------------

/// Compute this node's VRF output and proof for a round.
///
/// The returned [`LeaderElection`] contains the validator's own index and
/// VRF material. Whether this node actually won is determined by calling
/// [`select_leader_from_outputs`] once all validators' outputs are collected.
pub fn elect_leader(
    sk: &SigningKey,
    my_index: usize,
    _validators: &[ValidatorIdentity],
    round_seed: &[u8; 32],
    round: u64,
) -> LeaderElection {
    let input = vrf_input(round_seed, round);
    let (my_output, my_proof) = vrf_prove(sk, &input);
    LeaderElection {
        leader_index: my_index,
        vrf_output: my_output,
        vrf_proof: my_proof,
    }
}

// ---------------------------------------------------------------------------
// Remote verification — called when receiving another validator's claim
// ---------------------------------------------------------------------------

/// Verify that a given validator was the legitimate leader for a round.
///
/// Returns `true` only if `proof` is a valid VRF proof for the computed
/// round input under the validator's Ed25519 public key, and `claimed_output`
/// matches `BLAKE3(proof)`.
///
/// # Panics
///
/// Panics if `validator.ed25519_pubkey` is not a valid Ed25519 public key.
/// All keys stored in `ValidatorIdentity` are validated on admission, so this
/// should never occur in practice.
pub fn verify_leader(
    validator: &ValidatorIdentity,
    round_seed: &[u8; 32],
    round: u64,
    claimed_output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let input = vrf_input(round_seed, round);
    // A malformed ed25519 pubkey in the validator identity record means
    // the claimed identity is bogus -> the leader election simply fails
    // verification rather than panicking the node. Real production validators
    // pass through genesis/staking-tx validation which already enforces
    // pubkey validity; this guards against bad in-memory entries (e.g. a
    // forked state corruption surfacing through this read path).
    let pk = match ed25519_dalek::VerifyingKey::from_bytes(&validator.ed25519_pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    vrf_verify(&pk, &input, claimed_output, proof)
}

// ---------------------------------------------------------------------------
// Leader selection — lowest u64 wins
// ---------------------------------------------------------------------------

/// Given VRF outputs from all validators, determine the leader (lowest score).
///
/// The leader is the validator whose `VrfOutput`, interpreted as a
/// little-endian `u64` (first 8 bytes), is smallest. This is deterministic
/// given the same set of outputs.
///
/// # Panics
///
/// Panics if `outputs` is empty. The caller must ensure the validator set is
/// non-empty before calling this function.
pub fn select_leader_from_outputs(outputs: &[(usize, VrfOutput)]) -> usize {
    // Empty outputs is a caller-side bug, not a network-input failure:
    // `validators` in HotStuffEngine is built from genesis/staking-tx data
    // which always has ≥1 validator. The expect is documented as a precondition
    // (see #Panics above) and we keep it as an assertion to flag a logic bug
    // immediately rather than silently returning a wrong leader.
    #[allow(clippy::expect_used)]
    outputs
        .iter()
        .min_by_key(|(_, out)| vrf_output_to_u64(out))
        .map(|(idx, _)| *idx)
        .expect("non-empty validator set (caller precondition)")
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

    // -----------------------------------------------------------------------
    // Test helper
    // -----------------------------------------------------------------------

    fn make_validators(n: usize) -> (Vec<SigningKey>, Vec<ValidatorIdentity>) {
        let mut sks = Vec::new();
        let mut validators = Vec::new();
        for _ in 0..n {
            let sk = generate_signing_key();
            let bls_sk = BlsSecretKey::generate();
            validators.push(ValidatorIdentity {
                address: Address::from_public_key(&sk.verifying_key()),
                ed25519_pubkey: sk.verifying_key().to_bytes(),
                bls_pubkey: bls_sk.public_key(),
            });
            sks.push(sk);
        }
        (sks, validators)
    }

    // -----------------------------------------------------------------------
    // vrf_input tests
    // -----------------------------------------------------------------------

    #[test]
    fn vrf_input_deterministic() {
        let seed = [0x42u8; 32];
        let round = 7u64;
        let input1 = vrf_input(&seed, round);
        let input2 = vrf_input(&seed, round);
        assert_eq!(input1, input2);
    }

    #[test]
    fn vrf_input_differs_by_round() {
        let seed = [0x11u8; 32];
        let input_r1 = vrf_input(&seed, 1);
        let input_r2 = vrf_input(&seed, 2);
        assert_ne!(input_r1, input_r2);
    }

    // -----------------------------------------------------------------------
    // elect_leader / verify_leader tests
    // -----------------------------------------------------------------------

    #[test]
    fn elect_leader_produces_valid_proof() {
        let (sks, validators) = make_validators(4);
        let seed = [0xABu8; 32];
        let round = 3u64;

        let election = elect_leader(&sks[0], 0, &validators, &seed, round);
        assert!(verify_leader(
            &validators[0],
            &seed,
            round,
            &election.vrf_output,
            &election.vrf_proof,
        ));
    }

    #[test]
    fn verify_leader_rejects_wrong_validator() {
        let (sks, validators) = make_validators(4);
        let seed = [0xCDu8; 32];
        let round = 5u64;

        // Compute election for validator 0 but verify against validator 1.
        let election = elect_leader(&sks[0], 0, &validators, &seed, round);
        assert!(!verify_leader(
            &validators[1], // wrong validator
            &seed,
            round,
            &election.vrf_output,
            &election.vrf_proof,
        ));
    }

    // -----------------------------------------------------------------------
    // select_leader_from_outputs tests
    // -----------------------------------------------------------------------

    #[test]
    fn select_leader_picks_lowest_score() {
        let (sks, validators) = make_validators(4);
        let seed = [0x77u8; 32];
        let round = 1u64;

        // Collect all four outputs.
        let outputs: Vec<(usize, VrfOutput)> = sks
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let election = elect_leader(sk, i, &validators, &seed, round);
                (i, election.vrf_output)
            })
            .collect();

        let winner = select_leader_from_outputs(&outputs);

        // Verify the winner truly has the minimum u64 score.
        let winner_score = vrf_output_to_u64(&outputs[winner].1);
        for (_, out) in &outputs {
            assert!(winner_score <= vrf_output_to_u64(out));
        }
    }

    #[test]
    fn different_rounds_different_leaders_usually() {
        let (sks, validators) = make_validators(4);
        let seed = [0x55u8; 32];

        let leaders: Vec<usize> = (0..20u64)
            .map(|round| {
                let outputs: Vec<(usize, VrfOutput)> = sks
                    .iter()
                    .enumerate()
                    .map(|(i, sk)| {
                        let e = elect_leader(sk, i, &validators, &seed, round);
                        (i, e.vrf_output)
                    })
                    .collect();
                select_leader_from_outputs(&outputs)
            })
            .collect();

        // With 4 validators and 20 rounds, we expect at least 2 different leaders.
        let unique: std::collections::HashSet<usize> = leaders.into_iter().collect();
        assert!(
            unique.len() >= 2,
            "Expected at least 2 distinct leaders over 20 rounds, got {:?}",
            unique
        );
    }
}

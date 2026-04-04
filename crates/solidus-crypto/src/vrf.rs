//! Ed25519-based Verifiable Random Function (VRF).
//!
//! Construction:
//! - `output = BLAKE3(Ed25519_sign(sk, input))`
//! - `proof  = Ed25519_sign(sk, input)` (the 64-byte signature itself)
//!
//! Verification: check `Ed25519_verify(pk, input, proof)` AND `output == BLAKE3(proof)`.
//!
//! This is valid because Ed25519 signatures are deterministic (RFC 8032): the same
//! key + input always produces the same signature. The output is pseudorandom —
//! BLAKE3 of a valid signature is unpredictable without `sk`. Anyone with the
//! public key can verify the proof.

use crate::hash::blake3_hash;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The 32-byte pseudorandom output of a VRF evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput(pub [u8; 32]);

/// The 64-byte proof that a [`VrfOutput`] was computed correctly.
///
/// Serializes / deserializes as a lowercase hex string because `serde` cannot
/// derive `Serialize`/`Deserialize` for `[u8; 64]` out of the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfProof(pub [u8; 64]);

impl Serialize for VrfProof {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for VrfProof {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("VRF proof must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Produce a VRF output and proof for `input` using signing key `sk`.
///
/// Both the output and the proof are deterministic for the same `(sk, input)` pair.
pub fn vrf_prove(sk: &SigningKey, input: &[u8]) -> (VrfOutput, VrfProof) {
    let sig = sk.sign(input);
    let sig_bytes = sig.to_bytes();
    let output = VrfOutput(blake3_hash(&sig_bytes));
    let proof = VrfProof(sig_bytes);
    (output, proof)
}

/// Verify that `output` was computed correctly from `input` using the secret key
/// corresponding to `pk`.
///
/// Returns `true` only if:
/// 1. `proof` is a valid Ed25519 signature of `input` under `pk`, and
/// 2. `output == BLAKE3(proof)`.
pub fn vrf_verify(
    pk: &VerifyingKey,
    input: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> bool {
    let sig = Signature::from_bytes(&proof.0);
    if pk.verify(input, &sig).is_err() {
        return false;
    }
    output.0 == blake3_hash(&proof.0)
}

/// Convert a [`VrfOutput`] to a `u64` by reading the first 8 bytes as
/// little-endian. Used for deterministic leader ranking.
pub fn vrf_output_to_u64(output: &VrfOutput) -> u64 {
    u64::from_le_bytes(output.0[..8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::generate_signing_key;

    #[test]
    fn prove_and_verify_roundtrip() {
        let sk = generate_signing_key();
        let pk = sk.verifying_key();
        let input = b"solidus vrf test";
        let (output, proof) = vrf_prove(&sk, input);
        assert!(vrf_verify(&pk, input, &output, &proof));
    }

    #[test]
    fn deterministic_output() {
        let sk = generate_signing_key();
        let input = b"same input every time";
        let (out1, proof1) = vrf_prove(&sk, input);
        let (out2, proof2) = vrf_prove(&sk, input);
        assert_eq!(out1, out2);
        assert_eq!(proof1.0, proof2.0);
    }

    #[test]
    fn different_inputs_different_outputs() {
        let sk = generate_signing_key();
        let (out1, _) = vrf_prove(&sk, b"input alpha");
        let (out2, _) = vrf_prove(&sk, b"input beta");
        assert_ne!(out1, out2);
    }

    #[test]
    fn different_keys_different_outputs() {
        let sk1 = generate_signing_key();
        let sk2 = generate_signing_key();
        let input = b"shared input";
        let (out1, _) = vrf_prove(&sk1, input);
        let (out2, _) = vrf_prove(&sk2, input);
        assert_ne!(out1, out2);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk = generate_signing_key();
        let wrong_sk = generate_signing_key();
        let wrong_pk = wrong_sk.verifying_key();
        let input = b"test message";
        let (output, proof) = vrf_prove(&sk, input);
        assert!(!vrf_verify(&wrong_pk, input, &output, &proof));
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let sk = generate_signing_key();
        let pk = sk.verifying_key();
        let (output, proof) = vrf_prove(&sk, b"original input");
        assert!(!vrf_verify(&pk, b"tampered input", &output, &proof));
    }

    #[test]
    fn verify_rejects_tampered_output() {
        let sk = generate_signing_key();
        let pk = sk.verifying_key();
        let input = b"some data";
        let (mut output, proof) = vrf_prove(&sk, input);
        // Flip a bit in the output
        output.0[0] ^= 0xff;
        assert!(!vrf_verify(&pk, input, &output, &proof));
    }

    #[test]
    fn output_to_u64_is_deterministic() {
        let sk = generate_signing_key();
        let input = b"leader election seed";
        let (output, _) = vrf_prove(&sk, input);
        let v1 = vrf_output_to_u64(&output);
        let v2 = vrf_output_to_u64(&output);
        assert_eq!(v1, v2);
    }
}

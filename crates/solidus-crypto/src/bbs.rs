//! BBS+ selective-disclosure signatures.
//!
//! Wraps [`zkryptium`](https://crates.io/crates/zkryptium) (Cybersecurity-LINKS,
//! Apache-2.0) which implements the IRTF draft `draft-irtf-cfrg-bbs-signatures`
//! over BLS12-381. The ciphersuite pinned here is `BLS12-381-SHA-256` per the
//! draft. This module exposes a Solidus-shaped API mirroring the conventions of
//! the `bls` module (behind the `consensus` feature).
//!
//! Status: testnet-grade. External audit is pending and tracked under the
//! NLnet NGI Zero proposal. Do NOT use this for production-grade key material
//! until the audit completes.

use rand::RngCore;
use serde::{Deserialize, Serialize};
use zkryptium::{
    bbsplus::{
        ciphersuites::Bls12381Sha256,
        keys::{BBSplusPublicKey, BBSplusSecretKey},
    },
    keys::pair::KeyPair,
    schemes::{
        algorithms::BBSplus,
        generics::{PoKSignature, Signature},
    },
};

/// The ciphersuite Solidus uses for all BBS+ operations.
type BbsScheme = BBSplus<Bls12381Sha256>;

/// Serialized size of a BBS+ secret key (BLS12-381 Fr scalar).
pub const BBS_SECRET_KEY_BYTES: usize = 32;
/// Serialized size of a BBS+ public key (compressed BLS12-381 G2 point).
pub const BBS_PUBLIC_KEY_BYTES: usize = 96;
/// Serialized size of a BBS+ signature.
pub const BBS_SIGNATURE_BYTES: usize = 80;

/// Errors returned by BBS+ cryptographic operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BbsError {
    #[error("invalid BBS+ secret key")]
    InvalidSecretKey,

    #[error("invalid BBS+ public key")]
    InvalidPublicKey,

    #[error("invalid BBS+ signature")]
    InvalidSignature,

    #[error("invalid BBS+ proof")]
    InvalidProof,

    #[error("disclosed indices invalid (out of range or not strictly ascending)")]
    DisclosedIndicesInvalid,

    #[error("disclosed messages length does not match disclosed indices")]
    DisclosedLengthMismatch,

    #[error("BBS+ keypair generation failed")]
    KeyGenFailed,

    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),

    #[error("BBS+ operation failed: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// BbsSecretKey
// ---------------------------------------------------------------------------

/// A BBS+ secret key (32 bytes, big-endian Fr scalar).
pub struct BbsSecretKey(BBSplusSecretKey);

impl BbsSecretKey {
    /// Generate a new random BBS+ secret key.
    pub fn generate() -> Result<Self, BbsError> {
        let mut ikm = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut ikm);
        let kp =
            KeyPair::<BbsScheme>::generate(&ikm, None, None).map_err(|_| BbsError::KeyGenFailed)?;
        let (sk, _pk) = kp.into_parts();
        Ok(Self(sk))
    }

    /// Generate a BBS+ keypair deterministically from an input key material.
    /// Useful for test vectors and reproducible derivations.
    pub fn from_ikm(ikm: &[u8]) -> Result<Self, BbsError> {
        let kp =
            KeyPair::<BbsScheme>::generate(ikm, None, None).map_err(|_| BbsError::KeyGenFailed)?;
        let (sk, _pk) = kp.into_parts();
        Ok(Self(sk))
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> BbsPublicKey {
        BbsPublicKey(self.0.public_key())
    }

    /// Sign a vector of messages with optional context header.
    /// The `header` is bound into the signature and must be supplied identically at verify time.
    pub fn sign(&self, header: &[u8], messages: &[&[u8]]) -> Result<BbsSignature, BbsError> {
        let owned: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        let pk = self.0.public_key();
        let sig = Signature::<BbsScheme>::sign(Some(&owned), &self.0, &pk, Some(header))
            .map_err(|e| BbsError::Internal(format!("sign failed: {e:?}")))?;
        Ok(BbsSignature(sig))
    }

    /// Serialize the secret key to 32 bytes (big-endian).
    pub fn to_bytes(&self) -> [u8; BBS_SECRET_KEY_BYTES] {
        self.0.to_bytes()
    }

    /// Deserialize a secret key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; BBS_SECRET_KEY_BYTES]) -> Result<Self, BbsError> {
        BBSplusSecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BbsError::InvalidSecretKey)
    }
}

// ---------------------------------------------------------------------------
// BbsPublicKey
// ---------------------------------------------------------------------------

/// A BBS+ public key (96 bytes, compressed BLS12-381 G2 point).
#[derive(Clone, PartialEq, Eq)]
pub struct BbsPublicKey(BBSplusPublicKey);

impl BbsPublicKey {
    /// Serialize the public key to 96 bytes.
    pub fn to_bytes(&self) -> [u8; BBS_PUBLIC_KEY_BYTES] {
        self.0.to_bytes()
    }

    /// Deserialize a public key from 96 bytes.
    pub fn from_bytes(bytes: &[u8; BBS_PUBLIC_KEY_BYTES]) -> Result<Self, BbsError> {
        BBSplusPublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BbsError::InvalidPublicKey)
    }

    /// Encode as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, BbsError> {
        let raw = hex::decode(s).map_err(|e| BbsError::InvalidHex(e.to_string()))?;
        if raw.len() != BBS_PUBLIC_KEY_BYTES {
            return Err(BbsError::InvalidHex(format!(
                "expected {BBS_PUBLIC_KEY_BYTES} bytes, got {}",
                raw.len()
            )));
        }
        let mut arr = [0u8; BBS_PUBLIC_KEY_BYTES];
        arr.copy_from_slice(&raw);
        Self::from_bytes(&arr)
    }
}

impl std::fmt::Debug for BbsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BbsPublicKey({})", self.to_hex())
    }
}

impl Serialize for BbsPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BbsPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = String::deserialize(d)?;
        Self::from_hex(&h).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// BbsSignature
// ---------------------------------------------------------------------------

/// A BBS+ signature (80 bytes).
#[derive(Clone)]
pub struct BbsSignature(Signature<BbsScheme>);

impl BbsSignature {
    /// Verify this signature against a public key, header, and message vector.
    pub fn verify(
        &self,
        pk: &BbsPublicKey,
        header: &[u8],
        messages: &[&[u8]],
    ) -> Result<(), BbsError> {
        let owned: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        self.0
            .verify(&pk.0, Some(&owned), Some(header))
            .map_err(|_| BbsError::InvalidSignature)
    }

    /// Convenience: verify as a boolean.
    pub fn is_valid(&self, pk: &BbsPublicKey, header: &[u8], messages: &[&[u8]]) -> bool {
        self.verify(pk, header, messages).is_ok()
    }

    /// Generate a selective-disclosure proof from this signature.
    /// `disclosed_indices` must be in strictly ascending order.
    pub fn create_proof(
        &self,
        pk: &BbsPublicKey,
        header: &[u8],
        ph: &[u8],
        messages: &[&[u8]],
        disclosed_indices: &[usize],
    ) -> Result<BbsProof, BbsError> {
        for w in disclosed_indices.windows(2) {
            if w[0] >= w[1] {
                return Err(BbsError::DisclosedIndicesInvalid);
            }
        }
        if let Some(&max) = disclosed_indices.last() {
            if max >= messages.len() {
                return Err(BbsError::DisclosedIndicesInvalid);
            }
        }
        let owned: Vec<Vec<u8>> = messages.iter().map(|m| m.to_vec()).collect();
        let sig_bytes = self.0.to_bytes();
        let proof = PoKSignature::<BbsScheme>::proof_gen(
            &pk.0,
            &sig_bytes,
            Some(header),
            Some(ph),
            Some(&owned),
            Some(disclosed_indices),
        )
        .map_err(|e| BbsError::Internal(format!("proof_gen failed: {e:?}")))?;
        Ok(BbsProof(proof))
    }

    /// Serialize to 80 bytes.
    pub fn to_bytes(&self) -> [u8; BBS_SIGNATURE_BYTES] {
        self.0.to_bytes()
    }

    /// Deserialize from 80 bytes.
    pub fn from_bytes(bytes: &[u8; BBS_SIGNATURE_BYTES]) -> Result<Self, BbsError> {
        Signature::<BbsScheme>::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BbsError::InvalidSignature)
    }

    /// Encode as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex.
    pub fn from_hex(s: &str) -> Result<Self, BbsError> {
        let raw = hex::decode(s).map_err(|e| BbsError::InvalidHex(e.to_string()))?;
        if raw.len() != BBS_SIGNATURE_BYTES {
            return Err(BbsError::InvalidHex(format!(
                "expected {BBS_SIGNATURE_BYTES} bytes, got {}",
                raw.len()
            )));
        }
        let mut arr = [0u8; BBS_SIGNATURE_BYTES];
        arr.copy_from_slice(&raw);
        Self::from_bytes(&arr)
    }
}

impl std::fmt::Debug for BbsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BbsSignature({})", self.to_hex())
    }
}

impl PartialEq for BbsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BbsSignature {}

impl Serialize for BbsSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BbsSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let h = String::deserialize(d)?;
        Self::from_hex(&h).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// BbsProof
// ---------------------------------------------------------------------------

/// A BBS+ selective-disclosure proof. Variable size depending on the number
/// of undisclosed messages.
#[derive(Clone)]
pub struct BbsProof(PoKSignature<BbsScheme>);

impl BbsProof {
    /// Verify this proof against a public key, header, presentation header,
    /// disclosed messages, and the indices those messages occupied in the
    /// original signed vector.
    pub fn verify(
        &self,
        pk: &BbsPublicKey,
        header: &[u8],
        ph: &[u8],
        disclosed_indices: &[usize],
        disclosed_messages: &[&[u8]],
    ) -> Result<(), BbsError> {
        if disclosed_indices.len() != disclosed_messages.len() {
            return Err(BbsError::DisclosedLengthMismatch);
        }
        for w in disclosed_indices.windows(2) {
            if w[0] >= w[1] {
                return Err(BbsError::DisclosedIndicesInvalid);
            }
        }
        let owned: Vec<Vec<u8>> = disclosed_messages.iter().map(|m| m.to_vec()).collect();
        self.0
            .proof_verify(
                &pk.0,
                Some(&owned),
                Some(disclosed_indices),
                Some(header),
                Some(ph),
            )
            .map_err(|_| BbsError::InvalidProof)
    }

    /// Convenience: verify as a boolean.
    pub fn is_valid(
        &self,
        pk: &BbsPublicKey,
        header: &[u8],
        ph: &[u8],
        disclosed_indices: &[usize],
        disclosed_messages: &[&[u8]],
    ) -> bool {
        self.verify(pk, header, ph, disclosed_indices, disclosed_messages)
            .is_ok()
    }

    /// Serialize the proof. Length depends on undisclosed count.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Deserialize a proof from bytes.
    ///
    /// Defends against an upstream bug in zkryptium 0.6.1 where
    /// `PoKSignature::from_bytes` slices `&bytes[0..48]` without bounds-checking
    /// (panics on too-short input). A well-formed BBS proof is at least 240
    /// bytes (3×G1 + 3×Scalar) plus a multiple of 32 for hidden-message scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BbsError> {
        const MIN_PROOF_BYTES: usize = 240;
        if bytes.len() < MIN_PROOF_BYTES || !(bytes.len() - MIN_PROOF_BYTES).is_multiple_of(32) {
            return Err(BbsError::InvalidProof);
        }
        PoKSignature::<BbsScheme>::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BbsError::InvalidProof)
    }

    /// Encode as lowercase hex.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode from hex.
    pub fn from_hex(s: &str) -> Result<Self, BbsError> {
        let raw = hex::decode(s).map_err(|e| BbsError::InvalidHex(e.to_string()))?;
        Self::from_bytes(&raw)
    }
}

impl std::fmt::Debug for BbsProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BbsProof({} bytes)", self.to_bytes().len())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> &'static [u8] {
        b"solidus-bbs-test-header"
    }

    fn ph() -> &'static [u8] {
        b"solidus-bbs-test-presentation-header"
    }

    fn sample_messages() -> Vec<&'static [u8]> {
        vec![
            b"did:solidus:testnet:alice".as_ref(),
            b"Alice Liddell".as_ref(),
            b"1990-07-04".as_ref(),
            b"GB".as_ref(),
            b"passport".as_ref(),
            b"P-12345".as_ref(),
            b"KycL2".as_ref(),
            b"2026-01-15T00:00:00Z".as_ref(),
        ]
    }

    #[test]
    fn keygen_produces_valid_keypair() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        assert_eq!(sk.to_bytes().len(), BBS_SECRET_KEY_BYTES);
        assert_eq!(pk.to_bytes().len(), BBS_PUBLIC_KEY_BYTES);
    }

    #[test]
    fn sign_and_verify_single_message() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msg: &[u8] = b"hello bbs";
        let sig = sk.sign(header(), &[msg]).expect("sign");
        sig.verify(&pk, header(), &[msg]).expect("verify");
    }

    #[test]
    fn sign_and_verify_multi_message() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        assert!(sig.is_valid(&pk, header(), &msgs));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let mut msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        msgs[2] = b"1990-07-05"; // tamper one message
        assert!(!sig.is_valid(&pk, header(), &msgs));
    }

    #[test]
    fn verify_rejects_wrong_header() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        assert!(!sig.is_valid(&pk, b"different-header", &msgs));
    }

    #[test]
    fn verify_rejects_wrong_pk() {
        let sk1 = BbsSecretKey::generate().expect("keygen 1");
        let sk2 = BbsSecretKey::generate().expect("keygen 2");
        let msgs = sample_messages();
        let sig = sk1.sign(header(), &msgs).expect("sign");
        assert!(!sig.is_valid(&sk2.public_key(), header(), &msgs));
    }

    #[test]
    fn proof_disclose_subset() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        // Disclose did, country, kyc_level (indices 0, 3, 6).
        let disclosed = [0_usize, 3, 6];
        let proof = sig
            .create_proof(&pk, header(), ph(), &msgs, &disclosed)
            .expect("proof_gen");

        let revealed_msgs: Vec<&[u8]> = disclosed.iter().map(|&i| msgs[i]).collect();
        proof
            .verify(&pk, header(), ph(), &disclosed, &revealed_msgs)
            .expect("proof_verify");
    }

    #[test]
    fn proof_disclose_none_proves_signature_validity() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let proof = sig
            .create_proof(&pk, header(), ph(), &msgs, &[])
            .expect("proof_gen");
        proof
            .verify(&pk, header(), ph(), &[], &[])
            .expect("proof_verify");
    }

    #[test]
    fn proof_disclose_all() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let all: Vec<usize> = (0..msgs.len()).collect();
        let proof = sig
            .create_proof(&pk, header(), ph(), &msgs, &all)
            .expect("proof_gen");
        proof
            .verify(&pk, header(), ph(), &all, &msgs)
            .expect("proof_verify");
    }

    #[test]
    fn proof_rejects_tampered_disclosed_message() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let disclosed = [0_usize, 3, 6];
        let proof = sig
            .create_proof(&pk, header(), ph(), &msgs, &disclosed)
            .expect("proof_gen");
        // Lie about the disclosed country: claim FR instead of GB.
        let revealed_lied: Vec<&[u8]> = vec![msgs[0], b"FR", msgs[6]];
        assert!(!proof.is_valid(&pk, header(), ph(), &disclosed, &revealed_lied));
    }

    #[test]
    fn proof_rejects_index_out_of_range() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let bad = [0_usize, msgs.len()]; // out of range
        let err = sig
            .create_proof(&pk, header(), ph(), &msgs, &bad)
            .expect_err("expected error");
        assert_eq!(err, BbsError::DisclosedIndicesInvalid);
    }

    #[test]
    fn proof_rejects_non_ascending_indices() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let bad = [3_usize, 0]; // descending
        let err = sig
            .create_proof(&pk, header(), ph(), &msgs, &bad)
            .expect_err("expected error");
        assert_eq!(err, BbsError::DisclosedIndicesInvalid);
    }

    #[test]
    fn proof_from_bytes_rejects_short_input() {
        // 0 bytes — too short.
        assert_eq!(
            BbsProof::from_bytes(&[]).unwrap_err(),
            BbsError::InvalidProof
        );
        // 100 bytes — still too short (need ≥240).
        let short = vec![0u8; 100];
        assert_eq!(
            BbsProof::from_bytes(&short).unwrap_err(),
            BbsError::InvalidProof
        );
        // 241 bytes — wrong tail alignment (240 + 1 not multiple of 32).
        let misaligned = vec![0u8; 241];
        assert_eq!(
            BbsProof::from_bytes(&misaligned).unwrap_err(),
            BbsError::InvalidProof
        );
        // 1 byte — earlier zkryptium 0.6.1 would panic here without our guard.
        assert_eq!(
            BbsProof::from_bytes(&[0x00]).unwrap_err(),
            BbsError::InvalidProof
        );
    }

    #[test]
    fn proof_rejects_length_mismatch_at_verify() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let disclosed = [0_usize, 3];
        let proof = sig
            .create_proof(&pk, header(), ph(), &msgs, &disclosed)
            .expect("proof_gen");
        // Pass three messages with two indices.
        let bad: Vec<&[u8]> = vec![msgs[0], msgs[3], msgs[6]];
        let err = proof
            .verify(&pk, header(), ph(), &disclosed, &bad)
            .expect_err("expected error");
        assert_eq!(err, BbsError::DisclosedLengthMismatch);
    }

    #[test]
    fn signature_bytes_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let bytes = sig.to_bytes();
        assert_eq!(bytes.len(), BBS_SIGNATURE_BYTES);
        let decoded = BbsSignature::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(sig, decoded);
        assert!(decoded.is_valid(&pk, header(), &msgs));
    }

    #[test]
    fn signature_hex_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let h = sig.to_hex();
        let decoded = BbsSignature::from_hex(&h).expect("from_hex");
        assert_eq!(sig, decoded);
    }

    #[test]
    fn pubkey_bytes_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), BBS_PUBLIC_KEY_BYTES);
        let decoded = BbsPublicKey::from_bytes(&bytes).expect("from_bytes");
        assert_eq!(pk, decoded);
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let h = pk.to_hex();
        let decoded = BbsPublicKey::from_hex(&h).expect("from_hex");
        assert_eq!(pk, decoded);
    }

    #[test]
    fn secret_key_bytes_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk_before = sk.public_key();
        let bytes = sk.to_bytes();
        assert_eq!(bytes.len(), BBS_SECRET_KEY_BYTES);
        let decoded = BbsSecretKey::from_bytes(&bytes).expect("from_bytes");
        let pk_after = decoded.public_key();
        assert_eq!(pk_before, pk_after);
    }

    /// Run with `cargo test -p solidus-crypto bbs::tests::print_ts_port_fixture -- --ignored --nocapture`
    /// to dump a fixture for the TypeScript port to assert against.
    #[test]
    #[ignore]
    fn print_ts_port_fixture() {
        let ikm: &[u8] = b"solidus-bbs-ts-port-test-vector-fixed-ikm-32bytes";
        let sk = BbsSecretKey::from_ikm(ikm).expect("from_ikm");
        let pk = sk.public_key();

        let hdr: &[u8] = b"solidus-bbs-test-header";
        let msgs: Vec<&[u8]> = vec![
            b"did:solidus:testnet:alice".as_ref(),
            b"Alice Liddell".as_ref(),
            b"1990-07-04".as_ref(),
            b"GB".as_ref(),
            b"passport".as_ref(),
            b"P-12345".as_ref(),
            b"KycL2".as_ref(),
            b"2026-01-15T00:00:00Z".as_ref(),
        ];
        let sig = sk.sign(hdr, &msgs).expect("sign");

        eprintln!("ikm_hex={}", hex::encode(ikm));
        eprintln!("sk_hex={}", hex::encode(sk.to_bytes()));
        eprintln!("pk_hex={}", hex::encode(pk.to_bytes()));
        eprintln!("header_hex={}", hex::encode(hdr));
        for (i, m) in msgs.iter().enumerate() {
            eprintln!("msg_{}_hex={}", i, hex::encode(m));
        }
        eprintln!("sig_hex={}", hex::encode(sig.to_bytes()));
    }

    #[test]
    fn deterministic_keygen_from_ikm() {
        let ikm = b"solidus-bbs-deterministic-test-vector-input-key-material-64bytes";
        let sk1 = BbsSecretKey::from_ikm(ikm).expect("from_ikm 1");
        let sk2 = BbsSecretKey::from_ikm(ikm).expect("from_ikm 2");
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());
        assert_eq!(sk1.public_key(), sk2.public_key());
    }

    #[test]
    fn pubkey_serde_json_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let pk = sk.public_key();
        let j = serde_json::to_string(&pk).expect("serialize");
        let decoded: BbsPublicKey = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(pk, decoded);
    }

    #[test]
    fn signature_serde_json_roundtrip() {
        let sk = BbsSecretKey::generate().expect("keygen");
        let msgs = sample_messages();
        let sig = sk.sign(header(), &msgs).expect("sign");
        let j = serde_json::to_string(&sig).expect("serialize");
        let decoded: BbsSignature = serde_json::from_str(&j).expect("deserialize");
        assert_eq!(sig, decoded);
    }
}

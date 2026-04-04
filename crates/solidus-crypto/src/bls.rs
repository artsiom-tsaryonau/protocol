use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Domain separation tag for BLS signatures in the Solidus protocol.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Errors returned by BLS cryptographic operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum BlsError {
    #[error("invalid BLS signature")]
    InvalidSignature,

    #[error("invalid BLS public key")]
    InvalidPublicKey,

    #[error("signature aggregation failed")]
    AggregationFailed,

    #[error("invalid hex encoding: {0}")]
    InvalidHex(String),
}

/// A BLS12-381 secret key (min-pk variant).
pub struct BlsSecretKey(SecretKey);

impl BlsSecretKey {
    /// Generate a new random BLS secret key.
    pub fn generate() -> Self {
        let mut ikm = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut ikm);
        // blst requires IKM ≥ 32 bytes; key_gen with empty info is safe.
        let sk = SecretKey::key_gen(&ikm, &[]).expect("IKM is always 32 bytes");
        Self(sk)
    }

    /// Derive the corresponding public key.
    pub fn public_key(&self) -> BlsPublicKey {
        BlsPublicKey(self.0.sk_to_pk())
    }

    /// Sign a message. Returns a [`BlsSignature`].
    pub fn sign(&self, msg: &[u8]) -> BlsSignature {
        BlsSignature(self.0.sign(msg, DST, &[]))
    }

    /// Serialize the secret key to 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Deserialize a secret key from 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BlsError> {
        SecretKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }
}

// ---------------------------------------------------------------------------
// BlsPublicKey
// ---------------------------------------------------------------------------

/// A BLS12-381 public key (min-pk variant, 48 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct BlsPublicKey(PublicKey);

impl BlsPublicKey {
    /// Serialize the public key to 48 bytes.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_bytes()
    }

    /// Deserialize a public key from 48 bytes.
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self, BlsError> {
        PublicKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidPublicKey)
    }

    /// Encode the public key as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode a public key from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, BlsError> {
        let bytes = hex::decode(s).map_err(|e| BlsError::InvalidHex(e.to_string()))?;
        if bytes.len() != 48 {
            return Err(BlsError::InvalidHex(format!(
                "expected 48 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }
}

impl std::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsPublicKey({})", self.to_hex())
    }
}

impl Serialize for BlsPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// BlsSignature
// ---------------------------------------------------------------------------

/// A BLS12-381 signature (min-pk variant, 96 bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct BlsSignature(Signature);

impl BlsSignature {
    /// Verify this signature against a single public key and message.
    /// Returns `true` if valid.
    pub fn verify(&self, pk: &BlsPublicKey, msg: &[u8]) -> bool {
        let result = self.0.verify(true, msg, DST, &[], &pk.0, true);
        result == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// Aggregate multiple signatures into one.
    /// All signatures must be over the same message (use `fast_aggregate_verify` to verify).
    pub fn aggregate(sigs: &[&BlsSignature]) -> Result<Self, BlsError> {
        if sigs.is_empty() {
            return Err(BlsError::AggregationFailed);
        }
        let raw: Vec<&Signature> = sigs.iter().map(|s| &s.0).collect();
        AggregateSignature::aggregate(&raw, true)
            .map(|agg| Self(agg.to_signature()))
            .map_err(|_| BlsError::AggregationFailed)
    }

    /// Verify an aggregate signature where all signers signed the same message.
    /// `pks` must contain exactly the public keys of the signers.
    pub fn fast_aggregate_verify(&self, pks: &[&BlsPublicKey], msg: &[u8]) -> bool {
        if pks.is_empty() {
            return false;
        }
        let raw_pks: Vec<&PublicKey> = pks.iter().map(|pk| &pk.0).collect();
        let result = self.0.fast_aggregate_verify(true, msg, DST, &raw_pks);
        result == blst::BLST_ERROR::BLST_SUCCESS
    }

    /// Serialize the signature to 96 bytes.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    /// Deserialize a signature from 96 bytes.
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self, BlsError> {
        Signature::from_bytes(bytes)
            .map(Self)
            .map_err(|_| BlsError::InvalidSignature)
    }

    /// Encode the signature as a lowercase hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Decode a signature from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, BlsError> {
        let bytes = hex::decode(s).map_err(|e| BlsError::InvalidHex(e.to_string()))?;
        if bytes.len() != 96 {
            return Err(BlsError::InvalidHex(format!(
                "expected 96 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }
}

impl std::fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlsSignature({})", self.to_hex())
    }
}

impl Serialize for BlsSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        Self::from_hex(&hex_str).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let msg = b"solidus bls test";
        let sig = sk.sign(msg);
        assert!(sig.verify(&pk, msg));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let sig = sk.sign(b"correct message");
        assert!(!sig.verify(&pk, b"wrong message"));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let sk1 = BlsSecretKey::generate();
        let sk2 = BlsSecretKey::generate();
        let sig = sk1.sign(b"test message");
        assert!(!sig.verify(&sk2.public_key(), b"test message"));
    }

    #[test]
    fn aggregate_two_signatures() {
        let sk1 = BlsSecretKey::generate();
        let sk2 = BlsSecretKey::generate();
        let msg = b"aggregate two";

        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);

        let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();
        let pks = [&sk1.public_key(), &sk2.public_key()];
        assert!(agg.fast_aggregate_verify(&pks, msg));
    }

    #[test]
    fn aggregate_three_of_four() {
        let sk1 = BlsSecretKey::generate();
        let sk2 = BlsSecretKey::generate();
        let sk3 = BlsSecretKey::generate();
        let sk4 = BlsSecretKey::generate();
        let msg = b"quorum of three out of four";

        // Only sk1, sk2, sk3 sign (sk4 does not)
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        let sig3 = sk3.sign(msg);

        let agg = BlsSignature::aggregate(&[&sig1, &sig2, &sig3]).unwrap();

        let pk1 = sk1.public_key();
        let pk2 = sk2.public_key();
        let pk3 = sk3.public_key();
        let pks = [&pk1, &pk2, &pk3];
        assert!(agg.fast_aggregate_verify(&pks, msg));

        // Including sk4's key in the verifier set must fail
        let pk4 = sk4.public_key();
        let wrong_pks = [&pk1, &pk2, &pk3, &pk4];
        assert!(!agg.fast_aggregate_verify(&wrong_pks, msg));
    }

    #[test]
    fn aggregate_verify_fails_with_wrong_signer_set() {
        let sk1 = BlsSecretKey::generate();
        let sk2 = BlsSecretKey::generate();
        let sk3 = BlsSecretKey::generate();
        let msg = b"wrong signer set";

        // sk1 and sk2 sign
        let sig1 = sk1.sign(msg);
        let sig2 = sk2.sign(msg);
        let agg = BlsSignature::aggregate(&[&sig1, &sig2]).unwrap();

        // Verify against pk1 + pk3 (not pk2) — must fail
        let pk1 = sk1.public_key();
        let pk3 = sk3.public_key();
        let wrong_pks = [&pk1, &pk3];
        assert!(!agg.fast_aggregate_verify(&wrong_pks, msg));
    }

    #[test]
    fn public_key_hex_roundtrip() {
        let sk = BlsSecretKey::generate();
        let pk = sk.public_key();
        let hex = pk.to_hex();
        let decoded = BlsPublicKey::from_hex(&hex).unwrap();
        assert_eq!(pk, decoded);
    }

    #[test]
    fn signature_hex_roundtrip() {
        let sk = BlsSecretKey::generate();
        let sig = sk.sign(b"hex roundtrip");
        let hex = sig.to_hex();
        let decoded = BlsSignature::from_hex(&hex).unwrap();
        assert_eq!(sig, decoded);
    }
}

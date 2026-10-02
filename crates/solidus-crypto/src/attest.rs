//! Validator attestation keys: the secp256k1 key a node signs bridge messages with, and the
//! recovery a destination chain performs.
//!
//! ⚠ THIS IS A DIFFERENT KEY FROM THE CONSENSUS KEY, AND THAT SEPARATION IS THE POINT. A validator
//! signs blocks with BLS and attestations with secp256k1, so a stolen attestation key forges bridge
//! messages up to the threshold and cannot touch consensus, while a stolen consensus key cannot
//! forge a bridge message at all.
//!
//! ⛔ RECOVERY IS NOT VERIFICATION. `recover` returns an address for almost any well-formed
//! signature, including one made over a completely different digest. Whether that address counts is
//! the caller's question, and the caller answers it by checking membership in a validator set.

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

/// Ethereum keccak256 (the original padding, not NIST SHA3-256). Private on purpose: the public
/// one in `solidus-bridge-codec` is the estate's, and two public copies are two things to keep in
/// step. This exists so `solidus-crypto` does not have to depend on the bridge codec to derive an
/// address.
fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Why a signature could not be turned into an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestError {
    #[error("attestation signature must be 65 bytes, got {0}")]
    BadLength(usize),
    #[error("malformed attestation signature")]
    Malformed,
    /// EIP-2: the upper half of the curve order is the same signature with a flipped `v`, so
    /// accepting it would let one signature be presented as two distinct 65-byte strings.
    #[error("high-s attestation signature")]
    HighS,
    #[error("bad recovery id {0}")]
    BadRecoveryId(u8),
    #[error("attestation signature does not recover")]
    NoRecovery,
    #[error("attestation key must be 32 bytes of hex")]
    BadKey,
}

/// A node's attestation key. Held only on the chain box, never in an app box environment.
pub struct AttestationKey(SigningKey);

impl AttestationKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, AttestError> {
        let raw = hex::decode(hex_str.trim_start_matches("0x")).map_err(|_| AttestError::BadKey)?;
        SigningKey::from_slice(&raw)
            .map(Self)
            .map_err(|_| AttestError::BadKey)
    }

    /// keccak256 of the uncompressed public key without its 0x04 tag, last 20 bytes.
    pub fn address(&self) -> [u8; 20] {
        address_of(self.0.verifying_key())
    }

    /// Sign a 32-byte prehash. 65 bytes, `r ‖ s ‖ v` with `v` in {27, 28}: what Solidity's
    /// `ecrecover` takes and what the mirror's `AttestationLib` slices.
    ///
    /// ⚠ THE CALLER CHOOSES WHAT THE 32 BYTES ARE. The node passes the EIP-191 eth-signed hash of
    /// the §3.2 digest, because that is what the EVM side recovers from; Solana recovers from the
    /// digest itself. Making that choice here would bake one destination's framing into every one.
    pub fn sign(&self, prehash: &[u8; 32]) -> [u8; 65] {
        let (sig, rid) = self
            .0
            .sign_prehash_recoverable(prehash)
            .expect("a 32-byte prehash is always signable");
        let mut out = [0u8; 65];
        out[..64].copy_from_slice(&sig.to_bytes());
        out[64] = 27 + rid.to_byte();
        out
    }
}

fn address_of(key: &VerifyingKey) -> [u8; 20] {
    let point = key.to_encoded_point(false);
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash[12..]);
    out
}

/// Recover the Ethereum address that produced `sig` over `prehash`.
///
/// Accepts `v` in {0, 1, 27, 28}, because both conventions are in the wild and a signer that emits
/// the raw recovery id is not wrong, only terse.
pub fn recover(prehash: &[u8; 32], sig: &[u8]) -> Result<[u8; 20], AttestError> {
    if sig.len() != 65 {
        return Err(AttestError::BadLength(sig.len()));
    }
    let signature = Signature::from_slice(&sig[..64]).map_err(|_| AttestError::Malformed)?;
    if signature.normalize_s().is_some() {
        return Err(AttestError::HighS);
    }
    let rec = match sig[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        other => return Err(AttestError::BadRecoveryId(other)),
    };
    let rid = RecoveryId::from_byte(rec).ok_or(AttestError::BadRecoveryId(sig[64]))?;
    let key = VerifyingKey::recover_from_prehash(prehash, &signature, rid)
        .map_err(|_| AttestError::NoRecovery)?;
    Ok(address_of(&key))
}

//! One secp256k1 recovery primitive for the whole chain (registry §2.7).
//!
//! ⛔ A THIN WRAPPER AND NOT A SECOND IMPLEMENTATION. Consent verification, announcements and plan
//! 41's inbound check all recover an Ethereum address, and three copies of "parse the signature,
//! refuse high-s, map the recovery byte" drift one at a time and silently. The signing side is
//! `solidus_crypto::attest::AttestationKey::sign`; this is the only verifier.
//!
//! ⚠ THE ERROR STRINGS SAY "consent" BECAUSE `verify_consent`'s TESTS PIN THEM. Those tests are the
//! oldest caller and their strings reach an RPC error message, so the wrapper keeps them rather
//! than renaming a user-visible string to tidy an internal one. A later caller that wants its own
//! wording maps `solidus_crypto::attest::AttestError` itself.

use solidus_crypto::attest::{recover, AttestError};

/// Recover the Ethereum address that signed `digest`, or the reason it could not be recovered.
pub fn recover_eth_address(digest: &[u8; 32], sig: &[u8]) -> Result<[u8; 20], &'static str> {
    recover(digest, sig).map_err(|e| match e {
        AttestError::BadLength(_) => "consent signature must be 65 bytes",
        AttestError::Malformed => "malformed consent signature",
        AttestError::HighS => "high-s consent signature",
        AttestError::BadRecoveryId(_) => "bad recovery id",
        AttestError::NoRecovery => "consent signature does not recover",
        AttestError::BadKey => "bad attestation key",
    })
}

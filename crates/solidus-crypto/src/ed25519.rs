use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// Sign a message with the given Ed25519 signing key.
/// Returns a 64-byte signature.
pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Verify an Ed25519 signature against a message and verifying key.
/// Returns `true` if the signature is valid.
///
/// Uses `verify_strict`, which rejects identity / small-order public keys
/// and enforces a canonical `S`, giving SBS (exclusive ownership).
///
/// ⚠ CORRECTED 2026-08-25 — this comment used to say non-strict `verify`
/// "can accept the all-zeros pubkey + all-zeros sig pair". MEASURED, that
/// is false HERE: seeding `verify_strict` -> `verify` in this function
/// leaves `rejects_all_zero_key_and_signature` PASSING, because dalek's
/// non-strict path still rejects that pair on the verification equation.
/// The claim is true of a COFACTORED verifier, which dalek is not and
/// @noble/ed25519 (`{ zip215: true }`, its default) is — that is exactly
/// how the TypeScript half shipped without SBS until 2026-08-25.
///
/// So keep `verify_strict` for the property it really provides — small-order
/// key rejection and non-malleability in general — not for this one vector,
/// which cofactorless arithmetic already refuses.
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(signature);
    key.verify_strict(message, &sig).is_ok()
}

/// Generate a new random Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut rng = rand::thread_rng();
    SigningKey::generate(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Cross-language pin: `@solidus/jwt`'s ed25519-strict.test.ts asserts THE SAME PAIR on
    // the TypeScript side, where it is ACCEPTED under @noble's ZIP-215 default and rejected
    // once `{ zip215: false }` is passed. Both languages must reject it.
    //
    // ⚠ This test does NOT discriminate strict from non-strict in Rust — measured, it passes
    // under both. It is a regression pin on the OUTCOME, and the cross-language half of the
    // vector the TypeScript fix was built on. Do not read it as proof `verify_strict` is wired.
    #[test]
    fn rejects_all_zero_key_and_signature() {
        // An all-zero verifying key is the identity point: a small-order key. Paired with an
        // all-zero signature it satisfies the verification equation vacuously under the
        // cofactored (ZIP-215) rule, for ANY message.
        let key = VerifyingKey::from_bytes(&[0u8; 32])
            .expect("the identity point is a well-formed encoding — that is the whole problem");
        for message in [
            b"solidus protocol".as_slice(),
            b"".as_slice(),
            b"any message at all",
        ] {
            assert!(
                !verify(&key, message, &[0u8; 64]),
                "verify_strict must reject the all-zero key/signature pair"
            );
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = generate_signing_key();
        let message = b"solidus protocol";
        let sig = sign(&key, message);
        assert!(verify(&key.verifying_key(), message, &sig));
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let key = generate_signing_key();
        let sig = sign(&key, b"correct message");
        assert!(!verify(&key.verifying_key(), b"wrong message", &sig));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let key1 = generate_signing_key();
        let key2 = generate_signing_key();
        let sig = sign(&key1, b"test");
        assert!(!verify(&key2.verifying_key(), b"test", &sig));
    }

    #[test]
    fn signature_is_deterministic_for_same_key_and_message() {
        let key = generate_signing_key();
        let message = b"deterministic check";
        let sig1 = sign(&key, message);
        let sig2 = sign(&key, message);
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn generated_keys_are_unique() {
        let key1 = generate_signing_key();
        let key2 = generate_signing_key();
        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }
}

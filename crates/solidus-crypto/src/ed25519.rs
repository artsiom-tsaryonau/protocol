use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Sign a message with the given Ed25519 signing key.
/// Returns a 64-byte signature.
pub fn sign(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Verify an Ed25519 signature against a message and verifying key.
/// Returns `true` if the signature is valid.
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &[u8; 64]) -> bool {
    let sig = Signature::from_bytes(signature);
    key.verify(message, &sig).is_ok()
}

/// Generate a new random Ed25519 signing key.
pub fn generate_signing_key() -> SigningKey {
    let mut rng = rand::thread_rng();
    SigningKey::generate(&mut rng)
}

#[cfg(test)]
mod tests {
    use super::*;

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

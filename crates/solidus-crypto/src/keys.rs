use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::fmt;

use crate::hash::hash160;

/// Error type for address parsing operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    #[error("invalid base58 encoding: {0}")]
    InvalidBase58(String),

    #[error("invalid address length: expected 20 bytes, got {0}")]
    InvalidLength(usize),
}

/// A 20-byte account address derived from the BLAKE3 hash of a public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address([u8; 20]);

impl Address {
    /// Derive an address from an Ed25519 verifying (public) key.
    /// The address is the first 20 bytes of the BLAKE3 hash of the public key bytes.
    pub fn from_public_key(key: &VerifyingKey) -> Self {
        Self(hash160(key.as_bytes()))
    }

    /// Create an address from a raw 20-byte array.
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Return the raw 20-byte address.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Encode the address as a Base58 string.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }

    /// Decode an address from a Base58 string.
    pub fn from_base58(s: &str) -> Result<Self, AddressError> {
        let bytes = bs58::decode(s)
            .into_vec()
            .map_err(|e| AddressError::InvalidBase58(e.to_string()))?;

        if bytes.len() != 20 {
            return Err(AddressError::InvalidLength(bytes.len()));
        }

        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_base58())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::generate_signing_key;

    #[test]
    fn address_from_public_key_deterministic() {
        let key = generate_signing_key();
        let vk = key.verifying_key();
        let addr1 = Address::from_public_key(&vk);
        let addr2 = Address::from_public_key(&vk);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn different_keys_different_addresses() {
        let key1 = generate_signing_key();
        let key2 = generate_signing_key();
        let addr1 = Address::from_public_key(&key1.verifying_key());
        let addr2 = Address::from_public_key(&key2.verifying_key());
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn base58_roundtrip() {
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        let encoded = addr.to_base58();
        let decoded = Address::from_base58(&encoded).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn base58_invalid_length() {
        // Encode 10 bytes (too short) as base58
        let short = bs58::encode(&[0u8; 10]).into_string();
        let err = Address::from_base58(&short).unwrap_err();
        assert!(matches!(err, AddressError::InvalidLength(10)));
    }

    #[test]
    fn address_display_is_base58() {
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        assert_eq!(format!("{addr}"), addr.to_base58());
    }
}

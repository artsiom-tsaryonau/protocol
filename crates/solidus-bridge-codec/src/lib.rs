//! Solidus bridge codec.
//!
//! ⛔ ONE SOURCE OF BYTES FOR FOUR LANGUAGES. The chain (Rust), the mirror
//! contracts (Solidity), the Solana programs (Rust, on-chain) and the SDK
//! (TypeScript) must agree on every byte here. This crate is the reference:
//! it generates `test-fixtures/bridge/*.json`, and every other implementation is
//! tested against those files, never against a second reading of this code.
//!
//! `no_std` with `alloc` so the phase 8 ZK guest can link it unchanged.

#![no_std]

extern crate alloc;

pub mod attest;
pub mod consent;
pub mod ids;
pub mod message;
pub mod transfer;

pub use attest::*;
pub use consent::*;
pub use ids::*;
pub use message::*;
pub use transfer::*;

use sha3::{Digest, Keccak256};

/// Ethereum keccak256 (the original Keccak padding, not NIST SHA3-256).
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

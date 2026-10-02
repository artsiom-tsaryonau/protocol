//! Solidus cryptographic primitives.
//!
//! Modules are feature-gated: the default set is what a DID resolver needs
//! (`hash`, `keys`, `ed25519`). `bbs` and `consensus` (`bls` + `vrf`) are opt-in
//! so a client does not compile `zkryptium` or the C `blst` it never calls.

#[cfg(feature = "attest")]
pub mod attest;
#[cfg(feature = "bbs")]
pub mod bbs;
#[cfg(feature = "consensus")]
pub mod bls;
#[cfg(feature = "ed25519")]
pub mod ed25519;
#[cfg(feature = "hash")]
pub mod hash;
#[cfg(feature = "keys")]
pub mod keys;
#[cfg(feature = "consensus")]
pub mod vrf;

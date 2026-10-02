//! Client library for the Solidus Network.
//!
//! The protocol surface — derivation, `did:solidus` identifiers, resolution and
//! credential verification — without the node internals. A consumer of this
//! crate compiles no RocksDB, no libp2p, no consensus engine, and (unless it
//! asks for the `bbs` feature) no C.
//!
//! That boundary is asserted by `tests/boundary.rs`, which pins the transitive
//! dependency set as a whitelist — any addition fails until someone admits it
//! deliberately. It is a test rather than a comment because this comment
//! claimed it for two iterations before the test existed.

#![forbid(unsafe_code)]

pub mod derivation;
pub mod did;
pub mod tx;

pub use solidus_crypto::keys::Address;

//! # solidus-evm — the EVM subnet (Stage 6)
//!
//! REVM-based subnet (BD-5, §4.8) with three identity precompiles that
//! read **L1-finalized** DID/credential state via inclusion proofs
//! against roots delivered by the verified bridge (`solidus-subnet`):
//!
//! | address (…00xx) | precompile |
//! |---|---|
//! | 0x…0110 | `isDidActive(did) → bool` |
//! | 0x…0111 | `verifyCredential(credentialId, issuerDid) → bool` |
//! | 0x…0112 | `verifyBbsDisclosure(presentation, disclosed) → bool` |
//!
//! The precompile *logic* is pure Rust ([`precompiles`]) — REVM-version
//! independent and fuzzed directly; [`subnet::EvmSubnet`] wires it into
//! REVM execution so contracts reach it with `STATICCALL`. A real
//! foundry-compiled ERC-20 deploys + transfers end-to-end through the subnet
//! (`subnet::erc20_e2e`), and the ETH JSON-RPC edge ([`eth_rpc`]) now serves
//! both the read/`eth_call` path **and** `eth_sendRawTransaction` (legacy +
//! EIP-1559 decode + secp256k1 sender recovery in [`raw_tx`], validated
//! against `cast`-generated vectors).
//!
//! Scoping note (BD-8): this crate is deliberately isolated so the
//! bridge/precompile surface can be audited as a separate engagement from
//! the L1 — nothing here is on the L1 hot path.

pub mod codec;
pub mod eth_rpc;
pub mod precompiles;
pub mod raw_tx;
pub mod subnet;

pub use codec::{bool_word, InputBuilder, InputReader};
pub use eth_rpc::{EthRpcError, SharedSubnet};
pub use raw_tx::{decode as decode_raw_tx, DecodedTx, RawTxError};
pub use subnet::EvmSubnet;

/// Precompile failure taxonomy. Distinguishes "checked and false" (an
/// `Ok(false-word)` return) from unverifiable input (these errors).
#[derive(thiserror::Error, Debug)]
pub enum PrecompileFailure {
    /// The caller's claimed root is not the subnet's latest finalized
    /// root for that tree.
    #[error("claimed root is not the latest finalized root")]
    StaleRoot,

    /// The inclusion proof did not verify.
    #[error("inclusion proof rejected")]
    ProofRejected,

    /// Undecodable/oversized/truncated input.
    #[error("malformed input: {0}")]
    Malformed(String),

    /// No finalized roots delivered to the subnet yet.
    #[error("no finalized L1 roots available")]
    NoRoots,
}

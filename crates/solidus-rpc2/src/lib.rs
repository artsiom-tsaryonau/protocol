//! # solidus-rpc2 — the v2 JSON-RPC edge (node-layer)
//!
//! Binary internal, **JSON only at the boundary** (§5.1). Everything the
//! node stores and gossips is bincode; this crate is the single place
//! that translates to/from JSON for external clients.
//!
//! Three layers, each testable on its own:
//! - [`backend::RpcBackend`] — what the RPC needs from the node: committed
//!   account reads, receipts, chain head, and a tx-submit hook. Implemented
//!   over [`solidus_store2::Store2`] for reads + a submit callback.
//! - [`methods`] — pure request→response handlers (parse params, call the
//!   backend, shape JSON). No transport, no async — unit-testable directly.
//! - [`server`] — the `jsonrpsee` HTTP binding that registers the methods.
//!
//! Method surface (namespaced `solidus_`):
//! `getBalance` · `getNonce` · `getBlockHeight` · `getStateRoot` ·
//! `getReceipt` · `submitTransaction`.

pub mod backend;
pub mod methods;
pub mod server;

pub use backend::{RpcBackend, RpcBlock, Store2Backend};
pub use methods::RpcError;
pub use server::serve;

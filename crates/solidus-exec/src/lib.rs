//! # solidus-exec — the v2 two-lane executor (Stage 0: serial reference oracle)
//!
//! Part of the v2 rebuild (parallel network, new chain-id).
//! This crate owns block execution for the v2 chain:
//!
//! - **Stage 0 (this code):** the frozen core interfaces ([`types`],
//!   [`view::TxView`], [`delta::DeltaSet`], [`mvmemory::MvMemory`],
//!   [`fee::FeeAccumulator`], [`lane`]) plus the **serial reference
//!   executor** ([`reference`]) — a single-lane, fully-serial port of the
//!   live chain's `execute_block` over the 10 unchanged `TxPayload`
//!   variants. The reference executor is the permanent **differential
//!   oracle**: every future executor (the two-lane Block-STM pipeline)
//!   must produce byte-identical receipts and state roots against it.
//! - **Stage 3:** the two-lane pipeline — identity/serial lane first,
//!   frozen delta baseline, then payment-lane Block-STM over `Transfer`.
//!
//! ## Canonical v2 execution order (design decision D-ORDER)
//!
//! The two-lane split makes execution order **observable** (the DID-anchor
//! transfer guard and the pristine-DidCreate rule read state other txs
//! write). v2 therefore *defines* the canonical execution order of a
//! committed block as: **identity-lane txs first (in block order), then
//! payment-lane txs (in block order)** — the deterministic
//! [`lane::partition_lanes`] function of the committed tx list. The
//! reference oracle executes that same flattened order serially
//! ([`types::ExecOrder::LanePartitioned`]); the two-lane executor realizes
//! it with parallel machinery. For the Stage-0 parity anchor against the
//! *live* chain (which executes raw block order), the oracle also supports
//! [`types::ExecOrder::RawBlock`].
//!
//! ## Legacy behaviors intentionally not carried over (documented, pinned)
//!
//! 1. **Receipt-idempotency short-circuit** — the live executor consults
//!    `CF_RECEIPTS` before executing each tx so that dev-testnet validators
//!    sharing one RocksDB instance don't double-apply blocks. v2 executes a
//!    committed block exactly once per store; multi-validator-one-store is
//!    not a supported v2 topology.
//!
//!    ⛔ THAT REASONING IS ABOUT THE WRONG CASE, MEASURED 2026-09-24. It
//!    argues one BLOCK executed twice against one store. What actually
//!    happens is one TRANSACTION in TWO DIFFERENT BLOCKS, each executed
//!    exactly once: every validator's worker seals its own batch and the DAG
//!    mempool dedupes BATCHES by digest, not TRANSACTIONS across batches,
//!    which is how Narwhal-style mempools are meant to behave. Live proof:
//!    tx `df8676b0…` in blocks 3222202 AND 3222203, proposers 0 then 1.
//!
//!    The first copy executes and moves the money; the second fails the nonce
//!    check against the account its own first copy bumped. Execution stays
//!    correct — the nonce check is what makes the duplicate harmless — so the
//!    short-circuit is still not needed HERE, and this omission stands.
//!    What broke was the READ path: `tx_index` (tx_hash → height) was
//!    overwritten by the second inclusion, so `solidus_getReceipt` resolved
//!    to the failed execution and reported a successful transfer as failed.
//!    Fixed in `solidus-store2::Store2::persist_block` — first write wins —
//!    and pinned by `a_transaction_included_twice_keeps_the_index_on_its_real_execution`.
//!    Do not "restore" the short-circuit here expecting it to fix receipts.
//! 2. **Receipt persistence inside execution** — the reference executor
//!    *returns* receipts; storage is the node layer's concern (one
//!    WriteBatch per block, Stage 4).
//! 3. **Fee distribution policy** — the live 70/20/10
//!    validator/treasury/burn split survives as
//!    [`types::FeePolicy::LegacyDistribute`] (used by the parity anchor);
//!    the v2 chain default is [`types::FeePolicy::Burn`] (single
//!    supply-counter write, Hazard-C rule). Per-payload fee *amounts* are
//!    preserved verbatim from `solidus-txns`.

pub mod account;
pub mod bridge;
pub mod delta;
pub mod error;
pub mod fee;
pub mod handlers;
pub mod lane;
pub mod mvmemory;
pub mod payment;
pub mod protocol;
pub mod reference;
pub mod twolane;
pub mod types;
pub mod view;
pub mod wire;

pub use account::{Account, AccountType};
pub use delta::{DeltaSet, InMemoryState, StateReader};
pub use error::ExecError;
pub use lane::{partition_lanes, safe_sender, LanePlan};
pub use payment::PaymentOutcome;
pub use reference::{execute_block_reference, BlockOutcome};
pub use twolane::execute_block_twolane;
pub use types::{
    BlockCtx, ExecOptions, ExecOrder, FeePolicy, Lane, StateKey, StateSpace, WireMode,
    DEFAULT_IDENTITY_CAP,
};
pub use view::{SerialView, TxView};

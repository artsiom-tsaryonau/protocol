//! The bridge module (spec §4.2). Every rule here runs only at ProtocolVersion::V2.

pub(crate) mod consent;
// Public: registry §2.7 names it as the chain's one recovery primitive, shared by consent,
// announcements and plan 41's inbound check.
pub mod ecdsa;
pub(crate) mod export;
pub(crate) mod fanout;
pub(crate) mod governance;
pub(crate) mod heartbeat;
mod keys;
pub(crate) mod queue;
pub(crate) mod store;

use solidus_txns::types::Receipt;

use crate::account::Account;
use crate::error::ExecError;
use crate::types::BlockCtx;
use crate::view::TxView;

/// Registry §2.7 names the end-of-block step `solidus_exec::bridge::on_block_end`.
pub(crate) use heartbeat::on_block_end;

pub(crate) const NOT_ACTIVE: &str = "bridge transactions are not active at this height";

/// Every bridge failure path: persist the sender (nonce already bumped), fail the receipt.
pub(crate) fn fail<V: TxView>(
    view: &mut V,
    sender: &Account,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    reason: impl Into<String>,
) -> Result<Receipt, ExecError> {
    crate::handlers::save_account(view, sender)?;
    Ok(crate::handlers::failed_receipt(
        tx_hash,
        ctx.height,
        fee,
        reason.into(),
    ))
}

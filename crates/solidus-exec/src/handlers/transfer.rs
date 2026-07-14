//! `Transfer` — the payment-lane payload (ported verbatim from the live
//! executor's Transfer arm, including the DID-anchor value guard).

use solidus_crypto::keys::Address;
use solidus_txns::token::execute_transfer;
use solidus_txns::types::{Receipt, TxStatus};

use super::{failed_receipt, is_did_anchor, load_account, save_account};
use crate::account::Account;
use crate::error::ExecError;
use crate::types::BlockCtx;
use crate::view::TxView;

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_transfer<V: TxView>(
    view: &mut V,
    mut sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    to: Address,
    amount: u64,
) -> Result<Receipt, ExecError> {
    // Identity/value separation: a DID-anchor account is forbidden from
    // holding or moving value. Reject a Transfer to OR from one. (The
    // recipient guard keeps anchors value-free; the sender guard is
    // defense-in-depth.)
    let from_is_anchor = is_did_anchor(view, ctx.network, &sender_addr)?;
    let to_is_anchor = is_did_anchor(view, ctx.network, &to)?;
    if from_is_anchor || to_is_anchor {
        save_account(view, &sender)?; // fee already taken, nonce bumped
        let which = if from_is_anchor {
            "sender"
        } else {
            "recipient"
        };
        return Ok(failed_receipt(
            tx_hash,
            ctx.height,
            fee,
            format!("{which} is a DID identity anchor; anchors cannot hold or move value"),
        ));
    }

    // execute_transfer validates preconditions (zero amount, self-transfer,
    // balance). fee=0 because the fee was already deducted upstream.
    match execute_transfer(sender_addr, sender.balance, to, amount, 0) {
        Ok(result) => {
            // Deduct transferred amount from sender.
            sender.balance -= result.amount;
            save_account(view, &sender)?;

            // Credit recipient.
            let mut recipient = load_account(view, &to)?;
            recipient.balance += result.amount;
            save_account(view, &recipient)?;

            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: result.events,
            })
        }
        Err(token_err) => {
            // Transfer failed — sender still pays the fee and the nonce
            // still advances (they sent a valid tx).
            save_account(view, &sender)?;
            Ok(failed_receipt(
                tx_hash,
                ctx.height,
                fee,
                token_err.to_string(),
            ))
        }
    }
}

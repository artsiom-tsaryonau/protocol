//! Staking payloads — `Stake` / `Unstake` (ported verbatim, including the
//! MVP immediate-credit unbonding note).

use solidus_crypto::keys::Address;
use solidus_txns::staking::{execute_stake, execute_unstake};
use solidus_txns::types::{Event, Receipt, TxStatus};

use super::{failed_receipt, load_validator, save_account, save_validator};
use crate::account::Account;
use crate::error::ExecError;
use crate::types::BlockCtx;
use crate::view::TxView;

pub(super) fn handle_stake<V: TxView>(
    view: &mut V,
    mut sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    amount: u64,
) -> Result<Receipt, ExecError> {
    let existing = load_validator(view, &sender_addr)?;

    // Fee already deducted upstream, so fee=0 here (matches the live call).
    match execute_stake(&sender_addr, amount, sender.balance, existing.as_ref(), 0) {
        Ok(validator_info) => {
            // Deduct staked amount from sender balance.
            sender.balance -= amount;
            save_account(view, &sender)?;
            save_validator(view, &validator_info)?;

            let total_stake = validator_info.staked;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::Staked {
                    validator: sender_addr,
                    amount,
                    total_stake,
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

pub(super) fn handle_unstake<V: TxView>(
    view: &mut V,
    mut sender: Account,
    sender_addr: Address,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    amount: u64,
) -> Result<Receipt, ExecError> {
    let existing = load_validator(view, &sender_addr)?;

    match execute_unstake(amount, existing.as_ref(), ctx.timestamp_ms) {
        Ok(validator_info) => {
            // MVP semantics preserved: unstaked tokens credit back to the
            // sender immediately; the 21-day unbonding period is tracked in
            // ValidatorInfo but not enforced yet. (Slashing closes this
            // loop in Stage 7.)
            sender.balance += amount;
            save_account(view, &sender)?;
            save_validator(view, &validator_info)?;

            let remaining_stake = validator_info.staked;
            Ok(Receipt {
                tx_hash,
                status: TxStatus::Success,
                block_height: ctx.height,
                fee_paid: fee,
                events: vec![Event::Unstaked {
                    validator: sender_addr,
                    amount,
                    remaining_stake,
                }],
            })
        }
        Err(e) => {
            save_account(view, &sender)?;
            Ok(failed_receipt(tx_hash, ctx.height, fee, e.to_string()))
        }
    }
}

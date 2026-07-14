use solidus_crypto::keys::Address;

use crate::types::Event;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during token transfer execution.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },

    #[error("transfer amount must be greater than zero")]
    ZeroAmount,

    #[error("cannot transfer to self")]
    SelfTransfer,
}

// ---------------------------------------------------------------------------
// Transfer result
// ---------------------------------------------------------------------------

/// Successful transfer outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct TransferResult {
    /// Sender address.
    pub from: Address,
    /// Recipient address.
    pub to: Address,
    /// Amount transferred (excluding fee).
    pub amount: u64,
    /// Fee deducted from the sender.
    pub fee: u64,
    /// Events emitted by this transfer.
    pub events: Vec<Event>,
}

// ---------------------------------------------------------------------------
// Execute
// ---------------------------------------------------------------------------

/// Execute a token transfer, validating all preconditions.
///
/// Returns a `TransferResult` on success or a `TokenError` on failure.
///
/// # Errors
///
/// - `ZeroAmount` — if `amount` is zero.
/// - `SelfTransfer` — if `from == to`.
/// - `InsufficientBalance` — if `from_balance < amount + fee` (overflow-safe).
pub fn execute_transfer(
    from: Address,
    from_balance: u64,
    to: Address,
    amount: u64,
    fee: u64,
) -> Result<TransferResult, TokenError> {
    if amount == 0 {
        return Err(TokenError::ZeroAmount);
    }

    if from == to {
        return Err(TokenError::SelfTransfer);
    }

    let _total_debit = amount
        .checked_add(fee)
        .filter(|&total| total <= from_balance)
        .ok_or(TokenError::InsufficientBalance {
            have: from_balance,
            need: amount.saturating_add(fee),
        })?;

    // Build the transfer event.
    let events = vec![Event::Transfer { from, to, amount }];

    Ok(TransferResult {
        from,
        to,
        amount,
        fee,
        events,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::FEE_TRANSFER;

    fn addr(seed: u8) -> Address {
        Address::from_bytes([seed; 20])
    }

    #[test]
    fn successful_transfer() {
        let from = addr(1);
        let to = addr(2);
        let result = execute_transfer(from, 1_000_000, to, 500_000, FEE_TRANSFER)
            .expect("transfer should succeed");

        assert_eq!(result.from, from);
        assert_eq!(result.to, to);
        assert_eq!(result.amount, 500_000);
        assert_eq!(result.fee, FEE_TRANSFER);
        assert_eq!(result.events.len(), 1);
        assert_eq!(
            result.events[0],
            Event::Transfer {
                from,
                to,
                amount: 500_000,
            }
        );
    }

    #[test]
    fn insufficient_balance_fails() {
        let from = addr(1);
        let to = addr(2);
        let err = execute_transfer(from, 100, to, 200, FEE_TRANSFER)
            .expect_err("should fail with insufficient balance");

        assert_eq!(
            err,
            TokenError::InsufficientBalance {
                have: 100,
                need: 200 + FEE_TRANSFER,
            }
        );
    }

    #[test]
    fn zero_amount_fails() {
        let from = addr(1);
        let to = addr(2);
        let err = execute_transfer(from, 1_000_000, to, 0, FEE_TRANSFER)
            .expect_err("should fail with zero amount");

        assert_eq!(err, TokenError::ZeroAmount);
    }

    #[test]
    fn self_transfer_fails() {
        let same = addr(1);
        let err = execute_transfer(same, 1_000_000, same, 100, FEE_TRANSFER)
            .expect_err("should fail with self transfer");

        assert_eq!(err, TokenError::SelfTransfer);
    }

    #[test]
    fn exact_balance_succeeds() {
        let from = addr(1);
        let to = addr(2);
        let amount = 500_000;
        let fee = FEE_TRANSFER;

        // Balance is exactly amount + fee — should succeed with zero remaining.
        let result = execute_transfer(from, amount + fee, to, amount, fee)
            .expect("exact balance transfer should succeed");

        assert_eq!(result.amount, amount);
        assert_eq!(result.fee, fee);
    }

    #[test]
    fn fee_plus_amount_overflow_fails() {
        let from = addr(1);
        let to = addr(2);

        // amount + fee would overflow u64 → treat as insufficient balance.
        let err =
            execute_transfer(from, u64::MAX, to, u64::MAX, 1).expect_err("should fail on overflow");

        assert_eq!(
            err,
            TokenError::InsufficientBalance {
                have: u64::MAX,
                need: u64::MAX, // saturating_add caps at MAX
            }
        );
    }
}

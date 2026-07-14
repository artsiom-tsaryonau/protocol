use serde::{Deserialize, Serialize};
use solidus_crypto::keys::Address;
use thiserror::Error;

/// On-chain record for a validator (or candidate).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub staked: u64,                     // currently staked amount
    pub unbonding: u64,                  // amount being unstaked (21-day lock)
    pub unbonding_start_ms: Option<u64>, // when unbonding started
    pub reputation: u64,                 // 0-1000
    pub active: bool,                    // whether participating in consensus
}

impl ValidatorInfo {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializable")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Minimum stake to become a validator (10,000 SLDS = 1_000_000_000_000).
pub const MIN_STAKE: u64 = 1_000_000_000_000;

/// Unbonding period in milliseconds (21 days).
pub const UNBONDING_PERIOD_MS: u64 = 21 * 24 * 60 * 60 * 1000;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum StakingError {
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("stake amount must be greater than zero")]
    ZeroAmount,
    #[error("total stake below minimum {min}: would be {total}")]
    BelowMinimum { min: u64, total: u64 },
    #[error("insufficient staked balance: have {have}, want to unstake {requested}")]
    InsufficientStake { have: u64, requested: u64 },
    #[error("unstake would leave below minimum (must fully unstake or stay above {min})")]
    PartialUnstakeBelowMin { min: u64 },
}

/// Execute a Stake operation.
/// Returns the updated ValidatorInfo.
pub fn execute_stake(
    address: &Address,
    amount: u64,
    balance: u64,
    existing: Option<&ValidatorInfo>,
    fee: u64,
) -> Result<ValidatorInfo, StakingError> {
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }
    if balance < amount + fee {
        return Err(StakingError::InsufficientBalance {
            have: balance,
            need: amount + fee,
        });
    }

    let mut info = match existing {
        Some(v) => v.clone(),
        None => ValidatorInfo {
            address: *address,
            staked: 0,
            unbonding: 0,
            unbonding_start_ms: None,
            reputation: 1000,
            active: false,
        },
    };

    let new_total = info.staked + amount;
    if new_total < MIN_STAKE {
        return Err(StakingError::BelowMinimum {
            min: MIN_STAKE,
            total: new_total,
        });
    }

    info.staked = new_total;
    info.active = true;
    Ok(info)
}

/// Execute an Unstake operation.
/// Returns the updated ValidatorInfo.
pub fn execute_unstake(
    amount: u64,
    existing: Option<&ValidatorInfo>,
    timestamp_ms: u64,
) -> Result<ValidatorInfo, StakingError> {
    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }

    let info = existing.ok_or(StakingError::InsufficientStake {
        have: 0,
        requested: amount,
    })?;
    if info.staked < amount {
        return Err(StakingError::InsufficientStake {
            have: info.staked,
            requested: amount,
        });
    }

    let remaining = info.staked - amount;
    // Must either fully unstake or stay above minimum
    if remaining > 0 && remaining < MIN_STAKE {
        return Err(StakingError::PartialUnstakeBelowMin { min: MIN_STAKE });
    }

    let mut updated = info.clone();
    updated.staked = remaining;
    updated.unbonding += amount;
    updated.unbonding_start_ms = Some(timestamp_ms);
    updated.active = remaining >= MIN_STAKE;
    Ok(updated)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::keys::Address;

    fn addr() -> Address {
        Address::from_bytes([0xAB; 20])
    }

    fn make_validator(staked: u64) -> ValidatorInfo {
        ValidatorInfo {
            address: addr(),
            staked,
            unbonding: 0,
            unbonding_start_ms: None,
            reputation: 1000,
            active: staked >= MIN_STAKE,
        }
    }

    // 1. ValidatorInfo serialization roundtrip
    #[test]
    fn validator_info_roundtrip() {
        let v = make_validator(MIN_STAKE);
        let bytes = v.to_bytes();
        let v2 = ValidatorInfo::from_bytes(&bytes).expect("deserialize");
        assert_eq!(v, v2);
    }

    // 2. First stake creates new ValidatorInfo, active=true
    #[test]
    fn stake_success_new_validator() {
        let result = execute_stake(&addr(), MIN_STAKE, MIN_STAKE * 2, None, 0)
            .expect("stake should succeed");
        assert_eq!(result.staked, MIN_STAKE);
        assert!(result.active);
        assert_eq!(result.reputation, 1000);
    }

    // 3. Top up existing stake
    #[test]
    fn stake_success_existing_validator() {
        let existing = make_validator(MIN_STAKE);
        let result = execute_stake(&addr(), MIN_STAKE, MIN_STAKE * 3, Some(&existing), 0)
            .expect("stake should succeed");
        assert_eq!(result.staked, MIN_STAKE * 2);
        assert!(result.active);
    }

    // 4. ZeroAmount error
    #[test]
    fn stake_zero_amount() {
        let err =
            execute_stake(&addr(), 0, MIN_STAKE, None, 0).expect_err("should fail with ZeroAmount");
        assert_eq!(err, StakingError::ZeroAmount);
    }

    // 5. InsufficientBalance error
    #[test]
    fn stake_insufficient_balance() {
        // balance = MIN_STAKE - 1, need MIN_STAKE
        let err = execute_stake(&addr(), MIN_STAKE, MIN_STAKE - 1, None, 0)
            .expect_err("should fail with InsufficientBalance");
        assert!(matches!(err, StakingError::InsufficientBalance { .. }));
    }

    // 6. BelowMinimum error
    #[test]
    fn stake_below_minimum() {
        let small = MIN_STAKE / 2;
        let err = execute_stake(&addr(), small, small * 2, None, 0)
            .expect_err("should fail with BelowMinimum");
        assert!(matches!(err, StakingError::BelowMinimum { .. }));
    }

    // 7. Fully unstake, staked=0, active=false, unbonding set
    #[test]
    fn unstake_success_full() {
        let existing = make_validator(MIN_STAKE);
        let ts = 1_000_000u64;
        let result =
            execute_unstake(MIN_STAKE, Some(&existing), ts).expect("unstake should succeed");
        assert_eq!(result.staked, 0);
        assert!(!result.active);
        assert_eq!(result.unbonding, MIN_STAKE);
        assert_eq!(result.unbonding_start_ms, Some(ts));
    }

    // 8. Unstake some, remain above minimum
    #[test]
    fn unstake_success_partial() {
        let initial = MIN_STAKE * 3;
        let existing = make_validator(initial);
        let ts = 2_000_000u64;
        let unstake_amount = MIN_STAKE; // remaining = MIN_STAKE * 2 >= MIN_STAKE
        let result = execute_unstake(unstake_amount, Some(&existing), ts)
            .expect("partial unstake should succeed");
        assert_eq!(result.staked, MIN_STAKE * 2);
        assert!(result.active);
        assert_eq!(result.unbonding, MIN_STAKE);
        assert_eq!(result.unbonding_start_ms, Some(ts));
    }

    // 9. InsufficientStake error
    #[test]
    fn unstake_insufficient_stake() {
        let existing = make_validator(MIN_STAKE);
        let err = execute_unstake(MIN_STAKE * 2, Some(&existing), 0)
            .expect_err("should fail with InsufficientStake");
        assert!(matches!(err, StakingError::InsufficientStake { .. }));
    }

    // 10. PartialUnstakeBelowMin error
    #[test]
    fn unstake_partial_below_minimum() {
        // staked = MIN_STAKE * 2, unstake MIN_STAKE + 1 → remaining = MIN_STAKE - 1 (below min, non-zero)
        let existing = make_validator(MIN_STAKE * 2);
        let err = execute_unstake(MIN_STAKE + 1, Some(&existing), 0)
            .expect_err("should fail with PartialUnstakeBelowMin");
        assert!(matches!(err, StakingError::PartialUnstakeBelowMin { .. }));
    }
}

//! Commutative fee accumulation + block-end settlement (Hazard-C rule).
//!
//! Per-tx **debits** stay per-tx (a sender pays its own fee out of its own
//! account — no shared key). The fee **destination** is never written
//! per-tx: fees accumulate here and settle with a single policy-dependent
//! write set at block end.

use crate::account::Account;
use crate::delta::{read_through, DeltaSet, StateReader};
use crate::error::ExecError;
use crate::types::{FeePolicy, StateKey};

/// Meta key holding the cumulative amount of fees burned by the v2 chain
/// (`u64` little-endian). Lives outside the root-bearing trees, matching
/// the live chain's meta column family.
pub const META_FEES_BURNED: &[u8] = b"fees_burned_total";

/// The block's commutative fee reducer. Addition-only during execution;
/// read exactly once at settlement.
#[derive(Debug, Default)]
pub struct FeeAccumulator {
    total: u64,
}

impl FeeAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a tx's fee. Saturating: total fees cannot approach `u64::MAX`
    /// under the fixed per-payload fee schedule, but the accumulator must
    /// never wrap or panic on adversarial synthetic streams.
    pub fn charge(&mut self, amount: u64) {
        self.total = self.total.saturating_add(amount);
    }

    pub fn total(&self) -> u64 {
        self.total
    }
}

/// Live-chain fee split, preserved for the parity anchor.
const LEGACY_VALIDATOR_SHARE_PCT: u64 = 70;
const LEGACY_TREASURY_SHARE_PCT: u64 = 20;

/// Settle the block's accumulated fees into the delta, once.
///
/// - [`FeePolicy::Burn`] (v2 default): one write — the cumulative
///   `fees_burned_total` meta counter increases by the block total.
/// - [`FeePolicy::ProposerReward`]: one write — the proposer account is
///   credited the block total.
/// - [`FeePolicy::LegacyDistribute`]: byte-exact port of the live chain's
///   `distribute_fees` — 20% to treasury (if > 0), 70% split equally among
///   validators (skipped when the per-validator share rounds to 0), the
///   remainder implicitly burned. Plain arithmetic mirrors the live code.
pub fn settle<R: StateReader + ?Sized>(
    policy: &FeePolicy,
    fees: &FeeAccumulator,
    delta: &mut DeltaSet,
    baseline: &R,
) -> Result<(), ExecError> {
    let total = fees.total();
    if total == 0 {
        return Ok(());
    }

    match policy {
        FeePolicy::Burn => {
            let key = StateKey::meta(META_FEES_BURNED);
            let prior = match read_through(delta, baseline, &key)? {
                Some(bytes) => decode_u64_le(&bytes)?,
                None => 0,
            };
            let updated = prior.saturating_add(total);
            delta.insert(key, updated.to_le_bytes().to_vec())?;
        }
        FeePolicy::ProposerReward(proposer) => {
            let mut account = load_account(delta, baseline, proposer)?;
            account.balance = account.balance.saturating_add(total);
            delta.insert(StateKey::account(proposer), account.to_bytes())?;
        }
        FeePolicy::LegacyDistribute {
            treasury,
            validators,
        } => {
            // Treasury share — identical order and rounding to the live code.
            let treasury_amount = total * LEGACY_TREASURY_SHARE_PCT / 100;
            if treasury_amount > 0 {
                let mut acct = load_account(delta, baseline, treasury)?;
                acct.balance += treasury_amount;
                delta.insert(StateKey::account(treasury), acct.to_bytes())?;
            }

            // Validator share (split equally).
            if !validators.is_empty() {
                let validator_pool = total * LEGACY_VALIDATOR_SHARE_PCT / 100;
                let per_validator = validator_pool / validators.len() as u64;
                if per_validator > 0 {
                    for vaddr in validators {
                        let mut acct = load_account(delta, baseline, vaddr)?;
                        acct.balance += per_validator;
                        delta.insert(StateKey::account(vaddr), acct.to_bytes())?;
                    }
                }
            }
            // Remainder burned implicitly (no counter on the live chain).
        }
    }
    Ok(())
}

fn load_account<R: StateReader + ?Sized>(
    delta: &DeltaSet,
    baseline: &R,
    addr: &solidus_crypto::keys::Address,
) -> Result<Account, ExecError> {
    match read_through(delta, baseline, &StateKey::account(addr))? {
        Some(bytes) => {
            Account::from_bytes(&bytes).map_err(|e| ExecError::StateDecode(e.to_string()))
        }
        None => Ok(Account::new(*addr)),
    }
}

fn decode_u64_le(bytes: &[u8]) -> Result<u64, ExecError> {
    let arr: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ExecError::StateDecode("fees_burned_total is not 8 bytes".to_string()))?;
    Ok(u64::from_le_bytes(arr))
}

#[cfg(test)]
mod tests {
    use solidus_crypto::keys::Address;

    use super::*;
    use crate::delta::InMemoryState;

    #[test]
    fn zero_total_settles_nothing() {
        let base = InMemoryState::new();
        let mut delta = DeltaSet::new();
        let fees = FeeAccumulator::new();
        settle(&FeePolicy::Burn, &fees, &mut delta, &base).expect("settle");
        assert!(delta.is_empty());
    }

    #[test]
    fn burn_accumulates_across_blocks() {
        let mut base = InMemoryState::new();
        let mut fees = FeeAccumulator::new();
        fees.charge(10_000);

        let mut d1 = DeltaSet::new();
        settle(&FeePolicy::Burn, &fees, &mut d1, &base).expect("settle 1");
        base.apply_delta(&d1);

        let mut d2 = DeltaSet::new();
        settle(&FeePolicy::Burn, &fees, &mut d2, &base).expect("settle 2");

        let bytes = d2.get(&StateKey::meta(META_FEES_BURNED)).expect("counter");
        assert_eq!(decode_u64_le(bytes).expect("decode"), 20_000);
    }

    #[test]
    fn proposer_reward_is_single_credit() {
        let base = InMemoryState::new();
        let proposer = Address::from_bytes([5u8; 20]);
        let mut fees = FeeAccumulator::new();
        fees.charge(30_000);

        let mut delta = DeltaSet::new();
        settle(
            &FeePolicy::ProposerReward(proposer),
            &fees,
            &mut delta,
            &base,
        )
        .expect("settle");

        let acct = Account::from_bytes(delta.get(&StateKey::account(&proposer)).expect("account"))
            .expect("decode");
        assert_eq!(acct.balance, 30_000);
        assert_eq!(delta.len(), 1);
    }

    #[test]
    fn legacy_distribute_matches_70_20_10() {
        let base = InMemoryState::new();
        let treasury = Address::from_bytes([0xAA; 20]);
        let validator = Address::from_bytes([0xBB; 20]);
        let mut fees = FeeAccumulator::new();
        fees.charge(10_000);

        let mut delta = DeltaSet::new();
        settle(
            &FeePolicy::LegacyDistribute {
                treasury,
                validators: vec![validator],
            },
            &fees,
            &mut delta,
            &base,
        )
        .expect("settle");

        let t = Account::from_bytes(delta.get(&StateKey::account(&treasury)).expect("t"))
            .expect("decode");
        let v = Account::from_bytes(delta.get(&StateKey::account(&validator)).expect("v"))
            .expect("decode");
        assert_eq!(t.balance, 2_000);
        assert_eq!(v.balance, 7_000);
    }

    #[test]
    fn legacy_distribute_skips_dust_per_validator_share() {
        // 100 fee units, 71 validators → pool 70, per-validator 0 → skipped,
        // exactly like the live code.
        let base = InMemoryState::new();
        let treasury = Address::from_bytes([0xAA; 20]);
        let validators: Vec<Address> = (0..71u8).map(|i| Address::from_bytes([i; 20])).collect();
        let mut fees = FeeAccumulator::new();
        fees.charge(100);

        let mut delta = DeltaSet::new();
        settle(
            &FeePolicy::LegacyDistribute {
                treasury,
                validators,
            },
            &fees,
            &mut delta,
            &base,
        )
        .expect("settle");

        // Only the treasury write (20 units) lands.
        assert_eq!(delta.len(), 1);
    }

    #[test]
    fn accumulator_saturates() {
        let mut fees = FeeAccumulator::new();
        fees.charge(u64::MAX);
        fees.charge(10);
        assert_eq!(fees.total(), u64::MAX);
    }
}

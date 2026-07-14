//! The v2 account record.
//!
//! **Byte-compatible clone** of the live `solidus-state::account::Account`
//! (same field order, same enum variant order, same bincode encoding) so
//! that account leaves — and therefore the accounts sub-tree root — are
//! identical between the live chain and v2 for the same logical state.
//! The equality is pinned by a cross-crate test in `tests/legacy_parity.rs`.
//! Defined here rather than depending on `solidus-state`, which would drag
//! RocksDB into the executor's production dependency graph.

use serde::{Deserialize, Serialize};
use solidus_crypto::keys::Address;

/// Discriminator for the kind of on-chain account. Variant order is part
/// of the bincode encoding — do not reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountType {
    Regular,
    Validator,
    Treasury,
}

/// On-chain state of a single account. Field order is part of the bincode
/// encoding — do not reorder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub address: Address,
    pub nonce: u64,
    pub balance: u64,
    pub account_type: AccountType,
}

impl Account {
    /// A fresh zero-balance, zero-nonce `Regular` account — the default the
    /// executor materializes for never-seen addresses (matches the live
    /// chain's `load_account` contract).
    pub fn new(address: Address) -> Self {
        Self {
            address,
            nonce: 0,
            balance: 0,
            account_type: AccountType::Regular,
        }
    }

    /// Genesis/test helper with a pre-set balance and type.
    pub fn with_balance(address: Address, balance: u64, account_type: AccountType) -> Self {
        Self {
            address,
            nonce: 0,
            balance,
            account_type,
        }
    }

    /// bincode encoding — identical bytes to the live chain's account leaf.
    pub fn to_bytes(&self) -> Vec<u8> {
        // Fixed-shape POD struct: no bincode error path can fire (matches
        // the live crate's reasoning); the expect is a tripwire for anyone
        // widening the struct with a fallible field.
        #[allow(clippy::expect_used)]
        let bytes =
            bincode::serialize(self).expect("Account serialization cannot fail (POD struct)");
        bytes
    }

    /// Decode an account leaf.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let a = Account::with_balance(Address::from_bytes([7u8; 20]), 42, AccountType::Treasury);
        let b = Account::from_bytes(&a.to_bytes()).expect("decode");
        assert_eq!(a, b);
    }

    #[test]
    fn default_account_is_zeroed_regular() {
        let a = Account::new(Address::from_bytes([1u8; 20]));
        assert_eq!(a.nonce, 0);
        assert_eq!(a.balance, 0);
        assert_eq!(a.account_type, AccountType::Regular);
    }
}

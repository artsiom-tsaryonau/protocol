use serde::{Deserialize, Serialize};
use solidus_crypto::keys::Address;

// ---------------------------------------------------------------------------
// AccountType
// ---------------------------------------------------------------------------

/// Discriminator for the kind of on-chain account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccountType {
    /// A normal end-user account.
    Regular,
    /// A validator that participates in consensus.
    Validator,
    /// The protocol treasury (receives fees, issues rewards).
    Treasury,
}

// ---------------------------------------------------------------------------
// Account
// ---------------------------------------------------------------------------

/// Represents the on-chain state of a single account.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Account {
    /// The 20-byte account address.
    pub address: Address,
    /// Monotonically increasing nonce (replay protection).
    pub nonce: u64,
    /// Balance in the smallest denomination (1 SOLID = 10^8).
    pub balance: u64,
    /// The type of account.
    pub account_type: AccountType,
}

impl Account {
    /// Create a new account with zero balance, zero nonce, and `Regular` type.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            nonce: 0,
            balance: 0,
            account_type: AccountType::Regular,
        }
    }

    /// Create an account with a pre-set balance and account type (useful for
    /// genesis initialization).
    pub fn with_balance(address: Address, balance: u64, account_type: AccountType) -> Self {
        Self {
            address,
            nonce: 0,
            balance,
            account_type,
        }
    }

    /// Serialize the account to bytes using bincode.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Account serialization cannot fail")
    }

    /// Deserialize an account from bytes produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address() -> Address {
        Address::from_bytes([1u8; 20])
    }

    #[test]
    fn new_account_has_zero_balance_and_nonce() {
        let acct = Account::new(test_address());
        assert_eq!(acct.balance, 0);
        assert_eq!(acct.nonce, 0);
        assert_eq!(acct.account_type, AccountType::Regular);
        assert_eq!(acct.address, test_address());
    }

    #[test]
    fn with_balance_sets_fields() {
        let addr = test_address();
        let acct = Account::with_balance(addr, 1_000_000, AccountType::Validator);
        assert_eq!(acct.balance, 1_000_000);
        assert_eq!(acct.nonce, 0);
        assert_eq!(acct.account_type, AccountType::Validator);
        assert_eq!(acct.address, addr);
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let original = Account::with_balance(test_address(), 42_000, AccountType::Treasury);
        let bytes = original.to_bytes();
        let recovered = Account::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(original, recovered);
    }
}

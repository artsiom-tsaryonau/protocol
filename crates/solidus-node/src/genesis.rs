use std::collections::HashMap;

use serde::Deserialize;

use solidus_crypto::keys::Address;
use solidus_state::account::{Account, AccountType};
use solidus_state::executor::save_account;
use solidus_state::store::Store;

/// Genesis configuration loaded from a JSON file.
#[derive(Debug, Deserialize)]
pub struct GenesisConfig {
    /// Unique identifier for this chain.
    pub chain_id: String,
    /// Base58-encoded address of the protocol treasury.
    pub treasury_address: String,
    /// Base58-encoded addresses of initial validators.
    pub validator_addresses: Vec<String>,
    /// Map of base58-encoded address to initial balance.
    pub initial_balances: HashMap<String, u64>,
}

/// Load genesis state into the store.
///
/// For each entry in `initial_balances`, the account type is determined by
/// whether the address matches the treasury, a validator, or neither.
///
/// Returns the parsed `(treasury_address, validator_addresses)`.
pub fn load_genesis(
    store: &Store,
    genesis: &GenesisConfig,
) -> Result<(Address, Vec<Address>), Box<dyn std::error::Error>> {
    let treasury = Address::from_base58(&genesis.treasury_address)?;

    let validators: Vec<Address> = genesis
        .validator_addresses
        .iter()
        .map(|s| Address::from_base58(s))
        .collect::<Result<Vec<_>, _>>()?;

    for (addr_str, &balance) in &genesis.initial_balances {
        let address = Address::from_base58(addr_str)?;

        let account_type = if address == treasury {
            AccountType::Treasury
        } else if validators.contains(&address) {
            AccountType::Validator
        } else {
            AccountType::Regular
        };

        let account = Account::with_balance(address, balance, account_type);
        save_account(store, &account)?;
    }

    Ok((treasury, validators))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_state::executor::load_account;
    use solidus_state::store::Store;
    use tempfile::tempdir;

    /// Helper: open a store in a fresh temp directory.
    fn open_tmp() -> (Store, tempfile::TempDir) {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Store::open(dir.path()).expect("failed to open store");
        (store, dir)
    }

    /// Helper: create a deterministic 20-byte address from a seed byte and
    /// return its base58 encoding.
    fn make_address(seed: u8) -> (Address, String) {
        let addr = Address::from_bytes([seed; 20]);
        let b58 = addr.to_base58();
        (addr, b58)
    }

    #[test]
    fn load_genesis_creates_accounts() {
        let (store, _dir) = open_tmp();

        let (treasury_addr, treasury_b58) = make_address(0xAA);
        let (validator_addr, validator_b58) = make_address(0xBB);
        let (regular_addr, regular_b58) = make_address(0xCC);

        let mut initial_balances = HashMap::new();
        initial_balances.insert(treasury_b58.clone(), 10_000_000);
        initial_balances.insert(validator_b58.clone(), 5_000_000);
        initial_balances.insert(regular_b58.clone(), 1_000_000);

        let genesis = GenesisConfig {
            chain_id: "solidus-testnet".to_string(),
            treasury_address: treasury_b58,
            validator_addresses: vec![validator_b58],
            initial_balances,
        };

        let (ret_treasury, ret_validators) =
            load_genesis(&store, &genesis).expect("load_genesis failed");

        // Verify returned addresses match.
        assert_eq!(ret_treasury, treasury_addr);
        assert_eq!(ret_validators.len(), 1);
        assert_eq!(ret_validators[0], validator_addr);

        // Verify treasury account.
        let treasury_acct = load_account(&store, &treasury_addr).expect("load treasury failed");
        assert_eq!(treasury_acct.balance, 10_000_000);
        assert_eq!(treasury_acct.account_type, AccountType::Treasury);

        // Verify validator account.
        let validator_acct =
            load_account(&store, &validator_addr).expect("load validator failed");
        assert_eq!(validator_acct.balance, 5_000_000);
        assert_eq!(validator_acct.account_type, AccountType::Validator);

        // Verify regular account.
        let regular_acct = load_account(&store, &regular_addr).expect("load regular failed");
        assert_eq!(regular_acct.balance, 1_000_000);
        assert_eq!(regular_acct.account_type, AccountType::Regular);
    }
}

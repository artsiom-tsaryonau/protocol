use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use solidus_crypto::keys::Address;
use solidus_state::account::{Account, AccountType};
use solidus_state::executor::{save_account, save_committed_account};
use solidus_state::store::{Store, CF_ACCOUNTS};

/// Metadata describing the chain's native token.
///
/// Surfaced over JSON-RPC (`solidus_chainInfo`) so wallets, explorers,
/// indexers, and listing aggregators can self-discover the symbol and
/// decimal precision instead of hardcoding them.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct NativeTokenMetadata {
    /// Display symbol — `"SLDS"`. Uppercase, no `$` prefix.
    pub symbol: String,
    /// Display name — `"Solidus"`.
    pub name: String,
    /// Decimal precision. `8` → `1 SLDS = 10^8` base units. No named sub-unit.
    pub decimals: u8,
}

impl Default for NativeTokenMetadata {
    /// The default is a deliberate sentinel, not a usable value: a genesis
    /// file that omits `native_token` deserializes to `"TESTNET-SOLI"`,
    /// which screams "this genesis lacks metadata, regenerate it" rather
    /// than silently masquerading as the real `"SLDS"` token.
    fn default() -> Self {
        Self {
            symbol: "TESTNET-SOLI".to_string(),
            name: "Solidus (testnet, no metadata)".to_string(),
            decimals: 8,
        }
    }
}

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
    /// Native token metadata. `#[serde(default)]` keeps pre-2026-05-18
    /// genesis files (which predate this field) loadable — they surface the
    /// `TESTNET-SOLI` sentinel rather than failing to parse.
    #[serde(default)]
    pub native_token: NativeTokenMetadata,
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

        // Genesis initializes each account exactly once. If the account already
        // exists (node restart on a populated store), skip it — overwriting it
        // would reset accumulated balances to genesis on every restart, wiping
        // all state.
        if store.get(CF_ACCOUNTS, address.as_bytes())?.is_some() {
            continue;
        }

        let account_type = if address == treasury {
            AccountType::Treasury
        } else if validators.contains(&address) {
            AccountType::Validator
        } else {
            AccountType::Regular
        };

        let account = Account::with_balance(address, balance, account_type);
        save_account(store, &account)?;
        // Genesis allocations must also land in the committed view so RPC
        // (`getBalance`/`getNonce`) returns them before the first 3-chain
        // commit ever fires.
        save_committed_account(store, &account)?;
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
            native_token: NativeTokenMetadata::default(),
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
        let validator_acct = load_account(&store, &validator_addr).expect("load validator failed");
        assert_eq!(validator_acct.balance, 5_000_000);
        assert_eq!(validator_acct.account_type, AccountType::Validator);

        // Verify regular account.
        let regular_acct = load_account(&store, &regular_addr).expect("load regular failed");
        assert_eq!(regular_acct.balance, 1_000_000);
        assert_eq!(regular_acct.account_type, AccountType::Regular);
    }

    #[test]
    fn load_genesis_preserves_existing_account_balance() {
        // Genesis must initialize accounts only once. On restart (load_genesis
        // runs again on a populated store) it must NOT reset balances back to
        // their genesis values — otherwise every node restart wipes all
        // accumulated state. Regression: a restarted validator's recipient
        // balance reset to genesis, failing real-tx rejoin.
        let (store, _dir) = open_tmp();

        let (_treasury_addr, treasury_b58) = make_address(0xAA);
        let (validator_addr, validator_b58) = make_address(0xBB);

        let mut initial_balances = HashMap::new();
        initial_balances.insert(treasury_b58.clone(), 10_000_000);
        initial_balances.insert(validator_b58.clone(), 5_000_000);

        let genesis = GenesisConfig {
            chain_id: "solidus-testnet".to_string(),
            treasury_address: treasury_b58,
            validator_addresses: vec![validator_b58],
            initial_balances,
            native_token: NativeTokenMetadata::default(),
        };

        // First boot: accounts created with genesis balances.
        load_genesis(&store, &genesis).expect("first load_genesis failed");

        // Accumulate state: the validator account receives a transfer.
        let mut acct = load_account(&store, &validator_addr).expect("load validator failed");
        acct.balance += 2_000;
        save_account(&store, &acct).expect("save failed");

        // Restart: load_genesis runs again on the now-populated store.
        load_genesis(&store, &genesis).expect("second load_genesis failed");

        // The accumulated balance must survive — NOT be reset to 5_000_000.
        let after = load_account(&store, &validator_addr).expect("load validator failed");
        assert_eq!(
            after.balance, 5_002_000,
            "genesis re-apply wiped accumulated state"
        );
    }

    #[test]
    fn native_token_metadata_serde_roundtrip() {
        let token = NativeTokenMetadata {
            symbol: "SLDS".to_string(),
            name: "Solidus".to_string(),
            decimals: 8,
        };
        let json = serde_json::to_string(&token).expect("serialize");
        let back: NativeTokenMetadata = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(token, back);
    }

    #[test]
    fn native_token_metadata_default_is_sentinel() {
        let def = NativeTokenMetadata::default();
        assert_eq!(def.symbol, "TESTNET-SOLI");
        assert_eq!(def.decimals, 8);
    }

    #[test]
    fn genesis_config_uses_sentinel_when_native_token_absent() {
        // A genesis JSON predating the native_token field still parses,
        // surfacing the TESTNET-SOLI sentinel via #[serde(default)].
        let json = r#"{
            "chain_id": "solidus-testnet-1",
            "treasury_address": "treasury",
            "validator_addresses": [],
            "initial_balances": {}
        }"#;
        let cfg: GenesisConfig = serde_json::from_str(json).expect("parse legacy genesis");
        assert_eq!(cfg.native_token.symbol, "TESTNET-SOLI");
    }

    #[test]
    fn genesis_config_reads_native_token_when_present() {
        let json = r#"{
            "chain_id": "solidus-testnet-1",
            "treasury_address": "treasury",
            "validator_addresses": [],
            "initial_balances": {},
            "native_token": { "symbol": "SLDS", "name": "Solidus", "decimals": 8 }
        }"#;
        let cfg: GenesisConfig = serde_json::from_str(json).expect("parse genesis");
        assert_eq!(cfg.native_token.symbol, "SLDS");
        assert_eq!(cfg.native_token.name, "Solidus");
        assert_eq!(cfg.native_token.decimals, 8);
    }
}

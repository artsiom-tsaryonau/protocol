use std::collections::HashMap;
use std::fs;
use std::path::Path;

use rand::RngCore;
use serde::{Deserialize, Serialize};

use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisFile {
    pub chain_id: String,
    pub timestamp: String,
    pub round_seed: String,
    pub validators: Vec<GenesisValidator>,
    pub initial_balances: HashMap<String, u64>,
    pub params: GenesisParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub ed25519_public_key: String,
    pub bls_public_key: String,
    pub stake: u64,
    pub reputation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisParams {
    pub block_time_ms: u64,
    pub committee_size: usize,
    pub quorum_threshold: usize,
    pub round_timeout_ms: u64,
    pub max_block_txs: usize,
}

// ---------------------------------------------------------------------------
// Main generation function
// ---------------------------------------------------------------------------

/// Generate a complete testnet configuration and write it to `output_dir`.
///
/// Creates:
/// - `genesis.json` at the root of `output_dir`
/// - `validator-N/` directories (0-indexed) each containing:
///   - `node.key`   — Ed25519 secret key (hex)
///   - `bls.key`    — BLS12-381 secret key (hex)
///   - `config.toml`— node configuration
/// - `treasury.key` — treasury Ed25519 secret key (hex)
/// - `faucet.key`   — faucet Ed25519 secret key (hex)
pub fn generate_genesis(
    num_validators: usize,
    output_dir: &Path,
    chain_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(output_dir)?;

    // --- Generate random round_seed ---
    let mut round_seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut round_seed);
    let round_seed_hex = hex::encode(round_seed);

    // --- Generate validator keys and dirs ---
    let mut validators = Vec::with_capacity(num_validators);
    let mut initial_balances: HashMap<String, u64> = HashMap::new();

    let validator_stake: u64 = 10_000_000 * 100_000_000; // 10M SOLID

    for i in 0..num_validators {
        // Ed25519 key pair
        let ed_signing_key = generate_signing_key();
        let ed_verifying_key = ed_signing_key.verifying_key();
        let ed_secret_hex = hex::encode(ed_signing_key.to_bytes());
        let ed_public_hex = hex::encode(ed_verifying_key.to_bytes());

        // BLS key pair
        let bls_sk = BlsSecretKey::generate();
        let bls_pk = bls_sk.public_key();
        let bls_secret_hex = hex::encode(bls_sk.to_bytes());
        let bls_public_hex = bls_pk.to_hex();

        // Derive address from Ed25519 public key
        let address = Address::from_public_key(&ed_verifying_key);
        let address_b58 = address.to_base58();

        // Create validator directory
        let val_dir = output_dir.join(format!("validator-{i}"));
        fs::create_dir_all(&val_dir)?;

        // Write node.key (ed25519 secret, hex)
        fs::write(val_dir.join("node.key"), &ed_secret_hex)?;

        // Write bls.key (bls secret, hex)
        fs::write(val_dir.join("bls.key"), &bls_secret_hex)?;

        // Build peer list (all validators except self)
        let peers: Vec<(usize, u16)> = (0..num_validators)
            .filter(|&j| j != i)
            .map(|j| (j, 30300 + j as u16))
            .collect();

        let peer_entries: String = peers
            .iter()
            .map(|(idx, port)| {
                format!(
                    "\n[[peers]]\nindex = {idx}\naddress = \"127.0.0.1:{port}\"\n"
                )
            })
            .collect::<Vec<_>>()
            .join("");

        let listen_port = 30300 + i as u16;
        let rpc_port = 8080 + i as u16;

        let config_toml = format!(
            r#"[node]
chain_id = "{chain_id}"
listen_port = {listen_port}
data_dir = "./data"
genesis = "../genesis.json"
ed25519_key = "node.key"
bls_key = "bls.key"
rpc_port = {rpc_port}
node_index = {i}
{peer_entries}"#
        );

        fs::write(val_dir.join("config.toml"), config_toml)?;

        // Add to initial balances
        initial_balances.insert(address_b58.clone(), validator_stake);

        validators.push(GenesisValidator {
            address: address_b58,
            ed25519_public_key: ed_public_hex,
            bls_public_key: bls_public_hex,
            stake: validator_stake,
            reputation: 100,
        });
    }

    // --- Generate treasury key ---
    let treasury_signing_key = generate_signing_key();
    let treasury_address =
        Address::from_public_key(&treasury_signing_key.verifying_key()).to_base58();
    let treasury_secret_hex = hex::encode(treasury_signing_key.to_bytes());
    fs::write(output_dir.join("treasury.key"), &treasury_secret_hex)?;

    let treasury_balance: u64 = 50_000_000 * 100_000_000; // 50M SOLID
    initial_balances.insert(treasury_address.clone(), treasury_balance);

    // --- Generate faucet key ---
    let faucet_signing_key = generate_signing_key();
    let faucet_address =
        Address::from_public_key(&faucet_signing_key.verifying_key()).to_base58();
    let faucet_secret_hex = hex::encode(faucet_signing_key.to_bytes());
    fs::write(output_dir.join("faucet.key"), &faucet_secret_hex)?;

    let faucet_balance: u64 = 20_000_000 * 100_000_000; // 20M SOLID
    initial_balances.insert(faucet_address.clone(), faucet_balance);

    // --- Quorum threshold: (n * 2 / 3) + 1 ---
    let quorum_threshold = (num_validators * 2 / 3) + 1;

    // --- Timestamp ---
    // Use a simple RFC 3339 timestamp without external crate dependency.
    // We build an approximate UTC timestamp from SystemTime.
    let timestamp = system_time_iso8601();

    // --- GenesisParams ---
    let params = GenesisParams {
        block_time_ms: 500,
        committee_size: num_validators,
        quorum_threshold,
        round_timeout_ms: 2000,
        max_block_txs: 1000,
    };

    // --- GenesisFile ---
    let genesis = GenesisFile {
        chain_id: chain_id.to_string(),
        timestamp,
        round_seed: round_seed_hex,
        validators,
        initial_balances,
        params,
    };

    // --- Write genesis.json (pretty-printed) ---
    let genesis_json = serde_json::to_string_pretty(&genesis)?;
    fs::write(output_dir.join("genesis.json"), genesis_json)?;

    Ok(())
}

/// Return a best-effort ISO 8601 UTC timestamp using only `std`.
fn system_time_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Convert unix seconds to a readable date string.
    // We implement a minimal algorithm; no external crate needed.
    let (year, month, day, hour, min, sec) = unix_to_datetime(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Decompose Unix epoch seconds into (year, month, day, hour, min, sec) UTC.
fn unix_to_datetime(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec = secs % 60;
    let mins = secs / 60;
    let min = mins % 60;
    let hours = mins / 60;
    let hour = hours % 24;
    let days = hours / 24;

    // Days since 1970-01-01
    let mut remaining_days = days;
    let mut year = 1970u64;
    loop {
        let days_in_year = if is_leap(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let month_lengths = [
        31u64,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 1u64;
    for &ml in &month_lengths {
        if remaining_days < ml {
            break;
        }
        remaining_days -= ml;
        month += 1;
    }
    let day = remaining_days + 1;

    (year, month, day, hour, min, sec)
}

fn is_leap(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use tempfile::tempdir;

    #[test]
    fn generate_4_validator_genesis() {
        let dir = tempdir().expect("failed to create temp dir");
        let output = dir.path();

        generate_genesis(4, output, "solidus-testnet-1")
            .expect("generate_genesis failed");

        // --- genesis.json exists and parses ---
        let genesis_path = output.join("genesis.json");
        assert!(genesis_path.exists(), "genesis.json missing");

        let genesis_str =
            fs::read_to_string(&genesis_path).expect("failed to read genesis.json");
        let genesis: GenesisFile =
            serde_json::from_str(&genesis_str).expect("failed to parse genesis.json");

        // --- 4 validators ---
        assert_eq!(genesis.validators.len(), 4, "expected 4 validators");

        // --- quorum threshold = (4 * 2 / 3) + 1 = 3 ---
        assert_eq!(
            genesis.params.quorum_threshold, 3,
            "expected quorum_threshold = 3"
        );

        // --- each validator dir has node.key, bls.key, config.toml ---
        for i in 0..4 {
            let val_dir = output.join(format!("validator-{i}"));
            assert!(
                val_dir.exists(),
                "validator-{i} directory missing"
            );
            assert!(
                val_dir.join("node.key").exists(),
                "validator-{i}/node.key missing"
            );
            assert!(
                val_dir.join("bls.key").exists(),
                "validator-{i}/bls.key missing"
            );
            assert!(
                val_dir.join("config.toml").exists(),
                "validator-{i}/config.toml missing"
            );
        }

        // --- treasury.key and faucet.key exist ---
        assert!(output.join("treasury.key").exists(), "treasury.key missing");
        assert!(output.join("faucet.key").exists(), "faucet.key missing");

        // --- 6 initial balances: 4 validators + treasury + faucet ---
        assert_eq!(
            genesis.initial_balances.len(),
            6,
            "expected 6 initial balances"
        );
    }

    #[test]
    fn genesis_validator_keys_are_unique() {
        let dir = tempdir().expect("failed to create temp dir");
        let output = dir.path();

        generate_genesis(4, output, "solidus-testnet-1")
            .expect("generate_genesis failed");

        let genesis_str =
            fs::read_to_string(output.join("genesis.json")).expect("failed to read genesis.json");
        let genesis: GenesisFile =
            serde_json::from_str(&genesis_str).expect("failed to parse genesis.json");

        // All validator addresses are distinct
        let addresses: HashSet<&str> = genesis
            .validators
            .iter()
            .map(|v| v.address.as_str())
            .collect();

        assert_eq!(
            addresses.len(),
            genesis.validators.len(),
            "validator addresses are not all unique"
        );
    }
}

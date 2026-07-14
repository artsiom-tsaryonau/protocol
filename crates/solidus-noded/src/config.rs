//! Daemon configuration — one TOML file per validator. Everything a node
//! needs to join the network: its identity + secret keys, the full validator
//! set (the committee), the peer directory, and the genesis allocations. The
//! founder-only *values* (real chain-id, real genesis, real validator set)
//! live here as data; the daemon is the machinery that runs whatever this
//! file says.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct DaemonConfig {
    /// Chain id — the network's identity (R-WIRE: v2 signs over this).
    pub chain_id: u64,
    /// Human-readable network name (domain-separates gossip topics).
    pub network: String,
    /// This validator's index in the committee (0-based).
    pub index: u32,
    /// RocksDB data directory for this node.
    pub data_dir: String,
    /// JSON-RPC bind address, e.g. `127.0.0.1:8545`.
    pub rpc_addr: String,
    /// libp2p listen multiaddr, e.g. `/ip4/0.0.0.0/tcp/7000`.
    pub listen_addr: String,
    /// This node's BLS consensus secret key (32-byte hex).
    pub bls_secret_hex: String,
    /// This node's libp2p ed25519 secret seed (32-byte hex).
    pub p2p_secret_hex: String,
    /// The full validator set (the committee), ordered by index.
    pub validators: Vec<ValidatorEntry>,
    /// The other validators' peer id + dial address.
    pub peers: Vec<PeerEntry>,
    /// Genesis account allocations (identical on every node).
    pub genesis: Vec<GenesisAlloc>,
    /// Mempool/block tuning (optional; sensible defaults).
    #[serde(default)]
    pub tuning: TuningCfg,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ValidatorEntry {
    pub index: u32,
    /// BLS public key (48-byte hex).
    pub bls_pubkey_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PeerEntry {
    pub index: u32,
    /// libp2p peer id (base58).
    pub peer_id: String,
    /// Dial multiaddr.
    pub multiaddr: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GenesisAlloc {
    /// 20-byte account address (hex).
    pub address_hex: String,
    pub balance: u64,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TuningCfg {
    pub max_certs_per_block: usize,
    pub batch_max_bytes: usize,
    pub batch_max_txs: usize,
    pub flush_interval_ms: u64,
}

impl Default for TuningCfg {
    fn default() -> Self {
        Self {
            max_certs_per_block: 64,
            batch_max_bytes: 256 * 1024,
            batch_max_txs: 200,
            flush_interval_ms: 25,
        }
    }
}

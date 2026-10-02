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
    /// secp256k1 attestation key, 32 bytes of hex. Absent on a node that validates but does not
    /// attest, which is every node until the key is deployed.
    ///
    /// ⚠ A DIFFERENT KEY FROM `bls_secret_hex`, deliberately. A stolen attestation key forges
    /// bridge messages up to the threshold and cannot touch consensus; a stolen consensus key
    /// cannot forge a bridge message at all.
    #[serde(default)]
    pub bridge_attestation_secret_hex: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ValidatorEntry {
    pub index: u32,
    /// BLS public key (48-byte hex).
    pub bls_pubkey_hex: String,
    /// BLS proof of possession (96-byte hex). Required on every entry once any
    /// entry has one; required on all before `POP_ACTIVATION_VIEW` is scheduled.
    #[serde(default)]
    pub bls_pop_hex: Option<String>,
    /// The address this validator's attestations recover to (20-byte hex), so
    /// `solidus_getCommittee` can report who is expected to sign. Absent until that validator has
    /// a key: an absent address means "not expected to sign", not "signs as zero".
    #[serde(default)]
    pub attestation_address: Option<String>,
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
    /// Blocks kept behind the head before cold data is pruned. `0` disables.
    ///
    /// ⛔ `serde(default)` IS LOAD-BEARING, NOT TIDINESS. Every `node*.toml`
    /// already deployed carries a `[tuning]` block with exactly the four fields
    /// above. A required field here would fail to deserialize on every existing
    /// config, so an upgrade would brick a running validator set at boot rather
    /// than at build time.
    #[serde(default = "default_block_retention")]
    pub block_retention: u64,
    /// Minimum gap between this node's own proposals, ms. `0` disables pacing.
    ///
    /// ⛔ MEASURED WHY THIS EXISTS: with no pacing the live testnet produced
    /// **8,60 blocks/s, one every 116ms**, every one empty, against the 2,0s
    /// target the explorer states. `enter_view` proposes the instant this node
    /// leads and a view closes as soon as a QC forms, which on four validators
    /// over loopback is ~116ms.
    ///
    /// ⚠ SET `view_timeout_ms` WITH IT OR THE NODE REFUSES TO START. A view with
    /// no proposal by its timeout rotates leadership, so pacing above the timeout
    /// produces blocks at the BACKOFF rate with a timeout certificate each —
    /// while the chain still commits and looks healthy from outside.
    #[serde(default)]
    pub min_block_interval_ms: u64,
    /// View timeout base, ms. `0` keeps the pacemaker default (400ms).
    #[serde(default)]
    pub view_timeout_ms: u64,
    /// Propose an empty block after this long with nothing to include. `0`
    /// disables empty-block suppression.
    ///
    /// ⛔ SUPPRESSION IS ONLY SAFE BECAUSE CERTIFICATES ARE GOSSIPED. Before
    /// that a leader held only its own share of the committee's work, so this
    /// silenced leaders that simply had not assembled the batch themselves, and
    /// three attempts stalled the chain. ⚠ Keep it long; v1 uses 600s.
    #[serde(default)]
    pub idle_heartbeat_ms: u64,
    /// Work must be absent CONTINUOUSLY this long before a view is suppressed.
    /// ⚠ Must exceed batch flush + ack round trip, or a busy chain pays a view
    /// timeout in every gap between certificates.
    #[serde(default)]
    pub idle_grace_ms: u64,
}

/// Keep ~1M blocks. ⛔ That is about **269 MB** per validator, not the 100 MB this
/// comment claimed: re-measured 2026-09-24 on the rpc box as 269 MB of SST each
/// across all four validators, so **0.269 KB/block**, 2.7x the 0.1 KB/block the
/// old note carried. 1.17 GB across the four. See `solidus-node2/src/config.rs`
/// for the split between SST and the RocksDB info LOG, and for why the 09-02
/// devnet figure is not comparable.
fn default_block_retention() -> u64 {
    1_000_000
}

impl Default for TuningCfg {
    fn default() -> Self {
        Self {
            max_certs_per_block: 64,
            batch_max_bytes: 256 * 1024,
            batch_max_txs: 200,
            flush_interval_ms: 25,
            block_retention: default_block_retention(),
            min_block_interval_ms: 0,
            view_timeout_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
        }
    }
}

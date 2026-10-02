mod backfill;
mod config;
mod genesis;
mod genesis_cmd;
mod node_config;

use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

use solidus_consensus::hotstuff::{HotStuffConfig, HotStuffEngine};
use solidus_consensus::mempool::Mempool;
use solidus_consensus::proposer::{Proposer, ProposerConfig};
use solidus_consensus::types::{TimeoutVote, ValidatorIdentity};
use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey};
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use solidus_p2p::channel::create_channel_network;
use solidus_p2p::message::ConsensusMessage;
use solidus_p2p::transport::{ConsensusTransport, SourcePeer};
use solidus_rpc::methods::ChainMeta;
use solidus_rpc::server::start_rpc_server;
use solidus_rpc::types::RpcNativeToken;
use solidus_state::store::Store;

use crate::config::NodeConfig;
use crate::genesis::GenesisConfig;
use crate::genesis_cmd::GenesisFile;
use crate::node_config::MultiNodeConfig;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "solidus-node", about = "Solidus Protocol Node")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a complete testnet configuration (genesis.json, validator dirs, keys).
    Genesis {
        /// Number of validators to generate.
        #[arg(short = 'n', long, default_value = "4")]
        validators: usize,
        /// Output directory for the generated configuration.
        #[arg(short, long, default_value = "./testnet")]
        output: String,
        /// Chain identifier.
        #[arg(long, default_value = "solidus-testnet-1")]
        chain_id: String,
    },
    /// Start the node (default when no subcommand is given).
    Run {
        /// Path to the TOML configuration file.
        #[arg(short, long, default_value = "config.toml")]
        config: String,
        /// Enable HotStuff BFT consensus mode (multi-node).
        /// When false (default), the legacy single-node proposer is used.
        #[arg(long, default_value = "false")]
        consensus: bool,
        /// Run as a non-validating full node (C2): discover the network from
        /// `bootstrap_peers`, sync the canon by libp2p PeerId, serve RPC, and
        /// never propose/vote. Overrides `--consensus` when set. The same flag
        /// can also be set in the config file (`full_node = true`).
        #[arg(long, default_value = "false")]
        full_node: bool,
    },
    /// Run a dev testnet: all validators in one process (channel transport).
    /// Uses the genesis config to spawn N validators with shared channel transport.
    DevTestnet {
        /// Path to the testnet directory (containing genesis.json + validator-N/ dirs).
        #[arg(short, long, default_value = "./testnet")]
        testnet_dir: String,
        /// RPC port for the primary validator (validator-0).
        #[arg(long, default_value = "9944")]
        rpc_port: u16,
        /// RPC bind host for the primary validator. Defaults to loopback-only
        /// (matches prior hardcoded behavior — no change for existing callers).
        /// Container/compose use (e.g. local devnet) must pass 0.0.0.0
        /// explicitly to be reachable via Docker's port mapping / from other
        /// containers on the same network — Docker's port forwarding targets
        /// the container's own interface, not its loopback.
        #[arg(long, default_value = "127.0.0.1")]
        rpc_host: String,
        /// Directory for the chain database. Defaults to `<testnet-dir>/dev-data`
        /// (prior behaviour). Set it to keep keys read-only (e.g. a Kubernetes
        /// Secret) and the database on a separate writable volume.
        #[arg(long)]
        data_dir: Option<String>,
    },
    /// Print the libp2p PeerId derived from a node.key file.
    PeerId {
        /// Path to the node.key file (hex-encoded Ed25519 secret).
        #[arg(short, long, default_value = "node.key")]
        key: String,
    },
    /// Dump the canonical ledger index (canon head + per-seq hashes) for a node.
    /// Run only while the node is stopped (RocksDB is single-writer).
    CanonDump {
        /// Path to the node's TOML configuration file.
        #[arg(short, long, default_value = "config.toml")]
        config: String,
    },
    /// Build + sign a Transfer transaction and print it as JSON (for E2E /
    /// manual submission via solidus_sendTransaction).
    SignTransfer {
        /// Path to the sender's Ed25519 secret key file (hex).
        #[arg(long)]
        key: String,
        /// Recipient address (base58).
        #[arg(long)]
        to: String,
        /// Amount to transfer.
        #[arg(long)]
        amount: u64,
        /// Sender nonce.
        #[arg(long)]
        nonce: u64,
    },
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

/// Resolve on Ctrl+C (SIGINT) or, on Unix, SIGTERM — the signal container runtimes
/// (Docker, Kubernetes) send on stop. Without it a pod is SIGKILLed after the grace
/// period and RocksDB never sees a clean shutdown.
async fn shutdown_signal() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            r = tokio::signal::ctrl_c() => r,
            _ = term.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Genesis {
            validators,
            output,
            chain_id,
        }) => {
            let output_path = std::path::Path::new(&output);
            genesis_cmd::generate_genesis(validators, output_path, &chain_id)?;
            info!(
                validators = validators,
                output = %output,
                chain_id = %chain_id,
                "genesis configuration generated successfully"
            );
        }
        Some(Commands::Run {
            config,
            consensus,
            full_node,
        }) => {
            if full_node {
                run_full_node(&config).await?;
            } else if consensus {
                run_consensus_node(&config).await?;
            } else {
                run_node(&config).await?;
            }
        }
        Some(Commands::DevTestnet {
            testnet_dir,
            rpc_port,
            rpc_host,
            data_dir,
        }) => {
            run_dev_testnet(&testnet_dir, rpc_port, &rpc_host, data_dir.as_deref()).await?;
        }
        Some(Commands::PeerId { key }) => {
            println!("{}", peer_id_from_key_file(Path::new(&key))?);
        }
        Some(Commands::CanonDump { config }) => {
            canon_dump(&config)?;
        }
        Some(Commands::SignTransfer {
            key,
            to,
            amount,
            nonce,
        }) => {
            sign_transfer(&key, &to, amount, nonce)?;
        }
        // Default: run the node with config.toml in legacy mode
        None => {
            run_node("config.toml").await?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy single-node startup logic
// ---------------------------------------------------------------------------

async fn run_node(config_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Load config (with fallback to defaults)
    let cfg = match NodeConfig::from_file(config_path) {
        Ok(c) => {
            info!(path = %config_path, "loaded config");
            c
        }
        Err(e) => {
            info!(
                error = %e,
                "failed to load config, using defaults"
            );
            NodeConfig::default()
        }
    };

    // 2. Create data_dir, open Store
    std::fs::create_dir_all(&cfg.data_dir)?;
    let store = Arc::new(Store::open(&cfg.data_dir)?);
    info!(data_dir = %cfg.data_dir.display(), "opened store");

    // 3. Load genesis from JSON file
    let genesis_contents = std::fs::read_to_string(&cfg.genesis_file)?;
    let genesis_config: GenesisConfig = serde_json::from_str(&genesis_contents)?;
    let chain_id = genesis_config.chain_id.clone();

    let (treasury_address, validator_addresses) = genesis::load_genesis(&store, &genesis_config)?;
    info!(
        chain_id = %chain_id,
        treasury = %treasury_address,
        validators = validator_addresses.len(),
        "loaded genesis"
    );

    // 4. Create shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 5. Start RPC server.
    // Legacy single-node mode does not run the HotStuff committee, so the
    // RPC starts with an empty committee — `solidus_getValidators` will
    // return only on-chain validator records.
    let listen_addr: SocketAddr = cfg.rpc_listen.parse()?;
    let (rpc_handle, rpc_addr) = start_rpc_server(
        listen_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::new(Vec::new()),
        chain_meta_from(&genesis_config),
        None, // legacy single-node mode has no libp2p transport to broadcast on
        // Legacy mode's Proposer is clock-driven; nothing consumes the wake.
        Arc::new(tokio::sync::Notify::new()),
    )
    .await
    .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    info!(%rpc_addr, "RPC server started");

    // 6. Compute genesis_hash = blake3_hash(chain_id.as_bytes())
    let genesis_hash = blake3_hash(chain_id.as_bytes());

    // chain_id format: "solidus-{network}-{seq}" — extract network so DID
    // strings on this chain say `did:solidus:{network}:...` correctly.
    let network = chain_id
        .strip_prefix("solidus-")
        .and_then(|s| s.rsplit_once('-').map(|(prefix, _)| prefix))
        .unwrap_or("testnet")
        .to_string();

    // 7. Create and spawn Proposer
    let proposer_config = ProposerConfig {
        block_time_ms: cfg.block_time_ms,
        max_block_txs: cfg.max_block_txs,
        treasury_address,
        validator_addresses,
        network,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut proposer = Proposer::new(
        Arc::clone(&store),
        Arc::clone(&mempool),
        proposer_config,
        0,
        genesis_hash,
    );
    proposer.set_latest_height(Arc::clone(&latest_height));

    let proposer_handle = tokio::spawn(async move {
        proposer.run(shutdown_rx).await;
    });

    info!("solidus-node running — press Ctrl+C to stop");

    // 8. Wait for Ctrl+C or SIGTERM
    shutdown_signal().await?;
    info!("shutdown signal received");

    // 9. Send shutdown signal, await proposer, stop RPC
    if let Err(e) = shutdown_tx.send(true) {
        error!(error = %e, "failed to send shutdown signal");
    }

    proposer_handle.await?;
    info!("proposer stopped");

    rpc_handle.stop().map_err(|e| {
        error!(error = ?e, "failed to stop RPC server");
        format!("RPC stop error: {e:?}")
    })?;
    info!("RPC server stopped — goodbye");

    Ok(())
}

/// Build the RPC [`ChainMeta`] from a loaded genesis config. Surfaced by the
/// `solidus_chainInfo` JSON-RPC method so external tools self-discover the
/// chain id, native token, and node version.
fn chain_meta_from(genesis: &GenesisConfig) -> ChainMeta {
    ChainMeta {
        chain_id: genesis.chain_id.clone(),
        native_token: RpcNativeToken {
            symbol: genesis.native_token.symbol.clone(),
            name: genesis.native_token.name.clone(),
            decimals: genesis.native_token.decimals,
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

// ---------------------------------------------------------------------------
// HotStuff BFT consensus node startup
// ---------------------------------------------------------------------------

async fn run_consensus_node(config_path: &str) -> Result<(), Box<dyn Error>> {
    let config_file_path = Path::new(config_path);
    let config_dir = config_file_path.parent().unwrap_or_else(|| Path::new("."));

    // 1. Parse MultiNodeConfig from config.toml
    let multi_cfg = MultiNodeConfig::from_file(config_file_path)?;
    // If the config marks this as a full node, run the follower path even when
    // started with `--consensus` (config-driven full-node deployments).
    if multi_cfg.node.full_node {
        return run_full_node(config_path).await;
    }
    info!(
        node_index = multi_cfg.node.node_index,
        chain_id = %multi_cfg.node.chain_id,
        listen_port = multi_cfg.node.listen_port,
        rpc_port = multi_cfg.node.rpc_port,
        peers = multi_cfg.peers.len(),
        "loaded multi-node config"
    );

    // 2. Load Ed25519 key from node.key file (hex-encoded, 32 bytes)
    let ed25519_key_path = config_dir.join(&multi_cfg.node.ed25519_key);
    let ed25519_sk = load_ed25519_key(&ed25519_key_path)?;
    // Capture the seed now — `ed25519_sk` is moved into the engine below, but we
    // also need it to derive this node's libp2p identity.
    let node_key_seed = ed25519_sk.to_bytes();
    info!("loaded Ed25519 signing key");

    // 3. Load BLS key from bls.key file (hex-encoded, 32 bytes)
    let bls_key_path = config_dir.join(&multi_cfg.node.bls_key);
    let bls_sk = load_bls_key(&bls_key_path)?;
    info!("loaded BLS signing key");

    // 4. Load genesis.json and parse into GenesisFile
    let genesis_path = config_dir.join(&multi_cfg.node.genesis);
    let genesis_contents = std::fs::read_to_string(&genesis_path)?;
    let genesis_file: GenesisFile = serde_json::from_str(&genesis_contents)?;
    info!(
        chain_id = %genesis_file.chain_id,
        validators = genesis_file.validators.len(),
        "loaded genesis file"
    );

    // 5. Open/init RocksDB store, apply genesis balances if fresh
    let data_dir = config_dir.join(&multi_cfg.node.data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let store = Arc::new(Store::open(&data_dir)?);
    info!(data_dir = %data_dir.display(), "opened store");

    // Apply genesis balances: build the legacy GenesisConfig from the GenesisFile
    // so that the existing genesis loading logic can be reused.
    let treasury_address_str = genesis_file.treasury_or_else(|g| {
        // Legacy guess for genesis files without `treasury_address`.
        g.initial_balances
            .iter()
            .find(|(_, &bal)| bal == 50_000_000 * 100_000_000)
            .map(|(addr, _)| addr.clone())
            .unwrap_or_else(|| {
                // Fallback: use the first validator address
                g.validators[0].address.clone()
            })
    });

    let validator_address_strs: Vec<String> = genesis_file
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect();

    let genesis_config = GenesisConfig {
        chain_id: genesis_file.chain_id.clone(),
        treasury_address: treasury_address_str,
        validator_addresses: validator_address_strs,
        initial_balances: genesis_file.initial_balances.clone(),
        native_token: genesis_file.native_token.clone(),
    };

    let (treasury_address, validator_addresses) = genesis::load_genesis(&store, &genesis_config)?;
    info!(
        treasury = %treasury_address,
        validators = validator_addresses.len(),
        "applied genesis state"
    );

    // 6. Build Vec<ValidatorIdentity> from genesis validators.
    // Wrap in an Arc so the same set can be shared with the RPC server (for
    // `solidus_getValidators`) and with the consensus engine.
    let validators = load_genesis_validators(&genesis_file)?;
    let committee_arc = Arc::new(validators.clone());
    info!(
        committee_size = validators.len(),
        "built validator identity set"
    );

    // 7. Create shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 8. Create HotStuffEngine
    let quorum_threshold = genesis_file.params.quorum_threshold;

    let hotstuff_config = HotStuffConfig {
        max_block_txs: genesis_file.params.max_block_txs,
        quorum_threshold,
        treasury_address,
        skip_vrf: false,
    };

    let mut engine = HotStuffEngine::new(
        multi_cfg.node.node_index,
        ed25519_sk,
        bls_sk,
        validators,
        Arc::clone(&store),
        Arc::clone(&mempool),
        hotstuff_config,
    );

    // Set the round seed from genesis
    let round_seed_bytes = hex::decode(&genesis_file.round_seed)?;
    if round_seed_bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&round_seed_bytes);
        engine.round_seed = seed;
    }

    info!(
        node_index = multi_cfg.node.node_index,
        quorum_threshold = quorum_threshold,
        last_committed = engine.last_committed_height,
        "HotStuff engine created"
    );

    // 9. Start RPC server. Pass the in-process committee so
    // `solidus_getValidators` reflects the live voters even when no on-chain
    // staking transactions exist (the dev-testnet case).
    // Create the tx-broadcast bridge: the RPC `send_transaction` handler
    // forwards every successfully-mempooled tx here; the consensus loop
    // below drains the receiver and calls `transport.broadcast` so other
    // nodes receive the tx on the `/solidus/txs/1.0.0` gossipsub topic.
    let (tx_broadcast_tx, tx_broadcast_rx) =
        tokio::sync::mpsc::unbounded_channel::<solidus_txns::types::Transaction>();
    let tx_wake = Arc::new(tokio::sync::Notify::new());
    let rpc_addr: SocketAddr =
        format!("{}:{}", multi_cfg.node.rpc_listen, multi_cfg.node.rpc_port).parse()?;
    let (rpc_handle, actual_rpc_addr) = start_rpc_server(
        rpc_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::clone(&committee_arc),
        chain_meta_from(&genesis_config),
        Some(tx_broadcast_tx),
        Arc::clone(&tx_wake),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e })?;
    info!(%actual_rpc_addr, "RPC server started");

    // 10. Create the libp2p transport from this node's identity + peer config.
    let identity = solidus_p2p::identity::libp2p_keypair_from_node_seed(&node_key_seed)?;
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", multi_cfg.node.listen_port).parse()?;
    let peers = multi_cfg
        .peers
        .iter()
        .map(|p| solidus_p2p::libp2p_transport::PeerConfig {
            index: p.index,
            peer_id: p.peer_id.clone(),
            address: p.address.clone(),
        })
        .collect();
    let bootstrap_peers = multi_cfg
        .bootstrap_peers
        .iter()
        .map(|s| solidus_p2p::libp2p_transport::parse_bootstrap_addr(s))
        .collect::<Result<Vec<_>, String>>()?;
    let libp2p_cfg = solidus_p2p::libp2p_transport::LibP2PConfig {
        listen_addr,
        peers,
        node_index: multi_cfg.node.node_index,
        keypair: identity,
        bootstrap_peers,
    };
    let mut transport = solidus_p2p::libp2p_transport::LibP2PTransport::start(libp2p_cfg).await?;
    info!(local_peer_id = %transport.local_peer_id(), "libp2p transport started");

    // Wait until enough peers are connected before starting consensus, so the
    // first leader's proposal isn't dropped before dials complete. Bounded so a
    // node still starts (and recovers via the pacemaker) if peers are slow.
    let need = quorum_threshold
        .saturating_sub(1)
        .min(multi_cfg.peers.len());
    if need > 0 {
        let connected = transport
            .wait_for_peers(need, std::time::Duration::from_secs(30))
            .await;
        info!(
            connected,
            need, "peer connectivity gate passed (or timed out)"
        );
    }

    // Pre-loop catch-up: backfill the canon to a peer's tip, then re-execute it
    // to rebuild state — race-free because it runs BEFORE the consensus loop.
    startup_catch_up(&mut engine, &mut transport).await;

    // 11. Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 12. Spawn the consensus main loop
    let consensus_latest_height = Arc::clone(&latest_height);
    let consensus_handle = tokio::spawn(async move {
        run_consensus_loop(
            &mut engine,
            &mut transport,
            consensus_latest_height,
            shutdown_rx,
            Some(tx_broadcast_rx),
            tx_wake,
            IDLE_HEARTBEAT_MS,
        )
        .await;
    });

    info!(
        node_index = multi_cfg.node.node_index,
        "solidus-node (HotStuff consensus) running — press Ctrl+C to stop"
    );

    // 13. Wait for Ctrl+C or SIGTERM
    shutdown_signal().await?;
    info!("shutdown signal received");

    // 14. Send shutdown signal, await consensus loop, stop RPC
    if let Err(e) = shutdown_tx.send(true) {
        error!(error = %e, "failed to send shutdown signal");
    }

    consensus_handle.await?;
    info!("consensus loop stopped");

    rpc_handle.stop().map_err(|e| {
        error!(error = ?e, "failed to stop RPC server");
        format!("RPC stop error: {e:?}")
    })?;
    info!("RPC server stopped — goodbye");

    Ok(())
}

// ---------------------------------------------------------------------------
// Full-node (non-validating) startup — C2
// ---------------------------------------------------------------------------

/// Start a non-validating full node (C2).
///
/// Modeled on [`run_consensus_node`] for config/key/genesis loading, RPC, and
/// libp2p startup (with `bootstrap_peers` for open discovery), but it NEVER
/// proposes or votes: it runs [`run_follower_loop`] instead of
/// [`run_consensus_loop`]. The follower reuses the shipped backfill/ledger sync
/// stack, addressing peers by libp2p PeerId (it has no validator index), and
/// periodically re-executes the canon to advance its committed tip + RPC height.
async fn run_full_node(config_path: &str) -> Result<(), Box<dyn Error>> {
    let config_file_path = Path::new(config_path);
    let config_dir = config_file_path.parent().unwrap_or_else(|| Path::new("."));

    // 1. Parse MultiNodeConfig.
    let multi_cfg = MultiNodeConfig::from_file(config_file_path)?;
    info!(
        chain_id = %multi_cfg.node.chain_id,
        listen_port = multi_cfg.node.listen_port,
        rpc_port = multi_cfg.node.rpc_port,
        bootstrap_peers = multi_cfg.bootstrap_peers.len(),
        "loaded full-node config"
    );

    // 2. Load Ed25519 key (used only for the libp2p identity on a full node).
    let ed25519_key_path = config_dir.join(&multi_cfg.node.ed25519_key);
    let ed25519_sk = load_ed25519_key(&ed25519_key_path)?;
    let node_key_seed = ed25519_sk.to_bytes();
    info!("loaded Ed25519 signing key");

    // 3. Load BLS key (held by the engine; never used to sign on a full node).
    let bls_key_path = config_dir.join(&multi_cfg.node.bls_key);
    let bls_sk = load_bls_key(&bls_key_path)?;
    info!("loaded BLS signing key");

    // 4. Load genesis.json.
    let genesis_path = config_dir.join(&multi_cfg.node.genesis);
    let genesis_contents = std::fs::read_to_string(&genesis_path)?;
    let genesis_file: GenesisFile = serde_json::from_str(&genesis_contents)?;
    info!(
        chain_id = %genesis_file.chain_id,
        validators = genesis_file.validators.len(),
        "loaded genesis file"
    );

    // 5. Open store + apply genesis balances if fresh (same as a validator).
    let data_dir = config_dir.join(&multi_cfg.node.data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let store = Arc::new(Store::open(&data_dir)?);
    info!(data_dir = %data_dir.display(), "opened store");

    let treasury_address_str = genesis_file.treasury_or_else(|g| {
        // Legacy guess for genesis files without `treasury_address`.
        g.initial_balances
            .iter()
            .find(|(_, &bal)| bal == 50_000_000 * 100_000_000)
            .map(|(addr, _)| addr.clone())
            .unwrap_or_else(|| g.validators[0].address.clone())
    });

    let validator_address_strs: Vec<String> = genesis_file
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect();

    let genesis_config = GenesisConfig {
        chain_id: genesis_file.chain_id.clone(),
        treasury_address: treasury_address_str,
        validator_addresses: validator_address_strs,
        initial_balances: genesis_file.initial_balances.clone(),
        native_token: genesis_file.native_token.clone(),
    };

    let (treasury_address, validator_addresses) = genesis::load_genesis(&store, &genesis_config)?;
    info!(
        treasury = %treasury_address,
        validators = validator_addresses.len(),
        "applied genesis state"
    );

    // 6. Build the validator identity set (read-only on a full node: the
    // committee shape lets the engine serve sync + compute hashes, and the RPC
    // expose `solidus_getValidators`; the full node never indexes it to propose).
    let validators = load_genesis_validators(&genesis_file)?;
    let committee_arc = Arc::new(validators.clone());
    info!(
        committee_size = validators.len(),
        "built validator identity set"
    );

    // 7. Shared state.
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 8. Create the HotStuffEngine as the storage/sync vehicle (Q3). The follower
    // loop only ever calls its storage/sync methods (canon backfill, rebuild).
    let quorum_threshold = genesis_file.params.quorum_threshold;
    let hotstuff_config = HotStuffConfig {
        max_block_txs: genesis_file.params.max_block_txs,
        quorum_threshold,
        treasury_address,
        skip_vrf: false,
    };
    // node_index is kept for config uniformity but never indexed (Q2): the
    // follower never proposes, so `validators[node_index]` is never reached.
    let mut engine = HotStuffEngine::new(
        multi_cfg.node.node_index,
        ed25519_sk,
        bls_sk,
        validators,
        Arc::clone(&store),
        Arc::clone(&mempool),
        hotstuff_config,
    );
    let round_seed_bytes = hex::decode(&genesis_file.round_seed)?;
    if round_seed_bytes.len() == 32 {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&round_seed_bytes);
        engine.round_seed = seed;
    }
    info!(
        last_committed = engine.last_committed_height,
        "HotStuff engine created (full-node storage/sync vehicle)"
    );

    // 9. Start RPC server.
    // Full-nodes don't propose, but they DO serve `solidus_sendTransaction`
    // — a user submitting a tx here must reach the validator mesh via
    // libp2p gossip. The bridge channel forwards every accepted tx to the
    // follower loop below, which broadcasts on the `txs` gossipsub topic.
    let (tx_broadcast_tx, tx_broadcast_rx) =
        tokio::sync::mpsc::unbounded_channel::<solidus_txns::types::Transaction>();
    let tx_wake = Arc::new(tokio::sync::Notify::new());
    let rpc_addr: SocketAddr =
        format!("{}:{}", multi_cfg.node.rpc_listen, multi_cfg.node.rpc_port).parse()?;
    let (rpc_handle, actual_rpc_addr) = start_rpc_server(
        rpc_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::clone(&committee_arc),
        chain_meta_from(&genesis_config),
        Some(tx_broadcast_tx),
        Arc::clone(&tx_wake),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e })?;
    info!(%actual_rpc_addr, "RPC server started");

    // 10. Start libp2p with an EMPTY static peer set and the configured
    // bootstrap peers — open discovery (C1) is the only way a full node finds
    // the validator mesh.
    let identity = solidus_p2p::identity::libp2p_keypair_from_node_seed(&node_key_seed)?;
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", multi_cfg.node.listen_port).parse()?;
    let peers = multi_cfg
        .peers
        .iter()
        .map(|p| solidus_p2p::libp2p_transport::PeerConfig {
            index: p.index,
            peer_id: p.peer_id.clone(),
            address: p.address.clone(),
        })
        .collect();
    let bootstrap_peers = multi_cfg
        .bootstrap_peers
        .iter()
        .map(|s| solidus_p2p::libp2p_transport::parse_bootstrap_addr(s))
        .collect::<Result<Vec<_>, String>>()?;
    let libp2p_cfg = solidus_p2p::libp2p_transport::LibP2PConfig {
        listen_addr,
        peers,
        node_index: multi_cfg.node.node_index,
        keypair: identity,
        bootstrap_peers,
    };
    let mut transport = solidus_p2p::libp2p_transport::LibP2PTransport::start(libp2p_cfg).await?;
    info!(local_peer_id = %transport.local_peer_id(), "libp2p transport started");

    // 11. Wait until at least one peer is connected so sync requests have a
    // target. Bounded so the node still boots if discovery is slow.
    let connected = transport
        .wait_for_peers(1, std::time::Duration::from_secs(30))
        .await;
    info!(
        connected,
        "full-node peer-connectivity gate passed (or timed out)"
    );

    // 12. Pre-loop catch-up over the PeerId sync path, then update RPC height.
    startup_catch_up_full(&mut engine, &mut transport).await;
    update_latest_height(&engine, &latest_height);

    // 13. Shutdown signal + follower loop.
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let follower_latest_height = Arc::clone(&latest_height);
    let follower_handle = tokio::spawn(async move {
        run_follower_loop(
            &mut engine,
            &mut transport,
            follower_latest_height,
            shutdown_rx,
            Some(tx_broadcast_rx),
        )
        .await;
    });

    info!("solidus-node (full node) running — press Ctrl+C to stop");

    shutdown_signal().await?;
    info!("shutdown signal received");
    if let Err(e) = shutdown_tx.send(true) {
        error!(error = %e, "failed to send shutdown signal");
    }
    follower_handle.await?;
    info!("follower loop stopped");

    rpc_handle.stop().map_err(|e| {
        error!(error = ?e, "failed to stop RPC server");
        format!("RPC stop error: {e:?}")
    })?;
    info!("RPC server stopped — goodbye");

    Ok(())
}

/// Update the RPC-visible `latest_height` from the engine's committed tip (C2
/// Task 6). The full node never runs `try_commit`, so this is the only place its
/// RPC height advances. Last-write-wins by committed height (Q4 parity with
/// validators).
fn update_latest_height(engine: &HotStuffEngine, latest_height: &Arc<Mutex<u64>>) {
    if let Ok(mut h) = latest_height.lock() {
        if engine.last_committed_height > *h {
            *h = engine.last_committed_height;
        }
    }
}

/// Learn a peer's committed tip hash over the PeerId path, rotating through the
/// currently-connected peers. None if none answer before `deadline`. STORAGE/
/// sync helper — touches no consensus state.
async fn learn_tip_by_peer(
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
    deadline: tokio::time::Instant,
) -> Option<[u8; 32]> {
    let mut probe = 0usize;
    while tokio::time::Instant::now() < deadline {
        let peers = transport.connected_peer_ids();
        if peers.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            continue;
        }
        let target = peers[probe % peers.len()];
        probe += 1;
        if transport
            .send_to_peer_id(target, ConsensusMessage::GetTip)
            .await
            .is_ok()
        {
            if let Some(h) = recv_until_tip(transport, std::time::Duration::from_secs(2)).await {
                if h != [0u8; 32] {
                    return Some(h);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    }
    None
}

/// Fetch a block by hash over the PeerId path, rotating through connected peers
/// and retrying so one slow/gappy peer doesn't abort a backfill walk. STORAGE
/// helper — touches no consensus state.
async fn fetch_block_by_peer(
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
    hash: [u8; 32],
    deadline: tokio::time::Instant,
) -> Option<solidus_consensus::types::Block> {
    let mut attempt = 0usize;
    while tokio::time::Instant::now() < deadline && attempt < 12 {
        let peers = transport.connected_peer_ids();
        if peers.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            continue;
        }
        let target = peers[attempt % peers.len()];
        attempt += 1;
        if transport
            .send_to_peer_id(target, ConsensusMessage::GetBlockByHash { hash })
            .await
            .is_err()
        {
            continue;
        }
        if let Some(b) =
            recv_until_block_by_hash(transport, std::time::Duration::from_secs(3)).await
        {
            if b.hash() == hash {
                return Some(b);
            }
        }
    }
    None
}

/// Backfill the canon backward from `target` to genesis/known-canon over the
/// PeerId path. STORAGE-ONLY: writes only the canonical-ledger CFs via
/// `apply_fetched` (mirror of [`backfill_canon_to`], PeerId-addressed).
async fn backfill_canon_to_by_peer(
    engine: &HotStuffEngine,
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
    target: [u8; 32],
    deadline: tokio::time::Instant,
) {
    let mut walk = backfill::WalkState::default();
    let head = solidus_consensus::ledger::canon_head(&engine.store)
        .ok()
        .flatten()
        .map(|(_, h)| h);
    let mut cursor = match backfill::next_cursor(&walk, target, head) {
        Some(c) => c,
        None => return, // already at target
    };
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let block = match solidus_consensus::ledger::get_block_by_hash(&engine.store, &cursor)
            .ok()
            .flatten()
        {
            Some(b) => b,
            None => match fetch_block_by_peer(transport, cursor, deadline).await {
                Some(b) => b,
                None => break, // no peer provided it within the deadline
            },
        };
        match backfill::apply_fetched(&engine.store, cursor, block, &mut walk) {
            Ok(Some(next)) => cursor = next,
            Ok(None) => break, // connected — canon extended
            Err(_) => break,   // bad block
        }
    }
}

/// Bulk forward-burst over the PeerId path (full-node analog of
/// [`bulk_burst_by_range`]). Iterates connected peers and pulls contiguous
/// blocks starting at `canon_head + 1` via `GetBlockRange`. Stops on empty
/// or short response and lets the reverse walker catch the residue.
async fn bulk_burst_by_range_by_peer(
    engine: &HotStuffEngine,
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
    deadline: tokio::time::Instant,
) -> usize {
    const RANGE_BATCH: u16 = 64;
    let mut total_applied = 0usize;
    let mut probe = 0usize;
    let mut consecutive_empty = 0u32;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        if consecutive_empty >= 3 {
            break;
        }

        let peers = transport.connected_peer_ids();
        if peers.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            continue;
        }
        let target = peers[probe % peers.len()];
        probe += 1;

        let from_seq = match solidus_consensus::ledger::canon_head(&engine.store)
            .ok()
            .flatten()
        {
            Some((seq, _)) => seq + 1,
            None => 0,
        };

        if transport
            .send_to_peer_id(
                target,
                ConsensusMessage::GetBlockRange {
                    from_seq,
                    count: RANGE_BATCH,
                },
            )
            .await
            .is_err()
        {
            continue;
        }

        let blocks =
            match recv_until_block_range(transport, std::time::Duration::from_secs(3)).await {
                Some(b) => b,
                None => continue,
            };

        if blocks.is_empty() {
            consecutive_empty += 1;
            continue;
        }
        consecutive_empty = 0;

        let len = blocks.len();
        match backfill::apply_block_range(&engine.store, from_seq, &blocks) {
            Ok(applied) => {
                total_applied += applied;
                if len < RANGE_BATCH as usize {
                    break;
                }
            }
            Err(e) => {
                debug!(error = %e, ?target, "apply_block_range rejected; rotating peer");
            }
        }
    }
    total_applied
}

/// Pre-loop catch-up for a full node: learn a peer's committed tip over the
/// PeerId path, backfill the canon to it, then re-execute the canon to rebuild
/// state. Runs BEFORE the follower loop with exclusive transport access, so the
/// re-execution is race-free. Mirror of [`startup_catch_up`], PeerId-addressed.
async fn startup_catch_up_full(
    engine: &mut HotStuffEngine,
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
) {
    // Best-effort, time-bounded: a full node joining a long-running chain catches
    // up MANY blocks one round-trip at a time, and the chain keeps advancing — so
    // a single bounded pass cannot converge to a moving tip. We give one short
    // pass here (jump-starts a freshly-empty canon), then hand off to the
    // follower loop's continuous walker which completes and maintains the sync.
    // Bounded short so the node enters the follower loop promptly (never blocks
    // ~60s against a moving target, which wedged early-startup before).
    let overall = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    let tip_deadline =
        (tokio::time::Instant::now() + std::time::Duration::from_secs(3)).min(overall);
    if let Some(target) = learn_tip_by_peer(transport, tip_deadline).await {
        if engine.committed_tip_hash() != target {
            // C-3 batch burst FIRST (full-node analog): bulk-fetch via
            // GetBlockRange over the PeerId path. Big win for a freshly-
            // launched full node joining a long-running testnet.
            let bursted = bulk_burst_by_range_by_peer(engine, transport, overall).await;
            if bursted > 0 {
                info!(
                    bursted,
                    "full-node startup catch-up: burst-fetched contiguous range"
                );
            }
            backfill_canon_to_by_peer(engine, transport, target, overall).await;
            match engine.rebuild_state_from_canon() {
                Ok(seq) => info!(
                    canon_tip_seq = seq,
                    "full-node startup catch-up pass complete"
                ),
                Err(e) => warn!(error = %e, "full-node startup state rebuild failed"),
            }
        }
    }
    info!(
        tip_height = engine.last_committed_height,
        "full-node startup catch-up finished (follower loop continues sync)"
    );
}

/// The full-node follower loop.
///
/// POLL-SYNC ONLY (Task 5): the full node does NOT consume `NewBlock`/
/// `NewTransaction` gossip for state. It relies entirely on the out-of-band
/// backfill walker (~500ms cadence) targeting peers by libp2p PeerId, plus a
/// periodic canon re-execution that advances the committed tip + RPC height.
/// Using gossip as a sync trigger (lower latency) is deferred to C3+.
///
/// Unlike [`run_consensus_loop`], this loop has NO propose / pacemaker-timeout /
/// `Proposal` / `Vote` / `QC` / `TimeoutVote` arms — a full node never reaches
/// `build_block`/`try_propose_if_leader` (which would index `validators[node_index]`
/// and panic). It only: (1) ticks the PeerId-addressed backfill walker,
/// (2) applies `BlockByHash` responses (storage-only), (3) serves `GetTip`/
/// `GetBlockByHash` to other syncing peers, and (4) periodically re-executes the
/// canon to advance the tip.
async fn run_follower_loop(
    engine: &mut HotStuffEngine,
    transport: &mut solidus_p2p::libp2p_transport::LibP2PTransport,
    latest_height: Arc<Mutex<u64>>,
    mut shutdown: watch::Receiver<bool>,
    // Same RPC → loop bridge as `run_consensus_loop`: a tx submitted to a
    // full node's RPC must still reach the validator mesh via gossipsub
    // (full nodes don't propose). `None` disables the bridge.
    mut tx_broadcast_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<solidus_txns::types::Transaction>,
    >,
) {
    let _ = shutdown.borrow_and_update();

    // Out-of-band backfill walker state (STORAGE-ONLY). `awaiting` holds the
    // in-flight GetBlockByHash (hash, sent_at) so a stalled request retries.
    let mut walk = backfill::WalkState::default();
    let mut awaiting: Option<([u8; 32], Instant)> = None;
    let mut probe = 0usize;
    // Latest peer tip learned from a `Tip` response (the walk target until the
    // follower has its own committed tip). Single-sourced: ALL transport reads
    // go through the main `recv_with_source` arm — the backfill tick never blocks
    // on `recv` itself (that would steal/discard `BlockByHash` responses meant
    // for the walk). The tick just fires `GetTip`/`GetBlockByHash` and consumes
    // the responses via the main arm.
    let mut peer_tip: Option<[u8; 32]> = None;

    // Fast tick so a dropped chained response re-kicks the walk promptly (the
    // backward walk is one round-trip per block; a long chain needs the walk to
    // never stall on a single lost response).
    let mut backfill_tick = tokio::time::interval(std::time::Duration::from_millis(200));
    backfill_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Wake-trigger for follower-side tip-sync: a gossiped NewBlock from
    // a validator means a fresh tip is live; fire the backfill walker
    // immediately instead of waiting for the 200ms tick. Full nodes
    // benefit most from this — they exist precisely to mirror the live
    // tip with low latency.
    let sync_notify = std::sync::Arc::new(tokio::sync::Notify::new());
    // Re-execute the canon periodically to advance the committed tip + RPC height
    // as the backfill walker pulls in new blocks.
    let mut rebuild_tick = tokio::time::interval(std::time::Duration::from_secs(2));
    rebuild_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // ── Shutdown signal ──────────────────────────────────────────
            _ = shutdown.changed() => {
                info!("follower loop received shutdown signal");
                break;
            }

            // ── Tx broadcast bridge (full node serves RPC; forwards to mesh) ──
            // Same pattern as run_consensus_loop. Full nodes don't propose,
            // but their RPC consumers still need their txs to reach the
            // validator mesh — this fans them out on the `txs` topic.
            maybe_tx = async {
                match tx_broadcast_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<_>>().await,
                }
            }, if tx_broadcast_rx.is_some() => {
                if let Some(tx) = maybe_tx {
                    if let Err(e) = transport
                        .broadcast(ConsensusMessage::NewTransaction(tx))
                        .await
                    {
                        warn!(error = %e, "full-node: failed to broadcast NewTransaction");
                    }
                } else {
                    tx_broadcast_rx = None;
                }
            }

            // ── Periodic canon re-execution -> advance tip + RPC height ───
            _ = rebuild_tick.tick() => {
                match engine.rebuild_state_from_canon() {
                    Ok(_) => update_latest_height(engine, &latest_height),
                    Err(e) => warn!(error = %e, "follower canon rebuild failed"),
                }
                // Heartbeat: peer count (discovery) + synced height. The node-join
                // E2E asserts `peers>=2` here (bootstrap + a DHT-discovered peer).
                let canon_head = solidus_consensus::ledger::canon_head(&engine.store)
                    .ok()
                    .flatten()
                    .map(|(s, _)| s);
                info!(
                    peers = transport.connected_peer_ids().len(),
                    height = engine.last_committed_height,
                    ?canon_head,
                    "follower status"
                );
            }

            // ── Out-of-band ledger backfill (STORAGE-ONLY), PeerId-targeted ─
            // Fires on EITHER the 200ms ticker OR a wake from sync_notify
            // (gossiped NewBlock → chain advanced → fetch the new tip NOW).
            // The bias makes notify win on contention.
            _ = async {
                tokio::select! {
                    biased;
                    _ = sync_notify.notified() => {}
                    _ = backfill_tick.tick() => {}
                }
            } => {
                // Drop a stalled request so it retries (rotate peer) but KEEP the
                // walk's accumulated progress (resume from walk.cursor). A short
                // stale window keeps a single dropped response from stalling the
                // long backward walk for more than a tick.
                if let Some((_, sent)) = awaiting {
                    if sent.elapsed() > std::time::Duration::from_millis(400) {
                        awaiting = None;
                    }
                }
                if awaiting.is_none() {
                    let committed = engine.committed_tip_hash();
                    let head = solidus_consensus::ledger::canon_head(&engine.store)
                        .ok()
                        .flatten()
                        .map(|(_, h)| h);
                    // Walk target: our own committed tip once we have one,
                    // otherwise the latest tip learned from a peer. When neither
                    // is known yet, fire a (non-blocking) GetTip — its response is
                    // captured by the main recv arm into `peer_tip` for next tick.
                    let walk_target = if committed != backfill::GENESIS_PARENT {
                        Some(committed)
                    } else {
                        peer_tip
                    };
                    let peers = transport.connected_peer_ids();
                    if walk_target.is_none() && !peers.is_empty() {
                        let p = peers[probe % peers.len()];
                        probe = probe.wrapping_add(1);
                        let _ = transport.send_to_peer_id(p, ConsensusMessage::GetTip).await;
                    }
                    if let Some(wt) = walk_target {
                        if let Some(cursor) = backfill::next_cursor(&walk, wt, head) {
                            if !peers.is_empty() {
                                let p = peers[probe % peers.len()];
                                probe = probe.wrapping_add(1);
                                if transport
                                    .send_to_peer_id(
                                        p,
                                        ConsensusMessage::GetBlockByHash { hash: cursor },
                                    )
                                    .await
                                    .is_ok()
                                {
                                    walk.cursor = Some(cursor);
                                    awaiting = Some((cursor, Instant::now()));
                                }
                            }
                        }
                    }
                }
            }

            // ── Incoming network message ─────────────────────────────────
            result = transport.recv_with_source() => {
                match result {
                    Ok((from, source, msg)) => {
                        // Wake-trigger: gossiped NewBlock advances the walker
                        // NOW instead of waiting up to 200ms for the next tick.
                        if matches!(msg, ConsensusMessage::NewBlock(_)) {
                            sync_notify.notify_one();
                        }
                        match msg {
                            // Backfill response — storage-only, never consensus.
                            // Re-request the next ancestor from the SAME peer that
                            // answered (it provably has the blocks), avoiding a
                            // round-trip to a peer whose substream isn't ready.
                            ConsensusMessage::BlockByHash(maybe) => {
                                handle_block_by_hash_by_peer(
                                    engine,
                                    transport,
                                    source,
                                    maybe,
                                    &mut walk,
                                    &mut awaiting,
                                )
                                .await;
                            }
                            // Serve sync requests from other peers (reply by the
                            // captured source PeerId when the requester is
                            // index-less).
                            ConsensusMessage::GetTip => {
                                let hash = engine.committed_tip_hash();
                                if let Err(e) = reply_to(
                                    transport,
                                    from,
                                    source,
                                    ConsensusMessage::Tip { hash },
                                )
                                .await
                                {
                                    warn!(error = %e, "follower failed to send Tip");
                                }
                            }
                            ConsensusMessage::GetBlockByHash { hash } => {
                                let block = solidus_consensus::ledger::get_block_by_hash(
                                    &engine.store,
                                    &hash,
                                )
                                .unwrap_or(None);
                                if let Err(e) = reply_to(
                                    transport,
                                    from,
                                    source,
                                    ConsensusMessage::BlockByHash(block),
                                )
                                .await
                                {
                                    warn!(error = %e, "follower failed to send BlockByHash");
                                }
                            }
                            // Tip response to our own GetTip probe — record it as
                            // the walk target (consumed by the backfill tick).
                            // The genesis-sentinel tip is ignored (no real canon).
                            ConsensusMessage::Tip { hash } if hash != [0u8; 32] => {
                                peer_tip = Some(hash);
                            }
                            // Poll-sync: drop gossip (NewBlock/NewTransaction) and
                            // ignore live consensus traffic (Proposal/Vote/QC/
                            // Timeout). A full node never participates.
                            _ => {}
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "follower transport recv error");
                        break;
                    }
                }
            }
        }
    }
}

/// Apply a backfill `BlockByHash` response for the follower (STORAGE-ONLY),
/// re-requesting the next ancestor over the PeerId path on a successful apply.
/// Mirror of [`handle_block_by_hash`], PeerId-addressed.
async fn handle_block_by_hash_by_peer(
    engine: &HotStuffEngine,
    transport: &solidus_p2p::libp2p_transport::LibP2PTransport,
    source: Option<SourcePeer>,
    maybe_block: Option<solidus_consensus::types::Block>,
    walk: &mut backfill::WalkState,
    awaiting: &mut Option<([u8; 32], Instant)>,
) {
    let (block, want) = match (maybe_block, awaiting.as_ref().map(|(h, _)| *h)) {
        (Some(b), Some(w)) => (b, w),
        _ => {
            *awaiting = None;
            return;
        }
    };
    match backfill::apply_fetched(&engine.store, want, block, walk) {
        Ok(Some(next)) => {
            // Re-request from the responding peer (it just proved it has the
            // chain); fall back to any connected peer if the source is unknown.
            let target = source.or_else(|| transport.connected_peer_ids().into_iter().next());
            if let Some(p) = target {
                if transport
                    .send_to_peer_id(p, ConsensusMessage::GetBlockByHash { hash: next })
                    .await
                    .is_ok()
                {
                    *awaiting = Some((next, Instant::now()));
                } else {
                    *awaiting = None;
                }
            } else {
                *awaiting = None;
            }
        }
        // Connected (canon extended) or a bad/stale response — go idle; the
        // backfill tick re-kicks if the canon is still behind the tip.
        Ok(None) | Err(_) => *awaiting = None,
    }
}

// ---------------------------------------------------------------------------
// Dev testnet: all validators in one process
// ---------------------------------------------------------------------------

/// Where dev-testnet keeps its database: `--data-dir` when given, otherwise
/// `<testnet-dir>/dev-data` (unchanged default).
fn dev_data_dir(testnet_path: &Path, data_dir: Option<&str>) -> std::path::PathBuf {
    match data_dir {
        Some(d) => std::path::PathBuf::from(d),
        None => testnet_path.join("dev-data"),
    }
}

async fn run_dev_testnet(
    testnet_dir: &str,
    rpc_port: u16,
    rpc_host: &str,
    data_dir: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let testnet_path = Path::new(testnet_dir);

    // 1. Load genesis
    let genesis_path = testnet_path.join("genesis.json");
    let genesis_str = std::fs::read_to_string(&genesis_path)?;
    let genesis_file: GenesisFile = serde_json::from_str(&genesis_str)?;
    let n = genesis_file.validators.len();
    info!(validators = n, chain_id = %genesis_file.chain_id, "loading dev testnet");

    // 2. Build validator identities. Wrap in an Arc so the same set can be
    // shared with the RPC server (for `solidus_getValidators`) and cloned
    // into each per-validator engine.
    let validators = load_genesis_validators(&genesis_file)?;
    let committee_arc = Arc::new(validators.clone());

    // 4. Open store and apply genesis (shared by all validators in dev mode)
    let data_dir = dev_data_dir(testnet_path, data_dir);
    std::fs::create_dir_all(&data_dir)?;
    let store = Arc::new(Store::open(&data_dir)?);

    let treasury_address_str = genesis_file.treasury_or_else(|g| {
        // Legacy guess for genesis files without `treasury_address`.
        g.initial_balances
            .keys()
            .find(|k| !g.validators.iter().any(|v| v.address == **k))
            .cloned()
            .unwrap_or_default()
    });

    let validator_address_strs: Vec<String> = genesis_file
        .validators
        .iter()
        .map(|v| v.address.clone())
        .collect();

    let genesis_config = GenesisConfig {
        chain_id: genesis_file.chain_id.clone(),
        treasury_address: treasury_address_str,
        validator_addresses: validator_address_strs,
        initial_balances: genesis_file.initial_balances.clone(),
        native_token: genesis_file.native_token.clone(),
    };
    let (treasury_address, _validator_addresses) = genesis::load_genesis(&store, &genesis_config)?;

    // 5. Parse round seed
    let round_seed_bytes = hex::decode(&genesis_file.round_seed)?;
    let mut round_seed = [0u8; 32];
    if round_seed_bytes.len() == 32 {
        round_seed.copy_from_slice(&round_seed_bytes);
    }

    // 6. Shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    // Tx-wake: `send_transaction` fires this the moment a tx is mempooled;
    // all consensus loops share it, the current leader proposes.
    let tx_wake = Arc::new(tokio::sync::Notify::new());

    // 7. Create channel network
    let mut transports = create_channel_network(n);

    // 8. Create engines and spawn consensus loops
    let quorum_threshold = genesis_file.params.quorum_threshold;
    let (shutdown_tx, _) = watch::channel(false);
    let mut handles = Vec::new();

    for i in (0..n).rev() {
        let hotstuff_config = HotStuffConfig {
            max_block_txs: genesis_file.params.max_block_txs,
            quorum_threshold,
            treasury_address,
            skip_vrf: true, // dev-testnet uses round-robin leader election
        };

        // Load keys fresh for each validator (BlsSecretKey doesn't implement Clone)
        let val_dir = testnet_path.join(format!("validator-{i}"));
        let ed_sk = load_ed25519_key(&val_dir.join("node.key"))?;
        let bls_sk = load_bls_key(&val_dir.join("bls.key"))?;

        let mut engine = HotStuffEngine::new(
            i,
            ed_sk,
            bls_sk,
            validators.clone(),
            Arc::clone(&store),
            Arc::clone(&mempool),
            hotstuff_config,
        );
        engine.round_seed = round_seed;

        // Restart-resume: adopt the surviving canonical tip so this process
        // EXTENDS the existing chain instead of proposing a second height-1
        // chain into the same store. No-op on a fresh datadir. (State needs
        // no replay: the RocksDB the process just reopened already holds
        // the executed state these blocks produced.)
        if let Some(height) = engine.adopt_canon_tip() {
            if let Ok(mut lh) = latest_height.lock() {
                *lh = (*lh).max(height);
            }
            info!(node = i, height, "resumed from surviving canonical tip");
        }

        let mut transport = transports.remove(i);
        let lh = Arc::clone(&latest_height);
        let shutdown_rx = shutdown_tx.subscribe();
        let wake = Arc::clone(&tx_wake);

        let handle = tokio::spawn(async move {
            // dev-testnet uses an in-process channel transport that already
            // routes per-validator locally — no separate broadcast bridge.
            run_consensus_loop(
                &mut engine,
                &mut transport,
                lh,
                shutdown_rx,
                None,
                wake,
                IDLE_HEARTBEAT_MS,
            )
            .await;
        });
        handles.push(handle);
    }

    info!(
        validators = n,
        quorum = quorum_threshold,
        "dev testnet running — {} validators in one process",
        n
    );

    // 9. Start RPC server (exposes validator-0's state). Pass the in-process
    // committee so `solidus_getValidators` reflects live voters even though
    // dev-testnet has no on-chain staking transactions.
    let rpc_addr: SocketAddr = format!("{rpc_host}:{rpc_port}").parse()?;
    let (rpc_handle, actual_rpc_addr) = start_rpc_server(
        rpc_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
        Arc::clone(&committee_arc),
        chain_meta_from(&genesis_config),
        None, // dev-testnet: all validators share one mempool in-process
        Arc::clone(&tx_wake),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e })?;
    info!(%actual_rpc_addr, "RPC server started");

    // 10. Wait for Ctrl+C or SIGTERM
    shutdown_signal().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(true);

    for handle in handles {
        let _ = handle.await;
    }
    rpc_handle.stop().map_err(|e| format!("RPC stop: {e:?}"))?;
    info!("dev testnet stopped — goodbye");

    Ok(())
}

// ---------------------------------------------------------------------------
// Consensus main loop
// ---------------------------------------------------------------------------

/// Idle heartbeat interval for the event-driven proposer: with no work, the
/// chain proposes one empty block this often. Each heartbeat finalizes the
/// previous burst's leftover padding blocks (3-chain finality needs two
/// follow-up rounds), bounds how long engines can stay divergent, and keeps
/// the canonical head visibly advancing for the explorer and monitoring.
/// At 10 minutes this is ~144 blocks/day (single-digit MB/day) versus the
/// ~1.16 GB/day the free-running proposer wrote before 2026-07-13.
const IDLE_HEARTBEAT_MS: u64 = 600_000;

/// The HotStuff BFT consensus main loop.
///
/// Drives the pacemaker, handles incoming proposals/votes/timeouts, and
/// manages block commitment via the 3-chain finality rule.
///
/// After receiving a message, the loop drains all buffered messages via
/// `try_recv()` before re-entering the pacemaker timeout.  This prevents
/// timeout floods: when many timeout votes arrive simultaneously (e.g. all
/// validators timing out in the same round), they are processed in a single
/// batch rather than interleaved with spurious timeout re-fires.
/// Receive messages until a `Tip` arrives (ignoring others), or `timeout`.
async fn recv_until_tip(
    transport: &mut impl ConsensusTransport,
    timeout: std::time::Duration,
) -> Option<[u8; 32]> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, transport.recv()).await {
            Ok(Ok((_, ConsensusMessage::Tip { hash }))) => return Some(hash),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// Receive messages until a `BlockByHash` arrives (ignoring others), or `timeout`.
async fn recv_until_block_by_hash(
    transport: &mut impl ConsensusTransport,
    timeout: std::time::Duration,
) -> Option<solidus_consensus::types::Block> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, transport.recv()).await {
            Ok(Ok((_, ConsensusMessage::BlockByHash(Some(b))))) => return Some(b),
            Ok(Ok((_, ConsensusMessage::BlockByHash(None)))) => return None,
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// Receive messages until a `BlockRange` arrives (ignoring others), or `timeout`.
/// Returns the full block vector (may be empty: peer has nothing at `from_seq`).
async fn recv_until_block_range(
    transport: &mut impl ConsensusTransport,
    timeout: std::time::Duration,
) -> Option<Vec<solidus_consensus::types::Block>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, transport.recv()).await {
            Ok(Ok((_, ConsensusMessage::BlockRange { blocks }))) => return Some(blocks),
            Ok(Ok(_)) => continue,
            _ => return None,
        }
    }
}

/// Bulk-fetch contiguous blocks forward from local `canon_head + 1` via
/// `GetBlockRange`, rotating peers + applying each response atomically via
/// `backfill::apply_block_range`. Stops when a peer returns an empty range
/// (no more blocks to give us) or a short range (< 64; near tip). Used by
/// `startup_catch_up` to bulk-pull large gaps in O(K/64) round trips instead
/// of K. STORAGE-ONLY: writes only canonical-ledger CFs.
///
/// Returns the number of blocks applied.
async fn bulk_burst_by_range(
    engine: &HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    deadline: tokio::time::Instant,
) -> usize {
    const RANGE_BATCH: u16 = 64;
    let n = engine.validators.len();
    if n < 2 {
        return 0;
    }
    let mut total_applied = 0usize;
    let mut probe = 0usize;
    let mut consecutive_empty = 0u32;

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        // If three peers in a row return empty, assume we're at the tip.
        if consecutive_empty >= 3 {
            break;
        }

        // Where to start: just past our current canon head, or 0 if empty.
        let from_seq = match solidus_consensus::ledger::canon_head(&engine.store)
            .ok()
            .flatten()
        {
            Some((seq, _)) => seq + 1,
            None => 0,
        };

        // Pick a peer (rotate, skip ourselves).
        let peer = (engine.node_index + 1 + probe) % n;
        probe = probe.wrapping_add(1);

        if transport
            .send(
                peer,
                ConsensusMessage::GetBlockRange {
                    from_seq,
                    count: RANGE_BATCH,
                },
            )
            .await
            .is_err()
        {
            continue;
        }

        let blocks =
            match recv_until_block_range(transport, std::time::Duration::from_secs(3)).await {
                Some(b) => b,
                None => continue, // timeout or non-range message — try next peer
            };

        if blocks.is_empty() {
            consecutive_empty += 1;
            continue;
        }
        consecutive_empty = 0;

        let len = blocks.len();
        match backfill::apply_block_range(&engine.store, from_seq, &blocks) {
            Ok(applied) => {
                total_applied += applied;
                // If we got a SHORT response (peer is at/near its tip), we're
                // probably at the network tip too — break and let the reverse
                // walker catch the residue.
                if len < RANGE_BATCH as usize {
                    break;
                }
            }
            Err(e) => {
                // Peer sent a malformed/forked range. Try a different peer.
                debug!(error = %e, %peer, "apply_block_range rejected; rotating peer");
            }
        }
    }
    total_applied
}

/// Fetch a block by hash, rotating peers + retrying so one gappy/slow/flooded
/// peer doesn't abort a backfill walk. Returns None only if no peer provides the
/// block before `deadline`. STORAGE-LAYER helper (touches no consensus state).
async fn fetch_block_robust(
    transport: &mut impl ConsensusTransport,
    hash: [u8; 32],
    node_index: usize,
    n: usize,
    deadline: tokio::time::Instant,
) -> Option<solidus_consensus::types::Block> {
    let mut attempt = 0usize;
    while tokio::time::Instant::now() < deadline && attempt < n * 3 {
        let p = (node_index + 1 + attempt) % n;
        attempt += 1;
        if transport
            .send(p, ConsensusMessage::GetBlockByHash { hash })
            .await
            .is_err()
        {
            continue;
        }
        if let Some(b) =
            recv_until_block_by_hash(transport, std::time::Duration::from_secs(3)).await
        {
            if b.hash() == hash {
                return Some(b);
            }
        }
    }
    None
}

/// Backfill the canon backward from `target` to genesis/known-canon, fetching
/// missing blocks robustly (rotate peers, retry, never abort on one failure).
/// STORAGE-ONLY: writes only the canonical-ledger CFs via `apply_fetched`.
async fn backfill_canon_to(
    engine: &HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    target: [u8; 32],
    deadline: tokio::time::Instant,
) {
    let n = engine.validators.len();
    let mut walk = backfill::WalkState::default();
    let head = solidus_consensus::ledger::canon_head(&engine.store)
        .ok()
        .flatten()
        .map(|(_, h)| h);
    let mut cursor = match backfill::next_cursor(&walk, target, head) {
        Some(c) => c,
        None => return, // already at target
    };
    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        let block = match solidus_consensus::ledger::get_block_by_hash(&engine.store, &cursor)
            .ok()
            .flatten()
        {
            Some(b) => b,
            None => {
                match fetch_block_robust(transport, cursor, engine.node_index, n, deadline).await {
                    Some(b) => b,
                    None => break, // no peer provided it within the deadline
                }
            }
        };
        match backfill::apply_fetched(&engine.store, cursor, block, &mut walk) {
            Ok(Some(next)) => cursor = next,
            Ok(None) => break, // connected — canon extended
            Err(_) => break,   // bad block
        }
    }
}

/// Learn a peer's committed tip hash, retrying + rotating peers (request-response
/// may not be ready right after the gossip peer gate). None if none answer.
async fn learn_tip(
    transport: &mut impl ConsensusTransport,
    node_index: usize,
    n: usize,
    deadline: tokio::time::Instant,
) -> Option<[u8; 32]> {
    let mut probe = 0usize;
    while tokio::time::Instant::now() < deadline {
        let p = (node_index + 1 + probe) % n;
        probe += 1;
        if transport.send(p, ConsensusMessage::GetTip).await.is_ok() {
            if let Some(h) = recv_until_tip(transport, std::time::Duration::from_secs(2)).await {
                if h != [0u8; 32] {
                    return Some(h);
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    None
}

/// Pre-loop catch-up: learn a peer's committed tip, backfill the canon to it,
/// then re-execute the canon to rebuild state. Runs BEFORE the consensus loop
/// with exclusive transport access, so the re-execution is race-free.
/// STORAGE + pre-loop re-execution only; never runs concurrently with consensus.
async fn startup_catch_up(engine: &mut HotStuffEngine, transport: &mut impl ConsensusTransport) {
    let n = engine.validators.len();
    if n <= 1 {
        return;
    }
    let overall = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    // Converge: each pass backfills + re-executes to the current tip; the chain
    // advances meanwhile, so loop until the committed-tip gap is closed. Capped
    // so we don't spin forever if production permanently outpaces re-execution.
    for _ in 0..12 {
        if tokio::time::Instant::now() >= overall {
            warn!("startup catch-up did not converge within the deadline");
            break;
        }
        // Short per-call budget so genesis startup is NOT blocked ~60s: at genesis
        // every node is in this pre-loop catch-up and none serves GetTip yet, so
        // learn_tip gets no answer. A running peer (the restart case) answers in
        // <1s, so 5s is plenty; if none answer, skip catch-up and join the loop.
        let tip_deadline =
            (tokio::time::Instant::now() + std::time::Duration::from_secs(5)).min(overall);
        let target = match learn_tip(transport, engine.node_index, n, tip_deadline).await {
            Some(t) => t,
            None => break,
        };
        if engine.committed_tip_hash() == target {
            break; // caught up to the committed tip
        }
        // C-3 batch burst FIRST: bulk-fetch contiguous forward blocks via
        // GetBlockRange (up to 64 per round-trip). For a fresh full node with
        // an empty canon and 1000+ blocks to catch up, this is ~16 round-trips
        // instead of ~1000 with the reverse walker — minutes instead of an hour.
        // Stops on empty/short response and hands off to the reverse walker
        // below to catch the residue near tip (where peers may have just
        // committed a new block we couldn't burst).
        let bursted = bulk_burst_by_range(engine, transport, overall).await;
        if bursted > 0 {
            info!(bursted, "startup catch-up: burst-fetched contiguous range");
        }
        // Reverse walker as fallback for the near-tip residue. Cheap when canon
        // is already close: backfill_canon_to short-circuits via next_cursor
        // when we're already at target.
        backfill_canon_to(engine, transport, target, overall).await;
        match engine.rebuild_state_from_canon() {
            Ok(seq) => info!(canon_tip_seq = seq, "startup catch-up pass complete"),
            Err(e) => warn!(error = %e, "startup state rebuild failed"),
        }
    }
    info!(
        tip_height = engine.last_committed_height,
        "startup catch-up finished"
    );
}

async fn run_consensus_loop(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: Arc<Mutex<u64>>,
    mut shutdown: watch::Receiver<bool>,
    // Receiver half of the RPC → loop bridge for tx gossip. The loop pulls
    // every tx accepted by `solidus_sendTransaction` and broadcasts it on
    // the libp2p `txs` topic so other validators' mempools see it. `None`
    // when no broadcast fan-out is wanted (e.g. in-process dev-testnet
    // where the channel transport already routes locally).
    mut tx_broadcast_rx: Option<
        tokio::sync::mpsc::UnboundedReceiver<solidus_txns::types::Transaction>,
    >,
    // Wake signal fired by the RPC `send_transaction` handler the moment a
    // tx enters the mempool, so the current leader proposes immediately
    // instead of waiting for a tick. `notify_waiters` only wakes loops that
    // are currently parked in the select — a wake that lands while this
    // loop is busy is lost, which is fine: the loop re-evaluates
    // `has_proposable_work` on every iteration, and the 500ms backfill tick
    // bounds the worst-case pickup latency.
    tx_wake: Arc<tokio::sync::Notify>,
    // Idle heartbeat interval: with no work the chain proposes ONE empty
    // block this often — it finalizes leftover padding, bounds engine
    // divergence, and keeps the explorer/monitoring view advancing.
    heartbeat_ms: u64,
) {
    // Mark the initial value as seen so that `changed()` doesn't fire
    // immediately — we only want to break on an actual shutdown signal.
    let _ = shutdown.borrow_and_update();

    // Out-of-band backfill walker state (STORAGE-ONLY: only ever touches the
    // canonical-ledger CFs; never consensus state). `awaiting` holds the
    // in-flight GetBlockByHash (hash, sent_at) so a stalled request can retry.
    let mut walk = backfill::WalkState::default();
    let mut awaiting: Option<([u8; 32], Instant)> = None;
    let mut backfill_peer: usize = 0;
    let mut backfill_tick = tokio::time::interval(std::time::Duration::from_millis(500));
    backfill_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // Wake-trigger: a gossiped `NewBlock` from a peer means the chain has
    // advanced — fire the backfill walker IMMEDIATELY instead of waiting
    // for the next 500ms tick. Tip-sync latency drops from up to 500ms
    // to ~0ms whenever any peer broadcasts a fresh tip on the blocks
    // gossipsub topic. Populated below by the recv arm.
    let sync_notify = std::sync::Arc::new(tokio::sync::Notify::new());

    // Initial proposal attempt — the first leader should propose immediately
    // (suppressed when there is no work; the heartbeat covers liveness).
    try_propose_if_leader(engine, transport, false).await;
    drain_self_qcs(engine, transport, &latest_height).await;

    // Empty-block suppression state. While idle the pacemaker deadline is
    // NOT armed — otherwise an idle chain degenerates into a timeout/TC
    // storm every MIN_TIMEOUT_MS — and the loop parks on the idle heartbeat
    // instead.
    let mut next_heartbeat = Instant::now() + std::time::Duration::from_millis(heartbeat_ms);
    let mut was_idle = false;

    loop {
        // n == 1: apply any QC this node formed from its own vote since the
        // last turn (no-op for larger committees).
        drain_self_qcs(engine, transport, &latest_height).await;
        let idle = !engine.has_proposable_work();
        if idle != was_idle {
            if idle {
                next_heartbeat = Instant::now() + std::time::Duration::from_millis(heartbeat_ms);
            } else {
                // Leaving idle: the pacemaker deadline is stale (long
                // expired). Bump it BEFORE re-arming the sleep, or the
                // timeout arm fires instantly and a timeout-vote storm
                // races — and can TC-kill — the fresh proposal.
                engine.pacemaker.bump_deadline_after_timeout();
                // A lost tx_wake lands here via the next loop iteration
                // (bounded by the 500ms backfill tick): propose DIRECTLY
                // instead of waiting ~2s for the pacemaker timeout → TC
                // detour. The one-proposal-per-round guard makes this safe
                // to call alongside the other propose triggers.
                try_propose_if_leader(engine, transport, false).await;
            }
            was_idle = idle;
        }
        let deadline = if idle {
            next_heartbeat
        } else {
            engine.pacemaker.deadline()
        };

        tokio::select! {
            // ── Shutdown signal ──────────────────────────────────────────
            _ = shutdown.changed() => {
                info!("consensus loop received shutdown signal");
                break;
            }

            // ── Deadline: idle heartbeat OR pacemaker timeout ────────────
            _ = tokio::time::sleep_until(deadline) => {
                if idle {
                    // Idle heartbeat: the current leader proposes ONE empty
                    // block (force bypasses the suppression gate). This
                    // finalizes leftover padding from the last burst and
                    // keeps the canonical head advancing while quiet.
                    next_heartbeat =
                        Instant::now() + std::time::Duration::from_millis(heartbeat_ms);
                    try_propose_if_leader(engine, transport, true).await;
                    continue;
                }

                // Before broadcasting a new timeout, drain any messages that
                // arrived while we were waiting — they may advance the round
                // and make this timeout unnecessary.
                drain_pending(engine, transport, &latest_height, &mut walk, &mut awaiting).await;

                // Re-check: if draining advanced us past this round, skip.
                if engine.pacemaker.deadline() > Instant::now() {
                    continue;
                }

                let round = engine.pacemaker.current_round();
                info!(round = round, "pacemaker timeout — broadcasting timeout vote");

                let sig = engine.bls_sk.sign(&TimeoutVote::signing_bytes(round));
                let tv = TimeoutVote {
                    round,
                    voter_index: engine.node_index,
                    highest_qc: engine.highest_qc.clone(),
                    bls_signature: sig,
                };

                // Record our own vote BEFORE broadcasting. Channel + libp2p
                // broadcasts skip the sender, so without this our local
                // pending bucket would only ever contain peer votes and we
                // would need ALL n-1 peers to reach quorum — a single lost
                // or late vote then wedges the round. Recording our own vote
                // means we only need quorum-1 peer votes to form a TC, which
                // matches every other node's accounting of the same round.
                if let Some(tc) = engine.record_own_timeout_vote(tv.clone()) {
                    let next = tc.round + 1;
                    engine.pacemaker.advance_round_on_tc(next);
                    engine.prune_stale_timeout_votes(next);
                    info!(
                        next_round = next,
                        "timeout certificate formed on own vote — advancing round"
                    );
                    try_propose_if_leader(engine, transport, false).await;
                }

                if let Err(e) = transport.broadcast(ConsensusMessage::TimeoutVoteMsg(tv)).await {
                    warn!(error = %e, "failed to broadcast timeout vote");
                }

                // Push the deadline forward by `timeout_duration` so we don't
                // busy-spin on an already-expired deadline while we wait for
                // either a TC (advances round) or a late proposal/QC.
                engine.pacemaker.bump_deadline_after_timeout();
            }

            // ── Out-of-band ledger backfill (STORAGE-ONLY) ───────────────
            // Fires on EITHER the 500ms ticker OR a wake from sync_notify
            // (NewBlock gossip arrived → chain advanced → walk now). The
            // bias makes the notify win on contention, so a fresh tip is
            // never delayed by a stale tick.
            _ = async {
                tokio::select! {
                    biased;
                    _ = sync_notify.notified() => {}
                    _ = backfill_tick.tick() => {}
                }
            } => {
                let n = engine.validators.len();
                if n > 1 {
                    // Drop a stalled request so it retries (next peer) but KEEP the
                    // walk's accumulated progress (resume from walk.cursor). Wiping
                    // it made the from-empty canon build never converge under load.
                    if let Some((_, sent)) = awaiting {
                        if sent.elapsed() > std::time::Duration::from_millis(1500) {
                            awaiting = None;
                        }
                    }
                    if awaiting.is_none() {
                        let target = engine.committed_tip_hash();
                        // Skip until a real block is committed. Before the first
                        // commit `committed_tip_hash()` is the all-zero genesis
                        // sentinel; starting a walk toward it captures that hash as
                        // `walk.cursor`, and because a failed fetch deliberately keeps
                        // the cursor (to retry an aging-but-real hash), `next_cursor`
                        // would then prefer the stuck sentinel over the advancing tip
                        // forever — so a live from-genesis node would never build its
                        // canon. (Restarted nodes dodge this: their startup catch-up
                        // runs once the committed tip is already a real hash.)
                        if target != backfill::GENESIS_PARENT {
                            let head = solidus_consensus::ledger::canon_head(&engine.store)
                                .ok()
                                .flatten()
                                .map(|(_, h)| h);
                            if let Some(cursor) = backfill::next_cursor(&walk, target, head) {
                                backfill_peer = backfill_peer.wrapping_add(1);
                                let peer = (engine.node_index + 1 + backfill_peer) % n;
                                if transport
                                    .send(peer, ConsensusMessage::GetBlockByHash { hash: cursor })
                                    .await
                                    .is_ok()
                                {
                                    walk.cursor = Some(cursor);
                                    awaiting = Some((cursor, Instant::now()));
                                }
                            }
                        }
                    }
                }
            }

            // ── Tx broadcast bridge: RPC `send_transaction` → libp2p gossip ──
            // Drains every tx the RPC accepted into the local mempool and
            // broadcasts it on the `/solidus/txs/1.0.0` gossipsub topic so
            // other validators see it and can include it in their proposals.
            // Without this branch, a tx submitted to ONE validator only
            // reaches that validator's mempool — the proposer-elsewhere case
            // (very common at testnet block rates) would orphan the tx.
            maybe_tx = async {
                match tx_broadcast_rx.as_mut() {
                    Some(rx) => rx.recv().await,
                    None => std::future::pending::<Option<_>>().await,
                }
            }, if tx_broadcast_rx.is_some() => {
                if let Some(tx) = maybe_tx {
                    if let Err(e) = transport
                        .broadcast(ConsensusMessage::NewTransaction(tx))
                        .await
                    {
                        warn!(error = %e, "failed to broadcast NewTransaction");
                    }
                    // The RPC already put this tx in OUR mempool — if we are
                    // the current leader, propose now (event-driven; there
                    // is no free-running cycle to pick it up anymore).
                    try_propose_if_leader(engine, transport, false).await;
                }
                // None means the RPC dropped its sender — node is shutting
                // down. Stop polling this branch (the `if` guard now sees
                // `tx_broadcast_rx.is_some()` true but the channel is
                // closed; the recv will keep returning None — clear the
                // option to fall off the branch entirely).
                else {
                    tx_broadcast_rx = None;
                }
            }

            // ── Tx wake: RPC accepted a tx into the mempool ──────────────
            // Fired by `send_transaction` the moment a tx is mempooled, so
            // the leader proposes immediately (sub-ms) instead of on the
            // next tick. Non-leaders wake, no-op, and re-park.
            _ = tx_wake.notified() => {
                try_propose_if_leader(engine, transport, false).await;
            }

            // ── Incoming network message ─────────────────────────────────
            // recv_with_source surfaces the inbound message's network source so
            // the GetTip/GetBlockByHash serving arms can reply to an index-less
            // full-node requester (from == usize::MAX). ADDITIVE: for normal
            // validator traffic `from` is a real index, `source` is ignored, and
            // the index send path is taken exactly as before — the live consensus
            // logic (proposal/vote/QC) is unchanged.
            result = transport.recv_with_source() => {
                match result {
                    Ok((from, source, msg)) => {
                        // Wake-trigger: a gossiped NewBlock means the chain
                        // has advanced (a peer committed a fresh tip). Fire
                        // the backfill walker NOW instead of waiting for the
                        // 500ms ticker. The notify is a no-op if no one is
                        // waiting (notified() has a 1-permit semaphore).
                        if matches!(msg, ConsensusMessage::NewBlock(_)) {
                            sync_notify.notify_one();
                        }
                        if let ConsensusMessage::BlockByHash(maybe) = msg {
                            // Backfill response — storage-only, never consensus.
                            handle_block_by_hash(engine, transport, maybe, &mut walk, &mut awaiting)
                                .await;
                        } else {
                            handle_consensus_message(
                                engine,
                                transport,
                                &latest_height,
                                from,
                                source,
                                msg,
                            )
                            .await;
                            // Drain all buffered messages before returning to the
                            // select! — this ensures the pacemaker deadline is
                            // recomputed with up-to-date round state.
                            drain_pending(
                                engine,
                                transport,
                                &latest_height,
                                &mut walk,
                                &mut awaiting,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "transport recv error");
                        break;
                    }
                }
            }
        }
    }
}

/// Drain all buffered messages from the transport without blocking.
///
/// Processes up to 256 messages per call to bound CPU time per drain cycle.
/// Stale timeout votes (for rounds older than the engine's current round)
/// are silently dropped.
async fn drain_pending(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: &Arc<Mutex<u64>>,
    walk: &mut backfill::WalkState,
    awaiting: &mut Option<([u8; 32], Instant)>,
) {
    const MAX_DRAIN: usize = 256;
    let mut drained = 0;
    while let Some((from, msg)) = transport.try_recv() {
        // Drop stale timeout votes — they cannot form a TC for the current
        // round and would only waste processing time.
        if let ConsensusMessage::TimeoutVoteMsg(ref tv) = msg {
            if tv.round < engine.pacemaker.current_round() {
                continue;
            }
        }
        // Drop stale votes for rounds we've already moved past.
        if let ConsensusMessage::VoteMsg(ref v) = msg {
            if v.round < engine.pacemaker.current_round() {
                continue;
            }
        }
        match msg {
            ConsensusMessage::BlockByHash(maybe) => {
                handle_block_by_hash(engine, transport, maybe, walk, awaiting).await;
            }
            other => {
                handle_consensus_message(engine, transport, latest_height, from, None, other).await;
            }
        }
        drained += 1;
        if drained >= MAX_DRAIN {
            break;
        }
    }
}

/// Apply a backfill `BlockByHash` response (STORAGE-ONLY: writes only the
/// canonical-ledger CFs via `backfill`/`ledger`; `engine` is read-only). On a
/// successful apply that still needs an ancestor, immediately request the next.
async fn handle_block_by_hash(
    engine: &HotStuffEngine,
    transport: &impl ConsensusTransport,
    maybe_block: Option<solidus_consensus::types::Block>,
    walk: &mut backfill::WalkState,
    awaiting: &mut Option<([u8; 32], Instant)>,
) {
    let (block, want) = match (maybe_block, awaiting.as_ref().map(|(h, _)| *h)) {
        (Some(b), Some(w)) => (b, w),
        _ => {
            *awaiting = None;
            return;
        }
    };
    let n = engine.validators.len();
    if n <= 1 {
        *awaiting = None;
        return;
    }
    let peer = (engine.node_index + 1) % n;
    match backfill::apply_fetched(&engine.store, want, block, walk) {
        Ok(Some(next)) => {
            if transport
                .send(peer, ConsensusMessage::GetBlockByHash { hash: next })
                .await
                .is_ok()
            {
                *awaiting = Some((next, Instant::now()));
            } else {
                *awaiting = None;
            }
        }
        // Connected (canon extended) or a bad/stale response — go idle; the
        // backfill tick re-kicks if the canon is still behind the tip.
        Ok(None) | Err(_) => *awaiting = None,
    }
}

/// Reply to the sender of an inbound message. For a normal validator peer
/// (`from` is a real index) this uses the index `send` path unchanged. For an
/// index-less full-node requester (`from == usize::MAX`), it replies by the
/// captured network `source` via `send_to_peer_id`. ADDITIVE: the validator
/// index path is reached exactly as before whenever `from != usize::MAX`.
async fn reply_to(
    transport: &impl ConsensusTransport,
    from: usize,
    source: Option<SourcePeer>,
    msg: ConsensusMessage,
) -> Result<(), solidus_p2p::transport::TransportError> {
    if from == usize::MAX {
        match source {
            Some(src) => transport.send_to_peer_id(src, msg).await,
            None => Err(solidus_p2p::transport::TransportError::Closed),
        }
    } else {
        transport.send(from, msg).await
    }
}

/// Handle a single incoming consensus message.
///
/// `source` carries the inbound message's network-level origin (libp2p PeerId)
/// when available, so the `GetTip`/`GetBlockByHash` serving arms can reply to an
/// index-less full-node requester (`from == usize::MAX`). For normal validator
/// peers `source` is unused and the index `send` path is taken unchanged.
async fn handle_consensus_message(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: &Arc<Mutex<u64>>,
    from: usize,
    source: Option<SourcePeer>,
    msg: ConsensusMessage,
) {
    match msg {
        ConsensusMessage::Proposal { block, justify_qc } => {
            info!(
                height = block.header.height,
                round = block.header.round,
                proposer = %block.header.proposer,
                "received proposal"
            );

            // Update QC state from the justify QC. A proposal is one of the
            // three ways a QC arrives from the network, so its justify_qc gets
            // the same signature check as a relayed one; an unverifiable
            // justify_qc is dropped and the proposal is still evaluated on its
            // own merits, which is the safe direction (no lock movement).
            if let Some(ref qc) = justify_qc {
                if !engine.on_new_qc(qc) {
                    warn!(
                        round = qc.round,
                        "proposal carried a justify_qc that does not verify"
                    );
                }
            }

            // Execute the block's transactions BEFORE voting. The
            // executor is idempotent on `tx_hash` (since 2026-05-18) —
            // if the proposer already applied this block to a shared
            // store, this is a no-op that returns the cached receipts.
            // The HotStuff config doesn't carry a network field today;
            // fall back to "testnet" (matches dev_testnet usage).
            let receipts = solidus_state::executor::execute_block(
                &engine.store,
                &block.transactions,
                block.header.height,
                block.header.timestamp_ms,
                &engine.config.treasury_address,
                &[], // validator addresses for fee distribution
                "testnet",
            )
            .unwrap_or_default();

            // State-root check (added 2026-05-19, paired with the
            // proposer-side speculative execution in `build_block`).
            // The proposer committed to a post-execution state root in
            // `block.header.state_root`. We just executed the same
            // transactions against our store; our resulting state root
            // MUST match. If not, the proposer is malicious or buggy
            // (e.g. claimed a state root that doesn't follow from its
            // own transactions) — refuse to vote.
            let our_state_root =
                solidus_state::executor::compute_state_root(&engine.store).unwrap_or([0u8; 32]);
            if our_state_root != block.header.state_root {
                warn!(
                    height = block.header.height,
                    round = block.header.round,
                    proposer = %block.header.proposer,
                    claimed = ?block.header.state_root,
                    actual = ?our_state_root,
                    "rejecting proposal: state_root mismatch"
                );
                // Skip voting AND skip inserting into uncommitted_blocks
                // so the bad block can't reach commit via 3-chain. State
                // mutations from execute_block above leak in dev-testnet
                // (shared store) but the block can't get a QC without
                // votes, so finality is preserved.
                return;
            }

            // Validate the block and vote if valid.
            if let Some(vote) = engine.validate_and_vote(&block) {
                if let Err(e) = transport.send(from, ConsensusMessage::VoteMsg(vote)).await {
                    warn!(error = %e, "failed to send vote");
                }
            }

            // Track block for 3-chain commit.
            engine
                .uncommitted_blocks
                .insert(block.header.round, (block, receipts));
        }

        ConsensusMessage::VoteMsg(vote) => {
            // Drop votes for rounds we've already moved past.
            if vote.round < engine.pacemaker.current_round() {
                return;
            }

            info!(
                round = vote.round,
                voter = vote.voter_index,
                "received vote"
            );

            if let Some(qc) = engine.process_vote(vote) {
                apply_qc(engine, transport, latest_height, &qc).await;

                // Broadcast the QC so all nodes advance and the next leader
                // can propose — this is the critical relay step.
                if let Err(e) = transport.broadcast(ConsensusMessage::NewQC(qc)).await {
                    warn!(error = %e, "failed to broadcast QC");
                }
            }
        }

        ConsensusMessage::NewQC(qc) => {
            // Only process if this QC is for a round we haven't passed yet.
            if qc.round < engine.pacemaker.current_round() {
                return;
            }

            info!(
                round = qc.round,
                signer_count = qc.signer_count(),
                "received QC relay"
            );

            apply_qc(engine, transport, latest_height, &qc).await;
        }

        ConsensusMessage::TimeoutVoteMsg(tv) => {
            // Drop timeout votes for rounds we've already moved past.
            if tv.round < engine.pacemaker.current_round() {
                return;
            }

            info!(
                round = tv.round,
                voter = tv.voter_index,
                "received timeout vote"
            );

            if let Some(tc) = engine.process_timeout_vote(tv) {
                // Use the TC's round, not our local round: if peer votes
                // for round R arrived before our pacemaker reached R, we
                // would otherwise advance only by 1 (current+1) instead of
                // jumping to R+1, leaving us several rounds behind every
                // time.
                let next = tc.round + 1;
                engine.pacemaker.advance_round_on_tc(next);
                engine.prune_stale_timeout_votes(next);
                info!(
                    next_round = next,
                    "timeout certificate formed — advancing round"
                );

                // If this node is the next leader after TC, propose a block
                try_propose_if_leader(engine, transport, false).await;
            }
        }

        ConsensusMessage::GetBlockByHash { hash } => {
            let block =
                solidus_consensus::ledger::get_block_by_hash(&engine.store, &hash).unwrap_or(None);
            if let Err(e) = reply_to(
                transport,
                from,
                source,
                ConsensusMessage::BlockByHash(block),
            )
            .await
            {
                warn!(error = %e, "failed to send BlockByHash");
            }
        }
        ConsensusMessage::GetTip => {
            let hash = engine.committed_tip_hash();
            if let Err(e) = reply_to(transport, from, source, ConsensusMessage::Tip { hash }).await
            {
                warn!(error = %e, "failed to send Tip");
            }
        }
        ConsensusMessage::GetBlockRange { from_seq, count } => {
            // Serve a contiguous slice of canon starting at `from_seq`.
            // Cap per-response to MAX_RANGE blocks so the BlockRange
            // payload stays under the 4 MiB read cap even for verbose
            // blocks (each block is bounded by max_block_txs * tx size).
            const MAX_RANGE: u16 = 64;
            let take = count.min(MAX_RANGE);
            let mut blocks: Vec<solidus_consensus::types::Block> =
                Vec::with_capacity(take as usize);
            for i in 0..take as u64 {
                let seq = from_seq + i;
                let hash = match solidus_consensus::ledger::canon_get(&engine.store, seq) {
                    Ok(Some(h)) => h,
                    Ok(None) => break, // ran off the end of our canon
                    Err(e) => {
                        warn!(seq = seq, error = %e, "canon_get failed during GetBlockRange");
                        break;
                    }
                };
                match solidus_consensus::ledger::get_block_by_hash(&engine.store, &hash) {
                    Ok(Some(b)) => blocks.push(b),
                    Ok(None) => {
                        warn!(seq = seq, ?hash, "canon hash missing block body");
                        break;
                    }
                    Err(e) => {
                        warn!(seq = seq, error = %e, "get_block_by_hash failed");
                        break;
                    }
                }
            }
            if let Err(e) = reply_to(
                transport,
                from,
                source,
                ConsensusMessage::BlockRange { blocks },
            )
            .await
            {
                warn!(error = %e, "failed to send BlockRange");
            }
        }
        // Sync responses are handled by the backfill walker / startup path
        // (BlockRange consumers live in run_consensus_loop / run_follower_loop).
        ConsensusMessage::BlockByHash(_)
        | ConsensusMessage::Tip { .. }
        | ConsensusMessage::BlockRange { .. } => {}

        // Tx gossip: a peer broadcast a NewTransaction on the `/solidus/txs/
        // 1.0.0` gossipsub topic. Verify its signature (NEVER trust gossip)
        // + insert into our local mempool. Mempool deduplication (by
        // tx_hash) is what stops a tx from being processed more than once
        // even though gossipsub's mesh re-forwarding re-delivers it.
        ConsensusMessage::NewTransaction(tx) => {
            if !tx.verify_signature() {
                warn!("dropping gossiped NewTransaction with invalid signature");
                return;
            }
            match engine.mempool.lock() {
                Ok(mut pool) => {
                    let inserted = pool.insert(tx);
                    if inserted {
                        debug!("mempool inserted gossiped tx");
                    }
                    // Duplicates are silently dropped — gossipsub re-delivers
                    // the same message via mesh forwarding.
                }
                Err(e) => {
                    warn!(error = %e, "mempool lock poisoned while accepting gossiped tx");
                }
            }
            // Event-driven proposing: a gossiped tx must trigger the leader
            // directly — there is no free-running proposal cycle to pick it
            // up. The suppression gate no-ops when we are not the leader or
            // the tx was a duplicate of already-proposed work.
            try_propose_if_leader(engine, transport, false).await;
        }

        // NewBlock is a gossip message — not handled in the consensus loop
        // directly (would be routed to sync). Sync uses the out-of-band
        // backfill walker instead (storage-only path).
        _ => {}
    }
}

/// Apply a QC: update engine state, attempt 3-chain commit, advance round,
/// and propose if this node is the next leader.
async fn apply_qc(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: &Arc<Mutex<u64>>,
    qc: &solidus_consensus::types::QuorumCertificate,
) {
    // Everything below this line acts on the QC: it moves the lock, finalises
    // blocks through the 3-chain rule, advances the round and can trigger a
    // proposal. None of it may run for a QC whose aggregate signature does not
    // verify against its own signer set.
    if !engine.on_new_qc(qc) {
        warn!(
            round = qc.round,
            signer_count = qc.signer_count(),
            "ignoring unverifiable QC: no commit, no round advance"
        );
        return;
    }

    // Attempt 3-chain commit.
    let committed = engine.try_commit();
    for (block, _) in &committed {
        if let Ok(mut h) = latest_height.lock() {
            *h = block.header.height;
        }
        info!(
            height = block.header.height,
            round = block.header.round,
            "block committed"
        );
    }

    // Advance round on QC.
    let next = qc.round + 1;
    engine.pacemaker.advance_round_on_qc(next);
    // Drop any stale timeout-vote buckets for rounds we've now passed —
    // otherwise a future stale duplicate could short-circuit at dedup
    // and prevent a fresh TC bucket from accumulating for the new round.
    engine.prune_stale_timeout_votes(next);

    // If this node is the next leader, propose a block
    try_propose_if_leader(engine, transport, false).await;
}

/// Check if this node is the leader for the current round and propose a block if so.
/// Uses round-robin leader election: leader = round % num_validators.
/// This is deterministic — all nodes agree on the leader without exchanging VRF proofs.
/// VRF-based election is used for verification of proposals in production (libp2p mode).
/// Apply QCs this node formed from its own vote (single-validator committee),
/// one at a time, exactly as a QC formed from peer votes is applied in the
/// `VoteMsg` handler: `apply_qc`, then broadcast `NewQC`. `apply_qc` may propose
/// again and refill the slot, so this loops; it stops when the empty-block gate
/// in `try_propose_if_leader` finds no work. Iteration, not recursion.
async fn drain_self_qcs(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: &Arc<Mutex<u64>>,
) {
    while let Some(qc) = engine.pending_self_qc.take() {
        apply_qc(engine, transport, latest_height, &qc).await;
        if let Err(e) = transport.broadcast(ConsensusMessage::NewQC(qc)).await {
            warn!(error = %e, "failed to broadcast self-formed QC");
        }
    }
}

async fn try_propose_if_leader(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    force: bool,
) {
    let round = engine.pacemaker.current_round();
    let n = engine.validators.len();
    let leader_idx = (round as usize) % n;

    if leader_idx == engine.node_index {
        // ONE proposal per round — even when forced. Propose triggers (tx
        // wake, gossip, RPC bridge, QC/TC advance, heartbeat) can fire more
        // than once inside a round; a second same-round build_block would
        // re-drain the mempool and EVICT the in-flight block from
        // uncommitted_blocks, silently losing its transactions and skipping
        // a height. A proposal that truly dies recovers via the pacemaker's
        // TC round-advance, which clears this guard by changing the round.
        if engine.last_proposed_round == Some(round) {
            debug!(
                round = round,
                node = engine.node_index,
                "already proposed this round — not re-proposing"
            );
            return;
        }

        // Empty-block suppression: propose only when there is work — pending
        // mempool txs, or an uncommitted tx-bearing block whose 3-chain
        // finalization still needs follow-up rounds. `force` bypasses the
        // gate for the idle heartbeat.
        if !force && !engine.has_proposable_work() {
            debug!(
                round = round,
                node = engine.node_index,
                "suppressing empty proposal — no work"
            );
            return;
        }
        engine.last_proposed_round = Some(round);

        info!(
            round = round,
            node = engine.node_index,
            "I am leader — building block proposal"
        );
        let (block, receipts) = engine.build_block();

        // Record our own vote for the block we're proposing, so a QC needs only
        // quorum-1 peer votes (the proposer counts itself, like every replica).
        // Analogue of record_own_timeout_vote on the pacemaker path. For n >= 2
        // this buffers the vote and returns None (1 < quorum); the QC then forms
        // when peer votes arrive via the VoteMsg handler. For n == 1 the own
        // vote already forms the QC: it is parked in `pending_self_qc` and
        // applied by `drain_self_qcs` from the event loop, NOT here, which
        // avoids a propose -> apply_qc -> propose recursion.
        if let Some(vote) = engine.validate_and_vote(&block) {
            if let Some(qc) = engine.record_own_vote(vote) {
                engine.pending_self_qc = Some(qc);
            }
        }

        // Track our own proposal for 3-chain commit, symmetric with the
        // receivers' Proposal handler — broadcast skips the sender, so
        // nothing else ever inserts it here. Without this the proposer is
        // blind to its own tx-bearing block and the suppression gate above
        // could go idle with that work still unfinalized.
        engine
            .uncommitted_blocks
            .insert(block.header.round, (block.clone(), receipts));

        let proposal = ConsensusMessage::Proposal {
            block,
            justify_qc: engine.highest_qc.clone(),
        };
        if let Err(e) = transport.broadcast(proposal).await {
            warn!(error = %e, "failed to broadcast proposal");
        }
    }
}

// ---------------------------------------------------------------------------
// Sign transfer
// ---------------------------------------------------------------------------

fn sign_transfer(key_path: &str, to: &str, amount: u64, nonce: u64) -> Result<(), Box<dyn Error>> {
    let sk = load_ed25519_key(Path::new(key_path))?;
    let sender_pubkey = sk.verifying_key().to_bytes();
    let to_addr = Address::from_base58(to)?;
    let mut tx = solidus_txns::types::Transaction {
        sender_pubkey,
        nonce,
        payload: solidus_txns::types::TxPayload::Transfer {
            to: to_addr,
            amount,
        },
        signature: [0u8; 64],
    };
    let msg = tx.signing_bytes();
    tx.signature = solidus_crypto::ed25519::sign(&sk, &msg);
    println!("{}", serde_json::to_string(&tx)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Canon dump
// ---------------------------------------------------------------------------

fn canon_dump(config_path: &str) -> Result<(), Box<dyn Error>> {
    let config_file_path = Path::new(config_path);
    let config_dir = config_file_path.parent().unwrap_or_else(|| Path::new("."));

    let multi_cfg = MultiNodeConfig::from_file(config_file_path)?;
    let data_dir = config_dir.join(&multi_cfg.node.data_dir);

    let store = Store::open(&data_dir)?;
    match solidus_consensus::ledger::canon_head(&store)? {
        Some((head, head_hash)) => {
            println!("canon_head_seq={head}");
            println!("canon_head_hash={}", hex::encode(head_hash));
            let mut contiguous = true;
            for seq in 0..=head {
                match solidus_consensus::ledger::canon_get(&store, seq)? {
                    Some(h) => println!("canon[{seq}]={}", hex::encode(h)),
                    None => {
                        contiguous = false;
                        println!("canon[{seq}]=MISSING");
                    }
                }
            }
            println!("contiguous={contiguous}");
        }
        None => println!("canon_head=NONE"),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Key loading helpers
// ---------------------------------------------------------------------------

/// Derive the base58 libp2p PeerId from a `node.key` file.
fn peer_id_from_key_file(path: &Path) -> Result<String, Box<dyn Error>> {
    let sk = load_ed25519_key(path)?;
    let keypair = solidus_p2p::identity::libp2p_keypair_from_node_seed(&sk.to_bytes())?;
    Ok(keypair.public().to_peer_id().to_base58())
}

/// Load an Ed25519 signing key from a hex-encoded file (32 bytes).
fn load_ed25519_key(path: &Path) -> Result<SigningKey, Box<dyn Error>> {
    let hex_str = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "ed25519 key must be 32 bytes")?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Load a BLS12-381 secret key from a hex-encoded file (32 bytes).
fn load_bls_key(path: &Path) -> Result<BlsSecretKey, Box<dyn Error>> {
    let hex_str = std::fs::read_to_string(path)?.trim().to_string();
    let bytes = hex::decode(&hex_str)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "BLS key must be 32 bytes")?;
    BlsSecretKey::from_bytes(&arr).map_err(|e| e.into())
}

// ---------------------------------------------------------------------------
// Genesis validator loading
// ---------------------------------------------------------------------------

/// Build the validator identity set from the genesis file.
fn load_genesis_validators(
    genesis: &GenesisFile,
) -> Result<Vec<ValidatorIdentity>, Box<dyn Error>> {
    genesis
        .validators
        .iter()
        .map(|v| {
            let address = Address::from_base58(&v.address)?;
            let ed_bytes = hex::decode(&v.ed25519_public_key)?;
            let bls_pk = BlsPublicKey::from_hex(&v.bls_public_key)?;

            let mut ed_arr = [0u8; 32];
            if ed_bytes.len() != 32 {
                return Err(format!(
                    "Ed25519 public key for {} must be 32 bytes, got {}",
                    v.address,
                    ed_bytes.len()
                )
                .into());
            }
            ed_arr.copy_from_slice(&ed_bytes);

            Ok(ValidatorIdentity {
                address,
                ed25519_pubkey: ed_arr,
                bls_pubkey: bls_pk,
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// One validator, quorum 1, backed by a leaked tempdir store.
    fn solo_engine() -> HotStuffEngine {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = Arc::new(solidus_state::store::Store::open(dir.path()).expect("store"));
        std::mem::forget(dir);
        let ed_sk = solidus_crypto::ed25519::generate_signing_key();
        let bls_sk = solidus_crypto::bls::BlsSecretKey::generate();
        let validators = vec![solidus_consensus::types::ValidatorIdentity {
            address: Address::from_public_key(&ed_sk.verifying_key()),
            ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
            bls_pubkey: bls_sk.public_key(),
        }];
        let config = solidus_consensus::hotstuff::HotStuffConfig {
            max_block_txs: 100,
            quorum_threshold: 1,
            treasury_address: Address::from_bytes([0xAAu8; 20]),
            skip_vrf: true,
        };
        HotStuffEngine::new(
            0,
            ed_sk,
            bls_sk,
            validators,
            store,
            Arc::new(Mutex::new(solidus_consensus::mempool::Mempool::new())),
            config,
        )
    }

    // n = 1 self-commit (2026-10-03). With one validator the proposer's own vote
    // already forms the QC, but try_propose_if_leader discarded it to avoid a
    // propose -> apply_qc -> propose recursion, so a lone validator never
    // advanced. The QC must now be applied, iteratively, by drain_self_qcs.
    #[tokio::test]
    async fn single_validator_applies_its_own_qc() {
        let mut engine = solo_engine();
        let mut net = solidus_p2p::channel::create_channel_network(1);
        let mut transport = net.remove(0);
        let latest = Arc::new(Mutex::new(0u64));
        let round0 = engine.pacemaker.current_round();

        try_propose_if_leader(&mut engine, &mut transport, true).await;
        drain_self_qcs(&mut engine, &mut transport, &latest).await;

        assert!(engine.highest_qc.is_some(), "own QC was not applied");
        assert!(
            engine.pacemaker.current_round() > round0,
            "round did not advance past {round0}"
        );
    }

    // The reported symptom was "a one-validator chain never COMMITS". HotStuff's
    // 3-chain rule needs three consecutive QCs before the first block commits;
    // forced heartbeats give a lone validator that chain.
    #[tokio::test]
    async fn single_validator_commits_after_three_chained_qcs() {
        let mut engine = solo_engine();
        let mut net = solidus_p2p::channel::create_channel_network(1);
        let mut transport = net.remove(0);
        let latest = Arc::new(Mutex::new(0u64));
        for _ in 0..4 {
            try_propose_if_leader(&mut engine, &mut transport, true).await;
            drain_self_qcs(&mut engine, &mut transport, &latest).await;
        }
        assert!(
            engine.last_committed_height >= 1,
            "lone validator committed nothing (height {})",
            engine.last_committed_height
        );
    }

    // --data-dir (2026-10-03): an external Kubernetes review found dev-testnet
    // writes its database INSIDE the directory holding the validator keys
    // (`<testnet-dir>/dev-data`), so keys cannot be a read-only Secret with
    // data on a separate volume.
    #[test]
    fn dev_testnet_accepts_data_dir_flag() {
        let cli = Cli::try_parse_from([
            "solidus-node",
            "dev-testnet",
            "--testnet-dir",
            "/keys",
            "--data-dir",
            "/var/lib/solidus",
        ])
        .expect("parse");
        match cli.command {
            Some(Commands::DevTestnet { data_dir, .. }) => {
                assert_eq!(data_dir.as_deref(), Some("/var/lib/solidus"))
            }
            _ => panic!("expected dev-testnet"),
        }
    }

    #[test]
    fn dev_data_dir_defaults_inside_testnet_dir_and_honours_override() {
        assert_eq!(
            dev_data_dir(Path::new("/keys"), None),
            std::path::PathBuf::from("/keys/dev-data")
        );
        assert_eq!(
            dev_data_dir(Path::new("/keys"), Some("/var/lib/solidus")),
            std::path::PathBuf::from("/var/lib/solidus")
        );
    }

    #[test]
    fn peer_id_from_key_file_round_trips() {
        let seed = [9u8; 32];
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("node.key");
        std::fs::write(&key_path, hex::encode(seed)).unwrap();

        let printed = peer_id_from_key_file(&key_path).unwrap();
        let expected = solidus_p2p::identity::libp2p_keypair_from_node_seed(&seed)
            .unwrap()
            .public()
            .to_peer_id()
            .to_base58();
        assert_eq!(printed, expected);
    }

    // -----------------------------------------------------------------------
    // Empty-block suppression — full consensus-loop behavior over the same
    // in-process channel network the dev-testnet runs on.
    // -----------------------------------------------------------------------

    /// Spawn a 4-validator dev net (shared store + mempool, channel
    /// transport) running `run_consensus_loop`, mirroring `run_dev_testnet`.
    #[allow(clippy::type_complexity)]
    fn spawn_dev_net(
        heartbeat_ms: u64,
    ) -> (
        Arc<Mutex<Mempool>>,
        Arc<Mutex<u64>>,
        Arc<tokio::sync::Notify>,
        watch::Sender<bool>,
        Vec<tokio::task::JoinHandle<()>>,
        Arc<Store>,
    ) {
        let n = 4;
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
        let tx_wake = Arc::new(tokio::sync::Notify::new());

        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        std::mem::forget(dir); // must outlive the store; fine in tests

        let mut ed_keys = Vec::with_capacity(n);
        let mut bls_keys = Vec::with_capacity(n);
        let mut validators = Vec::with_capacity(n);
        for _ in 0..n {
            let ed_sk = solidus_crypto::ed25519::generate_signing_key();
            let bls_sk = BlsSecretKey::generate();
            validators.push(ValidatorIdentity {
                address: Address::from_public_key(&ed_sk.verifying_key()),
                ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
                bls_pubkey: bls_sk.public_key(),
            });
            ed_keys.push(ed_sk);
            bls_keys.push(bls_sk);
        }

        let (shutdown_tx, _) = watch::channel(false);
        let mut transports = create_channel_network(n);
        let mut handles = Vec::new();

        for i in (0..n).rev() {
            let config = HotStuffConfig {
                max_block_txs: 100,
                quorum_threshold: 3,
                treasury_address: Address::from_bytes([0xAAu8; 20]),
                skip_vrf: true,
            };
            let mut engine = HotStuffEngine::new(
                i,
                ed_keys[i].clone(),
                bls_keys.remove(i),
                validators.clone(),
                Arc::clone(&store),
                Arc::clone(&mempool),
                config,
            );
            engine.round_seed = [7u8; 32];

            let mut transport = transports.remove(i);
            let lh = Arc::clone(&latest_height);
            let rx = shutdown_tx.subscribe();
            let wake = Arc::clone(&tx_wake);
            handles.push(tokio::spawn(async move {
                run_consensus_loop(
                    &mut engine,
                    &mut transport,
                    lh,
                    rx,
                    None,
                    wake,
                    heartbeat_ms,
                )
                .await;
            }));
        }

        (mempool, latest_height, tx_wake, shutdown_tx, handles, store)
    }

    /// A validly-signed Transfer from a throwaway key. Unfunded — the
    /// transfer fails at execution, which is irrelevant here: suppression
    /// and commit flow key off tx PRESENCE, not success.
    fn throwaway_transfer() -> solidus_txns::types::Transaction {
        use solidus_txns::types::{Transaction, TxPayload};
        let sk = solidus_crypto::ed25519::generate_signing_key();
        let mut tx = Transaction {
            sender_pubkey: sk.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([0xBBu8; 20]),
                amount: 1,
            },
            signature: [0u8; 64],
        };
        let msg = tx.signing_bytes();
        tx.signature = solidus_crypto::ed25519::sign(&sk, &msg);
        tx
    }

    async fn wait_for_height(latest_height: &Arc<Mutex<u64>>, target: u64, max_ms: u64) -> u64 {
        let deadline = Instant::now() + std::time::Duration::from_millis(max_ms);
        loop {
            let h = *latest_height.lock().unwrap();
            if h >= target || Instant::now() >= deadline {
                return h;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    /// The core suppression contract: an idle chain produces NO blocks
    /// (the free-run wrote ~1.16 GB/day of empty ones), a submitted tx
    /// wakes it and commits fast, and after the burst it goes quiet again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn idle_chain_is_silent_then_wakes_commits_and_resilences() {
        // Heartbeat far away so it cannot interfere with the assertions.
        let (mempool, latest_height, tx_wake, shutdown, handles, store) = spawn_dev_net(600_000);

        // 1. Idle: a full second with zero blocks. The pre-fix free-runner
        //    committed hundreds of blocks per second on channel transport.
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        assert_eq!(
            *latest_height.lock().unwrap(),
            0,
            "idle chain must produce no blocks"
        );

        // 2. Submit a tx + fire the wake: the tx block must reach 3-chain
        //    finality well inside the SDK's 10s receipt budget.
        mempool.lock().unwrap().insert(throwaway_transfer());
        tx_wake.notify_waiters();
        let h = wait_for_height(&latest_height, 1, 5_000).await;
        assert!(h >= 1, "tx-bearing block must commit after wake, got {h}");

        // 3. Quiet again: nothing else may commit (the leftover padding
        //    blocks finalize on the NEXT burst/heartbeat by design).
        let before = *latest_height.lock().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        let after = *latest_height.lock().unwrap();
        assert_eq!(
            before, after,
            "chain must go quiet after the burst finalizes its work"
        );

        // 4. A SECOND tx (fresh round) must commit AND reach canon — this is
        //    the multi-commit canon-head case that regressed live on
        //    2026-07-13 (walker/engine interleave moved the head pointer
        //    backward; restart-resume then orphaned the second block).
        mempool.lock().unwrap().insert(throwaway_transfer());
        tx_wake.notify_waiters();
        let h2 = wait_for_height(&latest_height, after + 1, 5_000).await;
        assert!(h2 > after, "second tx block must commit, got {h2}");
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (tip_seq, _) = solidus_consensus::ledger::canon_tip_scan(&store)
            .unwrap()
            .expect("canon must exist after two commits");
        assert!(
            tip_seq >= 1,
            "canon tip must include the second committed block, got seq {tip_seq}"
        );
        let head = solidus_consensus::ledger::canon_head(&store)
            .unwrap()
            .unwrap();
        assert_eq!(
            head.0, tip_seq,
            "canon head pointer must not lag the true tip (monotone append)"
        );

        let _ = shutdown.send(true);
        for jh in handles {
            let _ = jh.await;
        }
    }

    /// One proposal per round, ever: a second same-round trigger (another
    /// tx_wake, gossip, the RPC bridge) must NOT re-propose — re-proposing
    /// would re-drain the mempool and EVICT the in-flight block from
    /// `uncommitted_blocks`, silently losing its transactions and skipping
    /// a height (adversarial-review finding, 2026-07-13).
    #[tokio::test]
    async fn second_same_round_trigger_does_not_evict_inflight_proposal() {
        let n = 4;
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(dir.path()).unwrap());
        std::mem::forget(dir);

        let mut ed_keys = Vec::new();
        let mut bls_keys = Vec::new();
        let mut validators = Vec::new();
        for _ in 0..n {
            let ed_sk = solidus_crypto::ed25519::generate_signing_key();
            let bls_sk = BlsSecretKey::generate();
            validators.push(ValidatorIdentity {
                address: Address::from_public_key(&ed_sk.verifying_key()),
                ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
                bls_pubkey: bls_sk.public_key(),
            });
            ed_keys.push(ed_sk);
            bls_keys.push(bls_sk);
        }
        let mut transports = create_channel_network(n);
        let mut engine = HotStuffEngine::new(
            0, // leader of round 0
            ed_keys[0].clone(),
            bls_keys.remove(0),
            validators,
            Arc::clone(&store),
            Arc::clone(&mempool),
            HotStuffConfig {
                max_block_txs: 100,
                quorum_threshold: 3,
                treasury_address: Address::from_bytes([0xAAu8; 20]),
                skip_vrf: true,
            },
        );
        let mut transport = transports.remove(0);

        // First trigger: proposes the tx block.
        mempool.lock().unwrap().insert(throwaway_transfer());
        try_propose_if_leader(&mut engine, &mut transport, false).await;
        let first = engine
            .uncommitted_blocks
            .get(&0)
            .cloned()
            .expect("proposer must track its own in-flight block");
        assert_eq!(first.0.header.tx_count, 1);

        // Second same-round trigger with a fresh mempool tx: must be a no-op.
        mempool.lock().unwrap().insert(throwaway_transfer());
        try_propose_if_leader(&mut engine, &mut transport, false).await;
        // Heartbeat force must not bypass the guard either.
        try_propose_if_leader(&mut engine, &mut transport, true).await;

        assert_eq!(
            engine.uncommitted_blocks.get(&0).unwrap().0.hash(),
            first.0.hash(),
            "in-flight proposal must not be evicted by a same-round re-propose"
        );
        assert_eq!(
            mempool.lock().unwrap().len(),
            1,
            "the second tx stays pooled for the next round"
        );
        // Exactly one Proposal reached the peers.
        let mut proposals = 0;
        while let Some((_, msg)) = transports[0].try_recv() {
            if matches!(msg, ConsensusMessage::Proposal { .. }) {
                proposals += 1;
            }
        }
        assert_eq!(
            proposals, 1,
            "peers must see exactly one proposal for round 0"
        );
    }

    /// While idle, the heartbeat keeps the chain (slowly) advancing: each
    /// beat proposes one empty block, and 3-chain finality commits the
    /// block from two beats ago.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn idle_heartbeat_advances_the_chain() {
        let (_mempool, latest_height, _tx_wake, shutdown, handles, _store) = spawn_dev_net(150);

        // 3 beats (~450ms) are needed before the first commit; give it 5s.
        let h = wait_for_height(&latest_height, 1, 5_000).await;
        assert!(h >= 1, "heartbeat must keep the idle chain advancing");

        let _ = shutdown.send(true);
        for jh in handles {
            let _ = jh.await;
        }
    }
}

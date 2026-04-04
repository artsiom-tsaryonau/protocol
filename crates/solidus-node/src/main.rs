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
use tracing::{error, info, warn};

use solidus_consensus::hotstuff::{HotStuffConfig, HotStuffEngine};
use solidus_consensus::mempool::Mempool;
use solidus_consensus::proposer::{Proposer, ProposerConfig};
use solidus_consensus::types::{TimeoutVote, ValidatorIdentity};
use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey};
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use solidus_p2p::channel::create_channel_network;
use solidus_p2p::message::ConsensusMessage;
use solidus_p2p::transport::ConsensusTransport;
use solidus_rpc::server::start_rpc_server;
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
    },
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

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
        Some(Commands::Run { config, consensus }) => {
            if consensus {
                run_consensus_node(&config).await?;
            } else {
                run_node(&config).await?;
            }
        }
        Some(Commands::DevTestnet {
            testnet_dir,
            rpc_port,
        }) => {
            run_dev_testnet(&testnet_dir, rpc_port).await?;
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

    let (treasury_address, validator_addresses) =
        genesis::load_genesis(&store, &genesis_config)?;
    info!(
        chain_id = %chain_id,
        treasury = %treasury_address,
        validators = validator_addresses.len(),
        "loaded genesis"
    );

    // 4. Create shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 5. Start RPC server
    let listen_addr: SocketAddr = cfg.rpc_listen.parse()?;
    let (rpc_handle, rpc_addr) = start_rpc_server(
        listen_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
    )
    .await
    .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    info!(%rpc_addr, "RPC server started");

    // 6. Compute genesis_hash = blake3_hash(chain_id.as_bytes())
    let genesis_hash = blake3_hash(chain_id.as_bytes());

    // 7. Create and spawn Proposer
    let proposer_config = ProposerConfig {
        block_time_ms: cfg.block_time_ms,
        max_block_txs: cfg.max_block_txs,
        treasury_address,
        validator_addresses,
    };

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut proposer = Proposer::new(
        Arc::clone(&store),
        Arc::clone(&mempool),
        proposer_config,
        0,
        genesis_hash,
    );

    let proposer_handle = tokio::spawn(async move {
        proposer.run(shutdown_rx).await;
    });

    info!("solidus-node running — press Ctrl+C to stop");

    // 8. Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
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

// ---------------------------------------------------------------------------
// HotStuff BFT consensus node startup
// ---------------------------------------------------------------------------

async fn run_consensus_node(config_path: &str) -> Result<(), Box<dyn Error>> {
    let config_file_path = Path::new(config_path);
    let config_dir = config_file_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    // 1. Parse MultiNodeConfig from config.toml
    let multi_cfg = MultiNodeConfig::from_file(config_file_path)?;
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
    let treasury_address_str = genesis_file
        .initial_balances
        .iter()
        .find(|(_, &bal)| bal == 50_000_000 * 100_000_000)
        .map(|(addr, _)| addr.clone())
        .unwrap_or_else(|| {
            // Fallback: use the first validator address
            genesis_file.validators[0].address.clone()
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
    };

    let (treasury_address, validator_addresses) =
        genesis::load_genesis(&store, &genesis_config)?;
    info!(
        treasury = %treasury_address,
        validators = validator_addresses.len(),
        "applied genesis state"
    );

    // 6. Build Vec<ValidatorIdentity> from genesis validators
    let validators = load_genesis_validators(&genesis_file)?;
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
        block_time_ms: genesis_file.params.block_time_ms,
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
        "HotStuff engine created"
    );

    // 9. Start RPC server
    let rpc_addr: SocketAddr = format!("127.0.0.1:{}", multi_cfg.node.rpc_port).parse()?;
    let (rpc_handle, actual_rpc_addr) = start_rpc_server(
        rpc_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e })?;
    info!(%actual_rpc_addr, "RPC server started");

    // 10. Create transport (channel-based for now; libp2p can be wired later)
    // For multi-node dev/test, we use a single-node channel transport.
    // In production, LibP2PTransport::start() would be used with peer configs.
    let n = engine.validators.len();
    let mut transports = create_channel_network(n);
    let mut transport = transports.remove(multi_cfg.node.node_index);

    // 11. Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // 12. Spawn the consensus main loop
    let consensus_latest_height = Arc::clone(&latest_height);
    let consensus_handle = tokio::spawn(async move {
        run_consensus_loop(&mut engine, &mut transport, consensus_latest_height, shutdown_rx).await;
    });

    info!(
        node_index = multi_cfg.node.node_index,
        "solidus-node (HotStuff consensus) running — press Ctrl+C to stop"
    );

    // 13. Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
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
// Dev testnet: all validators in one process
// ---------------------------------------------------------------------------

async fn run_dev_testnet(testnet_dir: &str, rpc_port: u16) -> Result<(), Box<dyn Error>> {
    let testnet_path = Path::new(testnet_dir);

    // 1. Load genesis
    let genesis_path = testnet_path.join("genesis.json");
    let genesis_str = std::fs::read_to_string(&genesis_path)?;
    let genesis_file: GenesisFile = serde_json::from_str(&genesis_str)?;
    let n = genesis_file.validators.len();
    info!(validators = n, chain_id = %genesis_file.chain_id, "loading dev testnet");

    // 2. Build validator identities
    let validators = load_genesis_validators(&genesis_file)?;

    // 4. Open store and apply genesis (shared by all validators in dev mode)
    let data_dir = testnet_path.join("dev-data");
    std::fs::create_dir_all(&data_dir)?;
    let store = Arc::new(Store::open(&data_dir)?);

    let treasury_address_str = genesis_file
        .initial_balances
        .keys()
        .find(|k| {
            !genesis_file
                .validators
                .iter()
                .any(|v| v.address == **k)
        })
        .cloned()
        .unwrap_or_default();

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
    };
    let (treasury_address, _validator_addresses) =
        genesis::load_genesis(&store, &genesis_config)?;

    // 5. Parse round seed
    let round_seed_bytes = hex::decode(&genesis_file.round_seed)?;
    let mut round_seed = [0u8; 32];
    if round_seed_bytes.len() == 32 {
        round_seed.copy_from_slice(&round_seed_bytes);
    }

    // 6. Shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 7. Create channel network
    let mut transports = create_channel_network(n);

    // 8. Create engines and spawn consensus loops
    let quorum_threshold = genesis_file.params.quorum_threshold;
    let (shutdown_tx, _) = watch::channel(false);
    let mut handles = Vec::new();

    for i in (0..n).rev() {
        let hotstuff_config = HotStuffConfig {
            max_block_txs: genesis_file.params.max_block_txs,
            block_time_ms: genesis_file.params.block_time_ms,
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

        let mut transport = transports.remove(i);
        let lh = Arc::clone(&latest_height);
        let shutdown_rx = shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            run_consensus_loop(&mut engine, &mut transport, lh, shutdown_rx).await;
        });
        handles.push(handle);
    }

    info!(
        validators = n,
        quorum = quorum_threshold,
        "dev testnet running — {} validators in one process",
        n
    );

    // 9. Start RPC server (exposes validator-0's state)
    let rpc_addr: SocketAddr = format!("127.0.0.1:{rpc_port}").parse()?;
    let (rpc_handle, actual_rpc_addr) = start_rpc_server(
        rpc_addr,
        Arc::clone(&store),
        Arc::clone(&mempool),
        Arc::clone(&latest_height),
    )
    .await
    .map_err(|e| -> Box<dyn Error> { e })?;
    info!(%actual_rpc_addr, "RPC server started");

    // 10. Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
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

/// The HotStuff BFT consensus main loop.
///
/// Drives the pacemaker, handles incoming proposals/votes/timeouts, and
/// manages block commitment via the 3-chain finality rule.
async fn run_consensus_loop(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: Arc<Mutex<u64>>,
    mut shutdown: watch::Receiver<bool>,
) {
    // Initial proposal attempt — the first leader should propose immediately
    try_propose_if_leader(engine, transport).await;

    loop {
        let deadline = engine.pacemaker.deadline();

        tokio::select! {
            // ── Shutdown signal ──────────────────────────────────────────
            _ = shutdown.changed() => {
                info!("consensus loop received shutdown signal");
                break;
            }

            // ── Pacemaker timeout: broadcast timeout vote ────────────────
            _ = tokio::time::sleep_until(deadline) => {
                let round = engine.pacemaker.current_round();
                info!(round = round, "pacemaker timeout — broadcasting timeout vote");

                let sig = engine.bls_sk.sign(format!("timeout_{round}").as_bytes());
                let tv = TimeoutVote {
                    round,
                    voter_index: engine.node_index,
                    highest_qc: engine.highest_qc.clone(),
                    bls_signature: sig,
                };

                if let Err(e) = transport.broadcast(ConsensusMessage::TimeoutVoteMsg(tv)).await {
                    warn!(error = %e, "failed to broadcast timeout vote");
                }
            }

            // ── Incoming network message ─────────────────────────────────
            result = transport.recv() => {
                match result {
                    Ok((from, msg)) => {
                        handle_consensus_message(engine, transport, &latest_height, from, msg).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "transport recv error");
                        // If the transport is closed, break out of the loop.
                        break;
                    }
                }
            }
        }
    }
}

/// Handle a single incoming consensus message.
async fn handle_consensus_message(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
    latest_height: &Arc<Mutex<u64>>,
    from: usize,
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

            // Update QC state from the justify QC.
            if let Some(ref qc) = justify_qc {
                engine.on_new_qc(qc);
            }

            // Validate the block and vote if valid.
            if let Some(vote) = engine.validate_and_vote(&block) {
                if let Err(e) = transport.send(from, ConsensusMessage::VoteMsg(vote)).await {
                    warn!(error = %e, "failed to send vote");
                }
            }

            // Execute the block's transactions for potential commit.
            let receipts = solidus_state::executor::execute_block(
                &engine.store,
                &block.transactions,
                block.header.height,
                &engine.config.treasury_address,
                &[], // validator addresses for fee distribution
            )
            .unwrap_or_default();

            // Track block for 3-chain commit.
            engine
                .uncommitted_blocks
                .insert(block.header.round, (block, receipts));
        }

        ConsensusMessage::VoteMsg(vote) => {
            info!(
                round = vote.round,
                voter = vote.voter_index,
                "received vote"
            );

            if let Some(qc) = engine.process_vote(vote) {
                engine.on_new_qc(&qc);

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
                engine.pacemaker.advance_round_on_qc(qc.round + 1);

                // If this node is the next leader, propose a block
                try_propose_if_leader(engine, transport).await;
            }
        }

        ConsensusMessage::TimeoutVoteMsg(tv) => {
            info!(
                round = tv.round,
                voter = tv.voter_index,
                "received timeout vote"
            );

            if let Some(_tc) = engine.process_timeout_vote(tv) {
                let next = engine.pacemaker.current_round() + 1;
                engine.pacemaker.advance_round_on_tc(next);
                info!(next_round = next, "timeout certificate formed — advancing round");

                // If this node is the next leader after TC, propose a block
                try_propose_if_leader(engine, transport).await;
            }
        }

        // NewBlock and NewTransaction are gossip messages — not handled in
        // the consensus loop directly (would be routed to mempool / sync).
        _ => {}
    }
}

/// Check if this node is the leader for the current round and propose a block if so.
/// Uses round-robin leader election: leader = round % num_validators.
/// This is deterministic — all nodes agree on the leader without exchanging VRF proofs.
/// VRF-based election is used for verification of proposals in production (libp2p mode).
async fn try_propose_if_leader(
    engine: &mut HotStuffEngine,
    transport: &mut impl ConsensusTransport,
) {
    let round = engine.pacemaker.current_round();
    let n = engine.validators.len();
    let leader_idx = (round as usize) % n;

    if leader_idx == engine.node_index {
        info!(round = round, node = engine.node_index, "I am leader — building block proposal");
        let block = engine.build_block();
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
// Key loading helpers
// ---------------------------------------------------------------------------

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
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "BLS key must be 32 bytes")?;
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
                return Err(
                    format!(
                        "Ed25519 public key for {} must be 32 bytes, got {}",
                        v.address,
                        ed_bytes.len()
                    )
                    .into(),
                );
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

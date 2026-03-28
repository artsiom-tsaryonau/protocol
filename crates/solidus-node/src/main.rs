mod config;
mod genesis;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use clap::Parser;
use tokio::sync::watch;
use tracing::{error, info};

use solidus_consensus::mempool::Mempool;
use solidus_consensus::proposer::{Proposer, ProposerConfig};
use solidus_crypto::hash::blake3_hash;
use solidus_rpc::server::start_rpc_server;
use solidus_state::store::Store;

use crate::config::NodeConfig;
use crate::genesis::GenesisConfig;

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(name = "solidus-node", about = "Solidus Protocol Node")]
struct Cli {
    /// Path to the TOML configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // 2. Parse CLI args
    let cli = Cli::parse();

    // 3. Load config (with fallback to defaults)
    let cfg = match NodeConfig::from_file(&cli.config) {
        Ok(c) => {
            info!(path = %cli.config, "loaded config");
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

    // 4. Create data_dir, open Store
    std::fs::create_dir_all(&cfg.data_dir)?;
    let store = Arc::new(Store::open(&cfg.data_dir)?);
    info!(data_dir = %cfg.data_dir.display(), "opened store");

    // 5. Load genesis from JSON file
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

    // 6. Create shared state
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let latest_height: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));

    // 7. Start RPC server
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

    // 8. Compute genesis_hash = blake3_hash(chain_id.as_bytes())
    let genesis_hash = blake3_hash(chain_id.as_bytes());

    // 9. Create and spawn Proposer
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

    // 10. Wait for Ctrl+C
    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");

    // 11. Send shutdown signal, await proposer, stop RPC
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

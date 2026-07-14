//! `solidus-noded` — the Solidus v2 node daemon (the deployable artifact).
//!
//! ```text
//! solidus-noded gen <dir> <n> [chain_id]   generate a local N-validator devnet
//! solidus-noded run <config.toml>          run a validator from its config
//! ```
//!
//! Scope (honest): this is the machinery to RUN v2. It does not choose the
//! production chain-id, genesis, or validator set — those founder-only values
//! are config data. And it does not touch the live legacy testnet: a v2 network
//! is a parallel network on its own chain-id (BD-6).

mod config;
mod faucet;
mod gen;
mod run;

use anyhow::{anyhow, Result};

const USAGE: &str = "solidus-noded — Solidus v2 node daemon\n\n\
USAGE:\n  \
solidus-noded gen <dir> <n> [chain_id]   generate a local N-validator devnet config set\n  \
solidus-noded run <config.toml>          run a validator from its config\n  \
solidus-noded faucet <faucet.toml>       run a testnet faucet against a node's RPC\n  \
solidus-noded keygen                     generate one validator's keys (for joining a committee)\n";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("gen") => {
            let dir = args
                .get(2)
                .ok_or_else(|| anyhow!("gen: missing <dir>\n\n{USAGE}"))?;
            let n: usize = args
                .get(3)
                .ok_or_else(|| anyhow!("gen: missing <n>\n\n{USAGE}"))?
                .parse()
                .map_err(|_| anyhow!("gen: <n> must be a number"))?;
            let chain_id: u64 = match args.get(4) {
                Some(s) => s
                    .parse()
                    .map_err(|_| anyhow!("gen: <chain_id> must be a number"))?,
                None => 31337,
            };
            gen::generate(dir, n, chain_id)
        }
        Some("run") => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow!("run: missing <config.toml>\n\n{USAGE}"))?;
            let text = std::fs::read_to_string(path).map_err(|e| anyhow!("read {path}: {e}"))?;
            let cfg: config::DaemonConfig =
                toml::from_str(&text).map_err(|e| anyhow!("parse {path}: {e}"))?;
            run::run(cfg).await
        }
        Some("keygen") => gen::keygen(),
        Some("faucet") => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow!("faucet: missing <faucet.toml>\n\n{USAGE}"))?;
            let text = std::fs::read_to_string(path).map_err(|e| anyhow!("read {path}: {e}"))?;
            let cfg: faucet::FaucetConfig =
                toml::from_str(&text).map_err(|e| anyhow!("parse {path}: {e}"))?;
            faucet::run(cfg).await
        }
        _ => {
            eprint!("{USAGE}");
            std::process::exit(2);
        }
    }
}

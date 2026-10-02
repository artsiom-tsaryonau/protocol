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

mod attest;
mod config;
mod faucet;
mod gen;
mod gov;
mod pop;
mod run;

use anyhow::{anyhow, Result};

const USAGE: &str = "solidus-noded — Solidus v2 node daemon\n\n\
USAGE:\n  \
solidus-noded gen <dir> <n> [chain_id]   generate a local N-validator devnet config set\n  \
solidus-noded run <config.toml>          run a validator from its config\n  \
solidus-noded faucet <faucet.toml>       run a testnet faucet against a node's RPC\n  \
solidus-noded keygen                     generate one validator's keys (for joining a committee)\n  \
solidus-noded bridge-gov <request.toml>  build a signed bridge governance tx (hex)\n  \
solidus-noded bls-pop <config.toml>      print this node's BLS proof of possession (never the secret)\n  \
solidus-noded --version                  print the version this binary was built from\n";

/// What this binary reports for `--version`.
///
/// ⛔ A RELEASE MANIFEST NAMES A VERSION AND THE BINARY MUST AGREE WITH IT. The
/// installer verifies a signed manifest whose `version` field drives the
/// download path, and before this existed an operator had no way to check that
/// what they installed is what the manifest promised. `--version` printed the
/// usage banner, which reads like a version and is not one.
///
/// ⚠ THE CRATE VERSION ALONE NAMES NO CODE: it has been 0.1.0 on every build.
/// The commit comes from `build.rs`, with ", tree modified" when the consensus
/// workspace had uncommitted tracked changes at build time.
const VERSION: &str = concat!(
    "solidus-noded ",
    env!("CARGO_PKG_VERSION"),
    " (commit ",
    env!("SOLIDUS_BUILD_COMMIT"),
    ")"
);

/// Should this binary refuse to start because it carries the test activation schedule?
///
/// ⛔ A NODE BUILT WITH THE TEST SCHEDULE SWITCHES RULES AT HEIGHT 1_000 AND FORKS FROM
/// EVERY REAL NODE. Only the local harness may run one, and it must say so explicitly:
/// the override is the exact string `"1"`, so a stray `SOLIDUS_ALLOW_TEST_SCHEDULE=true`
/// or `=yes` in a shell profile cannot quietly unlock a forking binary.
fn refuse_test_schedule(allow_env: Option<&str>) -> bool {
    solidus_exec::protocol::V2_ACTIVATION_HEIGHT
        == solidus_exec::protocol::TEST_V2_ACTIVATION_HEIGHT
        && allow_env != Some("1")
}

#[tokio::main]
async fn main() -> Result<()> {
    if refuse_test_schedule(std::env::var("SOLIDUS_ALLOW_TEST_SCHEDULE").ok().as_deref()) {
        eprintln!(
            "solidus-noded was built with the test-activation-schedule feature; refusing to start (set SOLIDUS_ALLOW_TEST_SCHEDULE=1 only in the local harness)"
        );
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") | Some("version") => {
            println!("{VERSION}");
            return Ok(());
        }
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
        Some("bls-pop") => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow!("bls-pop: missing <config.toml>\n\n{USAGE}"))?;
            let text = std::fs::read_to_string(path).map_err(|e| anyhow!("read {path}: {e}"))?;
            println!("{}", pop::pop_line(&text)?);
            Ok(())
        }
        Some("bridge-gov") => {
            let path = args
                .get(2)
                .ok_or_else(|| anyhow!("bridge-gov: missing <request.toml>\n\n{USAGE}"))?;
            let text = std::fs::read_to_string(path).map_err(|e| anyhow!("read {path}: {e}"))?;
            let tx = gov::build_transaction(&text)?;
            println!(
                "{}",
                hex::encode(bincode::serialize(&tx).map_err(|e| anyhow!("encode: {e}"))?)
            );
            Ok(())
        }
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

#[cfg(test)]
mod tests {
    use super::VERSION;

    /// `--version` must name the commit, not only the crate version. The crate
    /// version is 0.1.0 on every build since the fork, so it says nothing about
    /// which code is running; the item that asked for this found mtime to be the
    /// only datable fact about the validator producing our blocks.
    #[test]
    fn version_names_the_commit_it_was_built_from() {
        let rest = VERSION
            .strip_prefix(concat!(
                "solidus-noded ",
                env!("CARGO_PKG_VERSION"),
                " (commit "
            ))
            .unwrap_or_else(|| panic!("no commit in the version string: {VERSION:?}"));
        let commit = rest.split([',', ')']).next().unwrap_or_default();
        assert!(
            commit == "unknown"
                || (commit.len() == 12 && commit.chars().all(|c| c.is_ascii_hexdigit())),
            "the commit must be 12 hex digits or say unknown, got {commit:?} in {VERSION:?}"
        );
        assert!(VERSION.ends_with(')'), "{VERSION:?}");
    }
}

#[cfg(test)]
mod schedule_guard_tests {
    use super::*;

    /// ⚠ THE ASSERTIONS ARE WRITTEN AGAINST THE BUILD, NOT AGAINST A CONSTANT, so this one
    /// test file is meaningful in both builds: without the feature `test_build` is false and
    /// nothing is refused; with it, every value except exactly `"1"` refuses. Run it both ways.
    #[test]
    fn the_override_must_be_exactly_one() {
        let test_build = solidus_exec::protocol::V2_ACTIVATION_HEIGHT
            == solidus_exec::protocol::TEST_V2_ACTIVATION_HEIGHT;
        assert_eq!(refuse_test_schedule(None), test_build);
        assert_eq!(
            refuse_test_schedule(Some("true")),
            test_build,
            "only \"1\" overrides"
        );
        assert_eq!(
            refuse_test_schedule(Some("")),
            test_build,
            "empty is not \"1\""
        );
        assert!(!refuse_test_schedule(Some("1")));
    }
}

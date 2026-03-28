use serde::Deserialize;
use std::path::PathBuf;

/// Top-level node configuration, typically loaded from a TOML file.
#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    /// Directory where RocksDB and other persistent data are stored.
    pub data_dir: PathBuf,
    /// Socket address the JSON-RPC server will bind to (e.g. `"127.0.0.1:9944"`).
    pub rpc_listen: String,
    /// Target interval between blocks in milliseconds.
    pub block_time_ms: u64,
    /// Maximum number of transactions to include per block.
    pub max_block_txs: usize,
    /// Path to the genesis JSON file.
    pub genesis_file: PathBuf,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            rpc_listen: "127.0.0.1:9944".to_string(),
            block_time_ms: 500,
            max_block_txs: 1000,
            genesis_file: PathBuf::from("genesis.json"),
        }
    }
}

impl NodeConfig {
    /// Load a `NodeConfig` from a TOML file at the given path.
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&contents)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_expected_values() {
        let cfg = NodeConfig::default();
        assert_eq!(cfg.data_dir, PathBuf::from("./data"));
        assert_eq!(cfg.rpc_listen, "127.0.0.1:9944");
        assert_eq!(cfg.block_time_ms, 500);
        assert_eq!(cfg.max_block_txs, 1000);
        assert_eq!(cfg.genesis_file, PathBuf::from("genesis.json"));
    }

    #[test]
    fn from_file_parses_toml() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            r#"
data_dir = "/tmp/solidus"
rpc_listen = "0.0.0.0:8080"
block_time_ms = 1000
max_block_txs = 500
genesis_file = "my_genesis.json"
"#,
        )
        .expect("failed to write config");

        let cfg = NodeConfig::from_file(path.to_str().unwrap()).expect("failed to parse");
        assert_eq!(cfg.data_dir, PathBuf::from("/tmp/solidus"));
        assert_eq!(cfg.rpc_listen, "0.0.0.0:8080");
        assert_eq!(cfg.block_time_ms, 1000);
        assert_eq!(cfg.max_block_txs, 500);
        assert_eq!(cfg.genesis_file, PathBuf::from("my_genesis.json"));
    }

    #[test]
    fn from_file_missing_file_returns_error() {
        let result = NodeConfig::from_file("/nonexistent/config.toml");
        assert!(result.is_err());
    }
}

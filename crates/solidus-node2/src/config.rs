//! Node + topology configuration. The 21-validator / 3-region layout is
//! the mainnet-candidate target (§4.9) — this file is the Stage-7
//! topology-config artifact; actually standing it up needs multi-region
//! hardware (R-TOPOLOGY, founder follow-up).

use serde::{Deserialize, Serialize};

/// One validator's placement in the mainnet-candidate topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSpec {
    pub index: u32,
    /// Deployment region label (e.g. "eu-central", "us-east", "ap-south").
    pub region: String,
    /// Reachable address for validator-to-validator traffic
    /// (host:port; filled by ops at deploy time).
    pub address: String,
}

/// The network topology: regions and validator placement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyConfig {
    pub chain_id: u64,
    pub validators: Vec<ValidatorSpec>,
}

impl TopologyConfig {
    /// The §4.9 mainnet-candidate layout: 21 validators, 3 regions × 7.
    /// Sub-100ms intra-region RTT is REQUIRED for the sub-1s finality
    /// budget and is unverified until the real latency probe runs
    /// (R-TOPOLOGY — do not treat as load-bearing before measurement).
    pub fn three_regions_21(chain_id: u64) -> Self {
        let regions = ["eu-central", "us-east", "ap-south"];
        let validators = (0..21u32)
            .map(|index| ValidatorSpec {
                index,
                region: regions[(index / 7) as usize].to_string(),
                address: format!("validator-{index}.solidus-v2.internal:9500"),
            })
            .collect();
        Self {
            chain_id,
            validators,
        }
    }

    /// Local harness layout: n validators, one logical region.
    pub fn local(chain_id: u64, n: usize) -> Self {
        let validators = (0..n as u32)
            .map(|index| ValidatorSpec {
                index,
                region: "local".to_string(),
                address: format!("127.0.0.1:{}", 9500 + index),
            })
            .collect();
        Self {
            chain_id,
            validators,
        }
    }
}

/// Per-node runtime knobs.
#[derive(Debug, Clone)]
pub struct NodeTuning {
    /// Max batch certificates drafted into one proposal.
    pub max_certs_per_block: usize,
    /// Worker batch thresholds.
    pub batch_max_bytes: usize,
    pub batch_max_txs: usize,
    /// Worker flush interval (bounds batch latency under light load).
    pub flush_interval_ms: u64,
}

impl Default for NodeTuning {
    fn default() -> Self {
        Self {
            max_certs_per_block: 32,
            batch_max_bytes: 1_024 * 1_024,
            batch_max_txs: 2_000,
            flush_interval_ms: 25,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_topology_is_21_across_3_regions() {
        let topo = TopologyConfig::three_regions_21(2);
        assert_eq!(topo.validators.len(), 21);
        for region in ["eu-central", "us-east", "ap-south"] {
            assert_eq!(
                topo.validators
                    .iter()
                    .filter(|v| v.region == region)
                    .count(),
                7,
                "{region}"
            );
        }
        // Serializable for ops tooling.
        let encoded = bincode::serialize(&topo).expect("serialize");
        let back: TopologyConfig = bincode::deserialize(&encoded).expect("deserialize");
        assert_eq!(back.validators.len(), 21);
    }
}

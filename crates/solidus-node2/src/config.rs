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
    /// Minimum wall-clock gap between this node's own proposals, in ms. `0`
    /// disables pacing.
    ///
    /// ⛔ MUST HAVE VIEW-TIMEOUT HEADROOM. `Core::new` asserts the pacemaker
    /// timeout is at least `MIN_TIMEOUT_HEADROOM`x this, because a view with no
    /// proposal by its timeout rotates leadership: set this too high and blocks
    /// arrive at the BACKOFF rate with a timeout certificate each, while the
    /// chain still commits and looks fine from outside.
    pub min_block_interval_ms: u64,
    /// View timeout base, in ms. `0` keeps the pacemaker's own default.
    ///
    /// ⛔ IT IS HERE BECAUSE PACING WITHOUT IT IS UNSHIPPABLE. The pacemaker base
    /// is 400ms, and `Core::new` requires the timeout to be at least
    /// `MIN_TIMEOUT_HEADROOM`x the block interval, so with the default pacemaker
    /// the largest legal interval is 200ms. Asking for 2s blocks — the figure the
    /// explorer has always stated as the target — is impossible unless this moves
    /// with it. They are one decision, so they are one config block.
    pub view_timeout_ms: u64,
    /// Propose an empty block after this long with nothing to include. `0`
    /// disables empty-block suppression. ⚠ Keep it long; v1 uses 600s.
    pub idle_heartbeat_ms: u64,
    /// Work must be absent this long CONTINUOUSLY before a view is suppressed.
    pub idle_grace_ms: u64,
    /// Worker flush interval (bounds batch latency under light load).
    pub flush_interval_ms: u64,
    /// Keep this many blocks behind the committed head; prune cold data below
    /// that horizon. `0` disables pruning entirely.
    ///
    /// ⚠ THIS MUST EXCEED THE BLOCK-SYNC WINDOW. Pruning drops blocks, receipts
    /// and canon entries (never state), so a peer asking to backfill a height
    /// below the horizon cannot be served. Retention too small turns a lagging
    /// validator into a permanently stuck one.
    ///
    /// ⛔ SIZING: USE 0.27 KB/BLOCK, NOT 0.1. The older note here read "measured
    /// 2026-09-02 on the v2 devnet: 1.8M blocks occupied ~183 MB, so ~0.1 KB/block
    /// ... roughly 100 MB per validator". That is **2.7x optimistic** against the
    /// live chain and anyone sizing mainnet retention from it would be 2.7x under.
    ///
    /// Re-measured 2026-09-24 on the rpc box, all four validators identical:
    /// **269 MB of SST per validator** at a retention window confirmed from
    /// OUTSIDE the box (the RPC serves tip-1.000.000 and returns null at
    /// tip-1.010.000), so **0.269 KB/block**, and 1.17 GB across the four.
    /// Split the total, because the earlier 2.9x figure came from conflating them:
    /// 292 MB total per validator is 269 MB SST plus a RocksDB info LOG that was
    /// 31 MB on 09-18 and 5 MB today. The LOG rotates; the SST is the block cost.
    ///
    /// ⚠ WHY IT MAY EXCEED THE 09-02 DEVNET FIGURE IS NOT MEASURED. With 500 ms
    /// pacing and no empty-block suppression the chain produces ~2 blocks/s
    /// regardless of load, so most of today's million blocks are EMPTY and still
    /// cost 0.269 KB each. That is a hypothesis about the difference, not a
    /// measurement of it. Size from the measured figure, not from the story.
    pub block_retention: u64,
}

impl Default for NodeTuning {
    fn default() -> Self {
        Self {
            max_certs_per_block: 32,
            batch_max_bytes: 1_024 * 1_024,
            batch_max_txs: 2_000,
            flush_interval_ms: 25,
            block_retention: 1_000_000,
            // ⚠ PACING IS OFF BY DEFAULT, DELIBERATELY. Turning it on changes how
            // fast a chain produces blocks and how long a faulty leader stalls it;
            // that is a per-network decision, not a library default, and a default
            // that silently reshapes an existing chain's timing is how you get an
            // outage nobody connects to a version bump. Set both explicitly in
            // `[tuning]`. The live testnet's values and the reasoning are in
            // the protocol plan, and `Core::new` refuses an incoherent pair.
            min_block_interval_ms: 0,
            view_timeout_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
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

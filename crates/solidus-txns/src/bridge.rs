//! Bridge payloads and records (registry §2.5, §2.6). Executed only at
//! ProtocolVersion::V2; see `solidus_exec::bridge`.

use serde::{Deserialize, Serialize};
use solidus_crypto::hash::blake3_hash;

pub const EXPORT_STATUS_ACTIVE: u8 = 1;
pub const EXPORT_STATUS_REVOKED: u8 = 2;
pub const EXPORT_STATUS_EXPIRED: u8 = 3;
pub const EXPORT_STATUS_UNBOUND: u8 = 4;

/// The destination chain's virtual machine.
///
/// ⚠ The discriminants are the JSON code the RPC serves (1, 2, 3). Bincode does
/// NOT write them: serde encodes a unit variant by its declaration index, so
/// the wire carries 0, 1, 2. Append new variants at the end.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeDomainVm {
    Evm = 1,
    Svm = 2,
    Cosmos = 3,
}

impl BridgeDomainVm {
    /// JSON code served by the RPC (1, 2, 3). Bincode uses the declaration index instead.
    pub fn code(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernorApproval {
    pub public_key: [u8; 32],
    /// 64-byte ed25519 signature over `governance_signing_message`.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeGovAction {
    /// `inbox` is OUR contract on that chain (the mirror on EVM, the program id on SVM).
    RegisterDomain {
        domain: u32,
        vm: BridgeDomainVm,
        inbox: [u8; 32],
        heartbeat_interval_secs: u64,
        enabled: bool,
    },
    SetTrustRoot {
        did: String,
        enabled: bool,
    },
    /// Phase 4 (plan 41). Rejected by the executor until then.
    SetInboundSigners {
        origin_domain: u32,
        validators: Vec<[u8; 20]>,
        threshold: u8,
    },
}

/// `BLAKE3("SLDS_BRIDGE_GOV_V1" ‖ network len u64 LE ‖ network ‖ gov_nonce u64 LE ‖ bincode(action))`.
pub fn governance_signing_message(
    network: &str,
    gov_nonce: u64,
    action: &BridgeGovAction,
) -> [u8; 32] {
    #[allow(clippy::expect_used)]
    let action_bin =
        bincode::serialize(action).expect("BridgeGovAction bincode serialization cannot fail");
    let mut buf = Vec::with_capacity(18 + 8 + network.len() + 8 + action_bin.len());
    buf.extend_from_slice(b"SLDS_BRIDGE_GOV_V1");
    buf.extend_from_slice(&(network.len() as u64).to_le_bytes());
    buf.extend_from_slice(network.as_bytes());
    buf.extend_from_slice(&gov_nonce.to_le_bytes());
    buf.extend_from_slice(&action_bin);
    blake3_hash(&buf)
}

/// Stored at `StateKey::bridge_domain(domain)` (registry §2.6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeDomain {
    pub domain: u32,
    pub vm: BridgeDomainVm,
    pub inbox: [u8; 32],
    pub heartbeat_interval_secs: u64,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEntry {
    pub domain: u32,
    pub holder: [u8; 32],
    pub export_id: [u8; 32],
    pub valid_until: u64,
    pub status: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSet {
    pub entries: Vec<ExportEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub solidus_height: u64,
    pub message: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TxPayload;

    fn register() -> BridgeGovAction {
        BridgeGovAction::RegisterDomain {
            domain: 11_155_111,
            vm: BridgeDomainVm::Evm,
            inbox: [2; 32],
            heartbeat_interval_secs: 600,
            enabled: true,
        }
    }

    #[test]
    fn bridge_payloads_are_appended_at_indices_16_17_18() {
        let gov = TxPayload::BridgeGovernance {
            action: register(),
            gov_nonce: 0,
            approvals: vec![],
        };
        let export = TxPayload::ExportCredential {
            credential_id: "c".into(),
            domain: 1,
            holder: [0; 32],
            valid_until: 0,
            consent_sig: vec![],
            consent_expiry: 0,
        };
        let unexport = TxPayload::UnexportCredential {
            credential_id: "c".into(),
            domain: 1,
            holder: [0; 32],
        };
        assert_eq!(
            &bincode::serialize(&gov).unwrap()[..4],
            &16u32.to_le_bytes()
        );
        assert_eq!(
            &bincode::serialize(&export).unwrap()[..4],
            &17u32.to_le_bytes()
        );
        assert_eq!(
            &bincode::serialize(&unexport).unwrap()[..4],
            &18u32.to_le_bytes()
        );
    }

    #[test]
    fn governance_message_binds_network_nonce_and_action() {
        let base = governance_signing_message("testnet", 0, &register());
        assert_ne!(base, governance_signing_message("mainnet", 0, &register()));
        assert_ne!(base, governance_signing_message("testnet", 1, &register()));
        assert_ne!(
            base,
            governance_signing_message(
                "testnet",
                0,
                &BridgeGovAction::SetTrustRoot {
                    did: "did:x".into(),
                    enabled: true
                }
            )
        );
    }

    #[test]
    fn records_round_trip_through_bincode() {
        let set = ExportSet {
            entries: vec![ExportEntry {
                domain: 7,
                holder: [3; 32],
                export_id: [4; 32],
                valid_until: 9,
                status: EXPORT_STATUS_ACTIVE,
            }],
        };
        assert_eq!(
            bincode::deserialize::<ExportSet>(&bincode::serialize(&set).unwrap()).unwrap(),
            set
        );
        let e = OutboxEntry {
            solidus_height: 5,
            message: vec![1, 2, 3],
        };
        assert_eq!(
            bincode::deserialize::<OutboxEntry>(&bincode::serialize(&e).unwrap()).unwrap(),
            e
        );
    }

    #[test]
    fn vm_json_codes_are_one_two_three() {
        assert_eq!(BridgeDomainVm::Evm.code(), 1);
        assert_eq!(BridgeDomainVm::Svm.code(), 2);
        assert_eq!(BridgeDomainVm::Cosmos.code(), 3);
    }
}

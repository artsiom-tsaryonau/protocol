//! `solidus-noded bridge-gov <request.toml>`: build a signed BridgeGovernance
//! transaction offline. Secrets come from environment variables (load them with
//! the sops helper); nothing secret is printed.

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::SigningKey;
use serde::Deserialize;
use solidus_exec::WireMode;
use solidus_txns::bridge::{
    governance_signing_message, BridgeDomainVm, BridgeGovAction, GovernorApproval,
};
use solidus_txns::types::{Transaction, TxPayload};

#[derive(Deserialize)]
struct Request {
    network: String,
    chain_id: u64,
    wire: String,
    submitter_seed_env: String,
    submitter_nonce: u64,
    gov_nonce: u64,
    governor_seed_envs: Vec<String>,
    action: ActionSpec,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum ActionSpec {
    RegisterDomain {
        domain: u32,
        vm: String,
        inbox: String,
        heartbeat_interval_secs: u64,
        enabled: bool,
    },
    SetTrustRoot {
        did: String,
        enabled: bool,
    },
}

fn seed(env: &str) -> Result<SigningKey> {
    let hexed = std::env::var(env).map_err(|_| anyhow!("environment variable {env} is not set"))?;
    let bytes: [u8; 32] = hex::decode(hexed.trim().trim_start_matches("0x"))
        .map_err(|_| anyhow!("{env} is not hex"))?
        .try_into()
        .map_err(|_| anyhow!("{env} is not 32 bytes"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn bytes32(s: &str, name: &str) -> Result<[u8; 32]> {
    hex::decode(s.trim_start_matches("0x"))
        .map_err(|_| anyhow!("{name} is not hex"))?
        .try_into()
        .map_err(|_| anyhow!("{name} is not 32 bytes"))
}

pub fn build_transaction(text: &str) -> Result<Transaction> {
    let req: Request = toml::from_str(text).context("parse bridge-gov request")?;
    let action = match req.action {
        ActionSpec::RegisterDomain {
            domain,
            vm,
            inbox,
            heartbeat_interval_secs,
            enabled,
        } => BridgeGovAction::RegisterDomain {
            domain,
            vm: match vm.as_str() {
                "evm" => BridgeDomainVm::Evm,
                "svm" => BridgeDomainVm::Svm,
                "cosmos" => BridgeDomainVm::Cosmos,
                other => return Err(anyhow!("unknown vm {other}")),
            },
            inbox: bytes32(&inbox, "inbox")?,
            heartbeat_interval_secs,
            enabled,
        },
        ActionSpec::SetTrustRoot { did, enabled } => BridgeGovAction::SetTrustRoot { did, enabled },
    };
    let msg = governance_signing_message(&req.network, req.gov_nonce, &action);
    let approvals = req
        .governor_seed_envs
        .iter()
        .map(|env| {
            let k = seed(env)?;
            Ok(GovernorApproval {
                public_key: k.verifying_key().to_bytes(),
                signature: solidus_crypto::ed25519::sign(&k, &msg).to_vec(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let submitter = seed(&req.submitter_seed_env)?;
    let mode = match req.wire.as_str() {
        "v2" => WireMode::BinaryV2,
        "v3" => WireMode::BinaryV3 {
            chain_id: req.chain_id,
        },
        other => return Err(anyhow!("wire must be v2 or v3, got {other}")),
    };
    let mut tx = Transaction {
        sender_pubkey: submitter.verifying_key().to_bytes(),
        nonce: req.submitter_nonce,
        payload: TxPayload::BridgeGovernance {
            action,
            gov_nonce: req.gov_nonce,
            approvals,
        },
        signature: [0; 64],
    };
    tx.signature =
        solidus_crypto::ed25519::sign(&submitter, &solidus_exec::wire::signing_bytes(&tx, mode));
    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(kind_block: &str) -> String {
        format!(
            "network = \"testnet\"\nchain_id = 50002\nwire = \"v3\"\nsubmitter_seed_env = \"T_SUBMITTER\"\nsubmitter_nonce = 4\ngov_nonce = 7\ngovernor_seed_envs = [\"T_GOV1\", \"T_GOV2\"]\n\n[action]\n{kind_block}"
        )
    }

    fn with_env<T>(f: impl FnOnce() -> T) -> T {
        std::env::set_var("T_SUBMITTER", hex::encode([0xC0u8; 32]));
        std::env::set_var("T_GOV1", hex::encode([0xB1u8; 32]));
        std::env::set_var("T_GOV2", hex::encode([0xB2u8; 32]));
        f()
    }

    #[test]
    fn builds_a_signed_register_domain_transaction_with_two_valid_approvals() {
        let text = request(&format!(
            "kind = \"register-domain\"\ndomain = 11155111\nvm = \"evm\"\ninbox = \"0x{}\"\nheartbeat_interval_secs = 600\nenabled = true",
            hex::encode([2u8; 32])
        ));
        let tx = with_env(|| build_transaction(&text)).unwrap();
        assert_eq!(tx.nonce, 4);
        let TxPayload::BridgeGovernance {
            action,
            gov_nonce,
            approvals,
        } = &tx.payload
        else {
            panic!("wrong payload")
        };
        assert_eq!(*gov_nonce, 7);
        let msg = solidus_txns::bridge::governance_signing_message("testnet", 7, action);
        for a in approvals {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&a.public_key).unwrap();
            assert!(solidus_crypto::ed25519::verify(
                &vk,
                &msg,
                &a.signature.clone().try_into().unwrap()
            ));
        }
        assert!(solidus_exec::wire::verify_signature(
            &tx,
            solidus_exec::WireMode::BinaryV3 { chain_id: 50002 }
        ));
    }

    #[test]
    fn builds_set_trust_root() {
        let text = request(
            "kind = \"set-trust-root\"\ndid = \"did:solidus:testnet:root\"\nenabled = true",
        );
        let tx = with_env(|| build_transaction(&text)).unwrap();
        assert!(matches!(
            &tx.payload,
            TxPayload::BridgeGovernance {
                action: solidus_txns::bridge::BridgeGovAction::SetTrustRoot { .. },
                ..
            }
        ));
    }

    #[test]
    fn a_missing_secret_names_the_variable_and_not_a_value() {
        std::env::remove_var("T_MISSING");
        let text = request("kind = \"set-trust-root\"\ndid = \"d\"\nenabled = true")
            .replace("T_GOV2", "T_MISSING");
        let err = with_env(|| build_transaction(&text))
            .unwrap_err()
            .to_string();
        assert!(err.contains("T_MISSING"), "{err}");
    }
}

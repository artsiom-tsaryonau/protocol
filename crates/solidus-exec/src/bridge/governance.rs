//! Bridge governance: compiled governor keys, a threshold, and a replay nonce.

use std::collections::BTreeSet;

use ed25519_dalek::VerifyingKey;
use solidus_txns::bridge::{
    governance_signing_message, BridgeDomain, BridgeGovAction, GovernorApproval,
};
use solidus_txns::types::{Event, Receipt, TxStatus};

use super::fail;
use super::store::{
    load_domains_index, read_u64, save_domain, save_domains_index, set_flag, write_u64,
};
use crate::account::Account;
use crate::error::ExecError;
use crate::protocol::{bridge_governance_threshold, bridge_governor_keys};
use crate::types::{BlockCtx, StateKey};
use crate::view::TxView;

fn approved_count(
    network: &str,
    gov_nonce: u64,
    action: &BridgeGovAction,
    approvals: &[GovernorApproval],
) -> usize {
    let msg = governance_signing_message(network, gov_nonce, action);
    let governors = bridge_governor_keys();
    let mut approved = BTreeSet::new();
    for a in approvals {
        if !governors.contains(&a.public_key) {
            continue;
        }
        let Ok(sig) = <[u8; 64]>::try_from(a.signature.as_slice()) else {
            continue;
        };
        let Ok(vk) = VerifyingKey::from_bytes(&a.public_key) else {
            continue;
        };
        if solidus_crypto::ed25519::verify(&vk, &msg, &sig) {
            approved.insert(a.public_key);
        }
    }
    approved.len()
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_bridge_governance<V: TxView>(
    view: &mut V,
    sender: Account,
    ctx: &BlockCtx<'_>,
    tx_hash: [u8; 32],
    fee: u64,
    action: &BridgeGovAction,
    gov_nonce: u64,
    approvals: &[GovernorApproval],
) -> Result<Receipt, ExecError> {
    let expected = read_u64(view, &StateKey::bridge_gov_nonce())?;
    if gov_nonce != expected {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            format!("governance nonce mismatch: expected {expected}, got {gov_nonce}"),
        );
    }
    let count = approved_count(ctx.network, gov_nonce, action, approvals);
    let threshold = bridge_governance_threshold();
    if count < threshold {
        return fail(
            view,
            &sender,
            ctx,
            tx_hash,
            fee,
            format!("governance approvals below threshold: {count} of {threshold}"),
        );
    }
    let events = match action {
        BridgeGovAction::RegisterDomain {
            domain,
            vm,
            inbox,
            heartbeat_interval_secs,
            enabled,
        } => {
            save_domain(
                view,
                &BridgeDomain {
                    domain: *domain,
                    vm: *vm,
                    inbox: *inbox,
                    heartbeat_interval_secs: *heartbeat_interval_secs,
                    enabled: *enabled,
                },
            )?;
            let mut index = load_domains_index(view)?;
            if let Err(pos) = index.binary_search(domain) {
                index.insert(pos, *domain);
                save_domains_index(view, &index)?;
            }
            vec![Event::BridgeDomainRegistered {
                domain: *domain,
                enabled: *enabled,
            }]
        }
        BridgeGovAction::SetTrustRoot { did, enabled } => {
            set_flag(view, StateKey::bridge_trust_root(did), *enabled)?;
            vec![Event::BridgeTrustRootSet {
                did: did.clone(),
                enabled: *enabled,
            }]
        }
        BridgeGovAction::SetInboundSigners { .. } => {
            return fail(
                view,
                &sender,
                ctx,
                tx_hash,
                fee,
                "SetInboundSigners is not active until bridge phase 4",
            );
        }
    };
    write_u64(view, StateKey::bridge_gov_nonce(), gov_nonce + 1)?;
    crate::handlers::save_account(view, &sender)?;
    Ok(Receipt {
        tx_hash,
        status: TxStatus::Success,
        block_height: ctx.height,
        fee_paid: fee,
        events,
    })
}

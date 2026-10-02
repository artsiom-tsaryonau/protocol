#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
use solidus_txns::bridge::BridgeDomainVm;

#[test]
fn bridge_transactions_fail_before_v2_and_still_bump_the_nonce() {
    let mut chain = Chain::at_height(V2_ACTIVATION_HEIGHT - 2);
    let r = chain.run_one(
        &submitter(),
        gov_payload(
            0,
            register_action(SEPOLIA, BridgeDomainVm::Evm, mirror32()),
            &[1, 2],
        ),
    );
    assert_eq!(
        failure(&r),
        "bridge transactions are not active at this height"
    );
    assert_eq!(r.fee_paid, 0, "fee-exempt");
    let second = chain.tx(
        &submitter(),
        gov_payload(
            0,
            register_action(SEPOLIA, BridgeDomainVm::Evm, mirror32()),
            &[1, 2],
        ),
    );
    assert_eq!(
        second.nonce, 1,
        "the failed receipt bumped the nonce like any in-handler failure"
    );
}

use solidus_exec::StateKey;
use solidus_txns::bridge::{BridgeDomain, BridgeGovAction, GovernorApproval};
use solidus_txns::types::{Event, TxPayload};

fn register() -> BridgeGovAction {
    register_action(SEPOLIA, BridgeDomainVm::Evm, mirror32())
}

#[test]
fn two_of_three_governors_register_a_domain_and_consume_the_nonce() {
    let mut chain = Chain::new();
    let r = chain.run_one(&submitter(), gov_payload(0, register(), &[1, 2]));
    assert!(succeeded(&r), "{}", failure(&r));
    assert!(r.events.contains(&Event::BridgeDomainRegistered {
        domain: SEPOLIA,
        enabled: true
    }));
    let d: BridgeDomain =
        bincode::deserialize(&chain.read(&StateKey::bridge_domain(SEPOLIA)).unwrap()).unwrap();
    assert_eq!(d.inbox, mirror32());
    let index: Vec<u32> =
        bincode::deserialize(&chain.read(&StateKey::bridge_domains_index()).unwrap()).unwrap();
    assert_eq!(index, vec![SEPOLIA]);
    assert_eq!(
        chain.read(&StateKey::bridge_gov_nonce()).unwrap(),
        1u64.to_le_bytes().to_vec()
    );
}

#[test]
fn one_approval_is_below_the_threshold() {
    let mut chain = Chain::new();
    let r = chain.run_one(&submitter(), gov_payload(0, register(), &[1]));
    assert_eq!(failure(&r), "governance approvals below threshold: 1 of 2");
}

#[test]
fn a_repeated_governor_counts_once() {
    let mut chain = Chain::new();
    let r = chain.run_one(&submitter(), gov_payload(0, register(), &[1, 1]));
    assert_eq!(failure(&r), "governance approvals below threshold: 1 of 2");
}

#[test]
fn a_key_outside_the_governor_set_does_not_count() {
    let mut chain = Chain::new();
    let r = chain.run_one(&submitter(), gov_payload(0, register(), &[1, 9]));
    assert_eq!(failure(&r), "governance approvals below threshold: 1 of 2");
}

#[test]
fn a_replayed_governance_nonce_fails() {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let r = chain.run_one(&submitter(), gov_payload(0, register(), &[1, 2]));
    assert_eq!(failure(&r), "governance nonce mismatch: expected 1, got 0");
}

#[test]
fn approvals_for_a_different_action_do_not_authorise_this_one() {
    let mut chain = Chain::new();
    let signed_for = gov_payload(
        0,
        register_action(43_113, BridgeDomainVm::Evm, mirror32()),
        &[1, 2],
    );
    let TxPayload::BridgeGovernance { approvals, .. } = signed_for else {
        unreachable!()
    };
    let tampered = TxPayload::BridgeGovernance {
        action: register(),
        gov_nonce: 0,
        approvals,
    };
    let r = chain.run_one(&submitter(), tampered);
    assert_eq!(failure(&r), "governance approvals below threshold: 0 of 2");
}

#[test]
fn approvals_signed_for_another_network_do_not_count() {
    let mut chain = Chain::new();
    let msg = solidus_txns::bridge::governance_signing_message("mainnet", 0, &register());
    let approvals = [1u8, 2]
        .iter()
        .map(|i| {
            let k = governor(*i);
            GovernorApproval {
                public_key: k.verifying_key().to_bytes(),
                signature: solidus_crypto::ed25519::sign(&k, &msg).to_vec(),
            }
        })
        .collect();
    let r = chain.run_one(
        &submitter(),
        TxPayload::BridgeGovernance {
            action: register(),
            gov_nonce: 0,
            approvals,
        },
    );
    assert_eq!(failure(&r), "governance approvals below threshold: 0 of 2");
}

#[test]
fn a_trust_root_can_be_set_and_cleared() {
    let mut chain = Chain::new();
    let set = chain.run_one(
        &submitter(),
        gov_payload(
            0,
            BridgeGovAction::SetTrustRoot {
                did: "did:solidus:testnet:root".into(),
                enabled: true,
            },
            &[2, 3],
        ),
    );
    assert!(succeeded(&set), "{}", failure(&set));
    assert_eq!(
        chain.read(&StateKey::bridge_trust_root("did:solidus:testnet:root")),
        Some(vec![1])
    );
    let clear = chain.run_one(
        &submitter(),
        gov_payload(
            1,
            BridgeGovAction::SetTrustRoot {
                did: "did:solidus:testnet:root".into(),
                enabled: false,
            },
            &[1, 3],
        ),
    );
    assert!(succeeded(&clear), "{}", failure(&clear));
    assert_eq!(
        chain.read(&StateKey::bridge_trust_root("did:solidus:testnet:root")),
        Some(vec![0])
    );
}

#[test]
fn inbound_ism_changes_are_refused_until_phase_4_and_keep_the_nonce() {
    let mut chain = Chain::new();
    let r = chain.run_one(
        &submitter(),
        gov_payload(
            0,
            BridgeGovAction::SetInboundSigners {
                origin_domain: SEPOLIA,
                validators: vec![[1; 20]],
                threshold: 1,
            },
            &[1, 2],
        ),
    );
    assert_eq!(
        failure(&r),
        "SetInboundSigners is not active until bridge phase 4"
    );
    assert_eq!(
        chain.read(&StateKey::bridge_gov_nonce()),
        None,
        "a refused action does not consume the governance nonce"
    );
}

#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use solidus_bridge_codec::BridgeMessage;
use solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
use solidus_txns::bridge::{BridgeDomainVm, BridgeGovAction};
use solidus_txns::types::Event;

#[test]
fn the_registration_block_queues_the_first_heartbeat_with_the_parent_root() {
    let mut chain = Chain::new();
    let ts = chain.ts_ms / 1000;
    let tx = chain.tx(
        &submitter(),
        gov_payload(
            0,
            register_action(SEPOLIA, BridgeDomainVm::Evm, mirror32()),
            &[1, 2],
        ),
    );
    let out = chain.run(vec![tx]);
    assert!(out.block_events.iter().any(|e| matches!(
        e,
        Event::BridgeMessageQueued {
            domain: SEPOLIA,
            kind: 3,
            ..
        }
    )));
    let BridgeMessage::Heartbeat { body, .. } = outbox(&chain, SEPOLIA, last_seq(&chain, SEPOLIA))
    else {
        panic!("not a heartbeat")
    };
    assert_eq!(body.solidus_timestamp, ts);
    assert_eq!(body.global_root, [0x77; 32]);
}

#[test]
fn the_next_heartbeat_waits_for_the_interval() {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let after_register = last_seq(&chain, SEPOLIA);
    // The registration block ran at T and left the chain at T+1. After 598 more
    // seconds the next two blocks run at T+599 and T+600.
    chain.advance_secs(598);
    chain.run(vec![]);
    assert_eq!(
        last_seq(&chain, SEPOLIA),
        after_register,
        "599 s is not 600 s"
    );
    chain.run(vec![]);
    assert_eq!(
        last_seq(&chain, SEPOLIA),
        after_register + 1,
        "600 s is the interval"
    );
}

#[test]
fn a_disabled_domain_gets_no_heartbeat() {
    let mut chain = Chain::new();
    let action = BridgeGovAction::RegisterDomain {
        domain: SEPOLIA,
        vm: BridgeDomainVm::Evm,
        inbox: mirror32(),
        heartbeat_interval_secs: 600,
        enabled: false,
    };
    let r = chain.run_one(&submitter(), gov_payload(0, action, &[1, 2]));
    assert!(succeeded(&r), "{}", failure(&r));
    assert_eq!(last_seq(&chain, SEPOLIA), 0);
}

#[test]
fn no_block_events_before_v2() {
    let mut chain = Chain::at_height(V2_ACTIVATION_HEIGHT - 3);
    assert!(chain.run(vec![]).block_events.is_empty());
}

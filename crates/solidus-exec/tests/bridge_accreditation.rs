#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use solidus_bridge_codec::{issuer_did_hash, BridgeMessage};
use solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
use solidus_exec::StateKey;
use solidus_txns::bridge::BridgeGovAction;
use solidus_txns::credential::CredentialType;
use solidus_txns::types::{Event, TxPayload};

fn accredit(chain: &mut Chain, root: &Issuer, org: &Issuer) -> solidus_txns::types::Receipt {
    let hash = [(chain.height % 251) as u8; 32];
    chain.run_one(
        &root.key,
        TxPayload::CredentialIssue {
            subject_did: org.did.clone(),
            credential_type: CredentialType::AccreditedIssuer,
            hash,
        },
    )
}

fn world() -> (Chain, Issuer, Issuer) {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let root = issuer(&mut chain, 0x41);
    let org = issuer(&mut chain, 0x42);
    let r = chain.run_one(
        &submitter(),
        gov_payload(
            1,
            BridgeGovAction::SetTrustRoot {
                did: root.did.clone(),
                enabled: true,
            },
            &[1, 2],
        ),
    );
    assert!(succeeded(&r), "{}", failure(&r));
    (chain, root, org)
}

#[test]
fn a_trust_root_accredits_an_issuer_and_every_domain_hears_it() {
    let (mut chain, root, org) = world();
    let before = last_seq(&chain, SEPOLIA);
    let r = accredit(&mut chain, &root, &org);
    assert!(succeeded(&r), "{}", failure(&r));
    assert_eq!(
        chain.read(&StateKey::bridge_accredited(&org.did)),
        Some(vec![1])
    );
    let BridgeMessage::IssuerStatus { body, .. } = outbox(&chain, SEPOLIA, before + 1) else {
        panic!("not an issuer status")
    };
    assert_eq!(body.issuer_did_hash, issuer_did_hash(&org.did));
    assert!(body.accredited);
}

#[test]
fn a_non_root_cannot_accredit() {
    let (mut chain, _root, org) = world();
    let stranger = issuer(&mut chain, 0x43);
    assert_eq!(
        failure(&accredit(&mut chain, &stranger, &org)),
        "issuer is not a bridge trust root"
    );
}

#[test]
fn accreditation_must_name_its_subject() {
    let (mut chain, root, _org) = world();
    let r = chain.run_one(
        &root.key,
        TxPayload::CredentialIssueV2 {
            subject_commitment: [9; 32],
            credential_type: CredentialType::AccreditedIssuer,
            hash: [8; 32],
        },
    );
    assert_eq!(
        failure(&r),
        "AccreditedIssuer must name its subject: use CredentialIssue"
    );
}

#[test]
fn exports_carry_the_issuers_current_accreditation() {
    let (mut chain, root, org) = world();
    assert!(succeeded(&accredit(&mut chain, &root, &org)));
    let credential = issue(&mut chain, &org, CredentialType::KycL2);
    let (key, holder) = evm_holder();
    let exp = chain.ts_ms / 1000 + 3_600;
    let sig = evm_consent(&key, &credential, SEPOLIA, holder, exp);
    assert!(succeeded(&chain.run_one(
        &org.key,
        export_payload(&credential, SEPOLIA, holder, sig, exp)
    )));
    let BridgeMessage::CredentialStatus { body, .. } =
        outbox(&chain, SEPOLIA, last_seq(&chain, SEPOLIA))
    else {
        panic!()
    };
    assert!(body.issuer_accredited);
}

#[test]
fn revoking_an_accreditation_broadcasts_it() {
    let (mut chain, root, org) = world();
    let r = accredit(&mut chain, &root, &org);
    let id = r
        .events
        .iter()
        .find_map(|e| match e {
            Event::CredentialIssued { credential_id, .. } => Some(credential_id.clone()),
            _ => None,
        })
        .unwrap();
    let before = last_seq(&chain, SEPOLIA);
    assert!(succeeded(&chain.run_one(
        &root.key,
        TxPayload::CredentialRevoke { credential_id: id }
    )));
    assert_eq!(
        chain.read(&StateKey::bridge_accredited(&org.did)),
        Some(vec![0])
    );
    let BridgeMessage::IssuerStatus { body, .. } = outbox(&chain, SEPOLIA, before + 1) else {
        panic!()
    };
    assert!(!body.accredited);
}

#[test]
fn accreditation_is_refused_before_v2() {
    let mut chain = Chain::at_height(V2_ACTIVATION_HEIGHT - 4);
    let root = issuer(&mut chain, 0x44);
    let org = issuer(&mut chain, 0x45);
    assert!(chain.height < V2_ACTIVATION_HEIGHT);
    assert_eq!(
        failure(&accredit(&mut chain, &root, &org)),
        "AccreditedIssuer is not active at this height"
    );
}

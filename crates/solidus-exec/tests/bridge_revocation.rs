#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use solidus_bridge_codec::{BridgeMessage, ExportStatus};
use solidus_exec::protocol::V2_ACTIVATION_HEIGHT;
use solidus_exec::StateKey;
use solidus_txns::bridge::{ExportSet, EXPORT_STATUS_REVOKED, EXPORT_STATUS_UNBOUND};
use solidus_txns::credential::{CredentialRecord, CredentialType};
use solidus_txns::types::{Event, TxPayload};

const FUJI: u32 = 43_113;

fn export_to(chain: &mut Chain, issuer: &Issuer, credential: &str, domain: u32) {
    let (key, holder) = evm_holder();
    let exp = chain.ts_ms / 1000 + 3_600;
    let sig = evm_consent(&key, credential, domain, holder, exp);
    let r = chain.run_one(
        &issuer.key,
        export_payload(credential, domain, holder, sig, exp),
    );
    assert!(succeeded(&r), "{}", failure(&r));
}

#[test]
fn revoking_an_exported_credential_reaches_every_active_export_in_the_same_block() {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    register_evm_domain(&mut chain, FUJI, 1);
    let issuer = issuer(&mut chain, 0x31);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    export_to(&mut chain, &issuer, &credential, SEPOLIA);
    export_to(&mut chain, &issuer, &credential, FUJI);
    let (s_before, f_before) = (last_seq(&chain, SEPOLIA), last_seq(&chain, FUJI));

    let r = chain.run_one(
        &issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: credential.clone(),
        },
    );
    assert!(succeeded(&r), "{}", failure(&r));
    assert_eq!(
        r.events
            .iter()
            .filter(|e| matches!(e, Event::BridgeMessageQueued { .. }))
            .count(),
        2
    );
    for (domain, before) in [(SEPOLIA, s_before), (FUJI, f_before)] {
        assert_eq!(last_seq(&chain, domain), before + 1);
        let BridgeMessage::CredentialStatus { body, .. } = outbox(&chain, domain, before + 1)
        else {
            panic!()
        };
        assert_eq!(body.status, ExportStatus::Revoked);
    }
    let set: ExportSet =
        bincode::deserialize(&chain.read(&StateKey::bridge_exports(&credential)).unwrap()).unwrap();
    assert!(set
        .entries
        .iter()
        .all(|e| e.status == EXPORT_STATUS_REVOKED));
}

#[test]
fn an_unbound_export_hears_nothing_when_the_credential_is_revoked() {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let issuer = issuer(&mut chain, 0x32);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    export_to(&mut chain, &issuer, &credential, SEPOLIA);
    let (_, holder) = evm_holder();
    let un = chain.run_one(
        &issuer.key,
        TxPayload::UnexportCredential {
            credential_id: credential.clone(),
            domain: SEPOLIA,
            holder,
        },
    );
    assert!(succeeded(&un), "{}", failure(&un));
    let before = last_seq(&chain, SEPOLIA);
    let r = chain.run_one(
        &issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: credential.clone(),
        },
    );
    assert!(succeeded(&r), "{}", failure(&r));
    assert_eq!(last_seq(&chain, SEPOLIA), before);
    let set: ExportSet =
        bincode::deserialize(&chain.read(&StateKey::bridge_exports(&credential)).unwrap()).unwrap();
    assert_eq!(set.entries[0].status, EXPORT_STATUS_UNBOUND);
}

#[test]
fn revocation_before_v2_is_unchanged() {
    let mut chain = Chain::at_height(V2_ACTIVATION_HEIGHT - 5);
    let issuer = issuer(&mut chain, 0x33);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    let r = chain.run_one(
        &issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: credential.clone(),
        },
    );
    assert!(
        chain.height <= V2_ACTIVATION_HEIGHT,
        "the revoke ran below activation"
    );
    assert!(succeeded(&r), "{}", failure(&r));
    assert_eq!(
        r.events,
        vec![Event::CredentialRevoked {
            credential_id: credential.clone()
        }]
    );
    assert_eq!(chain.read(&StateKey::bridge_exports(&credential)), None);
}

#[test]
fn revoking_an_accredited_issuer_credential_before_v2_writes_no_bridge_state() {
    // ⚠ The KycL2 test above cannot see the V2 gate on the fan-out: before V2 no
    // export or domain exists, so an ungated fan-out does nothing there. An
    // AccreditedIssuer revoke is the path that writes bridge state (the
    // accreditation flag) with no export behind it.
    //
    // ⚠ No transaction can create that credential below V2 (Task 11 refuses it
    // through every issue path), so the record is written straight into state.
    // This guards the gate for the day those issue rules are loosened.
    let mut chain = Chain::at_height(V2_ACTIVATION_HEIGHT - 5);
    let issuer = issuer(&mut chain, 0x34);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    let key = StateKey::credential(&credential);
    let mut record = CredentialRecord::from_bytes(&chain.read(&key).unwrap()).unwrap();
    record.credential_type = CredentialType::AccreditedIssuer;
    record.subject_did = "did:solidus:testnet:org".into();
    chain.state.set(key, record.to_bytes());

    let tx = chain.tx(
        &issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: credential.clone(),
        },
    );
    let outcome = chain.run(vec![tx]);
    assert!(
        chain.height <= V2_ACTIVATION_HEIGHT,
        "the revoke ran below activation"
    );
    let r = &outcome.receipts[0];
    assert!(succeeded(r), "{}", failure(r));
    assert_eq!(
        r.events,
        vec![Event::CredentialRevoked {
            credential_id: credential
        }]
    );
    let bridge_writes: Vec<String> = outcome
        .delta
        .iter()
        .filter(|(k, _)| k.key.starts_with(b"bridge:"))
        .map(|(k, _)| String::from_utf8_lossy(&k.key).into_owned())
        .collect();
    assert!(
        bridge_writes.is_empty(),
        "no bridge state before V2, wrote {bridge_writes:?}"
    );
}

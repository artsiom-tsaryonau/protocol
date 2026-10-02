#![cfg(feature = "test-activation-schedule")]

mod bridge_common;

use bridge_common::*;
use solidus_bridge_codec::{
    credential_type_hash, export_id, issuer_did_hash, BridgeMessage, ExportStatus,
};
use solidus_exec::StateKey;
use solidus_txns::bridge::{ExportSet, EXPORT_STATUS_ACTIVE};
use solidus_txns::credential::CredentialType;
use solidus_txns::types::{Event, TxPayload};

struct Setup {
    chain: Chain,
    issuer: Issuer,
    credential: String,
    holder: [u8; 32],
    holder_key: k256::ecdsa::SigningKey,
}

fn setup() -> Setup {
    let mut chain = Chain::new();
    register_evm_domain(&mut chain, SEPOLIA, 0);
    let issuer = issuer(&mut chain, 0x21);
    let credential = issue(&mut chain, &issuer, CredentialType::KycL2);
    let (holder_key, holder) = evm_holder();
    Setup {
        chain,
        issuer,
        credential,
        holder,
        holder_key,
    }
}

fn expiry(chain: &Chain) -> u64 {
    chain.ts_ms / 1000 + 3_600
}

#[test]
fn an_export_queues_an_active_status_for_the_consenting_holder() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert!(succeeded(&r), "{}", failure(&r));
    let id = export_id(&s.credential, SEPOLIA, &s.holder);
    assert!(r.events.contains(&Event::CredentialExported {
        credential_id: s.credential.clone(),
        domain: SEPOLIA,
        export_id: id
    }));
    assert_eq!(r.fee_paid, 0);

    let BridgeMessage::CredentialStatus { header, body } =
        outbox(&s.chain, SEPOLIA, last_seq(&s.chain, SEPOLIA))
    else {
        panic!("not a credential status")
    };
    assert_eq!(header.solidus_height, s.chain.height - 1);
    assert_eq!(body.export_id, id);
    assert_eq!(body.issuer_did_hash, issuer_did_hash(&s.issuer.did));
    assert_eq!(body.credential_type_hash, credential_type_hash("KycL2"));
    assert_eq!(body.holder, s.holder);
    assert_eq!(body.status, ExportStatus::Active);
    assert_eq!(body.valid_until, 0);
    assert!(
        !body.issuer_accredited,
        "no AccreditedIssuer credential exists yet"
    );

    let set: ExportSet = bincode::deserialize(
        &s.chain
            .read(&StateKey::bridge_exports(&s.credential))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(set.entries.len(), 1);
    assert_eq!(set.entries[0].status, EXPORT_STATUS_ACTIVE);
}

#[test]
fn only_the_issuer_can_export() {
    let mut s = setup();
    let other = issuer(&mut s.chain, 0x22);
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &other.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert_eq!(failure(&r), "sender is not the credential's issuer");
}

#[test]
fn an_unknown_credential_is_refused() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(
        &s.holder_key,
        "urn:solidus:credential:missing",
        SEPOLIA,
        s.holder,
        exp,
    );
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(
            "urn:solidus:credential:missing",
            SEPOLIA,
            s.holder,
            sig,
            exp,
        ),
    );
    assert_eq!(failure(&r), "unknown credential");
}

#[test]
fn a_revoked_credential_cannot_be_exported() {
    let mut s = setup();
    let revoke = s.chain.run_one(
        &s.issuer.key,
        TxPayload::CredentialRevoke {
            credential_id: s.credential.clone(),
        },
    );
    assert!(succeeded(&revoke), "{}", failure(&revoke));
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert_eq!(failure(&r), "credential is revoked");
}

#[test]
fn an_unregistered_domain_is_refused() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, 43_113, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, 43_113, s.holder, sig, exp),
    );
    assert_eq!(failure(&r), "unknown or disabled bridge domain");
}

#[test]
fn an_expired_consent_is_refused() {
    let mut s = setup();
    let exp = s.chain.ts_ms / 1000;
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert_eq!(failure(&r), "consent has expired");
}

#[test]
fn a_past_valid_until_is_refused() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let payload = TxPayload::ExportCredential {
        credential_id: s.credential.clone(),
        domain: SEPOLIA,
        holder: s.holder,
        valid_until: 1,
        consent_sig: sig,
        consent_expiry: exp,
    };
    let r = s.chain.run_one(&s.issuer.key, payload);
    assert_eq!(failure(&r), "valid_until is in the past");
}

#[test]
fn a_consent_from_another_address_is_refused() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let wrong = k256::ecdsa::SigningKey::from_slice(
        &hex::decode("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a").unwrap(),
    )
    .unwrap();
    let sig = evm_consent(&wrong, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert_eq!(failure(&r), "consent signed by a different address");
}

#[test]
fn a_duplicate_export_is_refused() {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let first = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig.clone(), exp),
    );
    assert!(succeeded(&first), "{}", failure(&first));
    let second = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert_eq!(
        failure(&second),
        "credential is already exported to this holder on this domain"
    );
}

use solidus_txns::bridge::EXPORT_STATUS_UNBOUND;

fn exported() -> Setup {
    let mut s = setup();
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert!(succeeded(&r), "{}", failure(&r));
    s
}

fn unexport(s: &Setup) -> TxPayload {
    TxPayload::UnexportCredential {
        credential_id: s.credential.clone(),
        domain: SEPOLIA,
        holder: s.holder,
    }
}

#[test]
fn an_unexport_queues_unbound_and_marks_the_entry() {
    let mut s = exported();
    let before = last_seq(&s.chain, SEPOLIA);
    let payload = unexport(&s);
    let r = s.chain.run_one(&s.issuer.key, payload);
    assert!(succeeded(&r), "{}", failure(&r));
    assert!(r.events.iter().any(|e| matches!(
        e,
        Event::CredentialUnexported {
            domain: SEPOLIA,
            ..
        }
    )));
    assert_eq!(last_seq(&s.chain, SEPOLIA), before + 1);
    let BridgeMessage::CredentialStatus { body, .. } = outbox(&s.chain, SEPOLIA, before + 1) else {
        panic!()
    };
    assert_eq!(body.status, ExportStatus::Unbound);
    let set: ExportSet = bincode::deserialize(
        &s.chain
            .read(&StateKey::bridge_exports(&s.credential))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(set.entries[0].status, EXPORT_STATUS_UNBOUND);
}

#[test]
fn a_second_unexport_is_refused() {
    let mut s = exported();
    let p = unexport(&s);
    assert!(succeeded(&s.chain.run_one(&s.issuer.key, p)));
    let p = unexport(&s);
    assert_eq!(
        failure(&s.chain.run_one(&s.issuer.key, p)),
        "export is not active"
    );
}

#[test]
fn unexporting_something_never_exported_is_refused() {
    let mut s = setup();
    let p = unexport(&s);
    assert_eq!(
        failure(&s.chain.run_one(&s.issuer.key, p)),
        "no such export"
    );
}

#[test]
fn only_the_issuer_can_unexport() {
    let mut s = exported();
    let other = issuer(&mut s.chain, 0x23);
    let p = unexport(&s);
    assert_eq!(
        failure(&s.chain.run_one(&other.key, p)),
        "sender is not the credential's issuer"
    );
}

#[test]
fn an_unbound_export_can_be_exported_again() {
    let mut s = exported();
    let p = unexport(&s);
    assert!(succeeded(&s.chain.run_one(&s.issuer.key, p)));
    let exp = expiry(&s.chain);
    let sig = evm_consent(&s.holder_key, &s.credential, SEPOLIA, s.holder, exp);
    let r = s.chain.run_one(
        &s.issuer.key,
        export_payload(&s.credential, SEPOLIA, s.holder, sig, exp),
    );
    assert!(succeeded(&r), "{}", failure(&r));
    let BridgeMessage::CredentialStatus { body, .. } =
        outbox(&s.chain, SEPOLIA, last_seq(&s.chain, SEPOLIA))
    else {
        panic!()
    };
    assert_eq!(body.status, ExportStatus::Active);
}

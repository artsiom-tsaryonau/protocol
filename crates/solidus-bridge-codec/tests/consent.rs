use solidus_bridge_codec::{
    ed25519_consent_bytes, eip712_consent_digest, keccak256, ExportConsent, ED25519_CONSENT_PREFIX,
    EIP712_CONSENT_TYPE,
};

fn consent() -> ExportConsent {
    let mut holder = [0u8; 32];
    holder[12..].copy_from_slice(&hex::decode("70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap());
    ExportConsent {
        credential_id: "urn:solidus:credential:00ff".into(),
        domain: 11_155_111,
        holder,
        consent_expiry: 1_900_000_000,
    }
}

fn mirror() -> [u8; 20] {
    hex::decode("5fbdb2315678afecb367f032d93f642f64180aa3")
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn the_type_string_is_exactly_the_registry_value() {
    assert_eq!(
        EIP712_CONSENT_TYPE,
        "ExportConsent(string credentialId,uint32 domain,bytes32 holder,uint64 consentExpiry)"
    );
}

#[test]
fn every_field_chain_and_contract_changes_the_digest() {
    let base = eip712_consent_digest(&consent(), 11_155_111, &mirror());
    let mut c = consent();
    c.credential_id.push('0');
    assert_ne!(eip712_consent_digest(&c, 11_155_111, &mirror()), base);
    let mut c = consent();
    c.domain = 43_113;
    assert_ne!(eip712_consent_digest(&c, 11_155_111, &mirror()), base);
    let mut c = consent();
    c.holder[31] ^= 1;
    assert_ne!(eip712_consent_digest(&c, 11_155_111, &mirror()), base);
    let mut c = consent();
    c.consent_expiry += 1;
    assert_ne!(eip712_consent_digest(&c, 11_155_111, &mirror()), base);
    assert_ne!(
        eip712_consent_digest(&consent(), 43_113, &mirror()),
        base,
        "replay to another chain must fail"
    );
    let mut other = mirror();
    other[0] ^= 1;
    assert_ne!(
        eip712_consent_digest(&consent(), 11_155_111, &other),
        base,
        "replay to another contract must fail"
    );
}

#[test]
fn ed25519_consent_bytes_follow_the_registry_layout() {
    let program = [0x07u8; 32];
    let b = ed25519_consent_bytes(&consent(), &program);
    let p = ED25519_CONSENT_PREFIX.len();
    assert_eq!(&b[..p], b"SOLIDUS_BRIDGE_CONSENT_V1");
    assert_eq!(&b[p..p + 4], &11_155_111u32.to_be_bytes());
    assert_eq!(&b[p + 4..p + 36], &program);
    assert_eq!(
        &b[p + 36..p + 68],
        &keccak256(b"urn:solidus:credential:00ff")
    );
    assert_eq!(&b[p + 68..p + 100], &consent().holder);
    assert_eq!(&b[p + 100..], &1_900_000_000u64.to_be_bytes());
}

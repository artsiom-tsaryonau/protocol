use serde::{Deserialize, Serialize};
use solidus_crypto::hash::blake3_hash;
use thiserror::Error;

mod serde_bytes_96_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 96]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 96]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Option::deserialize(deserializer)?;
        match opt {
            None => Ok(None),
            Some(v) => v
                .try_into()
                .map(Some)
                .map_err(|v: Vec<u8>| serde::de::Error::invalid_length(v.len(), &"96 bytes")),
        }
    }
}

// ---------------------------------------------------------------------------
// CredentialType
// ---------------------------------------------------------------------------

/// The type of a verifiable credential issued on-chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Email,
    Phone,
    KycL1,
    KycL2,
    KycL3,
    Age,
    Reputation,
}

impl CredentialType {
    /// Return the issuance fee for this credential type (in smallest units).
    /// 1 SOLID = 100_000_000 (10^8).
    pub fn issue_fee(&self) -> u64 {
        match self {
            CredentialType::Email      => 1_000_000,       // 0.01 SOLID
            CredentialType::Phone      => 2_000_000,       // 0.02 SOLID
            CredentialType::KycL1      => 100_000_000,     // 1.0 SOLID
            CredentialType::KycL2      => 500_000_000,     // 5.0 SOLID
            CredentialType::KycL3      => 2_000_000_000,   // 20.0 SOLID
            CredentialType::Age        => 5_000_000,       // 0.05 SOLID
            CredentialType::Reputation => 1_000_000,       // 0.01 SOLID
        }
    }

    /// Return the issuance fee for a BBS+ credential of this type (in smallest units).
    /// 1.25× the base fee — BBS records are larger and require pairing-based verification.
    pub fn issue_fee_bbs(&self) -> u64 {
        self.issue_fee() * 5 / 4
    }
}

/// Maximum number of messages that can be signed in a single BBS+ credential.
/// Caps the on-chain record size and proof complexity. Aligned with the
/// initial Solidus KYC schema (8 fields). Increase via consensus-level
/// upgrade if larger schemas are needed.
pub const BBS_MAX_MESSAGE_COUNT: u32 = 64;

// ---------------------------------------------------------------------------
// CredentialRecord
// ---------------------------------------------------------------------------

/// A credential record persisted in the credential registry column family.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialRecord {
    /// Unique credential identifier: `urn:solidus:credential:<hex>`.
    pub id: String,
    /// DID of the entity that issued this credential.
    pub issuer_did: String,
    /// DID of the entity the credential was issued to.
    pub subject_did: String,
    /// The type of credential.
    pub credential_type: CredentialType,
    /// BLAKE3 hash of the off-chain credential payload.
    pub hash: [u8; 32],
    /// Unix timestamp (milliseconds) when the credential was issued.
    pub issued_ms: u64,
    /// Whether this credential has been revoked.
    pub revoked: bool,
    /// Unix timestamp (milliseconds) when the credential was revoked, if applicable.
    pub revoked_ms: Option<u64>,
    /// BBS+ public key the issuer used to sign this credential's message vector.
    /// `None` for traditional credentials whose payload is just an opaque hash.
    /// 96 bytes = compressed BLS12-381 G2 point.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "serde_bytes_96_opt"
    )]
    pub bbs_pubkey: Option<[u8; 96]>,
    /// Number of BBS+ messages signed (the `total_message_count` a verifier
    /// must supply when checking a selective-disclosure proof).
    /// `None` when `bbs_pubkey` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bbs_message_count: Option<u32>,
}

impl CredentialRecord {
    /// Serialize this record to JSON bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("CredentialRecord serialization cannot fail")
    }

    /// Deserialize a record from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ---------------------------------------------------------------------------
// CredentialError
// ---------------------------------------------------------------------------

/// Errors produced by credential registry operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CredentialError {
    #[error("issuer DID not found or inactive")]
    IssuerDidInvalid,

    #[error("subject DID not found or inactive")]
    SubjectDidInvalid,

    #[error("credential not found: {0}")]
    NotFound(String),

    #[error("credential already revoked: {0}")]
    AlreadyRevoked(String),

    #[error("sender is not the issuer of this credential")]
    NotIssuer,

    #[error("BBS+ public key is malformed (not a valid compressed BLS12-381 G2 point)")]
    InvalidBbsKey,

    #[error("BBS+ message count {count} exceeds the maximum allowed ({max})")]
    BbsMessageCountTooLarge { count: u32, max: u32 },

    #[error("BBS+ message count must be at least 1")]
    BbsMessageCountZero,
}

// ---------------------------------------------------------------------------
// ID builder
// ---------------------------------------------------------------------------

/// Build a deterministic credential ID from issuer, subject, hash, and block height.
///
/// Format: `urn:solidus:credential:<BLAKE3(issuer || subject || hash || height_le)>`
pub fn build_credential_id(
    issuer_did: &str,
    subject_did: &str,
    hash: &[u8; 32],
    height: u64,
) -> String {
    let mut input = Vec::with_capacity(
        issuer_did.len() + subject_did.len() + 32 + 8,
    );
    input.extend_from_slice(issuer_did.as_bytes());
    input.extend_from_slice(subject_did.as_bytes());
    input.extend_from_slice(hash);
    input.extend_from_slice(&height.to_le_bytes());
    let id_hash = blake3_hash(&input);
    format!("urn:solidus:credential:{}", hex::encode(id_hash))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Execute a `CredentialIssue` operation.
///
/// Returns a new [`CredentialRecord`] on success, or a [`CredentialError`] if
/// either DID is inactive.
pub fn execute_credential_issue(
    issuer_did: &str,
    subject_did: &str,
    credential_type: CredentialType,
    hash: [u8; 32],
    issuer_did_active: bool,
    subject_did_active: bool,
    block_height: u64,
    timestamp_ms: u64,
) -> Result<CredentialRecord, CredentialError> {
    if !issuer_did_active {
        return Err(CredentialError::IssuerDidInvalid);
    }
    if !subject_did_active {
        return Err(CredentialError::SubjectDidInvalid);
    }

    let id = build_credential_id(issuer_did, subject_did, &hash, block_height);
    Ok(CredentialRecord {
        id,
        issuer_did: issuer_did.to_string(),
        subject_did: subject_did.to_string(),
        credential_type,
        hash,
        issued_ms: timestamp_ms,
        revoked: false,
        revoked_ms: None,
        bbs_pubkey: None,
        bbs_message_count: None,
    })
}

/// Execute a `CredentialIssueBbs` operation — issue a BBS+ credential.
///
/// The `bbs_pubkey` is the compressed BLS12-381 G2 point (96 bytes) the issuer
/// used to sign the off-chain message vector. The `bbs_message_count` is the
/// number of messages signed; verifiers need this to check selective-disclosure
/// proofs.
///
/// Validates:
/// - both DIDs are active
/// - `bbs_pubkey` is a valid compressed G2 point (deserializes via [`solidus_crypto::bbs::BbsPublicKey`])
/// - `bbs_message_count` is in `[1, BBS_MAX_MESSAGE_COUNT]`
///
/// The on-chain record commits to the issuer's BBS pubkey + the off-chain
/// payload hash; verifying actual proofs is done via RPC, not on-chain.
pub fn execute_credential_issue_bbs(
    issuer_did: &str,
    subject_did: &str,
    credential_type: CredentialType,
    hash: [u8; 32],
    bbs_pubkey: [u8; 96],
    bbs_message_count: u32,
    issuer_did_active: bool,
    subject_did_active: bool,
    block_height: u64,
    timestamp_ms: u64,
) -> Result<CredentialRecord, CredentialError> {
    if !issuer_did_active {
        return Err(CredentialError::IssuerDidInvalid);
    }
    if !subject_did_active {
        return Err(CredentialError::SubjectDidInvalid);
    }
    if bbs_message_count == 0 {
        return Err(CredentialError::BbsMessageCountZero);
    }
    if bbs_message_count > BBS_MAX_MESSAGE_COUNT {
        return Err(CredentialError::BbsMessageCountTooLarge {
            count: bbs_message_count,
            max: BBS_MAX_MESSAGE_COUNT,
        });
    }
    solidus_crypto::bbs::BbsPublicKey::from_bytes(&bbs_pubkey)
        .map_err(|_| CredentialError::InvalidBbsKey)?;

    let id = build_credential_id(issuer_did, subject_did, &hash, block_height);
    Ok(CredentialRecord {
        id,
        issuer_did: issuer_did.to_string(),
        subject_did: subject_did.to_string(),
        credential_type,
        hash,
        issued_ms: timestamp_ms,
        revoked: false,
        revoked_ms: None,
        bbs_pubkey: Some(bbs_pubkey),
        bbs_message_count: Some(bbs_message_count),
    })
}

/// Execute a `CredentialRevoke` operation.
///
/// Returns a cloned, updated [`CredentialRecord`] with `revoked = true` on success.
pub fn execute_credential_revoke(
    sender_did: &str,
    credential: Option<&CredentialRecord>,
    timestamp_ms: u64,
) -> Result<CredentialRecord, CredentialError> {
    let cred = credential
        .ok_or_else(|| CredentialError::NotFound("unknown".to_string()))?;

    if cred.revoked {
        return Err(CredentialError::AlreadyRevoked(cred.id.clone()));
    }
    if cred.issuer_did != sender_did {
        return Err(CredentialError::NotIssuer);
    }

    let mut revoked = cred.clone();
    revoked.revoked = true;
    revoked.revoked_ms = Some(timestamp_ms);
    Ok(revoked)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sample_hash() -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 0xde;
        h[1] = 0xad;
        h[2] = 0xbe;
        h[3] = 0xef;
        h
    }

    fn sample_record() -> CredentialRecord {
        CredentialRecord {
            id: "urn:solidus:credential:aabbcc".to_string(),
            issuer_did: "did:solidus:testnet:issuer".to_string(),
            subject_did: "did:solidus:testnet:subject".to_string(),
            credential_type: CredentialType::KycL1,
            hash: sample_hash(),
            issued_ms: 1_000_000,
            revoked: false,
            revoked_ms: None,
            bbs_pubkey: None,
            bbs_message_count: None,
        }
    }

    /// Helper: produce a valid BBS+ pubkey (96 bytes) for tests.
    fn sample_bbs_pubkey() -> [u8; 96] {
        use solidus_crypto::bbs::BbsSecretKey;
        let sk = BbsSecretKey::from_ikm(b"solidus-credential-test-ikm-32-bytes-or-more").expect("ikm");
        sk.public_key().to_bytes()
    }

    // -----------------------------------------------------------------------
    // build_credential_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_credential_id_format() {
        let issuer  = "did:solidus:testnet:issuer";
        let subject = "did:solidus:testnet:subject";
        let hash    = sample_hash();
        let id = build_credential_id(issuer, subject, &hash, 42);
        assert!(
            id.starts_with("urn:solidus:credential:"),
            "expected URN prefix, got: {id}"
        );
    }

    #[test]
    fn build_credential_id_deterministic() {
        let issuer  = "did:solidus:testnet:issuer";
        let subject = "did:solidus:testnet:subject";
        let hash    = sample_hash();
        let id1 = build_credential_id(issuer, subject, &hash, 42);
        let id2 = build_credential_id(issuer, subject, &hash, 42);
        assert_eq!(id1, id2);
    }

    #[test]
    fn build_credential_id_differs_by_input() {
        let issuer   = "did:solidus:testnet:issuer";
        let subject1 = "did:solidus:testnet:subject_a";
        let subject2 = "did:solidus:testnet:subject_b";
        let hash = sample_hash();
        let id1 = build_credential_id(issuer, subject1, &hash, 42);
        let id2 = build_credential_id(issuer, subject2, &hash, 42);
        assert_ne!(id1, id2, "different subjects must produce different IDs");
    }

    // -----------------------------------------------------------------------
    // CredentialType fee tests
    // -----------------------------------------------------------------------

    #[test]
    fn credential_type_fees() {
        assert_eq!(CredentialType::Email.issue_fee(),      1_000_000);
        assert_eq!(CredentialType::Phone.issue_fee(),      2_000_000);
        assert_eq!(CredentialType::KycL1.issue_fee(),    100_000_000);
        assert_eq!(CredentialType::KycL2.issue_fee(),    500_000_000);
        assert_eq!(CredentialType::KycL3.issue_fee(),  2_000_000_000);
        assert_eq!(CredentialType::Age.issue_fee(),        5_000_000);
        assert_eq!(CredentialType::Reputation.issue_fee(), 1_000_000);
    }

    // -----------------------------------------------------------------------
    // execute_credential_issue tests
    // -----------------------------------------------------------------------

    #[test]
    fn issue_credential_success() {
        let result = execute_credential_issue(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            true,
            true,
            100,
            1_700_000_000_000,
        );
        let record = result.expect("expected success");
        assert!(record.id.starts_with("urn:solidus:credential:"));
        assert_eq!(record.issuer_did, "did:solidus:testnet:issuer");
        assert_eq!(record.subject_did, "did:solidus:testnet:subject");
        assert_eq!(record.credential_type, CredentialType::Email);
        assert_eq!(record.hash, sample_hash());
        assert_eq!(record.issued_ms, 1_700_000_000_000);
        assert!(!record.revoked);
        assert!(record.revoked_ms.is_none());
    }

    #[test]
    fn issue_credential_issuer_did_inactive() {
        let err = execute_credential_issue(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            false, // issuer inactive
            true,
            100,
            1_000,
        )
        .expect_err("expected IssuerDidInvalid");
        assert_eq!(err, CredentialError::IssuerDidInvalid);
    }

    #[test]
    fn issue_credential_subject_did_inactive() {
        let err = execute_credential_issue(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Phone,
            sample_hash(),
            true,
            false, // subject inactive
            100,
            1_000,
        )
        .expect_err("expected SubjectDidInvalid");
        assert_eq!(err, CredentialError::SubjectDidInvalid);
    }

    // -----------------------------------------------------------------------
    // execute_credential_revoke tests
    // -----------------------------------------------------------------------

    #[test]
    fn revoke_credential_success() {
        let record = sample_record();
        let result = execute_credential_revoke(
            "did:solidus:testnet:issuer",
            Some(&record),
            2_000_000,
        );
        let updated = result.expect("expected success");
        assert!(updated.revoked);
        assert_eq!(updated.revoked_ms, Some(2_000_000));
        assert_eq!(updated.id, record.id);
    }

    #[test]
    fn revoke_credential_already_revoked() {
        let mut record = sample_record();
        record.revoked = true;
        record.revoked_ms = Some(1_500_000);

        let err = execute_credential_revoke(
            "did:solidus:testnet:issuer",
            Some(&record),
            2_000_000,
        )
        .expect_err("expected AlreadyRevoked");
        assert_eq!(err, CredentialError::AlreadyRevoked(record.id));
    }

    #[test]
    fn revoke_credential_not_issuer() {
        let record = sample_record();
        let err = execute_credential_revoke(
            "did:solidus:testnet:other_party", // not the issuer
            Some(&record),
            2_000_000,
        )
        .expect_err("expected NotIssuer");
        assert_eq!(err, CredentialError::NotIssuer);
    }

    #[test]
    fn revoke_credential_not_found() {
        let err = execute_credential_revoke(
            "did:solidus:testnet:issuer",
            None,
            2_000_000,
        )
        .expect_err("expected NotFound");
        assert!(matches!(err, CredentialError::NotFound(_)));
    }

    // -----------------------------------------------------------------------
    // CredentialRecord serialization roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn credential_record_roundtrip() {
        let original = sample_record();
        let bytes = original.to_bytes();
        let decoded = CredentialRecord::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn legacy_credential_record_deserializes_without_bbs_fields() {
        // Old records (pre-BBS fields) must still deserialize cleanly.
        let legacy_json = serde_json::json!({
            "id": "urn:solidus:credential:legacy",
            "issuer_did": "did:solidus:testnet:issuer",
            "subject_did": "did:solidus:testnet:subject",
            "credential_type": "KycL1",
            "hash": [0xde, 0xad, 0xbe, 0xef, 0,0,0,0, 0,0,0,0, 0,0,0,0,
                      0,0,0,0,    0,0,0,0,    0,0,0,0,    0,0,0,0],
            "issued_ms": 1_000_000_u64,
            "revoked": false,
            "revoked_ms": null
        })
        .to_string();
        let decoded: CredentialRecord =
            serde_json::from_str(&legacy_json).expect("legacy JSON must deserialize");
        assert!(decoded.bbs_pubkey.is_none());
        assert!(decoded.bbs_message_count.is_none());
    }

    // -----------------------------------------------------------------------
    // execute_credential_issue_bbs tests
    // -----------------------------------------------------------------------

    #[test]
    fn issue_bbs_credential_success() {
        let pk = sample_bbs_pubkey();
        let result = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::KycL2,
            sample_hash(),
            pk,
            8,
            true,
            true,
            100,
            1_700_000_000_000,
        );
        let record = result.expect("expected success");
        assert_eq!(record.bbs_pubkey, Some(pk));
        assert_eq!(record.bbs_message_count, Some(8));
        assert!(!record.revoked);
        assert_eq!(record.credential_type, CredentialType::KycL2);
    }

    #[test]
    fn issue_bbs_credential_invalid_pubkey() {
        let bad_pk = [0u8; 96]; // not a valid G2 point
        let err = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            bad_pk,
            1,
            true,
            true,
            100,
            1_000,
        )
        .expect_err("expected InvalidBbsKey");
        assert_eq!(err, CredentialError::InvalidBbsKey);
    }

    #[test]
    fn issue_bbs_credential_zero_message_count() {
        let err = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            sample_bbs_pubkey(),
            0,
            true,
            true,
            100,
            1_000,
        )
        .expect_err("expected BbsMessageCountZero");
        assert_eq!(err, CredentialError::BbsMessageCountZero);
    }

    #[test]
    fn issue_bbs_credential_message_count_too_large() {
        let err = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            sample_bbs_pubkey(),
            BBS_MAX_MESSAGE_COUNT + 1,
            true,
            true,
            100,
            1_000,
        )
        .expect_err("expected BbsMessageCountTooLarge");
        assert_eq!(
            err,
            CredentialError::BbsMessageCountTooLarge {
                count: BBS_MAX_MESSAGE_COUNT + 1,
                max: BBS_MAX_MESSAGE_COUNT,
            }
        );
    }

    #[test]
    fn issue_bbs_credential_issuer_inactive() {
        let err = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::Email,
            sample_hash(),
            sample_bbs_pubkey(),
            3,
            false, // issuer inactive
            true,
            100,
            1_000,
        )
        .expect_err("expected IssuerDidInvalid");
        assert_eq!(err, CredentialError::IssuerDidInvalid);
    }

    #[test]
    fn revoke_bbs_credential_success() {
        let pk = sample_bbs_pubkey();
        let issued = execute_credential_issue_bbs(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:subject",
            CredentialType::KycL3,
            sample_hash(),
            pk,
            12,
            true,
            true,
            500,
            1_700_000_000_000,
        )
        .expect("issue");

        let revoked = execute_credential_revoke(
            "did:solidus:testnet:issuer",
            Some(&issued),
            1_800_000_000_000,
        )
        .expect("revoke");

        // BBS metadata is preserved through revocation.
        assert!(revoked.revoked);
        assert_eq!(revoked.revoked_ms, Some(1_800_000_000_000));
        assert_eq!(revoked.bbs_pubkey, Some(pk));
        assert_eq!(revoked.bbs_message_count, Some(12));
    }

    #[test]
    fn issue_fee_bbs_is_125_percent_of_base() {
        assert_eq!(CredentialType::Email.issue_fee_bbs(), 1_250_000);
        assert_eq!(CredentialType::KycL1.issue_fee_bbs(), 125_000_000);
        assert_eq!(CredentialType::KycL2.issue_fee_bbs(), 625_000_000);
        assert_eq!(CredentialType::KycL3.issue_fee_bbs(), 2_500_000_000);
    }
}

use serde::{Deserialize, Serialize};
use solidus_crypto::hash::blake3_hash;
use thiserror::Error;

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
}

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
        }
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
}

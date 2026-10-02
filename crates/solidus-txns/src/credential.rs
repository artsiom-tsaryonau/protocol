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
///
/// The agent-identity variants (`OwnerBinding`/`CapabilityScope`/`SpendMandate`,
/// added 2026-07-14) carry `serde(alias)` for the snake_case strings the
/// published `@solidus-network/agent-identity` SDK puts on the wire — the live
/// backend's `CredentialIssueBbs` txs were rejected with serde's
/// `unknown variant \`owner_binding\`` until the chain knew them. Records
/// serialize PascalCase like every other variant; only input accepts both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialType {
    Email,
    Phone,
    KycL1,
    KycL2,
    KycL3,
    Age,
    Reputation,
    /// Binds an AI agent's DID to its operator's DID (agent-identity Flow B).
    #[serde(alias = "owner_binding")]
    OwnerBinding,
    /// The capability scopes an agent is authorized for.
    #[serde(alias = "capability_scope")]
    CapabilityScope,
    /// A bounded spending mandate delegated to an agent.
    #[serde(alias = "spend_mandate")]
    SpendMandate,
    /// Accreditation of an issuer DID by a bridge trust root (bridge phase 0b).
    /// Accepted only at ProtocolVersion::V2, only through `CredentialIssue`
    /// (the subject is an organisation's DID, published on purpose).
    #[serde(alias = "accredited_issuer")]
    AccreditedIssuer,
}

impl CredentialType {
    /// Return the issuance fee for this credential type (in smallest units).
    /// 1 SLDS = 100_000_000 (10^8).
    pub fn issue_fee(&self) -> u64 {
        match self {
            CredentialType::Email => 1_000_000,      // 0.01 SLDS
            CredentialType::Phone => 2_000_000,      // 0.02 SLDS
            CredentialType::KycL1 => 100_000_000,    // 1.0 SLDS
            CredentialType::KycL2 => 500_000_000,    // 5.0 SLDS
            CredentialType::KycL3 => 2_000_000_000,  // 20.0 SLDS
            CredentialType::Age => 5_000_000,        // 0.05 SLDS
            CredentialType::Reputation => 1_000_000, // 0.01 SLDS
            // Agent credentials price at the Age tier: high-volume,
            // machine-issued, no human-verification cost behind them.
            // Mandates carry financial delegation — 2× that.
            CredentialType::OwnerBinding => 5_000_000, // 0.05 SLDS
            CredentialType::CapabilityScope => 5_000_000, // 0.05 SLDS
            CredentialType::SpendMandate => 10_000_000, // 0.1 SLDS
            // Issuance is fee-exempt in both executors, so this is never charged.
            CredentialType::AccreditedIssuer => 0,
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
    ///
    /// ⚠ EMPTY for a BD-6b (v2) record, where the subject is committed to rather
    /// than published. Read `subject_commitment` instead. It stays a `String` and
    /// not an `Option` so every existing v1 record deserialises unchanged.
    pub subject_did: String,
    /// Commitment to the subject DID (BD-6b, v2 only). `None` for v1 records.
    ///
    /// `BLAKE3(SUBJECT_COMMITMENT_DOMAIN ‖ subject_did ‖ nonce32)`. Additive and
    /// `skip_serializing_if`, mirroring `bbs_pubkey`, so v1 records neither carry the
    /// field nor change shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_commitment: Option<[u8; 32]>,
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

/// Domain separator for the subject commitment. Versioned so a future scheme
/// change cannot be confused with this one.
pub const SUBJECT_COMMITMENT_DOMAIN: &[u8] = b"solidus.cred.subject.v1";

/// Commit to a subject DID without publishing it.
///
/// `BLAKE3(domain ‖ subject_did ‖ nonce)`. The issuer draws `nonce` from a CSPRNG
/// once per credential and hands `(subject_did, nonce)` to the holder off-chain
/// alongside the credential. The chain stores only the output.
///
/// **The nonce is the entire point, not decoration.** Without it the commitment is
/// `BLAKE3(domain ‖ subject_did)` over a candidate set an observer can enumerate
/// from public `DidCreate` transactions, which is the same confirmation oracle that
/// `credential_id_leaks_the_subject_by_brute_force` demonstrates against the current
/// ID derivation. 32 bytes of per-credential entropy is what makes the search
/// infeasible rather than merely tedious.
///
/// NOT WIRED. This is preparation for the `subject_did` removal and nothing calls
/// it yet; landing that change is a founder decision (BD-7 scope).
pub fn build_subject_commitment(subject_did: &str, nonce: &[u8; 32]) -> [u8; 32] {
    let mut input =
        Vec::with_capacity(SUBJECT_COMMITMENT_DOMAIN.len() + subject_did.len() + nonce.len());
    input.extend_from_slice(SUBJECT_COMMITMENT_DOMAIN);
    input.extend_from_slice(subject_did.as_bytes());
    input.extend_from_slice(nonce);
    blake3_hash(&input)
}

/// Build a deterministic credential ID from issuer, subject, hash, and block height.
///
/// Format: `urn:solidus:credential:<BLAKE3(issuer || subject || hash || height_le)>`
pub fn build_credential_id(
    issuer_did: &str,
    subject_did: &str,
    hash: &[u8; 32],
    height: u64,
) -> String {
    let mut input = Vec::with_capacity(issuer_did.len() + subject_did.len() + 32 + 8);
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
#[allow(clippy::too_many_arguments)]
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
        subject_commitment: None,
        credential_type,
        hash,
        issued_ms: timestamp_ms,
        revoked: false,
        revoked_ms: None,
        bbs_pubkey: None,
        bbs_message_count: None,
    })
}

/// Build a v2 credential ID from the subject COMMITMENT rather than the subject DID.
///
/// Same construction as [`build_credential_id`], with the commitment in the subject's
/// place. That substitution is the entire fix: the v1 id is brute-forceable because
/// issuer, `hash` and height are all public and only the subject is unknown, so one
/// BLAKE3 per candidate DID identifies it. The commitment carries 32 bytes of
/// per-credential entropy the chain never sees, so the same search has nothing to
/// enumerate. See `credential_id_leaks_the_subject_by_brute_force` and
/// `subject_commitment_defeats_the_brute_force`.
pub fn build_credential_id_v2(
    issuer_did: &str,
    subject_commitment: &[u8; 32],
    hash: &[u8; 32],
    height: u64,
) -> String {
    let mut input = Vec::with_capacity(issuer_did.len() + 32 + 32 + 8);
    input.extend_from_slice(issuer_did.as_bytes());
    input.extend_from_slice(subject_commitment);
    input.extend_from_slice(hash);
    input.extend_from_slice(&height.to_le_bytes());
    format!(
        "urn:solidus:credential:{}",
        hex::encode(blake3_hash(&input))
    )
}

/// The `CF_CRED_BY_SUBJECT` key for a v2 credential.
///
/// v1 keys that column family by DID string, v2 by lowercase hex of the commitment.
/// **They cannot collide**: a DID key always begins `did:`, and hex is `[0-9a-f]` only.
/// The encoding lives here rather than in an executor so both chains agree on the key
/// format by construction, instead of by two implementations happening to match.
///
/// An observer cannot compute this key without the issuer's nonce, so the index stays
/// useful to a holder who knows their own commitments and useless for enumeration.
pub fn subject_commitment_index_key(subject_commitment: &[u8; 32]) -> String {
    hex::encode(subject_commitment)
}

/// Execute a `CredentialIssueV2` operation (Rebuild #2 BD-6b, v2 chain only).
///
/// ⚠ **There is no `subject_did_active` parameter, and that is a deliberate loss.**
/// v1 rejects issuance to a missing or deactivated subject via
/// [`CredentialError::SubjectDidInvalid`], resolving the subject with `load_did`. With
/// a commitment the chain cannot resolve the subject at all, so the check cannot run.
/// **Founder decision, 2026-08-21: drop it and document it.** The mitigation is that
/// such a credential is inert, because nobody holds the matching key and the holder
/// cannot present what they were never given. The stronger answer, recorded if issuance
/// ever becomes adversarial, is a subject co-signature on the transaction, which would
/// prove existence *and* consent rather than existence alone, at the cost of a
/// two-party transaction format.
///
/// The issuer check is UNCHANGED: an inactive issuer still fails.
pub fn execute_credential_issue_v2(
    issuer_did: &str,
    subject_commitment: [u8; 32],
    credential_type: CredentialType,
    hash: [u8; 32],
    issuer_did_active: bool,
    block_height: u64,
    timestamp_ms: u64,
) -> Result<CredentialRecord, CredentialError> {
    if !issuer_did_active {
        return Err(CredentialError::IssuerDidInvalid);
    }

    let id = build_credential_id_v2(issuer_did, &subject_commitment, &hash, block_height);
    Ok(CredentialRecord {
        id,
        issuer_did: issuer_did.to_string(),
        // Empty, not a placeholder DID: anything DID-shaped here would be a lie that
        // reads as data downstream.
        subject_did: String::new(),
        subject_commitment: Some(subject_commitment),
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
#[cfg(feature = "bbs")]
#[allow(clippy::too_many_arguments)]
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
        subject_commitment: None,
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
    let cred = credential.ok_or_else(|| CredentialError::NotFound("unknown".to_string()))?;

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
            subject_commitment: None,
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
    #[cfg(feature = "bbs")]
    fn sample_bbs_pubkey() -> [u8; 96] {
        use solidus_crypto::bbs::BbsSecretKey;
        let sk =
            BbsSecretKey::from_ikm(b"solidus-credential-test-ikm-32-bytes-or-more").expect("ikm");
        sk.public_key().to_bytes()
    }

    // -----------------------------------------------------------------------
    // build_credential_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn build_credential_id_format() {
        let issuer = "did:solidus:testnet:issuer";
        let subject = "did:solidus:testnet:subject";
        let hash = sample_hash();
        let id = build_credential_id(issuer, subject, &hash, 42);
        assert!(
            id.starts_with("urn:solidus:credential:"),
            "expected URN prefix, got: {id}"
        );
    }

    #[test]
    fn build_credential_id_deterministic() {
        let issuer = "did:solidus:testnet:issuer";
        let subject = "did:solidus:testnet:subject";
        let hash = sample_hash();
        let id1 = build_credential_id(issuer, subject, &hash, 42);
        let id2 = build_credential_id(issuer, subject, &hash, 42);
        assert_eq!(id1, id2);
    }

    /// ⛔ The credential ID is a CONFIRMATION ORACLE for the subject DID.
    ///
    /// `BLAKE3(issuer || subject || hash || height)` is not invertible, but that is
    /// not the property that matters here: **every other input is public.** The
    /// issuer is derived from the sender address in the signed transaction, `hash`
    /// is a field of the payload, and the height is the block the tx landed in. So
    /// an observer holding a candidate DID needs exactly one hash to test it.
    ///
    /// And candidates are not scarce. Every DID reaches the chain through a
    /// `DidCreate` transaction in a public block, so the candidate set is simply
    /// "every DID on the ledger", and identifying the subject of any credential
    /// costs one BLAKE3 per candidate.
    ///
    /// **This is why removing `subject_did` from `CredentialIssue` is NOT sufficient
    /// on its own.** The ID derivation has to change with it, or the field comes
    /// straight back out of the identifier that replaces it. Recorded as a test
    /// rather than a comment so the claim is checkable and so it fails loudly if
    /// someone changes the derivation and believes the problem is solved.
    /// The commitment defeats the brute force that the ID derivation does not.
    ///
    /// Same attacker, same public inputs, same candidate set as
    /// `credential_id_leaks_the_subject_by_brute_force`. The only change is that the
    /// subject reaches the chain as `build_subject_commitment(did, nonce)` instead of
    /// as itself. The search now fails, because reproducing the commitment requires
    /// the nonce and the nonce never reaches the chain.
    /// ⛔ THE ASSERTION THE PLAN'S VERIFICATION TABLE ASKS FOR: no `subject_did`
    /// reaches a v2 record.
    ///
    /// Row 4 of the plan demanded "a test asserting no `subject_did` reaches any
    /// payload". This is it, and it checks the RECORD rather than the payload, because
    /// the record is what gets written to disk and served by RPC.
    #[test]
    fn v2_record_carries_no_subject_did() {
        let commitment = build_subject_commitment("did:solidus:testnet:alice", &[9u8; 32]);
        let cred = execute_credential_issue_v2(
            "did:solidus:testnet:issuer",
            commitment,
            CredentialType::KycL3,
            sample_hash(),
            true,
            42,
            1_700_000_000_000,
        )
        .expect("an active issuer must succeed");

        assert!(
            cred.subject_did.is_empty(),
            "v2 must not carry a subject DID"
        );
        assert_eq!(cred.subject_commitment, Some(commitment));
        // The id must not leak it either: same construction, commitment in the
        // subject's place.
        assert_eq!(
            cred.id,
            build_credential_id_v2(
                "did:solidus:testnet:issuer",
                &commitment,
                &sample_hash(),
                42
            )
        );
        // CONTROL: the v1 path still DOES carry the DID, so the assertion above is
        // detecting the v2 behaviour rather than a field that is always empty.
        let v1 = execute_credential_issue(
            "did:solidus:testnet:issuer",
            "did:solidus:testnet:alice",
            CredentialType::KycL3,
            sample_hash(),
            true,
            true,
            42,
            1_700_000_000_000,
        )
        .expect("v1 happy path");
        assert_eq!(v1.subject_did, "did:solidus:testnet:alice");
        assert_eq!(v1.subject_commitment, None);
    }

    /// The dropped subject check is a DECISION, and this pins it so nobody restores it
    /// by accident or removes the issuer check by symmetry.
    #[test]
    fn v2_drops_the_subject_check_but_keeps_the_issuer_check() {
        let commitment = build_subject_commitment("did:solidus:testnet:nobody", &[1u8; 32]);

        // No subject exists, and there is no way to say so: issuance succeeds.
        // Founder decision 2026-08-21. Such a credential is inert, because nobody holds
        // the matching key.
        assert!(execute_credential_issue_v2(
            "did:solidus:testnet:issuer",
            commitment,
            CredentialType::Age,
            sample_hash(),
            true,
            1,
            1,
        )
        .is_ok());

        // The ISSUER check is untouched.
        assert!(matches!(
            execute_credential_issue_v2(
                "did:solidus:testnet:issuer",
                commitment,
                CredentialType::Age,
                sample_hash(),
                false,
                1,
                1,
            ),
            Err(CredentialError::IssuerDidInvalid)
        ));
    }

    /// v1 and v2 index keys share one column family and must not collide.
    /// ⛔ FROZEN CROSS-LANGUAGE VECTOR. Do not "fix" this value.
    ///
    /// `@solidus/sdk` computes the same commitment in TypeScript so an issuer can build
    /// the payload off-chain, and the two must agree **byte for byte** or a credential
    /// issued by the SDK commits to something the chain cannot reproduce. That failure
    /// is silent: the tx succeeds, the record is written, and the holder can never
    /// prove the credential is theirs.
    ///
    /// The identical constant is asserted in
    /// `packages/@solidus/sdk/src/__tests__/subject-commitment.test.ts`. Changing the
    /// domain separator, the field order or the hash breaks both, which is the point.
    #[test]
    fn subject_commitment_matches_the_frozen_typescript_vector() {
        assert_eq!(
            hex::encode(build_subject_commitment(
                "did:solidus:testnet:alice",
                &[0x5au8; 32]
            )),
            "67965a0e413eb538eb35ff98d665325e49be142f7ee4676bfcfcc418eb45d6df"
        );
    }

    #[test]
    fn index_keys_cannot_collide_between_v1_and_v2() {
        let key =
            subject_commitment_index_key(&build_subject_commitment("did:solidus:x", &[0u8; 32]));
        assert_eq!(key.len(), 64, "32 bytes as lowercase hex");
        assert!(key.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(
            !key.starts_with("did:"),
            "a v2 key must never look like a v1 DID key"
        );
    }

    #[test]
    fn subject_commitment_defeats_the_brute_force() {
        let candidates: Vec<String> = (0..500)
            .map(|i| format!("did:solidus:testnet:subject{i}"))
            .collect();
        let real_subject = &candidates[317];
        let nonce = [0x5au8; 32]; // stands in for a CSPRNG draw; secrecy is what matters

        let published = build_subject_commitment(real_subject, &nonce);

        // The attacker knows every candidate and the scheme, but not the nonce.
        let recovered = candidates
            .iter()
            .find(|c| build_subject_commitment(c, &[0u8; 32]) == published);
        assert!(
            recovered.is_none(),
            "the subject must not be recoverable without the nonce"
        );

        // CONTROL 1: the search is real. Given the nonce, the same loop finds it,
        // so the failure above is the missing nonce and not a broken comparison.
        let with_nonce = candidates
            .iter()
            .find(|c| build_subject_commitment(c, &nonce) == published);
        assert_eq!(
            with_nonce.map(String::as_str),
            Some(real_subject.as_str()),
            "with the nonce the holder can still prove which subject this is"
        );

        // CONTROL 2: two credentials for the SAME subject under different nonces do
        // not link. This is the property the ledger needs and the raw DID never had.
        let a = build_subject_commitment(real_subject, &[1u8; 32]);
        let b = build_subject_commitment(real_subject, &[2u8; 32]);
        assert_ne!(
            a, b,
            "same subject under different nonces must not be linkable"
        );
    }

    #[test]
    fn credential_id_leaks_the_subject_by_brute_force() {
        let issuer = "did:solidus:testnet:issuer";
        let hash = sample_hash();
        let height = 42u64;

        // The candidate set an observer builds by scanning DidCreate txs.
        let candidates: Vec<String> = (0..500)
            .map(|i| format!("did:solidus:testnet:subject{i}"))
            .collect();
        let real_subject = &candidates[317];

        // What the chain publishes.
        let published_id = build_credential_id(issuer, real_subject, &hash, height);

        // The whole attack: one hash per candidate, using only public inputs.
        let recovered = candidates
            .iter()
            .find(|c| build_credential_id(issuer, c, &hash, height) == published_id);

        assert_eq!(
            recovered.map(String::as_str),
            Some(real_subject.as_str()),
            "the subject must be recoverable, or this test has stopped describing the system"
        );

        // CONTROL: the search is doing real work, not passing trivially. A subject
        // outside the candidate set is NOT found, which is what distinguishes a
        // genuine search from an assertion that always succeeds.
        let absent_id =
            build_credential_id(issuer, "did:solidus:testnet:not-in-set", &hash, height);
        assert!(
            candidates
                .iter()
                .all(|c| build_credential_id(issuer, c, &hash, height) != absent_id),
            "a subject outside the candidate set must not match anything in it"
        );
    }

    #[test]
    fn build_credential_id_differs_by_input() {
        let issuer = "did:solidus:testnet:issuer";
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
        assert_eq!(CredentialType::Email.issue_fee(), 1_000_000);
        assert_eq!(CredentialType::Phone.issue_fee(), 2_000_000);
        assert_eq!(CredentialType::KycL1.issue_fee(), 100_000_000);
        assert_eq!(CredentialType::KycL2.issue_fee(), 500_000_000);
        assert_eq!(CredentialType::KycL3.issue_fee(), 2_000_000_000);
        assert_eq!(CredentialType::Age.issue_fee(), 5_000_000);
        assert_eq!(CredentialType::Reputation.issue_fee(), 1_000_000);
        assert_eq!(CredentialType::OwnerBinding.issue_fee(), 5_000_000);
        assert_eq!(CredentialType::CapabilityScope.issue_fee(), 5_000_000);
        assert_eq!(CredentialType::SpendMandate.issue_fee(), 10_000_000);
    }

    /// The exact live failure of 2026-07-13: the published agent-identity SDK
    /// sends snake_case type strings inside CredentialIssueBbs tx JSON, and
    /// the chain rejected them with `unknown variant \`owner_binding\``.
    /// The aliases must accept the wire form; records keep PascalCase.
    #[test]
    fn agent_credential_types_accept_sdk_wire_form() {
        for (wire, expected) in [
            ("owner_binding", CredentialType::OwnerBinding),
            ("capability_scope", CredentialType::CapabilityScope),
            ("spend_mandate", CredentialType::SpendMandate),
        ] {
            let parsed: CredentialType =
                serde_json::from_str(&format!("\"{wire}\"")).expect("snake_case alias");
            assert_eq!(parsed, expected);
        }
        // PascalCase (the record form) round-trips unchanged.
        let json = serde_json::to_string(&CredentialType::OwnerBinding).expect("ser");
        assert_eq!(json, "\"OwnerBinding\"");
        let back: CredentialType = serde_json::from_str(&json).expect("de");
        assert_eq!(back, CredentialType::OwnerBinding);
    }

    #[test]
    fn agent_credential_record_roundtrip() {
        let mut record = sample_record();
        record.credential_type = CredentialType::SpendMandate;
        let decoded = CredentialRecord::from_bytes(&record.to_bytes()).expect("roundtrip");
        assert_eq!(decoded.credential_type, CredentialType::SpendMandate);
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
        let result =
            execute_credential_revoke("did:solidus:testnet:issuer", Some(&record), 2_000_000);
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

        let err = execute_credential_revoke("did:solidus:testnet:issuer", Some(&record), 2_000_000)
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
        let err = execute_credential_revoke("did:solidus:testnet:issuer", None, 2_000_000)
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

    #[cfg(feature = "bbs")]
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

    #[cfg(feature = "bbs")]
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

    #[cfg(feature = "bbs")]
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

    #[cfg(feature = "bbs")]
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

    #[cfg(feature = "bbs")]
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

    #[cfg(feature = "bbs")]
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

    #[test]
    fn accredited_issuer_is_appended_with_a_stable_serde_name_and_index() {
        assert_eq!(
            serde_json::to_value(CredentialType::AccreditedIssuer).unwrap(),
            serde_json::json!("AccreditedIssuer")
        );
        assert_eq!(
            serde_json::from_str::<CredentialType>("\"accredited_issuer\"").unwrap(),
            CredentialType::AccreditedIssuer
        );
        // bincode writes the declaration index as u32 LE; 10 means appended after SpendMandate (9).
        assert_eq!(
            bincode::serialize(&CredentialType::AccreditedIssuer).unwrap(),
            10u32.to_le_bytes().to_vec()
        );
        assert_eq!(
            bincode::serialize(&CredentialType::SpendMandate).unwrap(),
            9u32.to_le_bytes().to_vec()
        );
    }
}

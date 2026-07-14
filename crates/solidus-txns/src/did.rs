use serde::{Deserialize, Serialize};
use solidus_crypto::ed25519;
use solidus_crypto::hash::blake3_hash;
use solidus_crypto::keys::Address;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Core DID document types
// ---------------------------------------------------------------------------

/// A service endpoint associated with a DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub service_type: String,
    pub service_endpoint: String,
}

/// A verification method (public key) associated with a DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationMethod {
    pub id: String,
    pub method_type: String,
    pub controller: String,
    pub public_key_hex: String,
}

/// Maximum guardians in a recovery policy (bounds verification cost + state size).
pub const MAX_GUARDIANS: usize = 16;

/// On-chain social-recovery policy for a DID. Set by the owner via
/// `DidPatch::SetRecoveryPolicy`. Recovery requires `threshold` valid
/// guardian signatures (see `execute_did_recover`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPolicy {
    /// Guardian DIDs. Resolved to their current authentication key at
    /// recovery time, so a guardian rotating its own key does not break this.
    pub guardians: Vec<String>,
    /// k — number of guardian signatures required (floor: 2).
    pub threshold: u8,
    /// Veto-window length in blocks. v1 enforces instant recovery; nonzero
    /// is reserved and rejected at set time until the finalize/cancel flow ships.
    #[serde(default)]
    pub delay_blocks: u64,
}

/// A W3C-compatible DID document stored on-chain.
///
/// The four verification relationships beyond `authentication`
/// (`assertion_method`, `key_agreement`, `capability_invocation`,
/// `capability_delegation`) are stored as `Vec<String>` of method ids,
/// matching the W3C DID Core data model. `#[serde(default)]` ensures
/// pre-existing on-chain documents (which omit these fields) deserialize
/// cleanly with empty vectors — the DidCreate handler populates sensible
/// defaults at issuance time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    pub context: String,
    pub id: String,
    pub controller: String,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
    /// Verification methods authorised to produce assertions
    /// (`assertionMethod` per W3C DID Core §5.3.2).
    #[serde(default)]
    pub assertion_method: Vec<String>,
    /// Verification methods authorised for ECDH key agreement
    /// (`keyAgreement` per W3C DID Core §5.3.3). Empty by default for
    /// Ed25519-only DIDs; populated when the controller adds an X25519
    /// key for encryption.
    #[serde(default)]
    pub key_agreement: Vec<String>,
    /// Verification methods authorised to invoke capabilities
    /// (`capabilityInvocation` per W3C DID Core §5.3.4).
    #[serde(default)]
    pub capability_invocation: Vec<String>,
    /// Verification methods authorised to delegate capabilities
    /// (`capabilityDelegation` per W3C DID Core §5.3.5).
    #[serde(default)]
    pub capability_delegation: Vec<String>,
    pub service: Vec<Service>,
    pub active: bool,
    pub created_ms: u64,
    pub updated_ms: u64,
    /// Content-hash version identifier (W3C DID Resolution §3.1.1
    /// `versionId`). Computed by [`compute_version_id`] as the hex-encoded
    /// BLAKE3 hash of this document with `version_id` zeroed out, so the
    /// hash is over a stable canonical pre-image that does not depend on
    /// itself. Recomputed in [`build_did_document`] at create time and at
    /// the end of [`apply_patch`] after every successful mutation.
    ///
    /// `#[serde(default)]` keeps pre-2026-05-09 on-chain documents
    /// readable: legacy records deserialize with an empty string. Such
    /// documents recompute their `version_id` on the next `DidUpdate`;
    /// the daily testnet reset clears any residual empty-string entries
    /// before mainnet launch.
    #[serde(default)]
    pub version_id: String,
    /// Social-recovery policy; `None` until the owner sets one. Recovery is
    /// impossible without it. `#[serde(default)]` keeps legacy docs readable.
    #[serde(default)]
    pub recovery_policy: Option<RecoveryPolicy>,
    /// Monotonic per-DID counter, bumped on each successful recovery. Binds
    /// guardian approvals to a single attempt (replay protection).
    #[serde(default)]
    pub recovery_nonce: u64,
}

impl DidDocument {
    /// Serialize this document to bytes (JSON).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("DidDocument serializable")
    }

    /// Deserialize a document from bytes (JSON).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ---------------------------------------------------------------------------
// DID patch operations
// ---------------------------------------------------------------------------

/// One of the five W3C DID Core verification relationships.
/// Used by `DidPatch::AddRelationship` / `RemoveRelationship`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationRelationship {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}

/// A mutation that can be applied to an existing DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DidPatch {
    /// Append a new service endpoint.
    AddService(Service),
    /// Remove the service endpoint with the given id.
    RemoveService(String),
    /// Replace all service endpoints atomically.
    ReplaceServices(Vec<Service>),
    /// Append a new verification method (e.g. for key rotation).
    /// The `id` MUST be unique within the document; the handler
    /// returns [`DidError::VerificationMethodExists`] otherwise.
    AddVerificationMethod(VerificationMethod),
    /// Remove the verification method with the given id, plus any
    /// references to it across the five verification relationships.
    /// Returns [`DidError::CannotRemoveLastAuth`] if it is the last
    /// authentication key (would brick the DID).
    RemoveVerificationMethod(String),
    /// Add a method id to one of the W3C verification relationships.
    /// No-op if already present.
    AddRelationship {
        relationship: VerificationRelationship,
        method_id: String,
    },
    /// Remove a method id from one of the W3C verification relationships.
    /// Returns [`DidError::CannotRemoveLastAuth`] if it would empty the
    /// authentication list.
    RemoveRelationship {
        relationship: VerificationRelationship,
        method_id: String,
    },
    /// Reassign the `controller` field of this DID document to a different
    /// DID. After this patch is applied, the new controller (and only the
    /// new controller) may submit subsequent `DidUpdate` and
    /// `DidDeactivate` transactions; the original sender's keys lose
    /// authority over the document. The handler refuses self-controller
    /// (no-op), reassignment to a DID whose document does not exist on
    /// chain, and reassignment to a deactivated DID. Cycles are permitted
    /// at the W3C level; resolvers must protect themselves with depth
    /// limits when transitively dereferencing controller chains.
    SetController(String),
    /// Set/replace this DID's social-recovery policy. Validated in
    /// `execute_did_update`'s pre-pass (floor + guardian resolution).
    SetRecoveryPolicy(RecoveryPolicy),
    /// Clear this DID's recovery policy.
    RemoveRecoveryPolicy,
}

// ---------------------------------------------------------------------------
// DID errors
// ---------------------------------------------------------------------------

/// Errors that can occur when executing DID operations.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DidError {
    #[error("DID already exists: {0}")]
    AlreadyExists(String),
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("DID is deactivated: {0}")]
    Deactivated(String),
    #[error("sender is not the controller of this DID")]
    NotController,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("DID document public key does not match the transaction signer; senders may only register DIDs they control")]
    PublicKeyMismatch,
    #[error("verification method not found: {0}")]
    VerificationMethodNotFound(String),
    #[error("verification method already exists: {0}")]
    VerificationMethodExists(String),
    #[error("cannot remove the last authentication key")]
    CannotRemoveLastAuth,
    /// Returned when a `SetController` patch names the current controller —
    /// the document would not change. We reject this rather than treating
    /// it as a silent no-op so the failure mode is explicit at the receipt
    /// level.
    #[error("controller reassignment is a no-op: new controller equals current controller")]
    ControllerUnchanged,
    /// Returned when a `SetController` patch points at a DID for which no
    /// document exists on chain. The new controller must be resolvable so
    /// the chain has authoritative knowledge of who holds authority after
    /// the handover.
    #[error("controller DID not found on chain: {0}")]
    ControllerNotFound(String),
    /// Returned when a `SetController` patch points at a DID whose
    /// document is on chain but has `active = false`. Handing authority
    /// to a tombstoned DID would brick the document.
    #[error("controller DID is deactivated: {0}")]
    ControllerDeactivated(String),
    #[error("recovery policy threshold must be at least 2")]
    PolicyThresholdTooLow,
    #[error("recovery policy needs at least 3 guardians")]
    PolicyTooFewGuardians,
    #[error("recovery policy exceeds the maximum guardian count")]
    PolicyTooManyGuardians,
    #[error("duplicate guardian in recovery policy: {0}")]
    PolicyDuplicateGuardian(String),
    #[error("a DID cannot be its own guardian")]
    PolicySelfGuardian,
    #[error("recovery delay is not supported yet; delay_blocks must be 0")]
    PolicyDelayUnsupported,
    #[error("guardian DID not found on chain: {0}")]
    GuardianNotFound(String),
    #[error("guardian DID is deactivated: {0}")]
    GuardianDeactivated(String),
    #[error("DID has no recovery policy configured")]
    NoRecoveryPolicy,
    #[error("insufficient valid guardian approvals for recovery")]
    InsufficientApprovals,
    #[error("too many guardian approvals supplied")]
    TooManyApprovals,
}

// ---------------------------------------------------------------------------
// Handler result types
// ---------------------------------------------------------------------------

/// Returned by a successful `DidCreate` execution.
#[derive(Debug, Clone)]
pub struct DidCreateResult {
    pub did: String,
    pub document: DidDocument,
}

// ---------------------------------------------------------------------------
// Helper: DID construction and document building
// ---------------------------------------------------------------------------

/// Build a `did:solidus:{network}:{base58address}` string.
pub fn build_did(network: &str, address: &Address) -> String {
    format!("did:solidus:{}:{}", network, address.to_base58())
}

/// Compute the W3C DID Resolution `versionId` for a document.
///
/// Returns the hex-encoded BLAKE3 hash of the document's canonical JSON
/// serialization, with the `version_id` field temporarily cleared so the
/// hash does not depend on its own previous value (chicken-and-egg). The
/// returned string is 64 lowercase hex characters.
///
/// This function is deterministic: serializing the same logical document
/// twice yields the same hash. Two documents that differ in any field
/// (services, verification methods, controller, timestamps, etc.) yield
/// different hashes with overwhelming probability.
pub fn compute_version_id(doc: &DidDocument) -> String {
    let mut snapshot = doc.clone();
    snapshot.version_id = String::new();
    let bytes = snapshot.to_bytes();
    hex::encode(blake3_hash(&bytes))
}

/// Build a fresh DID document from its component parts.
///
/// The single Ed25519 verification method is referenced by all four
/// verification relationships that are meaningful for a signing key
/// (`authentication`, `assertionMethod`, `capabilityInvocation`,
/// `capabilityDelegation`). `keyAgreement` is left empty — that
/// relationship is for X25519/ECDH keys, which are not added at
/// creation time.
pub fn build_did_document(
    did: &str,
    public_key_hex: &str,
    service_endpoints: Vec<Service>,
    timestamp_ms: u64,
) -> DidDocument {
    let key_id = format!("{}#key-0", did);
    let mut doc = DidDocument {
        context: "https://www.w3.org/ns/did/v1".to_string(),
        id: did.to_string(),
        controller: did.to_string(),
        verification_method: vec![VerificationMethod {
            id: key_id.clone(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_hex: public_key_hex.to_string(),
        }],
        authentication: vec![key_id.clone()],
        assertion_method: vec![key_id.clone()],
        key_agreement: vec![],
        capability_invocation: vec![key_id.clone()],
        capability_delegation: vec![key_id],
        service: service_endpoints,
        active: true,
        created_ms: timestamp_ms,
        updated_ms: timestamp_ms,
        version_id: String::new(),
        recovery_policy: None,
        recovery_nonce: 0,
    };
    doc.version_id = compute_version_id(&doc);
    doc
}

/// Apply a single [`DidPatch`] to an existing document in place, updating
/// `updated_ms` to `timestamp_ms`. Returns an error for patches that
/// cannot be applied without breaking document invariants (e.g. removing
/// the last authentication key, or adding a duplicate verification method).
///
/// The service-only patches never fail and are kept infallible through the
/// `apply_patch_infallible` helper for callers that only emit those.
pub fn apply_patch(
    doc: &mut DidDocument,
    patch: &DidPatch,
    timestamp_ms: u64,
) -> Result<(), DidError> {
    match patch {
        DidPatch::AddService(svc) => doc.service.push(svc.clone()),
        DidPatch::RemoveService(id) => doc.service.retain(|s| s.id != *id),
        DidPatch::ReplaceServices(svcs) => doc.service = svcs.clone(),
        DidPatch::AddVerificationMethod(vm) => {
            if doc.verification_method.iter().any(|v| v.id == vm.id) {
                return Err(DidError::VerificationMethodExists(vm.id.clone()));
            }
            doc.verification_method.push(vm.clone());
        }
        DidPatch::RemoveVerificationMethod(id) => {
            // First confirm the method exists.
            if !doc.verification_method.iter().any(|v| v.id == *id) {
                return Err(DidError::VerificationMethodNotFound(id.clone()));
            }
            // Reject if removing this would empty the authentication list.
            // (Authentication is the bedrock relationship; emptying it
            // bricks the DID.)
            let authn_after: Vec<&String> =
                doc.authentication.iter().filter(|m| *m != id).collect();
            if authn_after.is_empty() && doc.authentication.iter().any(|m| m == id) {
                return Err(DidError::CannotRemoveLastAuth);
            }
            doc.verification_method.retain(|v| v.id != *id);
            doc.authentication.retain(|m| m != id);
            doc.assertion_method.retain(|m| m != id);
            doc.key_agreement.retain(|m| m != id);
            doc.capability_invocation.retain(|m| m != id);
            doc.capability_delegation.retain(|m| m != id);
        }
        DidPatch::AddRelationship {
            relationship,
            method_id,
        } => {
            let list = relationship_list_mut(doc, *relationship);
            if !list.contains(method_id) {
                list.push(method_id.clone());
            }
        }
        DidPatch::RemoveRelationship {
            relationship,
            method_id,
        } => {
            if matches!(relationship, VerificationRelationship::Authentication) {
                let after: usize = doc
                    .authentication
                    .iter()
                    .filter(|m| *m != method_id)
                    .count();
                if after == 0 && doc.authentication.iter().any(|m| m == method_id) {
                    return Err(DidError::CannotRemoveLastAuth);
                }
            }
            let list = relationship_list_mut(doc, *relationship);
            list.retain(|m| m != method_id);
        }
        DidPatch::SetController(new) => {
            // The pre-pass in `execute_did_update` already validated that
            // `new` exists on chain, is active, and is not equal to the
            // current controller. Application here is a trivial assignment.
            doc.controller = new.clone();
        }
        DidPatch::SetRecoveryPolicy(policy) => {
            doc.recovery_policy = Some(policy.clone());
        }
        DidPatch::RemoveRecoveryPolicy => {
            doc.recovery_policy = None;
        }
    }
    doc.updated_ms = timestamp_ms;
    doc.version_id = compute_version_id(doc);
    Ok(())
}

fn relationship_list_mut(doc: &mut DidDocument, rel: VerificationRelationship) -> &mut Vec<String> {
    match rel {
        VerificationRelationship::Authentication => &mut doc.authentication,
        VerificationRelationship::AssertionMethod => &mut doc.assertion_method,
        VerificationRelationship::KeyAgreement => &mut doc.key_agreement,
        VerificationRelationship::CapabilityInvocation => &mut doc.capability_invocation,
        VerificationRelationship::CapabilityDelegation => &mut doc.capability_delegation,
    }
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

/// Execute a `DidCreate` transaction payload.
///
/// Validates that:
/// 1. `public_key` is non-zero (rejects the trivial invalid case).
/// 2. The address derived from `public_key` matches the transaction
///    `sender_address`. This prevents Alice from registering a DID
///    document whose verification key is Bob's public key — the on-chain
///    record would otherwise claim Alice controls a key she doesn't.
/// 3. No DID already exists at the derived id.
pub fn execute_did_create(
    sender_address: &Address,
    public_key: &[u8; 32],
    service_endpoints: Vec<Service>,
    existing_doc: Option<&DidDocument>,
    timestamp_ms: u64,
    network: &str,
) -> Result<DidCreateResult, DidError> {
    if public_key == &[0u8; 32] {
        return Err(DidError::InvalidPublicKey);
    }
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| DidError::InvalidPublicKey)?;
    let derived = Address::from_public_key(&vk);
    if &derived != sender_address {
        return Err(DidError::PublicKeyMismatch);
    }
    let did = build_did(network, sender_address);
    if existing_doc.is_some() {
        return Err(DidError::AlreadyExists(did));
    }
    let pk_hex = hex::encode(public_key);
    let document = build_did_document(&did, &pk_hex, service_endpoints, timestamp_ms);
    Ok(DidCreateResult { did, document })
}

/// Execute a `DidUpdate` transaction payload.
///
/// Applies all `patches` in order. Fails if the DID is not found, is
/// deactivated, or if the sender is not the controller.
///
/// The `lookup_controller` closure is invoked at most once per
/// `SetController` patch in the batch and must return the on-chain
/// `DidDocument` of the named DID, or `None` if no such DID exists.
/// The handler uses it to validate that any candidate new controller is
/// resolvable on chain and currently active, before any patch is
/// applied. Callers in production wire it to the state store's
/// `load_did` helper; tests can pass a closure backed by a `HashMap`.
///
/// Authority semantics: the existing controller check below is
/// performed against `doc.controller` (the pre-update state), so the
/// current owner of the document is the only party authorized to
/// initiate a handover. Once a `SetController` patch lands, subsequent
/// `DidUpdate` calls re-load the document and check the sender against
/// the *new* `controller` field, completing the handover.
pub fn execute_did_update<F>(
    sender_address: &Address,
    did: &str,
    patches: &[DidPatch],
    existing_doc: Option<&DidDocument>,
    lookup_controller: F,
    timestamp_ms: u64,
    network: &str,
) -> Result<DidDocument, DidError>
where
    F: Fn(&str) -> Option<DidDocument>,
{
    let doc = existing_doc.ok_or_else(|| DidError::NotFound(did.to_string()))?;
    if !doc.active {
        return Err(DidError::Deactivated(did.to_string()));
    }
    let expected_did = build_did(network, sender_address);
    if doc.controller != expected_did {
        return Err(DidError::NotController);
    }

    // Pre-pass: validate every `SetController(new)` and `SetRecoveryPolicy`
    // patch before applying any patch. We must reject early so a
    // partially-applied batch never mutates state.
    for patch in patches {
        if let DidPatch::SetController(new) = patch {
            if new == &doc.controller {
                return Err(DidError::ControllerUnchanged);
            }
            match lookup_controller(new) {
                None => return Err(DidError::ControllerNotFound(new.clone())),
                Some(target) if !target.active => {
                    return Err(DidError::ControllerDeactivated(new.clone()));
                }
                Some(_) => {}
            }
        }
        if let DidPatch::SetRecoveryPolicy(policy) = patch {
            if policy.threshold < 2 {
                return Err(DidError::PolicyThresholdTooLow);
            }
            if policy.guardians.len() < 3 {
                return Err(DidError::PolicyTooFewGuardians);
            }
            if policy.guardians.len() > MAX_GUARDIANS {
                return Err(DidError::PolicyTooManyGuardians);
            }
            if policy.delay_blocks != 0 {
                return Err(DidError::PolicyDelayUnsupported);
            }
            if (policy.threshold as usize) > policy.guardians.len() {
                return Err(DidError::PolicyThresholdTooLow);
            }
            let mut seen = std::collections::HashSet::new();
            for g in &policy.guardians {
                if g == &doc.id {
                    return Err(DidError::PolicySelfGuardian);
                }
                if !seen.insert(g.clone()) {
                    return Err(DidError::PolicyDuplicateGuardian(g.clone()));
                }
                match lookup_controller(g) {
                    None => return Err(DidError::GuardianNotFound(g.clone())),
                    Some(gd) if !gd.active => return Err(DidError::GuardianDeactivated(g.clone())),
                    Some(_) => {}
                }
            }
        }
    }

    let mut updated = doc.clone();
    for patch in patches {
        apply_patch(&mut updated, patch, timestamp_ms)?;
    }
    Ok(updated)
}

/// Execute a `DidDeactivate` transaction payload.
///
/// Sets `active = false` and updates `updated_ms`. Fails if the DID is not
/// found, already deactivated, or if the sender is not the controller.
pub fn execute_did_deactivate(
    sender_address: &Address,
    did: &str,
    existing_doc: Option<&DidDocument>,
    timestamp_ms: u64,
    network: &str,
) -> Result<DidDocument, DidError> {
    let doc = existing_doc.ok_or_else(|| DidError::NotFound(did.to_string()))?;
    if !doc.active {
        return Err(DidError::Deactivated(did.to_string()));
    }
    let expected_did = build_did(network, sender_address);
    if doc.controller != expected_did {
        return Err(DidError::NotController);
    }
    let mut deactivated = doc.clone();
    deactivated.active = false;
    deactivated.updated_ms = timestamp_ms;
    deactivated.version_id = compute_version_id(&deactivated);
    Ok(deactivated)
}

// ---------------------------------------------------------------------------
// Recovery signing helpers
// ---------------------------------------------------------------------------

/// Domain separator for guardian recovery signatures.
pub const RECOVER_DOMAIN_SEP: &[u8] = b"solidus.did.recover.v1";

/// The message each guardian signs to authorize a recovery. Binds the
/// approval to (this network, this subject, this new key, this attempt).
///
/// Canonical pre-image (length-prefixed to eliminate ambiguity between
/// different splits of the same byte stream):
/// `BLAKE3(RECOVER_DOMAIN_SEP ‖ (network.len() as u32).to_le_bytes() ‖ network
///         ‖ (subject_did.len() as u32).to_le_bytes() ‖ subject_did
///         ‖ new_public_key[32] ‖ recovery_nonce.to_le_bytes()[8])`.
///
/// The two variable-length fields are each preceded by their byte-length
/// encoded as a `u32` little-endian, ensuring distinct inputs always yield
/// distinct pre-images. The trailing fields (`new_public_key` 32 B,
/// `recovery_nonce` 8 B) are fixed-width and require no length prefix.
pub fn recovery_signing_message(
    network: &str,
    subject_did: &str,
    new_public_key: &[u8; 32],
    recovery_nonce: u64,
) -> [u8; 32] {
    let mut buf = Vec::new();
    buf.extend_from_slice(RECOVER_DOMAIN_SEP);
    buf.extend_from_slice(&(network.len() as u32).to_le_bytes());
    buf.extend_from_slice(network.as_bytes());
    buf.extend_from_slice(&(subject_did.len() as u32).to_le_bytes());
    buf.extend_from_slice(subject_did.as_bytes());
    buf.extend_from_slice(new_public_key);
    buf.extend_from_slice(&recovery_nonce.to_le_bytes());
    blake3_hash(&buf)
}

/// The raw 32-byte public key of a DID's first authentication method, if any.
pub fn first_auth_key(doc: &DidDocument) -> Option<[u8; 32]> {
    let method_id = doc.authentication.first()?;
    let vm = doc
        .verification_method
        .iter()
        .find(|v| &v.id == method_id)?;
    let bytes = hex::decode(&vm.public_key_hex).ok()?;
    bytes.try_into().ok()
}

// ---------------------------------------------------------------------------
// Guardian-authorized recovery
// ---------------------------------------------------------------------------

/// One guardian's authorization of a recovery, carried in `DidRecover`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardianApproval {
    pub guardian_did: String,
    /// 64-byte Ed25519 signature over `recovery_signing_message(...)`.
    pub signature: Vec<u8>,
}

/// Execute a guardian-authorized recovery: verify `threshold` distinct valid
/// guardian signatures, then rotate the subject DID's authentication key to
/// `new_public_key` and bump `recovery_nonce`. Pure: no I/O. `resolve_guardian`
/// returns a guardian DID's current document (production wires `load_did`).
pub fn execute_did_recover<F>(
    subject_did: &str,
    existing_doc: Option<&DidDocument>,
    new_public_key: &[u8; 32],
    approvals: &[GuardianApproval],
    resolve_guardian: F,
    network: &str,
    timestamp_ms: u64,
) -> Result<DidDocument, DidError>
where
    F: Fn(&str) -> Option<DidDocument>,
{
    let doc = existing_doc.ok_or_else(|| DidError::NotFound(subject_did.to_string()))?;
    // Defense-in-depth: the loaded doc must belong to the subject. Fails
    // closed on any future executor-wiring bug that loads the wrong document.
    if doc.id != subject_did {
        return Err(DidError::NotFound(subject_did.to_string()));
    }
    if !doc.active {
        return Err(DidError::Deactivated(subject_did.to_string()));
    }
    let policy = doc
        .recovery_policy
        .as_ref()
        .ok_or(DidError::NoRecoveryPolicy)?;
    // Belt-and-suspenders: threshold == 0 would let zero approvals succeed.
    // The set-time floor (≥ 2) already prevents this; this guard is an
    // additional fail-closed check in the executor.
    if policy.threshold == 0 {
        return Err(DidError::InsufficientApprovals);
    }
    // DoS cap: a legitimate recovery never needs more approvals than guardians
    // (duplicates are ignored). Without this bound, an attacker can submit
    // ~38k approvals per tx (p2p 4 MiB cap), each triggering a RocksDB read
    // + Ed25519 verify, stalling block execution within a 2000 ms round timeout.
    if approvals.len() > MAX_GUARDIANS {
        return Err(DidError::TooManyApprovals);
    }

    let msg = recovery_signing_message(network, subject_did, new_public_key, doc.recovery_nonce);

    let mut counted: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for approval in approvals {
        let gid = approval.guardian_did.as_str();
        if !policy.guardians.iter().any(|g| g == gid) {
            continue; // not a guardian
        }
        if counted.contains(gid) {
            continue; // dedupe
        }
        let Some(gdoc) = resolve_guardian(gid) else {
            continue;
        };
        if !gdoc.active {
            continue;
        }
        let Some(gkey) = first_auth_key(&gdoc) else {
            continue;
        };
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&gkey) else {
            continue;
        };
        let Ok(sig): Result<[u8; 64], _> = approval.signature.as_slice().try_into() else {
            continue;
        };
        if ed25519::verify(&vk, &msg, &sig) {
            if let Some(g) = policy.guardians.iter().find(|g| g.as_str() == gid) {
                counted.insert(g.as_str());
            }
        }
    }

    if counted.len() < policy.threshold as usize {
        return Err(DidError::InsufficientApprovals);
    }

    // Rotate: new key becomes the sole authentication key; controller resets to self.
    let key_id = format!("{}#key-0", subject_did);
    let pk_hex = hex::encode(new_public_key);
    let mut updated = doc.clone();
    updated.controller = subject_did.to_string();
    updated.verification_method = vec![VerificationMethod {
        id: key_id.clone(),
        method_type: "Ed25519VerificationKey2020".to_string(),
        controller: subject_did.to_string(),
        public_key_hex: pk_hex,
    }];
    updated.authentication = vec![key_id.clone()];
    updated.assertion_method = vec![key_id.clone()];
    updated.key_agreement = vec![];
    updated.capability_invocation = vec![key_id.clone()];
    updated.capability_delegation = vec![key_id];
    updated.recovery_nonce = doc.recovery_nonce.saturating_add(1);
    updated.updated_ms = timestamp_ms;
    updated.version_id = compute_version_id(&updated);
    Ok(updated)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use solidus_crypto::ed25519::{generate_signing_key, sign};

    // -----------------------------------------------------------------------
    // Test helpers
    // -----------------------------------------------------------------------

    /// Generate a fresh address + raw 32-byte public key.
    fn make_address_and_pubkey() -> (Address, [u8; 32]) {
        let sk = generate_signing_key();
        let vk = sk.verifying_key();
        let addr = Address::from_public_key(&vk);
        (addr, vk.to_bytes())
    }

    fn sample_service(id: &str) -> Service {
        Service {
            id: id.to_string(),
            service_type: "LinkedDomains".to_string(),
            service_endpoint: format!("https://example.com/{id}"),
        }
    }

    /// Closure stub for `execute_did_update` callers that don't issue any
    /// `SetController` patches. Returning `None` for every lookup is safe
    /// because the pre-pass only invokes the closure when a
    /// `SetController` variant is encountered.
    fn no_controller_lookup(_did: &str) -> Option<DidDocument> {
        None
    }

    // -----------------------------------------------------------------------
    // Type / helper tests (6)
    // -----------------------------------------------------------------------

    #[test]
    fn build_did_format() {
        let (addr, _) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        assert!(
            did.starts_with("did:solidus:testnet:"),
            "expected did:solidus:testnet:... got {did}"
        );
    }

    #[test]
    fn build_did_document_w3c_compliant() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let doc = build_did_document(&did, &pk_hex, vec![], 1_000);

        assert_eq!(doc.context, "https://www.w3.org/ns/did/v1");
        assert_eq!(doc.id, did);
        assert_eq!(doc.controller, did);
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(
            doc.verification_method[0].method_type,
            "Ed25519VerificationKey2020"
        );
        assert_eq!(doc.verification_method[0].public_key_hex, pk_hex);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.authentication[0], format!("{}#key-0", did));
        assert!(doc.active);
        assert_eq!(doc.created_ms, 1_000);
        assert_eq!(doc.updated_ms, 1_000);
    }

    #[test]
    fn did_document_serialization_roundtrip() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let doc = build_did_document(&did, &pk_hex, vec![sample_service("svc-1")], 2_000);

        let bytes = doc.to_bytes();
        let recovered = DidDocument::from_bytes(&bytes).expect("deserialization failed");
        assert_eq!(doc, recovered);
    }

    #[test]
    fn apply_add_service_patch() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let mut doc = build_did_document(&did, &pk_hex, vec![], 1_000);

        let _ = apply_patch(
            &mut doc,
            &DidPatch::AddService(sample_service("svc-1")),
            2_000,
        );

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, "svc-1");
        assert_eq!(doc.updated_ms, 2_000);
    }

    #[test]
    fn apply_remove_service_patch() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let mut doc = build_did_document(
            &did,
            &pk_hex,
            vec![sample_service("svc-1"), sample_service("svc-2")],
            1_000,
        );

        let _ = apply_patch(
            &mut doc,
            &DidPatch::RemoveService("svc-1".to_string()),
            3_000,
        );

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, "svc-2");
        assert_eq!(doc.updated_ms, 3_000);
    }

    #[test]
    fn apply_replace_services_patch() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let mut doc = build_did_document(
            &did,
            &pk_hex,
            vec![sample_service("old-1"), sample_service("old-2")],
            1_000,
        );

        let new_services = vec![sample_service("new-1")];
        let _ = apply_patch(
            &mut doc,
            &DidPatch::ReplaceServices(new_services.clone()),
            4_000,
        );

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].id, "new-1");
        assert_eq!(doc.updated_ms, 4_000);
    }

    // -----------------------------------------------------------------------
    // Handler tests (10)
    // -----------------------------------------------------------------------

    #[test]
    fn did_create_success() {
        let (addr, pk) = make_address_and_pubkey();
        let result = execute_did_create(&addr, &pk, vec![], None, 1_000, "testnet")
            .expect("create should succeed");

        assert!(result.did.starts_with("did:solidus:testnet:"));
        assert!(result.document.active);
        assert_eq!(result.document.created_ms, 1_000);
    }

    #[test]
    fn did_create_already_exists() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        let err = execute_did_create(&addr, &pk, vec![], Some(&existing), 2_000, "testnet")
            .expect_err("should fail when DID already exists");

        assert!(matches!(err, DidError::AlreadyExists(_)));
    }

    #[test]
    fn did_create_invalid_pubkey() {
        let (addr, _) = make_address_and_pubkey();
        let zero_key = [0u8; 32];

        let err = execute_did_create(&addr, &zero_key, vec![], None, 1_000, "testnet")
            .expect_err("zero key should be rejected");

        assert_eq!(err, DidError::InvalidPublicKey);
    }

    #[test]
    fn did_update_success() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        let patches = vec![DidPatch::AddService(sample_service("svc-1"))];
        let updated = execute_did_update(
            &addr,
            &did,
            &patches,
            Some(&existing),
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect("update should succeed");

        assert_eq!(updated.service.len(), 1);
        assert_eq!(updated.updated_ms, 2_000);
    }

    #[test]
    fn did_update_not_found() {
        let (addr, _) = make_address_and_pubkey();
        let did = "did:solidus:testnet:notexist";

        let err = execute_did_update(
            &addr,
            did,
            &[],
            None,
            no_controller_lookup,
            1_000,
            "testnet",
        )
        .expect_err("should fail when DID not found");

        assert!(matches!(err, DidError::NotFound(_)));
    }

    #[test]
    fn did_update_deactivated() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let mut existing = build_did_document(&did, &pk_hex, vec![], 1_000);
        existing.active = false;

        let err = execute_did_update(
            &addr,
            &did,
            &[],
            Some(&existing),
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect_err("should fail for deactivated DID");

        assert!(matches!(err, DidError::Deactivated(_)));
    }

    #[test]
    fn did_update_not_controller() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        // A different sender attempts the update.
        let (other_addr, _) = make_address_and_pubkey();
        let err = execute_did_update(
            &other_addr,
            &did,
            &[],
            Some(&existing),
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect_err("should fail when sender is not the controller");

        assert_eq!(err, DidError::NotController);
    }

    #[test]
    fn did_deactivate_success() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        let deactivated = execute_did_deactivate(&addr, &did, Some(&existing), 5_000, "testnet")
            .expect("deactivate should succeed");

        assert!(!deactivated.active);
        assert_eq!(deactivated.updated_ms, 5_000);
    }

    #[test]
    fn did_deactivate_not_controller() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        let (other_addr, _) = make_address_and_pubkey();
        let err = execute_did_deactivate(&other_addr, &did, Some(&existing), 5_000, "testnet")
            .expect_err("should fail when sender is not the controller");

        assert_eq!(err, DidError::NotController);
    }

    #[test]
    fn did_deactivate_already_deactivated() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let mut existing = build_did_document(&did, &pk_hex, vec![], 1_000);
        existing.active = false;

        let err = execute_did_deactivate(&addr, &did, Some(&existing), 5_000, "testnet")
            .expect_err("should fail when already deactivated");

        assert!(matches!(err, DidError::Deactivated(_)));
    }

    // ----------------------------------------------------------------------
    // Gap-5 tests — DidCreate enforces public_key == sender_address
    // ----------------------------------------------------------------------

    #[test]
    fn did_create_rejects_pubkey_not_matching_sender() {
        let (sender_addr, _sender_pk) = make_address_and_pubkey();
        let (_other_addr, other_pk) = make_address_and_pubkey();
        // Sender tries to register a DID document containing a key they
        // don't control. The chain must reject this.
        let err = execute_did_create(&sender_addr, &other_pk, vec![], None, 1_000, "testnet")
            .expect_err("expected PublicKeyMismatch");
        assert_eq!(err, DidError::PublicKeyMismatch);
    }

    #[test]
    fn did_create_accepts_pubkey_matching_sender() {
        let (sender_addr, sender_pk) = make_address_and_pubkey();
        // Same sender, same key — must succeed.
        let result = execute_did_create(&sender_addr, &sender_pk, vec![], None, 1_000, "testnet")
            .expect("self-registration should succeed");
        assert!(result.did.starts_with("did:solidus:testnet:"));
    }

    // ----------------------------------------------------------------------
    // Gap-4 tests — W3C verification relationships populated at create
    // ----------------------------------------------------------------------

    #[test]
    fn did_create_populates_w3c_verification_relationships() {
        let (addr, pk) = make_address_and_pubkey();
        let result =
            execute_did_create(&addr, &pk, vec![], None, 1_000, "testnet").expect("create");
        let key_id = format!("{}#key-0", result.did);
        assert_eq!(result.document.authentication, vec![key_id.clone()]);
        assert_eq!(result.document.assertion_method, vec![key_id.clone()]);
        assert_eq!(result.document.capability_invocation, vec![key_id.clone()]);
        assert_eq!(result.document.capability_delegation, vec![key_id]);
        // keyAgreement intentionally empty for Ed25519-only DIDs
        assert!(result.document.key_agreement.is_empty());
    }

    #[test]
    fn legacy_did_doc_without_relationships_deserializes() {
        // Old on-chain documents (pre-2026-05-09) didn't carry the four
        // additional relationship arrays. They must still deserialize via
        // serde defaults to empty vectors.
        let legacy = serde_json::json!({
            "context": "https://www.w3.org/ns/did/v1",
            "id": "did:solidus:testnet:example",
            "controller": "did:solidus:testnet:example",
            "verification_method": [],
            "authentication": ["did:solidus:testnet:example#key-0"],
            "service": [],
            "active": true,
            "created_ms": 1_000_u64,
            "updated_ms": 1_000_u64
        })
        .to_string();
        let doc: DidDocument = serde_json::from_str(&legacy).expect("legacy must parse");
        assert!(doc.assertion_method.is_empty());
        assert!(doc.key_agreement.is_empty());
        assert!(doc.capability_invocation.is_empty());
        assert!(doc.capability_delegation.is_empty());
    }

    // ----------------------------------------------------------------------
    // Gap-3 tests — DidPatch supports key rotation + relationship management
    // ----------------------------------------------------------------------

    fn sample_secondary_vm(did: &str) -> VerificationMethod {
        VerificationMethod {
            id: format!("{}#key-1", did),
            method_type: "Ed25519VerificationKey2020".to_string(),
            controller: did.to_string(),
            public_key_hex: "1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
        }
    }

    #[test]
    fn add_verification_method_appends() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let vm = sample_secondary_vm(&did);
        apply_patch(
            &mut doc,
            &DidPatch::AddVerificationMethod(vm.clone()),
            2_000,
        )
        .expect("add VM should succeed");
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.verification_method[1].id, vm.id);
        assert_eq!(doc.updated_ms, 2_000);
    }

    #[test]
    fn add_duplicate_verification_method_fails() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let dup = doc.verification_method[0].clone();
        let err = apply_patch(
            &mut doc,
            &DidPatch::AddVerificationMethod(dup.clone()),
            2_000,
        )
        .expect_err("duplicate must error");
        assert_eq!(err, DidError::VerificationMethodExists(dup.id));
    }

    #[test]
    fn remove_verification_method_removes_from_all_relationships() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        // Add a second key first so we don't trigger CannotRemoveLastAuth.
        let vm2 = sample_secondary_vm(&did);
        apply_patch(
            &mut doc,
            &DidPatch::AddVerificationMethod(vm2.clone()),
            2_000,
        )
        .unwrap();
        apply_patch(
            &mut doc,
            &DidPatch::AddRelationship {
                relationship: VerificationRelationship::Authentication,
                method_id: vm2.id.clone(),
            },
            2_500,
        )
        .unwrap();
        // Now remove the original key-0.
        let key0 = doc.verification_method[0].id.clone();
        apply_patch(
            &mut doc,
            &DidPatch::RemoveVerificationMethod(key0.clone()),
            3_000,
        )
        .expect("remove should succeed");
        // It's gone from verification_method and from every relationship.
        assert!(!doc.verification_method.iter().any(|v| v.id == key0));
        assert!(!doc.authentication.contains(&key0));
        assert!(!doc.assertion_method.contains(&key0));
        assert!(!doc.capability_invocation.contains(&key0));
        assert!(!doc.capability_delegation.contains(&key0));
    }

    #[test]
    fn remove_last_authentication_key_rejected() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let key0 = doc.verification_method[0].id.clone();
        let err = apply_patch(&mut doc, &DidPatch::RemoveVerificationMethod(key0), 2_000)
            .expect_err("should refuse to brick the DID");
        assert_eq!(err, DidError::CannotRemoveLastAuth);
    }

    #[test]
    fn add_relationship_idempotent() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let key_id = doc.verification_method[0].id.clone();
        // Already in keyAgreement? No — keyAgreement starts empty.
        apply_patch(
            &mut doc,
            &DidPatch::AddRelationship {
                relationship: VerificationRelationship::KeyAgreement,
                method_id: key_id.clone(),
            },
            2_000,
        )
        .unwrap();
        assert_eq!(doc.key_agreement, vec![key_id.clone()]);
        // Adding again is a no-op (still single entry).
        apply_patch(
            &mut doc,
            &DidPatch::AddRelationship {
                relationship: VerificationRelationship::KeyAgreement,
                method_id: key_id.clone(),
            },
            3_000,
        )
        .unwrap();
        assert_eq!(doc.key_agreement, vec![key_id]);
    }

    #[test]
    fn remove_relationship_keeps_method_and_other_relationships() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let key_id = doc.verification_method[0].id.clone();
        // Remove from assertionMethod only — authentication stays.
        apply_patch(
            &mut doc,
            &DidPatch::RemoveRelationship {
                relationship: VerificationRelationship::AssertionMethod,
                method_id: key_id.clone(),
            },
            2_000,
        )
        .unwrap();
        assert!(!doc.assertion_method.contains(&key_id));
        assert!(doc.authentication.contains(&key_id));
        assert_eq!(doc.verification_method.len(), 1);
    }

    #[test]
    fn key_rotation_via_two_patch_atomic_update() {
        // The full rotation flow: add new key, add it to authentication,
        // remove old key. All three patches in a single execute_did_update
        // call.
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let original = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let new_vm = sample_secondary_vm(&did);
        let new_id = new_vm.id.clone();
        let key0_id = original.verification_method[0].id.clone();
        let patches = vec![
            DidPatch::AddVerificationMethod(new_vm),
            DidPatch::AddRelationship {
                relationship: VerificationRelationship::Authentication,
                method_id: new_id.clone(),
            },
            DidPatch::RemoveVerificationMethod(key0_id.clone()),
        ];
        let updated = execute_did_update(
            &addr,
            &did,
            &patches,
            Some(&original),
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect("rotation should succeed");
        assert_eq!(updated.verification_method.len(), 1);
        assert_eq!(updated.verification_method[0].id, new_id);
        assert_eq!(updated.authentication, vec![new_id]);
        assert!(!updated.authentication.contains(&key0_id));
    }

    // ----------------------------------------------------------------------
    // Gap-7 tests — versionId resolution metadata (W3C DID Resolution §3.1.1)
    // ----------------------------------------------------------------------

    #[test]
    fn version_id_set_on_create() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        // Hex-encoded BLAKE3 hash is exactly 64 lowercase hex chars.
        assert_eq!(doc.version_id.len(), 64, "versionId must be 64 chars");
        assert!(
            doc.version_id.chars().all(|c| c.is_ascii_hexdigit()),
            "versionId must be valid hex: {}",
            doc.version_id
        );
    }

    #[test]
    fn version_id_changes_on_update() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let before = doc.version_id.clone();
        apply_patch(
            &mut doc,
            &DidPatch::AddService(sample_service("svc-1")),
            2_000,
        )
        .expect("AddService should succeed");
        assert_ne!(
            doc.version_id, before,
            "versionId must change when document mutates"
        );
        assert_eq!(doc.version_id.len(), 64);
    }

    #[test]
    fn version_id_deterministic() {
        // Two builds of the same logical document with the same inputs
        // must produce identical version_ids — content addressing requires
        // determinism.
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let doc_a = build_did_document(&did, &pk_hex, vec![], 1_000);
        let doc_b = build_did_document(&did, &pk_hex, vec![], 1_000);
        assert_eq!(doc_a.version_id, doc_b.version_id);
        // And `compute_version_id` itself is idempotent: hashing twice
        // returns the same value.
        assert_eq!(compute_version_id(&doc_a), doc_a.version_id);
    }

    #[test]
    fn legacy_doc_has_empty_version_id() {
        // Pre-2026-05-09 on-chain documents lacked a `version_id` field.
        // They must still deserialize via `#[serde(default)]` to the empty
        // string. The first post-upgrade `DidUpdate` recomputes it.
        let legacy = serde_json::json!({
            "context": "https://www.w3.org/ns/did/v1",
            "id": "did:solidus:testnet:example",
            "controller": "did:solidus:testnet:example",
            "verification_method": [],
            "authentication": ["did:solidus:testnet:example#key-0"],
            "service": [],
            "active": true,
            "created_ms": 1_000_u64,
            "updated_ms": 1_000_u64
        })
        .to_string();
        let doc: DidDocument = serde_json::from_str(&legacy).expect("legacy must parse");
        assert_eq!(doc.version_id, "");
    }

    // ----------------------------------------------------------------------
    // Gap-6 tests — controller reassignment via SetController patch
    // ----------------------------------------------------------------------

    /// Build a `lookup_controller` closure backed by a single in-memory
    /// document. Returns `Some(target.clone())` only when queried with
    /// `target.id`, mirroring `load_did` semantics for tests that need
    /// the chain to "know" about exactly one other DID.
    fn single_doc_lookup(target: DidDocument) -> impl Fn(&str) -> Option<DidDocument> {
        move |did: &str| {
            if did == target.id {
                Some(target.clone())
            } else {
                None
            }
        }
    }

    #[test]
    fn set_controller_happy_path() {
        // Alice owns DID-A; she submits a SetController patch handing
        // authority to Bob's DID-B. The chain knows about B (via the
        // closure), so the patch lands: A.controller is now B's DID,
        // updated_ms advances, version_id changes.
        let (alice_addr, alice_pk) = make_address_and_pubkey();
        let did_a = build_did("testnet", &alice_addr);
        let doc_a = build_did_document(&did_a, &hex::encode(alice_pk), vec![], 1_000);

        let (bob_addr, bob_pk) = make_address_and_pubkey();
        let did_b = build_did("testnet", &bob_addr);
        let doc_b = build_did_document(&did_b, &hex::encode(bob_pk), vec![], 1_500);

        let version_before = doc_a.version_id.clone();
        let patches = vec![DidPatch::SetController(did_b.clone())];
        let updated = execute_did_update(
            &alice_addr,
            &did_a,
            &patches,
            Some(&doc_a),
            single_doc_lookup(doc_b),
            2_000,
            "testnet",
        )
        .expect("controller reassignment should succeed");

        assert_eq!(updated.controller, did_b);
        assert_eq!(updated.updated_ms, 2_000);
        assert_ne!(updated.version_id, version_before);
        assert_eq!(updated.version_id.len(), 64);
    }

    #[test]
    fn set_controller_to_nonexistent_fails() {
        // Lookup returns None — the chain has no record of the target
        // DID. We must reject before any state mutation.
        let (alice_addr, alice_pk) = make_address_and_pubkey();
        let did_a = build_did("testnet", &alice_addr);
        let doc_a = build_did_document(&did_a, &hex::encode(alice_pk), vec![], 1_000);

        let bogus = "did:solidus:testnet:doesnotexist".to_string();
        let patches = vec![DidPatch::SetController(bogus.clone())];

        let err = execute_did_update(
            &alice_addr,
            &did_a,
            &patches,
            Some(&doc_a),
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect_err("must reject reassignment to a DID with no on-chain record");

        assert_eq!(err, DidError::ControllerNotFound(bogus));
    }

    #[test]
    fn set_controller_to_deactivated_fails() {
        // Target DID exists but is tombstoned (active = false).
        let (alice_addr, alice_pk) = make_address_and_pubkey();
        let did_a = build_did("testnet", &alice_addr);
        let doc_a = build_did_document(&did_a, &hex::encode(alice_pk), vec![], 1_000);

        let (bob_addr, bob_pk) = make_address_and_pubkey();
        let did_b = build_did("testnet", &bob_addr);
        let mut doc_b = build_did_document(&did_b, &hex::encode(bob_pk), vec![], 1_500);
        doc_b.active = false;

        let patches = vec![DidPatch::SetController(did_b.clone())];
        let err = execute_did_update(
            &alice_addr,
            &did_a,
            &patches,
            Some(&doc_a),
            single_doc_lookup(doc_b),
            2_000,
            "testnet",
        )
        .expect_err("must reject reassignment to a deactivated DID");

        assert_eq!(err, DidError::ControllerDeactivated(did_b));
    }

    #[test]
    fn set_controller_to_self_is_noop() {
        // Submitting `SetController(my_own_did)` is rejected with an
        // explicit error rather than silently succeeding, so the failure
        // surfaces in the receipt.
        let (alice_addr, alice_pk) = make_address_and_pubkey();
        let did_a = build_did("testnet", &alice_addr);
        let doc_a = build_did_document(&did_a, &hex::encode(alice_pk), vec![], 1_000);

        let patches = vec![DidPatch::SetController(did_a.clone())];
        let err = execute_did_update(
            &alice_addr,
            &did_a,
            &patches,
            Some(&doc_a),
            // Even if the closure could resolve `did_a`, the no-op check
            // fires first — we don't even reach the lookup.
            no_controller_lookup,
            2_000,
            "testnet",
        )
        .expect_err("must reject reassignment to the same controller");

        assert_eq!(err, DidError::ControllerUnchanged);
    }

    // ----------------------------------------------------------------------
    // Recovery primitive tests (Task 1)
    // ----------------------------------------------------------------------

    #[test]
    fn legacy_did_doc_deserializes_with_recovery_defaults() {
        // A document JSON written before recovery fields existed.
        let legacy = r#"{
            "context":"https://www.w3.org/ns/did/v1","id":"did:solidus:testnet:abc",
            "controller":"did:solidus:testnet:abc",
            "verification_method":[],"authentication":[],"service":[],
            "active":true,"created_ms":1,"updated_ms":1
        }"#;
        let doc = DidDocument::from_bytes(legacy.as_bytes()).expect("legacy doc must parse");
        assert_eq!(doc.recovery_policy, None);
        assert_eq!(doc.recovery_nonce, 0);
    }

    #[test]
    fn recovery_policy_round_trips() {
        let p = RecoveryPolicy {
            guardians: vec!["did:solidus:testnet:g1".into()],
            threshold: 2,
            delay_blocks: 0,
        };
        let json = serde_json::to_vec(&p).unwrap();
        let back: RecoveryPolicy = serde_json::from_slice(&json).unwrap();
        assert_eq!(p, back);
    }

    // ----------------------------------------------------------------------
    // Task 2 tests — SetRecoveryPolicy / RemoveRecoveryPolicy patches
    // ----------------------------------------------------------------------

    #[test]
    fn set_recovery_policy_rejects_threshold_below_two() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // three guardians but threshold 1 -> floor violation
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 1,
            delay_blocks: 0,
        });
        let always = |_d: &str| Some(doc.clone());
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), always, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicyThresholdTooLow);
    }

    #[test]
    fn set_recovery_policy_rejects_unknown_guardian() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let none = |_d: &str| None; // no guardian resolves
        let err =
            execute_did_update(&addr, &did, &[patch], Some(&doc), none, 2, "testnet").unwrap_err();
        assert!(matches!(err, DidError::GuardianNotFound(_)));
    }

    #[test]
    fn set_recovery_policy_then_remove_round_trips() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let active = |_d: &str| {
            Some(build_did_document(
                "did:solidus:testnet:g1",
                &hex::encode(pk),
                vec![],
                1,
            ))
        };
        let set = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let after_set =
            execute_did_update(&addr, &did, &[set], Some(&doc), active, 2, "testnet").unwrap();
        assert!(after_set.recovery_policy.is_some());
        let after_rm = execute_did_update(
            &addr,
            &did,
            &[DidPatch::RemoveRecoveryPolicy],
            Some(&after_set),
            active,
            3,
            "testnet",
        )
        .unwrap();
        assert_eq!(after_rm.recovery_policy, None);
    }

    #[test]
    fn set_recovery_policy_rejects_too_few_guardians() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // Only 2 guardians — minimum is 3
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), |_| None, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicyTooFewGuardians);
    }

    #[test]
    fn set_recovery_policy_rejects_too_many_guardians() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // 17 guardians — maximum is MAX_GUARDIANS (16)
        let g: Vec<String> = (1..=17)
            .map(|i| format!("did:solidus:testnet:g{i}"))
            .collect();
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), |_| None, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicyTooManyGuardians);
    }

    #[test]
    fn set_recovery_policy_rejects_duplicate_guardian() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // g1 appears at positions 0 and 2
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g1".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let g1_doc = build_did_document("did:solidus:testnet:g1", &hex::encode(pk), vec![], 1);
        let g2_doc = build_did_document("did:solidus:testnet:g2", &hex::encode(pk), vec![], 1);
        let lookup = move |d: &str| match d {
            "did:solidus:testnet:g1" => Some(g1_doc.clone()),
            "did:solidus:testnet:g2" => Some(g2_doc.clone()),
            _ => None,
        };
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), lookup, 2, "testnet")
            .unwrap_err();
        assert!(matches!(err, DidError::PolicyDuplicateGuardian(_)));
    }

    #[test]
    fn set_recovery_policy_rejects_self_guardian() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // Subject's own DID is listed as guardian
        let g = vec![
            did.clone(),
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), |_| None, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicySelfGuardian);
    }

    #[test]
    fn set_recovery_policy_rejects_delay_blocks() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 1, // non-zero — unsupported
        });
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), |_| None, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicyDelayUnsupported);
    }

    #[test]
    fn set_recovery_policy_rejects_deactivated_guardian() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 2,
            delay_blocks: 0,
        });
        let active_doc = build_did_document("did:solidus:testnet:g1", &hex::encode(pk), vec![], 1);
        let mut deactivated =
            build_did_document("did:solidus:testnet:g3", &hex::encode(pk), vec![], 1);
        deactivated.active = false;
        let lookup = move |d: &str| match d {
            "did:solidus:testnet:g1" | "did:solidus:testnet:g2" => Some(active_doc.clone()),
            "did:solidus:testnet:g3" => Some(deactivated.clone()),
            _ => None,
        };
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), lookup, 2, "testnet")
            .unwrap_err();
        assert!(matches!(err, DidError::GuardianDeactivated(_)));
    }

    #[test]
    fn set_recovery_policy_rejects_threshold_above_guardian_count() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        // 3 guardians but threshold 4 — exceeds guardian count
        let g = vec![
            "did:solidus:testnet:g1".into(),
            "did:solidus:testnet:g2".into(),
            "did:solidus:testnet:g3".into(),
        ];
        let patch = DidPatch::SetRecoveryPolicy(RecoveryPolicy {
            guardians: g,
            threshold: 4,
            delay_blocks: 0,
        });
        let err = execute_did_update(&addr, &did, &[patch], Some(&doc), |_| None, 2, "testnet")
            .unwrap_err();
        assert_eq!(err, DidError::PolicyThresholdTooLow);
    }

    // ----------------------------------------------------------------------
    // Task 3 tests — canonical recovery message + guardian auth-key helper
    // ----------------------------------------------------------------------

    #[test]
    fn recovery_message_is_nonce_bound() {
        let pk = [7u8; 32];
        let m0 = recovery_signing_message("testnet", "did:solidus:testnet:s", &pk, 0);
        let m1 = recovery_signing_message("testnet", "did:solidus:testnet:s", &pk, 1);
        assert_ne!(m0, m1, "different nonce must change the message");
        let m_net = recovery_signing_message("mainnet", "did:solidus:testnet:s", &pk, 0);
        assert_ne!(m0, m_net, "different network must change the message");
    }

    #[test]
    fn first_auth_key_returns_authentication_method_key() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let doc = build_did_document(&did, &hex::encode(pk), vec![], 1);
        assert_eq!(first_auth_key(&doc), Some(pk));
    }

    // ----------------------------------------------------------------------
    // Task 4 tests — execute_did_recover (k-of-n guardian key rotation)
    // ----------------------------------------------------------------------

    /// Build a subject doc with a 3-guardian / threshold-2 policy and
    /// return (subject_did, subject_doc, guardian_keys, guardian_docs).
    fn recovery_fixture() -> (
        String,
        DidDocument,
        Vec<ed25519_dalek::SigningKey>,
        Vec<DidDocument>,
    ) {
        let (addr, pk) = make_address_and_pubkey();
        let subject_did = build_did("testnet", &addr);
        let mut doc = build_did_document(&subject_did, &hex::encode(pk), vec![], 1);
        let mut gkeys = Vec::new();
        let mut gdocs = Vec::new();
        let mut gids = Vec::new();
        for i in 0..3 {
            let k = generate_signing_key();
            let gpk = k.verifying_key().to_bytes();
            let gaddr = solidus_crypto::keys::Address::from_public_key(&k.verifying_key());
            let gdid = build_did("testnet", &gaddr);
            gdocs.push(build_did_document(&gdid, &hex::encode(gpk), vec![], 1));
            gids.push(gdid);
            gkeys.push(k);
            let _ = i;
        }
        doc.recovery_policy = Some(RecoveryPolicy {
            guardians: gids,
            threshold: 2,
            delay_blocks: 0,
        });
        (subject_did, doc, gkeys, gdocs)
    }

    fn approve(
        gkey: &ed25519_dalek::SigningKey,
        gdoc: &DidDocument,
        network: &str,
        subject: &str,
        new_pk: &[u8; 32],
        nonce: u64,
    ) -> GuardianApproval {
        let msg = recovery_signing_message(network, subject, new_pk, nonce);
        GuardianApproval {
            guardian_did: gdoc.id.clone(),
            signature: sign(gkey, &msg).to_vec(),
        }
    }

    #[test]
    fn recover_succeeds_at_threshold_and_rotates_key() {
        let (subject, doc, gkeys, gdocs) = recovery_fixture();
        let new_key = generate_signing_key();
        let new_pk = new_key.verifying_key().to_bytes();
        let approvals = vec![
            approve(&gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, 0),
            approve(&gkeys[1], &gdocs[1], "testnet", &subject, &new_pk, 0),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let updated = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap();
        assert_eq!(
            first_auth_key(&updated),
            Some(new_pk),
            "key rotated to new key"
        );
        assert_eq!(updated.recovery_nonce, 1, "nonce bumped");
        assert_eq!(updated.controller, subject, "controller reset to self");
    }

    #[test]
    fn recover_fails_below_threshold() {
        let (subject, doc, gkeys, gdocs) = recovery_fixture();
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        let approvals = vec![approve(
            &gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, 0,
        )];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(err, DidError::InsufficientApprovals);
    }

    #[test]
    fn recover_ignores_duplicate_guardian() {
        let (subject, doc, gkeys, gdocs) = recovery_fixture();
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        // same guardian twice = counts once -> below threshold
        let approvals = vec![
            approve(&gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, 0),
            approve(&gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, 0),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(err, DidError::InsufficientApprovals);
    }

    #[test]
    fn recover_rejects_replay_with_stale_nonce() {
        let (subject, mut doc, gkeys, gdocs) = recovery_fixture();
        doc.recovery_nonce = 5; // current on-chain nonce
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        // approvals signed over nonce 0 (stale)
        let approvals = vec![
            approve(&gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, 0),
            approve(&gkeys[1], &gdocs[1], "testnet", &subject, &new_pk, 0),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DidError::InsufficientApprovals,
            "stale-nonce sigs don't verify"
        );
    }

    #[test]
    fn recover_fails_without_policy() {
        let (addr, pk) = make_address_and_pubkey();
        let subject = build_did("testnet", &addr);
        let doc = build_did_document(&subject, &hex::encode(pk), vec![], 1); // no policy
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        let resolve = |_d: &str| None;
        let err = execute_did_recover(&subject, Some(&doc), &new_pk, &[], resolve, "testnet", 99)
            .unwrap_err();
        assert_eq!(err, DidError::NoRecoveryPolicy);
    }

    #[test]
    fn recover_rejects_excessive_approvals() {
        // MAX_GUARDIANS + 1 (17) approvals must be rejected before any
        // resolve_guardian call or signature verify — confirming the cap fires
        // first even with no real guardian content.
        let (subject, doc, _gkeys, _gdocs) = recovery_fixture();
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        let approvals: Vec<GuardianApproval> = (0..=MAX_GUARDIANS)
            .map(|i| GuardianApproval {
                guardian_did: format!("did:solidus:testnet:g{i}"),
                signature: vec![0u8; 64],
            })
            .collect();
        assert_eq!(approvals.len(), MAX_GUARDIANS + 1);
        let resolve = |_d: &str| None; // cap must fire before any resolve call
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            1,
        )
        .unwrap_err();
        assert_eq!(err, DidError::TooManyApprovals);
    }

    // ----------------------------------------------------------------------
    // Task 4 hardening tests — security properties of execute_did_recover
    // ----------------------------------------------------------------------

    /// A valid signature over the correct recovery message from a key that is
    /// NOT in the guardian set must never count toward the threshold.
    #[test]
    fn recover_rejects_valid_signature_from_non_guardian() {
        let (subject, doc, _gkeys, gdocs) = recovery_fixture();
        let new_pk = generate_signing_key().verifying_key().to_bytes();

        let non_guardian_key = generate_signing_key();
        let non_guardian_addr =
            solidus_crypto::keys::Address::from_public_key(&non_guardian_key.verifying_key());
        let non_guardian_did = build_did("testnet", &non_guardian_addr);
        let non_guardian_doc = build_did_document(
            &non_guardian_did,
            &hex::encode(non_guardian_key.verifying_key().to_bytes()),
            vec![],
            1,
        );
        let msg = recovery_signing_message("testnet", &subject, &new_pk, doc.recovery_nonce);
        let non_guardian_sig = sign(&non_guardian_key, &msg).to_vec();

        // Case 1: claims to be guardian[0] and guardian[1], but sig comes from non-guardian key
        let approvals_impersonate = vec![
            GuardianApproval {
                guardian_did: gdocs[0].id.clone(),
                signature: non_guardian_sig.clone(),
            },
            GuardianApproval {
                guardian_did: gdocs[1].id.clone(),
                signature: non_guardian_sig.clone(),
            },
        ];
        let gdocs_c = gdocs.clone();
        let resolve = move |d: &str| gdocs_c.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals_impersonate,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DidError::InsufficientApprovals,
            "non-guardian sig must not count even when claiming a guardian DID"
        );

        // Case 2: uses its own non-guardian DID, valid sig over correct msg — still not a guardian
        let approvals_own = vec![GuardianApproval {
            guardian_did: non_guardian_did.clone(),
            signature: non_guardian_sig,
        }];
        let ngd = non_guardian_doc;
        let nd = non_guardian_did;
        let resolve2 = move |d: &str| {
            gdocs.iter().find(|g| g.id == d).cloned().or_else(|| {
                if d == nd {
                    Some(ngd.clone())
                } else {
                    None
                }
            })
        };
        let err2 = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals_own,
            resolve2,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(
            err2,
            DidError::InsufficientApprovals,
            "non-guardian DID with valid sig must not count"
        );
    }

    /// After a successful recovery, all key-related fields in the document
    /// must reflect ONLY the new key, and metadata fields must advance.
    #[test]
    fn recover_full_rotation_replaces_all_key_fields() {
        let (subject, doc, gkeys, gdocs) = recovery_fixture();
        let old_version_id = doc.version_id.clone();
        let old_nonce = doc.recovery_nonce;
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        let approvals = vec![
            approve(
                &gkeys[0], &gdocs[0], "testnet", &subject, &new_pk, old_nonce,
            ),
            approve(
                &gkeys[1], &gdocs[1], "testnet", &subject, &new_pk, old_nonce,
            ),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let updated = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            100,
        )
        .unwrap();

        let key_id = format!("{}#key-0", subject);
        assert_eq!(
            updated.verification_method.len(),
            1,
            "exactly one verification method after rotation"
        );
        assert!(
            updated.key_agreement.is_empty(),
            "keyAgreement must be cleared"
        );
        assert_eq!(
            updated.assertion_method,
            vec![key_id.clone()],
            "assertionMethod must reference new key"
        );
        assert_eq!(
            updated.capability_invocation,
            vec![key_id.clone()],
            "capabilityInvocation must reference new key"
        );
        assert_eq!(
            updated.capability_delegation,
            vec![key_id.clone()],
            "capabilityDelegation must reference new key"
        );
        assert_eq!(
            updated.authentication,
            vec![key_id],
            "authentication must reference new key"
        );
        assert_eq!(
            updated.controller, subject,
            "controller must be reset to self"
        );
        assert_eq!(
            updated.recovery_nonce,
            old_nonce + 1,
            "nonce must advance by 1"
        );
        assert_ne!(updated.version_id, old_version_id, "version_id must change");
    }

    /// Approvals signed over a different subject_did must not verify against
    /// this subject's recovery message (the subject field is bound in the msg).
    #[test]
    fn recover_rejects_cross_subject_approvals() {
        let (subject, doc, gkeys, gdocs) = recovery_fixture();
        let other_subject = "did:solidus:testnet:totallydifferentsubject";
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        // Approvals signed for the WRONG subject — they bind to `other_subject`
        let approvals = vec![
            approve(
                &gkeys[0],
                &gdocs[0],
                "testnet",
                other_subject,
                &new_pk,
                doc.recovery_nonce,
            ),
            approve(
                &gkeys[1],
                &gdocs[1],
                "testnet",
                other_subject,
                &new_pk,
                doc.recovery_nonce,
            ),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DidError::InsufficientApprovals,
            "cross-subject approvals must not verify"
        );
    }

    /// When a guardian's resolved doc has `active = false`, its approval must
    /// be skipped — it must not count toward the threshold.
    #[test]
    fn recover_skips_inactive_guardian() {
        // 3 guardians, threshold 2. Guardian[1] is inactive.
        // Only guardian[0] produces a valid sig → 1 < 2 → InsufficientApprovals.
        let (subject, doc, gkeys, mut gdocs) = recovery_fixture();
        gdocs[1].active = false;
        let new_pk = generate_signing_key().verifying_key().to_bytes();
        let approvals = vec![
            approve(
                &gkeys[0],
                &gdocs[0],
                "testnet",
                &subject,
                &new_pk,
                doc.recovery_nonce,
            ),
            approve(
                &gkeys[1],
                &gdocs[1],
                "testnet",
                &subject,
                &new_pk,
                doc.recovery_nonce,
            ),
        ];
        let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
        let err = execute_did_recover(
            &subject,
            Some(&doc),
            &new_pk,
            &approvals,
            resolve,
            "testnet",
            99,
        )
        .unwrap_err();
        assert_eq!(
            err,
            DidError::InsufficientApprovals,
            "inactive guardian approval must be skipped"
        );
    }

    // ----------------------------------------------------------------------
    // Task 7 — proptest: execute_did_recover never panics on arbitrary approvals
    // ----------------------------------------------------------------------

    proptest! {
        #[test]
        fn recover_never_panics_on_arbitrary_approvals(
            new_pk in proptest::array::uniform32(any::<u8>()),
            approvals_raw in proptest::collection::vec(
                (any::<u64>(), proptest::collection::vec(any::<u8>(), 64..=64)),
                0..40,
            ),
        ) {
            let (subject, doc, _g, gdocs) = recovery_fixture();
            let approvals: Vec<GuardianApproval> = approvals_raw
                .iter()
                .map(|(did_seed, sig_bytes)| GuardianApproval {
                    guardian_did: format!("did:solidus:testnet:rand{}", did_seed),
                    signature: sig_bytes.clone(),
                })
                .collect();
            let resolve = |d: &str| gdocs.iter().find(|g| g.id == d).cloned();
            // Must return a Result, never panic — for any count (incl. n > MAX_GUARDIANS).
            let _ = execute_did_recover(&subject, Some(&doc), &new_pk, &approvals, resolve, "testnet", 1);
        }
    }

    #[test]
    fn set_controller_then_old_owner_loses_authority() {
        // Step 1: Alice reassigns DID-A's controller to Bob's DID-B.
        // Step 2: Alice tries another DidUpdate (AddService) signed with
        //         her key — the existing controller check at the top of
        //         `execute_did_update` now compares Alice's address-derived
        //         DID against the post-handover controller (B's DID), so
        //         the second update is rejected with NotController.
        let (alice_addr, alice_pk) = make_address_and_pubkey();
        let did_a = build_did("testnet", &alice_addr);
        let doc_a = build_did_document(&did_a, &hex::encode(alice_pk), vec![], 1_000);

        let (bob_addr, bob_pk) = make_address_and_pubkey();
        let did_b = build_did("testnet", &bob_addr);
        let doc_b = build_did_document(&did_b, &hex::encode(bob_pk), vec![], 1_500);

        // Hand-off.
        let after_handover = execute_did_update(
            &alice_addr,
            &did_a,
            &[DidPatch::SetController(did_b.clone())],
            Some(&doc_a),
            single_doc_lookup(doc_b),
            2_000,
            "testnet",
        )
        .expect("handover should succeed");
        assert_eq!(after_handover.controller, did_b);

        // Alice tries another update on the same document, post-handover.
        let err = execute_did_update(
            &alice_addr,
            &did_a,
            &[DidPatch::AddService(sample_service("late-svc"))],
            Some(&after_handover),
            no_controller_lookup,
            3_000,
            "testnet",
        )
        .expect_err("old controller must lose authority after handover");

        assert_eq!(err, DidError::NotController);
    }

    // -----------------------------------------------------------------------
    // Cross-language parity vectors (lock the recovery wire shape for the SDK)
    // -----------------------------------------------------------------------

    /// Fixed known-answer vectors that the TypeScript SDK's recovery
    /// implementation must reproduce byte-for-byte. Prints the canonical
    /// recovery signing-message hash and the canonical `DidRecover` payload
    /// JSON so they can be copied into the SDK test fixtures. Changing either
    /// printed value is a wire-format break.
    #[test]
    fn recovery_message_known_vector() {
        use crate::types::TxPayload;

        let h = recovery_signing_message("testnet", "did:solidus:testnet:abc", &[1u8; 32], 7);
        println!("RECOVERY_MSG_HEX={}", hex::encode(h));
        assert_eq!(h.len(), 32);

        let payload = TxPayload::DidRecover {
            did: "did:solidus:testnet:abc".into(),
            new_public_key: [1u8; 32],
            approvals: vec![GuardianApproval {
                guardian_did: "did:solidus:testnet:g1".into(),
                signature: vec![2u8; 64],
            }],
        };
        println!(
            "RECOVERY_PAYLOAD_JSON={}",
            serde_json::to_string(&payload).unwrap()
        );
    }
}

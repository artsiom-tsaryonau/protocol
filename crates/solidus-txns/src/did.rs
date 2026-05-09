use serde::{Deserialize, Serialize};
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
    DidDocument {
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
    }
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
    }
    doc.updated_ms = timestamp_ms;
    Ok(())
}

fn relationship_list_mut(
    doc: &mut DidDocument,
    rel: VerificationRelationship,
) -> &mut Vec<String> {
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
pub fn execute_did_update(
    sender_address: &Address,
    did: &str,
    patches: &[DidPatch],
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
    Ok(deactivated)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_crypto::ed25519::generate_signing_key;

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
        assert_eq!(doc.verification_method[0].method_type, "Ed25519VerificationKey2020");
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

        apply_patch(
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

        apply_patch(
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
        apply_patch(
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
        let updated = execute_did_update(&addr, &did, &patches, Some(&existing), 2_000, "testnet")
            .expect("update should succeed");

        assert_eq!(updated.service.len(), 1);
        assert_eq!(updated.updated_ms, 2_000);
    }

    #[test]
    fn did_update_not_found() {
        let (addr, _) = make_address_and_pubkey();
        let did = "did:solidus:testnet:notexist";

        let err = execute_did_update(&addr, did, &[], None, 1_000, "testnet")
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

        let err = execute_did_update(&addr, &did, &[], Some(&existing), 2_000, "testnet")
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
        let err = execute_did_update(&other_addr, &did, &[], Some(&existing), 2_000, "testnet")
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
        let err = execute_did_create(
            &sender_addr,
            &other_pk,
            vec![],
            None,
            1_000,
            "testnet",
        )
        .expect_err("expected PublicKeyMismatch");
        assert_eq!(err, DidError::PublicKeyMismatch);
    }

    #[test]
    fn did_create_accepts_pubkey_matching_sender() {
        let (sender_addr, sender_pk) = make_address_and_pubkey();
        // Same sender, same key — must succeed.
        let result = execute_did_create(
            &sender_addr,
            &sender_pk,
            vec![],
            None,
            1_000,
            "testnet",
        )
        .expect("self-registration should succeed");
        assert!(result.did.starts_with("did:solidus:testnet:"));
    }

    // ----------------------------------------------------------------------
    // Gap-4 tests — W3C verification relationships populated at create
    // ----------------------------------------------------------------------

    #[test]
    fn did_create_populates_w3c_verification_relationships() {
        let (addr, pk) = make_address_and_pubkey();
        let result = execute_did_create(&addr, &pk, vec![], None, 1_000, "testnet")
            .expect("create");
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
            public_key_hex: "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        }
    }

    #[test]
    fn add_verification_method_appends() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let mut doc = build_did_document(&did, &hex::encode(pk), vec![], 1_000);
        let vm = sample_secondary_vm(&did);
        apply_patch(&mut doc, &DidPatch::AddVerificationMethod(vm.clone()), 2_000)
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
        let err = apply_patch(&mut doc, &DidPatch::AddVerificationMethod(dup.clone()), 2_000)
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
        apply_patch(&mut doc, &DidPatch::AddVerificationMethod(vm2.clone()), 2_000).unwrap();
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
        apply_patch(&mut doc, &DidPatch::RemoveVerificationMethod(key0.clone()), 3_000)
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
            2_000,
            "testnet",
        )
        .expect("rotation should succeed");
        assert_eq!(updated.verification_method.len(), 1);
        assert_eq!(updated.verification_method[0].id, new_id);
        assert_eq!(updated.authentication, vec![new_id]);
        assert!(!updated.authentication.contains(&key0_id));
    }
}

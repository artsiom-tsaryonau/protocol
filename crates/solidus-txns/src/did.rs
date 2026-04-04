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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DidDocument {
    pub context: String,
    pub id: String,
    pub controller: String,
    pub verification_method: Vec<VerificationMethod>,
    pub authentication: Vec<String>,
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

/// A mutation that can be applied to an existing DID document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DidPatch {
    /// Append a new service endpoint.
    AddService(Service),
    /// Remove the service endpoint with the given id.
    RemoveService(String),
    /// Replace all service endpoints atomically.
    ReplaceServices(Vec<Service>),
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
        authentication: vec![key_id],
        service: service_endpoints,
        active: true,
        created_ms: timestamp_ms,
        updated_ms: timestamp_ms,
    }
}

/// Apply a single [`DidPatch`] to an existing document in place, updating
/// `updated_ms` to `timestamp_ms`.
pub fn apply_patch(doc: &mut DidDocument, patch: &DidPatch, timestamp_ms: u64) {
    match patch {
        DidPatch::AddService(svc) => doc.service.push(svc.clone()),
        DidPatch::RemoveService(id) => doc.service.retain(|s| s.id != *id),
        DidPatch::ReplaceServices(svcs) => doc.service = svcs.clone(),
    }
    doc.updated_ms = timestamp_ms;
}

// ---------------------------------------------------------------------------
// Handler functions
// ---------------------------------------------------------------------------

/// Execute a `DidCreate` transaction payload.
///
/// Returns [`DidError::InvalidPublicKey`] for an all-zero key and
/// [`DidError::AlreadyExists`] if `existing_doc` is `Some`.
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
) -> Result<DidDocument, DidError> {
    let doc = existing_doc.ok_or_else(|| DidError::NotFound(did.to_string()))?;
    if !doc.active {
        return Err(DidError::Deactivated(did.to_string()));
    }
    let expected_did = build_did("testnet", sender_address);
    if doc.controller != expected_did {
        return Err(DidError::NotController);
    }
    let mut updated = doc.clone();
    for patch in patches {
        apply_patch(&mut updated, patch, timestamp_ms);
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
) -> Result<DidDocument, DidError> {
    let doc = existing_doc.ok_or_else(|| DidError::NotFound(did.to_string()))?;
    if !doc.active {
        return Err(DidError::Deactivated(did.to_string()));
    }
    let expected_did = build_did("testnet", sender_address);
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
        let updated = execute_did_update(&addr, &did, &patches, Some(&existing), 2_000)
            .expect("update should succeed");

        assert_eq!(updated.service.len(), 1);
        assert_eq!(updated.updated_ms, 2_000);
    }

    #[test]
    fn did_update_not_found() {
        let (addr, _) = make_address_and_pubkey();
        let did = "did:solidus:testnet:notexist";

        let err = execute_did_update(&addr, did, &[], None, 1_000)
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

        let err = execute_did_update(&addr, &did, &[], Some(&existing), 2_000)
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
        let err = execute_did_update(&other_addr, &did, &[], Some(&existing), 2_000)
            .expect_err("should fail when sender is not the controller");

        assert_eq!(err, DidError::NotController);
    }

    #[test]
    fn did_deactivate_success() {
        let (addr, pk) = make_address_and_pubkey();
        let did = build_did("testnet", &addr);
        let pk_hex = hex::encode(pk);
        let existing = build_did_document(&did, &pk_hex, vec![], 1_000);

        let deactivated = execute_did_deactivate(&addr, &did, Some(&existing), 5_000)
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
        let err = execute_did_deactivate(&other_addr, &did, Some(&existing), 5_000)
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

        let err = execute_did_deactivate(&addr, &did, Some(&existing), 5_000)
            .expect_err("should fail when already deactivated");

        assert!(matches!(err, DidError::Deactivated(_)));
    }
}

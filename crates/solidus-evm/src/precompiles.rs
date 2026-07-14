//! The 3 identity precompiles (§4.8) as pure functions: input bytes +
//! the subnet's latest finalized sub-tree root → 32-byte EVM bool word.
//! No L1 re-execution anywhere — every read is an inclusion proof against
//! an L1-finalized root (§5.7). A stale-but-finalized root is acceptable;
//! the staleness bound is the L1→subnet gossip lag.
//!
//! Failure semantics: *cryptographically valid* inputs whose domain check
//! fails (inactive DID, revoked credential, issuer mismatch, BBS proof
//! invalid) return the `false` word; *malformed or unproven* inputs
//! (wrong claimed root, bad proof, undecodable record, truncation) return
//! a precompile error — Solidity callers can distinguish "checked and
//! false" from "unverifiable input".

use solidus_state_tree::{verify_inclusion, InclusionProof};
use solidus_txns::credential::CredentialRecord;
use solidus_txns::did::DidDocument;

use crate::codec::{bool_word, InputReader};
use crate::PrecompileFailure;

/// Precompile addresses (last byte of the 20-byte address).
pub const ADDR_IS_DID_ACTIVE: u8 = 0x10;
pub const ADDR_VERIFY_CREDENTIAL: u8 = 0x11;
pub const ADDR_VERIFY_BBS_DISCLOSURE: u8 = 0x12;

const MAX_FIELD: usize = 64 * 1024;
const MAX_DISCLOSED: u32 = 64; // BBS_MAX_MESSAGE_COUNT

fn checked_leaf<'a>(
    reader: &mut InputReader<'a>,
    finalized_root: &[u8; 32],
) -> Result<(&'a [u8], &'a [u8]), PrecompileFailure> {
    let claimed_root = reader.read_root()?;
    if claimed_root != *finalized_root {
        return Err(PrecompileFailure::StaleRoot);
    }
    let key = reader.read_field(MAX_FIELD)?;
    let value = reader.read_field(MAX_FIELD)?;
    Ok((key, value))
}

fn checked_proof(
    reader: &mut InputReader<'_>,
    root: &[u8; 32],
    key: &[u8],
    value: &[u8],
) -> Result<(), PrecompileFailure> {
    let proof_bytes = reader.read_field(MAX_FIELD)?;
    let proof: InclusionProof = bincode::deserialize(proof_bytes)
        .map_err(|e| PrecompileFailure::Malformed(format!("proof decode: {e}")))?;
    if !verify_inclusion(root, key, value, &proof) {
        return Err(PrecompileFailure::ProofRejected);
    }
    Ok(())
}

/// `isDidActive(bytes did) → bool`
///
/// Input: `[32B claimed dids_root][did][did_document_leaf][smt_proof]`
/// (all variable fields u32-BE length-prefixed).
pub fn is_did_active(dids_root: &[u8; 32], input: &[u8]) -> Result<[u8; 32], PrecompileFailure> {
    let mut reader = InputReader::new(input);
    let (did, doc_bytes) = checked_leaf(&mut reader, dids_root)?;
    checked_proof(&mut reader, dids_root, did, doc_bytes)?;
    reader.finish()?;

    let doc = DidDocument::from_bytes(doc_bytes)
        .map_err(|e| PrecompileFailure::Malformed(format!("did document decode: {e}")))?;
    Ok(bool_word(doc.active))
}

/// `verifyCredential(bytes32 credentialId, bytes issuerDid) → bool`
///
/// Input: `[32B claimed credentials_root][credential_id][record_leaf]
/// [issuer_did][smt_proof]`.
pub fn verify_credential(
    credentials_root: &[u8; 32],
    input: &[u8],
) -> Result<[u8; 32], PrecompileFailure> {
    let mut reader = InputReader::new(input);
    let (cred_id, record_bytes) = checked_leaf(&mut reader, credentials_root)?;
    let issuer_did = reader.read_field(MAX_FIELD)?;
    checked_proof(&mut reader, credentials_root, cred_id, record_bytes)?;
    reader.finish()?;

    let record = CredentialRecord::from_bytes(record_bytes)
        .map_err(|e| PrecompileFailure::Malformed(format!("credential decode: {e}")))?;
    let ok = record.issuer_did.as_bytes() == issuer_did && !record.revoked;
    Ok(bool_word(ok))
}

/// `verifyBbsDisclosure(bytes presentation, bytes disclosedAttributes) → bool`
///
/// Input: `[32B claimed credentials_root][credential_id][record_leaf]
/// [smt_proof][header][presentation_header][u32 n_disclosed]
/// n × ([u32 index][message])[bbs_proof]`.
///
/// Verifies the BBS+ selective-disclosure proof against the on-chain
/// `bbs_pubkey` fetched (proof-verified) from the credential record.
pub fn verify_bbs_disclosure(
    credentials_root: &[u8; 32],
    input: &[u8],
) -> Result<[u8; 32], PrecompileFailure> {
    let mut reader = InputReader::new(input);
    let (cred_id, record_bytes) = checked_leaf(&mut reader, credentials_root)?;
    checked_proof(&mut reader, credentials_root, cred_id, record_bytes)?;

    let header = reader.read_field(MAX_FIELD)?;
    let ph = reader.read_field(MAX_FIELD)?;
    let n_disclosed = reader.read_u32()?;
    if n_disclosed > MAX_DISCLOSED {
        return Err(PrecompileFailure::Malformed(format!(
            "{n_disclosed} disclosed messages exceeds cap {MAX_DISCLOSED}"
        )));
    }
    let mut indices = Vec::with_capacity(n_disclosed as usize);
    let mut messages: Vec<&[u8]> = Vec::with_capacity(n_disclosed as usize);
    for _ in 0..n_disclosed {
        indices.push(reader.read_u32()? as usize);
        messages.push(reader.read_field(MAX_FIELD)?);
    }
    let bbs_proof_bytes = reader.read_field(MAX_FIELD)?;
    reader.finish()?;

    let record = CredentialRecord::from_bytes(record_bytes)
        .map_err(|e| PrecompileFailure::Malformed(format!("credential decode: {e}")))?;
    if record.revoked {
        return Ok(bool_word(false));
    }
    let Some(bbs_pubkey) = record.bbs_pubkey else {
        return Err(PrecompileFailure::Malformed(
            "credential carries no BBS+ public key".into(),
        ));
    };

    let pk = solidus_crypto::bbs::BbsPublicKey::from_bytes(&bbs_pubkey)
        .map_err(|e| PrecompileFailure::Malformed(format!("bbs pubkey: {e:?}")))?;
    let proof = solidus_crypto::bbs::BbsProof::from_bytes(bbs_proof_bytes)
        .map_err(|e| PrecompileFailure::Malformed(format!("bbs proof: {e:?}")))?;

    Ok(bool_word(
        proof.is_valid(&pk, header, ph, &indices, &messages),
    ))
}

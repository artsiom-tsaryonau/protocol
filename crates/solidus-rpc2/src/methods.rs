//! Pure JSON-RPC method handlers — parse params, call the backend, shape
//! JSON. No transport, no async: directly unit-testable.
//!
//! Wire conventions at the JSON boundary:
//! - addresses: base58 string (matches `Address::to_base58`)
//! - hashes / roots: lowercase hex string
//! - a submitted transaction: hex of its **bincode** encoding (R-WIRE —
//!   the v2 binary format; the client SDK bincodes and hex-wraps).

use serde_json::{json, Value};
use solidus_crypto::keys::Address;
use solidus_txns::types::{Event, Receipt, Transaction, TxStatus};

use crate::backend::{ProofError, RpcBackend};
use solidus_exec::StateKey;

/// A JSON-RPC-level error (bad params / not found / rejected submit).
#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("invalid params: {0}")]
    InvalidParams(String),
    #[error("not found")]
    NotFound,
    #[error("submit rejected: {0}")]
    SubmitRejected(String),
    /// A method this node deliberately does not serve.
    ///
    /// ⛔ DISTINCT FROM `NotFound` ON PURPOSE. "Refused by policy" and "no such
    /// thing" are different answers, and collapsing them lets a caller read a
    /// refusal as an absence.
    #[error("policy disabled: {0}")]
    PolicyDisabled(String),
    #[error("no finality evidence yet at or above the requested height")]
    NoEvidenceYet,
    #[error("state advanced while the proof was built; retry")]
    StateAdvancing,
}

fn param_str(params: &Value, idx: usize, name: &str) -> Result<String, RpcError> {
    // Accept both positional [..] and by-name {..} params.
    let v = if let Some(arr) = params.as_array() {
        arr.get(idx).cloned()
    } else if let Some(obj) = params.as_object() {
        obj.get(name).cloned()
    } else {
        None
    };
    match v {
        Some(Value::String(s)) => Ok(s),
        Some(_) => Err(RpcError::InvalidParams(format!("{name} must be a string"))),
        None => Err(RpcError::InvalidParams(format!("missing param {name}"))),
    }
}

fn param_u64(params: &Value, idx: usize, name: &str) -> Result<u64, RpcError> {
    let v = if let Some(arr) = params.as_array() {
        arr.get(idx).cloned()
    } else if let Some(obj) = params.as_object() {
        obj.get(name).cloned()
    } else {
        None
    };
    match v {
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| RpcError::InvalidParams(format!("{name} must be a u64"))),
        Some(Value::String(s)) => s
            .parse()
            .map_err(|_| RpcError::InvalidParams(format!("{name} must be a u64"))),
        _ => Err(RpcError::InvalidParams(format!("missing param {name}"))),
    }
}

fn parse_address(s: &str) -> Result<Address, RpcError> {
    Address::from_base58(s).map_err(|_| RpcError::InvalidParams(format!("bad address: {s}")))
}

fn parse_hash(s: &str) -> Result<[u8; 32], RpcError> {
    let bytes = hex::decode(s).map_err(|_| RpcError::InvalidParams("bad hex hash".into()))?;
    bytes
        .try_into()
        .map_err(|_| RpcError::InvalidParams("hash must be 32 bytes".into()))
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub fn get_balance(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_address(&param_str(params, 0, "address")?)?;
    Ok(json!(backend.balance(&addr).to_string()))
}

pub fn get_nonce(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_address(&param_str(params, 0, "address")?)?;
    Ok(json!(backend.nonce(&addr)))
}

pub fn get_block_height(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!(backend.block_height()))
}

/// One disclosed message: its position in the originally signed vector, and
/// the message bytes as lowercase hex.
struct Disclosed {
    index: u32,
    message: Vec<u8>,
}

/// Parse and VALIDATE the disclosed-message set.
///
/// ⛔ THESE CHECKS ARE SECURITY, NOT TIDINESS, AND THEY RUN BEFORE ANY CRYPTO.
/// A duplicate index or an index at/beyond `total_message_count` describes a
/// disclosure set that does not correspond to what the issuer signed. Rejecting
/// them here means the verifier is never handed a malformed set to interpret.
fn parse_disclosed(params: &Value, total: u32) -> Result<Vec<Disclosed>, RpcError> {
    let raw = if let Some(arr) = params.as_array() {
        arr.get(4).cloned()
    } else if let Some(obj) = params.as_object() {
        obj.get("disclosed_messages").cloned()
    } else {
        None
    };
    let list = raw
        .and_then(|v| v.as_array().cloned())
        .ok_or_else(|| RpcError::InvalidParams("missing param disclosed_messages".into()))?;

    let mut out: Vec<Disclosed> = Vec::with_capacity(list.len());
    for item in &list {
        let index = item
            .get("index")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| RpcError::InvalidParams("disclosed message missing index".into()))?
            as u32;
        let hexstr = item
            .get("message")
            .and_then(|v| v.as_str())
            .ok_or_else(|| RpcError::InvalidParams("disclosed message missing message".into()))?;
        let message = hex::decode(hexstr)
            .map_err(|e| RpcError::InvalidParams(format!("invalid message hex: {e}")))?;
        out.push(Disclosed { index, message });
    }

    out.sort_by_key(|d| d.index);
    for w in out.windows(2) {
        if w[0].index == w[1].index {
            return Err(RpcError::InvalidParams("duplicate disclosed index".into()));
        }
    }
    if let Some(last) = out.last() {
        if last.index >= total {
            return Err(RpcError::InvalidParams(format!(
                "disclosed index {} >= total_message_count {}",
                last.index, total
            )));
        }
    }
    Ok(out)
}

/// Run BBS+ proof verification over an already-validated disclosure set.
fn verify_bbs(
    pubkey: &[u8; 96],
    proof_hex: &str,
    header_hex: &str,
    ph_hex: &str,
    disclosed: &[Disclosed],
) -> Result<bool, RpcError> {
    let pk = solidus_crypto::bbs::BbsPublicKey::from_hex(&hex::encode(pubkey))
        .map_err(|e| RpcError::InvalidParams(format!("invalid pubkey: {e}")))?;
    let proof = solidus_crypto::bbs::BbsProof::from_hex(proof_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid proof hex: {e}")))?;
    let header = hex::decode(header_hex)
        .map_err(|e| RpcError::InvalidParams(format!("invalid header hex: {e}")))?;
    let ph =
        hex::decode(ph_hex).map_err(|e| RpcError::InvalidParams(format!("invalid ph hex: {e}")))?;

    let indices: Vec<usize> = disclosed.iter().map(|d| d.index as usize).collect();
    let msgs: Vec<&[u8]> = disclosed.iter().map(|d| d.message.as_slice()).collect();
    Ok(proof.is_valid(&pk, &header, &ph, &indices, &msgs))
}

/// `solidus_bbsVerifyProof` - verify a selective-disclosure proof, statelessly.
///
/// ⚠ All hex inputs are lowercase. Returns `true` iff the proof is
/// cryptographically valid; a malformed input is an ERROR, never `false`.
/// Reporting `false` for input this node could not parse would state that the
/// proof failed verification, which it never ran.
pub fn bbs_verify_proof(_b: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let proof_hex = param_str(params, 0, "proof_hex")?;
    let pubkey_hex = param_str(params, 1, "pubkey_hex")?;
    let header_hex = param_str(params, 2, "header_hex")?;
    let ph_hex = param_str(params, 3, "ph_hex")?;
    let total = param_u64(params, 5, "total_message_count")? as u32;

    let disclosed = parse_disclosed(params, total)?;
    let pk_bytes: [u8; 96] = hex::decode(&pubkey_hex)
        .ok()
        .and_then(|b| <[u8; 96]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| RpcError::InvalidParams("invalid pubkey hex".into()))?;

    Ok(json!(verify_bbs(
        &pk_bytes,
        &proof_hex,
        &header_hex,
        &ph_hex,
        &disclosed
    )?))
}

/// `solidus_bbsVerifyCredentialProof` - proof validity combined with on-chain
/// credential state.
///
/// ⛔ `valid` IS PROOF-VALID **AND** NOT-REVOKED. A proof can verify perfectly
/// against a credential revoked after the proof was generated, which is why
/// `proof_valid` is reported separately rather than folded in. Collapsing them
/// would let a revoked credential present as usable.
pub fn bbs_verify_credential_proof(
    backend: &dyn RpcBackend,
    params: &Value,
) -> Result<Value, RpcError> {
    let credential_id = param_str(params, 0, "credential_id")?;
    let proof_hex = param_str(params, 1, "proof_hex")?;
    let header_hex = param_str(params, 2, "header_hex")?;
    let ph_hex = param_str(params, 3, "ph_hex")?;

    let Some(c) = backend.credential(&credential_id) else {
        return Ok(json!({
            "valid": false,
            "proof_valid": false,
            "is_bbs": false,
            "revoked": false,
            "credential": Value::Null,
        }));
    };

    // Not a BBS+ credential: say so rather than running a verification that
    // cannot apply and reporting its result.
    let (Some(pk), Some(total)) = (c.bbs_pubkey, c.bbs_message_count) else {
        return Ok(json!({
            "valid": false,
            "proof_valid": false,
            "is_bbs": false,
            "revoked": c.revoked,
            "credential": credential_record_json(&c),
        }));
    };

    let disclosed = parse_disclosed(params, total)?;
    let proof_valid = verify_bbs(&pk, &proof_hex, &header_hex, &ph_hex, &disclosed)?;

    Ok(json!({
        "valid": proof_valid && !c.revoked,
        "proof_valid": proof_valid,
        "is_bbs": true,
        "revoked": c.revoked,
        "credential": credential_record_json(&c),
    }))
}

/// `solidus_credentialsByIssuer` - every credential an issuer DID issued.
///
/// ⚠ UNGATED, unlike `credentialsBySubject`, and the asymmetry is the point.
/// Enumerating a subject's credentials is a correlation handle over a person;
/// enumerating what an issuer issued is a property of a public entity. v1 gates
/// the first and not the second.
///
/// ⚠ An id in the index with no credential behind it is SKIPPED and reported on
/// stderr, not silently dropped and not fatal. It means the index and the
/// records disagree, which a reader should learn about, but refusing the whole
/// query would punish a caller for a node-side inconsistency.
pub fn credentials_by_issuer(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let did = param_str(params, 0, "did")?;
    let ids = backend.credential_ids_by_issuer(&did);
    let mut records = Vec::with_capacity(ids.len());
    for id in &ids {
        match backend.credential(id) {
            Some(c) => records.push(credential_record_json(&c)),
            None => eprintln!(
                "solidus-rpc2: credential index for issuer {did} references missing credential {id}"
            ),
        }
    }
    Ok(json!(records))
}

/// Shape one validator for the wire.
///
/// ⛔ FIVE FIELDS, NOT SIX. `ValidatorInfo` also carries `unbonding_start_ms`
/// and v1 does not emit it. Enumerated rather than serialised for the same
/// reason as the credential record: a field added to the chain type must not
/// leave the node until someone decides it should.
fn validator_json(v: &solidus_txns::staking::ValidatorInfo) -> Value {
    json!({
        "address": v.address.to_base58(),
        "staked": v.staked,
        "unbonding": v.unbonding,
        "reputation": v.reputation,
        "active": v.active,
    })
}

/// `solidus_getValidators` - every validator in committed state.
pub fn get_validators(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    let mut out: Vec<Value> = backend.validators().iter().map(validator_json).collect();
    // Sorted by address so repeated calls agree. RocksDB iteration order is
    // stable, but a caller diffing two responses should not depend on that.
    out.sort_by(|a, b| {
        a.get("address")
            .and_then(|v| v.as_str())
            .cmp(&b.get("address").and_then(|v| v.as_str()))
    });
    Ok(json!(out))
}

/// `solidus_getValidatorStake` - one validator by base58 address, or `null`.
pub fn get_validator_stake(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let addr = parse_address(&param_str(params, 0, "address")?)?;
    Ok(match backend.validator(&addr) {
        Some(v) => validator_json(&v),
        None => Value::Null,
    })
}

/// The credential fields permitted to leave the node.
///
/// ⛔ ONE WHITELIST, USED BY EVERY METHOD THAT RETURNS A CREDENTIAL. Two copies
/// would drift, and the copy someone forgets is the one that leaks. v1's
/// comment records the property this preserves: adding `subject_commitment` to
/// the chain record did NOT expose it by accident.
///
/// ⚠ Optional fields are OMITTED when absent rather than emitted as null,
/// matching v1's `skip_serializing_if`. A caller distinguishes "not a BBS+
/// credential" from "BBS+ with no key" by presence, so null would change the
/// meaning rather than merely add noise.
fn credential_record_json(c: &solidus_txns::credential::CredentialRecord) -> Value {
    let mut record = json!({
        "id": c.id,
        "issuer_did": c.issuer_did,
        "subject_did": c.subject_did,
        "credential_type": format!("{:?}", c.credential_type),
        "hash": hex::encode(c.hash),
        "issued_ms": c.issued_ms,
        "revoked": c.revoked,
        "revoked_ms": c.revoked_ms,
    });
    if let Some(obj) = record.as_object_mut() {
        if let Some(sc) = c.subject_commitment {
            obj.insert("subject_commitment".into(), json!(hex::encode(sc)));
        }
        if let Some(pk) = c.bbs_pubkey {
            obj.insert("bbs_pubkey".into(), json!(hex::encode(pk)));
        }
        if let Some(n) = c.bbs_message_count {
            obj.insert("bbs_message_count".into(), json!(n));
        }
    }
    record
}

/// `solidus_credentialsBySubject` - every credential held by a subject DID.
///
/// ⛔ REFUSED BY DEFAULT, AND THE REFUSAL IS THE FEATURE. Enumerating every
/// credential a subject holds is a correlation handle. That gate was closed
/// deliberately on v1 as a privacy fix; porting this method "working" would
/// silently reopen it.
///
/// ⛔ IT ERRORS RATHER THAN RETURNING `[]`. An empty list asserts "this DID
/// holds no credentials" - a statement the node never computed, and false for
/// most subjects. Never report a result you did not compute. An error is also
/// unambiguous, where an empty list looks like a successful query.
/// `solidus_credentialsByCommitment` - a holder's own credentials, on v2.
///
/// ⛔ UNGATED, AND THAT IS THE WHOLE DESIGN RATHER THAN AN OVERSIGHT.
/// `solidus_credentialsBySubject` is refused because a subject DID turns one
/// identifier into a profile of everything that person holds, and a node-wide
/// boolean cannot tell a holder listing their OWN credentials from an observer
/// profiling them.
///
/// A commitment tells the two apart by construction. It is
/// `BLAKE3(domain ‖ subject_did ‖ nonce32)`, the nonce is 32 bytes from the
/// issuer's CSPRNG, and it reaches only the holder — off-chain, with the
/// credential. **Presenting a commitment IS the proof that you are the holder**,
/// because an observer who knows the DID still cannot compute it. So this needs
/// no policy switch: the capability is the secret.
///
/// ⚠ This is the fix `identity/src/lib/enumeration-refused.ts` names as
/// preference 1. That file returns an EMPTY LIST on refusal and says in its own
/// words that the day a credential exists, that becomes a lie — a holder told
/// they have none. This is what stops it becoming one.
pub fn credentials_by_commitment(
    backend: &dyn RpcBackend,
    params: &Value,
) -> Result<Value, RpcError> {
    let commitment = param_str(params, 0, "subjectCommitment")?;
    // Validated rather than passed through: the index is keyed by LOWERCASE hex
    // of exactly 32 bytes, so anything else is a caller error and must say so
    // rather than return an empty list that reads as "you hold nothing".
    let bytes = parse_hash(&commitment)?;
    let key = solidus_txns::credential::subject_commitment_index_key(&bytes);

    let records: Vec<Value> = backend
        .credential_ids_by_subject(&key)
        .iter()
        .filter_map(|id| backend.credential(id))
        .map(|c| credential_record_json(&c))
        .collect();
    Ok(Value::Array(records))
}

pub fn credentials_by_subject(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    if !backend.subject_enumeration_allowed() {
        return Err(RpcError::PolicyDisabled(
            concat!(
                "solidus_credentialsBySubject is disabled on this node: enumerating ",
                "every credential held by a subject DID is a correlation handle. ",
                "Query a known credential by id with solidus_credentialVerify, or ",
                "run a node with subject enumeration explicitly enabled.",
            )
            .to_string(),
        ));
    }
    let did = param_str(params, 0, "did")?;
    let records: Vec<Value> = backend
        .credential_ids_by_subject(&did)
        .iter()
        .filter_map(|id| backend.credential(id))
        .map(|c| credential_record_json(&c))
        .collect();
    Ok(json!(records))
}

/// `solidus_credentialVerify` - validity plus the credential record, or `null`.
///
/// ⛔ THE FIELD LIST IS A WHITELIST AND THAT IS A SECURITY PROPERTY, NOT STYLE.
/// v1's `RpcCredentialRecord` exists precisely so the response "enumerates what
/// leaves the node rather than deriving itself from `CredentialRecord`", and
/// its comment records that adding `subject_commitment` to the chain record did
/// NOT expose it here by accident. This repo has already leaked KYC internals
/// and a pricing enum through a denylist; a new field on the domain type must
/// stay invisible here until someone adds it deliberately.
///
/// ⚠ So: never `serde_json::to_value(&record)`. Enumerate.
pub fn credential_verify(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let id = param_str(params, 0, "credentialId")?;
    let Some(c) = backend.credential(&id) else {
        return Ok(Value::Null);
    };

    let record = credential_record_json(&c);
    Ok(json!({
        // `valid` is existence AND not-revoked, per v1's own field comment.
        "valid": !c.revoked,
        "credential": record,
        "revoked": c.revoked,
    }))
}

/// `solidus_didResolve` - a DID document, or `null`.
///
/// ⛔ BUILT BY HAND, NOT BY SERDE, AND THAT IS THE POINT. v1 shapes this with
/// `#[serde(rename)]` plus a flattened legacy struct; reproducing it through
/// the same indirection is how a key name silently changes. Every key below is
/// written out, so a diff shows a rename and a test can pin one by name.
///
/// ⛔ EVERY DID CORE PROPERTY IS EMITTED TWICE, W3C camelCase AND legacy
/// snake_case. v1's comment: the published npm SDK reads `verification_method`
/// and friends, the repo SDK reads camelCase first and falls back, and
/// "emitting both is the only shape that serves an installed integrator and a
/// conformant JSON-LD processor at once". DO NOT drop the legacy names while
/// porting - that is a separate decision with an npm release attached.
pub fn did_resolve(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let did = param_str(params, 0, "did")?;
    let Some(doc) = backend.did_document(&did) else {
        return Ok(Value::Null);
    };

    // ⚠ TWO KEY ENCODINGS PER METHOD, BOTH REQUIRED.
    // `publicKeyMultibase` is multicodec-prefixed, not the raw key, and is
    // `null` rather than wrong when the key is not 32 bytes - a wrong value
    // would be worse than an absent one. `publicKeyHex` is in no W3C spec and
    // ships only because the npm SDK still reads it.
    let vms: Vec<Value> = doc
        .verification_method
        .iter()
        .map(|vm| {
            let multibase = hex::decode(&vm.public_key_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .map(|k| solidus_crypto::keys::public_key_multibase(&k));
            json!({
                "id": vm.id,
                "type": vm.method_type,
                "controller": vm.controller,
                "publicKeyMultibase": multibase,
                "publicKeyHex": vm.public_key_hex,
            })
        })
        .collect();

    // ⛔ W3C NAMES, BUILT EXPLICITLY. Serialising `doc.service` directly emits
    // the RUST field names — `service_type` and `service_endpoint` — because the
    // struct carries no serde renames. Every other field in this response is
    // deliberately W3C-named, so a verbatim service array was the one place the
    // document stopped being a DID document.
    //
    // ⚠ IT FAILED SILENTLY, WHICH IS WHY THIS IS NOT COSMETIC. auth's
    // `resolveWebId` finds the pod with `s.type === 'SolidPod'` and then reads
    // `serviceEndpoint`; against the verbatim shape BOTH are `undefined`, so it
    // returned null, sign-in proceeded WITHOUT a WebID, and the DID-to-pod
    // binding was quietly gone. v1 has always emitted the W3C names
    // (`solidus-rpc/src/types.rs`), so this is v2 catching up, not a new
    // convention.
    let service = Value::Array(
        doc.service
            .iter()
            .map(|svc| {
                json!({
                    "id": svc.id,
                    "type": svc.service_type,
                    "serviceEndpoint": svc.service_endpoint,
                })
            })
            .collect::<Vec<Value>>(),
    );

    Ok(json!({
        // W3C DID Core names.
        "@context": doc.context,
        "id": doc.id,
        "controller": doc.controller,
        "verificationMethod": vms,
        "authentication": doc.authentication,
        "assertionMethod": doc.assertion_method,
        "keyAgreement": doc.key_agreement,
        "capabilityInvocation": doc.capability_invocation,
        "capabilityDelegation": doc.capability_delegation,
        // The same values under the pre-2026-08-25 names the published SDK reads.
        "context": doc.context,
        "verification_method": vms,
        "assertion_method": doc.assertion_method,
        "key_agreement": doc.key_agreement,
        "capability_invocation": doc.capability_invocation,
        "capability_delegation": doc.capability_delegation,
        // Non-duplicated fields.
        "service": service,
        "active": doc.active,
        "created_ms": doc.created_ms,
        "updated_ms": doc.updated_ms,
        "version_id": doc.version_id,
        "recovery_policy": serde_json::to_value(&doc.recovery_policy).unwrap_or(Value::Null),
        "recovery_nonce": doc.recovery_nonce,
    }))
}

/// `solidus_getBlock` - a committed block by height, or `null`.
///
/// ⚠ SHAPE DIVERGES FROM v1 ON PURPOSE. See [`RpcBlock`]: v2 has no
/// transactions root, and its `exec_state_root` trails the block rather than
/// describing its post-state, so it is not emitted as `state_root`.
pub fn get_block(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let height = param_u64(params, 0, "height")?;
    Ok(match backend.block_at(height) {
        Some(b) => serde_json::to_value(b).unwrap_or(Value::Null),
        None => Value::Null,
    })
}

/// `solidus_getLatestBlock` - the newest committed block, or `null`.
///
/// Reads the PERSISTED head rather than the exec anchor, so it can never name a
/// height whose block this node cannot actually produce.
pub fn get_latest_block(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    let Some((height, _)) = backend.canon_head() else {
        return Ok(Value::Null);
    };
    Ok(match backend.block_at(height) {
        Some(b) => serde_json::to_value(b).unwrap_or(Value::Null),
        None => Value::Null,
    })
}

/// Best-effort resident set size of this process, in bytes.
///
/// Reads `/proc/self/statm` on Linux and returns 0 elsewhere, matching v1. A
/// zero here means "not measurable on this platform", not "no memory used".
fn current_rss_bytes() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(statm) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(resident_pages) = statm.split_whitespace().nth(1) {
                if let Ok(pages) = resident_pages.parse::<u64>() {
                    return pages * 4096;
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// `solidus_getTransaction` - a committed transaction by hash, or `null`.
///
/// ⛔ v2 DOES NOT SCAN. v1 answers this by walking every block backwards from
/// the tip - its comment: "This is O(blocks) which is acceptable for testnet" -
/// which at 1.8M blocks is not. v2 reads a `tx_hash -> height` index written on
/// the commit path, then resolves the body from that block's batches.
///
/// ⚠ `null` HERE MEANS "NOT FOUND ON THIS NODE", NOT "NEVER EXISTED". After
/// pruning, the index entry and the batch body are both gone. A caller must not
/// read this as proof a transaction was never committed.
pub fn get_transaction(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let hex_hash = param_str(params, 0, "tx_hash")?;
    let bytes = hex::decode(&hex_hash)
        .map_err(|e| RpcError::InvalidParams(format!("invalid hex hash: {e}")))?;
    // Length is checked explicitly so a short hash is a clear error rather than
    // a silent miss that looks like "no such transaction".
    let hash: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        RpcError::InvalidParams(format!(
            "invalid hash length: expected 32 bytes, got {}",
            bytes.len()
        ))
    })?;
    Ok(match backend.transaction(&hash) {
        Some(tx) => serde_json::to_value(tx).unwrap_or(Value::Null),
        None => Value::Null,
    })
}

/// `solidus_nodeInfo` - process metadata.
///
/// Shape measured live from v1 on 2026-09-02:
/// `{"version":str,"uptime_seconds":u64,"rss_bytes":u64}`.
pub fn node_info(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": backend.uptime_seconds(),
        "rss_bytes": current_rss_bytes(),
    }))
}

/// `solidus_getBlockBySeq` - v1's name for a block by its sequence number.
///
/// ⚠ AN ALIAS, because in v2 sequence IS height: `canon` is keyed by height and
/// there is no separate sequence space. Registering it means an estate caller
/// using v1's name keeps working rather than failing on a name v2 chose
/// differently.
pub fn get_block_by_seq(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    get_block(backend, params)
}

/// `solidus_chainInfo` - network identity and tip.
///
/// Shape measured live from v1 on 2026-09-02:
///   {"chain_id":"solidus-testnet-1","native_token":{"symbol","name","decimals"},
///    "genesis_hash":hex,"latest_block":u64,"version":str}
///
/// ⚠ `chain_id` CARRIES THE NETWORK NAME, NOT THE NUMBER. v2's numeric chain id
/// is 50002; v1 puts a string here. Serving the number would type-check and
/// break every caller that reads it.
///
/// ⚠ `latest_block` IS THE EXEC ANCHOR, matching v1, where it read 94,707 while
/// canonHead.seq read 92,928. The two are different questions and both are
/// served, unchanged, rather than reconciled into one number that answers
/// neither.
pub fn chain_info(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    let (network, genesis) = backend.chain_identity();
    let next = backend.block_height().saturating_add(1);
    let v2 =
        solidus_exec::protocol::version_at(next) >= solidus_exec::protocol::ProtocolVersion::V2;
    Ok(json!({
        "chain_id": network,
        "chainIdNumeric": backend.chain_id_numeric(),
        "protocolVersion": if v2 { "v2" } else { "v1" },
        "wire": if v2 { "binary-v3" } else { "binary-v2" },
        "native_token": { "symbol": "SLDS", "name": "Solidus", "decimals": 8 },
        "genesis_hash": hex::encode(genesis),
        "latest_block": backend.block_height(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// `solidus_canonHead` - the persisted canonical head, or `null`.
///
/// Shape matches v1 exactly: `{ "seq": u64, "hash": hex }`. Measured against
/// the LIVE v1 endpoint on 2026-09-02 rather than read off a struct, because
/// the wire shape is the contract and a struct is only one way to produce it.
pub fn canon_head(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(match backend.canon_head() {
        Some((seq, hash)) => json!({ "seq": seq, "hash": hex::encode(hash) }),
        None => Value::Null,
    })
}

/// `solidus_blockNumber` - v1's name for the newest committed height.
///
/// An alias, deliberately. v2 already serves this number as `getBlockHeight`.
/// The estate calls `blockNumber` at 21 sites, so v2 not answering it blocks
/// migration for no reason other than a name. Both names answer, and neither
/// is deprecated out from under a caller.
pub fn block_number(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!(backend.block_height()))
}

pub fn get_state_root(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    Ok(json!(hex::encode(backend.state_root())))
}

pub fn get_receipt(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    // ⛔ TWO SHAPES, AND THE ONE-ARGUMENT FORM IS WHY ANY CLIENT CAN CONFIRM A
    // TRANSACTION AT ALL. A submitter gets back a HASH; v1 let it poll on that
    // alone. Requiring `[height, txHash]` meant an SDK ported from v1 could
    // submit successfully and then never learn the outcome, because the height
    // is exactly the thing it does not have.
    //
    // The store has always carried `tx_index` (tx_hash → height), so the
    // one-argument form is a lookup rather than a scan. `[height, txHash]`
    // still works untouched, and is strictly cheaper when the caller knows the
    // height — a block explorer walking a range, for instance.
    let (height, tx_hash) = match params.get(1) {
        Some(_) => (
            param_u64(params, 0, "height")?,
            parse_hash(&param_str(params, 1, "txHash")?)?,
        ),
        None => {
            let tx_hash = parse_hash(&param_str(params, 0, "txHash")?)?;
            // ⚠ NOT FOUND rather than an error: a transaction that has not been
            // included YET is the normal case while polling, and a poller must
            // be able to tell "not yet" from "malformed request".
            let height = backend.tx_height(&tx_hash).ok_or(RpcError::NotFound)?;
            (height, tx_hash)
        }
    };
    let receipt = backend
        .receipt(height, &tx_hash)
        .ok_or(RpcError::NotFound)?;
    Ok(receipt_to_json(&receipt))
}

pub fn submit_transaction(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let hex_tx = param_str(params, 0, "transaction")?;
    let bytes = hex::decode(&hex_tx)
        .map_err(|_| RpcError::InvalidParams("transaction must be hex".into()))?;
    let tx: Transaction = bincode::deserialize(&bytes)
        .map_err(|e| RpcError::InvalidParams(format!("undecodable transaction: {e}")))?;
    let tx_hash = backend.submit(tx).map_err(RpcError::SubmitRejected)?;
    Ok(json!(hex::encode(tx_hash)))
}

fn receipt_to_json(receipt: &Receipt) -> Value {
    let (status, reason) = match &receipt.status {
        TxStatus::Success => ("success", Value::Null),
        TxStatus::Failed(r) => ("failed", json!(r)),
    };
    let tx_hash_hex = hex::encode(receipt.tx_hash);
    json!({
        "txHash": tx_hash_hex,
        "status": status,
        "failureReason": reason,
        "blockHeight": receipt.block_height,
        "feePaid": receipt.fee_paid.to_string(),
        "eventCount": receipt.events.len(),

        // ⛔ THE v1 KEY NAMES, EMITTED ALONGSIDE, BECAUSE rpc.solidus.network IS
        // BEING REPOINTED AT THIS CHAIN AND KEEPS ITS ADDRESS. A published
        // caller cannot be upgraded, so the endpoint has to speak both.
        //
        // ⚠ THE ONE THAT MATTERS IS `tx_hash`, AND THIS FILE ALREADY RECORDS WHY
        // a few lines above. @solidus-network/sdk 0.6.5, measured from the npm
        // tarball rather than from our tree, computes a credential id as
        // `<from events> ?? urn:solidus:credential:${receipt.tx_hash}`. Reading
        // `tx_hash` off a v2 receipt gives undefined, so the moment the event
        // lookup misses, EVERY credential is assigned the same permanent id,
        // `urn:solidus:credential:undefined`, silently. The events array added
        // earlier makes the primary path work; this makes the BACKSTOP work.
        //
        // ⚠ `fee_paid` IS A NUMBER HERE AND `feePaid` IS A STRING, DELIBERATELY.
        // v1 emitted a u64; v2 emits a string because a fee can exceed 2^53 and
        // JSON has no integer type. Each key keeps the type its own readers
        // already expect, rather than one key changing shape by version.
        //
        // ⚠ `status` IS NOT ALIASED. v1 encodes a failure as "failed: <reason>"
        // while v2 uses "failed" plus `failureReason`. Both satisfy the only
        // check the published SDK makes, `status.startsWith("success")`, and
        // rewriting the string would break v2 readers to help nobody.
        "tx_hash": tx_hash_hex,
        "block_height": receipt.block_height,
        "fee_paid": receipt.fee_paid,
        // ⛔ THE EVENTS THEMSELVES, NOT ONLY A COUNT. A count cannot carry the
        // one thing a submitter needs back: the id the chain assigned. The SDK
        // reads `CredentialIssued`/`CredentialIssuedV2` out of this array, and
        // against a count-only receipt it read `undefined`, threw on `.find`,
        // and — once guarded — fell through to
        // `urn:solidus:credential:${receipt.tx_hash}`, which is ALSO absent
        // here. Every credential would have been assigned the same id,
        // `urn:solidus:credential:undefined`, silently and permanently.
        //
        // `eventCount` stays: it predates this and something may read it.
        "events": receipt.events.iter().map(event_to_json).collect::<Vec<_>>(),
    })
}

/// One [`Event`] as JSON, matching what v1 emits key-for-key.
///
/// ⚠ DUPLICATED FROM `solidus-rpc/src/types.rs` ON PURPOSE, AND THE TESTS ARE
/// WHAT KEEP THEM HONEST. Sharing it would mean `solidus-rpc2` depending on the
/// v1 crate, which is exactly the coupling the v2 stack was built without. The
/// shapes are asserted here so a drift is a failing test rather than a client
/// that reads `undefined` off a live chain.
fn event_to_json(event: &Event) -> Value {
    match event {
        Event::Transfer { from, to, amount } => json!({
            "type": "Transfer",
            "from": from.to_base58(),
            "to": to.to_base58(),
            "amount": amount,
        }),
        Event::DidCreated { did, controller } => json!({
            "type": "DidCreated",
            "did": did,
            "controller": controller.to_base58(),
        }),
        Event::DidUpdated { did } => json!({ "type": "DidUpdated", "did": did }),
        Event::DidDeactivated { did } => json!({ "type": "DidDeactivated", "did": did }),
        Event::DidRecovered { did } => json!({ "type": "DidRecovered", "did": did }),
        Event::CredentialIssued {
            credential_id,
            issuer,
            subject,
        } => json!({
            "type": "CredentialIssued",
            "credentialId": credential_id,
            "issuer": issuer,
            "subject": subject,
        }),
        // ⛔ NOTE THE ABSENT FIELD, AND DO NOT ADD IT. This deliberately does
        // NOT emit `subject`. Receipts are served publicly by
        // `solidus_getReceipt`, so an event is a PUBLICATION SURFACE — dropping
        // `subject_did` from the payload while the event still republished it
        // would move the leak rather than close it, which is the exact mistake
        // the 2026-08-20 measurement caught in the original plan. The
        // commitment is safe to emit: it is already on-chain in the record and
        // reveals nothing without the issuer's nonce.
        Event::CredentialIssuedV2 {
            credential_id,
            issuer,
            subject_commitment,
        } => json!({
            "type": "CredentialIssuedV2",
            "credentialId": credential_id,
            "issuer": issuer,
            "subjectCommitment": hex::encode(subject_commitment),
        }),
        Event::CredentialRevoked { credential_id } => json!({
            "type": "CredentialRevoked",
            "credentialId": credential_id,
        }),
        Event::Staked {
            validator,
            amount,
            total_stake,
        } => json!({
            "type": "Staked",
            "validator": validator.to_base58(),
            "amount": amount,
            "totalStake": total_stake,
        }),
        Event::Unstaked {
            validator,
            amount,
            remaining_stake,
        } => json!({
            "type": "Unstaked",
            "validator": validator.to_base58(),
            "amount": amount,
            "remainingStake": remaining_stake,
        }),
        Event::ComputeAdmitted { operator, tier } => json!({
            "type": "ComputeAdmitted",
            "operator": operator.to_base58(),
            "tier": tier_str(tier),
        }),
        Event::ComputeRemoved { operator } => json!({
            "type": "ComputeRemoved",
            "operator": operator.to_base58(),
        }),
        Event::ComputeRegistered {
            operator,
            jurisdiction,
            tier,
        } => json!({
            "type": "ComputeRegistered",
            "operator": operator.to_base58(),
            "jurisdiction": jurisdiction,
            "tier": tier_str(tier),
        }),
        Event::ComputeAnchored {
            merkle_root,
            batch_count,
        } => json!({
            "type": "ComputeAnchored",
            "merkleRoot": hex::encode(merkle_root),
            "batchCount": batch_count,
        }),
        Event::ComputeSlashed {
            operator,
            severe,
            reputation,
        } => json!({
            "type": "ComputeSlashed",
            "operator": operator.to_base58(),
            "severe": severe,
            "reputation": reputation,
        }),
        // Bridge events (bridge plan 02), key-for-key with `solidus-rpc`.
        Event::BridgeDomainRegistered { domain, enabled } => json!({
            "type": "BridgeDomainRegistered",
            "domain": domain,
            "enabled": enabled,
        }),
        Event::BridgeTrustRootSet { did, enabled } => json!({
            "type": "BridgeTrustRootSet",
            "did": did,
            "enabled": enabled,
        }),
        Event::CredentialExported {
            credential_id,
            domain,
            export_id,
        } => json!({
            "type": "CredentialExported",
            "credentialId": credential_id,
            "domain": domain,
            "exportId": hex::encode(export_id),
        }),
        Event::CredentialUnexported {
            credential_id,
            domain,
            export_id,
        } => json!({
            "type": "CredentialUnexported",
            "credentialId": credential_id,
            "domain": domain,
            "exportId": hex::encode(export_id),
        }),
        Event::BridgeMessageQueued {
            domain,
            domain_seq,
            kind,
            message_id,
        } => json!({
            "type": "BridgeMessageQueued",
            "domain": domain,
            "domainSeq": domain_seq,
            "kind": kind,
            "messageId": hex::encode(message_id),
        }),
    }
}

fn tier_str(tier: &solidus_txns::compute::ComputeTier) -> &'static str {
    match tier {
        solidus_txns::compute::ComputeTier::Trusted => "trusted",
        solidus_txns::compute::ComputeTier::Attested => "attested",
    }
}

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn decode_state<T: serde::de::DeserializeOwned>(
    backend: &dyn RpcBackend,
    key: &StateKey,
) -> Option<T> {
    backend
        .state_value(key)
        .and_then(|b| bincode::deserialize(&b).ok())
}

/// `solidus_getBridgeDomains`.
pub fn get_bridge_domains(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    let index: Vec<u32> =
        decode_state(backend, &StateKey::bridge_domains_index()).unwrap_or_default();
    let domains: Vec<Value> = index
        .into_iter()
        .filter_map(|d| {
            decode_state::<solidus_txns::bridge::BridgeDomain>(backend, &StateKey::bridge_domain(d))
        })
        .map(|d| {
            json!({
                "domain": d.domain, "vm": d.vm.code(), "inbox": hex0x(&d.inbox),
                "heartbeatIntervalSecs": d.heartbeat_interval_secs, "enabled": d.enabled,
            })
        })
        .collect();
    Ok(json!({ "domains": domains }))
}

/// `solidus_getBridgeMessages` - a page of one domain's outbox, in sequence order.
pub fn get_bridge_messages(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let domain = u32::try_from(param_u64(params, 0, "domain")?)
        .map_err(|_| RpcError::InvalidParams("domain must fit in u32".into()))?;
    let from = param_u64(params, 1, "fromSeq")?.max(1);
    let limit = param_u64(params, 2, "limit")?;
    if limit == 0 || limit > 500 {
        return Err(RpcError::InvalidParams(
            "limit must be between 1 and 500".into(),
        ));
    }
    let last = backend
        .state_value(&StateKey::bridge_seq(domain))
        .and_then(|b| <[u8; 8]>::try_from(b.as_slice()).ok())
        .map(u64::from_le_bytes)
        .unwrap_or(0);
    let to = last.min(from.saturating_add(limit - 1));
    let mut messages = Vec::new();
    for seq in from..=to {
        let Some(entry) = decode_state::<solidus_txns::bridge::OutboxEntry>(
            backend,
            &StateKey::bridge_outbox(domain, seq),
        ) else {
            break;
        };
        messages.push(json!({
            "domainSeq": seq, "solidusHeight": entry.solidus_height,
            "message": hex0x(&entry.message), "messageId": hex0x(&solidus_bridge_codec::keccak256(&entry.message)),
        }));
    }
    Ok(json!({ "messages": messages, "lastSeq": last }))
}

/// `solidus_getBridgeAttestation` (registry §2.8) - THIS NODE'S signatures for a range of one
/// domain's outbox, inclusive, at most 500 sequences.
///
/// ⚠ ONE NODE'S SIGNATURES, NOT AN ASSEMBLED SET. Four validators means four calls, and the
/// gateway (§3.3) puts them together. The top-level `signer` is what tells a caller whose
/// signatures it is holding, which is why it is present even when the list is empty.
///
/// ⛔ A SEQUENCE THIS NODE HAS NOT SIGNED IS OMITTED, NEVER RETURNED WITH A NULL SIGNATURE. An
/// entry with `"signature": null` reads as "signed with nothing" to anything scanning the list,
/// and an assembler counting entries would count it toward the threshold.
pub fn get_bridge_attestation(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let domain = u32::try_from(param_u64(params, 0, "domain")?)
        .map_err(|_| RpcError::InvalidParams("domain must fit in u32".into()))?;
    let from = param_u64(params, 1, "fromSeq")?.max(1);
    let to = param_u64(params, 2, "toSeq")?;
    if to < from {
        return Err(RpcError::InvalidParams("toSeq must be >= fromSeq".into()));
    }
    // Inclusive, so 500 entries is `to - from == 499`.
    if to - from >= 500 {
        return Err(RpcError::InvalidParams(
            "the range must cover at most 500 sequences".into(),
        ));
    }

    let signer = backend.attestation_signer();
    let mut attestations = Vec::new();
    for seq in from..=to {
        // The signature is the gate: no signature, no entry, and the outbox is not even read.
        let Some(sig) = backend.attestation(domain, seq) else {
            continue;
        };
        let Some(entry) = decode_state::<solidus_txns::bridge::OutboxEntry>(
            backend,
            &StateKey::bridge_outbox(domain, seq),
        ) else {
            continue;
        };
        attestations.push(json!({
            "domainSeq": seq,
            "messageId": hex0x(&solidus_bridge_codec::keccak256(&entry.message)),
            "solidusHeight": entry.solidus_height,
            "signature": hex0x(&sig),
            "signer": signer.map(|s| hex0x(&s)),
        }));
    }
    Ok(json!({
        "attestations": attestations,
        "signer": signer.map(|s| hex0x(&s)),
        "committedHeight": backend.canon_head().map(|(h, _)| h),
    }))
}

/// `solidus_getExports`.
pub fn get_exports(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let id = param_str(params, 0, "credentialId")?;
    let set: solidus_txns::bridge::ExportSet =
        decode_state(backend, &StateKey::bridge_exports(&id)).unwrap_or_default();
    let entries: Vec<Value> = set
        .entries
        .iter()
        .map(|e| json!({ "domain": e.domain, "holder": hex0x(&e.holder), "exportId": hex0x(&e.export_id), "validUntil": e.valid_until, "status": e.status }))
        .collect();
    Ok(json!({ "entries": entries }))
}

/// `solidus_getLatestCommittedHeight` - the persisted canonical head.
pub fn get_latest_committed_height(
    backend: &dyn RpcBackend,
    _params: &Value,
) -> Result<Value, RpcError> {
    Ok(json!({ "height": backend.canon_head().map(|(h, _)| h) }))
}

/// `solidus_getStateProof` - latest executed height only.
pub fn get_state_proof(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let tree = match param_str(params, 0, "tree")?.as_str() {
        "accounts" => 0,
        "dids" => 1,
        "credentials" => 2,
        "validators" => 3,
        other => return Err(RpcError::InvalidParams(format!("unknown tree {other}"))),
    };
    let key_hex = param_str(params, 1, "key")?;
    let key = hex::decode(key_hex.trim_start_matches("0x"))
        .map_err(|_| RpcError::InvalidParams("key must be hex".into()))?;
    let b = match backend.state_proof(tree, &key) {
        Ok(b) => b,
        Err(ProofError::StateAdvancing) => return Err(RpcError::StateAdvancing),
        Err(ProofError::BadTree) => return Err(RpcError::InvalidParams("unknown tree".into())),
        Err(ProofError::Unavailable) => {
            return Err(RpcError::PolicyDisabled(
                "state proofs are not served by this node".into(),
            ))
        }
    };
    Ok(json!({
        "height": b.height,
        "globalRoot": hex0x(&b.global_root),
        "subRoots": { "accounts": hex0x(&b.sub_roots[0]), "dids": hex0x(&b.sub_roots[1]), "credentials": hex0x(&b.sub_roots[2]), "validators": hex0x(&b.sub_roots[3]) },
        "value": b.value.as_deref().map(hex0x),
        "proof": b.proof.as_ref().map(|(bitmap, sib)| json!({ "bitmap": hex0x(bitmap), "siblings": sib.iter().map(|s| hex0x(s)).collect::<Vec<_>>() })),
    }))
}

/// `solidus_getCommittee`.
pub fn get_committee(backend: &dyn RpcBackend, _params: &Value) -> Result<Value, RpcError> {
    let c = backend
        .committee_info()
        .ok_or_else(|| RpcError::PolicyDisabled("committee is not served by this node".into()))?;
    Ok(json!({
        "chainId": c.chain_id, "quorum": c.quorum, "popActivationView": c.pop_activation_view,
        "validators": c.validators.iter().map(|(i, pk, pop, att)| json!({
            "index": i,
            "blsPublicKey": hex0x(pk),
            "pop": pop.as_ref().map(|p| hex0x(p)),
            "attestationAddress": att.as_ref().map(|a| hex0x(a)),
        })).collect::<Vec<_>>(),
    }))
}

/// `solidus_getFinalityEvidence`.
pub fn get_finality_evidence(backend: &dyn RpcBackend, params: &Value) -> Result<Value, RpcError> {
    let at = param_u64(params, 0, "atOrAbove")?;
    let e = backend
        .finality_evidence(at)
        .ok_or(RpcError::NoEvidenceYet)?;
    Ok(json!({
        "height": e.height, "parentHeader": hex0x(&e.parent_header), "childBlock": hex0x(&e.child_block), "childQc": hex0x(&e.child_qc),
        "roots": {
            "l1Height": e.l1_height, "globalRoot": hex0x(&e.global_root), "accountsRoot": hex0x(&e.sub_roots[0]),
            "didsRoot": hex0x(&e.sub_roots[1]), "credentialsRoot": hex0x(&e.sub_roots[2]), "validatorsRoot": hex0x(&e.sub_roots[3]),
        },
    }))
}

#[cfg(test)]
mod tests {
    use solidus_txns::types::Event;

    use super::*;
    use crate::backend::RpcBlock;

    #[derive(Default)]
    struct StubBackend {
        committee: Option<crate::backend::CommitteeInfo>,
        allow_enumeration: bool,
        balance: u64,
        nonce: u64,
        height: u64,
        root: [u8; 32],
        receipt: Option<Receipt>,
        submit_ok: bool,
        /// Bridge records keyed by `StateKey.key` (bridge plan 02 Task 14).
        pub bridge_state: std::collections::HashMap<Vec<u8>, Vec<u8>>,
        /// This node's attestation signatures (bridge plan 11 Task 4).
        pub attestations: std::collections::HashMap<(u32, u64), [u8; 65]>,
        pub signer: Option<[u8; 20]>,
    }

    impl RpcBackend for StubBackend {
        fn committee_info(&self) -> Option<crate::backend::CommitteeInfo> {
            self.committee.clone()
        }
        fn state_value(&self, key: &solidus_exec::StateKey) -> Option<Vec<u8>> {
            self.bridge_state.get(&key.key).cloned()
        }

        fn attestation(&self, domain: u32, seq: u64) -> Option<[u8; 65]> {
            self.attestations.get(&(domain, seq)).copied()
        }

        fn attestation_signer(&self) -> Option<[u8; 20]> {
            self.signer
        }
        fn transaction(&self, tx_hash: &[u8; 32]) -> Option<Transaction> {
            // Exactly one hash resolves, so a handler that ignores its argument
            // and always returns a transaction fails rather than passing.
            (*tx_hash == [0x5A; 32]).then(|| Transaction {
                sender_pubkey: [0x01; 32],
                nonce: 3,
                payload: solidus_txns::types::TxPayload::Transfer {
                    to: Address::from_bytes([0x02; 20]),
                    amount: 500,
                },
                signature: [0x03; 64],
            })
        }
        fn uptime_seconds(&self) -> u64 {
            4_242
        }
        fn subject_enumeration_allowed(&self) -> bool {
            self.allow_enumeration
        }
        fn credential_ids_by_issuer(&self, did: &str) -> Vec<String> {
            if did == "did:solidus:issuer" {
                // The third id has NO credential behind it, so the
                // index/record inconsistency path is exercised rather than
                // assumed.
                vec![
                    "urn:solidus:credential:plain".to_string(),
                    "urn:solidus:credential:bbs".to_string(),
                    "urn:solidus:credential:dangling".to_string(),
                ]
            } else {
                Vec::new()
            }
        }
        fn credential_ids_by_subject(&self, did: &str) -> Vec<String> {
            if did == "did:solidus:subject" {
                vec![
                    "urn:solidus:credential:plain".to_string(),
                    "urn:solidus:credential:bbs".to_string(),
                ]
            } else {
                Vec::new()
            }
        }
        fn validators(&self) -> Vec<solidus_txns::staking::ValidatorInfo> {
            use solidus_txns::staking::ValidatorInfo;
            // Returned OUT of address order so the handler's sort is observable.
            vec![
                ValidatorInfo {
                    address: Address::from_bytes([0xFF; 20]),
                    staked: 200,
                    unbonding: 20,
                    unbonding_start_ms: Some(1_700_000_000_000),
                    reputation: 900,
                    active: true,
                },
                ValidatorInfo {
                    address: Address::from_bytes([0x01; 20]),
                    staked: 100,
                    unbonding: 0,
                    unbonding_start_ms: None,
                    reputation: 500,
                    active: false,
                },
            ]
        }
        fn validator(&self, addr: &Address) -> Option<solidus_txns::staking::ValidatorInfo> {
            self.validators().into_iter().find(|v| v.address == *addr)
        }
        fn credential(&self, id: &str) -> Option<solidus_txns::credential::CredentialRecord> {
            use solidus_txns::credential::{CredentialRecord, CredentialType};
            // Two ids resolve, differing ONLY in the optional fields, so the
            // omit-when-absent behaviour is observable rather than assumed.
            let (subject_commitment, bbs_pubkey, bbs_message_count, revoked) = match id {
                "urn:solidus:credential:plain" => (None, None, None, false),
                "urn:solidus:credential:bbs" => {
                    (Some([0x22; 32]), Some([0x33; 96]), Some(5u32), true)
                }
                _ => return None,
            };
            Some(CredentialRecord {
                id: id.to_string(),
                issuer_did: "did:solidus:issuer".to_string(),
                subject_did: "did:solidus:subject".to_string(),
                subject_commitment,
                credential_type: CredentialType::Email,
                hash: [0x44; 32],
                issued_ms: 1_700_000_000_000,
                revoked,
                revoked_ms: revoked.then_some(1_700_000_000_500),
                bbs_pubkey,
                bbs_message_count,
            })
        }
        fn did_document(&self, did: &str) -> Option<solidus_txns::did::DidDocument> {
            use solidus_txns::did::{DidDocument, Service, VerificationMethod};
            // Only one DID resolves, so a handler that ignores its argument and
            // always returns a document is caught.
            if did != "did:solidus:stub" {
                return None;
            }
            Some(DidDocument {
                context: "https://www.w3.org/ns/did/v1".to_string(),
                id: did.to_string(),
                controller: did.to_string(),
                verification_method: vec![
                    VerificationMethod {
                        id: format!("{did}#key-1"),
                        method_type: "Ed25519VerificationKey2020".to_string(),
                        controller: did.to_string(),
                        public_key_hex: "11".repeat(32),
                    },
                    // A key that is NOT 32 bytes: multibase must come back null
                    // rather than wrong.
                    VerificationMethod {
                        id: format!("{did}#key-short"),
                        method_type: "Ed25519VerificationKey2020".to_string(),
                        controller: did.to_string(),
                        public_key_hex: "abcd".to_string(),
                    },
                ],
                authentication: vec![format!("{did}#key-1")],
                assertion_method: vec![format!("{did}#key-1")],
                key_agreement: vec![],
                capability_invocation: vec![format!("{did}#key-1")],
                capability_delegation: vec![],
                service: vec![Service {
                    id: format!("{did}#svc"),
                    service_type: "LinkedDomains".to_string(),
                    service_endpoint: "https://example.test".to_string(),
                }],
                active: true,
                created_ms: 1_700_000_000_000,
                updated_ms: 1_700_000_000_001,
                version_id: "deadbeef".to_string(),
                recovery_policy: None,
                recovery_nonce: 0,
            })
        }
        fn block_at(&self, height: u64) -> Option<RpcBlock> {
            // Only the stub's own height resolves, so a handler that ignores
            // the requested height and always returns the tip is caught.
            (height == self.height).then(|| RpcBlock {
                height,
                view: height + 1,
                hash: "aa".repeat(32),
                parent_hash: "bb".repeat(32),
                exec_height: height.saturating_sub(1),
                exec_state_root: "cc".repeat(32),
                timestamp_ms: 1_700_000_000_000,
                proposer: 3,
                tx_count: 7,
                // Deliberately fewer than tx_count: on a pruned node a batch
                // body may be gone, and both numbers are lower bounds. A stub
                // where they agree would hide a consumer that assumes they must.
                transactions: vec!["dd".repeat(32), "ee".repeat(32)],
            })
        }
        fn chain_identity(&self) -> (String, [u8; 32]) {
            ("v2-stub-net".to_string(), [0xEF; 32])
        }
        fn chain_id_numeric(&self) -> u64 {
            50_002
        }
        fn canon_head(&self) -> Option<(u64, [u8; 32])> {
            // Distinct from `block_height` on purpose: the two are different
            // reads (store vs in-memory anchor) and a stub that returns the
            // same number for both would hide a handler wired to the wrong one.
            Some((self.height.saturating_sub(1), [0xAB; 32]))
        }
        fn balance(&self, _a: &Address) -> u64 {
            self.balance
        }
        fn nonce(&self, _a: &Address) -> u64 {
            self.nonce
        }
        fn block_height(&self) -> u64 {
            self.height
        }
        fn state_root(&self) -> [u8; 32] {
            self.root
        }
        fn receipt(&self, _h: u64, _t: &[u8; 32]) -> Option<Receipt> {
            self.receipt.clone()
        }
        fn tx_height(&self, _t: &[u8; 32]) -> Option<u64> {
            // Mirrors `receipt`: a stub that knows a receipt knows its height.
            // Returning None regardless would make the one-argument getReceipt
            // untestable here, which is the form clients actually use.
            self.receipt.as_ref().map(|_| 1)
        }
        fn submit(&self, tx: Transaction) -> Result<[u8; 32], String> {
            if self.submit_ok {
                Ok(solidus_exec::wire::tx_hash(
                    &tx,
                    solidus_exec::WireMode::BinaryV2,
                ))
            } else {
                Err("mempool full".into())
            }
        }
    }

    fn stub() -> StubBackend {
        StubBackend {
            committee: None,
            // Closed, matching the shipping default.
            allow_enumeration: false,
            attestations: std::collections::HashMap::new(),
            signer: None,
            balance: 12_345,
            nonce: 7,
            height: 99,
            root: [0xAB; 32],
            receipt: Some(Receipt {
                tx_hash: [0x11; 32],
                status: TxStatus::Success,
                block_height: 42,
                fee_paid: 10_000,
                events: vec![Event::Transfer {
                    from: Address::from_bytes([1; 20]),
                    to: Address::from_bytes([2; 20]),
                    amount: 5,
                }],
            }),
            submit_ok: true,
            bridge_state: Default::default(),
        }
    }

    /// ⚠ A SHORT HASH MUST BE AN ERROR, NOT A MISS. Truncating or padding a bad
    /// hash and then reporting "not found" would state that no such transaction
    /// exists, which the node never determined. Same rule the enumeration gate
    /// and the BBS validations follow.
    #[test]
    fn get_transaction_resolves_by_hash_and_rejects_a_malformed_one() {
        let b = StubBackend::default();

        let found = get_transaction(&b, &json!(["5a".repeat(32)])).expect("resolves");
        assert!(found.is_object(), "a known hash returns the transaction");
        assert_eq!(
            found.get("nonce").and_then(|v| v.as_u64()),
            Some(3),
            "and it is the transaction the stub holds, not a placeholder"
        );

        // A well-formed hash the node does not hold: null, which means NOT
        // FOUND HERE rather than never existed.
        assert!(get_transaction(&b, &json!(["11".repeat(32)]))
            .expect("resolves")
            .is_null());

        // Wrong length is an error, never a null.
        let short = get_transaction(&b, &json!(["abcd"])).expect_err("must reject");
        assert!(
            matches!(short, RpcError::InvalidParams(ref m) if m.contains("32 bytes")),
            "a short hash must say so, not silently look like a miss"
        );
        assert!(matches!(
            get_transaction(&b, &json!(["zz".repeat(32)])).expect_err("must reject"),
            RpcError::InvalidParams(_)
        ));
    }

    /// ⛔ THE VALIDATIONS RUN BEFORE ANY CRYPTO, AND THEY ARE THE SECURITY.
    /// A duplicate index, or an index at/beyond `total_message_count`,
    /// describes a disclosure set that does not correspond to what the issuer
    /// signed. Each must be an ERROR, never `false`: returning `false` would
    /// state that the proof failed verification, which this node never ran.
    #[test]
    fn bbs_verify_proof_rejects_malformed_disclosure_sets_before_verifying() {
        let b = StubBackend::default();
        let pk = "aa".repeat(96);

        let dup = json!([
            "00", pk, "", "",
            [{"index": 1, "message": "01"}, {"index": 1, "message": "02"}],
            4
        ]);
        assert!(
            matches!(
                bbs_verify_proof(&b, &dup).expect_err("must reject"),
                RpcError::InvalidParams(ref m) if m.contains("duplicate")
            ),
            "a duplicate disclosed index must be an error, not a false verdict"
        );

        let oob = json!([
            "00", pk, "", "",
            [{"index": 7, "message": "01"}],
            4
        ]);
        assert!(
            matches!(
                bbs_verify_proof(&b, &oob).expect_err("must reject"),
                RpcError::InvalidParams(ref m) if m.contains("total_message_count")
            ),
            "an index at/beyond total_message_count must be an error"
        );

        let bad_hex = json!([
            "00", pk, "", "",
            [{"index": 0, "message": "zz"}],
            4
        ]);
        assert!(matches!(
            bbs_verify_proof(&b, &bad_hex).expect_err("must reject"),
            RpcError::InvalidParams(_)
        ));
    }

    /// ⛔ `valid` IS PROOF-VALID **AND** NOT-REVOKED, AND A NON-BBS CREDENTIAL
    /// MUST NOT BE VERIFIED AT ALL. Reporting a verification result for a
    /// credential that carries no BBS+ key would be reporting a result this
    /// node never computed.
    #[test]
    fn bbs_verify_credential_proof_distinguishes_missing_non_bbs_and_revoked() {
        let b = StubBackend::default();

        // Unknown credential: everything false, record null. Not an error -
        // "no such credential" is a computed answer.
        let missing = bbs_verify_credential_proof(
            &b,
            &json!(["urn:solidus:credential:nope", "00", "", "", []]),
        )
        .expect("answers");
        assert_eq!(missing.get("is_bbs").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(missing.get("valid").and_then(|v| v.as_bool()), Some(false));
        assert!(missing.get("credential").expect("present").is_null());

        // A credential with no BBS+ key: is_bbs false, and NO verification was
        // attempted. The record still comes back so a caller can see why.
        let plain = bbs_verify_credential_proof(
            &b,
            &json!(["urn:solidus:credential:plain", "00", "", "", []]),
        )
        .expect("answers");
        assert_eq!(plain.get("is_bbs").and_then(|v| v.as_bool()), Some(false));
        assert_eq!(
            plain.get("proof_valid").and_then(|v| v.as_bool()),
            Some(false),
            "no proof was verified, so proof_valid must not claim otherwise"
        );
        assert!(plain.get("credential").expect("present").is_object());
    }

    /// ⚠ UNGATED, UNLIKE THE SUBJECT PATH, AND THAT ASYMMETRY IS ASSERTED.
    /// Enumerating a subject's credentials is a correlation handle over a
    /// person; enumerating what an issuer issued is a property of a public
    /// entity. v1 gates the first and not the second. If someone later "fixes"
    /// the inconsistency by gating both, this test fails and makes them argue
    /// for it rather than tidy it away.
    #[test]
    fn credentials_by_issuer_answers_with_the_gate_closed_and_skips_dangling_ids() {
        // Default stub = subject enumeration CLOSED. The issuer path must still
        // answer, which is what proves the two are independent.
        let b = StubBackend::default();
        assert!(!b.subject_enumeration_allowed());

        let list = credentials_by_issuer(&b, &json!(["did:solidus:issuer"]))
            .expect("issuer enumeration is not gated");
        let arr = list.as_array().expect("array");

        // Three ids indexed, one with no credential behind it: a dangling entry
        // is skipped rather than dropping the whole query or emitting a null.
        assert_eq!(
            arr.len(),
            2,
            "a dangling index entry must be skipped, not fatal and not null"
        );
        for rec in arr {
            assert!(rec.get("id").is_some(), "each entry is a credential record");
        }

        let none = credentials_by_issuer(&b, &json!(["did:solidus:nobody"])).expect("answers");
        assert_eq!(none.as_array().map(|a| a.len()), Some(0));
    }

    /// ⛔ THE REFUSAL IS THE FEATURE, AND DEFAULT-CLOSED IS THE ASSERTION.
    /// Enumerating every credential a subject holds is a correlation handle.
    /// The gate was closed deliberately on v1 as a privacy fix, so a v2 port
    /// that answers by default would silently reopen it.
    #[test]
    fn credentials_by_subject_is_refused_by_default_and_errors_rather_than_returning_empty() {
        // Default stub = gate closed, which is the shipping configuration.
        let closed = StubBackend::default();
        let err = credentials_by_subject(&closed, &json!(["did:solidus:subject"]))
            .expect_err("must refuse while the gate is closed");
        assert!(
            matches!(err, RpcError::PolicyDisabled(_)),
            "must be a POLICY refusal, not NotFound and not an empty list: an \
             empty list asserts `this DID holds no credentials`, which the node \
             never computed and which is false for most subjects"
        );

        // Opened, it answers - proving the refusal above is the gate and not a
        // handler that simply cannot find anything.
        let open = StubBackend {
            allow_enumeration: true,
            ..Default::default()
        };
        let list = credentials_by_subject(&open, &json!(["did:solidus:subject"]))
            .expect("must answer when explicitly enabled");
        assert_eq!(list.as_array().map(|a| a.len()), Some(2));

        // And it reuses the SAME whitelist as credentialVerify.
        let first = list
            .pointer("/0")
            .and_then(|v| v.as_object())
            .expect("record");
        assert!(first.contains_key("id"));
        assert!(
            !first.contains_key("unbonding_start_ms"),
            "sanity: the credential whitelist, not some other record"
        );

        // A subject with nothing recorded is an empty list, which here is a
        // computed answer rather than a stand-in for a refusal.
        let none = credentials_by_subject(&open, &json!(["did:solidus:nobody"])).expect("answers");
        assert_eq!(none.as_array().map(|a| a.len()), Some(0));
    }

    /// ⛔ FIVE FIELDS, NOT SIX. `ValidatorInfo` carries `unbonding_start_ms`
    /// and v1 does not emit it. Asserting the EXACT key set means a field added
    /// to the chain type cannot reach the wire unnoticed - the same whitelist
    /// property as the credential record.
    #[test]
    fn get_validators_emits_five_fields_sorted_and_omits_unbonding_start() {
        let b = StubBackend::default();
        let list = get_validators(&b, &Value::Null).expect("get_validators");
        let arr = list.as_array().expect("array");
        assert_eq!(arr.len(), 2);

        let keys: Vec<&str> = {
            let mut k: Vec<&str> = arr[0]
                .as_object()
                .expect("object")
                .keys()
                .map(|s| s.as_str())
                .collect();
            k.sort_unstable();
            k
        };
        assert_eq!(
            keys,
            vec!["active", "address", "reputation", "staked", "unbonding"],
            "EXACT key set. `unbonding_start_ms` is on the chain type and must \
             NOT appear here; if this fails because a field was added, decide \
             deliberately whether it should leave the node."
        );

        // The stub returns them out of order, so this proves the handler sorts
        // rather than inheriting RocksDB iteration order.
        let a0 = arr[0]
            .get("address")
            .and_then(|v| v.as_str())
            .expect("addr");
        let a1 = arr[1]
            .get("address")
            .and_then(|v| v.as_str())
            .expect("addr");
        assert!(a0 < a1, "validators must come back sorted by address");

        // Lookup by address resolves, and an unknown address is null rather
        // than a default record.
        let known = get_validator_stake(&b, &json!([a0])).expect("stake");
        assert_eq!(known.get("address").and_then(|v| v.as_str()), Some(a0));
        let unknown = Address::from_bytes([0x77; 20]).to_base58();
        assert!(get_validator_stake(&b, &json!([unknown]))
            .expect("stake")
            .is_null());
    }

    /// ⛔ THE FIELD LIST IS A WHITELIST AND THIS TEST DEFENDS IT. v1's record
    /// type exists so the response enumerates what leaves the node instead of
    /// deriving itself from the chain record. This repo has already leaked KYC
    /// internals and a pricing enum through a denylist, so the exact key set is
    /// asserted: a new field on `CredentialRecord` must NOT appear here until
    /// someone adds it deliberately, and this test fails if one does.
    #[test]
    fn credential_verify_emits_an_exact_whitelist_and_omits_absent_optionals() {
        let b = StubBackend::default();

        let plain = credential_verify(&b, &json!(["urn:solidus:credential:plain"]))
            .expect("credential_verify");
        assert_eq!(plain.get("valid").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(plain.get("revoked").and_then(|v| v.as_bool()), Some(false));

        let rec = plain
            .get("credential")
            .and_then(|v| v.as_object())
            .expect("record");
        let mut keys: Vec<&str> = rec.keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "credential_type",
                "hash",
                "id",
                "issued_ms",
                "issuer_did",
                "revoked",
                "revoked_ms",
                "subject_did",
            ],
            "EXACT key set for a non-BBS credential. If this fails because a \
             field was added to CredentialRecord, that is the whitelist working: \
             decide deliberately whether it should leave the node."
        );

        // The optional trio appears only when present, and by PRESENCE, since a
        // caller distinguishes "not a BBS+ credential" from "BBS+ with no key".
        let bbs = credential_verify(&b, &json!(["urn:solidus:credential:bbs"]))
            .expect("credential_verify");
        let rec = bbs
            .get("credential")
            .and_then(|v| v.as_object())
            .expect("record");
        for key in ["subject_commitment", "bbs_pubkey", "bbs_message_count"] {
            assert!(rec.contains_key(key), "missing `{key}` on a BBS+ record");
        }
        assert_eq!(
            bbs.get("valid").and_then(|v| v.as_bool()),
            Some(false),
            "a revoked credential is not valid"
        );

        assert!(
            credential_verify(&b, &json!(["urn:solidus:credential:nope"]))
                .expect("credential_verify")
                .is_null()
        );
    }

    /// ⛔ THE COMMITMENT LOOKUP IS UNGATED WHILE THE SUBJECT LOOKUP IS NOT,
    /// AND THAT ASYMMETRY IS THE DESIGN.
    ///
    /// A subject DID turns one identifier into a profile of everything a person
    /// holds, and a node-wide boolean cannot tell a holder listing their own
    /// credentials from an observer profiling them. A commitment tells them
    /// apart by construction: it is BLAKE3(domain ‖ did ‖ nonce32) and the nonce
    /// reaches only the holder, so PRESENTING one is the proof. The capability
    /// is the secret, which is why no policy switch is needed.
    #[test]
    fn the_commitment_lookup_works_where_subject_enumeration_is_refused() {
        // Same node, same policy: subject enumeration OFF.
        let b = stub();
        assert!(
            matches!(
                credentials_by_subject(&b, &json!(["did:solidus:stub"])),
                Err(RpcError::PolicyDisabled(_))
            ),
            "the stub must have enumeration disabled, or this proves nothing"
        );

        // The commitment path is not refused on that same node.
        let out = credentials_by_commitment(&b, &json!([hex::encode([0x42; 32])]));
        assert!(
            !matches!(out, Err(RpcError::PolicyDisabled(_))),
            "the commitment lookup must not be policy-gated"
        );
        assert!(out.is_ok(), "it must answer rather than error");
    }

    /// A malformed commitment is a CALLER ERROR, never an empty list.
    ///
    /// ⚠ Returning `[]` for a bad input would read to a holder as "you hold
    /// nothing", which is the exact lie this method exists to prevent.
    #[test]
    fn a_malformed_commitment_is_an_error_not_an_empty_list() {
        let b = stub();
        for bad in ["", "zz", "42", &"ab".repeat(31)] {
            assert!(
                credentials_by_commitment(&b, &json!([bad])).is_err(),
                "{bad:?} must be rejected, not answered with an empty list"
            );
        }
    }

    /// An unknown-but-well-formed commitment answers with an empty array.
    /// That IS the honest answer: nothing is indexed under it.
    #[test]
    fn an_unknown_commitment_answers_empty_rather_than_erroring() {
        let out = credentials_by_commitment(&stub(), &json!([hex::encode([0x7f; 32])])).unwrap();
        assert_eq!(out, json!([]));
    }

    /// ⛔ A RECEIPT CARRIES ITS EVENTS, NOT ONLY A COUNT, AND THE COUNT-ONLY
    /// FORM FAILED CATASTROPHICALLY AND SILENTLY.
    ///
    /// The SDK reads the chain-assigned credential id out of
    /// `CredentialIssued`/`CredentialIssuedV2`. Against a count-only receipt
    /// `receipt.events` was `undefined`, `.find` threw, and the guarded fallback
    /// (`urn:solidus:credential:` plus the tx hash) read a field that is also
    /// absent under v2's camelCase. Every credential would have been assigned
    /// the SAME id, `urn:solidus:credential:undefined`, forever.
    #[test]
    fn a_receipt_carries_its_events_and_not_only_a_count() {
        let out = get_receipt(&stub(), &json!([hex::encode([0x11; 32])])).unwrap();
        let events = out["events"].as_array().expect("events array");
        assert_eq!(
            out["eventCount"],
            json!(events.len()),
            "the count must agree with the list"
        );
        assert!(!events.is_empty(), "the stub's receipt carries one event");
        assert!(events[0]["type"].is_string(), "each event names its type");
    }

    /// ⛔ THE PRIVACY RULE, PINNED. `CredentialIssuedV2` must NOT republish the
    /// subject. Receipts are served publicly, so an event is a publication
    /// surface: dropping `subject_did` from the payload while the event still
    /// carried it would move the leak rather than close it.
    #[test]
    fn the_v2_issuance_event_never_republishes_the_subject() {
        let ev = event_to_json(&Event::CredentialIssuedV2 {
            credential_id: "urn:solidus:credential:abc".to_string(),
            issuer: "did:solidus:issuer".to_string(),
            subject_commitment: [0x77; 32],
        });
        assert_eq!(ev["type"], json!("CredentialIssuedV2"));
        assert_eq!(ev["credentialId"], json!("urn:solidus:credential:abc"));
        assert_eq!(ev["subjectCommitment"], json!("77".repeat(32)));
        assert!(
            ev.get("subject").is_none(),
            "the subject DID must never reach a public receipt"
        );
        assert!(ev.get("subjectDid").is_none(), "under any spelling");
    }

    /// The event keys the SDK reads, pinned by name. They cross a JSON boundary
    /// no type checker sees, and v1 emits the same ones.
    #[test]
    fn credential_events_use_the_same_keys_v1_emits() {
        let issued = event_to_json(&Event::CredentialIssued {
            credential_id: "urn:solidus:credential:xyz".to_string(),
            issuer: "did:solidus:issuer".to_string(),
            subject: "did:solidus:subject".to_string(),
        });
        assert_eq!(issued["type"], json!("CredentialIssued"));
        assert_eq!(issued["credentialId"], json!("urn:solidus:credential:xyz"));

        let revoked = event_to_json(&Event::CredentialRevoked {
            credential_id: "urn:solidus:credential:xyz".to_string(),
        });
        assert_eq!(revoked["type"], json!("CredentialRevoked"));
        assert_eq!(revoked["credentialId"], json!("urn:solidus:credential:xyz"));
    }

    /// ⛔ SERVICE ENTRIES ARE W3C-NAMED, AND THE FAILURE WAS SILENT.
    ///
    /// Serialising `doc.service` directly emits the RUST field names, because
    /// the struct carries no serde renames. auth's `resolveWebId` finds a pod
    /// with `s.type === 'SolidPod'` and reads `serviceEndpoint`; against the
    /// verbatim shape BOTH are undefined, so it returns null, sign-in proceeds
    /// WITHOUT a WebID, and the DID-to-pod binding is quietly gone. Nothing
    /// errors, which is what makes this worth a test rather than a comment.
    #[test]
    fn a_service_entry_uses_w3c_names_not_rust_field_names() {
        let out = did_resolve(&stub(), &json!(["did:solidus:stub"])).unwrap();
        let svc = out["service"].as_array().expect("service array");
        assert_eq!(svc.len(), 1, "the stub carries exactly one service entry");

        assert_eq!(
            svc[0]["type"],
            json!("LinkedDomains"),
            "W3C calls it `type`"
        );
        assert_eq!(
            svc[0]["serviceEndpoint"],
            json!("https://example.test"),
            "W3C calls it `serviceEndpoint`"
        );

        // And the Rust names must be ABSENT, or a consumer could read either
        // and the two would drift apart.
        assert!(
            svc[0].get("service_type").is_none(),
            "no raw Rust field names"
        );
        assert!(
            svc[0].get("service_endpoint").is_none(),
            "no raw Rust field names"
        );
    }

    /// ⛔ PINS EVERY EMITTED KEY OF didResolve BY NAME. 81 call sites plus every
    /// installed npm SDK read these, across a JSON boundary no type checker
    /// sees. A rename here is a silent break, so each name is asserted rather
    /// than the document compared as a whole.
    #[test]
    fn did_resolve_emits_both_namings_and_both_key_encodings() {
        let b = StubBackend::default();
        let params = json!(["did:solidus:stub"]);
        let d = did_resolve(&b, &params).expect("did_resolve");

        // W3C DID Core names.
        for key in [
            "@context",
            "id",
            "controller",
            "verificationMethod",
            "authentication",
            "assertionMethod",
            "keyAgreement",
            "capabilityInvocation",
            "capabilityDelegation",
        ] {
            assert!(d.get(key).is_some(), "missing W3C key `{key}`");
        }

        // The legacy names the published SDK still reads. Dropping these is a
        // separate decision with an npm release attached.
        for key in [
            "context",
            "verification_method",
            "assertion_method",
            "key_agreement",
            "capability_invocation",
            "capability_delegation",
        ] {
            assert!(d.get(key).is_some(), "missing legacy key `{key}`");
        }

        for key in [
            "service",
            "active",
            "created_ms",
            "updated_ms",
            "version_id",
            "recovery_policy",
            "recovery_nonce",
        ] {
            assert!(d.get(key).is_some(), "missing key `{key}`");
        }

        // Both namings must carry the SAME values, not merely both exist.
        assert_eq!(d.get("@context"), d.get("context"));
        assert_eq!(d.get("verificationMethod"), d.get("verification_method"));
        assert_eq!(
            d.get("capabilityInvocation"),
            d.get("capability_invocation")
        );

        // Two key encodings per verification method.
        let vm0 = d.pointer("/verificationMethod/0").expect("vm 0");
        assert_eq!(
            vm0.get("publicKeyHex").and_then(|v| v.as_str()),
            Some("11".repeat(32).as_str()),
            "publicKeyHex is in no W3C spec and ships only for the npm SDK"
        );
        assert!(
            vm0.get("publicKeyMultibase")
                .and_then(|v| v.as_str())
                .is_some(),
            "a 32-byte key must produce a multibase value"
        );

        // ⚠ A non-32-byte key must be NULL, not absent and not wrong.
        let vm1 = d.pointer("/verificationMethod/1").expect("vm 1");
        assert!(
            vm1.get("publicKeyMultibase").is_some(),
            "the field must still be present"
        );
        assert!(
            vm1.get("publicKeyMultibase").expect("present").is_null(),
            "and null for a key that cannot be encoded - a wrong value would be \
             worse than an absent one"
        );

        // An unknown DID resolves to null, not to a default document.
        assert!(did_resolve(&b, &json!(["did:solidus:nope"]))
            .expect("did_resolve")
            .is_null());
    }

    /// ⛔ THE TRAP A TYPE CHECKER CANNOT CATCH. v1's `chainInfo.chain_id` is a
    /// STRING - "solidus-testnet-1", measured live 2026-09-02 - while v2's
    /// `chain_id` is a u64 (50002). Serving the number under that key compiles
    /// perfectly and breaks every caller that reads it, because the estate is
    /// TypeScript on the far side of a JSON boundary.
    #[test]
    fn chain_info_chain_id_is_the_network_name_not_the_number() {
        let b = StubBackend {
            height: 500,
            ..Default::default()
        };
        let info = chain_info(&b, &Value::Null).expect("chain_info");

        assert_eq!(
            info.get("chain_id").and_then(|v| v.as_str()),
            Some("v2-stub-net"),
            "chain_id must be the network NAME as a string"
        );
        assert!(
            info.get("chain_id").and_then(|v| v.as_u64()).is_none(),
            "and must never be a bare number, which is what a naive port of \
             v2's numeric chain_id would produce"
        );
        assert_eq!(
            info.pointer("/native_token/symbol")
                .and_then(|v| v.as_str()),
            Some("SLDS")
        );
        assert_eq!(
            info.pointer("/native_token/decimals")
                .and_then(|v| v.as_u64()),
            Some(8)
        );
        assert_eq!(
            info.get("latest_block").and_then(|v| v.as_u64()),
            Some(500),
            "latest_block tracks the exec anchor, as v1's does"
        );
        assert_eq!(
            info.get("genesis_hash").and_then(|v| v.as_str()),
            Some("efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef"),
            "hex, lowercase, no 0x prefix"
        );
        assert!(
            info.get("version").and_then(|v| v.as_str()).is_some(),
            "v1 carries a version string and callers may display it"
        );
    }

    /// Pins the WIRE SHAPE of the two v1-compatible methods against what the
    /// live v1 endpoint actually returned on 2026-09-02:
    ///   canonHead -> {"seq":92928,"hash":"9a047ce3..."}
    ///   blockNumber -> a bare integer
    ///
    /// The shape is the contract. A caller in the estate parses these fields by
    /// name, so renaming one is a breaking change no type checker here would
    /// catch - the estate is TypeScript on the other side of a JSON boundary.
    #[test]
    fn canon_head_and_block_number_match_v1_wire_shape() {
        let b = StubBackend {
            height: 42,
            ..Default::default()
        };

        let head = canon_head(&b, &Value::Null).expect("canon_head");
        assert_eq!(
            head.get("seq").and_then(|v| v.as_u64()),
            Some(41),
            "v1 names this field `seq`, not `height`"
        );
        assert_eq!(
            head.get("hash").and_then(|v| v.as_str()),
            Some("abababababababababababababababababababababababababababababababab"),
            "and `hash` is lowercase hex with no 0x prefix, as v1 returns it"
        );

        let n = block_number(&b, &Value::Null).expect("block_number");
        assert_eq!(
            n.as_u64(),
            Some(42),
            "blockNumber is a BARE integer, not an object and not hex"
        );
        assert_ne!(
            n.as_u64(),
            head.get("seq").and_then(|v| v.as_u64()),
            "and it is a different read from canonHead.seq - v1's own two \
             values differed by ~1,800 when measured, so a handler wired to \
             the wrong source would look correct in steady state"
        );
    }

    #[test]
    fn balance_nonce_height_root() {
        let b = stub();
        let addr = Address::from_bytes([9; 20]).to_base58();
        assert_eq!(
            get_balance(&b, &json!([addr])).unwrap(),
            json!("12345"),
            "balance is a decimal string (u64-safe for JS clients)"
        );
        assert_eq!(get_nonce(&b, &json!([addr])).unwrap(), json!(7));
        assert_eq!(get_block_height(&b, &json!([])).unwrap(), json!(99));
        assert_eq!(
            get_state_root(&b, &json!([])).unwrap(),
            json!(hex::encode([0xAB; 32]))
        );
    }

    #[test]
    fn by_name_params_also_work() {
        let b = stub();
        let addr = Address::from_bytes([9; 20]).to_base58();
        assert_eq!(
            get_balance(&b, &json!({ "address": addr })).unwrap(),
            json!("12345")
        );
    }

    #[test]
    fn bad_address_is_invalid_params() {
        let b = stub();
        assert!(matches!(
            get_balance(&b, &json!(["not-base58-!!!"])),
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            get_balance(&b, &json!([])),
            Err(RpcError::InvalidParams(_))
        ));
    }

    #[test]
    fn receipt_shape_and_not_found() {
        let b = stub();
        let out = get_receipt(&b, &json!([42, hex::encode([0x11; 32])])).unwrap();
        assert_eq!(out["status"], json!("success"));
        assert_eq!(out["feePaid"], json!("10000"));
        assert_eq!(out["eventCount"], json!(1));

        let mut missing = stub();
        missing.receipt = None;
        assert!(matches!(
            get_receipt(&missing, &json!([1, hex::encode([0; 32])])),
            Err(RpcError::NotFound)
        ));
    }

    /// ⛔ A v1 CLIENT MUST STILL READ THIS RECEIPT, because
    /// `rpc.solidus.network` is being repointed at this chain and keeps its
    /// address. A published caller cannot be upgraded.
    ///
    /// ⚠ THE ASSERTION THAT EARNS ITS KEEP IS `tx_hash`. @solidus-network/sdk
    /// 0.6.5 computes a credential id as
    /// `<from events> ?? urn:solidus:credential:${receipt.tx_hash}`. Without the
    /// alias that is `undefined`, and every credential taking the fallback gets
    /// the SAME permanent id.
    #[test]
    fn receipt_also_carries_the_v1_key_names() {
        let b = stub();
        let out = get_receipt(&b, &json!([42, hex::encode([0x11; 32])])).unwrap();

        // Same value under both names, so a reader of either is correct.
        assert_eq!(out["tx_hash"], out["txHash"]);
        assert_eq!(out["block_height"], out["blockHeight"]);
        assert!(
            !out["tx_hash"].is_null(),
            "a v1 client reads tx_hash and would get undefined"
        );

        // ⚠ TYPES DIFFER ON PURPOSE: v1 emitted a u64, v2 emits a string
        // because a fee can exceed 2^53. Each key keeps the type its own
        // readers expect rather than changing shape by version.
        assert_eq!(out["fee_paid"], json!(10_000));
        assert_eq!(out["feePaid"], json!("10000"));

        // CONTROL: the v2 names are untouched, so this is additive and no v2
        // reader was traded away to serve a v1 one.
        assert_eq!(out["status"], json!("success"));
        assert_eq!(out["eventCount"], json!(1));
        assert!(out["events"].is_array());
    }

    /// ⛔ THE ONE-ARGUMENT FORM IS WHAT MAKES A TRANSACTION CONFIRMABLE. A
    /// submitter receives a HASH and nothing else. v1 let it poll on that
    /// alone; requiring `[height, txHash]` meant a client could submit
    /// successfully and then never learn the outcome, because the height is
    /// precisely what it does not have.
    #[test]
    fn a_receipt_is_reachable_by_hash_alone() {
        let b = stub();
        let by_hash = get_receipt(&b, &json!([hex::encode([0x11; 32])])).unwrap();
        let by_height = get_receipt(&b, &json!([1, hex::encode([0x11; 32])])).unwrap();
        assert_eq!(
            by_hash, by_height,
            "both forms must return the same receipt; if they diverge, callers \
             get different answers depending on what they happen to know"
        );
    }

    /// A hash the chain has never seen is NOT FOUND, not a malformed request.
    /// A poller has to be able to tell "not yet" from "you called it wrong".
    #[test]
    fn an_unknown_hash_is_not_found_rather_than_invalid_params() {
        let mut missing = stub();
        missing.receipt = None;
        assert!(matches!(
            get_receipt(&missing, &json!([hex::encode([0xAB; 32])])),
            Err(RpcError::NotFound)
        ));
    }

    /// The two-argument form keeps working untouched. It is strictly cheaper
    /// when the caller already knows the height — an explorer walking a range —
    /// so it is not deprecated by the addition.
    #[test]
    fn the_height_and_hash_form_still_works() {
        let b = stub();
        let out = get_receipt(&b, &json!([42, hex::encode([0x11; 32])])).unwrap();
        assert_eq!(out["status"], json!("success"));
    }

    #[test]
    fn submit_roundtrips_bincode_and_returns_hash() {
        use solidus_crypto::ed25519::{generate_signing_key, sign};
        use solidus_txns::types::TxPayload;

        let key = generate_signing_key();
        let mut tx = Transaction {
            sender_pubkey: key.verifying_key().to_bytes(),
            nonce: 0,
            payload: TxPayload::Transfer {
                to: Address::from_bytes([3; 20]),
                amount: 100,
            },
            signature: [0u8; 64],
        };
        let msg = solidus_exec::wire::signing_bytes(&tx, solidus_exec::WireMode::BinaryV2);
        tx.signature = sign(&key, &msg);
        let hex_tx = hex::encode(bincode::serialize(&tx).unwrap());

        let b = stub();
        let out = submit_transaction(&b, &json!([hex_tx])).unwrap();
        let expected = hex::encode(solidus_exec::wire::tx_hash(
            &tx,
            solidus_exec::WireMode::BinaryV2,
        ));
        assert_eq!(out, json!(expected));

        let mut rejecting = stub();
        rejecting.submit_ok = false;
        assert!(matches!(
            submit_transaction(&rejecting, &json!([hex_tx])),
            Err(RpcError::SubmitRejected(_))
        ));

        // Garbage hex → invalid params.
        assert!(matches!(
            submit_transaction(&b, &json!(["zzzz"])),
            Err(RpcError::InvalidParams(_))
        ));
    }

    #[test]
    fn chain_info_reports_numeric_chain_id_version_and_wire_for_the_next_block() {
        let b = StubBackend::default();
        let v = chain_info(&b, &serde_json::Value::Null).unwrap();
        assert_eq!(v["chainIdNumeric"], serde_json::json!(b.chain_id_numeric()));
        let next = b.block_height() + 1;
        let (version, wire) = if solidus_exec::protocol::version_at(next)
            >= solidus_exec::protocol::ProtocolVersion::V2
        {
            ("v2", "binary-v3")
        } else {
            ("v1", "binary-v2")
        };
        assert_eq!(v["protocolVersion"], version);
        assert_eq!(v["wire"], wire);
        assert!(
            v.get("chain_id").is_some(),
            "the v1-compatible name field stays"
        );
    }

    /// Bridge events (bridge plan 02). The v2 executor emits them, so receipts
    /// served here carry them. Same keys as `solidus-rpc`'s `event_to_json`,
    /// which has the identical test: camelCase keys, byte arrays in bare hex like
    /// every other event this renderer emits.
    #[test]
    fn bridge_events_render_with_camel_case_keys_and_hex_bytes() {
        let exported = event_to_json(&Event::CredentialExported {
            credential_id: "urn:c".into(),
            domain: 11_155_111,
            export_id: [4; 32],
        });
        assert_eq!(exported["type"], "CredentialExported");
        assert_eq!(exported["credentialId"], "urn:c");
        assert_eq!(exported["domain"], 11_155_111);
        assert_eq!(exported["exportId"], hex::encode([4u8; 32]));

        let queued = event_to_json(&Event::BridgeMessageQueued {
            domain: 7,
            domain_seq: 3,
            kind: 2,
            message_id: [9; 32],
        });
        assert_eq!(queued["type"], "BridgeMessageQueued");
        assert_eq!(queued["domainSeq"], 3);
        assert_eq!(queued["kind"], 2);
        assert_eq!(queued["messageId"], hex::encode([9u8; 32]));

        let unexported = event_to_json(&Event::CredentialUnexported {
            credential_id: "urn:c".into(),
            domain: 7,
            export_id: [5; 32],
        });
        assert_eq!(unexported["type"], "CredentialUnexported");
        assert_eq!(unexported["exportId"], hex::encode([5u8; 32]));

        let registered = event_to_json(&Event::BridgeDomainRegistered {
            domain: 7,
            enabled: false,
        });
        assert_eq!(registered["type"], "BridgeDomainRegistered");
        assert_eq!(registered["enabled"], false);

        let root = event_to_json(&Event::BridgeTrustRootSet {
            did: "did:solidus:testnet:x".into(),
            enabled: true,
        });
        assert_eq!(root["type"], "BridgeTrustRootSet");
        assert_eq!(root["did"], "did:solidus:testnet:x");
    }

    fn with_bridge_state() -> StubBackend {
        use solidus_txns::bridge::*;
        let mut b = StubBackend::default();
        let put = |b: &mut StubBackend, k: solidus_exec::StateKey, v: Vec<u8>| {
            b.bridge_state.insert(k.key, v);
        };
        let d = BridgeDomain {
            domain: 11_155_111,
            vm: BridgeDomainVm::Evm,
            inbox: [2; 32],
            heartbeat_interval_secs: 600,
            enabled: true,
        };
        put(
            &mut b,
            solidus_exec::StateKey::bridge_domains_index(),
            bincode::serialize(&vec![11_155_111u32]).unwrap(),
        );
        put(
            &mut b,
            solidus_exec::StateKey::bridge_domain(11_155_111),
            bincode::serialize(&d).unwrap(),
        );
        put(
            &mut b,
            solidus_exec::StateKey::bridge_seq(11_155_111),
            3u64.to_le_bytes().to_vec(),
        );
        for seq in 1..=3u64 {
            let e = OutboxEntry {
                solidus_height: 1000 + seq,
                message: vec![seq as u8; 4],
            };
            put(
                &mut b,
                solidus_exec::StateKey::bridge_outbox(11_155_111, seq),
                bincode::serialize(&e).unwrap(),
            );
        }
        let set = ExportSet {
            entries: vec![ExportEntry {
                domain: 11_155_111,
                holder: [3; 32],
                export_id: [4; 32],
                valid_until: 0,
                status: 1,
            }],
        };
        put(
            &mut b,
            solidus_exec::StateKey::bridge_exports("urn:c"),
            bincode::serialize(&set).unwrap(),
        );
        b
    }

    #[test]
    fn get_bridge_domains_lists_registered_domains() {
        let v = get_bridge_domains(&with_bridge_state(), &json!({})).unwrap();
        assert_eq!(v["domains"][0]["domain"], 11_155_111);
        assert_eq!(v["domains"][0]["vm"], 1);
        assert_eq!(
            v["domains"][0]["inbox"],
            format!("0x{}", hex::encode([2u8; 32]))
        );
        assert_eq!(v["domains"][0]["heartbeatIntervalSecs"], 600);
    }

    #[test]
    fn get_bridge_messages_pages_from_a_sequence() {
        let b = with_bridge_state();
        let v = get_bridge_messages(
            &b,
            &json!({ "domain": 11_155_111, "fromSeq": 2, "limit": 10 }),
        )
        .unwrap();
        assert_eq!(v["lastSeq"], 3);
        let msgs = v["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["domainSeq"], 2);
        assert_eq!(msgs[0]["solidusHeight"], 1002);
        assert_eq!(msgs[0]["message"], "0x02020202");
        assert_eq!(
            msgs[0]["messageId"],
            format!(
                "0x{}",
                hex::encode(solidus_bridge_codec::keccak256(&[2, 2, 2, 2]))
            )
        );
    }

    #[test]
    fn get_bridge_messages_refuses_a_page_over_500() {
        let err = get_bridge_messages(
            &with_bridge_state(),
            &json!({ "domain": 1, "fromSeq": 1, "limit": 501 }),
        )
        .unwrap_err();
        assert!(matches!(err, RpcError::InvalidParams(_)));
    }

    /// `with_bridge_state` queues 3 messages on 11155111. This signs 1 and 3, leaving 2 unsigned,
    /// so "omits what it has not signed" is testable without a second fixture.
    fn with_attestations() -> StubBackend {
        let mut b = with_bridge_state();
        b.signer = Some([0x5A; 20]);
        b.attestations.insert((11_155_111, 1), [0x11; 65]);
        b.attestations.insert((11_155_111, 3), [0x33; 65]);
        b
    }

    #[test]
    fn get_bridge_attestation_returns_one_entry_per_signed_sequence() {
        let v = get_bridge_attestation(
            &with_attestations(),
            &json!({ "domain": 11_155_111, "fromSeq": 1, "toSeq": 3 }),
        )
        .unwrap();
        let a = v["attestations"].as_array().unwrap();
        assert_eq!(a.len(), 2, "two of the three sequences are signed");
        assert_eq!(a[0]["domainSeq"], 1);
        assert_eq!(
            a[0]["signature"],
            format!("0x{}", hex::encode([0x11u8; 65]))
        );
        // messageId and solidusHeight come from the OUTBOX, not from the signature.
        assert_eq!(a[0]["solidusHeight"], 1001);
        assert_eq!(
            a[0]["messageId"],
            format!(
                "0x{}",
                hex::encode(solidus_bridge_codec::keccak256(&[1, 1, 1, 1]))
            )
        );
        assert_eq!(a[1]["domainSeq"], 3);
        assert_eq!(a[1]["solidusHeight"], 1003);
    }

    /// ⛔ OMITTED, NOT NULL. An entry carrying `"signature": null` counts toward a threshold in
    /// any assembler that measures the list rather than inspecting every field.
    #[test]
    fn an_unsigned_sequence_is_omitted_rather_than_returned_with_a_null() {
        let v = get_bridge_attestation(
            &with_attestations(),
            &json!({ "domain": 11_155_111, "fromSeq": 2, "toSeq": 2 }),
        )
        .unwrap();
        let a = v["attestations"].as_array().unwrap();
        assert!(
            a.is_empty(),
            "sequence 2 is unsigned, so it is not in the list"
        );
        assert_eq!(
            v["signer"],
            format!("0x{}", hex::encode([0x5Au8; 20])),
            "the signer is reported even when the list is empty, or a caller cannot tell whose \
             empty answer this is"
        );
    }

    #[test]
    fn get_bridge_attestation_refuses_a_range_of_500_or_more() {
        let b = with_attestations();
        // Inclusive, so 500 sequences is a difference of 499 and must be accepted.
        assert!(
            get_bridge_attestation(&b, &json!({ "domain": 1, "fromSeq": 1, "toSeq": 500 })).is_ok(),
            "exactly 500 sequences is the limit, not one past it"
        );
        let err = get_bridge_attestation(&b, &json!({ "domain": 1, "fromSeq": 1, "toSeq": 501 }))
            .unwrap_err();
        assert!(matches!(err, RpcError::InvalidParams(_)));
        let backwards =
            get_bridge_attestation(&b, &json!({ "domain": 1, "fromSeq": 5, "toSeq": 4 }))
                .unwrap_err();
        assert!(
            matches!(backwards, RpcError::InvalidParams(_)),
            "a reversed range is a caller error, not an empty answer"
        );
    }

    #[test]
    fn a_node_with_no_attestation_key_reports_a_null_signer_and_no_attestations() {
        let v = get_bridge_attestation(
            &with_bridge_state(),
            &json!({ "domain": 11_155_111, "fromSeq": 1, "toSeq": 3 }),
        )
        .unwrap();
        assert_eq!(v["signer"], Value::Null, "this node does not attest");
        assert!(v["attestations"].as_array().unwrap().is_empty());
    }

    #[test]
    fn get_exports_returns_entries_or_an_empty_list() {
        let b = with_bridge_state();
        let v = get_exports(&b, &json!({ "credentialId": "urn:c" })).unwrap();
        assert_eq!(v["entries"][0]["status"], 1);
        assert_eq!(
            v["entries"][0]["exportId"],
            format!("0x{}", hex::encode([4u8; 32]))
        );
        assert_eq!(
            get_exports(&b, &json!({ "credentialId": "urn:none" })).unwrap()["entries"],
            json!([])
        );
    }

    #[test]
    fn latest_committed_height_is_the_canon_head_or_null() {
        let b = StubBackend::default();
        let v = get_latest_committed_height(&b, &json!({})).unwrap();
        assert_eq!(
            v["height"],
            match b.canon_head() {
                Some((h, _)) => json!(h),
                None => Value::Null,
            }
        );
    }

    #[test]
    fn state_proof_and_committee_are_refused_when_not_wired() {
        let b = StubBackend::default();
        assert!(matches!(
            get_state_proof(&b, &json!({ "tree": "credentials", "key": "0x00" })),
            Err(RpcError::PolicyDisabled(_))
        ));
        assert!(matches!(
            get_state_proof(&b, &json!({ "tree": "nope", "key": "0x00" })),
            Err(RpcError::InvalidParams(_))
        ));
        assert!(matches!(
            get_committee(&b, &json!({})),
            Err(RpcError::PolicyDisabled(_))
        ));
    }

    /// ⛔ `attestationAddress` WAS NEVER EMITTED (found 2026-09-29), so the committee reported null
    /// for all four validators while each signed as its configured address. Present, and absent
    /// where the config declares none: both shapes are pinned.
    #[test]
    fn committee_reports_each_validators_attestation_address() {
        let b = StubBackend {
            committee: Some(crate::backend::CommitteeInfo {
                chain_id: 50002,
                quorum: 3,
                pop_activation_view: 0,
                validators: vec![
                    (0, [1u8; 48], None, Some([0xab; 20])),
                    (1, [2u8; 48], None, None),
                ],
            }),
            ..Default::default()
        };
        let v = get_committee(&b, &json!({})).unwrap();
        assert_eq!(
            v["validators"][0]["attestationAddress"],
            json!(format!("0x{}", "ab".repeat(20)))
        );
        assert_eq!(v["validators"][1]["attestationAddress"], Value::Null);
    }

    /// Bridge plan 02 Task 16. "No evidence yet" is its own answer (-32006): a
    /// relayer waits on it, and must not read it as "not found" or "refused".
    #[test]
    fn finality_evidence_is_its_own_error_until_it_exists() {
        let b = StubBackend::default();
        assert!(matches!(
            get_finality_evidence(&b, &json!({ "atOrAbove": 1 })),
            Err(RpcError::NoEvidenceYet)
        ));
    }
}

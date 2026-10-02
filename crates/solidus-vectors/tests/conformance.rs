//! Runs every published conformance vector against this workspace.
//!
//! WHY THIS IS A TEST AND NOT A BINARY. `test-vectors/` is what we hand third
//! parties and tell them to run against their own implementation — "do not take
//! this text, or our code, on trust". Until now nothing ran it against *our*
//! Rust. The TypeScript runner in `solidus-test-vectors/runner` did, so the
//! chain — the reference implementation everyone else must match — was the one
//! part of the system with no conformance check pointed at it.
//!
//! THE ONE RULE THIS FILE ENFORCES ABOUT ITSELF: an unimplemented category is a
//! FAILURE, never a skip. A runner that silently passes vectors it does not
//! understand reports "12/12" while checking three of them, which is worse than
//! having no runner — it manufactures false confidence in exactly the artifact
//! we ask outsiders to trust. Every category below is either implemented or
//! loudly `Unimplemented`.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

#[derive(Debug)]
enum Outcome {
    Pass,
    Fail(String),
    /// Not yet implemented in Rust. Counts as a failure — see the module note.
    ///
    /// Never constructed today, and kept deliberately: the summary already knows how to render
    /// it, so the day a vector lands with no Rust runner the reader gets the distinction below
    /// rather than a bare failure. Deleting it to satisfy `dead_code` would throw away the
    /// design note, which is the opposite of what the lint is for.
    #[allow(dead_code)]
    Unimplemented,
    /// Implementable, but doing so would bake in an answer to an open question.
    /// Distinct from `Unimplemented` on purpose: "nobody wrote it yet" and
    /// "writing it decides something" need different responses from a reader.
    ///
    /// Also never constructed yet, and kept for the same reason.
    #[allow(dead_code)]
    Blocked(String),
    /// Tests a layer this crate deliberately does not own. Does NOT count as a
    /// failure — but the summary states the split explicitly, because "green"
    /// must never be readable as "all twelve pass".
    OutOfScope(String),
}

/// Walk up from this crate until `test-vectors/` appears. Beats a pile of `..`
/// segments, which break the moment the crate moves.
fn vectors_root() -> PathBuf {
    let mut dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = dir.join("test-vectors");
        if candidate.is_dir() {
            return candidate;
        }
        dir = dir.parent().unwrap_or_else(|| {
            panic!("walked to the filesystem root without finding test-vectors/")
        });
    }
}

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable vector directory") {
        let path = entry.expect("readable dir entry").path();
        if path.is_dir() {
            collect(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------- categories

/// BLAKE3_160(data) = BLAKE3-256(data)[0..20].
///
/// This vector exists because `docs/protocol.md` once described
/// RIPEMD-160(BLAKE3-256(data)) — a doc/code mismatch that would have given a
/// different address for the same public key in any implementation that trusted
/// the prose. Value-locked here so prose can never win again.
fn run_hash160(v: &Value) -> Outcome {
    let Some(data) = v["input"]["dataUtf8"].as_str() else {
        return Outcome::Fail("input.dataUtf8 missing".into());
    };
    let Some(expected) = v["expected"]["hash160Hex"].as_str() else {
        return Outcome::Fail("expected.hash160Hex missing".into());
    };
    let actual = hex(&solidus_crypto::hash::hash160(data.as_bytes()));
    if actual == expected {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("expected {expected}, got {actual}"))
    }
}

/// BIP-39 mnemonic -> identity key -> address, plus the per-verifier pairwise key.
///
/// ⚠ FROZEN. Asserted in four places now (this runner, the TypeScript SDK, the
/// identity backend, the identity frontend). A mismatch here is not a bug in the
/// vector — it is a key-derivation change that would re-key real users.
fn run_did_derivation(v: &Value) -> Outcome {
    let (Some(mnemonic), Some(network), Some(verifier)) = (
        v["input"]["mnemonic"].as_str(),
        v["input"]["network"].as_str(),
        v["input"]["pairwiseVerifierId"].as_str(),
    ) else {
        return Outcome::Fail("input fields missing".into());
    };

    // The vector's mnemonic is ASCII, so NFKD is the identity transform here.
    let seed = solidus_client::derivation::seed_from_mnemonic_nfkd(mnemonic);
    let identity = solidus_client::derivation::identity_key(&seed);
    let pairwise = solidus_client::derivation::pairwise_key(&seed, verifier);

    let checks: [(&str, String, &str); 4] = [
        (
            "identityPublicKeyHex",
            hex(&identity.public_key),
            v["expected"]["identityPublicKeyHex"].as_str().unwrap_or(""),
        ),
        (
            "identityAddress",
            identity.address.to_base58(),
            v["expected"]["identityAddress"].as_str().unwrap_or(""),
        ),
        (
            "pairwisePublicKeyHex",
            hex(&pairwise.public_key),
            v["expected"]["pairwisePublicKeyHex"].as_str().unwrap_or(""),
        ),
        (
            "pairwiseDid",
            pairwise.did(network),
            v["expected"]["pairwiseDid"].as_str().unwrap_or(""),
        ),
    ];

    let mismatches: Vec<String> = checks
        .iter()
        .filter(|(_, actual, expected)| actual != expected)
        .map(|(field, actual, expected)| format!("{field}: expected {expected}, got {actual}"))
        .collect();

    if mismatches.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail(mismatches.join("; "))
    }
}

/// `DidCreate` transaction signing. Fully recomputable — private key + nonce +
/// service endpoints in, signature out, no chain involved.
///
/// The preimage hashes the payload's **JSON serialisation**, so this vector
/// pins serde's output as consensus-relevant. That is the detail a port cannot
/// infer from a struct definition.
fn run_did_tx_create(v: &Value) -> Outcome {
    let Some(priv_hex) = v["input"]["signerPrivateKeyHex"].as_str() else {
        return Outcome::Fail("input.signerPrivateKeyHex missing".into());
    };
    let nonce = v["input"]["nonce"].as_u64().unwrap_or(0);
    if !v["input"]["serviceEndpoints"]
        .as_array()
        .is_some_and(|a| a.is_empty())
    {
        return Outcome::Fail(
            "this runner only handles the empty serviceEndpoints case the vector uses".into(),
        );
    }

    let mut private_key = [0u8; 32];
    for (i, byte) in private_key.iter_mut().enumerate() {
        let Ok(b) = u8::from_str_radix(&priv_hex[i * 2..i * 2 + 2], 16) else {
            return Outcome::Fail("signerPrivateKeyHex is not valid hex".into());
        };
        *byte = b;
    }

    let signed = solidus_client::tx::sign_did_create(&private_key, nonce, Vec::new());

    let checks: [(&str, String, &str); 3] = [
        (
            "senderPubkeyHex",
            hex(&signed.sender_pubkey),
            v["expected"]["senderPubkeyHex"].as_str().unwrap_or(""),
        ),
        (
            "payloadPublicKeyHex",
            hex(&signed.sender_pubkey),
            v["expected"]["payloadPublicKeyHex"].as_str().unwrap_or(""),
        ),
        (
            "signatureHex",
            hex(&signed.signature),
            v["expected"]["signatureHex"].as_str().unwrap_or(""),
        ),
    ];

    let mismatches: Vec<String> = checks
        .iter()
        .filter(|(_, actual, expected)| actual != expected)
        .map(|(f, a, e)| format!("{f}: expected {e}, got {a}"))
        .collect();

    if mismatches.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail(mismatches.join("; "))
    }
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

fn hexes(v: &Value) -> Option<Vec<Vec<u8>>> {
    v.as_array()?.iter().map(|m| unhex(m.as_str()?)).collect()
}

/// BBS+ keygen + sign + verify. The signature is ground truth from
/// `solidus-crypto`, so a mismatch here means the ciphersuite moved under us.
fn run_bbs_sign_verify(v: &Value) -> Outcome {
    use solidus_crypto::bbs::{BbsSecretKey, BbsSignature};
    let (Some(sk_hex), Some(hdr), Some(msgs), Some(sig_hex)) = (
        v["input"]["secretKeyHex"].as_str(),
        v["input"]["headerHex"].as_str().and_then(unhex),
        hexes(&v["input"]["messageHexes"]),
        v["input"]["signatureHex"].as_str(),
    ) else {
        return Outcome::Fail("input fields missing".into());
    };

    let Some(sk_bytes) = unhex(sk_hex) else {
        return Outcome::Fail("secretKeyHex not hex".into());
    };
    let Ok(sk_arr): Result<[u8; 32], _> = sk_bytes.try_into() else {
        return Outcome::Fail("secret key is not 32 bytes".into());
    };
    // from_bytes, not from_ikm: implementations disagree about BBS KeyGen, which
    // is why the vector publishes a derived key rather than only the IKM.
    let Ok(sk) = BbsSecretKey::from_bytes(&sk_arr) else {
        return Outcome::Fail("secret key rejected".into());
    };
    let pk = sk.public_key();

    let expected_pk = v["expected"]["publicKeyHex"].as_str().unwrap_or("");
    if pk.to_hex() != expected_pk {
        return Outcome::Fail(format!(
            "publicKeyHex: expected {expected_pk}, got {}",
            pk.to_hex()
        ));
    }

    let Ok(sig) = BbsSignature::from_hex(sig_hex) else {
        return Outcome::Fail("signatureHex rejected".into());
    };
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let verified = sig.is_valid(&pk, &hdr, &refs);
    let want = v["expected"]["signatureVerifies"].as_bool().unwrap_or(true);
    if verified == want {
        Outcome::Pass
    } else {
        Outcome::Fail(format!(
            "signatureVerifies: expected {want}, got {verified}"
        ))
    }
}

/// Selective disclosure: prove a subset without revealing the rest.
/// `negative` flips the expectation, for the lied-disclosure vector.
fn run_bbs_selective_disclosure(v: &Value) -> Outcome {
    use solidus_crypto::bbs::{BbsPublicKey, BbsSignature};
    let disclosed_field = if v["input"]["liedDisclosedMessageHexes"].is_array() {
        "liedDisclosedMessageHexes"
    } else {
        "disclosedMessageHexes"
    };
    let (Some(pk_hex), Some(hdr), Some(sig_hex), Some(msgs), Some(ph), Some(idx), Some(disclosed)) = (
        v["input"]["publicKeyHex"].as_str(),
        v["input"]["headerHex"].as_str().and_then(unhex),
        v["input"]["signatureHex"].as_str(),
        hexes(&v["input"]["messageHexes"]),
        v["input"]["presentationHeaderHex"].as_str().and_then(unhex),
        v["input"]["disclosedIndices"].as_array().map(|a| {
            a.iter()
                .filter_map(|i| i.as_u64().map(|n| n as usize))
                .collect::<Vec<_>>()
        }),
        hexes(&v["input"][disclosed_field]),
    ) else {
        return Outcome::Fail("input fields missing".into());
    };

    let (Ok(pk), Ok(sig)) = (
        BbsPublicKey::from_hex(pk_hex),
        BbsSignature::from_hex(sig_hex),
    ) else {
        return Outcome::Fail("public key or signature rejected".into());
    };
    let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
    let Ok(proof) = sig.create_proof(&pk, &hdr, &ph, &refs, &idx) else {
        return Outcome::Fail("proof generation failed".into());
    };

    let disclosed_refs: Vec<&[u8]> = disclosed.iter().map(|m| m.as_slice()).collect();
    let verified = proof.verify(&pk, &hdr, &ph, &idx, &disclosed_refs).is_ok();
    let want = v["expected"]["proofVerifies"].as_bool().unwrap_or(true);
    if verified == want {
        Outcome::Pass
    } else {
        Outcome::Fail(format!("proofVerifies: expected {want}, got {verified}"))
    }
}

/// Every negative case must fail to verify. These matter more than the positive
/// vectors: an implementation that accepts a tampered proof passes every
/// happy-path check and is still broken.
fn run_bbs_negative_cases(v: &Value) -> Outcome {
    use solidus_crypto::bbs::{BbsPublicKey, BbsSignature};
    let (Some(pk_hex), Some(hdr), Some(msgs), Some(sig_hex), Some(cases)) = (
        v["input"]["publicKeyHex"].as_str(),
        v["input"]["headerHex"].as_str().and_then(unhex),
        hexes(&v["input"]["messageHexes"]),
        v["input"]["signatureHex"].as_str(),
        v["input"]["cases"].as_array(),
    ) else {
        return Outcome::Fail("input fields missing".into());
    };

    let (Ok(base_pk), Ok(sig)) = (
        BbsPublicKey::from_hex(pk_hex),
        BbsSignature::from_hex(sig_hex),
    ) else {
        return Outcome::Fail("base public key or signature rejected".into());
    };

    let mut accepted: Vec<String> = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("<unnamed>");
        let mut messages = msgs.clone();
        if let (Some(i), Some(hexv)) = (
            case["messageOverrideIndex"].as_u64(),
            case["messageOverrideHex"].as_str().and_then(unhex),
        ) {
            if (i as usize) < messages.len() {
                messages[i as usize] = hexv;
            }
        }
        let header = case["headerOverrideHex"]
            .as_str()
            .and_then(unhex)
            .unwrap_or_else(|| hdr.clone());
        let pk = match case["publicKeyOverrideHex"].as_str() {
            Some(h) => match BbsPublicKey::from_hex(h) {
                Ok(p) => p,
                Err(_) => return Outcome::Fail(format!("{name}: override public key rejected")),
            },
            None => base_pk.clone(),
        };

        let refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();
        if sig.is_valid(&pk, &header, &refs) {
            accepted.push(name.to_string());
        }
    }

    let want_all_false = v["expected"]["allCasesVerifyFalse"]
        .as_bool()
        .unwrap_or(true);
    if accepted.is_empty() == want_all_false {
        Outcome::Pass
    } else {
        Outcome::Fail(format!(
            "these cases verified when they must not: {accepted:?}"
        ))
    }
}

/// A recorded `solidus_didResolve` response in the W3C DID Resolution shape.
///
/// The vector is replay-only — a fresh chain has no history to reproduce a
/// specific resolve against — so this checks the parts that ARE derivable from
/// `input.signerPublicKeyHex` and shape-checks the rest. That is still the
/// interesting half: the DID and the `publicKeyMultibase` are both functions of
/// the key, and getting either wrong is exactly how an implementation diverges.
fn run_did_resolve(v: &Value) -> Outcome {
    let Some(pk_hex) = v["input"]["signerPublicKeyHex"].as_str() else {
        return Outcome::Fail("input.signerPublicKeyHex missing".into());
    };
    let Some(pk_vec) = unhex(pk_hex) else {
        return Outcome::Fail("signerPublicKeyHex not hex".into());
    };
    let Ok(pk): Result<[u8; 32], _> = pk_vec.try_into() else {
        return Outcome::Fail("public key is not 32 bytes".into());
    };

    let doc = &v["expected"]["didDocument"];
    let mut problems: Vec<String> = Vec::new();

    // The identifier is derivable from the key.
    let expected_did = v["input"]["did"].as_str().unwrap_or("");
    let derived_id = solidus_client::did::identifier_for(&pk);
    if !expected_did.ends_with(&derived_id) {
        problems.push(format!(
            "did does not end with the derived identifier {derived_id}"
        ));
    }
    if !solidus_client::did::is_valid_did(expected_did) {
        problems.push(format!("did fails SPEC v0.2.0 §4.1 syntax: {expected_did}"));
    }

    // So is publicKeyMultibase — and this is the value the whole R3b block was about.
    let want_mb = solidus_client::did::public_key_multibase(&pk);
    let got_mb = doc["verificationMethod"][0]["publicKeyMultibase"]
        .as_str()
        .unwrap_or("");
    if got_mb != want_mb {
        problems.push(format!(
            "publicKeyMultibase: expected {want_mb}, got {got_mb}"
        ));
    }

    // W3C DID Resolution shape.
    for key in [
        "didDocument",
        "didDocumentMetadata",
        "didResolutionMetadata",
    ] {
        if v["expected"][key].is_null() {
            problems.push(format!("missing {key}"));
        }
    }
    if doc["id"].as_str() != Some(expected_did) {
        problems.push("didDocument.id does not match the resolved DID".into());
    }

    // deactivate-v1 is the same document after a tombstone flag.
    if let Some(expected_deactivated) =
        v["expected"]["didDocumentMetadata"]["deactivated"].as_bool()
    {
        let is_deactivate_vector = v["category"].as_str() == Some("did-deactivate");
        if expected_deactivated != is_deactivate_vector {
            problems.push(format!(
                "didDocumentMetadata.deactivated is {expected_deactivated} for a {} vector",
                v["category"].as_str().unwrap_or("?")
            ));
        }
    }

    if problems.is_empty() {
        Outcome::Pass
    } else {
        Outcome::Fail(problems.join("; "))
    }
}

/// The v2 transaction wire format.
///
/// ⛔ CHECKED FROM PRIMITIVES, NOT BY RE-RUNNING THE ENCODER THAT PRODUCED IT.
/// These vectors are what we hand third parties and tell them to run against
/// their own implementation. Verifying them by calling `bincode::serialize`
/// would prove only that bincode agrees with itself; it would pass even if the
/// documented rules were wrong. So this reassembles the transaction from its
/// PARTS using the rules as written, and checks the two hashes:
///
///   wire          = sender_pubkey ‖ nonce_le ‖ payload ‖ u64(64) ‖ signature
///   signing_bytes = BLAKE3(sender_pubkey ‖ nonce_le ‖ payload)
///   tx_hash       = BLAKE3(wire)
///
/// ⚠ The signature is LENGTH-PREFIXED and the pubkey is NOT. Two fixed-size
/// byte arrays in one struct, encoded differently, because one carries a
/// `serde_bytes` attribute. An implementer who misses that produces a wire that
/// decodes into the wrong fields, so it is the single most valuable thing these
/// vectors pin.
fn run_tx_wire_binaryv2(v: &Value) -> Outcome {
    let Some(cases) = v["cases"].as_object() else {
        return Outcome::Fail("no `cases` object".into());
    };
    if cases.is_empty() {
        // A file with no cases would pass every assertion below vacuously.
        return Outcome::Fail("`cases` is empty".into());
    }

    for (name, c) in cases {
        let hexf = |k: &str| -> Result<Vec<u8>, String> {
            c[k].as_str()
                .ok_or_else(|| format!("{name}: `{k}` is not a string"))
                .and_then(|h| unhex(h).ok_or_else(|| format!("{name}: `{k}` is not hex")))
        };
        let (pubkey, payload, sig, wire, signing, tx_hash) = match (
            hexf("sender_pubkey"),
            hexf("payload_bincode"),
            hexf("signature"),
            hexf("wire"),
            hexf("signing_bytes"),
            hexf("tx_hash"),
        ) {
            (Ok(a), Ok(b), Ok(c2), Ok(d), Ok(e), Ok(f)) => (a, b, c2, d, e, f),
            _ => return Outcome::Fail(format!("{name}: a field is missing or not hex")),
        };
        let Some(nonce) = c["nonce"].as_u64() else {
            return Outcome::Fail(format!("{name}: `nonce` is not a u64"));
        };

        if pubkey.len() != 32 {
            return Outcome::Fail(format!("{name}: sender_pubkey is {} bytes", pubkey.len()));
        }
        if sig.len() != 64 {
            return Outcome::Fail(format!("{name}: signature is {} bytes", sig.len()));
        }

        // Rebuild the wire from the documented rules.
        let mut rebuilt = Vec::with_capacity(wire.len());
        rebuilt.extend_from_slice(&pubkey);
        rebuilt.extend_from_slice(&nonce.to_le_bytes());
        rebuilt.extend_from_slice(&payload);
        rebuilt.extend_from_slice(&(sig.len() as u64).to_le_bytes());
        rebuilt.extend_from_slice(&sig);
        if rebuilt != wire {
            return Outcome::Fail(format!(
                "{name}: `wire` does not match pubkey‖nonce_le‖payload‖len(sig)‖sig"
            ));
        }

        let mut preimage = Vec::with_capacity(32 + 8 + payload.len());
        preimage.extend_from_slice(&pubkey);
        preimage.extend_from_slice(&nonce.to_le_bytes());
        preimage.extend_from_slice(&payload);
        if solidus_crypto::hash::blake3_hash(&preimage).to_vec() != signing {
            return Outcome::Fail(format!(
                "{name}: `signing_bytes` is not BLAKE3 of the preimage"
            ));
        }

        if solidus_crypto::hash::blake3_hash(&wire).to_vec() != tx_hash {
            return Outcome::Fail(format!("{name}: `tx_hash` is not BLAKE3 of `wire`"));
        }
    }
    Outcome::Pass
}

fn dispatch(category: &str, v: &Value) -> Outcome {
    match category {
        "hash160" => run_hash160(v),
        "did-derivation" => run_did_derivation(v),
        "did-tx-create" => run_did_tx_create(v),
        "bbs-sign-verify" => run_bbs_sign_verify(v),
        "bbs-selective-disclosure" | "bbs-selective-disclosure-negative" => {
            run_bbs_selective_disclosure(v)
        }
        "bbs-negative-cases" => run_bbs_negative_cases(v),
        "tx-wire-binaryv2" => run_tx_wire_binaryv2(v),

        // Implemented next, in this order (see 2026-08-07-sdk-rust.md):
        //   did-derivation  — BIP-39 -> identity key -> address -> DID, plus the
        //                     HKDF pairwise hierarchy. FROZEN: changing any value
        //                     re-keys real users.
        //   did-tx-create / did-deactivate — byte-exact signing_bytes.
        //   did-resolve     — decodes the WIRE shape, not our TypeScript types.
        //   bbs-*           — zkryptium 0.6, byte-compatible with the vectors.
        //   credential-bundle — message-map order is frozen once shipped.
        "did-resolve" | "did-deactivate" => run_did_resolve(v),

        // DECIDED 2026-08-07 (R6b): the Rust client does not own agent credentials.
        // These vectors exercise the agent-identity MESSAGE MAP — owner_binding,
        // capability_scope, spend_mandate — which is a product-layer schema, not a
        // protocol primitive. The chain knows only a generic CredentialType; how
        // claims are laid out for BBS+ signing is agent-identity's choice and is
        // still moving. Porting it here would double the maintenance surface for a
        // schema this crate has no stake in. They remain conformance vectors — for
        // the agent-identity SDK, not for solidus-client.
        "credential-bundle" => Outcome::OutOfScope(
            "agent-identity message map — product layer, not the protocol surface (R6b)".into(),
        ),

        other => Outcome::Fail(format!(
            "unknown category {other:?} — a new vector was published and this runner \
             was not taught about it; that is a failure, not a skip"
        )),
    }
}

#[test]
fn conformance_vectors() {
    let root = vectors_root();
    let mut files = Vec::new();
    collect(&root, &mut files);
    files.sort();

    assert!(
        !files.is_empty(),
        "found zero vectors under {} — an empty run must never report success",
        root.display()
    );

    let mut passed = 0usize;
    let mut failures: Vec<String> = Vec::new();
    let mut out_of_scope: Vec<String> = Vec::new();

    println!("\nconformance vectors — {}\n", root.display());
    for path in &files {
        let raw = fs::read_to_string(path).expect("readable vector");
        let v: Value = serde_json::from_str(&raw).expect("vector is valid JSON");
        let category = v["category"].as_str().unwrap_or("<missing>");
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .display()
            .to_string();

        let outcome = dispatch(category, &v);
        let label = match &outcome {
            Outcome::Pass => {
                passed += 1;
                "PASS".to_string()
            }
            Outcome::Unimplemented => {
                failures.push(format!("{rel} [{category}] not implemented in Rust"));
                "TODO".to_string()
            }
            Outcome::OutOfScope(why) => {
                out_of_scope.push(format!("{rel} [{category}] {why}"));
                "SKIP".to_string()
            }
            Outcome::Blocked(why) => {
                failures.push(format!("{rel} [{category}] BLOCKED — {why}"));
                "BLKD".to_string()
            }
            Outcome::Fail(why) => {
                failures.push(format!("{rel} [{category}] {why}"));
                "FAIL".to_string()
            }
        };
        println!("  [{label}] {category:<34} {rel}");
    }

    let in_scope = files.len() - out_of_scope.len();
    println!(
        "\n  {passed}/{in_scope} IN-SCOPE vectors pass ({} outstanding)",
        failures.len()
    );
    if !out_of_scope.is_empty() {
        println!(
            "  {} of {} vectors are OUT OF SCOPE for this crate — green here does NOT mean {}/{} :",
            out_of_scope.len(),
            files.len(),
            files.len(),
            files.len()
        );
        for o in &out_of_scope {
            println!("    {o}");
        }
    }
    println!();

    assert!(
        failures.is_empty(),
        "conformance vectors outstanding:\n  {}",
        failures.join("\n  ")
    );
}

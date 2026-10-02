//! Proof of possession (IRTF draft-irtf-cfrg-bls-signature, PopProve / PopVerify).
//! Regenerate the vector deliberately: UPDATE_VECTORS=1 cargo test -p solidus-crypto --features consensus --test bls_pop

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_crypto::bls::{BlsSecretKey, BlsSignature, DST_BASIC, DST_POP_PROOF, DST_POP_SIG};

fn key(seed: u8) -> BlsSecretKey {
    BlsSecretKey::from_bytes(
        &blst::min_pk::SecretKey::key_gen(&[seed; 32], &[])
            .unwrap()
            .to_bytes(),
    )
    .unwrap()
}

#[test]
fn the_three_dsts_are_the_irtf_strings() {
    assert_eq!(DST_BASIC, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_");
    assert_eq!(DST_POP_SIG, b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
    assert_eq!(
        DST_POP_PROOF,
        b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"
    );
}

#[test]
fn a_proof_verifies_for_its_own_key_only() {
    let (a, b) = (key(1), key(2));
    let pop = a.prove_possession();
    assert!(a.public_key().verify_possession(&pop));
    assert!(!b.public_key().verify_possession(&pop));
}

#[test]
fn a_proof_is_not_a_message_signature_over_the_key_bytes() {
    let a = key(1);
    let pk = a.public_key().to_bytes();
    let as_message = a.sign_with_dst(&pk, DST_POP_SIG);
    assert!(
        !a.public_key().verify_possession(&as_message),
        "domain separation between PoP and signatures"
    );
}

#[test]
fn signatures_under_one_dst_do_not_verify_under_the_other() {
    let a = key(3);
    let msg = [9u8; 32];
    let pop_sig = a.sign_with_dst(&msg, DST_POP_SIG);
    assert!(pop_sig.verify_with_dst(&a.public_key(), &msg, DST_POP_SIG));
    assert!(!pop_sig.verify_with_dst(&a.public_key(), &msg, DST_BASIC));
    assert!(
        !pop_sig.verify(&a.public_key(), &msg),
        "legacy verify stays on the basic suite"
    );
    let agg = BlsSignature::aggregate(&[&pop_sig]).unwrap();
    assert!(agg.fast_aggregate_verify_with_dst(&[&a.public_key()], &msg, DST_POP_SIG));
    assert!(!agg.fast_aggregate_verify(&[&a.public_key()], &msg));
}

fn vectors_path() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().expect("cwd");
    loop {
        let c = dir.join("test-fixtures");
        if c.is_dir() {
            return c.join("bls").join("pop-v1.json");
        }
        dir = dir.parent().expect("test-vectors/ not found");
    }
}

#[test]
fn pop_vectors_match_the_committed_file() {
    let produced: Value = json!({ "version": 1, "cases": (1u8..=3).map(|s| {
        let k = key(s);
        json!({ "keyGenSeedByte": s, "publicKey": hex::encode(k.public_key().to_bytes()), "pop": hex::encode(k.prove_possession().to_bytes()) })
    }).collect::<Vec<_>>() });
    let path = vectors_path();
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .unwrap();
        return;
    }
    let committed: Value = serde_json::from_str(
        &std::fs::read_to_string(&path).expect("pop-v1.json missing: regenerate deliberately"),
    )
    .unwrap();
    assert_eq!(committed, produced);
}

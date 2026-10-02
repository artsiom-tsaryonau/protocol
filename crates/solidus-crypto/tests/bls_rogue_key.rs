//! The attack the PoP ciphersuite exists to stop, demonstrated, so the fix is
//! tested against the real thing rather than described.
//!
//! An attacker who sees honest key P_h registers P_r = x·G1 − P_h. The aggregate
//! of {P_h, P_r} is x·G1, so the attacker alone produces a signature that
//! `fast_aggregate_verify` accepts for BOTH keys. The only defence is refusing
//! P_r at admission, because nobody can prove possession of its secret.
//! Regenerate: UPDATE_VECTORS=1 cargo test -p solidus-crypto --features consensus --test bls_rogue_key

use std::path::{Path, PathBuf};

use blst::{
    blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress, blst_p1_cneg,
    blst_p1_from_affine, blst_p1_to_affine, blst_p1_uncompress, blst_scalar,
    blst_scalar_from_bendian, blst_sk_to_pk_in_g1, BLST_ERROR,
};
use serde_json::{json, Value};
use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey, BlsSignature, DST_BASIC, DST_POP_SIG};

fn key(seed: u8) -> BlsSecretKey {
    BlsSecretKey::from_bytes(
        &blst::min_pk::SecretKey::key_gen(&[seed; 32], &[])
            .unwrap()
            .to_bytes(),
    )
    .unwrap()
}

/// P_r = x·G1 − P_h, compressed.
fn rogue_public_key(attacker_secret_be: &[u8; 32], honest_pk: &[u8; 48]) -> [u8; 48] {
    // SAFETY: fixed-size inputs, every pointer refers to a local of the right blst type.
    unsafe {
        let mut scalar = blst_scalar::default();
        blst_scalar_from_bendian(&mut scalar, attacker_secret_be.as_ptr());
        let mut attacker = blst_p1::default();
        blst_sk_to_pk_in_g1(&mut attacker, &scalar);

        let mut honest_affine = blst_p1_affine::default();
        assert_eq!(
            blst_p1_uncompress(&mut honest_affine, honest_pk.as_ptr()),
            BLST_ERROR::BLST_SUCCESS
        );
        let mut honest = blst_p1::default();
        blst_p1_from_affine(&mut honest, &honest_affine);
        blst_p1_cneg(&mut honest, true);

        let mut rogue = blst_p1::default();
        blst_p1_add_or_double(&mut rogue, &attacker, &honest);
        let mut rogue_affine = blst_p1_affine::default();
        blst_p1_to_affine(&mut rogue_affine, &rogue);
        let mut out = [0u8; 48];
        blst_p1_affine_compress(out.as_mut_ptr(), &rogue_affine);
        out
    }
}

struct Scenario {
    honest: BlsPublicKey,
    attacker: BlsSecretKey,
    rogue: BlsPublicKey,
    msg: [u8; 32],
}

fn scenario() -> Scenario {
    let honest = key(1).public_key();
    let attacker = key(66);
    let rogue =
        BlsPublicKey::from_bytes(&rogue_public_key(&attacker.to_bytes(), &honest.to_bytes()))
            .expect("rogue key is a valid point");
    Scenario {
        honest,
        attacker,
        rogue,
        msg: [0x42; 32],
    }
}

#[test]
fn without_possession_checks_one_attacker_forges_a_two_key_aggregate_under_either_suite() {
    let s = scenario();
    for dst in [DST_BASIC, DST_POP_SIG] {
        let forged = s.attacker.sign_with_dst(&s.msg, dst);
        assert!(
            forged.fast_aggregate_verify_with_dst(&[&s.honest, &s.rogue], &s.msg, dst),
            "the forgery must verify: this is the attack, and the DST alone does not stop it"
        );
    }
}

#[test]
fn the_attacker_cannot_prove_possession_of_the_rogue_key() {
    let s = scenario();
    assert!(!s.rogue.verify_possession(&s.attacker.prove_possession()));
    let pretend = BlsSignature::aggregate(&[&s.attacker.prove_possession()]).unwrap();
    assert!(!s.rogue.verify_possession(&pretend));
}

#[test]
fn rogue_key_vector_matches_the_committed_file() {
    let s = scenario();
    let produced: Value = json!({
        "version": 1,
        "honestPublicKey": hex::encode(s.honest.to_bytes()),
        "attackerSecretKey": hex::encode(s.attacker.to_bytes()),
        "roguePublicKey": hex::encode(s.rogue.to_bytes()),
        "message": hex::encode(s.msg),
        "forgedSignaturePopSuite": hex::encode(s.attacker.sign_with_dst(&s.msg, DST_POP_SIG).to_bytes()),
        "expected": { "fastAggregateVerifyWithoutAdmission": true, "roguePossessionVerifies": false },
    });
    let mut dir: &Path = &std::env::current_dir().unwrap();
    let path: PathBuf = loop {
        let c = dir.join("test-fixtures");
        if c.is_dir() {
            break c.join("bls").join("rogue-key-v1.json");
        }
        dir = dir.parent().unwrap();
    };
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .unwrap();
        return;
    }
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("rogue-key-v1.json missing"))
            .unwrap();
    assert_eq!(committed, produced);
}

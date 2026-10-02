//! Regenerate deliberately: UPDATE_VECTORS=1 cargo test -p solidus-state-tree --test bridge_proof_vectors

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_state_tree::{verify_inclusion, InclusionProof, StateForest, TreeId};

fn path() -> PathBuf {
    let mut dir: &Path = &std::env::current_dir().unwrap();
    loop {
        let c = dir.join("test-fixtures");
        if c.is_dir() {
            return c.join("bridge").join("state-proofs-v1.json");
        }
        dir = dir.parent().unwrap();
    }
}

#[test]
fn state_proof_vectors_match_the_committed_file() {
    let mut forest = StateForest::new();
    for i in 0u8..40 {
        forest.apply(
            TreeId::Credentials,
            format!("bridge:filler:{i}").as_bytes(),
            &[i; 8],
        );
    }
    let key = b"bridge:seq:\x00\xaa\x36\xa7".to_vec();
    let value = 3u64.to_le_bytes().to_vec();
    forest.apply(TreeId::Credentials, &key, &value);
    let root = forest.subtree_root(TreeId::Credentials);
    let proof = forest
        .prove(TreeId::Credentials, &key)
        .expect("present key");

    let mut tampered = proof.clone();
    tampered.siblings[0][0] ^= 1;
    let wrong_value = 4u64.to_le_bytes().to_vec();

    let case = |name: &str, k: &[u8], v: &[u8], p: &InclusionProof| {
        json!({
            "name": name, "tree": "credentials", "key": hex::encode(k), "value": hex::encode(v), "subRoot": hex::encode(root),
            "bitmap": hex::encode(p.sibling_bitmap), "siblings": p.siblings.iter().map(hex::encode).collect::<Vec<_>>(),
            "expected": verify_inclusion(&root, k, v, p),
        })
    };
    let produced = json!({ "version": 1, "hash": "blake3", "cases": [
        case("valid", &key, &value, &proof),
        case("tampered-sibling", &key, &value, &tampered),
        case("wrong-value", &key, &wrong_value, &proof),
        case("wrong-key", b"bridge:seq:other", &value, &proof),
    ] });
    assert_eq!(produced["cases"][0]["expected"], true);
    assert_eq!(produced["cases"][1]["expected"], false);
    assert_eq!(produced["cases"][2]["expected"], false);
    assert_eq!(produced["cases"][3]["expected"], false);

    let p = path();
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            &p,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .unwrap();
        return;
    }
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("state-proofs-v1.json missing"))
            .unwrap();
    assert_eq!(committed, produced);
}

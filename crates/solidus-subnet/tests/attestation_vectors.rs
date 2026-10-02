//! Regenerate deliberately: UPDATE_VECTORS=1 cargo test -p solidus-subnet --test attestation_vectors

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
use solidus_hotstuff2::{vote_message, Block2, BlockHeader2, Committee, QuorumCert};
use solidus_state_tree::{StateForest, TreeId};
use solidus_subnet::runtime::{BridgeAttestation, BridgeVerifier};
use solidus_subnet::L1FinalizedRoots;

const CHAIN: u64 = 50_002;

fn keys() -> Vec<BlsSecretKey> {
    (1..=4u8)
        .map(|s| {
            BlsSecretKey::from_bytes(
                &blst::min_pk::SecretKey::key_gen(&[s; 32], &[])
                    .unwrap()
                    .to_bytes(),
            )
            .unwrap()
        })
        .collect()
}

fn qc(keys: &[BlsSecretKey], hash: [u8; 32], view: u64) -> QuorumCert {
    let msg = vote_message(CHAIN, view, &hash);
    let sigs: Vec<BlsSignature> = keys[..3].iter().map(|k| k.sign(&msg)).collect();
    QuorumCert {
        view,
        block_hash: hash,
        signers: vec![0, 1, 2],
        agg_sig: BlsSignature::aggregate(&sigs.iter().collect::<Vec<_>>()).unwrap(),
    }
}

fn roots_json(r: &L1FinalizedRoots) -> Value {
    json!({ "l1Height": r.l1_height, "globalRoot": hex::encode(r.global_root), "accountsRoot": hex::encode(r.accounts_root),
            "didsRoot": hex::encode(r.dids_root), "credentialsRoot": hex::encode(r.credentials_root), "validatorsRoot": hex::encode(r.validators_root) })
}

#[test]
fn attestation_vectors_match_the_committed_file() {
    let keys = keys();
    let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
    let mut forest = StateForest::new();
    forest.apply(
        TreeId::Credentials,
        b"bridge:seq:\x00\xaa\x36\xa7",
        &3u64.to_le_bytes(),
    );
    let global = forest.global_root();

    let build = |child_view: u64, child_qc_view: u64| {
        let parent_header = BlockHeader2 {
            chain_id: CHAIN,
            height: 41,
            view: 41,
            parent: [7; 32],
            batch_certs: vec![],
            exec_height: 41,
            exec_state_root: global,
            timestamp_ms: 1,
            proposer: 0,
        };
        let child = Block2 {
            header: BlockHeader2 {
                chain_id: CHAIN,
                height: 42,
                view: child_view,
                parent: parent_header.hash(),
                batch_certs: vec![],
                exec_height: 40,
                exec_state_root: [4; 32],
                timestamp_ms: 2,
                proposer: 1,
            },
            justify: qc(&keys, parent_header.hash(), 41),
        };
        let child_qc = qc(&keys, child.hash(), child_qc_view);
        L1FinalizedRoots {
            l1_height: 41,
            global_root: global,
            accounts_root: forest.subtree_root(TreeId::Accounts),
            dids_root: forest.subtree_root(TreeId::Dids),
            credentials_root: forest.subtree_root(TreeId::Credentials),
            validators_root: forest.subtree_root(TreeId::Validators),
            commit_qc: BridgeAttestation {
                parent_header,
                child,
                child_qc,
            }
            .encode(),
        }
    };
    let valid = build(42, 42);
    let non_consecutive = build(43, 43);
    let mut bad_sig = build(42, 42);
    let last = bad_sig.commit_qc.len() - 1;
    bad_sig.commit_qc[last] ^= 1;
    let mut wrong_root = build(42, 42);
    wrong_root.credentials_root[0] ^= 1;

    let verifier = BridgeVerifier::new(CHAIN, committee, [0; 32]);
    let case = |name: &str, r: &L1FinalizedRoots| json!({ "name": name, "roots": roots_json(r), "commitQc": hex::encode(&r.commit_qc), "expected": verifier.verify(r).is_ok() });
    let produced = json!({
        "version": 1, "chainId": CHAIN,
        "committee": keys.iter().map(|k| hex::encode(k.public_key().to_bytes())).collect::<Vec<_>>(),
        "cases": [case("valid", &valid), case("non-consecutive-views", &non_consecutive), case("bad-aggregate-signature", &bad_sig), case("sub-root-mismatch", &wrong_root)],
    });
    assert_eq!(produced["cases"][0]["expected"], true);
    for i in 1..4 {
        assert_eq!(
            produced["cases"][i]["expected"], false,
            "case {i} must be rejected"
        );
    }

    let mut dir: &Path = &std::env::current_dir().unwrap();
    let p: PathBuf = loop {
        let c = dir.join("test-fixtures");
        if c.is_dir() {
            break c.join("bridge").join("attestation-v1.json");
        }
        dir = dir.parent().unwrap();
    };
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::write(
            &p,
            format!("{}\n", serde_json::to_string_pretty(&produced).unwrap()),
        )
        .unwrap();
        return;
    }
    let committed: Value =
        serde_json::from_str(&std::fs::read_to_string(&p).expect("attestation-v1.json missing"))
            .unwrap();
    assert_eq!(committed, produced);
}

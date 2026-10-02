//! Bridge sources for the RPC edge: state proofs from the shared forest, and
//! finality evidence from stored blocks (Task 16).

use std::sync::{Mutex, RwLock};

use solidus_hotstuff2::Block2;
use solidus_rpc2::backend::{EvidenceBytes, ProofBundle, ProofError};
use solidus_state_tree::{StateForest, TreeId};
use solidus_store2::Store2;

/// Proof for `key` in tree `tree` (0 accounts, 1 dids, 2 credentials, 3 validators),
/// consistent with the exec anchor or `StateAdvancing`.
pub fn prove(
    forest: &RwLock<StateForest>,
    anchor: &Mutex<(u64, [u8; 32])>,
    tree: u8,
    key: &[u8],
) -> Result<ProofBundle, ProofError> {
    let id = match tree {
        0 => TreeId::Accounts,
        1 => TreeId::Dids,
        2 => TreeId::Credentials,
        3 => TreeId::Validators,
        _ => return Err(ProofError::BadTree),
    };
    let f = forest.read().map_err(|_| ProofError::Unavailable)?;
    let global_root = f.global_root();
    let (height, anchor_root) = *anchor.lock().map_err(|_| ProofError::Unavailable)?;
    if anchor_root != global_root {
        return Err(ProofError::StateAdvancing);
    }
    let value = f.get(id, key).map(<[u8]>::to_vec);
    let proof = value
        .as_ref()
        .and_then(|_| f.prove(id, key))
        .map(|p| (p.sibling_bitmap, p.siblings));
    Ok(ProofBundle {
        height,
        global_root,
        sub_roots: f.sub_roots(),
        value,
        proof,
    })
}

fn stored_block(store: &Store2, height: u64) -> Option<Block2> {
    let hash = store.canon_hash(height).ok().flatten()?;
    let bytes = store.block_by_hash(&hash).ok().flatten()?;
    bincode::deserialize(&bytes).ok()
}

/// The first height h >= `at_or_above` (within `scan_limit` heights) where block h+1
/// is in view(h)+1 and carries QC(h), and block h+2 carries QC(h+1). That pair is
/// HotStuff-2 commit evidence for h; its roots are the sub-roots stored for
/// h's exec height.
pub fn finality_evidence_at_or_above(
    store: &Store2,
    at_or_above: u64,
    scan_limit: u64,
) -> Option<EvidenceBytes> {
    let head = store.canon_head().ok().flatten()?;
    let end = at_or_above.saturating_add(scan_limit);
    let mut h = at_or_above;
    while h.saturating_add(2) <= head && h < end {
        let (Some(parent), Some(child), Some(grand)) = (
            stored_block(store, h),
            stored_block(store, h + 1),
            stored_block(store, h + 2),
        ) else {
            return None;
        };
        let consecutive = child.header.view == parent.header.view + 1
            && child.justify.block_hash == parent.hash()
            && child.justify.view == parent.header.view
            && grand.justify.block_hash == child.hash()
            && grand.justify.view == child.header.view;
        if consecutive {
            let sub_roots = store.sub_roots(parent.header.exec_height).ok().flatten()?;
            let global_root = solidus_state_tree::global_state_root(
                &sub_roots[0],
                &sub_roots[1],
                &sub_roots[2],
                &sub_roots[3],
            );
            if global_root != parent.header.exec_state_root {
                return None;
            }
            return Some(EvidenceBytes {
                height: h,
                parent_header: bincode::serialize(&parent.header).ok()?,
                child_block: bincode::serialize(&child).ok()?,
                child_qc: bincode::serialize(&grand.justify).ok()?,
                l1_height: parent.header.exec_height,
                global_root,
                sub_roots,
            });
        }
        h += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use solidus_state_tree::{verify_inclusion, StateForest, TreeId};

    fn shared(forest: StateForest, height: u64) -> (RwLock<StateForest>, Mutex<(u64, [u8; 32])>) {
        let root = forest.global_root();
        (RwLock::new(forest), Mutex::new((height, root)))
    }

    #[test]
    fn a_proof_verifies_against_the_returned_sub_root_and_names_its_height() {
        let mut forest = StateForest::new();
        forest.apply(
            TreeId::Credentials,
            b"bridge:seq:\x00\xaa\x36\xa7",
            &3u64.to_le_bytes(),
        );
        forest.apply(TreeId::Accounts, b"acct", b"a");
        let (f, a) = shared(forest, 1234);
        let bundle = prove(&f, &a, 2, b"bridge:seq:\x00\xaa\x36\xa7").unwrap();
        assert_eq!(bundle.height, 1234);
        let (bitmap, siblings) = bundle.proof.clone().expect("present key has a proof");
        let proof = solidus_state_tree::InclusionProof {
            sibling_bitmap: bitmap,
            siblings,
        };
        assert!(verify_inclusion(
            &bundle.sub_roots[2],
            b"bridge:seq:\x00\xaa\x36\xa7",
            bundle.value.as_deref().unwrap(),
            &proof
        ));
        assert_eq!(
            solidus_state_tree::global_state_root(
                &bundle.sub_roots[0],
                &bundle.sub_roots[1],
                &bundle.sub_roots[2],
                &bundle.sub_roots[3]
            ),
            bundle.global_root
        );
    }

    #[test]
    fn an_absent_key_returns_no_value_and_no_proof() {
        let (f, a) = shared(StateForest::new(), 1);
        let bundle = prove(&f, &a, 2, b"missing").unwrap();
        assert!(bundle.value.is_none() && bundle.proof.is_none());
    }

    #[test]
    fn a_forest_ahead_of_the_anchor_reports_state_advancing() {
        let mut forest = StateForest::new();
        forest.apply(TreeId::Dids, b"k", b"v");
        let f = RwLock::new(forest);
        let a = Mutex::new((7u64, [0u8; 32]));
        assert!(matches!(
            prove(&f, &a, 1, b"k"),
            Err(ProofError::StateAdvancing)
        ));
    }

    #[test]
    fn an_unknown_tree_is_refused() {
        let (f, a) = shared(StateForest::new(), 1);
        assert!(matches!(prove(&f, &a, 4, b"k"), Err(ProofError::BadTree)));
    }

    use solidus_crypto::bls::{BlsSecretKey, BlsSignature};
    use solidus_exec::DeltaSet;
    use solidus_hotstuff2::{vote_message, Block2, BlockHeader2, Committee, QuorumCert};
    use solidus_store2::{Profile, Store2};
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

    /// Stores heights 10..=13. Views: 10, 11, 13 (a timeout skipped view 12), 14.
    fn stored_chain(dir: &std::path::Path) -> (Store2, Vec<BlsSecretKey>, [[u8; 32]; 4]) {
        let store = Store2::open(dir, Profile::Testnet).unwrap();
        let keys = keys();
        let roots = [[1u8; 32], [2; 32], [3; 32], [4; 32]];
        let global =
            solidus_state_tree::global_state_root(&roots[0], &roots[1], &roots[2], &roots[3]);
        let mut parent = [0u8; 32];
        let mut justify = qc(&keys, [0; 32], 9);
        for (height, view) in [(10u64, 10u64), (11, 11), (12, 13), (13, 14)] {
            let header = BlockHeader2 {
                chain_id: CHAIN,
                height,
                view,
                parent,
                batch_certs: vec![],
                exec_height: height,
                exec_state_root: global,
                timestamp_ms: height,
                proposer: 0,
            };
            let block = Block2 {
                header,
                justify: justify.clone(),
            };
            let hash = block.hash();
            store
                .persist_block(
                    height,
                    hash,
                    &bincode::serialize(&block).unwrap(),
                    &DeltaSet::new(),
                    &[],
                    &[],
                    roots,
                )
                .unwrap();
            justify = qc(&keys, hash, view);
            parent = hash;
        }
        (store, keys, roots)
    }

    #[test]
    fn evidence_skips_a_non_consecutive_pair_and_verifies_with_the_bridge_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let (store, keys, roots) = stored_chain(dir.path());
        // (10,11) is consecutive and 12 is stored, so 10 qualifies directly.
        let e = finality_evidence_at_or_above(&store, 10, 16).expect("evidence at 10");
        assert_eq!(e.height, 10);
        // (11,12) has views 11 and 13: not consecutive, so the next candidate is (12,13), which has no grandchild yet.
        assert!(finality_evidence_at_or_above(&store, 11, 16).is_none());

        let att = BridgeAttestation {
            parent_header: bincode::deserialize(&e.parent_header).unwrap(),
            child: bincode::deserialize(&e.child_block).unwrap(),
            child_qc: bincode::deserialize(&e.child_qc).unwrap(),
        };
        let announced = L1FinalizedRoots {
            l1_height: e.l1_height,
            global_root: e.global_root,
            accounts_root: roots[0],
            dids_root: roots[1],
            credentials_root: roots[2],
            validators_root: roots[3],
            commit_qc: att.encode(),
        };
        let verifier = BridgeVerifier::new(
            CHAIN,
            Committee::new(keys.iter().map(|k| k.public_key()).collect()),
            [0; 32],
        );
        verifier
            .verify(&announced)
            .expect("stored evidence verifies");
    }

    #[test]
    fn no_evidence_below_two_stored_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let (store, _, _) = stored_chain(dir.path());
        assert!(finality_evidence_at_or_above(&store, 13, 16).is_none());
    }
}

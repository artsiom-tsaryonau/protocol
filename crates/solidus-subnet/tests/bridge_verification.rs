//! Stage-5 acceptance: the bridge verifier accepts exactly the messages
//! carrying real 2-chain commit evidence signed by the L1 committee, and
//! a demo subnet ingests + serves verified roots; inclusion proofs from
//! the L1 forest verify against the delivered sub-tree roots.

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{vote_message, Block2, BlockHeader2, Committee, QuorumCert};
use solidus_state_tree::{verify_inclusion, StateForest, TreeId};
use solidus_subnet::runtime::{BridgeAttestation, BridgeVerifier, TrackingSubnet};
use solidus_subnet::{L1FinalizedRoots, Subnet, SubnetError};

const CHAIN_ID: u64 = 2;

struct L1Fixture {
    keys: Vec<BlsSecretKey>,
    committee: Committee,
    genesis_hash: [u8; 32],
}

fn l1(n: usize) -> L1Fixture {
    let keys: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let committee = Committee::new(keys.iter().map(|k| k.public_key()).collect());
    L1Fixture {
        keys,
        committee,
        genesis_hash: [0u8; 32],
    }
}

impl L1Fixture {
    fn qc_over(&self, block_hash: [u8; 32], view: u64) -> QuorumCert {
        let msg = vote_message(CHAIN_ID, view, &block_hash);
        let quorum = self.committee.quorum();
        let sigs: Vec<_> = self.keys[..quorum].iter().map(|k| k.sign(&msg)).collect();
        let agg = solidus_crypto::bls::BlsSignature::aggregate(&sigs.iter().collect::<Vec<_>>())
            .expect("aggregate");
        QuorumCert {
            view,
            block_hash,
            signers: (0..quorum as u32).collect(),
            agg_sig: agg,
        }
    }
}

/// Build (roots message, forest) for a committed parent at `height` whose
/// state contains a known DID leaf, with full commit evidence.
fn committed_roots(l1: &L1Fixture) -> (L1FinalizedRoots, StateForest, String, Vec<u8>) {
    // L1 state: a DID document lives in the Dids tree.
    let mut forest = StateForest::new();
    let did = "did:solidus:v2:someone".to_string();
    let doc = b"did-document-bytes".to_vec();
    forest.apply(TreeId::Dids, did.as_bytes(), &doc);
    forest.apply(TreeId::Accounts, b"acct", b"account-bytes");

    let global = forest.global_root();

    // Parent at height 41 / view 41; child at height 42 / view 42 carries
    // the parent's post-state root.
    // The committed parent announces (exec_height=41, root) as its anchor
    // (in the running chain the anchor lags a couple of blocks; equal
    // heights keep the fixture minimal — the verifier checks linkage and
    // anchor fields, not the lag policy).
    let parent_header = BlockHeader2 {
        chain_id: CHAIN_ID,
        height: 41,
        view: 41,
        parent: [7u8; 32],
        batch_certs: vec![],
        exec_height: 41,
        exec_state_root: global,
        timestamp_ms: 1,
        proposer: 0,
    };
    let parent_hash = parent_header.hash();
    let parent_qc = l1.qc_over(parent_hash, 41);

    let child_header = BlockHeader2 {
        chain_id: CHAIN_ID,
        height: 42,
        view: 42,
        parent: parent_hash,
        batch_certs: vec![],
        exec_height: 40,
        exec_state_root: [4u8; 32],
        timestamp_ms: 2,
        proposer: 1,
    };
    let child = Block2 {
        header: child_header,
        justify: parent_qc,
    };
    let child_qc = l1.qc_over(child.hash(), 42);

    let attestation = BridgeAttestation {
        parent_header,
        child,
        child_qc,
    };

    let roots = L1FinalizedRoots {
        l1_height: 41,
        global_root: global,
        accounts_root: forest.subtree_root(TreeId::Accounts),
        dids_root: forest.subtree_root(TreeId::Dids),
        credentials_root: forest.subtree_root(TreeId::Credentials),
        validators_root: forest.subtree_root(TreeId::Validators),
        commit_qc: attestation.encode(),
    };
    (roots, forest, did, doc)
}

#[test]
fn verified_roots_flow_to_subnet_and_proofs_verify() {
    let l1 = l1(4);
    let verifier = BridgeVerifier::new(CHAIN_ID, l1.committee.clone(), l1.genesis_hash);
    let (roots, forest, did, doc) = committed_roots(&l1);

    let mut subnet = TrackingSubnet::new(1);
    verifier
        .deliver(&mut subnet, roots)
        .expect("valid bridge message must deliver");

    assert_eq!(subnet.latest_l1_height(), Some(41));
    let dids_root = subnet
        .latest_finalized(TreeId::Dids)
        .expect("dids root delivered");

    // The precompile path: an inclusion proof from L1 state verifies
    // against the subnet's delivered sub-tree root.
    let proof = forest.prove(TreeId::Dids, did.as_bytes()).expect("leaf");
    assert!(verify_inclusion(&dids_root, did.as_bytes(), &doc, &proof));
    assert!(!verify_inclusion(
        &dids_root,
        did.as_bytes(),
        b"forged",
        &proof
    ));
}

#[test]
fn bridge_rejects_bad_evidence() {
    let l1 = l1(4);
    let verifier = BridgeVerifier::new(CHAIN_ID, l1.committee.clone(), l1.genesis_hash);

    // 1. Wrong global root (state not actually certified).
    let (mut roots, ..) = committed_roots(&l1);
    roots.global_root = [9u8; 32];
    assert!(matches!(
        verifier.verify(&roots),
        Err(SubnetError::InvalidCommitQc { l1_height: 41 })
    ));

    // 2. Non-consecutive views (no 2-chain commit — abandoned branch).
    let (roots, ..) = committed_roots(&l1);
    let mut att: BridgeAttestation = bincode::deserialize(&roots.commit_qc).expect("decode");
    att.child.justify.view = 40; // gap: 40 → 42
    let mut bad = roots.clone();
    bad.commit_qc = att.encode();
    assert!(verifier.verify(&bad).is_err());

    // 3. Sub-quorum child QC.
    let (roots, ..) = committed_roots(&l1);
    let mut att: BridgeAttestation = bincode::deserialize(&roots.commit_qc).expect("decode");
    att.child_qc.signers = vec![0, 1];
    let mut bad = roots.clone();
    bad.commit_qc = att.encode();
    assert!(verifier.verify(&bad).is_err());

    // 4. Anchor-height mismatch.
    let (mut roots, ..) = committed_roots(&l1);
    roots.l1_height = 40;
    assert!(verifier.verify(&roots).is_err());

    // 5. Sub-tree roots that don't combine to the global root.
    let (mut roots, ..) = committed_roots(&l1);
    roots.dids_root = [3u8; 32];
    assert!(verifier.verify(&roots).is_err());

    // 6. Garbage attestation bytes.
    let (mut roots, ..) = committed_roots(&l1);
    roots.commit_qc = vec![1, 2, 3];
    assert!(verifier.verify(&roots).is_err());
}

#[test]
fn subnet_rejects_stale_heights_after_progress() {
    let l1 = l1(4);
    let verifier = BridgeVerifier::new(CHAIN_ID, l1.committee.clone(), l1.genesis_hash);
    let (roots, ..) = committed_roots(&l1);
    let mut subnet = TrackingSubnet::new(1);
    verifier.deliver(&mut subnet, roots.clone()).expect("first");

    // Same-height redelivery is fine (idempotent refresh)…
    verifier
        .deliver(&mut subnet, roots.clone())
        .expect("re-deliver");

    // …but a LOWER height is stale. Craft one by rebuilding evidence at
    // height 40: simplest is to reuse the message and drop the height —
    // which the verifier itself rejects (height/evidence mismatch), so
    // staleness is exercised via the subnet directly.
    let mut stale = roots;
    stale.l1_height = 39;
    assert!(matches!(
        subnet.on_l1_finalized(stale),
        Err(SubnetError::StaleRoots {
            got: 39,
            latest: 41
        })
    ));
}

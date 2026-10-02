use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey, BlsSignature, DST_BASIC, DST_POP_SIG};
use solidus_hotstuff2::types::{
    vote_dst_for_view, vote_message, Committee, CommitteeError, QuorumCert,
};

fn key(seed: u8) -> BlsSecretKey {
    let raw = blst::min_pk::SecretKey::key_gen(&[seed; 32], &[])
        .unwrap()
        .to_bytes();
    BlsSecretKey::from_bytes(&raw).unwrap()
}

fn committee(activation: u64) -> (Vec<BlsSecretKey>, Committee) {
    let keys: Vec<BlsSecretKey> = (1..=4).map(key).collect();
    let pks = keys.iter().map(|k| k.public_key()).collect();
    let pops = keys.iter().map(|k| k.prove_possession()).collect();
    let c = Committee::with_pop_activation(pks, pops, activation).expect("valid pops");
    (keys, c)
}

fn qc(keys: &[BlsSecretKey], c: &Committee, view: u64, block: [u8; 32]) -> QuorumCert {
    let msg = vote_message(50_002, view, &block);
    let sigs: Vec<BlsSignature> = keys[..3]
        .iter()
        .map(|k| k.sign_with_dst(&msg, c.dst_for_view(view)))
        .collect();
    let refs: Vec<&BlsSignature> = sigs.iter().collect();
    QuorumCert {
        view,
        block_hash: block,
        signers: vec![0, 1, 2],
        agg_sig: BlsSignature::aggregate(&refs).unwrap(),
    }
}

#[test]
fn the_dst_switches_exactly_at_the_activation_view() {
    assert_eq!(vote_dst_for_view(99, 100), DST_BASIC);
    assert_eq!(vote_dst_for_view(100, 100), DST_POP_SIG);
    assert_eq!(
        vote_dst_for_view(u64::MAX - 1, u64::MAX),
        DST_BASIC,
        "u64::MAX means never"
    );
}

#[test]
fn a_qc_verifies_under_the_suite_of_its_own_view() {
    let (keys, c) = committee(100);
    assert!(qc(&keys, &c, 99, [1; 32])
        .verify(50_002, &c, &[0; 32])
        .is_ok());
    assert!(qc(&keys, &c, 100, [1; 32])
        .verify(50_002, &c, &[0; 32])
        .is_ok());
}

#[test]
fn a_qc_signed_under_the_wrong_suite_for_its_view_is_rejected() {
    let (keys, c) = committee(100);
    let msg = vote_message(50_002, 100, &[1; 32]);
    let sigs: Vec<BlsSignature> = keys[..3]
        .iter()
        .map(|k| k.sign_with_dst(&msg, DST_BASIC))
        .collect();
    let refs: Vec<&BlsSignature> = sigs.iter().collect();
    let wrong = QuorumCert {
        view: 100,
        block_hash: [1; 32],
        signers: vec![0, 1, 2],
        agg_sig: BlsSignature::aggregate(&refs).unwrap(),
    };
    assert!(wrong.verify(50_002, &c, &[0; 32]).is_err());
}

#[test]
fn a_committee_refuses_the_rogue_key_from_the_vector() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../test-fixtures/bls/rogue-key-v1.json"
    ))
    .unwrap();
    let hex48 = |s: &str| -> [u8; 48] { hex::decode(s).unwrap().try_into().unwrap() };
    let honest = BlsPublicKey::from_bytes(&hex48(v["honestPublicKey"].as_str().unwrap())).unwrap();
    let rogue = BlsPublicKey::from_bytes(&hex48(v["roguePublicKey"].as_str().unwrap())).unwrap();
    let attacker = BlsSecretKey::from_bytes(
        &hex::decode(v["attackerSecretKey"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let honest_pop = key(1).prove_possession();
    let result = Committee::with_pop_activation(
        vec![honest, rogue],
        vec![honest_pop, attacker.prove_possession()],
        0,
    );
    assert!(
        matches!(result, Err(CommitteeError::InvalidPop(1))),
        "index 1 is the rogue key, got {:?}",
        result.err()
    );
}

#[test]
fn a_committee_refuses_a_pop_count_mismatch() {
    let pks = vec![key(1).public_key(), key(2).public_key()];
    let result = Committee::with_pop_activation(pks, vec![key(1).prove_possession()], 0);
    assert!(matches!(
        result,
        Err(CommitteeError::PopCountMismatch { keys: 2, pops: 1 })
    ));
}

#[test]
fn the_legacy_constructor_never_activates_pop() {
    let c = Committee::new(vec![key(1).public_key()]);
    assert_eq!(c.dst_for_view(u64::MAX - 1), DST_BASIC);
}

// ---------------------------------------------------------------------------
// ⛔ NOT IN THE ORIGINAL PLAN. Added because the plan made every SIGNATURE
// view-aware but left the two per-vote checks in `aggregate.rs` on the legacy
// Basic verify. At the activation view a node signs its vote with the PoP suite
// and every aggregator would then reject it, so no QC or TC forms and the chain
// stops. Nothing else caught it: while POP_ACTIVATION_VIEW is u64::MAX no test
// reaches an activated view through the aggregators.
// ---------------------------------------------------------------------------

use solidus_hotstuff2::aggregate::{TimeoutAggregator, VoteAggregator};
use solidus_hotstuff2::types::{timeout_message, TimeoutVote, Vote};

#[test]
fn votes_signed_at_an_activated_view_still_form_a_qc() {
    let (keys, c) = committee(100);
    for view in [99u64, 100, 101] {
        let mut agg = VoteAggregator::new();
        let block = [7u8; 32];
        let msg = vote_message(50_002, view, &block);
        let mut qc = None;
        for (i, k) in keys.iter().take(3).enumerate() {
            let v = Vote {
                view,
                block_hash: block,
                voter: i as u32,
                sig: k.sign_with_dst(&msg, c.dst_for_view(view)),
            };
            qc = agg
                .add_vote(50_002, &c, &v)
                .unwrap_or_else(|e| panic!("view {view}: vote {i} rejected: {e:?}"));
        }
        let qc = qc.unwrap_or_else(|| panic!("view {view}: no QC after a quorum of valid votes"));
        qc.verify(50_002, &c, &[0; 32])
            .unwrap_or_else(|e| panic!("view {view}: the QC does not verify: {e:?}"));
    }
}

#[test]
fn timeouts_signed_at_an_activated_view_still_form_a_tc() {
    let (keys, c) = committee(100);
    for view in [99u64, 100, 101] {
        let mut agg = TimeoutAggregator::new();
        let msg = timeout_message(50_002, view);
        let high_qc = QuorumCert::genesis([0; 32], keys[0].sign(b"g"));
        let mut tc = None;
        for (i, k) in keys.iter().take(3).enumerate() {
            let tv = TimeoutVote {
                view,
                voter: i as u32,
                sig: k.sign_with_dst(&msg, c.dst_for_view(view)),
                high_qc: high_qc.clone(),
            };
            tc = agg
                .add_timeout(50_002, &c, &tv)
                .unwrap_or_else(|e| panic!("view {view}: timeout {i} rejected: {e:?}"));
        }
        assert!(
            tc.is_some(),
            "view {view}: no TC after a quorum of valid timeouts"
        );
    }
}

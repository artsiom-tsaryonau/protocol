//! Multi-node integration tests for the HotStuff consensus engine.
//!
//! Proves that 4 in-process nodes connected via channel transports can:
//!   1. Complete one full round of consensus (leader proposes, validators vote, QC forms).
//!   2. Handle leader failure via timeout votes and TC formation.

use std::sync::{Arc, Mutex};

use solidus_consensus::hotstuff::{HotStuffConfig, HotStuffEngine};
use solidus_consensus::leader::{elect_leader, select_leader_from_outputs};
use solidus_consensus::mempool::Mempool;
use solidus_consensus::types::{TimeoutVote, ValidatorIdentity};
use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_p2p::channel::{create_channel_network, ChannelTransport};
use solidus_p2p::message::ConsensusMessage;
use solidus_p2p::transport::ConsensusTransport;
use solidus_state::store::Store;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Test setup helper
// ---------------------------------------------------------------------------

/// Create `n` HotStuff engines with matching channel transports.
///
/// Each engine gets unique Ed25519/BLS keys, its own tempdir-backed RocksDB store,
/// and a shared round_seed of `[0u8; 32]`. The quorum threshold is `(n * 2 / 3) + 1`.
fn setup_test_network(n: usize) -> (Vec<HotStuffEngine>, Vec<ChannelTransport>) {
    let mempool = Arc::new(Mutex::new(Mempool::new()));

    // Generate keys for all validators.
    let mut ed_keys = Vec::with_capacity(n);
    let mut bls_keys = Vec::with_capacity(n);
    let mut validators = Vec::with_capacity(n);

    for _ in 0..n {
        let ed_sk = generate_signing_key();
        let bls_sk = BlsSecretKey::generate();
        validators.push(ValidatorIdentity {
            address: Address::from_public_key(&ed_sk.verifying_key()),
            ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
            bls_pubkey: bls_sk.public_key(),
        });
        ed_keys.push(ed_sk);
        bls_keys.push(bls_sk);
    }

    let quorum_threshold = (n * 2 / 3) + 1;

    let mut engines = Vec::with_capacity(n);

    // Same shape as the hotstuff.rs builder loop — i is the validator
    // index, ed_keys is indexed, bls_keys is drained destructively.
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        let dir = tempdir().expect("failed to create temp dir");
        let store = Arc::new(Store::open(dir.path()).expect("failed to open store"));

        // Leak the tempdir so it outlives the store (acceptable in tests).
        std::mem::forget(dir);

        let config = HotStuffConfig {
            max_block_txs: 100,
            quorum_threshold,
            treasury_address: Address::from_bytes([0xAAu8; 20]),
            skip_vrf: false,
        };

        engines.push(HotStuffEngine::new(
            i,
            ed_keys[i].clone(),
            bls_keys.remove(0),
            validators.clone(),
            store,
            Arc::clone(&mempool),
            config,
        ));
    }

    let transports = create_channel_network(n);

    (engines, transports)
}

// ---------------------------------------------------------------------------
// Test 1: Four nodes complete one full round of consensus
// ---------------------------------------------------------------------------

#[tokio::test]
async fn four_nodes_one_round() {
    let (mut engines, mut transports) = setup_test_network(4);

    let round = engines[0].pacemaker.current_round();
    assert_eq!(round, 0, "pacemaker should start at round 0");

    // Step 1: Determine the leader for round 0 via VRF.
    //
    // Each node computes its VRF output for this round. The node with the
    // lowest u64-encoded output wins.
    let round_seed = engines[0].round_seed;
    let outputs: Vec<(usize, solidus_crypto::vrf::VrfOutput)> = (0..4)
        .map(|i| {
            let election = elect_leader(
                &engines[i].ed25519_sk,
                i,
                &engines[i].validators,
                &round_seed,
                round,
            );
            (i, election.vrf_output)
        })
        .collect();

    let leader = select_leader_from_outputs(&outputs);

    // Step 2: Leader builds a block and broadcasts the proposal.
    let (block, _) = engines[leader].build_block();
    let proposal = ConsensusMessage::Proposal {
        block: block.clone(),
        justify_qc: None,
    };

    transports[leader]
        .broadcast(proposal)
        .await
        .expect("broadcast should succeed");

    // Step 3: Non-leaders receive the proposal, validate, and vote.
    //
    // We need to split transports to allow mutable borrow of individual elements.
    let non_leaders: Vec<usize> = (0..4).filter(|&i| i != leader).collect();
    let mut votes = Vec::new();

    for &i in &non_leaders {
        let (_from, msg) = transports[i]
            .recv()
            .await
            .expect("non-leader should receive proposal");

        match msg {
            ConsensusMessage::Proposal {
                block: received_block,
                ..
            } => {
                assert_eq!(
                    received_block.hash(),
                    block.hash(),
                    "received block hash should match proposed block"
                );

                let vote = engines[i]
                    .validate_and_vote(&received_block)
                    .expect("non-leader should produce a vote for a valid proposal");

                votes.push(vote);
            }
            other => panic!("expected Proposal, got {:?}", other),
        }
    }

    assert_eq!(votes.len(), 3, "should have 3 votes from non-leaders");

    // Step 4: Leader processes votes. QC should form on the 3rd vote.
    let result1 = engines[leader].process_vote(votes.remove(0));
    assert!(result1.is_none(), "QC should not form with 1 vote");

    let result2 = engines[leader].process_vote(votes.remove(0));
    assert!(result2.is_none(), "QC should not form with 2 votes");

    let result3 = engines[leader].process_vote(votes.remove(0));
    assert!(result3.is_some(), "QC should form with 3 votes (quorum)");

    let qc = result3.unwrap();
    assert_eq!(qc.round, round, "QC round should match the proposal round");
    assert_eq!(
        qc.block_hash,
        block.hash(),
        "QC block hash should match the proposed block"
    );
    assert!(
        qc.signer_count() >= 3,
        "QC should have at least 3 signers, got {}",
        qc.signer_count()
    );
}

// ---------------------------------------------------------------------------
// Test 2: Leader failure triggers timeout and TC formation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn leader_failure_triggers_timeout() {
    let (mut engines, _transports) = setup_test_network(4);

    let round = engines[0].pacemaker.current_round();
    assert_eq!(round, 0, "pacemaker should start at round 0");

    // Simulate leader not proposing: skip the proposal phase entirely.
    // All 4 nodes create timeout votes for the current round.
    // The bytes the node actually signs. This test used `round.to_le_bytes()`
    // -- a different message from the one production signs -- and nothing
    // caught it for as long as the file has existed, because until 2026-08-24
    // nothing verified a timeout vote at all.
    let timeout_msg = TimeoutVote::signing_bytes(round);

    let tv0 = TimeoutVote {
        round,
        voter_index: 0,
        highest_qc: None,
        bls_signature: engines[0].bls_sk.sign(&timeout_msg),
    };
    let tv1 = TimeoutVote {
        round,
        voter_index: 1,
        highest_qc: None,
        bls_signature: engines[1].bls_sk.sign(&timeout_msg),
    };
    let tv2 = TimeoutVote {
        round,
        voter_index: 2,
        highest_qc: None,
        bls_signature: engines[2].bls_sk.sign(&timeout_msg),
    };
    let tv3 = TimeoutVote {
        round,
        voter_index: 3,
        highest_qc: None,
        bls_signature: engines[3].bls_sk.sign(&timeout_msg),
    };

    // One node (engine 0) collects timeout votes. TC should form on the 3rd vote.
    let result0 = engines[0].process_timeout_vote(tv0);
    assert!(result0.is_none(), "TC should not form with 1 timeout vote");

    let result1 = engines[0].process_timeout_vote(tv1);
    assert!(result1.is_none(), "TC should not form with 2 timeout votes");

    let result2 = engines[0].process_timeout_vote(tv2);
    assert!(
        result2.is_some(),
        "TC should form with 3 timeout votes (quorum)"
    );

    let tc = result2.unwrap();
    assert_eq!(tc.round, round, "TC round should match the timed-out round");
    assert_eq!(
        tc.signers.count_ones(),
        3,
        "TC should have exactly 3 signers"
    );
    assert!(
        tc.highest_qc.is_none(),
        "TC highest_qc should be None since no QC was formed"
    );

    // Advance the pacemaker to the next round via TC.
    let event = engines[0].pacemaker.advance_round_on_tc(round + 1);
    assert_eq!(
        engines[0].pacemaker.current_round(),
        round + 1,
        "pacemaker should advance to round 1 after TC"
    );
    assert!(
        matches!(
            event,
            solidus_consensus::pacemaker::PacemakerEvent::NewRound { round: 1 }
        ),
        "pacemaker should emit NewRound event for round 1"
    );

    // The 4th timeout vote should still be processable but won't form another TC
    // since pending_timeout_votes for this round were already cleaned up.
    let result3 = engines[0].process_timeout_vote(tv3);
    // After TC formation the pending votes for that round are removed, so
    // feeding tv3 starts a fresh collection — 1 vote is not enough for quorum.
    assert!(
        result3.is_none(),
        "4th timeout vote after TC should not form a second TC"
    );
}

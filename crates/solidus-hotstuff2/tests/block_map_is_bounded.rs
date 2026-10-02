//! The in-memory block map must not grow with chain height.
//!
//! ⛔ WHY THIS TEST EXISTS. `ConsensusCore::blocks` was inserted into at five
//! sites and removed at none: not on commit, not on sync, not ever. It grew for
//! the life of the process on a HEALTHY chain as well as a stalled one. On the
//! 4 GB testnet box that meant a validator peaked at 1.1 GB after 34h of normal
//! operation against a 207 MB resting set, and a validator replaying a range
//! after restart reached 1.9 GB in 81 seconds and was OOM-killed before it could
//! finish. It never caught up, the committee lost quorum, and the survivors then
//! grew the same way because a stalled chain commits nothing.
//!
//! ⚠ THE OPPOSITE MISTAKE WEDGES THE CHAIN SILENTLY, so this test asserts BOTH
//! directions. `on_proposal` looks up `header.parent` and declines to vote when
//! it misses, so a map pruned too aggressively makes a validator refuse every
//! proposal while looking perfectly healthy. The last committed block must
//! survive every prune: `commit_chain` walks back to it and must find it to
//! terminate.

use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{
    Block2, BlockHeader2, Committee, ConsensusCore, CoreConfig, EmptyPayloads, Pacemaker,
    QuorumCert, RoundRobin,
};

const CHAIN_ID: u64 = 2;
const N: usize = 4;

fn core() -> ConsensusCore<RoundRobin, EmptyPayloads> {
    let secrets: Vec<BlsSecretKey> = (0..N)
        .map(|i| BlsSecretKey::from_bytes(&[(i as u8) + 1; 32]).expect("secret"))
        .collect();
    let committee = Committee::new(secrets.iter().map(|s| s.public_key()).collect());
    ConsensusCore::new(
        CoreConfig {
            chain_id: CHAIN_ID,
            my_index: 0,
            secret: BlsSecretKey::from_bytes(&secrets[0].to_bytes()).expect("secret"),
            committee,
            pacemaker: Pacemaker::default(),
            // Pacing off in tests: these assert on block PRODUCTION,
            // and a wall-clock gate would make them time-dependent.
            min_block_interval_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
        },
        RoundRobin::new(N),
        EmptyPayloads { ts_ms: 1 },
    )
}

/// Build a chain of `n` blocks descending from `parent`, heights 1..=n.
fn chain_from(parent: [u8; 32], n: u64, qc: &QuorumCert) -> Vec<Block2> {
    let mut out = Vec::new();
    let mut p = parent;
    for h in 1..=n {
        let header = BlockHeader2 {
            chain_id: CHAIN_ID,
            height: h,
            view: h,
            parent: p,
            batch_certs: vec![],
            exec_height: 0,
            exec_state_root: [0u8; 32],
            timestamp_ms: h,
            proposer: 0,
        };
        p = header.hash();
        out.push(Block2 {
            header,
            justify: qc.clone(),
        });
    }
    out
}

#[test]
fn the_block_map_does_not_grow_with_chain_height() {
    let mut c = core();
    let genesis = c.genesis_hash();
    let qc = c.high_qc().clone();

    // Replay 2_000 blocks the way a restarted validator does: the bodies land as
    // peers serve the range, then the commit pointer walks up behind them.
    //
    // ⚠ The pointer must advance SEPARATELY from the bodies arriving. An earlier
    // version of this test resumed once per block with that block already marked
    // committed, so `note_synced_commit` saw no advance, took its early return,
    // and the prune never ran. The test passed no judgement on the fix at all.
    let blocks = chain_from(genesis, 2_000, &qc);
    c.resume(solidus_hotstuff2::ResumeState {
        last_voted_view: 0,
        high_qc: qc.clone(),
        last_committed_hash: genesis,
        last_committed_height: 0,
        blocks: blocks.clone(),
    });
    assert_eq!(
        c.tracked_blocks(),
        2_001,
        "control: all bodies plus genesis must be present before any commit advances"
    );
    for b in &blocks {
        c.note_synced_commit(b.hash(), b.header.height);
    }

    let held = c.tracked_blocks();
    // Before the fix this was 2_001 and would be the full chain at any height.
    assert!(
        held < 600,
        "block map grew with chain height: {held} blocks held after 2000 commits. \
         The retention window regressed, and this is the OOM that took the testnet down."
    );
}

#[test]
fn the_last_committed_block_always_survives_the_prune() {
    let mut c = core();
    let genesis = c.genesis_hash();
    let qc = c.high_qc().clone();
    let blocks = chain_from(genesis, 1_000, &qc);
    c.resume(solidus_hotstuff2::ResumeState {
        last_voted_view: 0,
        high_qc: qc.clone(),
        last_committed_hash: genesis,
        last_committed_height: 0,
        blocks: blocks.clone(),
    });
    for b in &blocks {
        c.note_synced_commit(b.hash(), b.header.height);
    }

    let (tip_hash, tip_height) = c.last_committed();
    assert_eq!(tip_height, 1_000, "commit pointer did not advance");
    assert!(
        c.block(&tip_hash).is_some(),
        "the last committed block was pruned. commit_chain walks back to it and \
         on_proposal resolves parents against it: losing it wedges the chain silently."
    );
}

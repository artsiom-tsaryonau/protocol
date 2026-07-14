//! C2 Task 7: follower canon-sync integration test (channel-free / store-level).
//!
//! Proves the full-node follower's sync CORE: given a "source" node with a
//! 3-block contiguous canon and an EMPTY follower store, replicating the source's
//! blocks into the follower store + appending its canon (what the PeerId-addressed
//! backfill walker does via `fetch_block_by_peer` + `apply_fetched`), then running
//! `rebuild_state_from_canon` (what `run_follower_loop`'s rebuild tick does):
//!
//!   1. The follower's `CF_CANON` reaches the source's tip seq.
//!   2. Every per-seq canon hash is IDENTICAL to the source's.
//!   3. The follower's `last_committed_height` advances to the tip.
//!   4. Each block is indexed in `CF_BLOCKS` by height (RPC height path; Task 6).
//!
//! Uses only public crate APIs (`solidus_consensus::ledger`, `rebuild_state_from_canon`),
//! since the bin-internal `backfill`/follower-loop code is not importable from an
//! integration test. The walker's per-step behaviour is exercised separately by
//! `backfill::tests` in the bin and by the libp2p `sync_by_peerid` round-trip test.

use std::sync::{Arc, Mutex};

use solidus_consensus::hotstuff::{HotStuffConfig, HotStuffEngine};
use solidus_consensus::ledger;
use solidus_consensus::mempool::Mempool;
use solidus_consensus::types::{Block, BlockHeader, ValidatorIdentity};
use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;
use solidus_state::store::{Store, CF_BLOCKS};
use tempfile::tempdir;

/// A single-validator engine backed by a fresh tempdir store. Returns the engine;
/// the tempdir is leaked so the store outlives it (matches the consensus crate's
/// own test-store pattern).
fn engine() -> HotStuffEngine {
    let dir = tempdir().expect("tempdir");
    let store = Arc::new(Store::open(dir.path()).expect("open store"));
    std::mem::forget(dir);

    let ed_sk = generate_signing_key();
    let bls_sk = BlsSecretKey::generate();
    let validators = vec![ValidatorIdentity {
        address: Address::from_public_key(&ed_sk.verifying_key()),
        ed25519_pubkey: ed_sk.verifying_key().to_bytes(),
        bls_pubkey: bls_sk.public_key(),
    }];
    let config = HotStuffConfig {
        max_block_txs: 100,
        quorum_threshold: 1,
        treasury_address: Address::from_bytes([0xAAu8; 20]),
        skip_vrf: false,
    };
    HotStuffEngine::new(
        0,
        ed_sk,
        bls_sk,
        validators,
        store,
        Arc::new(Mutex::new(Mempool::new())),
        config,
    )
}

/// Build a contiguous chain of `count` empty blocks (heights 1..=count) with
/// correct parent linkage, returning them in seq order.
fn build_chain(count: u64) -> Vec<Block> {
    let proposer = Address::from_bytes([0u8; 20]);
    let mut blocks = Vec::new();
    let mut parent = [0u8; 32];
    for h in 1..=count {
        let block = Block {
            header: BlockHeader {
                height: h,
                round: h - 1,
                parent_hash: parent,
                state_root: [0u8; 32],
                transactions_root: [0u8; 32],
                timestamp_ms: 0,
                tx_count: 0,
                proposer,
            },
            transactions: vec![],
            parent_qc: None,
            vrf_proof: None,
        };
        parent = block.hash();
        blocks.push(block);
    }
    blocks
}

#[test]
fn follower_syncs_canon_to_source_tip() {
    // --- Source node: a 3-block contiguous canon. ---
    let source = engine();
    let chain = build_chain(3);
    for (seq, b) in chain.iter().enumerate() {
        ledger::put_block_by_hash(&source.store, b).expect("source put by hash");
        ledger::canon_append(&source.store, seq as u64, &b.hash()).expect("source canon append");
    }
    let (src_head, src_head_hash) = ledger::canon_head(&source.store)
        .expect("source canon_head")
        .expect("source has a canon head");
    assert_eq!(src_head, 2, "source canon head seq should be 2 (3 blocks)");

    // --- Follower node: starts EMPTY. ---
    let mut follower = engine();
    assert!(
        ledger::canon_head(&follower.store)
            .expect("follower canon_head")
            .is_none(),
        "follower canon must start empty"
    );
    assert_eq!(follower.last_committed_height, 0);

    // --- Sync: replicate blocks + canon (what the backfill walker does). ---
    // The walker fetches blocks by hash from a peer and `apply_fetched` writes
    // them by hash + extends the canon. We model that with the public ledger API.
    for seq in 0..=src_head {
        let hash = ledger::canon_get(&source.store, seq)
            .expect("source canon_get")
            .expect("source canon entry");
        let block = ledger::get_block_by_hash(&source.store, &hash)
            .expect("source get by hash")
            .expect("source has block");
        ledger::put_block_by_hash(&follower.store, &block).expect("follower put by hash");
        ledger::canon_append(&follower.store, seq, &hash).expect("follower canon append");
    }

    // --- Rebuild: advance the follower's committed tip + RPC height (Task 6). ---
    let tip_seq = follower
        .rebuild_state_from_canon()
        .expect("follower rebuild_state_from_canon");

    // 1. Follower canon reached the source tip seq.
    assert_eq!(
        tip_seq, src_head,
        "follower should reach the source tip seq"
    );
    let (f_head, f_head_hash) = ledger::canon_head(&follower.store)
        .expect("follower canon_head")
        .expect("follower has a canon head");
    assert_eq!(f_head, src_head, "follower canon head seq mismatch");

    // 2. Per-seq canon hashes are IDENTICAL to the source's.
    assert_eq!(f_head_hash, src_head_hash, "follower head hash mismatch");
    for seq in 0..=src_head {
        let s = ledger::canon_get(&source.store, seq).unwrap().unwrap();
        let f = ledger::canon_get(&follower.store, seq).unwrap().unwrap();
        assert_eq!(s, f, "canon hash differs at seq {seq}");
    }

    // 3. last_committed_height advanced to the tip (block height 3).
    assert_eq!(
        follower.last_committed_height, 3,
        "follower committed height should advance to the tip height"
    );
    assert_eq!(
        follower.committed_tip_hash(),
        chain[2].hash(),
        "follower committed tip hash mismatch"
    );

    // 4. Blocks indexed in CF_BLOCKS by height for the RPC height path (Task 6).
    for b in &chain {
        let bytes = follower
            .store
            .get(CF_BLOCKS, &b.header.height.to_le_bytes())
            .expect("follower CF_BLOCKS get")
            .unwrap_or_else(|| panic!("follower CF_BLOCKS missing height {}", b.header.height));
        let stored: Block = serde_json::from_slice(&bytes).expect("decode stored block");
        assert_eq!(stored.hash(), b.hash(), "CF_BLOCKS wrong block at height");
    }
}

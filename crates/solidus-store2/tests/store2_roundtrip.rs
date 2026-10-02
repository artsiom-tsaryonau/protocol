//! Stage-4 verification: the two-lane executor runs directly against
//! RocksDB-backed Store2 with outcomes identical to the in-memory
//! baseline; blocks persist atomically; state survives reopen; pruning
//! bounds cold growth without touching state.

use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_twolane, Account, AccountType, BlockCtx, DeltaSet, ExecOptions, InMemoryState,
    StateKey, StateReader, WireMode,
};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Receipt, Transaction, TxPayload, TxStatus};

fn ctx_at(height: u64) -> BlockCtx<'static> {
    BlockCtx {
        height,
        timestamp_ms: 1_700_000_000_000 + height,
        network: "v2-store-test",
        parent_state_root: [0u8; 32],
    }
}

fn signed_transfer(
    key: &ed25519_dalek::SigningKey,
    to: Address,
    amount: u64,
    nonce: u64,
) -> Transaction {
    let mut tx = Transaction {
        sender_pubkey: key.verifying_key().to_bytes(),
        nonce,
        payload: TxPayload::Transfer { to, amount },
        signature: [0u8; 64],
    };
    let msg = solidus_exec::wire::signing_bytes(&tx, WireMode::BinaryV2);
    tx.signature = sign(key, &msg);
    tx
}

#[test]
fn executor_on_store2_matches_in_memory_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");
    let mut memory = InMemoryState::new();

    // Identical genesis on both baselines.
    let mut keys = Vec::new();
    for _ in 0..20 {
        let key = generate_signing_key();
        let addr = Address::from_public_key(&key.verifying_key());
        let acct = Account::with_balance(addr, 1_000_000, AccountType::Regular);
        store
            .seed_state(&StateKey::account(&addr), &acct.to_bytes())
            .expect("seed");
        memory.set(StateKey::account(&addr), acct.to_bytes());
        keys.push(key);
    }

    let opts = ExecOptions::v2_defaults(50_002);
    let mut expected_head = 0;
    for height in 1..=5u64 {
        let txs: Vec<Transaction> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let mut to = [0u8; 20];
                to[0] = i as u8;
                to[19] = height as u8;
                signed_transfer(k, Address::from_bytes(to), 100 + height, height - 1)
            })
            .collect();

        let ctx = ctx_at(height);
        let on_disk = execute_block_twolane(&store, &txs, &ctx, &opts).expect("store2 exec");
        let in_mem = execute_block_twolane(&memory, &txs, &ctx, &opts).expect("memory exec");

        // Identical outcomes across baselines.
        assert_eq!(on_disk.receipts, in_mem.receipts, "height {height}");
        let d1: Vec<_> = on_disk.delta.iter().collect();
        let d2: Vec<_> = in_mem.delta.iter().collect();
        assert_eq!(d1, d2, "delta divergence at height {height}");
        assert!(on_disk
            .receipts
            .iter()
            .all(|r| r.status == TxStatus::Success));

        // Persist atomically (one WriteBatch) and advance both baselines.
        let block_hash = [height as u8; 32];
        store
            .persist_block(
                height,
                block_hash,
                b"opaque-block-bytes",
                &on_disk.delta,
                &on_disk.receipts,
                &[],
                [[0u8; 32]; 4],
            )
            .expect("persist");
        memory.apply_delta(&in_mem.delta);
        expected_head = height;
    }

    // Receipts and canon are readable.
    assert_eq!(store.canon_head().expect("head"), Some(expected_head));
    assert_eq!(
        store.canon_hash(3).expect("canon"),
        Some([3u8; 32]),
        "canonical hash at height 3"
    );

    // Reopen: state must be identical to the in-memory mirror.
    drop(store);
    let reopened = Store2::open(dir.path(), Profile::Testnet).expect("reopen");
    for (key, value) in memory.iter() {
        let got = reopened.get(key).expect("read");
        assert_eq!(got.as_deref(), Some(value.as_slice()), "key {key:?}");
    }
    assert_eq!(reopened.canon_head().expect("head"), Some(expected_head));
}

#[test]
fn receipts_persist_and_prune_by_height_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");

    let key = generate_signing_key();
    let addr = Address::from_public_key(&key.verifying_key());
    let acct = Account::with_balance(addr, 10_000_000, AccountType::Regular);
    store
        .seed_state(&StateKey::account(&addr), &acct.to_bytes())
        .expect("seed");

    let opts = ExecOptions::v2_defaults(50_002);
    let mut receipt_keys = Vec::new();
    for height in 1..=10u64 {
        let tx = signed_transfer(&key, Address::from_bytes([9; 20]), 10, height - 1);
        let ctx = ctx_at(height);
        let outcome = execute_block_twolane(&store, &[tx], &ctx, &opts).expect("exec");
        receipt_keys.push((height, outcome.receipts[0].tx_hash));
        store
            .persist_block(
                height,
                [height as u8; 32],
                b"block",
                &outcome.delta,
                &outcome.receipts,
                &[],
                [[0u8; 32]; 4],
            )
            .expect("persist");
    }

    // All receipts present.
    for (h, tx_hash) in &receipt_keys {
        assert!(store.receipt(*h, tx_hash).expect("read").is_some());
    }

    // Prune below height 6: 1..=5 gone, 6..=10 retained; state untouched.
    store.prune_cold_before(6).expect("prune");
    for (h, tx_hash) in &receipt_keys {
        let present = store.receipt(*h, tx_hash).expect("read").is_some();
        assert_eq!(present, *h >= 6, "height {h}");
        let canon = store.canon_hash(*h).expect("canon").is_some();
        assert_eq!(canon, *h >= 6, "canon {h}");
    }
    // State survives pruning (only cold history is pruned).
    let account_bytes = store
        .get(&StateKey::account(&addr))
        .expect("read")
        .expect("account present");
    let account = Account::from_bytes(&account_bytes).expect("decode");
    assert_eq!(account.nonce, 10);
    // Canon head pointer survives.
    assert_eq!(store.canon_head().expect("head"), Some(10));
}

#[test]
fn sub_roots_are_persisted_with_the_block_and_pruned_with_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");
    let roots = |h: u8| [[h; 32], [h + 1; 32], [h + 2; 32], [h + 3; 32]];
    for h in 1..=3u64 {
        store
            .persist_block(
                h,
                [h as u8; 32],
                b"block",
                &solidus_exec::DeltaSet::new(),
                &[],
                &[],
                roots(h as u8),
            )
            .unwrap();
    }
    assert_eq!(store.sub_roots(2).unwrap(), Some(roots(2)));
    assert_eq!(store.sub_roots(9).unwrap(), None);
    store.prune_cold_before(3).unwrap();
    assert_eq!(
        store.sub_roots(2).unwrap(),
        None,
        "pruned with the cold data"
    );
    assert_eq!(store.sub_roots(3).unwrap(), Some(roots(3)));
}

/// The block -> batch-digest index round-trips, and pruning removes both the index row and the
/// batch bodies it names. Added 2026-09-22 when both places that read the packed index moved from
/// `chunks_exact(32)` to `as_chunks::<32>()` for clippy: the existing prune test persists every
/// block with NO digests, so neither read had ever run under a test.
#[test]
fn batch_digest_index_roundtrips_and_prune_deletes_the_bodies() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");

    let digests = [[1u8; 32], [2u8; 32], [3u8; 32]];
    for d in &digests {
        store.put_batch(d, b"batch body").expect("put batch");
    }
    let empty = DeltaSet::default();
    store
        .persist_block(
            5,
            [5u8; 32],
            b"block",
            &empty,
            &[],
            &digests,
            [[0u8; 32]; 4],
        )
        .expect("persist 5");
    store
        .persist_block(6, [6u8; 32], b"block", &empty, &[], &[], [[0u8; 32]; 4])
        .expect("persist 6");

    assert_eq!(
        store.block_batch_digests(5).expect("read"),
        digests.to_vec()
    );
    assert!(
        store.block_batch_digests(6).expect("read").is_empty(),
        "no digests at 6"
    );
    for d in &digests {
        assert!(
            store.batch_by_digest(d).expect("read").is_some(),
            "body present before prune"
        );
    }

    store.prune_cold_before(6).expect("prune");
    assert!(
        store.block_batch_digests(5).expect("read").is_empty(),
        "index row pruned"
    );
    for d in &digests {
        assert!(
            store.batch_by_digest(d).expect("read").is_none(),
            "body pruned with its block"
        );
    }
}

/// ⛔ THE SAME TRANSACTION IS INCLUDED IN TWO CONSECUTIVE BLOCKS ON THE LIVE CHAIN, AND THE
/// SECOND INCLUSION USED TO HIJACK ITS RECEIPT. Measured 2026-09-24: tx df8676b0… landed in
/// blocks 3222202 and 3222203, proposed by validator 0 then validator 1. Each validator's
/// worker seals its own batch and the DAG mempool dedupes BATCHES, not TRANSACTIONS, which is
/// normal for Narwhal-style designs.
///
/// The first copy executes and moves the money. The second fails the nonce check against the
/// account its own first copy bumped. Both receipts are stored — the key is (height, tx_hash) —
/// but `tx_index` is keyed by hash ALONE, and it was overwritten unconditionally. So
/// `solidus_getReceipt(hash)` resolved to the LATER, failed execution and reported
/// `failed: invalid nonce` for a transfer whose money had demonstrably arrived.
///
/// ⚠ FIRST WRITE WINS, because the first inclusion is the one that actually executed. This is
/// a pure index fix: no execution changes, no delta changes, and receipts are not part of the
/// state root, so no consensus rule moves and no activation height is needed.
#[test]
fn a_transaction_included_twice_keeps_the_index_on_its_real_execution() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");

    let tx_hash = [0xABu8; 32];
    let succeeded = Receipt {
        tx_hash,
        status: TxStatus::Success,
        block_height: 1,
        fee_paid: 7,
        events: vec![],
    };
    let hijacker = Receipt {
        tx_hash,
        status: TxStatus::Failed("invalid nonce: expected 2, got 1".into()),
        block_height: 2,
        fee_paid: 0,
        events: vec![],
    };

    store
        .persist_block(
            1,
            [1u8; 32],
            b"b1",
            &DeltaSet::default(),
            &[succeeded],
            &[],
            [[0u8; 32]; 4],
        )
        .expect("persist 1");
    store
        .persist_block(
            2,
            [2u8; 32],
            b"b2",
            &DeltaSet::default(),
            &[hijacker],
            &[],
            [[0u8; 32]; 4],
        )
        .expect("persist 2");

    assert_eq!(
        store.tx_height(&tx_hash).expect("tx_height"),
        Some(1),
        "the index must still point at the execution that actually happened"
    );

    let resolved = store
        .receipt(1, &tx_hash)
        .expect("receipt read")
        .expect("a receipt at the indexed height");
    assert_eq!(
        resolved.status,
        TxStatus::Success,
        "getReceipt resolves through tx_index, so a hijacked index reports a successful \
         transaction as failed"
    );

    // The duplicate's own receipt is still readable at ITS height — nothing is destroyed,
    // the index simply stops pointing at it.
    let dup = store
        .receipt(2, &tx_hash)
        .expect("dup read")
        .expect("dup receipt");
    assert!(matches!(dup.status, TxStatus::Failed(_)));
}

/// ⛔ NODE-LOCAL, NOT CONSENSUS STATE. A signature is this validator's own view of an outbox entry,
/// and nodes do not agree on each other's signatures. It lives in its own column family so nothing
/// in the state root ever depends on it, and so losing it costs a re-sign rather than a fork.
#[test]
fn attestations_round_trip_and_are_keyed_by_domain_and_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");

    assert_eq!(store.attestation(11_155_111, 1).unwrap(), None);
    store.put_attestation(11_155_111, 1, &[7u8; 65]).unwrap();
    store.put_attestation(43_113, 1, &[9u8; 65]).unwrap();

    assert_eq!(store.attestation(11_155_111, 1).unwrap(), Some([7u8; 65]));
    assert_eq!(
        store.attestation(43_113, 1).unwrap(),
        Some([9u8; 65]),
        "domains do not collide"
    );
    assert_eq!(store.attestation(11_155_111, 2).unwrap(), None);
}

/// ⚠ THE KEY IS BIG-ENDIAN, AND THIS IS THE TEST THAT SAYS SO. Little-endian would order sequence
/// 256 before sequence 2, and the gateway reads a range in key order to find what it has not yet
/// delivered. The bug would look like a gateway that skips messages under load and nowhere else.
#[test]
fn attestation_keys_sort_in_sequence_order() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");
    for seq in [1u64, 2, 10, 256, 1000] {
        store
            .put_attestation(11_155_111, seq, &[seq as u8; 65])
            .unwrap();
    }
    let seen = store.attestations_from(11_155_111, 2, 10).unwrap();
    assert_eq!(
        seen.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        vec![2, 10, 256, 1000],
        "a range read must come back in ascending sequence order"
    );
}

/// ⛔ A RANGE READ MUST STOP AT ITS OWN DOMAIN, and the domain it reads from decides whether the
/// test can see that at all. Fuji is 43 113 (0x0000A849) and Sepolia is 11 155 111 (0x00AA36A7), so
/// a forward scan from FUJI runs into Sepolia's keys and a scan from Sepolia runs off the end into
/// nothing. My first version of this test read Sepolia, and deleting the prefix check left it green.
#[test]
fn a_range_read_does_not_bleed_into_the_next_domain() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store2::open(dir.path(), Profile::Testnet).expect("open");
    store.put_attestation(43_113, 1, &[1u8; 65]).unwrap();
    store.put_attestation(43_113, 2, &[2u8; 65]).unwrap();
    store.put_attestation(11_155_111, 1, &[9u8; 65]).unwrap();

    let fuji = store.attestations_from(43_113, 1, 10).unwrap();
    assert_eq!(
        fuji.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
        vec![1, 2],
        "the read stopped at the end of Fuji rather than continuing into Sepolia"
    );
    assert!(
        fuji.iter().all(|(_, sig)| sig[0] != 9),
        "a Sepolia signature reached a Fuji read"
    );
}

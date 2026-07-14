//! Stage-4 verification: the two-lane executor runs directly against
//! RocksDB-backed Store2 with outcomes identical to the in-memory
//! baseline; blocks persist atomically; state survives reopen; pruning
//! bounds cold growth without touching state.

use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{
    execute_block_twolane, Account, AccountType, BlockCtx, ExecOptions, InMemoryState, StateKey,
    StateReader, WireMode,
};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Transaction, TxPayload, TxStatus};

fn ctx_at(height: u64) -> BlockCtx<'static> {
    BlockCtx {
        height,
        timestamp_ms: 1_700_000_000_000 + height,
        network: "v2-store-test",
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

    let opts = ExecOptions::v2_defaults();
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

    let opts = ExecOptions::v2_defaults();
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

//! Restart recovery: a validator that stops must come back where it was.
//!
//! ⛔ THIS IS THE REGRESSION FOR A DEFECT THAT HALTED THE v2 DEVNET FOR A MONTH.
//! `Node::new` used to hardcode the exec anchor to `(0, [0u8; 32])` and never
//! read the store. The anchor feeds consensus as the state anchor for proposals
//! and votes, so a restarted validator rejoined at height 0 with a zero root,
//! could not agree with peers that had not restarted, and the chain lost quorum.
//! Measured 2026-09-02 on the live devnet: a validator holding 1,835,001 blocks
//! came back reporting 0.
//!
//! ⚠ THE HEIGHT ALONE IS NOT ENOUGH, WHICH IS WHY THE ROOT IS ASSERTED TOO.
//! The in-memory state forest also starts empty. Recovering the height without
//! rebuilding the forest pairs a real height with an empty state root, which is
//! worse than the original bug because it looks recovered.

use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType, DeltaSet, StateKey};
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeTuning};
use solidus_store2::{Profile, Store2};

const CHAIN_ID: u64 = 2;
const NETWORK: &str = "v2-restart-recovery-test";
const COMMITTED_HEIGHT: u64 = 7;

/// Like `spawn`, but hands back the boot error instead of panicking.
fn try_spawn(store: Store2) -> Result<Node, solidus_node2::NodeError> {
    let secret = BlsSecretKey::generate();
    let pubkeys = vec![secret.public_key()];
    let committee = Committee::new(pubkeys.clone());
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(1));
    Node::new(
        0,
        CHAIN_ID,
        secret,
        committee,
        pubkeys,
        Pacemaker::default(),
        elector,
        store,
        NodeTuning {
            max_certs_per_block: 64,
            batch_max_bytes: 512 * 1024,
            batch_max_txs: 400,
            flush_interval_ms: 25,
            min_block_interval_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
            view_timeout_ms: 0,
            block_retention: 0,
        },
        NETWORK.to_string(),
    )
}

/// Write what a REAL validator leaves behind at `height`: a decodable block and
/// a safety record.
///
/// ⚠ THE OLD FIXTURES WROTE NEITHER, AND STILL BOOTED. That only worked because
/// an unresumable store used to start a fresh chain on top of itself — the
/// defect that put two chains in one store on devnet-v2. Now such a store stops
/// the node, so a fixture that wants a RESUMABLE validator has to look like one.
fn persist_resumable(node: &Node, height: u64, delta: &DeltaSet) -> [u8; 32] {
    persist_resumable_with(node, height, delta, &[])
}

fn persist_resumable_with(
    node: &Node,
    height: u64,
    delta: &DeltaSet,
    batches: &[[u8; 32]],
) -> [u8; 32] {
    let genesis = [0u8; 32];
    let block = solidus_hotstuff2::Block2 {
        header: solidus_hotstuff2::BlockHeader2 {
            chain_id: CHAIN_ID,
            height,
            view: height,
            parent: genesis,
            proposer: 0,
            timestamp_ms: 1,
            batch_certs: Vec::new(),
            exec_height: 0,
            exec_state_root: [0u8; 32],
        },
        justify: solidus_hotstuff2::QuorumCert::genesis(
            genesis,
            BlsSecretKey::generate().sign(b"g"),
        ),
    };
    let hash = block.hash();
    let bytes = bincode::serialize(&block).expect("encode block");
    node.store()
        .persist_block(height, hash, &bytes, delta, &[], batches, [[0u8; 32]; 4])
        .expect("persist block");
    let qc = bincode::serialize(&block.justify).expect("encode qc");
    node.store().put_safety(height, &qc).expect("put safety");
    hash
}

fn spawn(store: Store2) -> Node {
    let secret = BlsSecretKey::generate();
    let pubkeys = vec![secret.public_key()];
    let committee = Committee::new(pubkeys.clone());
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(1));
    Node::new(
        0,
        CHAIN_ID,
        secret,
        committee,
        pubkeys,
        Pacemaker::default(),
        elector,
        store,
        NodeTuning {
            max_certs_per_block: 64,
            batch_max_bytes: 512 * 1024,
            batch_max_txs: 400,
            flush_interval_ms: 25,
            min_block_interval_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
            view_timeout_ms: 0,
            block_retention: 0, // pruning is exercised explicitly below
        },
        NETWORK.to_string(),
    )
    .expect("node boots")
}

#[test]
fn restarted_node_recovers_height_and_state_root_from_the_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let addr = Address::from_bytes([7u8; 20]);
    let acct = Account::with_balance(addr, 1_000_000, AccountType::Regular);
    let seeded_root;

    // ── Boot 1: a fresh chain, seeded, then given committed history ──────────
    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let mut node = spawn(store);

        // Control: a genuinely fresh store must still start at height 0. If this
        // ever fails, recovery is inventing a height rather than reading one.
        assert_eq!(
            node.exec_anchor().lock().expect("anchor").0,
            0,
            "a fresh chain must start at height 0"
        );

        node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        seeded_root = node.exec_anchor().lock().expect("anchor").1;
        assert_ne!(
            seeded_root, [0u8; 32],
            "seeding state must move the global root off zero, else the root \
             assertion below proves nothing"
        );

        let mut delta = DeltaSet::new();
        delta
            .insert(StateKey::account(&addr), acct.to_bytes())
            .expect("delta insert");
        // A REAL validator's leftovers: a decodable block and a safety record.
        // Writing neither used to boot anyway, because an unresumable store
        // started a fresh chain on top of itself.
        persist_resumable(&node, COMMITTED_HEIGHT, &delta);
    }

    // ── Boot 2: same directory, and deliberately NO seeding ─────────────────
    // A restart does not re-seed genesis, so everything asserted here has to
    // come from the store.
    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let node = spawn(store);
        let (height, root) = *node.exec_anchor().lock().expect("anchor");

        assert_eq!(
            height, COMMITTED_HEIGHT,
            "a restarted validator must resume at its stored height, not 0 — \
             this is the defect that halted the devnet"
        );
        assert_eq!(
            root, seeded_root,
            "and it must resume with the state it had; an empty forest here \
             would look recovered while disagreeing with every peer"
        );
    }
}

#[test]
fn pruning_stays_below_the_head_and_never_touches_state() {
    // The interaction between the two Phase-1 fixes: pruning must not damage
    // what boot recovery depends on.
    //
    // ⚠ THIS TEST FIRST ASSERTED THAT PRUNING CANNOT REMOVE THE HEAD, ON THE
    // THEORY THAT AN ABSENT HEAD READS AS A FRESH CHAIN AND RE-SEEDS GENESIS.
    // Seeding it disproved that: `canon_head()` reads `META_CANON_HEAD` from
    // `s_meta`, and `prune_cold_before` only touches `canon` and `blocks`, so
    // the head pointer is unreachable from pruning and the assertion could
    // never fail. A test that cannot fail is not a test.
    //
    // What IS real, and is asserted below: pruning at or above the head deletes
    // the head's own block and canon entry, leaving `canon_head()` pointing at a
    // block the store no longer holds. And state is never pruned, so the
    // boot-time forest rebuild still sees a complete tree.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    let addr = Address::from_bytes([9u8; 20]);
    let acct = Account::with_balance(addr, 500_000, AccountType::Regular);
    let seeded_root;

    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let mut node = spawn(store);
        node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        seeded_root = node.exec_anchor().lock().expect("anchor").1;

        for height in 1..=10u64 {
            let mut delta = DeltaSet::new();
            delta
                .insert(StateKey::account(&addr), acct.to_bytes())
                .expect("delta insert");
            // One batch body per block, so batch pruning is observable.
            let digest = [height as u8; 32];
            node.store()
                .put_batch(&digest, b"batch-body")
                .expect("put batch");
            persist_resumable_with(&node, height, &delta, &[digest]);
        }

        // Prune everything below 8, exactly as the commit path does.
        node.store().prune_cold_before(8).expect("prune");

        let head = node.store().canon_head().expect("head");
        assert_eq!(head, Some(10), "the head pointer is never pruned");

        // The assertion that can actually fail: the head's own block must still
        // resolve. Pruning at or above the head deletes it, and `canon_head()`
        // would then name a block the store cannot produce.
        assert!(
            node.store().canon_hash(10).expect("canon").is_some(),
            "pruning must stay strictly BELOW the head — otherwise canon_head \
             points at a block that has been deleted"
        );
        // ⛔ THE REGRESSION THIS FIX EXISTS FOR. Persisting batch bodies was
        // required for block sync, and for a while nothing deleted them, so the
        // larger record type grew without bound while `block_retention` bounded
        // only blocks. Batch lifetime is now tied to the block that certifies
        // it, via the block_batches index.
        assert!(
            node.store()
                .batch_by_digest(&[3u8; 32])
                .expect("read")
                .is_none(),
            "a batch certified by a pruned block must be pruned with it"
        );
        assert_eq!(
            node.store().batch_by_digest(&[9u8; 32]).expect("read"),
            Some(b"batch-body".to_vec()),
            "and a batch certified by a block ABOVE the horizon must survive — \
             otherwise this test would pass by deleting everything"
        );

        assert!(
            node.store().canon_hash(3).expect("canon").is_none(),
            "and it must actually prune: height 3 is below the horizon of 8, so \
             it must be gone, else this test would pass without pruning anything"
        );
    }

    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let node = spawn(store);
        let (height, root) = *node.exec_anchor().lock().expect("anchor");
        assert_eq!(height, 10, "a pruned chain still restarts at its real head");
        assert_eq!(
            root, seeded_root,
            "and pruning must never touch STATE — only blocks, receipts and \
             canon — so the boot-time forest rebuild still sees everything"
        );
    }
}

#[test]
fn batch_bodies_survive_a_restart_so_a_peer_can_still_be_served() {
    // ⛔ WITHOUT THIS, BLOCK SYNC CANNOT WORK AT ALL. A v2 block carries
    // `batch_certs` — the body BY DIGEST — so the transactions are not in the
    // block. `BatchStore` was an in-memory HashMap and the `batches` column
    // family, declared in CF_COLD and documented "mempool persistence", was
    // never written. So every node lost its batch bodies on restart, and a
    // backfilling peer could fetch a block it could never execute.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();
    let digest = [42u8; 32];
    let body = b"bincode-encoded-batch-body".to_vec();

    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        store.put_batch(&digest, &body).expect("put batch");
        assert_eq!(
            store.batch_by_digest(&digest).expect("read"),
            Some(body.clone()),
            "a batch must be readable in the session that stored it"
        );
    }

    {
        let store = Store2::open(&path, Profile::Testnet).expect("reopen");
        assert_eq!(
            store.batch_by_digest(&digest).expect("read"),
            Some(body),
            "and it must SURVIVE the restart — otherwise the node cannot honour \
             insert_verified's promise to never ack what it cannot re-serve"
        );
        assert_eq!(
            store.batch_by_digest(&[7u8; 32]).expect("read"),
            None,
            "control: an unknown digest must be absent, so the assertion above \
             is not passing on a store that returns something for anything"
        );
    }
}

#[test]
fn the_tx_index_is_written_readable_and_pruned_with_its_receipts() {
    // ⛔ WHY THIS INDEX EXISTS. v1 answers getTransaction by walking every block
    // backwards from the tip, and says so in its own comment: "This is
    // O(blocks) which is acceptable for testnet". At 1.8M blocks it is not, and
    // this chain targets 50K TPS, so v2 pays one small write per transaction
    // instead of a full scan per query.
    use solidus_txns::types::{Receipt, TxStatus};

    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("store");

    let receipt_at = |h: u64| Receipt {
        tx_hash: [h as u8; 32],
        status: TxStatus::Success,
        block_height: h,
        fee_paid: 1,
        events: vec![],
    };

    for height in 1..=10u64 {
        let delta = DeltaSet::new();
        store
            .persist_block(
                height,
                [height as u8; 32],
                b"block",
                &delta,
                &[receipt_at(height)],
                &[],
                [[0u8; 32]; 4],
            )
            .expect("persist");
    }

    // Written and readable, and it resolves to the RIGHT height rather than any
    // height - a constant would pass a weaker assertion.
    assert_eq!(store.tx_height(&[3u8; 32]).expect("read"), Some(3));
    assert_eq!(store.tx_height(&[9u8; 32]).expect("read"), Some(9));
    assert_eq!(
        store.tx_height(&[99u8; 32]).expect("read"),
        None,
        "control: an unknown hash must be absent, so the assertions above are \
         not passing against a store that answers for anything"
    );

    store.prune_cold_before(8).expect("prune");

    assert_eq!(
        store.tx_height(&[3u8; 32]).expect("read"),
        None,
        "an index entry must be pruned with the receipt it mirrors - one left \
         behind points at a height whose data is gone"
    );
    assert_eq!(
        store.tx_height(&[9u8; 32]).expect("read"),
        Some(9),
        "and an entry above the horizon must survive, so this test cannot pass \
         by deleting the whole index"
    );
}

#[test]
fn safety_state_survives_a_restart_and_absence_is_distinguishable() {
    // ⛔ THE VALUE THAT PREVENTS SELF-SLASHING. A validator that forgets which
    // views it voted in can vote twice in one view after a restart, which is
    // equivocation, which this repo's own EquivocationDetector catches. This
    // asserts the record survives a reopen, because without it the whole
    // restart-recovery fix is more dangerous than the bug it repairs.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        assert_eq!(
            store.safety().expect("read"),
            None,
            "a validator that has never voted reports None, and that must stay \
             distinguishable from a recorded view of 0"
        );
        store.put_safety(42, b"qc-bytes").expect("put safety");
    }

    {
        let store = Store2::open(&path, Profile::Testnet).expect("reopen");
        let (view, qc) = store.safety().expect("read").expect("must survive");
        assert_eq!(view, 42, "the voted view must survive a restart");
        assert_eq!(qc, b"qc-bytes".to_vec(), "and so must the lock");
    }

    // A recorded view of 0 is NOT the same as never having voted: the first
    // reports Some(0), the second None. Collapsing them would let a node that
    // voted in view 0 look like a fresh validator.
    {
        let dir2 = tempfile::tempdir().expect("tempdir");
        let store = Store2::open(dir2.path(), Profile::Testnet).expect("store");
        store.put_safety(0, b"").expect("put");
        assert_eq!(store.safety().expect("read"), Some((0, Vec::new())));
    }
}

/// ⛔ A STORE WITH COMMITTED BLOCKS AND NO SAFETY RECORD MUST STOP THE NODE.
///
/// The old behaviour logged the refusal and booted a FRESH chain onto the same
/// store, which is the worst of both. Measured on devnet-v2 on 2026-09-03: the
/// new chain reached height 20774 while heights 25000, 30000 and 44497 all
/// still answered with old-chain blocks. Nothing in a height query can tell the
/// two apart, and `read_block_range` would hand those stale blocks to a peer
/// that asked to sync.
///
/// A node that cannot resume has two honest options and "start fresh on top of
/// the old data" is neither. Stopping is loud and recoverable; the mix is
/// silent and permanent.
#[test]
fn a_store_it_cannot_resume_stops_the_node_instead_of_starting_a_second_chain() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_path_buf();

    // Commit history WITHOUT ever writing a safety record — exactly the shape of
    // a store written by a binary from before safety state was persisted.
    let committed_height;
    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        let mut node = spawn(store);
        let addr = Address::from_bytes([9u8; 20]);
        let acct = Account::with_balance(addr, 500, AccountType::Regular);
        node.seed_account(&StateKey::account(&addr), &acct.to_bytes());

        let mut delta = DeltaSet::new();
        delta
            .insert(StateKey::account(&addr), acct.to_bytes())
            .expect("delta insert");
        committed_height = 1;
        node.store()
            .persist_block(
                committed_height,
                [1u8; 32],
                b"block",
                &delta,
                &[],
                &[],
                [[0u8; 32]; 4],
            )
            .expect("persist block");
    }

    // Control: the store really does have committed blocks. Without this the
    // refusal below could just be an empty-store path.
    {
        let store = Store2::open(&path, Profile::Testnet).expect("store");
        assert_eq!(
            store.canon_head().expect("head"),
            Some(committed_height),
            "the fixture must leave committed history, or this test proves nothing"
        );
        assert!(
            store.safety().expect("safety").is_none(),
            "the fixture must leave NO safety record, which is the condition under test"
        );
    }

    let store = Store2::open(&path, Profile::Testnet).expect("store");
    match try_spawn(store) {
        Err(solidus_node2::NodeError::CannotResume { height, .. }) => {
            assert_eq!(
                height, committed_height,
                "the refusal must name the head it refused at"
            );
        }
        Err(other) => panic!("wrong refusal: {other}"),
        Ok(_) => panic!(
            "the node started a second chain on top of committed history. Every height below \
             the new tip would be the new chain and every height above it the old one, and no \
             query can tell them apart"
        ),
    }
}

/// Control: a genuinely EMPTY store still boots. The refusal must key on
/// "committed blocks I cannot resume", not on "no safety record", or no node
/// could ever start for the first time.
#[test]
fn a_fresh_store_still_boots_with_no_safety_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = Store2::open(dir.path(), Profile::Testnet).expect("store");
    assert!(
        try_spawn(store).is_ok(),
        "a fresh store has no safety record either, and must still start"
    );
}

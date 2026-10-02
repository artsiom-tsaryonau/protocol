//! Restart the WHOLE validator set over real libp2p, the way `systemctl
//! restart` does on the devnet box, and require the chain to keep going.
//!
//! ⛔ THIS IS THE ACCEPTANCE CRITERION FOR RESTART RECOVERY. The v2 devnet
//! restarted on 2026-09-02, every validator resumed correctly, the height held
//! at 811, and not one block followed. In-process tests all passed, because
//! channels stop the whole set in the same instant — the one condition under
//! which the defect cannot appear. Only the real transport made the stop
//! non-uniform, so only this test could see it.
//!
//! It ran RED and found five things. Four were named and retracted first, each
//! argued from mechanism and each killed by a measurement; the fifth was found
//! by instrumenting the branch points and reading which one fired:
//!
//! 1. `resume` derived the view from PRIVATE state (`last_voted_view`) where
//!    the committee needed a shared certificate. Validators came back scattered
//!    and timeout votes never gathered in any one view.
//! 2. Nothing ever re-dialled a peer, so of four validators one reached the
//!    connections it needed to boot. "Gossipsub mesh formation is
//!    probabilistic" had been the standing explanation for years of flaky
//!    libp2p tests here; it was a missing retry.
//! 3. The execution guard refused to run a block over a gap — correctly — and
//!    never asked anyone to fill it, so the head stopped forever while
//!    consensus certified ~1750 proposals every 25 seconds.
//!
//! ⚠ NO LONGER `#[ignore]`, AND THE REASON IT WAS IS THE REASON IT NEED NOT BE.
//! It was skipped as "probabilistic mesh formation", which turned out to be
//! defect 2. With the retry in place it passes 12 of 12 in about 21 seconds
//! each. If it goes red again, a validator cannot survive a restart, which is
//! the mainnet upgrade case.
//!
//! ⚠ PHASE ONE IS AN ASSERTION, NOT SETUP. A wedge after a set that never
//! started is not evidence of anything, so the first assertion exists to make a
//! phase-two failure readable.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use libp2p::identity::Keypair as P2pKeypair;
use libp2p::{Multiaddr, PeerId};
use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey};
use solidus_crypto::ed25519::{generate_signing_key, sign};
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType, StateKey, WireMode};
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeInput, NodeTuning};
use solidus_p2p2::{build_swarm_with_keypair, Executed, P2pRunner};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::{Transaction, TxPayload};
use tokio::sync::mpsc;

const CHAIN_ID: u64 = 2;
const NETWORK: &str = "v2-libp2p-restart";
const N: usize = 4;

fn transfer(key: &SigningKey, to: Address, amount: u64, nonce: u64) -> Transaction {
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

/// Everything that survives a restart, because on a real box it lives on disk
/// or in a config file rather than in the process.
struct Identity {
    dirs: Vec<std::path::PathBuf>,
    _tempdirs: Vec<tempfile::TempDir>,
    bls_secret_bytes: Vec<[u8; 32]>,
    bls_pubkeys: Vec<BlsPublicKey>,
    p2p_keys: Vec<P2pKeypair>,
    funded: Vec<SigningKey>,
}

/// Build one validator against its own directory.
///
/// ⚠ `seed_genesis` is false on every restart, deliberately. `solidus-noded`
/// seeds genesis only when `canon_head()` is None, so re-seeding here would test
/// something the daemon does not do and would overwrite live balances.
fn build_runner(id: &Identity, index: usize, seed_genesis: bool) -> P2pRunner {
    let store = Store2::open(&id.dirs[index], Profile::Testnet).expect("store");
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(N));
    let committee = Committee::new(id.bls_pubkeys.clone());
    let mut node = Node::new(
        index as u32,
        CHAIN_ID,
        BlsSecretKey::from_bytes(&id.bls_secret_bytes[index]).expect("secret"),
        committee,
        id.bls_pubkeys.clone(),
        Pacemaker::default(),
        elector,
        store,
        NodeTuning {
            max_certs_per_block: 64,
            batch_max_bytes: 256 * 1024,
            batch_max_txs: 200,
            flush_interval_ms: 25,
            min_block_interval_ms: 0,
            idle_heartbeat_ms: 0,
            idle_grace_ms: 0,
            view_timeout_ms: 0,
            block_retention: 0,
        },
        NETWORK.to_string(),
    )
    .expect("node boots");

    if seed_genesis {
        for key in &id.funded {
            let addr = Address::from_public_key(&key.verifying_key());
            let acct = Account::with_balance(addr, 1_000_000_000, AccountType::Regular);
            node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        }
    }

    let swarm = build_swarm_with_keypair(CHAIN_ID, id.p2p_keys[index].clone()).expect("swarm");
    P2pRunner::new(index as u32, CHAIN_ID, node, swarm)
}

/// Listen, wire the full mesh, and spawn every runner. Returns the task handles
/// and one input sender per node.
async fn start_set(
    id: &Identity,
    seed_genesis: bool,
    executed: &Arc<Mutex<Vec<Vec<Executed>>>>,
) -> (
    Vec<tokio::task::JoinHandle<()>>,
    Vec<mpsc::UnboundedSender<NodeInput>>,
) {
    let mut runners: Vec<P2pRunner> = Vec::new();
    let mut exec_rxs = Vec::new();
    for index in 0..N {
        let mut runner = build_runner(id, index, seed_genesis);
        let (tx, rx) = mpsc::unbounded_channel();
        runner.set_executed_sink(tx);
        exec_rxs.push(rx);
        runners.push(runner);
    }

    let mut addrs: Vec<Multiaddr> = Vec::new();
    for runner in runners.iter_mut() {
        addrs.push(runner.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap()).await);
    }
    let peer_ids: Vec<PeerId> = id
        .p2p_keys
        .iter()
        .map(|k| k.public().to_peer_id())
        .collect();

    #[allow(clippy::needless_range_loop)]
    for i in 0..N {
        for j in 0..N {
            if i != j {
                runners[i].add_peer(j as u32, peer_ids[j], addrs[j].clone());
            }
        }
    }

    let inputs: Vec<mpsc::UnboundedSender<NodeInput>> =
        runners.iter().map(|r| r.input_sender()).collect();

    for (i, mut rx) in exec_rxs.into_iter().enumerate() {
        let executed = Arc::clone(executed);
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                executed.lock().expect("lock")[i].push(e);
            }
        });
    }

    // Quorum rather than all N-1: mesh formation is probabilistic here, and a
    // quorum is what consensus actually needs.
    let handles = runners
        .into_iter()
        .map(|r| tokio::spawn(r.run(N - 2)))
        .collect();
    (handles, inputs)
}

fn highest(executed: &Arc<Mutex<Vec<Vec<Executed>>>>) -> u64 {
    executed
        .lock()
        .expect("lock")
        .iter()
        .filter_map(|rows| rows.last().map(|e| e.height))
        .max()
        .unwrap_or(0)
}

async fn feed(
    inputs: &[mpsc::UnboundedSender<NodeInput>],
    funded: &[SigningKey],
    from: u64,
    n: u64,
) {
    for i in from..from + n {
        let payer = &funded[(i as usize) % funded.len()];
        let nonce = i / funded.len() as u64;
        let mut to = [0u8; 20];
        to[..8].copy_from_slice(&i.to_le_bytes());
        to[19] = 0xEE;
        let tx = transfer(payer, Address::from_bytes(to), 100, nonce);
        let _ = inputs[(i as usize) % N].send(NodeInput::SubmitTx(tx));
        if i % 200 == 199 {
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn the_validator_set_restarts_over_libp2p_and_keeps_producing() {
    let bls: Vec<BlsSecretKey> = (0..N).map(|_| BlsSecretKey::generate()).collect();
    let mut tempdirs = Vec::new();
    let mut dirs = Vec::new();
    for _ in 0..N {
        let d = tempfile::tempdir().expect("tempdir");
        dirs.push(d.path().to_path_buf());
        tempdirs.push(d);
    }
    let id = Identity {
        dirs,
        _tempdirs: tempdirs,
        bls_secret_bytes: bls.iter().map(|k| k.to_bytes()).collect(),
        bls_pubkeys: bls.iter().map(|k| k.public_key()).collect(),
        p2p_keys: (0..N).map(|_| P2pKeypair::generate_ed25519()).collect(),
        funded: (0..50).map(|_| generate_signing_key()).collect(),
    };

    let executed: Arc<Mutex<Vec<Vec<Executed>>>> = Arc::new(Mutex::new(vec![Vec::new(); N]));

    // ── phase one: a chain exists ───────────────────────────────────────────
    let (handles, inputs) = start_set(&id, true, &executed).await;
    // ⚠ Longer than four_node_libp2p's 6s. Measured: with 6s, two runs in three
    // never committed at all, so the test failed at phase one and said nothing
    // about restarts. Mesh formation is the flaky part, not the restart.
    tokio::time::sleep(Duration::from_secs(12)).await;
    feed(&inputs, &id.funded, 0, 4_000).await;

    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while highest(&executed) < 8 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the set never committed over libp2p, so a restart would prove \
             nothing. This is the probabilistic mesh, not the restart path"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let before = highest(&executed);
    println!("phase one: committed to height {before}");

    // ── the restart ─────────────────────────────────────────────────────────
    // Aborting drops each future and with it the Node, which releases RocksDB's
    // lock. Without that the reopen fails and the test would look like a
    // recovery bug rather than a harness one.
    for h in &handles {
        h.abort();
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

    let (handles2, inputs2) = start_set(&id, false, &executed).await;
    tokio::time::sleep(Duration::from_secs(6)).await;
    feed(&inputs2, &id.funded, 4_000, 4_000).await;

    // ── phase two: does it produce again? ───────────────────────────────────
    // ⚠ FIVE MINUTES, NOT NINETY SECONDS, AND THE LENGTH IS THE QUESTION. A
    // wedge and a very slow recovery look identical at 90s, and they are
    // different bugs: the pacemaker backs off exponentially, so a set that
    // needs several minutes to re-converge is a tuning problem where a set that
    // never converges is a correctness one.
    let restart_deadline = tokio::time::Instant::now() + Duration::from_secs(300);
    let mut after = highest(&executed);
    while after <= before {
        assert!(
            tokio::time::Instant::now() < restart_deadline,
            "⛔ REPRODUCED: the set restarted over libp2p and never committed \
             again. Highest before {before}, still {after} after 300s. This is \
             the devnet's failure: on the box the height held at 811 with zero \
             refusals and no block ever followed.\n  per-node executed \
             heights: {:?}\n  (all equal and stuck means consensus is fine and \
             EXECUTION is blocked — measured 2026-09-03: after a restart the \
             set still certified ~1750 proposals and QCs every 25s with zero \
             timeouts, so the chain was healthy and simply not executing)",
            executed
                .lock()
                .expect("lock")
                .iter()
                .map(|rows| rows.last().map(|e| e.height).unwrap_or(0))
                .collect::<Vec<_>>()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
        after = highest(&executed);
    }

    println!("phase two: resumed and committed to height {after}");
    assert!(
        after > before,
        "the restarted set must commit ABOVE where it stopped"
    );

    for h in &handles2 {
        h.abort();
    }
}

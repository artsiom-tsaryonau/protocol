//! The daemon: load a validator's config, build its `Node` (HotStuff-2 + DAG
//! mempool + two-lane executor + store2), wire it to the real libp2p stack via
//! `P2pRunner`, bind the `rpc2` JSON-RPC edge over a shared `Arc<Store2>`, and
//! run until Ctrl-C. This is one validator process; a network is N of these
//! with a shared committee + genesis.

use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use libp2p::identity::Keypair as P2pKeypair;
use libp2p::{Multiaddr, PeerId};

use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey};
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType, StateKey, WireMode};
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeInput, NodeTuning};
use solidus_p2p2::{build_swarm_with_keypair, P2pRunner};
use solidus_rpc2::{serve, RpcBackend, Store2Backend};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::Transaction;

use crate::config::DaemonConfig;

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).with_context(|| format!("{what}: invalid hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("{what}: expected {N} bytes, got {}", bytes.len()))
}

pub async fn run(cfg: DaemonConfig) -> Result<()> {
    // Committee + validator pubkeys, ordered by index (consensus indexes into
    // this vector, so the order is load-bearing).
    let mut vals = cfg.validators.clone();
    vals.sort_by_key(|v| v.index);
    let pubkeys: Vec<BlsPublicKey> = vals
        .iter()
        .map(|v| {
            let b = hex_n::<48>(&v.bls_pubkey_hex, "validator bls pubkey")?;
            BlsPublicKey::from_bytes(&b).map_err(|e| anyhow!("bad bls pubkey: {e:?}"))
        })
        .collect::<Result<_>>()?;
    let n = pubkeys.len();
    if n == 0 {
        return Err(anyhow!("no validators in config"));
    }
    let committee = Committee::new(pubkeys.clone());

    // This node's secret identities.
    let bls_secret = BlsSecretKey::from_bytes(&hex_n::<32>(&cfg.bls_secret_hex, "bls secret")?)
        .map_err(|e| anyhow!("bad bls secret: {e:?}"))?;
    let p2p_keypair =
        P2pKeypair::ed25519_from_bytes(hex_n::<32>(&cfg.p2p_secret_hex, "p2p secret")?)
            .map_err(|e| anyhow!("bad p2p secret: {e}"))?;

    // Store + genesis seeding (idempotent: re-seeding writes the same bytes).
    std::fs::create_dir_all(&cfg.data_dir).ok();
    let store = Store2::open(Path::new(&cfg.data_dir), Profile::Testnet)
        .map_err(|e| anyhow!("open store at {}: {e:?}", cfg.data_dir))?;
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));
    let tuning = NodeTuning {
        max_certs_per_block: cfg.tuning.max_certs_per_block,
        batch_max_bytes: cfg.tuning.batch_max_bytes,
        batch_max_txs: cfg.tuning.batch_max_txs,
        flush_interval_ms: cfg.tuning.flush_interval_ms,
    };
    let mut node = Node::new(
        cfg.index,
        cfg.chain_id,
        bls_secret,
        committee,
        pubkeys,
        Pacemaker::default(),
        elector,
        store,
        tuning,
        cfg.network.clone(),
    );
    for g in &cfg.genesis {
        let addr = Address::from_bytes(hex_n::<20>(&g.address_hex, "genesis address")?);
        let acct = Account::with_balance(addr, g.balance, AccountType::Regular);
        node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
    }

    // Shared handles for the RPC edge — grab BEFORE the node moves into the
    // runner. Store2 methods are all `&self` (RocksDB is internally synced),
    // so the node writes while the RPC reads through the same Arc.
    let rpc_store = node.store();
    let anchor = node.exec_anchor();

    // Real libp2p transport + the swarm↔node event loop.
    let swarm = build_swarm_with_keypair(cfg.chain_id, p2p_keypair)
        .map_err(|e| anyhow!("build swarm: {e:?}"))?;
    let mut runner = P2pRunner::new(cfg.index, cfg.chain_id, node, swarm);
    let listen: Multiaddr = cfg.listen_addr.parse().context("listen_addr")?;
    let bound = runner.listen(listen).await;
    for p in &cfg.peers {
        let pid: PeerId = p
            .peer_id
            .parse()
            .with_context(|| format!("peer {} id", p.index))?;
        let a: Multiaddr = p
            .multiaddr
            .parse()
            .with_context(|| format!("peer {} multiaddr", p.index))?;
        runner.add_peer(p.index, pid, a);
    }

    // JSON-RPC edge: reads bind to the shared store + anchor; submits feed the
    // node's input channel (the same path a p2p-received tx takes).
    let submit_input = runner.input_sender();
    let backend: Arc<dyn RpcBackend> = Arc::new(Store2Backend::new(
        rpc_store,
        anchor,
        move |tx: Transaction| {
            let hash = solidus_exec::wire::tx_hash(&tx, WireMode::BinaryV2);
            submit_input
                .send(NodeInput::SubmitTx(tx))
                .map_err(|e| format!("node input closed: {e}"))?;
            Ok(hash)
        },
    ));
    let rpc_addr = cfg.rpc_addr.parse().context("rpc_addr")?;
    let (rpc_bound, rpc_handle) = serve(rpc_addr, backend).await.context("bind rpc")?;

    // Gated boot: enter consensus only once a BFT quorum of peers is reachable
    // (else the first proposal gossips into an empty mesh and is lost).
    let f = (n - 1) / 3;
    let min_peers = (n - f).saturating_sub(1); // quorum − 1 (self counts toward the quorum)
    println!(
        "solidus-noded: validator {} · chain {} '{}' · {n} validators (f={f}) · \
         libp2p {bound} · JSON-RPC http://{rpc_bound} · booting at ≥{min_peers} connected peers",
        cfg.index, cfg.chain_id, cfg.network
    );

    let handle = tokio::spawn(runner.run(min_peers));

    // Run until interrupted; keep the RPC server handle alive for the duration.
    tokio::signal::ctrl_c().await.ok();
    println!("solidus-noded: shutdown signal — stopping");
    rpc_handle.stop().ok();
    handle.abort();
    Ok(())
}

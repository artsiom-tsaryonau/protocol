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

use solidus_crypto::bls::{BlsPublicKey, BlsSecretKey, BlsSignature};
use solidus_crypto::keys::Address;
use solidus_exec::{Account, AccountType, StateKey, WireMode};
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeInput, NodeTuning};
use solidus_p2p2::{build_swarm_with_keypair, P2pRunner};
use solidus_rpc2::{serve, RpcBackend, Store2Backend};
use solidus_store2::{Profile, Store2};
use solidus_txns::types::Transaction;

use crate::config::{DaemonConfig, ValidatorEntry};

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
    let (committee, pubkeys) = committee_from_entries(&vals)?;
    let n = pubkeys.len();

    // The committee as the RPC edge serves it (solidus_getCommittee). Built here,
    // before `committee` and `pubkeys` move into the node, from the keys
    // `committee_from_entries` already parsed and validated.
    let committee_info = solidus_rpc2::backend::CommitteeInfo {
        chain_id: cfg.chain_id,
        quorum: committee.quorum(),
        pop_activation_view: solidus_hotstuff2::params::POP_ACTIVATION_VIEW,
        validators: vals
            .iter()
            .zip(&pubkeys)
            .map(|(v, pk)| {
                let pop = v
                    .bls_pop_hex
                    .as_deref()
                    .and_then(|h| hex_n::<96>(h, "validator bls pop").ok());
                let attestation = v.attestation_address.as_deref().and_then(|h| {
                    hex_n::<20>(h.trim_start_matches("0x"), "attestation_address").ok()
                });
                (v.index, pk.to_bytes(), pop, attestation)
            })
            .collect(),
    };

    // Addresses for the RPC edge's validator list.
    //
    // ⛔ A v2 VALIDATOR HAS NO ADDRESS ANYWHERE. The config gives it a BLS
    // pubkey and an index; the `[[genesis]]` allocations are separate funded
    // dev accounts (see `gen.rs`). Nothing seeds the Validators state space, so
    // `solidus_getValidators` returned `[]` on a chain producing a block every
    // ~116ms, and the explorer honestly showed "ACTIVE VALIDATORS 0".
    //
    // ⚠ THE DERIVATION IS NOT INVENTED. `Address::from_public_key` is
    // `hash160(pubkey_bytes)`, so applying `hash160` to the BLS pubkey is the
    // same rule over a different key, and it is deterministic and identical on
    // every node because the committee is ordered by index.
    //
    // ⚠ These are IDENTIFIERS FOR DISPLAY, not staking accounts. Nothing pays
    // to them and nothing signs from them. If on-chain staking later assigns
    // validators real addresses, those rows win: `validators()` unions on-chain
    // first and dedupes, so a real record supersedes the derived entry.
    let committee_addrs: Vec<solidus_crypto::keys::Address> = pubkeys
        .iter()
        .map(|pk| {
            solidus_crypto::keys::Address::from_bytes(solidus_crypto::hash::hash160(
                pk.to_bytes().as_ref(),
            ))
        })
        .collect();

    // This node's secret identities.
    let bls_secret = BlsSecretKey::from_bytes(&hex_n::<32>(&cfg.bls_secret_hex, "bls secret")?)
        .map_err(|e| anyhow!("bad bls secret: {e:?}"))?;
    let p2p_keypair =
        P2pKeypair::ed25519_from_bytes(hex_n::<32>(&cfg.p2p_secret_hex, "p2p secret")?)
            .map_err(|e| anyhow!("bad p2p secret: {e}"))?;

    // Store + genesis seeding.
    std::fs::create_dir_all(&cfg.data_dir).ok();
    let store = Store2::open(Path::new(&cfg.data_dir), Profile::Testnet)
        .map_err(|e| anyhow!("open store at {}: {e:?}", cfg.data_dir))?;

    // ⛔ SEED GENESIS ONLY ON A FRESH CHAIN. The old comment here called
    // re-seeding "idempotent: re-seeding writes the same bytes", and that was
    // true only because the node could never recover its state — every boot
    // started from an empty forest, so re-seeding genesis was the only way any
    // state existed at all. Now that `Node::new` rebuilds the forest from the
    // store, re-seeding on a restart would OVERWRITE LIVE BALANCES with their
    // genesis values. Read the head BEFORE the store moves into the node.
    // ⛔ THIS READ MUST NOT FAIL OPEN, AND IT IS THE MOST DANGEROUS OF THE THREE.
    // An earlier draft wrote `.ok().flatten().is_none()`, so a transient store
    // error meant `is_fresh_chain = true` and the daemon would RE-SEED GENESIS
    // OVER A LIVE CHAIN, resetting every genesis account's balance. A halt is
    // loud; silently rewritten balances are not. This function returns Result,
    // so the error propagates instead of being guessed at.
    let is_fresh_chain = store
        .canon_head()
        .map_err(|e| anyhow!("read canonical head from {}: {e:?}", cfg.data_dir))?
        .is_none();
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(n));
    let tuning = NodeTuning {
        max_certs_per_block: cfg.tuning.max_certs_per_block,
        batch_max_bytes: cfg.tuning.batch_max_bytes,
        batch_max_txs: cfg.tuning.batch_max_txs,
        flush_interval_ms: cfg.tuning.flush_interval_ms,
        block_retention: cfg.tuning.block_retention,
        min_block_interval_ms: cfg.tuning.min_block_interval_ms,
        view_timeout_ms: cfg.tuning.view_timeout_ms,
        idle_heartbeat_ms: cfg.tuning.idle_heartbeat_ms,
        idle_grace_ms: cfg.tuning.idle_grace_ms,
    };
    let mut node = Node::new(
        cfg.index,
        cfg.chain_id,
        bls_secret,
        committee,
        pubkeys,
        // ⚠ The pacemaker and the block interval are ONE decision: `Core::new`
        // asserts the timeout leaves headroom over the interval, so a config that
        // paces without widening the timeout is refused at construction rather
        // than degrading into a chain that times out every view.
        if cfg.tuning.view_timeout_ms > 0 {
            Pacemaker::new(cfg.tuning.view_timeout_ms, cfg.tuning.view_timeout_ms * 8)
        } else {
            Pacemaker::default()
        },
        elector,
        store,
        tuning,
        cfg.network.clone(),
    )
    .map_err(|e| anyhow!("boot node {}: {e}", cfg.index))?;
    if is_fresh_chain {
        for g in &cfg.genesis {
            let addr = Address::from_bytes(hex_n::<20>(&g.address_hex, "genesis address")?);
            let acct = Account::with_balance(addr, g.balance, AccountType::Regular);
            node.seed_account(&StateKey::account(&addr), &acct.to_bytes());
        }
    }

    // Shared handles for the RPC edge — grab BEFORE the node moves into the
    // runner. Store2 methods are all `&self` (RocksDB is internally synced),
    // so the node writes while the RPC reads through the same Arc.
    let rpc_store = node.store();
    let anchor = node.exec_anchor();
    let forest = node.forest_handle();
    let genesis_hash = node.genesis_hash();

    // Bridge attestations. A node without a key is a full validator that does not attest, which is
    // the state of every node until Task 7 deploys one, so this is silent when absent.
    let mut attestation_signer: Option<[u8; 20]> = None;
    if let Some(secret) = cfg.bridge_attestation_secret_hex.as_deref() {
        let attestor = crate::attest::Attestor::from_hex(secret, cfg.chain_id)
            .map_err(|e| anyhow!("bridge_attestation_secret_hex: {e}"))?;
        let address = attestor.address();

        // ⛔ REFUSE ON A MISMATCH RATHER THAN SIGN WITH THE WRONG KEY. Every signature a
        // mis-keyed node produces is well-formed and recovers to an address the mirror does not
        // know, so the messages simply never reach the threshold and nothing says why. The config
        // already declares which address this validator is expected to sign as; checking it here
        // turns a silent stall into a failed boot.
        if let Some(declared) = cfg
            .validators
            .iter()
            .find(|v| v.index == cfg.index)
            .and_then(|v| v.attestation_address.as_deref())
        {
            // ⚠ `0x` IS THE CONVENTION FOR AN ETHEREUM ADDRESS and every tool that produces one
            // writes it, so refusing the prefix rejects the correct value. The BLS fields above are
            // bare hex, which is why this is stripped here and not in `hex_n`.
            let want = hex_n::<20>(declared.trim_start_matches("0x"), "attestation_address")?;
            if want != address {
                return Err(anyhow!(
                    "attestation key does not match this validator's declared \
                     attestation_address: key is 0x{}, config says 0x{}",
                    hex::encode(address),
                    hex::encode(want)
                ));
            }
        }

        println!(
            "solidus-noded: bridge attestations signed as 0x{}",
            hex::encode(address)
        );
        // ⚠ BEFORE THE NODE RUNS. The commit path signs after persisting, so a crash between the
        // two leaves an outbox entry with no signature; this is the only thing that fills it.
        let filled =
            crate::attest::backfill_unsigned(&attestor, &rpc_store, crate::attest::BACKFILL_WINDOW);
        if filled > 0 {
            println!("solidus-noded: re-signed {filled} outbox entr(ies) missing a signature");
        }
        node.set_attestor(Arc::new(attestor));
        attestation_signer = Some(address);
    }

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
    // Block reader for the RPC edge. Supplied as a closure for the same reason
    // `submit` is: decoding a `Block2` needs consensus types, and `solidus-rpc2`
    // deliberately does not depend on `solidus-hotstuff2` so the RPC edge stays
    // independent of consensus.
    //
    // ⚠ tx_count IS DERIVED FROM THE BATCH BODIES, not read off the block. A v2
    // block carries `batch_certs` - the body by digest - so the count only
    // exists if this node persisted those bodies. A body it does not hold is
    // skipped, which makes the count a LOWER BOUND on a pruned node rather than
    // a wrong number presented as exact.
    let chain_id = cfg.chain_id;
    let block_store = Arc::clone(&rpc_store);
    let read_block = move |height: u64| -> Option<solidus_rpc2::RpcBlock> {
        let hash = block_store.canon_hash(height).ok().flatten()?;
        let bytes = block_store.block_by_hash(&hash).ok().flatten()?;
        if bytes.is_empty() {
            return None; // stored before block bytes were persisted
        }
        let block: solidus_hotstuff2::Block2 = bincode::deserialize(&bytes).ok()?;
        let mut tx_count = 0usize;
        // Collected in the same pass that counts them: the bodies are already
        // deserialized here, and a consumer holding only a v2 block has no other
        // way to learn what is in it.
        let mut transactions: Vec<String> = Vec::new();
        for cert in &block.header.batch_certs {
            if let Ok(Some(body)) = block_store.batch_by_digest(&cert.digest.0) {
                if let Ok(batch) = bincode::deserialize::<solidus_mempool_dag::Batch>(&body) {
                    tx_count += batch.transactions.len();
                    for tx in &batch.transactions {
                        transactions.push(hex::encode(solidus_exec::wire::tx_hash(
                            tx,
                            solidus_exec::wire::wire_for_height(
                                solidus_exec::WireMode::BinaryV2,
                                chain_id,
                                height,
                            ),
                        )));
                    }
                }
            }
        }
        Some(solidus_rpc2::RpcBlock {
            height: block.header.height,
            view: block.header.view,
            hash: hex::encode(hash),
            parent_hash: hex::encode(block.header.parent),
            exec_height: block.header.exec_height,
            exec_state_root: hex::encode(block.header.exec_state_root),
            timestamp_ms: block.header.timestamp_ms,
            proposer: block.header.proposer,
            tx_count,
            transactions,
        })
    };

    // Transaction lookup by hash. Index gives the height; the body lives in the
    // block's batches, so this walks block -> digests -> bodies and matches on
    // the v2 tx hash.
    //
    // ⚠ Only possible because batches are persisted. Before that, a committed
    // transaction's body was unrecoverable after a restart.
    let tx_store = Arc::clone(&rpc_store);
    let read_tx = move |wanted: &[u8; 32]| -> Option<solidus_txns::types::Transaction> {
        let height = tx_store.tx_height(wanted).ok().flatten()?;
        let mode = solidus_exec::wire::wire_for_height(WireMode::BinaryV2, chain_id, height);
        let block_hash = tx_store.canon_hash(height).ok().flatten()?;
        let block_bytes = tx_store.block_by_hash(&block_hash).ok().flatten()?;
        let block: solidus_hotstuff2::Block2 = bincode::deserialize(&block_bytes).ok()?;
        for cert in &block.header.batch_certs {
            let Ok(Some(body)) = tx_store.batch_by_digest(&cert.digest.0) else {
                continue;
            };
            let Ok(batch) = bincode::deserialize::<solidus_mempool_dag::Batch>(&body) else {
                continue;
            };
            for tx in batch.transactions {
                if &solidus_exec::wire::tx_hash(&tx, mode) == wanted {
                    return Some(tx);
                }
            }
        }
        None
    };

    let submit_anchor = Arc::clone(&anchor);
    let prove_forest = Arc::clone(&forest);
    let prove_anchor = Arc::clone(&anchor);
    let sources = solidus_rpc2::backend::BridgeSources {
        prove: Box::new(move |tree, key| {
            solidus_node2::bridge_evidence::prove(&prove_forest, &prove_anchor, tree, key)
        }),
        finality_evidence: {
            let store = Arc::clone(&rpc_store);
            Box::new(move |at| {
                solidus_node2::bridge_evidence::finality_evidence_at_or_above(&store, at, 256)
            })
        },
        committee: committee_info,
    };
    // ⚠ WITHOUT THIS THE METHOD LIES BY OMISSION. `solidus_getBridgeAttestation` reports the
    // signer so a gateway knows whose signature it holds; a node that signs but reports `null`
    // looks like a node that does not attest.
    let mut store_backend = Store2Backend::new(
        rpc_store,
        anchor,
        cfg.network.clone(),
        genesis_hash,
        cfg.chain_id,
        committee_addrs,
        read_block,
        read_tx,
        move |tx: Transaction| {
            // The hash of the wire the next block verifies. Around the activation
            // height a transaction can still land one block later than this; the
            // V3 hash does not depend on the height, so it only differs at the boundary.
            let next = submit_anchor
                .lock()
                .map(|a| a.0)
                .unwrap_or(0)
                .saturating_add(1);
            let hash = solidus_exec::wire::tx_hash(
                &tx,
                solidus_exec::wire::wire_for_height(WireMode::BinaryV2, chain_id, next),
            );
            submit_input
                .send(NodeInput::SubmitTx(tx))
                .map_err(|e| format!("node input closed: {e}"))?;
            Ok(hash)
        },
    )
    .with_bridge_sources(sources);
    if let Some(signer) = attestation_signer {
        store_backend = store_backend.with_attestation_signer(signer);
    }
    let backend: Arc<dyn RpcBackend> = Arc::new(store_backend);
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

/// Build the committee. All entries have PoPs → PoP-admitted committee.
/// None have PoPs → legacy committee, allowed only while the PoP suite is unscheduled.
///
/// ⛔ A PARTIAL SET IS REFUSED. Some entries with a proof and some without is a
/// misconfiguration, and silently falling back to the legacy committee would
/// hide it until the PoP view is scheduled and those validators cannot vote.
pub(crate) fn committee_from_entries(
    vals: &[ValidatorEntry],
) -> Result<(Committee, Vec<BlsPublicKey>)> {
    let pubkeys: Vec<BlsPublicKey> = vals
        .iter()
        .map(|v| {
            let b = hex_n::<48>(&v.bls_pubkey_hex, "validator bls pubkey")?;
            BlsPublicKey::from_bytes(&b).map_err(|e| anyhow!("bad bls pubkey: {e:?}"))
        })
        .collect::<Result<_>>()?;
    if pubkeys.is_empty() {
        return Err(anyhow!("no validators in config"));
    }
    let with_pop = vals.iter().filter(|v| v.bls_pop_hex.is_some()).count();
    if with_pop == 0 {
        if solidus_hotstuff2::params::POP_ACTIVATION_VIEW != u64::MAX {
            return Err(anyhow!(
                "the PoP ciphersuite is scheduled but no validator entry carries bls_pop_hex"
            ));
        }
        return Ok((Committee::new(pubkeys.clone()), pubkeys));
    }
    if with_pop != vals.len() {
        return Err(anyhow!(
            "{with_pop} of {} validator entries carry bls_pop_hex; all or none",
            vals.len()
        ));
    }
    let pops = vals
        .iter()
        .map(|v| {
            let b = hex_n::<96>(
                v.bls_pop_hex.as_deref().unwrap_or_default(),
                "validator bls pop",
            )?;
            BlsSignature::from_bytes(&b).map_err(|e| anyhow!("bad bls pop: {e:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let committee = Committee::new_with_pops(pubkeys.clone(), pops)
        .map_err(|e| anyhow!("committee refused: {e}"))?;
    Ok((committee, pubkeys))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committee_from_entries_requires_every_pop_once_any_is_present() {
        let k = solidus_crypto::bls::BlsSecretKey::from_bytes(&[3u8; 32])
            .unwrap_or_else(|_| solidus_crypto::bls::BlsSecretKey::generate());
        let good = crate::config::ValidatorEntry {
            index: 0,
            bls_pubkey_hex: k.public_key().to_hex(),
            bls_pop_hex: Some(k.prove_possession().to_hex()),
            attestation_address: None,
        };
        let missing = crate::config::ValidatorEntry {
            index: 1,
            bls_pubkey_hex: solidus_crypto::bls::BlsSecretKey::generate()
                .public_key()
                .to_hex(),
            bls_pop_hex: None,
            attestation_address: None,
        };
        assert!(committee_from_entries(std::slice::from_ref(&good)).is_ok());
        assert!(
            committee_from_entries(&[good, missing]).is_err(),
            "a partial set of pops is a misconfiguration"
        );
    }

    /// ⛔ THE PREMISE OF THIS TEST INVERTED ON 2026-09-22, when the PoP view was
    /// scheduled (`POP_ACTIVATION_VIEW`). Until then a config with no `bls_pop_hex`
    /// built the legacy committee, and this test asserted that, so the rollout could
    /// not brick a validator running an old config. With a scheduled view that shape
    /// is a MISCONFIGURATION: the validator would vote under the Basic suite while
    /// its peers switch at the view, so `committee_from_entries` refuses it.
    ///
    /// ⚠ WHAT THIS MEANS FOR THE ROLLOUT, and it is the whole point of the refusal:
    /// a validator started on this binary with a PoP-less config DOES NOT BOOT. Add
    /// the proofs to every config (plan 02 Task 20 Step 8) BEFORE restarting any
    /// validator (Step 9). A node that refuses to start is loud; one that votes on
    /// the wrong ciphersuite is a silent, slashable fork.
    ///
    /// The parse half still holds and is still asserted: serde reads a missing
    /// `Option` as `None`, so an old config file is readable; it is the committee
    /// that now says no.
    #[test]
    fn a_config_without_pops_is_refused_once_the_pop_view_is_scheduled() {
        let pk = solidus_crypto::bls::BlsSecretKey::generate()
            .public_key()
            .to_hex();
        let entry: crate::config::ValidatorEntry =
            toml::from_str(&format!("index = 0\nbls_pubkey_hex = \"{pk}\"\n"))
                .expect("old shape parses");
        assert!(
            entry.bls_pop_hex.is_none(),
            "an absent field must read as None, not an error"
        );

        let err = match committee_from_entries(&[entry]) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a PoP-less config must be refused while the PoP view is scheduled"),
        };
        assert!(
            err.contains("bls_pop_hex"),
            "the refusal must name the missing field, so an operator knows what to add: {err}"
        );
    }
}

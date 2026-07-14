//! Local-devnet config generator: writes `node0.toml … node{N-1}.toml` (a
//! shared committee + genesis, distinct keys/ports per node) plus a
//! `genesis-keys.txt` listing the funded dev accounts' secrets so you can
//! actually spend. This is a DEV convenience — production configs carry the
//! founder's real chain-id, genesis, and validator set, not generated ones.

use anyhow::{anyhow, Result};
use libp2p::identity::Keypair as P2pKeypair;
use rand::RngCore;

use solidus_crypto::bls::BlsSecretKey;
use solidus_crypto::ed25519::generate_signing_key;
use solidus_crypto::keys::Address;

use crate::config::{DaemonConfig, GenesisAlloc, PeerEntry, TuningCfg, ValidatorEntry};

const BASE_P2P_PORT: usize = 7000;
const BASE_RPC_PORT: usize = 8545;
const DEV_ACCOUNTS: usize = 5;
const DEV_BALANCE: u64 = 1_000_000_000;

pub fn generate(dir: &str, n: usize, chain_id: u64) -> Result<()> {
    if n < 4 {
        return Err(anyhow!(
            "n must be ≥ 4 (BFT minimum; a smaller committee has no fault tolerance and a \
             1-validator committee self-recurses the consensus core)"
        ));
    }
    std::fs::create_dir_all(dir)?;

    // Per-node consensus (BLS) + transport (libp2p) identities.
    let bls: Vec<BlsSecretKey> = (0..n).map(|_| BlsSecretKey::generate()).collect();
    let mut p2p_seeds: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut peer_ids: Vec<String> = Vec::with_capacity(n);
    for _ in 0..n {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let kp = P2pKeypair::ed25519_from_bytes(seed).map_err(|e| anyhow!("gen p2p key: {e}"))?;
        peer_ids.push(kp.public().to_peer_id().to_string());
        p2p_seeds.push(seed);
    }
    let listen_addrs: Vec<String> = (0..n)
        .map(|i| format!("/ip4/127.0.0.1/tcp/{}", BASE_P2P_PORT + i))
        .collect();

    let validators: Vec<ValidatorEntry> = (0..n)
        .map(|i| ValidatorEntry {
            index: i as u32,
            bls_pubkey_hex: hex::encode(bls[i].public_key().to_bytes()),
        })
        .collect();

    // Shared genesis: a handful of funded dev accounts (their secrets are
    // dumped so an operator can spend).
    let dev_keys: Vec<_> = (0..DEV_ACCOUNTS).map(|_| generate_signing_key()).collect();
    let genesis: Vec<GenesisAlloc> = dev_keys
        .iter()
        .map(|k| GenesisAlloc {
            address_hex: hex::encode(Address::from_public_key(&k.verifying_key()).as_bytes()),
            balance: DEV_BALANCE,
        })
        .collect();

    for i in 0..n {
        let peers: Vec<PeerEntry> = (0..n)
            .filter(|&j| j != i)
            .map(|j| PeerEntry {
                index: j as u32,
                peer_id: peer_ids[j].clone(),
                multiaddr: listen_addrs[j].clone(),
            })
            .collect();
        let cfg = DaemonConfig {
            chain_id,
            network: format!("v2-devnet-{chain_id}"),
            index: i as u32,
            data_dir: format!("{dir}/data-node{i}"),
            rpc_addr: format!("127.0.0.1:{}", BASE_RPC_PORT + i),
            listen_addr: listen_addrs[i].clone(),
            bls_secret_hex: hex::encode(bls[i].to_bytes()),
            p2p_secret_hex: hex::encode(p2p_seeds[i]),
            validators: validators.clone(),
            peers,
            genesis: genesis.clone(),
            tuning: TuningCfg::default(),
        };
        std::fs::write(format!("{dir}/node{i}.toml"), toml::to_string_pretty(&cfg)?)?;
    }

    let mut keydump = String::from("# Solidus v2 devnet — funded genesis accounts (DEV ONLY)\n");
    for (i, k) in dev_keys.iter().enumerate() {
        keydump.push_str(&format!(
            "dev-account-{i} address={} secret={}\n",
            hex::encode(Address::from_public_key(&k.verifying_key()).as_bytes()),
            hex::encode(k.to_bytes())
        ));
    }
    std::fs::write(format!("{dir}/genesis-keys.txt"), keydump)?;

    // A ready-to-run faucet config: dev-account-0's key, dripping via node0's
    // RPC. `solidus-noded faucet <dir>/faucet.toml` (devnet convenience — a
    // public deployment writes its own with a founder-chosen funded key).
    std::fs::write(
        format!("{dir}/faucet.toml"),
        format!(
            "rpc_url = \"http://127.0.0.1:{BASE_RPC_PORT}\"\n\
             bind_addr = \"127.0.0.1:8600\"\n\
             secret_hex = \"{}\"\n\
             min_interval_secs = 60\n",
            hex::encode(dev_keys[0].to_bytes())
        ),
    )?;

    println!(
        "generated {n}-validator devnet (chain {chain_id}) in {dir}/:\n  \
         node0.toml … node{}.toml + genesis-keys.txt\n  \
         run each: solidus-noded run {dir}/node<i>.toml   (RPC on 127.0.0.1:{}…{})",
        n - 1,
        BASE_RPC_PORT,
        BASE_RPC_PORT + n - 1
    );
    Ok(())
}

/// Generate one validator's key material — what an operator runs on their
/// own box to join a committee. Secrets stay on their machine; only the
/// PUBLIC lines (bls pubkey, peer id) are sent to the network coordinator
/// for inclusion in the shared committee config.
pub fn keygen() -> Result<()> {
    let bls = BlsSecretKey::generate();
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let seed_hex = hex::encode(seed); // capture BEFORE — ed25519_from_bytes zeroizes its input
    let kp = P2pKeypair::ed25519_from_bytes(seed).map_err(|e| anyhow!("gen p2p key: {e}"))?;
    println!("# secrets — keep on this box, put in YOUR node config only");
    println!("bls_secret_hex = \"{}\"", hex::encode(bls.to_bytes()));
    println!("p2p_secret_hex = \"{seed_hex}\"");
    println!("# public — send these to the network coordinator");
    println!(
        "bls_pubkey_hex = \"{}\"",
        hex::encode(bls.public_key().to_bytes())
    );
    println!("peer_id = \"{}\"", kp.public().to_peer_id());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DaemonConfig;
    use std::collections::HashSet;

    #[test]
    fn gen_produces_a_consistent_devnet() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().unwrap();
        generate(path, 4, 31337).expect("generate");

        assert!(std::path::Path::new(&format!("{path}/genesis-keys.txt")).exists());
        let cfgs: Vec<DaemonConfig> = (0..4)
            .map(|i| {
                let t = std::fs::read_to_string(format!("{path}/node{i}.toml")).expect("read");
                toml::from_str(&t).expect("parse")
            })
            .collect();

        let committee: Vec<&String> = cfgs[0]
            .validators
            .iter()
            .map(|v| &v.bls_pubkey_hex)
            .collect();
        let genesis: Vec<&String> = cfgs[0].genesis.iter().map(|g| &g.address_hex).collect();

        for (i, c) in cfgs.iter().enumerate() {
            assert_eq!(c.index, i as u32, "node index");
            assert_eq!(c.chain_id, 31337);
            assert_eq!(c.validators.len(), 4, "full committee on every node");

            // Committee + genesis are byte-identical (and ordered) across nodes.
            assert_eq!(
                c.validators
                    .iter()
                    .map(|v| &v.bls_pubkey_hex)
                    .collect::<Vec<_>>(),
                committee,
                "shared committee"
            );
            assert_eq!(
                c.genesis.iter().map(|g| &g.address_hex).collect::<Vec<_>>(),
                genesis,
                "shared genesis"
            );

            // Peers reference exactly the OTHER validators.
            let mut peer_idx: Vec<u32> = c.peers.iter().map(|p| p.index).collect();
            peer_idx.sort_unstable();
            let expected: Vec<u32> = (0..4u32).filter(|&j| j != i as u32).collect();
            assert_eq!(peer_idx, expected, "peers = the other validators");

            // Key material is valid hex of the right length.
            assert_eq!(hex::decode(&c.bls_secret_hex).unwrap().len(), 32);
            assert_eq!(hex::decode(&c.p2p_secret_hex).unwrap().len(), 32);
            for v in &c.validators {
                assert_eq!(hex::decode(&v.bls_pubkey_hex).unwrap().len(), 48);
            }
            for g in &c.genesis {
                assert_eq!(hex::decode(&g.address_hex).unwrap().len(), 20);
            }

            // Distinct, predictable ports.
            assert!(c.rpc_addr.ends_with(&(BASE_RPC_PORT + i).to_string()));
            assert!(c.listen_addr.ends_with(&(BASE_P2P_PORT + i).to_string()));
        }

        // Every node has its own distinct secret keys + peer id.
        let bls: HashSet<_> = cfgs.iter().map(|c| &c.bls_secret_hex).collect();
        let p2p: HashSet<_> = cfgs.iter().map(|c| &c.p2p_secret_hex).collect();
        let peer_ids: HashSet<_> = cfgs[0].peers.iter().map(|p| &p.peer_id).collect();
        assert_eq!(bls.len(), 4, "distinct BLS secrets");
        assert_eq!(p2p.len(), 4, "distinct libp2p secrets");
        assert_eq!(peer_ids.len(), 3, "distinct peer ids");
    }

    #[test]
    fn gen_rejects_below_bft_minimum() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().to_str().unwrap();
        assert!(
            generate(path, 3, 1).is_err(),
            "n=3 is below the BFT minimum"
        );
        assert!(generate(path, 1, 1).is_err(), "n=1 self-recurses");
    }
}

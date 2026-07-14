//! C1 acceptance: a bootstrap-only node (C) discovers a peer (B) it was never
//! told about, through another node's (A) Kademlia routing table.
//!
//! Topology: A<->B statically paired (A dials B). C has an EMPTY static peer
//! list and only A as a Kademlia bootstrap. C must reach peer_count == 2 (A +
//! the discovered B). Uses ephemeral ports (/tcp/0) + the listen_addr accessor
//! so re-runs never collide on a fixed port (TIME_WAIT-safe).

use libp2p::Multiaddr;
use solidus_p2p::identity::libp2p_keypair_from_node_seed;
use solidus_p2p::libp2p_transport::{LibP2PConfig, LibP2PTransport, PeerConfig};
use std::time::Duration;

fn ephemeral() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

#[tokio::test]
async fn bootstrap_only_node_discovers_peer_via_dht() {
    let kp_a = libp2p_keypair_from_node_seed(&[20u8; 32]).unwrap();
    let kp_b = libp2p_keypair_from_node_seed(&[21u8; 32]).unwrap();
    let kp_c = libp2p_keypair_from_node_seed(&[22u8; 32]).unwrap();
    let pid_a = kp_a.public().to_peer_id();
    let pid_b = kp_b.public().to_peer_id();

    // Start B first (index 1, passive listener) so we can learn its bound addr.
    let cfg_b = LibP2PConfig {
        listen_addr: ephemeral(),
        peers: vec![],
        node_index: 1,
        keypair: kp_b,
        bootstrap_peers: vec![],
    };
    let t_b = LibP2PTransport::start(cfg_b).await.unwrap();
    let addr_b = t_b
        .listen_addr(Duration::from_secs(5))
        .await
        .expect("B should bind a listen address");

    // A (index 0) statically knows B and dials it (lower index dials higher).
    let cfg_a = LibP2PConfig {
        listen_addr: ephemeral(),
        peers: vec![PeerConfig {
            index: 1,
            peer_id: pid_b.to_base58(),
            address: addr_b.to_string(),
        }],
        node_index: 0,
        keypair: kp_a,
        bootstrap_peers: vec![],
    };
    let t_a = LibP2PTransport::start(cfg_a).await.unwrap();
    let addr_a = t_a
        .listen_addr(Duration::from_secs(5))
        .await
        .expect("A should bind a listen address");

    // Wait for the A<->B static mesh, then let Identify populate A's kad table.
    let ab = t_a.wait_for_peers(1, Duration::from_secs(15)).await;
    assert_eq!(ab, 1, "A and B should form the static mesh first");
    tokio::time::sleep(Duration::from_secs(1)).await;

    // C (index 2) knows NOBODY statically; only A as a Kademlia bootstrap.
    let cfg_c = LibP2PConfig {
        listen_addr: ephemeral(),
        peers: vec![],
        node_index: 2,
        keypair: kp_c,
        bootstrap_peers: vec![(pid_a, addr_a)],
    };
    let t_c = LibP2PTransport::start(cfg_c).await.unwrap();

    // C dials bootstrap A, runs a DHT bootstrap query, learns B from A's
    // routing table, dials B -> peer_count 2. The whole point: C reached B
    // WITHOUT B ever being in C's config.
    let discovered = t_c.wait_for_peers(2, Duration::from_secs(30)).await;
    assert_eq!(
        discovered, 2,
        "C should discover B through A's DHT (reached {discovered} peers)"
    );

    // t_b is the discovery target — keep it alive until the assertion above.
    drop(t_b);
}

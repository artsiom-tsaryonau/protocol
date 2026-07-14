//! C2 acceptance: a full node (F) with NO validator index can round-trip a sync
//! request to a discovered peer by its libp2p `PeerId`.
//!
//! Topology: A<->B statically paired (A dials B). F has an EMPTY static peer list
//! and only B as a Kademlia bootstrap; F discovers A through B's routing table.
//! F then `send_to_peer_id(a_peer_id, GetTip)` — A has no `peer_map` entry for F
//! (F is index-less), so A must capture F's source `PeerId` via `recv_with_source`
//! and reply with `send_to_peer_id(source, Tip { .. })`. F receives the `Tip`.
//!
//! This proves the index-free send/recv round trip the validator `peer_map`/index
//! path cannot do. Ephemeral ports (/tcp/0) so re-runs never collide.

use libp2p::Multiaddr;
use solidus_p2p::identity::libp2p_keypair_from_node_seed;
use solidus_p2p::libp2p_transport::{LibP2PConfig, LibP2PTransport, PeerConfig};
use solidus_p2p::message::ConsensusMessage;
use solidus_p2p::transport::{ConsensusTransport, SourcePeer};
use std::time::Duration;

fn ephemeral() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/0".parse().unwrap()
}

#[tokio::test]
async fn full_node_round_trips_get_tip_by_peer_id() {
    // Distinct seeds from the C1 discovery test (20/21/22) to avoid any chance
    // of a stray cross-test PeerId clash.
    let kp_a = libp2p_keypair_from_node_seed(&[30u8; 32]).unwrap();
    let kp_b = libp2p_keypair_from_node_seed(&[31u8; 32]).unwrap();
    let kp_f = libp2p_keypair_from_node_seed(&[32u8; 32]).unwrap();
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
    let mut t_a = LibP2PTransport::start(cfg_a).await.unwrap();

    // Wait for the A<->B static mesh, then let Identify populate B's kad table.
    let ab = t_a.wait_for_peers(1, Duration::from_secs(15)).await;
    assert_eq!(ab, 1, "A and B should form the static mesh first");
    tokio::time::sleep(Duration::from_secs(1)).await;

    // F (full node) knows NOBODY statically; only B as a Kademlia bootstrap.
    // It discovers A through B's DHT (same path C1 proved), then sends GetTip to
    // A directly by PeerId.
    let cfg_f = LibP2PConfig {
        listen_addr: ephemeral(),
        peers: vec![],
        node_index: usize::MAX, // index-less full node sentinel
        keypair: kp_f,
        bootstrap_peers: vec![(pid_b, addr_b)],
    };
    let mut t_f = LibP2PTransport::start(cfg_f).await.unwrap();

    // F should reach >=2 peers (B + the discovered A).
    let discovered = t_f.wait_for_peers(2, Duration::from_secs(30)).await;
    assert!(
        discovered >= 2,
        "F should discover A through B's DHT (reached {discovered} peers)"
    );

    // A serves GetTip by replying to whatever source asked. Drive A's recv in the
    // background so it answers F's index-less request.
    let a_server = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            match tokio::time::timeout(remaining, t_a.recv_with_source()).await {
                Ok(Ok((from, source, ConsensusMessage::GetTip))) => {
                    let reply = ConsensusMessage::Tip { hash: [7u8; 32] };
                    if from == usize::MAX {
                        // Index-less requester: reply by captured source PeerId.
                        let src = source.expect("request arm must carry a source peer");
                        let _ = t_a.send_to_peer_id(src, reply).await;
                    } else {
                        let _ = t_a.send(from, reply).await;
                    }
                    return;
                }
                Ok(Ok(_)) => continue,
                _ => return,
            }
        }
    });

    // F sends GetTip to A by PeerId, retrying a few times until A answers (the
    // request-response substream may not be ready the instant the dial lands).
    let mut got_tip: Option<[u8; 32]> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline && got_tip.is_none() {
        let _ = t_f
            .send_to_peer_id(SourcePeer(pid_a), ConsensusMessage::GetTip)
            .await;
        match tokio::time::timeout(Duration::from_secs(2), t_f.recv()).await {
            Ok(Ok((_, ConsensusMessage::Tip { hash }))) => got_tip = Some(hash),
            _ => continue,
        }
    }

    let _ = a_server.await;
    drop(t_b);

    assert_eq!(
        got_tip,
        Some([7u8; 32]),
        "F should receive A's Tip via the PeerId-addressed round trip"
    );
}

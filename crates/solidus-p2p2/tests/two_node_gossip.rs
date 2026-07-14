//! Two real libp2p swarms over TCP loopback: node A publishes a
//! `NetMessage` on the Proposals topic, node B receives + decodes it
//! byte-identically. This proves the gossipsub wire actually delivers —
//! the one part of p2p2 that needs real sockets to verify (a full
//! N-validator consensus run is multi-process; the node2 localnet harness
//! stands in for that).

use std::time::Duration;

use futures::StreamExt;
use libp2p::{gossipsub, Multiaddr};
use solidus_hotstuff2::QuorumCert;
use solidus_p2p2::behaviour::{build_swarm, publish, SolidusBehaviourEvent};
use solidus_p2p2::{NetMessage, Topic};

const CHAIN_ID: u64 = 2;

fn sample_message() -> NetMessage {
    let sk = solidus_crypto::bls::BlsSecretKey::generate();
    // A QC is a compact, fully-serializable broadcast message.
    NetMessage::Qc(QuorumCert::genesis([0x5A; 32], sk.sign(b"genesis")))
}

#[tokio::test]
async fn gossip_delivers_a_netmessage_between_two_swarms() {
    let mut a = build_swarm(CHAIN_ID).expect("swarm a");
    let mut b = build_swarm(CHAIN_ID).expect("swarm b");

    // B listens on an ephemeral loopback port.
    b.listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
        .expect("listen");
    let b_addr: Multiaddr = loop {
        if let Some(libp2p::swarm::SwarmEvent::NewListenAddr { address, .. }) = b.next().await {
            break address;
        }
    };

    // A dials B and both drive their event loops.
    a.dial(b_addr).expect("dial");

    let message = sample_message();
    let want = message.encode();
    let topic = gossipsub::IdentTopic::new(Topic::Qcs.ident(CHAIN_ID));

    // With only two peers, gossipsub's mesh may stay below mesh_n_low; add
    // each side as an EXPLICIT gossip peer once connected so messages flow
    // regardless of mesh formation, then retry-publish until B receives.
    // Assert the delivered bytes are byte-identical and decode back.
    let a_peer = *a.local_peer_id();
    let b_peer = *b.local_peer_id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut publish_tick = tokio::time::interval(Duration::from_millis(300));
    let received: Vec<u8> = loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "gossip did not deliver in time"
        );

        tokio::select! {
            ev = a.select_next_some() => {
                if let libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } = ev {
                    a.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                }
            }
            ev = b.select_next_some() => {
                match ev {
                    libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        b.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                    libp2p::swarm::SwarmEvent::Behaviour(SolidusBehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) => {
                        assert_eq!(message.topic, topic.hash());
                        break message.data;
                    }
                    _ => {}
                }
            }
            _ = publish_tick.tick() => {
                // Idempotent retries — gossipsub dedups by message id, so
                // repeats are harmless; the first that lands after the mesh
                // is ready delivers.
                a.behaviour_mut().gossipsub.add_explicit_peer(&b_peer);
                b.behaviour_mut().gossipsub.add_explicit_peer(&a_peer);
                let _ = publish(&mut a, CHAIN_ID, Topic::Qcs, want.clone());
            }
        }
    };

    assert_eq!(received, want, "delivered bytes must be byte-identical");
    let decoded = NetMessage::decode(&received).expect("decode");
    assert_eq!(decoded, message, "round-trips to the same NetMessage");
}

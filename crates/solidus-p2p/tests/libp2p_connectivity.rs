//! Two real libp2p transports connect over loopback and exchange a message.
//! Fixed high ports avoid the need for a listen-address accessor; if these
//! ports are ever busy in CI, bump them.

use libp2p::Multiaddr;
use solidus_p2p::identity::libp2p_keypair_from_node_seed;
use solidus_p2p::libp2p_transport::{LibP2PConfig, LibP2PTransport, PeerConfig};
use solidus_p2p::message::ConsensusMessage;
use solidus_p2p::transport::ConsensusTransport;
use std::time::Duration;

fn test_tx() -> solidus_txns::types::Transaction {
    use ed25519_dalek::SigningKey;
    use solidus_crypto::keys::Address;
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let payload = solidus_txns::types::TxPayload::Transfer {
        to: Address::from_bytes([0u8; 20]),
        amount: 100,
    };
    let mut tx = solidus_txns::types::Transaction {
        sender_pubkey: sk.verifying_key().to_bytes(),
        nonce: 0,
        payload,
        signature: [0u8; 64],
    };
    tx.signature = solidus_crypto::ed25519::sign(&sk, &tx.signing_bytes());
    tx
}

#[tokio::test]
async fn two_nodes_connect_and_exchange() {
    let kp0 = libp2p_keypair_from_node_seed(&[10u8; 32]).unwrap();
    let kp1 = libp2p_keypair_from_node_seed(&[11u8; 32]).unwrap();
    let pid0 = kp0.public().to_peer_id().to_base58();
    let pid1 = kp1.public().to_peer_id().to_base58();
    let addr0 = "/ip4/127.0.0.1/tcp/49801";
    let addr1 = "/ip4/127.0.0.1/tcp/49802";

    let cfg0 = LibP2PConfig {
        listen_addr: addr0.parse::<Multiaddr>().unwrap(),
        peers: vec![PeerConfig {
            index: 1,
            peer_id: pid1,
            address: addr1.to_string(),
        }],
        node_index: 0,
        keypair: kp0,
        bootstrap_peers: vec![],
    };
    let cfg1 = LibP2PConfig {
        listen_addr: addr1.parse::<Multiaddr>().unwrap(),
        peers: vec![PeerConfig {
            index: 0,
            peer_id: pid0,
            address: addr0.to_string(),
        }],
        node_index: 1,
        keypair: kp1,
        bootstrap_peers: vec![],
    };

    let t0 = LibP2PTransport::start(cfg0).await.unwrap();
    let mut t1 = LibP2PTransport::start(cfg1).await.unwrap();

    let connected = t0.wait_for_peers(1, Duration::from_secs(10)).await;
    assert_eq!(connected, 1, "node 0 should connect to node 1");

    t0.send(1, ConsensusMessage::NewTransaction(test_tx()))
        .await
        .unwrap();

    let (from, msg) = tokio::time::timeout(Duration::from_secs(5), t1.recv())
        .await
        .expect("recv timed out")
        .expect("recv failed");
    assert_eq!(from, 0, "message should be attributed to node 0");
    assert!(matches!(msg, ConsensusMessage::NewTransaction(_)));
}

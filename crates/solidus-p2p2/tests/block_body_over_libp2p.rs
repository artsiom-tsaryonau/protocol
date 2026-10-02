//! The block-BODY protocol over REAL libp2p sockets, deterministically.
//!
//! A restarted validator can hold a QC whose block it does not have. Until it
//! resolves that body it can neither propose nor vote, so it contributes
//! nothing — this is the fetch that unwedges it, and in production it runs over
//! the request/response transport, not the in-process channels the node2
//! localnet harness uses.
//!
//! **Why this one is NOT `#[ignore]` while `four_node_libp2p` is:** that test
//! depends on gossipsub MESH formation, which is probabilistic when four full
//! swarms share one process. The body protocol is point-to-point by
//! construction — a request/response stream over a dialled connection — so it
//! needs no mesh and is deterministic here.
//!
//! Two properties, in the order that makes each one mean something:
//!
//! 1. **A miss is silence.** An unknown hash draws no reply at all, rather than
//!    an empty frame the requester would have to distinguish from an answer.
//! 2. **A hit returns the stored bytes.** Byte-identical, over the wire.
//!
//! ⚠ THE ORDER IS THE POINT. Absence proves nothing on a connection that might
//! simply be dead, so the negative is asserted FIRST and the positive that
//! follows on the SAME connection is what proves the server was listening
//! throughout. Reversed, the negative would be worthless.

use std::time::Duration;

use futures::StreamExt;
use libp2p::request_response;
use libp2p::{Multiaddr, PeerId};
use solidus_crypto::bls::BlsSecretKey;
use solidus_hotstuff2::{Committee, LeaderElector, Pacemaker, RoundRobin};
use solidus_node2::{Node, NodeTuning};
use solidus_p2p2::behaviour::{send_direct_to_peer, SolidusBehaviourEvent};
use solidus_p2p2::{build_swarm, NetMessage, P2pRunner};
use solidus_store2::{Profile, Store2};

const CHAIN_ID: u64 = 2;
const NETWORK: &str = "v2-body-fetch";
const N: usize = 4;

/// Longer than `RANGE_REQUEST_MIN_INTERVAL` (250ms), which the body path shares.
///
/// ⚠ WITHOUT THIS THE NEGATIVE ASSERTION IS VACUOUS: back-to-back requests from
/// one peer are dropped by the rate limiter, so a second request would draw
/// silence whether or not the block was in the store.
const PAST_RATE_LIMIT: Duration = Duration::from_millis(600);

/// Wait for a `BlockBody` frame addressed to us, or return `None` on timeout.
///
/// The server answers with its OWN request (that is what `send_direct_to_peer`
/// does), so the reply arrives here as an inbound request, not as a response.
async fn await_body(
    swarm: &mut libp2p::Swarm<solidus_p2p2::SolidusBehaviour>,
    within: Duration,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let ev = match tokio::time::timeout(remaining, swarm.select_next_some()).await {
            Ok(ev) => ev,
            Err(_) => return None,
        };
        if let libp2p::swarm::SwarmEvent::Behaviour(SolidusBehaviourEvent::Direct(
            request_response::Event::Message {
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            },
        )) = ev
        {
            let _ = swarm
                .behaviour_mut()
                .direct
                .send_response(channel, Vec::new());
            if let Ok(NetMessage::BlockBody { bytes }) = NetMessage::decode(&request) {
                return Some(bytes);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_serves_one_block_body_by_hash_over_real_sockets() {
    // The server's store holds ONE block, addressed by hash. put_pending_block
    // is deliberate: a locked block need never have been committed, so it has
    // no height to ask for and no canon entry to find it by.
    let dir = tempfile::tempdir().expect("tempdir");
    // Owned rather than `keep()`ed: see four_node_libp2p. The handle lives to
    // the end of the test, which outlives every use of the store.
    let store = Store2::open(dir.path(), Profile::Testnet).expect("store");
    let held_hash = [0xABu8; 32];
    let held_bytes = b"the locked block body, verbatim".to_vec();
    store
        .put_pending_block(&held_hash, &held_bytes)
        .expect("stage the block");

    let bls: Vec<BlsSecretKey> = (0..N).map(|_| BlsSecretKey::generate()).collect();
    let committee = Committee::new(bls.iter().map(|k| k.public_key()).collect());
    let elector: Box<dyn LeaderElector> = Box::new(RoundRobin::new(N));
    let node = Node::new(
        0,
        CHAIN_ID,
        BlsSecretKey::from_bytes(&bls[0].to_bytes()).unwrap(),
        committee,
        bls.iter().map(|k| k.public_key()).collect(),
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

    // Precondition, not decoration: without it a red positive assertion is
    // ambiguous between "the store lost it" and "the wire lost it", and those
    // are different bugs in different crates.
    assert_eq!(
        node.store().block_by_hash(&held_hash).expect("store read"),
        Some(held_bytes.clone()),
        "the server must actually hold the block before we ask it for one"
    );

    let server_swarm = build_swarm(CHAIN_ID).expect("server swarm");
    let mut server = P2pRunner::new(0, CHAIN_ID, node, server_swarm);
    let server_peer: PeerId = server.local_peer_id();
    let server_addr: Multiaddr = server.listen("/ip4/127.0.0.1/tcp/0".parse().unwrap()).await;

    // expected_peers = 2 keeps consensus DORMANT: `run` only calls start() once
    // that many peers connect. Serving is handled by the swarm event loop
    // regardless, so this isolates the transport from consensus noise.
    tokio::spawn(server.run(2));

    let mut client = build_swarm(CHAIN_ID).expect("client swarm");
    client.dial(server_addr).expect("dial");
    let connected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let libp2p::swarm::SwarmEvent::ConnectionEstablished { peer_id, .. } =
                client.select_next_some().await
            {
                break peer_id;
            }
        }
    })
    .await
    .expect("the client connects to the server");
    assert_eq!(connected, server_peer, "connected to the node under test");

    // 1. A hash the server does not have draws NO frame.
    let absent = [0x11u8; 32];
    send_direct_to_peer(
        &mut client,
        server_peer,
        NetMessage::GetBlockBody { hash: absent }.encode(),
    );
    assert!(
        await_body(&mut client, Duration::from_secs(2))
            .await
            .is_none(),
        "a miss must be silence: an empty body frame is indistinguishable \
         from an answer, and the requester would have to guess"
    );

    tokio::time::sleep(PAST_RATE_LIMIT).await;

    // 2. The hash it does have comes back byte-identical — on this same
    //    connection, which is what makes step 1 evidence rather than noise.
    send_direct_to_peer(
        &mut client,
        server_peer,
        NetMessage::GetBlockBody { hash: held_hash }.encode(),
    );
    let got = await_body(&mut client, Duration::from_secs(10))
        .await
        .expect("the server serves the body it holds");
    assert_eq!(got, held_bytes, "the body must survive the wire verbatim");
}

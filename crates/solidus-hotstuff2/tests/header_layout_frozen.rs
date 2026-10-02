//! The `BlockHeader2` wire layout is FROZEN, and this is what enforces it.
//!
//! ⛔ WHY THIS EXISTS, AND WHY IT IS THE FIRST THING BUILT FOR UPGRADABILITY.
//! The obvious way to make a chain upgradable is to put a protocol version in
//! the block header. On this chain that would DESTROY it, and the reason is not
//! obvious until you look at how a header is addressed:
//!
//!     BlockHeader2::hash() = blake3(bincode::serialize(self))
//!
//! bincode is POSITIONAL: no field names, no tags, no schema evolution. Adding a
//! field, removing one, reordering two, or widening a type all change the bytes
//! of EVERY header. That changes every header hash. Every block names its parent
//! BY HASH, so every parent link breaks at once, and stored blocks stop decoding
//! because old bytes no longer match the struct.
//!
//! The chain this protects held ~971k blocks and served `rpc.solidus.network`
//! when this was written.
//!
//! ⚠ SO THE VERSION DOES NOT GO IN THE BLOCK. It is derived from the HEIGHT, via
//! an activation table compiled into the binary. That is how Ethereum and
//! Bitcoin schedule forks, and it needs no wire change at all. This test is the
//! guard rail that keeps the next person from taking the tempting route.
//!
//! ⚠ IF YOU ARE HERE BECAUSE THIS TEST FAILED: you changed the consensus wire
//! format. That is a hard fork of a live chain, not a refactor. Nothing about
//! this test needs updating until that is a deliberate, scheduled decision.

use solidus_hotstuff2::BlockHeader2;

/// A header with NO batch certificates, so the bytes depend only on the struct
/// layout and not on certificate encoding. Every value is a fixed constant: a
/// changing input would make a changing hash meaningless as a layout pin.
fn frozen_header() -> BlockHeader2 {
    BlockHeader2 {
        chain_id: 50_002,
        height: 1_000_000,
        view: 1_000_001,
        parent: [0x11; 32],
        batch_certs: vec![],
        exec_height: 999_998,
        exec_state_root: [0x22; 32],
        timestamp_ms: 1_700_000_000_000,
        proposer: 3,
    }
}

/// The exact bincode encoding. Held as hex so a diff shows WHICH bytes moved.
///
/// Layout, field by field, all little-endian fixint:
///   chain_id u64 · height u64 · view u64 · parent [u8;32] raw ·
///   batch_certs Vec len u64 (0 here) · exec_height u64 ·
///   exec_state_root [u8;32] raw · timestamp_ms u64 · proposer
const FROZEN_BINCODE_HEX: &str = concat!(
    "52c3000000000000", // chain_id   50002
    "40420f0000000000", // height     1000000
    "41420f0000000000", // view       1000001
    "1111111111111111111111111111111111111111111111111111111111111111", // parent
    "0000000000000000", // batch_certs len 0
    "3e420f0000000000", // exec_height 999998
    "2222222222222222222222222222222222222222222222222222222222222222", // exec_state_root
    "0068e5cf8b010000", // timestamp_ms 1700000000000
    // ⚠ MEASURED, NOT HAND-COMPUTED. My first draft wrote 0028876b8a010000
    // here from reasoning about little-endian and it was WRONG, which the
    // test caught on its first run. Every other byte was right, so the
    // failure was a clean signal rather than noise.
    "03000000", // proposer 3
);

/// blake3 of the bytes above. This is the value a parent link is made of.
const FROZEN_HASH_HEX: &str = "c1029ebbae2d7ef1ce15c18a2e7f8b389b8101cbbf89ded908ead8b198e4e5c9";

#[test]
fn the_header_bincode_layout_has_not_changed() {
    let bytes = bincode::serialize(&frozen_header()).expect("header serialises");
    let got = hex::encode(&bytes);
    assert_eq!(
        got, FROZEN_BINCODE_HEX,
        "\n\n⛔ THE CONSENSUS HEADER WIRE FORMAT CHANGED.\n\
         Every header hash changes with it, so every parent link in the live chain \n\
         breaks and stored blocks stop decoding. This is a hard fork, not a refactor.\n\
         If a protocol version is what you are adding: it does NOT go here. Derive it \n\
         from the block height via the activation table.\n\n"
    );
}

#[test]
fn the_header_hash_has_not_changed() {
    // Asserted separately from the bytes: a hash change with unchanged bytes
    // would mean the HASHING changed rather than the layout, and the two
    // failures want different fixes.
    let got = hex::encode(frozen_header().hash());
    assert_eq!(
        got, FROZEN_HASH_HEX,
        "\n\n⛔ THE HEADER HASH CHANGED while the bincode bytes did not, so the \n\
         hashing itself moved. Every parent link in the live chain breaks.\n\n"
    );
}

/// ⚠ THE CONTROL. Without this, both assertions above would still pass if
/// `hash()` returned a constant, or if serialisation silently produced the same
/// bytes for different headers. A layout pin that cannot tell two headers apart
/// is pinning nothing.
#[test]
fn control_a_different_header_serialises_and_hashes_differently() {
    let a = frozen_header();
    let mut b = frozen_header();
    b.height += 1;

    assert_ne!(
        bincode::serialize(&a).expect("a"),
        bincode::serialize(&b).expect("b"),
        "serialisation does not distinguish two different headers, so the pins above are vacuous"
    );
    assert_ne!(
        a.hash(),
        b.hash(),
        "hash() does not distinguish two different headers, so the pins above are vacuous"
    );
}

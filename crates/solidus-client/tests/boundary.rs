//! Pins the transitive dependency set of `solidus-client`.
//!
//! WHY A WHITELIST AND NOT A DENYLIST. The obvious version of this test asserts
//! "no rocksdb, no libp2p, no blst". That version passes forever while some
//! other heavy dependency walks in — it only catches the four things whoever
//! wrote it happened to think of. The project rule is `whitelist by
//! construction, never a denylist`, and it applies here exactly as it applies to
//! an API response: enumerate what is allowed, and let anything new fail until
//! someone deliberately admits it.
//!
//! So this test fails on **any** change to the dependency graph, including
//! additions that are perfectly reasonable. That is the intended cost. Adding a
//! line to `ALLOWED` is a two-second edit; noticing six months later that a
//! client library pulls a C toolchain is not.
//!
//! WHAT IT IS PROTECTING. `solidus-client` is extracted from a node workspace
//! that contains RocksDB, libp2p, a consensus engine and a C BLS library. The
//! whole reason the crate exists is that an outsider can depend on the protocol
//! surface without any of it. That claim was a comment in `lib.rs` until this
//! file existed — which is the failure mode this branch was opened to stop.

use std::collections::BTreeSet;
use std::process::Command;

/// Every crate `solidus-client` is allowed to pull with default features.
///
/// Pure Rust throughout: no C, no async runtime, no network stack, no storage
/// engine. If a change here is deliberate, edit the list in the same commit and
/// say why in the message.
const ALLOWED: &[&str] = &[
    "arrayref",
    "arrayvec",
    // Added 2026-09-22 (bridge plan 02 Task 2): solidus-txns hashes bincode(action)
    // in governance_signing_message (registry §2.5). Pure Rust, serde only, no C.
    "bincode",
    "blake3",
    "block-buffer",
    "bs58",
    "cfg-if",
    "constant_time_eq",
    "cpufeatures",
    "crypto-common",
    "curve25519-dalek",
    // Proc-macro used by curve25519-dalek to select its x86_64 backends. Pure Rust, build-time
    // only, and absent on aarch64 — see the --target all note above.
    "curve25519-dalek-derive",
    "digest",
    "ed25519",
    "ed25519-dalek",
    // Formally-verified field arithmetic, used by curve25519-dalek on targets
    // without a 64-bit backend. Pure Rust, no C.
    "fiat-crypto",
    "generic-array",
    "getrandom",
    "hex",
    "hkdf",
    "hmac",
    "itoa",
    "libc",
    "memchr",
    "pbkdf2",
    "ppv-lite86",
    "proc-macro2",
    "quote",
    "rand",
    "rand_chacha",
    "rand_core",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "sha2",
    "signature",
    "solidus-client",
    "solidus-crypto",
    "solidus-txns",
    "subtle",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    // Raw wasi syscall bindings, reached only on wasm32-wasi. Pure Rust, and this
    // crate already builds for wasm32-unknown-unknown by design.
    "wasi",
    "zerocopy",
    // Proc-macro half of zerocopy, which is already allowed. Build-time only.
    "zerocopy-derive",
    "zeroize",
    "zmij",
];

#[test]
fn dependency_boundary() {
    let output = Command::new(env!("CARGO"))
        .args([
            "tree",
            "-p",
            "solidus-client",
            "-e",
            "normal",
            "--prefix",
            "none",
            // ⚠ ALL TARGETS, NOT THE HOST. Without this the answer depends on the machine
            // running the test, and it silently did: `curve25519-dalek` pulls
            // `curve25519-dalek-derive` for its x86_64 backends and not on aarch64, so this
            // test passed on the author's ARM Mac and failed on CI's x86_64 Linux. Nobody saw
            // it for 25 days because GitHub Actions was refusing to dispatch jobs.
            //
            // The union across targets is also STRICTLY STRONGER than the host graph, which is
            // the real argument for it: a heavy dependency that appears only on Linux is
            // exactly the thing this whitelist exists to catch, and the host-only form could
            // not see one. 46 crates on this host, 50 across all targets.
            "--target",
            "all",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree should run; without it this test verifies nothing");

    // An empty or failed run must NOT read as a pass. A check that could not
    // look at anything has not passed — it has not run.
    assert!(
        output.status.success(),
        "cargo tree failed, so the boundary is unverified:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "cargo tree produced no output — unverified, not clean"
    );

    let actual: BTreeSet<&str> = stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| !n.is_empty() && *n != "(*)")
        .collect();

    assert!(
        actual.contains("solidus-client"),
        "cargo tree output did not contain the crate under test — parsing is wrong, \
         and a wrong parser would silently accept anything"
    );

    let allowed: BTreeSet<&str> = ALLOWED.iter().copied().collect();
    let added: Vec<&&str> = actual.difference(&allowed).collect();
    let removed: Vec<&&str> = allowed.difference(&actual).collect();

    assert!(
        added.is_empty() && removed.is_empty(),
        "solidus-client's dependency graph changed.\n\
         \n  added (not in ALLOWED):   {added:?}\
         \n  removed (still listed):   {removed:?}\n\
         \nIf this is deliberate, update ALLOWED in the same commit and say why.\n\
         Before you do: this crate must stay free of C toolchains, async runtimes,\n\
         storage engines and network stacks — that is the reason it was extracted."
    );
}

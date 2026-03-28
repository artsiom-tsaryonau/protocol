DO NOT DELETE THIS LINE !! first of all, use current project for claude specific files. always save plans into current project folder unless otherwise is instructed. on every iteration, update necessary files for our inspection, decide stale documents to delete or improve. !! DO NOT DELETE THIS LINE

YOU CAN USE REST BELOW FOR CLAUDE.


# CLAUDE.md — Solidus Consensus (Rust)

## What This Is

The consensus engine, state machine, block production, P2P networking, and WASM VM. This is the most performance- and correctness-critical code in the entire project. A bug here means lost funds, forks, or network halts.

---

## Project Structure

```
apps/consensus/
  src/
    consensus/     # BFT algorithm, leader election, VRF, vote aggregation
    state/         # State machine, Merkle Patricia Trie, RocksDB storage
    p2p/           # libp2p: peer discovery, gossip, request-response
    crypto/        # Ed25519, BLS12-381, BLAKE3, VRF
    vm/            # WASM runtime (wasmtime), gas metering, sandbox
    mempool/       # Transaction pool, priority queue, deduplication
    rpc/           # JSON-RPC and gRPC server
    sync/          # Block sync, fast-sync (state snapshot)
    types/         # Shared types: Block, Tx, Hash, Address, PublicKey
  proto/           # Protobuf definitions (source of truth for wire format)
  tests/           # Integration tests
  benches/         # Criterion benchmarks
  fuzz/            # cargo-fuzz targets
  Cargo.toml
  rust-toolchain.toml
```

---

## Coding Rules

### Error Handling

- Use `thiserror` for library errors — never `anyhow` in library code
- Use `anyhow` only in binary entry points (`main.rs`, CLI tools)
- Every error variant must carry enough context to debug without a debugger
- Never `.unwrap()` or `.expect()` outside of tests — use `?` or handle explicitly
- Never silently swallow errors — log at minimum `warn!` before discarding

```rust
// GOOD
#[derive(thiserror::Error, Debug)]
pub enum ConsensusError {
    #[error("block {height} has invalid signature from validator {validator}")]
    InvalidSignature { height: u64, validator: PublicKey },

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

// BAD
fn validate_block(b: &Block) -> Result<(), Box<dyn std::error::Error>> { ... }
```

### Panics

- No `panic!`, `unwrap()`, or `expect()` in any path reachable from network input
- Panics in consensus = node crash = slashable downtime
- Use `debug_assert!` for invariants that should only be checked in development
- If you must assert in production, return an error instead

### Unsafe

- `unsafe` is allowed only where necessary for FFI (libp2p, RocksDB) or provably safe zero-copy operations
- Every `unsafe` block must have a `// SAFETY:` comment explaining the invariant that makes it safe
- No `unsafe` in consensus/, state/, or crypto/ — these must be pure safe Rust

```rust
// GOOD
// SAFETY: `ptr` is valid for `len` bytes because it was allocated by `alloc_aligned`
// and is exclusively owned by this scope.
let slice = unsafe { std::slice::from_raw_parts(ptr, len) };

// BAD
let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
```

### Performance

- **Benchmark before and after every change to hot paths** — `cargo bench`
- Hot paths: block validation, signature verification, state root computation, tx processing
- Avoid heap allocations in the consensus loop — pre-allocate or use stack
- Avoid cloning in message passing — use `Arc<T>` for shared read-only data
- Profile with `perf` or `cargo flamegraph` before optimizing — no blind micro-optimizations
- BLS signature aggregation: always aggregate before verifying — never verify individually when batch is possible

### Async

- Use `tokio` for all async I/O
- Never block the async runtime — use `tokio::task::spawn_blocking` for CPU-heavy work
- Keep async functions short — extract synchronous logic into regular functions
- Use structured concurrency: `tokio::select!` with explicit cancellation, not fire-and-forget spawns

```rust
// GOOD: CPU-heavy crypto work moved off async thread
let sig_valid = tokio::task::spawn_blocking(move || {
    crypto::verify_aggregate_bls(&sig, &pubkeys, &msg)
}).await?;

// BAD: blocks the tokio thread pool
async fn validate_block(block: Block) -> Result<()> {
    let sig_valid = crypto::verify_aggregate_bls(...); // heavy, blocks runtime
    ...
}
```

### Serialization

- Protobuf (prost) for all P2P wire format and block encoding
- Never change a proto field number — it breaks backward compatibility
- Add new fields with new numbers; deprecate old fields with `[deprecated = true]`
- `serde` only for RPC/JSON — never for consensus-critical encoding
- Canonical encoding for anything that gets hashed: deterministic, no optional fields

### Cryptography

- Never roll your own crypto — use `ed25519-dalek`, `bls12-381`, `blake3`
- BLAKE3 for all hashes (not SHA-256 — performance matters)
- Ed25519 for individual validator signatures
- BLS12-381 for aggregate committee signatures
- VRF (ed25519-based) for leader election — never use `rand` for consensus randomness
- Keys must never appear in logs — use `Display` impls that show only the first/last 4 bytes

---

## Testing

### Unit Tests

- Test every function that has a non-trivial precondition or postcondition
- Put unit tests in the same file as the code (`#[cfg(test)] mod tests { ... }`)
- Use `proptest` for any function operating on untrusted input (block headers, transactions, signatures)

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn tx_serialization_roundtrip(tx in arbitrary_tx()) {
        let encoded = tx.encode_to_vec();
        let decoded = Transaction::decode(&*encoded).unwrap();
        prop_assert_eq!(tx, decoded);
    }
}
```

### Integration Tests

- Live in `tests/` — test the full consensus loop end-to-end with an in-memory network
- Simulate: normal round, leader timeout, double vote (equivocation), partial network partition
- Use `tokio::time::pause()` + `advance()` to test timeouts without real wall-clock time

### Benchmarks

- Live in `benches/` using `criterion`
- Required benchmarks: block validation, signature verification, state root, tx throughput
- Run with `cargo bench` — CI fails on > 5% regression vs baseline
- Save baseline with `cargo bench -- --save-baseline main`

### Fuzz Targets

- Every entry point that accepts untrusted bytes must have a fuzz target
- Targets: block deserialization, tx deserialization, P2P message parsing, RPC input
- Run with `cargo fuzz run <target> -- -max_total_time=60`

---

## Consensus Algorithm (PoI — Proof of Identity)

Key invariants to never violate:

1. **Safety:** Two honest nodes never commit different blocks at the same height
2. **Liveness:** If 2/3+ validators are online and honest, the chain makes progress
3. **VRF leader election:** Leader for round R is deterministic given the VRF output of round R-1
4. **Committee size:** 21 validators per round, selected from the top-100 by stake
5. **BLS threshold:** Commit requires aggregate signature from ≥ 14/21 committee members
6. **Slashing:** Double-voting or equivocation = slashable — detect, prove, submit evidence
7. **View change:** If leader is silent for `TIMEOUT_MS` (configurable, default 2000ms), trigger view change

Never modify these without a full SIP (Solidus Improvement Proposal) and formal analysis.

---

## State Machine

- State root = Merkle Patricia Trie root (deterministic across all nodes)
- State transitions are pure functions: `apply(state, tx) -> (new_state, receipt)` — no side effects
- RocksDB is append-only during a round — rollback by discarding uncommitted writes
- Column families: `state`, `blocks`, `headers`, `validator_set`, `receipts`, `evidence`
- Never write to RocksDB directly — go through the `StateStore` abstraction

---

## P2P Networking (libp2p)

- Protocols: `/solidus/gossip/1.0.0` (blocks/txs), `/solidus/consensus/1.0.0` (votes), `/solidus/sync/1.0.0` (fast sync)
- All messages are size-limited: max 2MB for blocks, max 1KB for votes/proposals
- Rate-limit per peer: 100 messages/second for gossip, 50 for consensus
- Disconnect and blacklist peers that send invalid messages (after 3 strikes)
- Never trust peer-reported data — verify every signature before acting

---

## Commit Checklist

Before committing any change to consensus/, state/, or crypto/:

- [ ] `cargo fmt` passes
- [ ] `cargo clippy -- -D warnings` passes
- [ ] `cargo test` passes (all unit + integration tests)
- [ ] `cargo bench` run — no regression > 5%
- [ ] No new `unwrap()`/`expect()` outside tests
- [ ] No new `unsafe` without `// SAFETY:` comment
- [ ] All new public types/functions have doc comments
- [ ] Proto changes are backward-compatible (no field number changes)

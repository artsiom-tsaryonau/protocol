# Solidus L1 v2 — Per-Component Audit-Readiness Packets

Status: §8 deliverable (BD-8 rolling per-component audit-readiness),
drafted 2026-07-11 (branch `feat/l1-v2-two-lane`).

> **R-AUDIT (do not soften):** **No external audit has occurred on any part
> of this protocol.** These are *readiness* artifacts — what an auditor
> would need to start, per component. Nothing here is an audit result and
> no v2 output may be described as "audited." Expect 1–2 high-severity
> findings once a real engagement begins.

**Scoping (BD-8):** the L1 core and the EVM bridge/precompiles are
**separate** engagements — the L1 audit must not be gated on Solidity/EVM
surface. Suggested engagement order: (1) `solidus-exec` + `solidus-hotstuff2`
(the consensus + execution spine, highest blast radius), (2)
`solidus-mempool-dag` + `solidus-store2`, (3) `solidus-subnet` +
`solidus-evm` (bridge + precompiles).

Each packet: **purpose · invariants · test/verification coverage · known
limitations & flagged risks · audit focus.**

---

## 1. solidus-exec — the two-lane executor ★ highest priority

- **Purpose:** deterministic block execution over the 10 native payloads,
  split into a serial identity lane and a parallel (wave-OCC Block-STM)
  payment lane, producing byte-identical receipts + one global state root.
- **Invariants:**
  - Two-lane output ≡ serial reference oracle, byte-for-byte (D-ORDER
    canonical order = identity lane then payment lane, each in block order,
    sig-invalid txs last).
  - Hazard-A: a sender is wholly in one lane (nonce-correct by construction).
  - Hazard-B: identity delta frozen before the payment lane reads it.
  - Hazard-C: fee destination never written per-tx (commutative accumulator,
    single settlement).
  - Wave-OCC is serial-equivalent: every committed tx's read-set re-validates
    against the exact multi-version prefix below it.
- **Coverage:** 34 unit tests + the differential anchor (**1.76M txs, 0
  divergence** incl. the four §5.6 adversarial cases + over-cap parity);
  criterion benches (payment 74.4K TPS / identity 17.6K ops/s / mixed 63.8K,
  M4). Handlers ported 1:1 from the live executor and held to parity.
- **Known limitations / flagged:** the ≥10⁹ differential is a CI/cluster
  run (not yet done — 1.76M local); wave-OCC uses a rebuild-per-wave
  validation (simple, auditable) rather than the full Aptos collaborative
  scheduler (upgrade path behind the same MVMemory API if contention binds).
- **Audit focus:** the lane-partition invariant under adversarial sender
  distributions; the freeze/merge ordering; the commutative fee accumulator
  under overflow; MVMemory read-set validation correctness (ABA safety —
  origins compared by (writer, incarnation), never by value).

## 2. solidus-hotstuff2 — consensus core

- **Purpose:** HotStuff-2 two-chain consecutive-view BFT; pure event-driven
  state machine (no I/O/timers/wall-clock).
- **Invariants:** `commit(B@v) ⇔ QC(B@v) ∧ QC(child(B)@v+1)`; R1
  one-vote-per-view; R3 high-qc lock (merge-then-check); quorum =
  ⌈(n+f+1)/2⌉ ≥ 2f+1; O(N) proposal path unrepresentable.
- **Coverage:** 25 unit + 4-node tokio finality/leader-crash tests; a
  written safety proof (`docs/v2-consensus.md`); the TLA+ spec with
  Byzantine votes + equivocating leaders. Equivocation slashing detection +
  evidence + verification.
- **Known limitations / flagged:** **TLC model-check DONE 2026-07-12**
  (exhaustive MaxView=2 complete + simulation MaxView=4 124M states, no
  safety violation — `tla+/TLC_RESULTS.md`);
  block-sync/fetch-missing-parent is a node-layer concern (the core refuses
  to vote/propose over unknown parents); VRF-by-stake elector is pluggable
  (round-robin ships); a **degenerate 1-validator committee self-recurses**
  (never at n≥4, the BFT minimum) — a cheap defensive per-event
  synchronous-work bound is a future hardening.
- **Audit focus:** the commit rule + lock rule against equivocation and
  view-change races; TC formation + the own-vote rule; the exec-anchor
  (D-EXEC-DEFER) — headers commit to the parent's executed root, so
  divergence trips at the next proposal (the differential is the backstop).

## 3. solidus-mempool-dag — Narwhal-style mempool

- **Purpose:** worker/primary split; consensus orders 32-byte batch
  digests, never bodies; BLS availability certificates.
- **Invariants:** a certified batch is held by ≥ f+1 honest validators
  (availability quorum = consensus quorum); own-ack counted first;
  attestation aggregate verifies (fast_aggregate_verify over a shared
  per-batch message).
- **Coverage:** 12 unit + a 4-worker loopback availability flow (seal→cert
  p95 24ms); header-size acceptance (5.3KB ≤ 10KB at capacity).
- **Known limitations / flagged:** RocksDB-backed batch persistence is a
  store2 concern (in-memory today); the availability attestation's signer
  bitmap is a sorted `Vec<u32>` (compact enough at n≤21).
- **Audit focus:** the ack-lane signing (acks sign over the ORIGINATING
  worker's lane — a bug caught pre-network); cert-pool draft/requeue/retire
  correctness under view changes (retire is global + permanent).

## 4. solidus-state-tree — incremental SMT

- **Purpose:** in-memory incremental 4-sub-tree sparse Merkle state root +
  compressed inclusion proofs.
- **Invariants:** root is a pure function of the final key→value map
  (insertion-order-independent); hashing byte-identical to the live
  RocksDB-backed tree; proofs verify iff (key, value) ∈ root.
- **Coverage:** 14 unit + 6 legacy-tree differential-parity tests; proof
  roundtrip + adversarial rejection (forged value/root/key, tampered
  siblings, bitmap inflation, smuggled extras).
- **Known limitations / flagged:** per-leaf apply ~41µs and wall-time
  degrades ~2.4×/decade of state (node-store cache pressure) — **the
  flagged pre-Stage-7 optimization** (sorted-batch level-sharing + arena
  nodes + rayon across sub-trees) before sustained-50K root-budget claims.
- **Audit focus:** the canonical internal-node path math (the
  zero-bits-below regression that once made only the last leaf count); the
  compressed-proof sibling-bitmap verifier.

## 5. solidus-store2 — storage

- **Purpose:** binary, one WriteBatch per block, hot/cold CF split, tuning
  profiles, range-pruning.
- **Invariants:** a block's whole delta + receipts + block + canon pointer
  land atomically (one WriteBatch); pruning touches only cold history,
  never state; executor-on-RocksDB ≡ in-memory baseline.
- **Coverage:** 2 integration tests (executor-on-store2 parity across
  blocks + reopen; receipt persist + range-prune); persist bench (20.3ms
  for a 50K-shaped block, M4 NVMe).
- **Known limitations / flagged:** boot rebuilds the root forest from hot
  CFs (O(state) once at startup — incremental node persistence is a later
  optimization, no interface change); receipts keyed by height++tx_hash (a
  hash-only index is a later add).
- **Audit focus:** WriteBatch atomicity under crash; the range-delete
  pruning boundary; profile tuning safety (no data loss on the mainnet
  profile).

## 6. solidus-subnet — subnet framework + bridge

- **Purpose:** Avalanche-L1-style subnet trait + L1→subnet finalized-root
  bridge with full 2-chain commit evidence.
- **Invariants:** the bridge accepts roots only with full commit evidence
  (child block + child QC + consecutive views + parent linkage +
  parent.exec_root == announced roots + sub-tree recombination) — a
  merely-QC'd abandoned branch can never feed precompiles; height
  monotonicity.
- **Coverage:** 3 tests + 1 unit (accept path with real BLS evidence; 6
  rejection classes; staleness).
- **Known limitations / flagged:** launch config hardcodes "all L1
  validators run the one EVM subnet" (opt-in committee/slashing-scope
  machinery deferred to a second subnet, BD-5/d).
- **Audit focus:** the finality-evidence check (this is what stops a stale
  or forked root from reaching the EVM); the inclusion-proof verifier reuse.

## 7. solidus-evm — EVM subnet + precompiles

- **Purpose:** REVM subnet + 3 identity precompiles reading L1-finalized
  DID/credential state via inclusion proofs.
- **Invariants:** every read is an inclusion proof against a bridge-verified
  root — no L1 re-execution; failure taxonomy separates "checked and false"
  (bool word) from unverifiable input (revert): stale roots + bad proofs
  REVERT.
- **Coverage:** E2E through real revm transact against real-executor L1
  state (genuine disclosure verifies, forged→false, impostor→false,
  stale-root→revert); 5,000-mutation input fuzz (0 panics, 0
  false-verifies); precompile benches (17µs/17µs/4.3ms). **A real
  foundry-compiled ERC-20** (forge 1.7.1 + Solc 0.8.35; `contracts/Token.sol`)
  deploys + transfers + `balanceOf`s end-to-end through revm, with an
  over-balance transfer reverting (`erc20_e2e`). **`eth_sendRawTransaction`**
  decodes raw legacy (EIP-155) + EIP-1559 txs and secp256k1-recovers the
  sender (`raw_tx`), validated against `cast`-generated known-answer vectors,
  and a foundry-**signed** ERC-20 `transfer` moves balance end-to-end through
  the RPC handler.
- **Known limitations / flagged:** `eth_sendRawTransaction`'s `submit_raw`
  executes immediately against the current bridged state — **no persistent
  mempool / receipt store / block production yet**, and **no gas/fee market**
  (gas is metered but priced 0); both are node-layer/founder follow-ups that
  do NOT gate the L1. Precompile gas costs are flat placeholders pending real
  metering. Supported tx types: legacy + EIP-1559; type-1/3/4 rejected.
- **Audit focus (SEPARATE engagement):** the length-prefixed input decoder
  (fuzzed but the highest untrusted-input surface); **the raw-tx RLP framing +
  the signing-hash reconstruction + secp256k1 recovery** (`raw_tx` — highest
  new untrusted-input surface; ECDSA delegated to alloy/k256, framing is ours);
  the revert-vs-false
  boundary; the BBS+ disclosure verification against the on-chain pubkey.

## 8. solidus-node2 / -rpc2 / -p2p2 — node layer

- **Purpose:** integrated validator (consensus+mempool+executor+store), the
  JSON-RPC edge, and the libp2p transport.
- **Coverage:** node2 localnet (4 nodes, all committed heights agree on
  executed roots, ~31k txs over reliable channels); rpc2 live jsonrpsee
  server roundtrip; p2p2 2-node loopback gossip byte-identical + the
  4-node-over-real-libp2p **demonstration** (`#[ignore]` — in-process
  gossipsub mesh formation is probabilistic; deterministic proofs are the
  first two).
- **Known limitations / flagged:** a deterministic N-validator
  consensus-over-real-libp2p run needs real multi-process/geo hardware
  (Stage 7); the p2p2 runner's cert-pool requeue-on-view-change is wired but
  the churn path wants the geo-soak to exercise.
- **Audit focus:** the transport wire codec + topic routing; RPC input
  validation (bad-sig submit rejected at the edge); the swarm↔node event
  loop's gated-boot + flush behaviours.

---

*Rolling: update each packet as its component changes. This file is the
starting point an auditor reads first — it is not, and must not be
represented as, an audit.*

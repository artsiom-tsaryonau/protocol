# Solidus v2 — Execution Model (Stage 0, frozen)

Status: Stage-0 design freeze, 2026-07-11.
This document records the decisions the code implements plus the Stage-0
verification results. It is an engineering design doc, not a benchmark
claim — every number below is a local measurement with the hardware named.

## The two lanes (BD-1)

One committed block → one deterministic execution → one global state root.
Internally, two lanes with independent performance budgets:

- **Payment lane** — `Transfer` only, from senders that do *nothing but*
  transfer in the block. Block-STM parallel scheduler (Stage 3).
- **Identity/serial lane** — the 9 non-Transfer payloads (7 identity + 2
  staking) **plus every tx from any sender that does one of those in this
  block** (the Hazard-A closure). Strictly serial, capped at 512 txs/block
  (`DEFAULT_IDENTITY_CAP`).

Lane assignment (frozen, `solidus-exec/src/lane.rs`):

```
S_identity = { sender : sender has ≥1 non-Transfer tx in this block }
lane(tx)   = Identity  if tx.sender ∈ S_identity  else  Payment
```

A sender is wholly in one lane ⇒ per-sender nonce order is globally
preserved by construction.

## D-ORDER — the canonical execution order (new decision, Stage 0)

The two-lane split makes execution order **observable**: the Transfer
anchor-guard reads DID state that identity txs write, and the
pristine-DidCreate rule reads balances that transfers write. Running
"identity first" is therefore not just an implementation strategy — it is
a *semantic definition*. v2 defines the canonical execution order of a
committed block as:

> **identity-lane txs first (in block order), then payment-lane txs (in
> block order)** — a deterministic function of the committed tx list,
> re-derived identically by every validator.

Consequences:

- The serial reference oracle executes that same flattened order
  (`ExecOrder::LanePartitioned`); the Stage-3 two-lane executor realizes
  it with parallel machinery. "Byte-identical to the oracle" is therefore
  a meaningful, achievable gate.
- Raw-block-order semantics survive only in `ExecOrder::RawBlock`, used
  exclusively by the legacy parity anchor (the live chain executes raw
  order).
- Consensus stays lane-agnostic: it orders one linear list of batch
  digests and never knows lanes exist.

## Fee settlement (Hazard-C rule)

Per-tx fee **debits** stay per-tx (sender's own account). The fee
**destination** is never written per-tx; fees accumulate in the
commutative `FeeAccumulator` and settle exactly once at block end:

| Policy | Writes | Use |
|---|---|---|
| `Burn` (v2 default) | 1 — `fees_burned_total` meta counter | v2 chain |
| `ProposerReward` | 1 — proposer account credit | v2 optional variant |
| `LegacyDistribute` | treasury + per-validator credits (70/20/10) | parity anchor only |

Per-payload fee *amounts* are preserved verbatim from `solidus-txns`
(`FEE_TRANSFER = 10_000`, …), as are the fee exemptions (all 7
DID/credential payloads are fee-exempt; their signers are value-free
DID anchors).

## Legacy behaviors intentionally dropped (pinned)

1. **Receipt-idempotency short-circuit** — a dev-testnet workaround for
   multiple validators sharing one RocksDB store. v2 executes a committed
   block exactly once per store; the shared-store topology is unsupported.
2. **In-execution receipt persistence** — v2 returns receipts; the node
   layer persists them (one WriteBatch per block, Stage 4).
3. **70/20/10 fee distribution as the chain default** — survives only as
   the parity-anchor policy (see table above).

Everything else — all 10 handler semantics, failure strings, event
payloads, nonce/fee behavior on failure paths, the DID-anchor guard, the
pristine rule, record encodings — is ported verbatim and differentially
verified.

## Stage-0 verification results (measured 2026-07-11, Apple M4 10c/16GB)

- **Differential parity anchor** (`solidus-exec/tests/legacy_parity.rs`):
  the v2 serial reference executor vs the live executor, identical
  streams — byte-identical receipts, all six state namespaces, and
  **exact global-state-root equality**. Bounded fuzz sample: **879,466
  transactions across 40 seeded streams × 1500 blocks — zero
  divergence**, including the four §5.6 adversarial cross-lane scenarios.
  The ≥10⁹-stream run remains a CI/cluster job and gates Stage 3
  (two-lane vs oracle), not Stage 0.
- **Tree parity** (`solidus-state-tree/tests/legacy_tree_parity.rs`):
  v2 in-memory incremental SMT vs the live RocksDB-backed tree —
  identical roots on randomized maps, updates, and insertion orders.
- **Criterion baselines** (`solidus-exec/benches/executor.rs`):
  - serial reference executor, 256-tx Transfer blocks: **~32.8K txs/s**
    (single-threaded, includes per-tx Ed25519 verification)
  - live legacy executor, same workload on RocksDB: **~26.3K txs/s**
  - incremental root apply: **~24.0K leaves/s** (~41 µs/leaf; 256 BLAKE3
    levels per touched leaf)

  These are oracle baselines on one laptop core, **not** chain throughput,
  and none of them is the 50K TPS target — that belongs to the Stage-3
  parallel payment lane (Rayon signature pre-pass + Block-STM) measured on
  validator-class hardware. Known optimization target: the per-leaf SMT
  apply cost must drop (batched level-sharing and/or parallel sub-tree
  apply) before Stage 4's <50ms-per-block root budget is realistic.

# Solidus L1 v2 — Benchmarks (measured, reproducible, honestly labelled)

Status: end-goal pass 2026-07-13, branch `feat/l1-v2-two-lane`. Every number
on this page was **re-measured on 2026-07-13** by re-running the in-repo
harness; the raw, unedited outputs live in
[`docs/bench/2026-07-13-apple-m4/`](bench/2026-07-13-apple-m4/) next to the
hardware spec. Nothing here is extrapolated. **The one number this plan
exists to produce — 50K TPS sustained on a 21-validator, 3-region network —
has NEVER been measured** (it needs hardware this project does not own; a
priced launch plan exists and the run is pending). Publishing that fact is
the point of this page: what is real is labelled real, and what is missing
is priced, not implied.

## Measurement box

```
Apple M4 (10 cores, 16 GB, NVMe) · macOS 15.7.3 · rustc 1.96.0-nightly
```

The plan's §7 numeric targets are specified for a **32-core validator**.
Everything below is a 10-core laptop reading — a *lower* bound environment
for the throughput criteria, which is why clearing a 32-core target on it is
reported, but the criterion is only fully discharged on target-class
hardware (launch-plan Tier A, ~€15).

## §7 acceptance criteria — the truth table

| Criterion (target) | Measured | Where / command | Verdict |
|---|---|---|---|
| **(a)** zero divergence vs serial oracle, all 10 payloads + 4 adversarial cross-lane cases, **≥10⁹** scale | **0 divergence** over 2,186,046 txs / 1,000 streams (fresh, this box, 310.7s) — cumulative custody chain ≈ 6.0M txs incl. 879K live≡oracle | `differential-large.txt`; cmd below | **MET at ~6×10⁶ scale · the ≥10⁹ campaign NEVER-RUN** (Tier A, ~3–5h on 48 vCPU) |
| **(b)** payment lane **≥40K** Transfer TPS on a 32-core validator | **75.6K TPS** (10,000 disjoint transfers, full pipeline incl. sig pre-pass) | `bench-exec.txt` → `twolane_payment_lane` | **MET on lesser hardware · 32-core reading NEVER-MEASURED** |
| **(c)** identity lane **≥3K** serialized ops/sec | **17.7K ops/s** (500 issues, one hot issuer — max contention) | `bench-exec.txt` → `twolane_identity_lane` | **MET** (5.9× target on 10 cores) |
| **(d)** **≥45K TPS on the 95/5 mix**, identity contention maximized, payment unaffected | **64.9K TPS** (9,500 transfers + 500 hot-issuer issues) | `bench-exec.txt` → `twolane_mixed_95_5` | **MET on lesser hardware · 32-core reading NEVER-MEASURED** |
| finality **p50 ≤600ms / p99 ≤1500ms** (4-node LAN, Stage 1) | p50 **7.7ms** / p99 **16.3ms**, 604 commits — **in-process loopback, not a network** | `finality.txt` | **MET on loopback · LAN/geo reading NEVER-MEASURED** (Tier B) |
| consensus header ≤10KB @ capacity; batch p95 <250ms (Stage 2) | 5,344B @ 17 certs; seal→cert p50 21.2ms (2026-07-11 measurement) | `docs/v2-consensus.md` | **MET on loopback** |
| per-block durable write **<50ms at 50K-TPS shape** (Stage 4) | **19.9–20.1ms** (50K leaves + 25K receipts, testnet & mainnet profiles) | `bench-store2.txt` | **MET on this NVMe · validator-disk reading pending** |
| root apply O(touched) | 25.3K leaves/s @10K-leaf state → **13.3K @100K** (2K delta) — O(touched) by construction, wall-time degrades with cache pressure | `bench-tree.txt` | **MET structurally · flagged optimization before sustained-50K claims** |
| precompiles <50ms (Stage 6) | 17.5µs / 17.3µs / **4.41ms** (BBS pairing) | `bench-evm.txt` | **MET** |
| TLA+ safety, no violation (Stage 1) | exhaustive MaxView=2 (963,033 states) + simulation MaxView=4 (124.4M states), 0 violations | `tla+/TLC_RESULTS.md` | **MET** (bounded model-check, not a proof) |
| **Stage 7: 50K TPS × 72h, 21 validators / 3 regions, p99 <1500ms, zero divergence/halts** | — | needs 21 geo boxes (priced: ~€2.1K week, launch plan Tier C) | **NEVER-MEASURED** |

Supporting consensus-crypto floor (sizes the per-view budget): BLS sign
193µs · verify 443µs · aggregate-14 387µs · QC-verify 428µs
(`bench-consensus.txt`).

## Reproduce it yourself

```bash
git clone https://github.com/solidusnetwork/protocol.git && cd protocol
# (b)(c)(d) — the three lane criteria + reference/legacy baselines:
cargo bench -p solidus-exec --bench executor
# (a) — differential vs the serial oracle (defaults are CI-fast; this is
#       the exact 2.19M-tx configuration used above):
SOLIDUS_TWOLANE_SEEDS=1000 SOLIDUS_TWOLANE_BLOCKS=100 SOLIDUS_TWOLANE_TXS=96 \
  cargo test -p solidus-exec --release --test twolane_vs_oracle randomized -- --nocapture
# finality (loopback), storage, tree scaling, BLS, precompiles:
cargo test  -p solidus-hotstuff2 --release --test four_node happy_path -- --nocapture
cargo bench -p solidus-store2 --bench store2
cargo bench -p solidus-state-tree --bench tree
cargo bench -p solidus-hotstuff2 --bench consensus
cargo bench -p solidus-evm --bench precompiles
```

Chain-id: the executor benches run pure execution (network label
`v2-bench`); the end-to-end devnet in `docs/v2-validator-join.md` runs a
real 4-validator chain (rehearsed on chain-id 41414) where a faucet-funded
transfer was visible on another node **0.16s** after submission.

> **Reproducibility boundary (honest):** as of 2026-07-14 the v2 crates,
> this harness, and the raw logs are public in this repo — anyone can run
> the commands above. What remains unreproduced is the *environment*: every
> published figure comes from one 10-core laptop. The 32-core-class readings
> and the 21-validator geo soak have not been run by us or anyone else, and
> no number on this page should be treated as network throughput until they
> are.

## Reading these numbers (do not over-quote)

1. **None of this is network throughput.** The lane benches measure the
   execution pipeline on one box. The chain's TPS is bounded by consensus +
   dissemination + execution together — that is exactly what the Stage-7
   soak measures and why it is the only number worth headlines.
2. **Loopback finality is protocol overhead, not latency.** 7.7ms says the
   protocol adds little on top of the wire; it says nothing about
   inter-region RTT, which will dominate (geo p99 is the gate).
3. **The reference executor (~18K tx/s serial) vs the two-lane 75.6K is the
   honest speedup story (~4.2× on 10 cores)** — the legacy executor's 26K/s
   on a 256-tx block is an apples-to-oranges baseline (RocksDB-backed,
   JSON wire) included for scale, not for marketing.
4. No number on this page may be quoted without its hardware and its
   caveat. "75K TPS" without "single-box execution pipeline, 10-core
   laptop" is a fabrication by omission.

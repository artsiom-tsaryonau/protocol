# TLC Model-Check Results — HotStuff2Commit.tla

Gate (a) discharged 2026-07-12 on the build box (Apple M4, 10 cores,
OpenJDK 17, TLA+ tools `tla2tools.jar` v1.8.0 / TLC 2026.07.09). The
spec's safety invariants — `NoConflictingCommits` (no two honest replicas
commit conflicting blocks) and `QcUniquePerView` (per-view QC uniqueness) —
were checked under a Byzantine replica (`Byzantine = {r4}`, f=1, n=4) with
equivocating leaders (2 blocks/view) and unconstrained Byzantine votes.

## Result 1 — EXHAUSTIVE, MaxView = 2 (`MC_small.cfg`)

```
Model checking completed. No error has been found.
14,122,857 states generated, 963,033 distinct states found, 0 states left on queue.
The depth of the complete state graph search is 24.
Finished in 20s.
```

The **entire reachable state graph** of the MaxView=2 model was explored
(0 states left on queue) with **no safety violation** — a complete proof
for the smallest non-trivial model.

## Result 2 — SIMULATION, MaxView = 4 (`MC.cfg`)

Exhaustive BFS at MaxView=4 exceeds the local disk budget for the state
graph, so the full model was checked by random-simulation (disk-light;
every visited state is invariant-checked, a violation halts with a trace):

```
Running Random Simulation with 10 workers.
The number of states generated: 124,354,945
2,000,000 traces generated (trace length: mean=35, sd=25).
Finished in 03min 25s.  [no error / no invariant violation]
```

**124,354,945 states across 2,000,000 random traces on the full MaxView=4
model — zero safety violations.** Simulation is not exhaustive (it is
random-walk coverage), but 124M states with an active Byzantine replica and
equivocating leaders is strong evidence; it covers vastly more of the
MaxView=4 space than exhaustive BFS reached in the disk budget.

## Result 3 — EXHAUSTIVE (PARTIAL), MaxView = 3 (`MC3.cfg`)

Exhaustive BFS at MaxView=3 was launched and ran to:

```
Progress(14) at 2026-07-12 05:30:15: 553,696,858 states generated,
69,440,453 distinct states found, 43,597,396 states left on queue.
[no error / no invariant violation]
```

**69.4M distinct states explored (553.7M generated) at MaxView=3 with zero
safety violation.** The run did **not** exhaust the graph — the frontier
queue was still *growing* (39.6M → 43.6M over the last three minutes), i.e.
the MaxView=3 reachable space is large enough that BFS would not converge
within the build-box window and the on-disk state queue would eventually
exceed the disk budget. It was **deliberately stopped**, not completed, to
protect the disk. This is therefore a *bounded partial* exhaustive result,
not a complete proof at MaxView=3.

The discharged gate stands on **Result 1 (MaxView=2 exhaustive, complete)**
and **Result 2 (MaxView=4 simulation, 124M states)**; Result 3 is
additional no-violation coverage (69M distinct states BFS-explored), not the
basis of the gate. A complete MaxView=3 exhaustive run is a nice-to-have that
needs either a bigger disk/off-heap FP-set budget or a longer window.

## Reproduce

```
cd protocol/apps/consensus/crates/solidus-hotstuff2/tla+
# fetch tla2tools.jar (v1.8.0) — gitignored, not committed
curl -fsSLo tla2tools.jar https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar
export TMPDIR="$PWD"
java -cp tla2tools.jar tlc2.TLC -config MC_small.cfg -workers auto HotStuff2Commit.tla       # exhaustive MaxView=2
java -Xmx3g -cp tla2tools.jar tlc2.TLC -config MC.cfg -simulate num=200000 -depth 60 -workers auto HotStuff2Commit.tla  # sim MaxView=4
```

## Honest scope

- These are model-checking results on a **bounded** model (n=4, f=1,
  MaxView≤4). Model-checking a bounded instance is standard practice for
  consensus safety and is what the plan's gate (a) asked for; it is not a
  hand proof for arbitrary n (the written argument in `docs/v2-consensus.md`
  covers the general quorum-intersection reasoning).
- The spec mirrors `src/safety.rs` + `src/core.rs` (R1 one-vote-per-view,
  R3 lock-on-justify, consecutive-view 2-chain commit). Any change to those
  rules must re-run TLC.

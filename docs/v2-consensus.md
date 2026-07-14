# Solidus v2 — HotStuff-2 Consensus (Stage 1)

Status: Stage-1 core implemented and measured, 2026-07-11. Plan §4.4, BD-3.
Crate: `solidus-hotstuff2`. Every number below is a local measurement with
the hardware named; nothing here is a network-throughput or audit claim.

## Protocol

Two-chain HotStuff (HotStuff-2/Jolteon family), consecutive-view commit:

> **commit(B@v) ⇔ QC(B@v) ∧ QC(B′@v+1)** where `B′.parent = B` and `B′`'s
> embedded justify is exactly `QC(B@v)`.

Replica state (in `safety.rs`, mirrored by `tla+/HotStuff2Commit.tla`):

- **R1 — vote monotonicity:** vote at most once per view, strictly
  increasing (`last_voted_view`).
- **R3 — lock:** `high_qc` = the highest-view QC ever observed. Vote for a
  proposal only if its justify's view ≥ the lock's view (the justify is
  merged into the lock first — merge-then-check).
- **R2 — view continuity (in `core.rs`):** a proposal at view `v` must
  carry justify from view `v−1`, or a TC for `v−1` whose reported high-QC
  its justify matches-or-beats.

### Safety argument (why no two honest replicas commit conflicting blocks)

Suppose `B` commits via `QC(B,v)` ∧ `QC(B′,v+1)`, `B′.parent = B`. Let `S`
be the honest signers of `QC(B′,v+1)` — at least `quorum − f ≥ f+1 ≥ 1`
replicas. Each `r ∈ S` merged `B′`'s justify (`QC(B,v)`) into its lock
when voting, so from that moment `lock(r) ≥ v`, and by R1 `r` never votes
again at views ≤ v+1.

Claim: every QC at view `w > v` certifies a block extending `B`. Strong
induction on `w`:

- Any `QC(C,w)` shares an honest replica `r ∈ S` with `QC(B′,v+1)`
  (quorum intersection: `2q − n ≥ f+1`). `r` voted for `C` only with
  `C.justify.view ≥ lock(r) ≥ v`, so `C.justify.view ∈ [v, w)`.
- If `C.justify.view = v`: per-view QC uniqueness (two same-view QCs on
  different blocks would require `f+1` honest double-voters, impossible
  under R1) forces `C.justify = QC(B,v)` — so `C` extends `B`.
- If `C.justify.view = u ∈ (v, w)`: by induction the block certified at
  `u` extends `B`, and `C` extends it.

Hence every later-certified chain extends `B`; a conflicting commit would
need a QC on a non-descendant at some view > v (or a second same-view QC),
both excluded. ∎

The TLA+ spec encodes exactly these rules with Byzantine replicas voting
arbitrarily and equivocating leaders (2 blocks/view) and checks
`NoConflictingCommits` + `QcUniquePerView`. **MODEL-CHECKED 2026-07-12**
(TLC — exhaustive MaxView=2 complete state graph + simulation MaxView=4
124,354,945 states / 2M traces, no safety violation, with a Byzantine
replica + equivocating leaders; see `tla+/TLC_RESULTS.md`). Re-run TLC on
any change to the R1/R3/commit rules.

## Pacemaker

400ms base view timeout, ×2 backoff capped at 3200ms (`pacemaker.rs`) —
replaces the live chain's 2000→16000ms ladder. Backoff resets on QC
progress only, never on TC entry. Timeout votes re-broadcast on each
re-armed timer for the stuck view.

Timeout certificates: every timeout signer of view `v` signs the same
domain-separated `(chain_id, v)` message, so the TC aggregate remains
`fast_aggregate_verify`-able; the highest QC travels alongside as
independently-verifiable data (a QC self-certifies — a Byzantine TC
carrier can withhold but not forge).

## Dissemination shape (no O(N) proposal path, by construction)

The core is a pure event-driven state machine (`core.rs`); its action
vocabulary is the complete list of network effects: `BroadcastProposal`,
`BroadcastQc`, `BroadcastTc`, `BroadcastTimeoutVote` (gossip) and
`SendVote { to }` (point-to-point to the next leader). There is no way to
express a per-peer proposal send. The gossipsub transport binding lands in
`solidus-p2p2`; the live chain's O(N) request-response proposal path is
structurally unrepresentable here.

Proposals are proposer-signed (`proposal_message` domain) so leadership
cannot be impersonated; blocks carry batch-certificate digests only.

## Stage-1 measurements (Apple M4, 10 cores, release — local box)

- **4-validator in-process harness** (`tests/four_node.rs`, tokio, real
  timers, loopback channels): **finality p50 = 7.6ms, p99 = 11.5ms** over
  600 commit observations; chains byte-identical across nodes;
  leader-crash test: 3 live nodes keep committing through TC rotation
  with a crashed leader/aggregator. Loopback RTT is ~µs — these numbers
  are protocol+crypto overhead, not network finality. The ≤600ms p50 /
  ≤1500ms p99 4-node-LAN acceptance bounds are met with ~80× margin on
  this box; the real-LAN and geo measurements remain Stage-7 items
  (R-TOPOLOGY).
- **BLS hot path** (criterion, 21-validator committee, quorum 14):
  sign 194µs · single-vote verify 435µs · aggregate-14 385µs ·
  QC-verify 418µs.
  The per-view budget driver is **vote verification** (14 × 435µs ≈ 6ms
  if serial), not aggregation. Consequences: (a) the node layer must run
  vote verification off the consensus thread (§4.4) and SHOULD batch it;
  (b) a known optimization if it ever binds: aggregate optimistically and
  verify the aggregate once (~0.4ms), bisecting only on failure.

## Deferred to later stages (explicit)

- Block sync / fetch-missing-parent (node layer; the core refuses to vote
  or propose over unknown parents and lets the pacemaker rotate).
- VRF-by-stake leader election (elector trait is pluggable; round-robin
  ships now; safety is elector-agnostic and the TLA+ spec quantifies over
  arbitrary proposers).
- Epoch/committee rotation from the staking tree; slashing evidence
  (Stage 7 closes the loop).
- Real gossipsub transport (`solidus-p2p2`) and `spawn_blocking`
  placement in the node runtime (node2).

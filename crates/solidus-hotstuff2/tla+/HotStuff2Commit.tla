---------------------------- MODULE HotStuff2Commit ----------------------------
(***************************************************************************)
(* HotStuff-2 (two-chain, consecutive-view) commit-rule spec for Solidus  *)
(* v2 — Stage-1 COMPLETE ACTIONS, MODEL-CHECKED.                           *)
(*                                                                         *)
(* STATUS: actions complete, mirrors src/safety.rs + src/core.rs (R1 vote  *)
(* monotonicity, R3 lock-on-justify, quorum formation, consecutive-view    *)
(* commit). MODEL-CHECKED 2026-07-12 with TLC (see TLC_RESULTS.md):        *)
(*   - EXHAUSTIVE MaxView=2 (MC_small.cfg): complete state graph, 963,033  *)
(*     distinct states, NO safety violation.                               *)
(*   - SIMULATION MaxView=4 (MC.cfg): 124,354,945 states / 2M traces, NO   *)
(*     safety violation, with a Byzantine replica + equivocating leaders.  *)
(* Safety invariants checked: NoConflictingCommits, QcUniquePerView.       *)
(* Re-run TLC on any change to the R1/R3/commit rules.                     *)
(*                                                                         *)
(* Modeling notes:                                                         *)
(* - Blocks are abstract: [proposed, parent, jview]. `jview` is the view   *)
(*   of the QC the block embeds (its justify), constrained to be a formed  *)
(*   QC on the parent at proposal time.                                    *)
(* - A Byzantine leader may equivocate: up to 2 distinct blocks per view   *)
(*   (alt ∈ {1,2}). Leader identity is unconstrained — safety must not     *)
(*   depend on who proposes.                                               *)
(* - Byzantine replicas vote arbitrarily (any block, any view, many        *)
(*   times). Honest replicas follow R1 + R3, with the lock updated at      *)
(*   vote time from the proposal's justify — exactly like the Rust core.   *)
(* - Timeouts/TCs are not modeled: they only gate WHICH views produce      *)
(*   proposals (liveness), never the safety of votes/commits. This spec    *)
(*   already allows arbitrary view/leader schedules.                       *)
(***************************************************************************)

EXTENDS Naturals, FiniteSets

CONSTANTS
    Replicas,       \* e.g. {r1, r2, r3, r4}
    Byzantine,      \* Byzantine subset, |Byzantine| ≤ f
    MaxView         \* view bound for model checking

ASSUME Byzantine \subseteq Replicas
ASSUME 3 * Cardinality(Byzantine) < Cardinality(Replicas)

Honest == Replicas \ Byzantine

\* Quorum: any set of ≥ ⌈(n+f+1)/2⌉ replicas (two quorums share an honest one).
N == Cardinality(Replicas)
F == (N - 1) \div 3
QuorumSize == (N + F + 2) \div 2
Quorum == {Q \in SUBSET Replicas : Cardinality(Q) >= QuorumSize}

Views == 1 .. MaxView

\* Block identities: (view, alt) — a Byzantine leader may propose 2 blocks
\* in its view. 'G' is genesis.
G == [view |-> 0, alt |-> 1]
BlockIds == [view : Views, alt : {1, 2}] \cup {G}

VARIABLES
    blocks,     \* BlockIds → [proposed, parent ∈ BlockIds, jview ∈ 0..MaxView]
    votes,      \* Replicas → SUBSET (Views × BlockIds)
    lastVoted,  \* Honest → 0..MaxView       (R1 state)
    lockView,   \* Honest → 0..MaxView       (R3 state: high_qc.view)
    qcs,        \* SUBSET [block : BlockIds, view : 0..MaxView]
    committed   \* Honest → SUBSET BlockIds

vars == <<blocks, votes, lastVoted, lockView, qcs, committed>>

Init ==
    /\ blocks = [b \in BlockIds |->
                   IF b = G THEN [proposed |-> TRUE,  parent |-> G, jview |-> 0]
                            ELSE [proposed |-> FALSE, parent |-> G, jview |-> 0]]
    /\ votes = [r \in Replicas |-> {}]
    /\ lastVoted = [r \in Honest |-> 0]
    /\ lockView = [r \in Honest |-> 0]
    /\ qcs = {[block |-> G, view |-> 0]}
    /\ committed = [r \in Honest |-> {G}]

\* A QC exists on block b at view v.
HasQC(b, v) == [block |-> b, view |-> v] \in qcs

(***************************************************************************)
(* Propose: any not-yet-proposed block id may materialize, provided its    *)
(* parent is proposed and its justify is a formed QC on that parent at a   *)
(* strictly lower view.                                                    *)
(***************************************************************************)
Propose(b, parent, jv) ==
    /\ ~blocks[b].proposed
    /\ blocks[parent].proposed
    /\ jv < b.view
    /\ parent.view = jv
    /\ HasQC(parent, jv)
    /\ blocks' = [blocks EXCEPT ![b] = [proposed |-> TRUE, parent |-> parent, jview |-> jv]]
    /\ UNCHANGED <<votes, lastVoted, lockView, qcs, committed>>

(***************************************************************************)
(* HonestVote: R1 (strictly increasing views, one vote per view) and R3    *)
(* (justify view ≥ lock), with the lock raised to the justify at vote      *)
(* time (the merge-then-check discipline in safety.rs).                    *)
(***************************************************************************)
HonestVote(r, b) ==
    /\ r \in Honest
    /\ blocks[b].proposed
    /\ b.view > lastVoted[r]
    /\ blocks[b].jview >= lockView[r]
    /\ votes' = [votes EXCEPT ![r] = @ \cup {<<b.view, b>>}]
    /\ lastVoted' = [lastVoted EXCEPT ![r] = b.view]
    /\ lockView' = [lockView EXCEPT ![r] =
                      IF blocks[b].jview > @ THEN blocks[b].jview ELSE @]
    /\ UNCHANGED <<blocks, qcs, committed>>

(***************************************************************************)
(* ByzantineVote: unconstrained — any views, any blocks, equivocation.     *)
(***************************************************************************)
ByzantineVote(r, v, b) ==
    /\ r \in Byzantine
    /\ blocks[b].proposed
    /\ votes' = [votes EXCEPT ![r] = @ \cup {<<v, b>>}]
    /\ UNCHANGED <<blocks, lastVoted, lockView, qcs, committed>>

(***************************************************************************)
(* FormQC: a quorum voted (v, b) with v = the block's own view.            *)
(***************************************************************************)
FormQC(b, v) ==
    /\ blocks[b].proposed
    /\ b.view = v
    /\ \E Q \in Quorum : \A r \in Q : <<v, b>> \in votes[r]
    /\ qcs' = qcs \cup {[block |-> b, view |-> v]}
    /\ UNCHANGED <<blocks, votes, lastVoted, lockView, committed>>

(***************************************************************************)
(* Commit: the frozen 2-chain rule — a QC'd child at the immediately next  *)
(* view whose justify is exactly the parent's QC finalizes the parent.     *)
(***************************************************************************)
Commit(r, b) ==
    /\ r \in Honest
    /\ blocks[b].proposed
    /\ \E child \in BlockIds \ {G} :
         /\ blocks[child].proposed
         /\ blocks[child].parent = b
         /\ blocks[child].jview = b.view
         /\ child.view = b.view + 1
         /\ HasQC(child, child.view)
         /\ HasQC(b, b.view)
    /\ committed' = [committed EXCEPT ![r] = @ \cup {b}]
    /\ UNCHANGED <<blocks, votes, lastVoted, lockView, qcs>>

Next ==
    \/ \E b \in BlockIds \ {G}, p \in BlockIds, jv \in 0..MaxView : Propose(b, p, jv)
    \/ \E r \in Honest, b \in BlockIds \ {G} : HonestVote(r, b)
    \/ \E r \in Byzantine, v \in Views, b \in BlockIds \ {G} : ByzantineVote(r, v, b)
    \/ \E b \in BlockIds \ {G}, v \in Views : FormQC(b, v)
    \/ \E r \in Honest, b \in BlockIds : Commit(r, b)

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Safety properties                                                       *)
(***************************************************************************)

\* Ancestor set of a block by parent-walking (fuel-bounded).
RECURSIVE AncestorsRec(_, _)
AncestorsRec(b, fuel) ==
    IF b = G \/ fuel = 0 THEN {b}
    ELSE {b} \cup AncestorsRec(blocks[b].parent, fuel - 1)
Ancestors(b) == AncestorsRec(b, MaxView + 1)

Conflicting(b1, b2) ==
    /\ ~(b1 \in Ancestors(b2))
    /\ ~(b2 \in Ancestors(b1))

\* THE invariant: no two honest replicas commit conflicting blocks —
\* including the r1 = r2 case.
NoConflictingCommits ==
    \A r1, r2 \in Honest :
        \A b1 \in committed[r1], b2 \in committed[r2] :
            ~Conflicting(b1, b2)

\* Supporting lemma, also checked: per-view QC uniqueness.
QcUniquePerView ==
    \A q1, q2 \in qcs :
        (q1.view = q2.view /\ q1.view > 0) => q1.block = q2.block

=============================================================================

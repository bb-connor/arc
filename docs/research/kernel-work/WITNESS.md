# Minimal witness and repaired counterdesigns

Date: 2026-10-02. Task 3. Common semantics: [MODEL.md](MODEL.md).

## Indistinguishable histories

Use F05 with the same finalized request `(issuance=11, envelope=21)`, two owner
approvals, integrity endorsement, original nonce and one-unit reservation.

| Step | History H0 | History H1 | Recovering participant's observation |
| --- | --- | --- | --- |
| Capture | Native one-send claim committed | Same | Original operation captured |
| Transport | Message does not apply | Receiver applies once | No acknowledgement |
| Restart | Durable claim recovered | Same | Unknown original operation |
| Parent refund | 100 returned | 100 returned | Financial parent terminal |
| Proposed replacement | Would be first physical write | Would duplicate write | Identical local input |

A deterministic controller with identical visible inputs chooses identically.
A randomized controller that sometimes retries has a positive duplicate risk in
H1. Therefore neither can guarantee the one-effect bound while using a blind
replacement to finish H0. This is an indistinguishability argument under E2,
not a new impossibility theorem. S12 knowledge-of-preconditions, S27 partial
observation and existing RIFL/Beldi recovery explain the obstruction. E1 changes
the observation premise through exact, complete retained outcome evidence and a
closure fence; a signature over `unknown`, a refund and an unfenced `not_found`
do not. The experiment must retain H0 and H1 and compare their controller states,
excluding the oracle count. Deny-all and retry-all should fail different tests.

## Useful composed continuation

1. B funds a 100-unit parent. P allocates independent 30-unit backing for C and
   disjoint logical-call partitions for publication, specialist and sibling.
2. Owners D1 and D2 qualify C's confined host and approve the exact seed release.
   C's bounded return is explicitly authorized, with errors and metadata mediated.
   The original labels and P's accumulated knowledge remain restricted.
3. V accepts C's original predicate/context. S records the earned 30-unit child
   claim against P's allocation. Owners permit the limited commercial metadata
   visible to S, V and the selected rail. No issue content is released to them.
4. P materializes the issue. D1 and D2 approve that exact publication and the
   distinct integrity authority endorses it. P durably binds original issuance,
   request and native capture before the only send.
5. The reply is lost. Publication remains unknown. B's parent can refund under
   its contract; that event changes neither execution knowledge nor C's backing.
6. The independent sibling completes under its own workflow, allocation and
   prerequisites. Internal settlement can record the original disposition after
   caller expiry. A revoked result audience cannot read the result.
7. Under E1, exact authoritative lookup may append the original outcome; under
   E2 the publication stays unknown. Neither branch creates new authority by
   forgetting knowledge, consumed nonces or earlier possible effects.

The consequential composition obligation is at the joins: the payment observer
is also a disclosure recipient; the release approval must bind the exact effect;
resource ownership must persist independently of commercial refund; and internal
settlement must not inherit an unrelated current read predicate. Individually
correct escrow, IFC and durable workflow implementations do not automatically
supply those bindings. However, ordinary engineering can supply them.

## Reproduce it before claiming an advantage

| Construction | Minimum added glue over its supplied primitives | Trust/coordination needed for this witness |
| --- | --- | --- |
| Chio assumed full recovery | Bind work-edge prerequisites to original operation, owner components, independent backing, acceptance context and all actual observers; public reusable adapter contract | Each honest local host/store; owner-qualified receiving host; E1 receiver when used; V/S; local capture and original-identity readback |
| B1 conventional services | A reusable edge record plus exact owner approvals, durable native capture/one-send record, scoped readback and lifetime-aware workflow predicates; use a shared library across applications | The same hosts, receiver, V/S and local durable operations; no global workflow DB required |
| B2 Agoric capability contracts | Durable per-operation facets; typed original-operation evidence; off-chain qualified host/release and effect adapter; independently backed child seat | Contract/settlement domain plus the same off-chain host/receiver premises; no extra party needed solely for this witness |
| B3 OpenAPPA composition | Bind durable operation/label claims to independent funded edges and exact receiver evidence; carry separate owner components and typed dependencies | The same owner-qualified hosts, receiver and V/S; independently scoped claim families permitted |

These repairs are permitted baseline mechanisms. No behavior in this witness
separates Chio from the repaired constructions. Shared libraries and reusable
adapters are allowed on every side. B2/B3 are hand-worked constructions, not
executed implementations. Task 4 selects B1; claiming those products were tested
would be false. The remaining systems question is the cost of correctly reusing
the contract across families, not whether someone can add an ordinary field.

## Smallest algorithm and argument worth testing

Represent the local continuation frontier as typed obligations: exact authority,
original operation ownership, current/held prerequisites, exposure, release
coverage and independent backing. For each registered command, collect its
obligations from visible records and evaluate each at its owning boundary. Return
an advisory enabled/refused/bound-exhausted result. Native capture alone changes
execution ownership. Do not enumerate all physically compatible histories: the
unresolved original-operation tombstone is a conservative sufficient summary for
this profile. No general minimality or optimality claim follows.

For m registered candidates with a approval entries, d dependencies, c required
label components and f funding records, a direct scan takes
O(m(a*c + d + f)) predicate work, plus the linear history space actually retained.
The live frontier is O(m + a + d + f); immutable audit history grows with events.
KW1 fixes three operations and four components. B1 may use exactly the same
indexes or summary; there is no claimed asymptotic advantage. The procedure is
complete only for the explicitly enumerated commands at the current snapshot,
not arbitrary plans, dynamic DAGs or safe actions hidden outside the registry.

A standard induction explains the necessary join conditions: initially there
is no effect or unbacked earned claim; a local step preserves its owner's
invariants under the supplied native axioms; an edge step must preserve source
components, exact identity and disjoint ownership at its receiving boundary;
replay/recovery changes observations without manufacturing authority. Removing
an edge premise admits a concrete bad trace even when each isolated service's
local property is true. This is a proof outline to organize counterexamples,
not a checked arbitrary-trace theorem and not evidence of novelty.

Decentralized IFC already preserves per-owner restrictions and permits owner-
scoped release ([S25](https://www.cs.cornell.edu/andru/papers/iflow-tosem.pdf)).
Temporal interface assumptions and composition are also established
([S30, Interface Automata](https://web.cs.wpi.edu/~heineman/html/teaching_/CS562/p109-de_alfaro.pdf),
sections 1 and 3; [source pin](task3-sources.json)). Neither literature comparison
establishes a formal reduction of this entire kernel to that work. It does defeat
presenting “compose explicit interfaces” as a novel theorem by itself.

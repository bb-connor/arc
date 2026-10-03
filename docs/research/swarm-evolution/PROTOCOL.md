# S1: additive swarm evolution

## Rule and scope

Plans may grow while previously issued commitments keep their original bounds
and execution identity. The profile is additive. It does not retire tasks,
reclaim budgets, migrate committed work, change the revocation epoch, or revise
the original policy envelope.

An owner provisions one protected graph lineage for one declared pool. Its
store serializes extensions. Each task uses one protected native receiver
custody domain. Independently forked databases, separately provisioned graphs
spending the same pool, and compromised trusted issuers violate these
assumptions. The implementation adds no distributed consensus.

## Reuse map

| Existing component | Responsibility retained | Added connection |
| --- | --- | --- |
| `chio-swarm-authority` | Signed graphs, scopes, witness chains, routes, joins, budget arithmetic, revocation | A pure verifier checks preservation between two ordinarily valid bundles |
| SQLite runtime orchestration store | Protected admission evidence | One transaction archives the old version and installs a checked successor |
| Runtime admission hook | Exact request binding, local capability and freshness checks | Resolves the existing graph digest to its exact stored version |
| Native operation-owned custody | Owns continuation resources and physical claims | Same continuation ID is used across graph versions |
| Bilateral treaty admission | Receiver-selected treaty evidence and destructive lease | Remains a required independent gate; old claims resolve old swarm evidence |
| D1 workflow delegation | Recursive allocation, editable selection before sealing, stable sealed permits | Retained unchanged; a unified D1/S1 allocation handoff is not asserted |

No signature algorithm, wire schema, native invocation capability or dependency
is added. The installer requires an already provisioned graph; it cannot
register a root or install new trusted issuers.

## Pure extension check

`verify_swarm_authority_extension(previous, candidate, trusted_keys, now)`:

1. Verify both bundles with the existing live admission verifier at the
   caller's time. Ignore both transported time values as authority.
2. Require strict node growth, with no terminal graph receipt on either side.
3. Retain the original graph ID, planner, issuer, root transaction, lifetime,
   depth/fan-out bounds, witness mode, pool reference and revocation reference.
4. Retain every old node, edge, join definition, route reference, route
   artifact, witness chain, join receipt and allocation exactly.
5. Retain the pool envelope and exact revocation epoch. Ordinary checked
   accounting must bound the sum of all allocation ceilings by the fixed pool.
6. Retain each old continuation ID and every field except its graph digest and
   signature. The newly signed token binds the successor graph.
7. Require single-use mode and at most one continuation per task or allocation.
   New tokens and allocations must name new tasks; each task has at most one
   allocation. An existing task cannot gain another attempt identity.

The result is the existing live-verification report. The pairwise check alone
cannot serialize writers. Two proposals can both be individually valid.

## Durable installation and historical resolution

`extend_swarm_authority_bundle(expected_bundle_sha256, candidate, trusted_keys)`
opens an immediate SQLite transaction. It validates the stored head's full
digest, compares the expected digest, runs the extension verifier using the
store clock, archives the parent, updates the head and commits. Any failure
leaves head and history unchanged. Only one contender using an old expected
head can succeed; another must read and preserve the installed successor.

The archive index is `(task_graph_id, signed_graph_sha256)`. Historical reads
validate strict JSON, the full bundle digest, graph ID and signed graph digest.
The admission hook already receives a graph digest in its request reference;
the new lookup uses it without adding a caller-controlled authority field.
Unknown hashes still fail normal reference binding. The original immutable
insert API remains immutable and idempotent.

The default lookup on other store implementations preserves their existing
single-version behavior. Exact historical resolution is provided by SQLite and
forwarded by the existing layered store. An alternate backend must implement
equivalent protected serialization and historical binding before claiming S1.

## Why concurrent old dispatch remains safe

Let `A_i` contain the uniquely identified allocations in installed graph `G_i`.
Every successor retains `A_i` and its ceilings, and ordinary verification checks
`sum(ceiling(a) for a in A_(i+1)) <= B` for the same pool `B`. Atomic installation
establishes one lineage. Thus the union of every installed allocation equals
the latest allocation set and has total ceiling at most `B`.

Old and new dispatch interleave safely with respect to this declared invariant
because neither path removes an old allocation. Old continuations preserve
their IDs; native custody owns those IDs across graph versions. Changing the
token's graph digest cannot refresh an already consumed continuation. An old
unstarted request still has exact artifacts, subject to ordinary expiry,
current capability revocation, local policy and treaty admission.

There is no cancellation race to solve in an additive extension: no permission
is withdrawn by changing the head. Withdrawal, transfer and reclaim need
explicit closure or fencing authority and cannot be approximated by an archive
lookup. These are conditional arguments about existing components, not a
mechanized proof of the Rust implementation or arbitrary external effects.

## Relationship to the broader claim

S1 supplies a reusable operation for a program that discovers more work after
starting. D1 permits collaborators to be selected and replaced before sealing.
F1 preserves recorded earned financial obligations. Their scarce resources
have distinct custodians and units. The current experiments exercise them as
separate profiles, without claiming one evaluated dynamic funded swarm.

The next integration should reuse those custodians and bind their identities
at explicit handoffs. Adding another authority representation would obscure
which component prevents a double commitment. Independent implementations and
useful-work economics remain necessary to evaluate the broader agentic-web
hypothesis.

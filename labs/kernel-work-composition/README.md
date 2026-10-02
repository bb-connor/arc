# KW1 work-composition experiment

A standalone, deterministic Rust research model for Tasks 2-4 of the
[Chio kernel research plan](../../docs/superpowers/plans/2026-10-02-kernel-breakthrough-research.md).
Read the [common model](../../docs/research/kernel-work/MODEL.md),
[preregistered G1 decision](../../docs/research/kernel-work/G1-DECISION.md) and
[G2 result](../../docs/research/kernel-work/results/G2.md) before interpreting it.

## Reproduce

Requires Rust 1.94.1, rustfmt, Clippy and Python 3. No root workspace build,
network service, credentials, real payment, Lean installation or production
recovery implementation is used. Cargo initially downloads the locked Rust
parser/serialization dependencies unless already cached.

```sh
cargo test --locked --manifest-path labs/kernel-work-composition/Cargo.toml
cargo run --locked --manifest-path labs/kernel-work-composition/Cargo.toml --bin explore
python3 labs/kernel-work-composition/verify.py --record
python3 labs/kernel-work-composition/verify.py --check
```

Run from the repository root. `--record` reruns the full standalone suite,
formatting, Clippy, deterministic explorer and the existing Task 1 provenance
checker, retaining terminal stdout/stderr and exit codes. It hashes executable
sources, lockfile, model, preregistration and fixtures. `--check` only verifies
those retained bytes and successful exits; it is not another execution. The
manifest's repository HEAD is contextual; file hashes bind uncommitted as well
as committed inputs without a self-referential commit hash. Keep original red
logs alongside final evidence. Explorer JSON can also be redirected independently.

## What is implemented

`model.rs` defines visible records and supplied specification ports.
`continuation.rs` constructs named obligations. `baseline.rs` uses separately
written direct service guards over the same facts. `lib.rs` admits commands and
routes them to their owning ports. `exploration.rs` enumerates all permitted
prefixes through depth five for each recorded alphabet, without random sampling
or state deduplication. Repeated visits are schedules, not distinct states.

F01-F16 contain 66 directed variants after five boundary regressions and nine review regressions were added.
Thirty-two named family/arm tests execute every variant and its expected decisions
and state. Additional tests check the E2 observation pair, deny/retry controls,
five candidate removals and bounded schedules. Deny-all and retry-all are negative
controls; B1 is the fully provisioned comparison. No result treats disabling a
baseline safety mechanism as an advantage for Chio.

The oracle holds physical send counts separately. Fault application/ACK choices
are delivered only after a decision. Neither decision API accepts an oracle or
fault. Authentic provider evidence is an explicit input, and the explorer excludes
false first authoritative answers under the qualified E1 truth premise, counting
those excluded prefixes. It still probes contradicting already-terminal records
and wrong-context authentic assertions. This does not establish correctness
against an equivocating provider on which authoritative truth depends.

## Port ownership and assumptions

The aggregate simulator state is a product used by the experiment, not a proposed
shared execution database. The fixed topology and symbolic bindings are the
model's edges; there is no dynamic cross-owner DAG runtime in this lab. All three
modeled native operations originate in P's local authority domain; the child
operation is P's request to the qualified C host. Issuance/envelope ownership is
unique within that local domain across these records, including retained
terminal tombstones. This is not global identity uniqueness across independent
owners or a new shared identity service.

| Commands | Owning decision boundary and visible facts |
| --- | --- |
| approve, change, permission, dependency updates | Qualified owner/environment observations. Issuer identity and semantic basis have already been authenticated by supplied ports. They are not agent APIs to mint approvals or edit policy. |
| finalize, readback, capture, send, crash, rollback, GC | Local authority/native store: original envelope/issuance, operation ownership and serving fence. Crash after capture conservatively retains unknown ownership; no live handle is reconstructed. |
| lookup, evidence | Local connector budget/current authority for a new lookup; separately, exact original-context evidence ingestion. A retained fact does not require a new external call. |
| release, read_result, translate | Qualified local information-flow boundary: canonical owner components, approved source version and exact modeled audience/channel. Translation swaps destination namespace slots, never the canonical owning principals. |
| fund, accept, pay, refund_parent | Selected settlement/verifier ports. Funding reads the settlement domain's local backing ledger, not another owner's private workflow state. Parent and child allocations are distinct. |
| plan, project, settle | Advice/derived projections and narrow local historical settlement. No report or stored request is a live execution permit. |

`bounded` return classification, authenticated claims, declared channel coverage,
qualified receiving host, held reservation and provider closure are supplied
facts from the recovery specification, not checks implemented on arbitrary bytes
here. The model tests how their bindings are composed and used. It does not test
signature algorithms, RFC 8785 parsing, provider-host isolation, crash persistence,
anti-rollback hardware or actual native capture. Numeric keys, revisions and
envelope IDs are symbolic identities, not computed cryptographic digests.

Resource partitions are fixed and disjoint: publication 1, sibling 2, child 4,
recovery lookup 3. Each of the three modeled operations captures at most one unit;
unused partition capacity cannot migrate between workflows. Lookup spends one of
the three recovery units. Budget reset and concurrency probes are within this
fixed profile; general dynamic delegation/allocation needs a later model.
`wallet_reserved` reports total irrevocably allocated backing, including amounts
already paid, so spent money cannot be allocated again. `earned` persists after
payment as a historical entitlement; it is not an outstanding balance.

The candidate and B1 share the supplied transition adapter. Differential parity
therefore cannot catch a shared adapter defect alone. Independent fixture/oracle
assertions did catch capture-crash ownership, globally scoped dependencies and
misleading planner advice; the failing and passing runs are retained. The final
review and future native correspondence must examine this shared assumption.

A generic `release` uses the prepared immutable artifact version 1. Publication
`change` commands alter operation 0's ActionIntent basis, not that retained
artifact. The model does not establish a binding between a newly materialized
publication payload and the generic artifact. Current audience permission still
applies to every result-release entry point, including this generic one; exact
owner coverage cannot replace it. Other channel permissions are fixed supplied
facts in KW1. The final review exposed this audience bypass and cross-operation
identity reuse; both have combined negative/reauthorization or distinct-identity
regressions and dedicated exploration alphabets.

## Evidence limits

These are finite symbolic executions under declared axioms. They establish no
arbitrary-trace composition theorem, unbounded noninterference, implementation
correspondence, deployment independence or measured integration advantage.
State byte sizes are JSON representations of this simulator; guard counts are
source-level diagnostic counts, not comparable CPU work or production latency.
The two implementations may expose the same abstraction and reuse any correct
library. Scientific success remains the preregistered systems result, not parity
or a large test count. The flagship paper stays frozen pending later gates.

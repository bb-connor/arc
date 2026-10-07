# P0 execution plan and acceptance budgets

Scope: contracts and assurance baseline from architecture revision 3. The architecture
package remains a historical specification. This phase adds production data contracts
and pure Rust components; durable recovery, grant v2, native recovery participants,
exact-envelope storage and a live recovery profile remain P1.

## Tasks

| Task | Deliverable | Requirements |
|---|---|---|
| P0-01 | Distinct identifiers/digests, closed effect/release/control vocabulary, checked lists/integers and mandatory profiles | SEC-08, RUST-03, OPS-02 |
| P0-02 | Allocation-free intake preflight followed by the existing signed canonical reader; aggregate limits and bounded public errors | SEC-08, RUST-07, RUST-10 |
| P0-03 | Two pure portable crates, deterministic bounded DAG validation, shared work meter and advisory reduction | SEC-01, RUST-01, RUST-08, RUST-11 |
| P0-04 | Exhaustive owning-kernel request projection; native owner construction/duplication/shared-capture and typed-domain compile failures | SEC-02, RUST-02, RUST-11 |
| P0-05 | Authoritative schemas, generated Rust/TypeScript/Python data bindings, shared malformed-input corpus and effect/authority/knowledge assertions | OPS-03, TEST-01 |
| P0-06 | Owning quality gates, isolated/unified feature and MSRV/WASM checks, measured baselines and complete scoped code review | RUST-06, RUST-08 |

## Resource budgets

These ceilings are declared before performance measurement. Callers can tighten
them; no incoming wire field can raise them. Intake refuses before the existing JSON
reader allocates an object graph. String accounting includes raw encoded escape bytes,
which conservatively bounds decoded strings and serde's unescape scratch. Tool payloads
retain their existing owning parser; P0 metadata accepts only unsigned safe integers.

| Resource | Hard ceiling |
|---|---|
| Input bytes | 65,536 |
| JSON container nesting | 16 |
| Aggregate JSON values and object keys | 4,096 |
| Aggregate encoded string-content bytes | 32,768 |
| Entries in any JSON container | 256 |
| Opaque ASCII identifier | 128 bytes |
| Safe interoperable integer | 2^53 - 1 |
| Dependency steps / dependencies per step | 16 / 16 |
| Trajectory frames | 32 |
| Verification work per evaluation | 4,096 units, caller-owned shared meter |
| Effect cardinality in minimal contract | 1 through 16 |

Every primitive/list is checked before its own growth. The enclosing reader additionally
accounts for repeated/nested collections before typed construction. Budget exhaustion
is irreversible for a work meter. A bounded valid graph can still exceed a tighter
evaluation budget; the result is refusal, not a partial permissive interpretation.

## Performance and error acceptance

Measure 1,000 pure intake/hash/reduction/graph samples after 100 warmups. Measure
64 useful native persistent-store calls after eight warmups, plus eight exact replays.
Retain build profile, toolchain, OS/architecture, fixture identity, sample count, p50,
p95, p99, maximum, elapsed time and observed effects/quota charges. Samples use a
local deterministic counting connector with actual native admission and SQLite stores.

Predeclared pure p95 ceilings: canonical intake 5 ms, framed digest 250 microseconds,
advisory reduction 250 microseconds and 16-step graph validation 1 ms. Benign cases
must have zero errors and matching effect/authority counts. P1's matched native
fixture must remain within 1.20 times P0 native p95 plus 1 ms under the same build
profile, toolchain and host, with unchanged error/effect semantics. This is a local
non-regression budget. It is not a production throughput or cross-host latency claim.
P6 qualifies optimized builds and representative deployment workloads separately.

## Review and evidence contract

Review every handwritten production change and the schema/generation boundaries for
authority manufacture, optional/downgraded bindings, unchecked resource growth,
integer overflow, effect/receipt conflation, request omissions and diagnostic disclosure.
Resolve every discovered P0/P1 severity issue before completion. Retain failed test
logs when correcting an implementation or fixture. Keep the 14 requirement mappings,
command results and source hashes in the final phase evidence. Local implementation,
hosted checks, publication and release qualification are separate statuses.

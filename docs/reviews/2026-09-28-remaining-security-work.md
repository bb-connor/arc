# Remaining security engineering work

Source base: `f16d4e781c`, with the kernel/SQLite batch on `packet/3-retention-accounting`,
`/tmp/arc-security-launch`. Reconciled on September 28 against the September
25-28 plans, review passes, implementation records and current source/config.
The current batch has its own implementation and verification record below; this queue does not establish hosted or release qualification.

## Current inventory

| Work | Current recorded scope | Interpretation |
| --- | --- | --- |
| Decoder classification | 374 `raw-input-baseline` files; control plane 43, runtime core 13; kernel and SQLite baseline owners reviewed | Lexical inventory awaiting semantic disposition, not a vulnerability count. |
| Arithmetic | 122 pending of 638 original entries; 516 classified, including 132 repaired | Historical source anchors include fixtures and code already moved or repaired. All 264 previously pending kernel/SQLite entries have dispositions. |
| Ambient clocks | 157 occurrences at 152 inventory keys | The scoped kernel/SQLite review migrated 22 production reads and classified 90 fixture occurrences. Other owners remain. |
| Negative assertions | Baseline contains 1,264 assertions at 1,181 sites | This is the committed ratchet, not proof that every assertion is security-relevant or currently defective. |
| Tenant runtime matrix | 85 of 85 SQLite tables mapped to exercised families | Signed authorization consumption now has production commit/replay/reopen and substitution evidence. Shared family witnesses do not establish query-by-query mutation coverage. |
| Schema/domain duplication | Wire lock records 200 identifiers declared in multiple files; domain gate has 38 debt entries | Snapshot/growth gates exist; consolidation and domain-shape repairs remain. Domain debt includes both duplicates and shape exceptions. |

Sources: `docs/security/trust-boundary-inventory.json`,
`docs/reviews/2026-09-27-arithmetic-inventory.tsv`,
`scripts/security-clock-inventory.json`, `scripts/negative-assertions-baseline.txt`,
`spec/wire-schemas.lock`, and `scripts/check-domain-separation.py`.
The old 213-negative-assertion count and older arithmetic totals in narrative
sections are historical, not the current queue size.

## Substantial implementation batches

### 1. Kernel and SQLite correctness completion (implemented)

The [owner plan](../superpowers/plans/2026-09-28-kernel-admission-reader-closure.md)
and [execution record](2026-09-28-kernel-admission-reader-execution.md) record the
73 reader-file dispositions, 264 arithmetic dispositions, 22 production clock
migrations and 90 clock fixture classifications. Retained requests now require
v4 authority profiles. Signed authorization consumption has genuine commit,
replay, reopen, substitution and corrupt-row tests through production paths.
Structured local parser causes and reviewed-owner gates accompany the changes.
Use the execution record for the exact terminal checks and residual boundaries.

The next substantial source batch is item 2, followed by item 3's compiler and
secret-ownership work. This continuation does not erase the other queues.

### 2. Remaining authority boundaries and rejection semantics

Continue the reader and proof-result census through control plane, runtime,
broker, core types and then remaining product/protocol owners. Complete the
TCB-wide error-source migration from U1/mechanism C, registered redacted rejection
codes, and specific negative assertions/mutations. Finish remaining clock,
deadline, quota and lease types by owner. Every assertion or decoder needs its
real contract, not a mass syntactic replacement.

References: corrections 1D/1F/3A/4A/4B, Packet 8, packets 10.2/10.3, and
[pass 8 U1](2026-09-26-security-review-pass-8.md). Original proof-type and error
counts in the reviews are historical; do not quote them as today's unresolved
defect count. The eleven registered sealed proof types are bounded delivered work,
not a workspace-wide proof-result audit.

### 3. Compiler enforcement and secret ownership

Finish hardening H1/H3/H4: unsafe-operation and safety-comment lints, `forbid`
where unsafe is unnecessary, the scoped TCB deny set, reasoned exceptions, and
the scoped arithmetic compiler lint. The current workspace lint table still
contains only `unwrap_used` and `expect_used`; a lint-parity gate cannot enforce
rules that have not been enabled. Complete broader H7 secret-wrapper and access
ownership beyond the delivered FROST/private-key boundaries.

Miri configuration, the additive nextest job, lint-parity gate, schema snapshot
gate and ASan/TSan workflows already exist. Preserve them. Remaining qualification
includes unsafe reach, meaningful test coverage and sanitizer expansion to
store/broker owners; the sanitizer crate list currently contains security types,
bounded, supervisor and keyring. A source declaration of a job is not hosted
passing evidence. H6 Verus remains behind FV-E5 promotion; H8 API snapshot and
semver checks belong to publication preparation. No historical-reader compatibility
requirement overrides the user's no-compatibility directive.

Reference: [hardening spec](../superpowers/specs/2026-09-26-hardening-toolchain-spec.md).

### 4. Structural boundaries, helper isolation and declaration ownership

Complete Packet 7's real module/privacy cuts: security ports, broker service,
SQLite security state, control-plane security composition and kernel tests.
The first three still use textual includes. Preserve separate mechanical,
visibility and formatting diffs so behavior changes remain reviewable.

Split `chio-cage-init` from the broad cage package as H11 requires. Its current
budget still measures `chio-cage` at a ceiling of 260 packages and records
network/runtime dependencies as pending removals. Measure the resulting helper
package and artifact separately, then tighten the budget. Consolidate duplicate
schema and domain declarations with their owners and canonical fixtures.
Prefer one authoritative definition and direct imports over new compatibility
layers. These broad structural changes remain separately reviewable successor
work under the existing plan's sequencing.

### 5. Measured storage performance

Packet 9.3/9.5 remains: use statement caching on measured authorization paths,
set cache capacities explicitly and remove redundant hold reads without changing
fencing or transaction semantics. The current budget implementation still loads
the hold twice within a reversal path. Record populated-store before/after cost.

Exact financial aggregation, typed cost columns, indexed query shapes and initial
populated benchmarks already landed. Do not redo them. Broad read-pool/single-
writer migration is explicitly deferred to a separately qualified successor;
it requires crash/anchor verification and measured justification, not a global
mutex replacement. Release-overflow benchmark and release-tier evidence also
remain acceptance work.

### 6. Retention and production-linked lifecycle assurance

Resolve the historical retention stall #1045 using the original workload and
blocked-stack/ownership evidence, then repair its demonstrated cause and retain
a deterministic regression. The property is already enabled. Passing it again
does not explain the old timeout. Run original scale gates after the owner is
stable.

Complete lifecycle trace linkage to actual commit, external effect and receipt
boundaries, and resolve the original larger temporal-model timeout. The finite
model, bounded proofs, focused fuzz targets and cutpoint tests already exist;
their local results do not close the broader liveness/refinement claims.

### 7. Candidate qualification and delivery

The parent plan still requires the genuine `aws-lc-rs` source audit and fork
review, trusted workflow/caller/verifier provenance, signed committed capture,
native x86_64 enforcement, publishable dependency closure, clean-host package
installation and final independent review. Freeze a candidate before the full
workspace, release, formal, fuzz, scale and hosted campaigns. Reconcile exact
source/artifact/check identities before integration and publication. The M11
observed pilot remains a separate operational acceptance boundary.

This reconciliation did not refresh remote PR/check state. These are the parent
plan's outstanding gates; no claim about current hosted success or failure is
made here.

## Delivered work to preserve

Production signed dry-run and authority-mode separation; FROST round-two sealing
with durable recipient acceptance; checked budget exposure/count primitives;
exact financial receipt/analytics handling; shared clocks across the migrated
owners; phase-aware store recovery with its existing local corpus; typed
checkpoint predecessor storage; named signed-reader migrations; and the expanded
tenant runtime matrix all have implementation records. Their scope remains
bounded by those records. Repeating them would not retire the work above.

The [engineering plan](../superpowers/plans/2026-09-26-security-engineering-excellence.md)
and [assurance closeout plan](../superpowers/plans/2026-09-25-security-assurance-closeout.md)
remain the parent acceptance contracts. A reproduced P0/P1 takes priority over
this grouping. The kernel/SQLite execution record contains the local checks for this continuation; broader candidate qualification remains open.

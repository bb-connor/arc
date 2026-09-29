# Remaining security engineering work

Source base: `a3217b9145`, with the four-owner authority batch on `packet/3-retention-accounting`,
`/tmp/arc-security-launch`. Reconciled on September 28 against the September
25-28 plans, review passes, implementation records and current source/config.
The current batch has its own implementation and verification record below; this queue does not establish hosted or release qualification.

## Current inventory

| Work | Current recorded scope | Interpretation |
| --- | --- | --- |
| Decoder classification | 298 `raw-input-baseline` files; core types, runtime core, broker, control plane, kernel and SQLite baseline owners reviewed | Lexical inventory awaiting semantic disposition, not a vulnerability count. |
| Arithmetic | 85 pending of 638 original entries; 553 classified, including 133 repaired | Historical source anchors include fixtures and code already moved or repaired. All 264 previously pending kernel/SQLite entries and 37 scoped runtime/broker entries have dispositions. |
| Ambient clocks | 140 occurrences at 135 inventory keys | The kernel/SQLite review migrated 22 production reads; the four-owner review migrated 15 more and classified 36 fixture occurrences. Native admission, kernel, broker and caller executor clocks now share their configured authority owners; other owners remain. |
| Negative assertions | Baseline contains 1,260 assertions at 1,177 sites | This is the committed ratchet, not proof that every assertion is security-relevant or currently defective. |
| Tenant runtime matrix | 85 of 85 SQLite tables mapped to exercised families | Signed authorization consumption now has production commit/replay/reopen and substitution evidence. Shared family witnesses do not establish query-by-query mutation coverage. |
| Schema/domain duplication | Wire lock records 163 identifiers declared in multiple files; domain gate has 32 shape exceptions and zero duplicate byte domains | Six duplicated byte domains and 37 schema duplicates retired with 43 canonical identity pins. Remaining schema consolidation and domain-shape repairs stay queued. |

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

The four-owner part of item 2 is implemented and locally qualified in the
[authority-boundary record](2026-09-28-authority-boundary-closure.md). Item 2
continues with the remaining product/protocol owners. The compiler and
secret-ownership implementation in item 3 is recorded in the
[September 29 execution record](2026-09-29-compiler-secret-hardening-execution.md).
The four production owners and helper portion of item 4 are implemented in the
[module-boundary record](2026-09-29-security-module-boundaries-execution.md).
Kernel test ownership and the selected declaration consolidation in item 4 are
implemented in the [native clock and test ownership record](2026-09-29-native-clock-test-ownership-execution.md).
This continuation does not erase the other queues.

### 2. Remaining authority boundaries and rejection semantics

Continue the reader and proof-result census through the remaining product/protocol
owners. The core-types/runtime/broker/control-plane baseline readers now have
explicit contracts; their [execution record](2026-09-28-authority-boundary-closure.md)
separates implementation from local qualification. Complete the
TCB-wide error-source migration from U1/mechanism C, registered redacted rejection
codes, and specific negative assertions/mutations. Finish remaining clock,
deadline, quota and lease types by owner. Every assertion or decoder needs its
real contract, not a mass syntactic replacement.

References: corrections 1D/1F/3A/4A/4B, Packet 8, packets 10.2/10.3, and
[pass 8 U1](2026-09-26-security-review-pass-8.md). Original proof-type and error
counts in the reviews are historical; do not quote them as today's unresolved
defect count. The twelve registered sealed proof types are bounded delivered work,
not a workspace-wide proof-result audit.

### 3. Compiler enforcement and secret ownership (implemented)

The [compiler and secret-ownership record](2026-09-29-compiler-secret-hardening-execution.md)
contains the H1/H3/H4/H7 implementation and its exact qualification state:
workspace unsafe-operation, documentation and single-operation lints across all
177 manifests; eligible-root forbids across 165 libraries with 12 named unsafe
boundaries; the production deny set on 25 TCB libraries; checked accounting
arithmetic and conversions; and explicit secret owners for guards, authority,
broker and settlement inputs. Compiler/source calibration and CI wiring prevent
silent removal of the policy. Existing FROST custody protections remain intact.

Remaining assurance is separate from this implementation. Miri configuration,
the additive nextest job, lint-parity gate, schema snapshot
gate and ASan/TSan workflows already exist. Preserve them. Remaining qualification
includes unsafe reach, meaningful test coverage and sanitizer expansion to
store/broker owners; the sanitizer crate list currently contains security types,
bounded, supervisor and keyring. A source declaration of a job is not hosted
passing evidence. H6 Verus remains behind FV-E5 promotion; H8 API snapshot and
semver checks belong to publication preparation. No historical-reader compatibility
requirement overrides the user's no-compatibility directive.

Reference: [hardening spec](../superpowers/specs/2026-09-26-hardening-toolchain-spec.md).

### 4. Structural boundaries, helper isolation and declaration ownership (selected batch implemented)

The September 29 batches convert security ports, broker service, SQLite security
state, control-plane composition and kernel tests into named module/privacy
owners. Mechanical relocation, visibility and formatting remain separate commits.
The kernel cut preserves all 845 scenario bodies and 1,491 compiled tests, migrates
exact selectors and removes the 40,754-line root allowance. Packet 7's remaining
owners are not implied complete by finishing its five ranked starting owners.

`chio-cage-init` is a standalone package with a 72-package normal musl graph and
zero denied dependencies. Shared contracts live in `chio-cage-plan`; the parent
cage retains supervision. The available aarch64 static artifact is measured
separately from native x86_64 enforcement qualification.

The [native clock and declaration record](2026-09-29-native-clock-test-ownership-execution.md)
records the deterministic fixture clock, repaired kernel/SQLite/broker/executor
clock ownership, all six duplicate byte-domain retirements and 37 retired schema
duplicates. All 1,098 recorded wire values are unchanged; 43 identity/canonical
hash fixtures pin the moved identifiers. The remaining 163 duplicated schema
values and 32 domain-shape exceptions need semantic ownership or versioned
protocol decisions. Do not mechanically rewrite their bytes to satisfy a gate.
No new historical compatibility aliases were introduced.

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

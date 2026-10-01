# Remaining security engineering work

Source base: `a3217b9145`, with the four-owner authority batch on `packet/3-retention-accounting`,
`/tmp/arc-security-launch`. Reconciled on September 28 against the September
25-28 plans, review passes, implementation records and current source/config.
Updated through the September 30 trust reader batch. Each batch has its own
implementation and verification record below; this queue does not establish
hosted or release qualification.

## Current inventory

| Work | Current recorded scope | Interpretation |
| --- | --- | --- |
| Decoder classification | 131 `raw-input-baseline` files; core types, runtime core, broker, control plane, kernel, SQLite, selected native/remote/A2A protocol owners, 28 API-protect/CLI/proof-room files, 26 further CLI readers, the remaining 29 CLI readers, all 28 remaining protocol readers, all 35 pinned trust readers and the removed manifest-v1 converter disposed | Lexical inventory awaiting semantic disposition, not a vulnerability count. |
| Arithmetic | 85 pending of 638 original entries; 553 classified, including 133 repaired | Historical source anchors include fixtures and code already moved or repaired. All 264 previously pending kernel/SQLite entries and 37 scoped runtime/broker entries have dispositions. |
| Ambient clocks | 154 occurrences at 149 inventory keys | The kernel/SQLite review migrated 22 production reads; the four-owner review migrated 15 more and classified 36 fixture occurrences. Native admission, kernel, broker and caller executor clocks share their configured authority owners. Four protocol adapters and policy evaluation now use the shared clock; A2A deferred tasks use fenced deadlines. The five remote production readers now use shared clocks. ACP receipt/compliance now migrate the three remaining production readers to the shared fenced owner; the three fixtures stay classified. Other owners remain. |
| Negative assertions | Baseline contains 1,257 assertions at 1,175 sites | This is the committed ratchet, not proof that every assertion is security-relevant or currently defective. |
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
defect count. The fourteen registered sealed proof types are bounded delivered work,
not a workspace-wide proof-result audit.

The [September 29 protocol batch](2026-09-29-protocol-authority-boundaries-execution.md)
reviews 22 decoder owners across MCP edge/adapter, A2A, OpenAI and the shared SSE
reader. It repairs OAuth cache lifetime, task expiry, writer deadline and bounded
stream paths; typed parser and clock failures retain their sources and redacted
codes. Final review repairs serialize OAuth observations, check final advertised
expiry, isolate expired writer commands and retain uncollected task results until
TTL expiry. The 13-package local campaign passes 889 tests. It adds the
cage-required launch proof to the seal gate. Broader semantic
error-source migration and other protocol/product ingress remain queued.

The [native and remote protocol batch](2026-09-29-enforced-native-protocol-boundaries-execution.md)
removes the legacy native launch enum and authorization, all uncaged provisioning
discovery, and the A2A compatibility bypass. CLI/doctor/broker consumers use the
sealed enforced launch. Shell/Docker/SDK/conformance provisioning consumers
require explicit enforcing-host configuration and preserve retained authority.
Hosted integration scenarios use test-only transports at
the remote owner while retaining signed discovery validation. Bounded original-byte
readers, typed local rejection causes, fallible policy clocks and fenced A2A task
retention are implemented. The active-response and budget-test size overages are
removed without cap increases. See the execution record for exact check status.

The [remote lifecycle, ACP and native CI batch](2026-09-29-remote-lifecycle-acp-native-ci-execution.md)
implements those four follow-up tasks: remote clock custody and transactional
session renewal; complete ACP bypass removal; bounded original-byte ACP ingress
and typed local causes; and explicit native CI/SDK/example/conformance fixtures.
Focused local evidence is recorded there. Native x86_64 execution and the
Docker/provider-dependent mini-SWE campaigns remain separate acceptance gates.

The [native consumer, ACP clock/error and OpenAPI batch](2026-09-29-native-consumers-acp-errors-openapi-execution.md)
implements the three ACP/remote/OpenAPI owner tasks. ACP audit, signing and
compliance use a shared fenced clock; semantic failures retain local native
causes; original OpenAPI bytes are bounded before duplicate-aware JSON/YAML
projection. Native x86_64 discovery and the two process recovery campaigns now
pass on the restored OCI worker. Full mini-SWE and the other native consumers
are not qualified by those fixtures.

The [multi-route consumer batch](2026-09-29-native-multiroute-consumers-execution.md)
now implements bounded broker routes, host-owned Docker/provider/repository
adapters, prepared session/operator/repository consumers, scalable retained-history
validation, exact Python/SQLite resources and current-only proof/state readers.
The native baseline, known/unknown crash campaigns and installed consumer matrix
pass. Final large-output/restart/offline-proof acceptance and the eight-case
comparison pass. Its execution record pins source/binary identities and OCI
lifecycle. Do not repeat the already completed
consumer migration or treat these focused campaigns as hosted qualification.

The [September 30 product-reader batch](2026-09-30-product-authority-readers-execution.md)
disposes those 13 CLI process/evidence files, six API-protect files and nine
proof-room files. Original-byte decoding, bounded reads and cumulative collection
budgets, typed local causes, safe public errors, shared fenced clocks, owned
request reservations and sealed proof-result identity are implemented. The unused
permissive nonce middleware is removed. Its record contains the focused evidence
and exact per-reader dispositions.

The [CLI authority and proof-reader batch](2026-09-30-cli-authority-proof-readers-execution.md)
disposes the next 26 CLI readers and retires the manifest-v1 conversion owner.
Its shared input, private custody, exact session, captured export, collection,
clock/deadline and catalog-path contracts are recorded with focused evidence.

The [remaining CLI reader batch](2026-09-30-cli-remaining-readers-execution.md)
disposes all 29 of those readers. Finding/attestation/workflow, buyer/treaty/pheromone
and MCP/runtime/lineage/market use bounded original documents and explicit custody.
The batch removes status-floor v1 conversion, binds publish acknowledgements and
retained market records, caps aggregate failed reads, validates complete archive
namespaces before extraction, and makes relay/reloader time fallible.

The [provider reader batch](2026-09-30-provider-reader-boundaries-execution.md)
disposes those 28 protocol readers. Shared HTTP and Bedrock SDK response custody,
strict original/nested JSON, complete selected stream lifecycles, native error
sources, bounded recorder/replay inputs and process cleanup are qualified locally
with 596 tests. Its record distinguishes existing fixture event contracts from
live-provider interoperability and hosted acceptance.

The [trust reader batch](2026-09-30-trust-reader-boundaries-execution.md)
disposes all 35 pinned trust readers: attestation and buyer imports, custody,
TEE, remote signing, federation, and pheromone evidence. It also binds HTTP/Iroh
positive delivery reports to complete sent batches and replaces the misleading
mobile shape-only verifier API with explicit inspection. The mobile kernel's
other capability/passport readers remain in the baseline; Apple binary artifacts
require a separate rebuild. See the execution record for terminal qualification.

Next execute the 33 guard and security readers pinned in the trust batch's
`next-readers.json`: guard loading/registry and external verdict input, WASM
boundaries, sandbox launch/bootstrap, quarantine/effect journal, keyring and
security-type deserializers. There are 131 baseline files across the workspace,
with zero trust, protocol or CLI baseline files. These lexical counts describe
semantic review debt, not known vulnerabilities. Broader clock/deadline/accounting
and negative-control work remains owner-specific.

Broader semantic error taxonomy, other product/protocol readers, and the
remaining structural/declaration/assurance queues below remain open.

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

Packet 9.3/9.5 is implemented and locally measured in the
[September 29 execution record](2026-09-29-sqlite-performance-retention-execution.md).
Sixteen hot reader functions cache compiled SQL with explicit capacity 64;
reversal, release and settlement reuse their already-validated hold inside the
original transaction. Observed compilation counts fall from four to one and
validation reads from two to one. The paired development-profile run records
all eight paths, including unchanged write-pair intervals and an admission-write
control slowdown. The smaller local population does not qualify release latency
or default-population scaling.

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
does not explain the old timeout. The September 29 diagnostic recovered the
original 256-case configuration and canceled job. Its current-owner slow-sync
run completed 242 cases before the preset 900-second overall limit while still
progressing; stack attachment was denied. Saved counterexamples and deterministic
ownership checks passed separately. These observations do not close the historical
root cause or complete the original-scale gate. Use the new in-process capture for a supported blocked attempt, then repair
demonstrated ownership faults and complete the original scale gate.

The [retention/lifecycle assurance batch](2026-09-29-retention-lifecycle-assurance-execution.md)
adds in-process sync entry stacks and lock ownership through delegated I/O,
watchdog coverage through teardown, and a bounded diagnostic runner. Its
calibration does not close issue 1045 or complete the original-scale gate.

Durable lifecycle linkage now covers real SQLite response commits, native
session-throttle commands and signed stored receipts through owner restart and
effect/receipt acknowledgement loss. The scheduled lane requires generated
artifacts and corruption controls. Other effects, concurrent workers and crash
cutpoints remain outside that fixture. The original 4-authority/8-capability
length-24 query is still unverified; source-pinned inductive progress obligations
at those cardinalities plus finite TLC witnesses replace its expensive operational
rerun. Projection correspondence and the fairness argument remain manual, so the
broader liveness/refinement claim is not closed.

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

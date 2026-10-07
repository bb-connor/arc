# P0 implementation and review

Phase: **P0, contracts and assurance baseline**, architecture revision 3.
Implementation and local acceptance are complete at the scope defined in [PLAN.md](PLAN.md).
The changed code has received a complete authored-change review by Codex. No
independent human review or release qualification is claimed. There are **zero open
P0 or P1 severity code-review findings** in this phase's changes.

The [source-bound verification record](verification.json) contains the exact source
inventory, checks, retained log hashes, host/tool versions and measured baselines.
The architecture requirements registry remains the historical specification;
implementation coverage is recorded here instead of rewriting its previous claims.

## Accomplished tasks

| Task | Implemented result | Acceptance evidence |
|---|---|---|
| P0-01 | Distinct bounded identifiers/digests, safe integers, checked operation references, effect/release/control vocabulary and mandatory deployment profiles | Boundary, stripped-profile, wrong-deployment and cross-context vectors |
| P0-02 | Allocation-free aggregate preflight and exact canonical intake using the existing signed JSON reader | Byte/depth/node/string/container limits, nested duplicates, noncanonical bytes, unsafe numbers and canaries |
| P0-03 | Portable `chio-recovery` and `chio-semantic-contracts`, deterministic bounded DAG validation, irreversible shared work meter and advisory workflow reduction | Node/edge insertion permutations, useful 16-step graph, cycles/missing evidence, exhaustion, cancellation, unresolved admission and partial/withheld results |
| P0-04 | Exhaustive owning-kernel request projection with reviewed unsigned capability semantics, fixed authorization custody and separate native nonce claims | Every request field, nine semantic mutations, seven fixed authorization mutations, original nonce attachment, owner `Send` assertion and compile failures |
| P0-05 | Five authoritative schemas, generated Rust/TypeScript/Python bindings, one shared 41-vector corpus and mandatory trajectory assertions | 6 positive and 35 refusal vectors; generated positive-field round trips; independent assertion mutations |
| P0-06 | Owning build/Clippy/formatting, dependency and feature guards, isolated/unified portability checks, declared/measured budgets and complete scoped review | Retained local logs and hashes, CI dependency guard, Rust 1.93 and WASM matrix, pure/native baselines |

## Requirements crosswalk

These rows cover the P0 implementation slice. They do not claim completion of
the P1 native driver, capture participant, durable records, grant v2 or providers.

| Requirement | Implementation and review conclusion | Retained verification |
|---|---|---|
| SEC-01 | Pure libraries expose data/advice only; no alternate dispatch path or platform dependency was added | Dependency graph guard; native ownership review and foundation tests |
| SEC-02 | Wire evidence cannot deserialize or clone the existing live owner; shared-reference capture fails | Owner compile diagnostics, including E0277 and E0596 |
| SEC-08 | Missing/corrupt inputs, unknown variants, unsafe arithmetic, cycles and exhausted budgets refuse | Shared vectors and bounded verifier tests |
| RUST-01 | The new pure crates have no effectful normal dependencies or ambient state reads | Manifest/feature guard and full pure call-graph review |
| RUST-02 | Existing private live construction remains in the kernel; no new permit type or evidence conversion was introduced | Compile failures and native capture API inspection |
| RUST-03 | Identifier/digest domains are distinct; bounded types have checked construction and closed wire versions | Domain compile failures, boundary tests and schema vectors |
| RUST-06 | Owning lint/build/source-size/format/dependency checks pass without weakened lint baselines | Clippy with `-D warnings`, build, formatting, registry and direction checks |
| RUST-07 | Identifiers/digests and request projection redact Debug; new public recovery errors are closed reason codes | Canary tests, error-boundary and tracing review |
| RUST-08 | Declared Rust 1.93 substrate/pure MSRV, alloc-only isolation, additive std, WASM and deterministic results are preserved | Isolated/unified compiler and metadata matrix; existing proof inputs reviewed; Kani execution limit below |
| RUST-10 | Resource preflight runs before JSON graph allocation; visitors reject overflowing elements before decoding; repeated graph work shares one irreversible meter | Aggregate input limits, probe visitor and exhaustion tests |
| RUST-11 | Planner vocabulary and workflow directives are non-authorizing; every native request field has explicit classification and original digest meanings remain unchanged | Exhaustive destructure, field mutations and typed-domain tests |
| OPS-02 | Required enforcement inventory and deployment identity cannot be omitted or downgraded; matching metadata does not enable a deployment | Missing participant, wrong deployment and strict-nonce profile refusal controls |
| OPS-03 | Authoritative closed schemas and one shared corpus cover malformed, unknown and absent recovery bindings | Rust raw intake plus Rust/TypeScript/Python parsed-schema validation |
| TEST-01 | Trajectories require effect count, consumed authority, remaining budget, retained knowledge and original native/process digests | All six independent assertion mutations; actual endpoint/quota baseline |

## Security and Rust review

Reviewed every handwritten production module added or changed, each schema and
fixture boundary, the relevant native owner/capture APIs, and generated artifact
deltas. Existing Python model changes are schema-fingerprint/header updates; the
root export list adds recovery models while retaining every previous export and
imported identity. New recovery modules come from the pinned generator. Generated Rust remains in
the repository's existing quarantined generated surface. Portable bounded APIs
are the hand-maintained modules, not generated unbounded vectors.

Review conclusions:

- There is no signing, provider dispatch, grant consumption, store mutation,
  clock/environment read, RNG call or asynchronous runtime in the new pure libraries.
- `Unknown`, in-flight, pending caller reports and unresolved admission retain
  their original identity through cancellation. Settled partial/failed effects
  and withheld/denied output recommend projection, never another submission.
- Mandatory authority-domain/tenant/process claims remain untrusted. Host scope
  comparison is explicit, and successful parsing/profile matching creates no owner.
- Resource accounting precedes allocation of the JSON graph; raw escape bytes
  conservatively bound serde unescape scratch. Depth uses a fixed stack. List and
  identifier construction is checked, arithmetic is bounded, and budget exhaustion
  is terminal, including an exact debit to zero followed by a zero-unit charge.
- Stable topological ordering ends in opaque step ID. Node insertion and dependency
  list insertion order do not change decisions. Repeated dependencies still charge
  work and duplicate identities refuse.
- The request boundary exhaustively destructures all 16 fields without `..`.
  Unsigned capability claims are reviewed and the complete signed artifact is
  retained. One native-owned nonce claim stays separate from the reviewed semantics.
  No legacy process/native hash algorithm, owner constructor or capture method changed.
- Public errors retain no input/parser text. Debug never displays protected identifiers,
  digests, arguments, signatures or authorization artifacts from these new surfaces.
- Generated models describe data. They are not complete admission validators:
  cross-field schema constraints, duplicate-rejecting canonical intake, aggregate
  budgets, scope binding and native authority checks remain mandatory owning gates.

Corrections made during review included unresolved-admission advice, accepting valid
dependency permutations, checked standalone operation references, terminal exact-zero
work exhaustion, coarsened projection errors, and explicit fixed-authorization mutation
coverage. Recovery-specific definition names prevent generated Python helper classes
from renaming existing security exports. The full previous root export/import inventory
is retained and has a regression test. The profile's mandatory-membership constraints were moved to its top-level
composition so the pinned Rust generator produces usable types; authoritative schema
validation still enforces every constraint. Positive generated round trips prove no
field stripping. No generator pin or Rust lint allowance was relaxed.

Two pre-existing owning-check obstacles were corrected narrowly: a collapsible nested
condition in `chio-quarantine` with identical short-circuit behavior, and a conformance
test comparing canonical state paths with macOS's `/var` temporary-path alias. The
related library tests pass. The generated Docker workspace manifest/lock was refreshed
from its canonical root inputs, including existing overflow/lint policy drift.

## Verification scope and limits

Local portable/related unit suites pass **559 tests**. Contract/generated integration
suites pass **26 tests**, owner/domain doctests pass **12 tests**, and native process
foundation targets pass **4 top-level tests**. The explicit native benchmark passes
separately. TypeScript's shared-schema target passes **42 cases**, Python's focused
generated/model suite passes **121 cases**, and strict TypeScript source/test checking
passes. Exact counts and final commands are in the verification record.

All three codegen drift checks pass with their existing pins. The Python generator
was run from the exact upstream `0.34.0` source because local uv resolution/network
access failed. Its verified Git blob/file hashes and task-local invocation adapter
are recorded in [generator provenance](evidence/python-generator-source.json). No
production tooling pin changed. TypeScript runtime tests used locally available
Vitest 4.1.8, not a fresh install of the package lock's 4.1.11; Ajv and TypeScript
versions are recorded. Hosted package-lock installation is a separate unchecked gate.
TypeScript checking resolved current checkout sources and explicit Node declarations
instead of relying on stale installed package declarations. Its retained configuration
is [here](evidence/typescript-compile-config.json); copy it to `target/` to reproduce
the same relative paths. Task-local node_modules links were removed after verification.

Two broader verification results remain unqualified:

- The full existing kernel library suite passed **1,447 tests**; **12 HTTP payment
  tests** failed at listener creation with sandbox `EPERM`. Their complete failure
  log is retained. No test was disabled or weakened to turn this into a green run.
- Kani 0.67.0 could not start: its installed toolchain link targets absent
  `nightly-2025-11-21-aarch64-apple-darwin`. Rust 1.93 builds pass, and existing proof
  harnesses/tool pins were not changed. A new Kani execution or formal proof is not
  claimed; proof-tool execution compatibility remains unverified in this environment.

These are verification limits, not unresolved P0/P1 findings in reviewed recovery
code. Local phase acceptance must not be presented as a fully green workspace,
hosted CI, a supported live recovery profile, production latency qualification,
deployment or public release. No commit, push or publication was performed.

## Baseline and next phase

Both baselines are local debug builds with the retained toolchain/host/fixture identity.
Pure intake/hash/reduction/16-step graph p95 values satisfy their predeclared ceilings
with zero errors. The native fixture executed 8 warmups and 64 measured useful calls,
plus 8 exact replays: **72 external effects and 72 logical-call quota charges**, with
no extra effect or charge during replay. Timing values and the unchanged P1 comparison
formula are recorded in verification.json. These numbers are not production throughput.

Proceed to [P1: exact durable recovery](../../10-delivery-decisions.md). Start with
sealed native effect observations and authoritative no-effect/admission-intent closure,
then protected exact-envelope custody and the complete process reservation/nonce
bridge. Integrate recovery-bound grant v2 and the native capture participant into
the existing ownership path. Finish the support-ticket-to-public-issue slice with
fresh-process recovery, all admission/capture/effect/ack cutpoints, partial settlement,
authorized output replay and proof that no hidden resubmission occurs. Retain the
P0 contracts, resource ceilings and baseline comparison while adding that behavior.

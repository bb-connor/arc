# Security launch: current execution status

Updated 2026-09-11. This is the short working index for the accepted
[execution plan](launch-execution-plan.md), not another qualification campaign.
Candidate: `/tmp/arc-security-launch`, `security/launch-integration`, base HEAD
`8b9f9243905dfa61acac82d83438684940777fe3`. The accumulated 722-path checkpoint
was committed and pushed as `7e54c14a60` to
[draft PR #1117](https://github.com/bb-connor/arc/pull/1117) under the user's
2026-09-11 authorization. Follow-up implementation continues on the same branch.
This is not merge or release approval.

## Milestone control

| Milestone | State / missing acceptance | Next action / blocker | Evidence |
| --- | --- | --- | --- |
| M0 | Consolidated for implementation | Keep this index current; no independent cleanup campaign | Requirement and review maps below |
| M1 | In progress; native output classification is now connected to operation-owned taint preparation in shared release; native connector still closed | Complete capture-to-live-owner and frozen execution/return coupling, then native use/declassification/nonce custody | Current M1 checkpoint below |
| M2 | Pending real native invocation | Process cutpoints and recovery against M1 | Existing reply-fault coverage is partial evidence only |
| M3 | Missing authenticated caller start and durable delivery | Preserve lost-report counterexample until real handshake fixes it | [Caller design](../superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md) |
| M4 | Consumer qualification incomplete | Inventory positive supported paths and required startup denials after M1-M3 | [Original requirement ledger](launch-plan.md#requirement-ledger) |
| M5 | Swarm is a Disabled-profile integration smoke | Bind issued capability identities, shared budget and enforced cage | [Swarm limitations](../../examples/reference-swarm/README.md) |
| M6 | Components present, integrated topology unqualified | Compose keyring, broker, cage and receipts; designated runner needed | Enterprise ledger and original plan |
| M7 | Active-defense components present, composed paths unqualified | Complete flow, response and rollback acceptance in controlled profiles | Active-defense ledger and original plan |
| M8 | Retention, scale and operational recovery unqualified | Real campaigns after lifecycle integration | Retention #1045 and million-receipt gates remain required |
| M9 | Entry packages unpublished and external consumer unqualified | Package dependency closure and clean install after M4-M8 | Three intended entrypoints remain `publish = false` |
| M10 | Not release qualified | Local gates, audits, authorized exact-candidate hosted and publication steps | Candidate lacks passing exact-head hosted qualification |
| M11 | Not started | Authorized observed pilot and signed promotion stages | [Numeric operator contract](active-defense-rollout.md) |

## Complete original-requirement routing

`Carried` means implementation exists according to the original ledger, not that
its entire acceptance gate has passed. `Partial local` means linked local evidence
exists but the complete composed requirement remains open. No row is externally
qualified for this candidate. This routing preserves all original tasks/phases;
the normative plans retain their detailed acceptance requirements.

| Protocol task | Current state | Owning milestone |
| --- | --- | --- |
| 1 Characterization | Carried; final affected regressions pending | M10 |
| 2 Signed aggregate root | Carried; bound swarm acceptance pending | M5 |
| 3 Capability negotiation | Carried; consumer parity pending | M4 |
| 4 Composite holds and mutation | Partial local; complete native composition pending | M1 |
| 5 Durable SQLite and remote authority semantics | Partial local; crash/recovery qualification pending | M2 |
| 6 Admission ordering and signed terminal projection | Partial local; native execution and caller handshake missing | M1, M3 |
| 7 Policy-owned threshold requirements | Carried; composed action acceptance pending | M7 |
| 8 Bounded approval verification | Partial local; combined native capture passes, complete invocation pending | M1 |
| 9 Durable replay and collection | Partial local; composed recovery and response pending | M2, M7 |
| 10 Federation threshold compatibility | Carried; final native authorization coupling pending | M1 |
| 11 Existing bounded runtime evidence | Partial local; verified validity is checked at native capture and commit, complete invocation pending | M1 |
| 12 Authoritative schemas and four-language generation | Carried; final changed-wire parity pending | M4 |
| 13 Adapter preservation | Partial local; complete consumer inventory pending | M4 |
| 14 Cross-implementation conformance | Carried; exact-candidate execution pending | M10 |
| 15 Formal and concurrency checks | Partial local; full required campaigns pending | M10 |
| 16 Final release gate | Missing exact integrated qualification/publication | M9-M11 |

| Active-defense phase | Current state | Owning milestone |
| --- | --- | --- |
| 0 Provenance and dependency direction | Carried; exact-candidate gate pending | M10 |
| 1 Portable labels and lattice | Carried; exact-candidate portable gate pending | M10 |
| 2 Authenticated manifests and bridges | Partial local; constructor/consumer parity pending | M4 |
| 3 Durable security stores | Partial local; native recovery and retention pending | M2, M8 |
| 4 Flow and one-shot declassification | Partial local; native custody/release missing | M1 |
| 5 Kernel adapter composition | Partial local; complete positive profiles pending | M4 |
| 6 Deception and tripwires | Carried; integrated pre-effect/raw-output acceptance pending | M7 |
| 7 Temporal correlation | Carried; authenticated bounded replay acceptance pending | M7 |
| 8 Affected sets, approvals, effects and rollback | Carried; composed failure/overlap acceptance pending | M7 |
| 9 Scheduler and posture | Carried; composed TTL/restart acceptance pending | M7 |
| 10 Receipts and adversarial evidence | Partial local; source-bound full campaign pending | M10 |
| 11 Migration and promotion | Tools present; operational qualification missing | M8, M11 |

| Enterprise phase | Current state | Owning milestone |
| --- | --- | --- |
| 0 Source and enforcement-stack audit | Carried; actual designated platform pending | M10 |
| 1 RFC 6962 consistency | Carried; exact-candidate gate pending | M10 |
| 2 Key log and witnessed rotation | Carried; integrated topology pending | M6 |
| 3 Rotation verification | Carried; integrated signing/replay pending | M6 |
| 4 Broker authorization | Carried; integrated original-operation capture pending | M6 |
| 5 Broker custody and execution | Carried; integrated no-secret/no-fallback acceptance pending | M6 |
| 6 Manifest resource compilation | Carried; real confined swarm pending | M5 |
| 7 Linux enforcement | Carried; actual designated platform pending | M6 |
| 8 Cage-init and supervision | Carried; complete process topology pending | M6 |
| 9 Production composition and receipts | Integrated acceptance missing | M6 |
| 10 Schemas, adversarial evidence and migration | Partial local; exact-platform/migration qualification pending | M8, M10 |

## Execution-profile support contract

These are implementation boundaries, not release approvals. All selected runtime,
governed-approval and DPoP participants are mandatory; absence is never permission
to silently switch authority. Original-operation recovery belongs to the durable
admission coordinator and fenced authoritative store, not a decoded receipt.

| Profile / public entrypoint | Mandatory authority beyond capability, guards and budget | Recovery / release policy | Current limitation |
| --- | --- | --- | --- |
| Ordinary `evaluate_tool_call*` | Installed runtime, credentials and selected security lifecycle | Coordinator/store; output guards and current security release | Legacy paths exercised; native lifecycle unfinished |
| Nested `evaluate_tool_call_operation_with_nested_flow_client*` | Same participants, plus nested/session binding | Same original-operation owners; nested return finalization | Complete native success path unfinished |
| Nonce-required ordinary/nested | Operation-owned nonce and authenticated delivery identity | Durable nonce plus admission owner; uncertain outcomes retain accounting | Native nonce composition missing |
| Governed ordinary/nested | Exact request-bound approval quorum and replay custody | Exact fenced claim disposition; expiry checked before capture | Combined native capture and public nested credential transport exercised; full invocation unfinished |
| Native-flow security-context entrypoints | Original native binding, full-source join, policy, egress/use custody and live capture authority | Native owner; current output policy, not historical capture | Capture-only checkpoint denies before connector; declassification unsupported |
| Brokered invocation | Broker attempt, delegated parent/family quotas, witnessed identity and confined connector | Broker and admission original-operation reconciliation | Integrated enterprise topology unqualified; no direct fallback permitted |
| Caller `reserve_caller_execution_blocking` / `reconcile_caller_execution_blocking` | Nonce/caller identity and complete authenticated start/delivery contract | Executor durable claim plus original admission owner | Start handshake missing; credential/security profiles explicitly denied; lost-report counterexample open |

## Dependency-ordered review packages

Integrated checkpoint `7e54c14a60`: 722 accumulated paths, 11 slices, zero
unclassified. This is the checkpoint delta, not subsequent incremental work.
The script's `classify` function was applied to `git diff --name-only HEAD` plus
all untracked paths. Its commit-only `--base-ref HEAD` mode does not inspect WIP.
Classification is a review index, not permission to merge independently unsafe
intermediate states. Each package includes its invariant tests and schema effects.

1. Authority/wire contracts: `core-protocol` (2), authority types from
   `kernel-runtime`, and their canonical vectors.
2. Durable ownership: store portions of `storage-control-observability` (410),
   exact fences, replay, capture and recovery; keep dependent port/type changes.
3. Kernel lifecycle: remaining `kernel-runtime` (225), credential custody,
   native execution, caller start and terminalization. Review coupled kernel/store
   fixes together when separation could introduce a bypass or refund.
4. Security composition: `security-runtime` (8) and control-plane adapters from
   the storage/control slice; live policy versus retained evidence boundaries.
5. Consumers and runnable product: `adapters-edges` (10), `sdks-examples` (28),
   `products-editors-bench` (7). Positive promised profiles and startup denials.
6. Qualification and claims: `attestation-conformance-formal` (8),
   `ci-tooling-workspace` (13), `release-ops-evidence` (2),
   `architecture-docs` (9). No source hash is a new proof.

The review packages describe one integrated checkpoint in draft PR #1117, not
independently mergeable layers. Kernel ports, physical storage contracts and their
consumers are coupled. Keeping them together preserves the locally checked tree;
subsequent milestones can be reviewed as incremental commits. The prior local
checks below are retained evidence, not fresh exact-commit hosted qualification.

## Current M1 checkpoint

The native capture path now carries bounded validity from the configured runtime
verifier into the physical transaction and checks it again before commit. The
verifier reconstructs the original plan from verified artifacts, including signed
treaty/swarm evidence and the bilateral capability lease. Historical metadata is
not used as a substitute for verification or live credential custody.

The real SQLite control-plane fixture captures runtime, governed approval and
DPoP together for ordinary and public nested calls, local and egress, retaining
all three original claims and the exact ledger after reopen. Missing proof or
changed approved intent denies before capture. The connector remains deliberately
closed at this checkpoint.

The combined egress test exposed repeated DPoP source verification within a read.
Source records already verified against the complete global projection are now
reused within that same read. There is no cross-transaction cache, skipped
integrity check, changed canonical format or extended policy deadline.

Focused evidence: `/tmp/chio-native-combined-credentials-retained-source.log`
(two tests, including both local and egress); signed-runtime evidence:
`/tmp/chio-native-runtime-validity-tests-final.log` (three tests); validity type:
`/tmp/chio-native-runtime-validity-unit.log` (one test). The affected DPoP suite
passed 63 tests (`/tmp/chio-native-runtime-dpop-regressions.log`); all-target strict
Clippy passed the six affected packages before the nested API change. These tests
do not qualify the missing native output/recovery lifecycle or a real pilot.

The compatible public nested API now accepts explicit `NestedToolCallProofs`
without changing session wire types. Five real SQLite tests pass blocking and
current-thread async invocation, replay custody, missing/substituted proof denial,
nonce retry and context-authority error cleanup. The cleanup test reproduced an
in-flight leak before the fix. Native declassification remains explicitly denied,
not silently dropped or activated by supplying its artifact.

The composed nested egress test exposed a stack overflow during bounded history
verification beneath the nested evaluation future. Boxing that future once at
the evaluation boundary fixes all four nested mode/egress combinations without
increasing thread stacks or changing verification limits. The four-test composed
suite then passed (`/tmp/chio-native-combined-public-nested-proofs-repeat.log`).
One earlier ordinary egress run hit the unchanged policy deadline; keep
`/tmp/chio-native-combined-public-nested-proofs-fixed.log` as timing-failure
evidence. A repeat pass does not establish cold-start or sustained-load headroom.

After session cleanup, focused tests passed: five public credential cases
(`/tmp/chio-public-nested-proofs-final.log`), seven existing nested-flow cases
(`/tmp/chio-public-nested-compatibility-final.log`), three signed-runtime cases
(`/tmp/chio-native-runtime-signed-validity-final.log`) and the validity unit test
(`/tmp/chio-native-runtime-validity-unit-final.log`). The final four-test composed
rerun also passed (`/tmp/chio-native-combined-credentials-final.log`, 105.97 s).
All-target strict Clippy passed kernel, runtime-core, runtime, SQLite, control
plane and xtask; production-library checks passed the five runtime packages.

Source closeout passed: 20 formal-mirror checker tests, 192 matching source-drift
entries, and generated coverage matching 58 rows / 168 artifacts. All 182 prior
entries and their symbols remain present, with unchanged top-level claim metadata.
No hash placeholder remains and no source anchor is a new proof. Formatting,
explicit include-file formatting, file hygiene, structural checks for 57 exact
test inventories, the security CI contract and whitespace checks pass. Logs use
`/tmp/chio-native-handoff-*`. The required AST-only graph refresh passed; no
external model or publication was invoked.

The next implementation must introduce actual operation-owned native output
taint/use and release custody, coupled to a frozen pre-dispatch return context.
The original runtime-expiry recheck was implemented, but its clock sample still
preceded additional verification. The physical-commit checkpoint below records
the subsequently reproduced gap and its follow-up fix.
The input-join journal currently permits one pre-budget join per operation; it
cannot be reused as a post-output writer by replaying history or changing an
operation identifier. Native nonce/declassification support remains required.
Cold-start and sustained-load timing qualification remains required; no deadline
was extended to accommodate this host's unoptimized build.

Tracing the native release integration exposed a shared finalization deadlock:
the kernel held its mutation sequencer while invoking the live release owner.
The regression reproduced the failure. Release now runs outside that sequencer;
the checkpoint write resumes serialization and revalidates the original lease,
serving owner and exact outcome/evaluation before terminal publication. It never
renews a lease on the strength of callback success. The real SQLite release suite
passes 21 tests, including ordinary/public nested blocking and async reentry,
checkpoint expiry and three process-crash boundaries. Four monetary release tests
also pass, preserving settlement ordering and no repeated capture/refund. Evidence:
`/tmp/chio-release-sequencer-{red,suite,payment}.log`. The complete release suite is
now included in the flow gate's exact inventory. This fixes a prerequisite for M1;
it does not activate native dispatch, implement its output journal, or close M1.
The two reentry tests passed again after test-worker cleanup, and strict
all-target Clippy passed kernel and SQLite. The source-drift gate matches all
192 entries, preserving every prior anchor/symbol and all claim metadata; only
two source fingerprints changed. Regenerated proof coverage matches 58 rows /
168 artifacts. The 58-group flow inventory contract passes, and its release
group exactly matches the 21 executed test names. These are affected-boundary
checks, not full workspace, native-profile or launch qualification.
Formatting, file hygiene, whitespace and the AST-only graph refresh also pass;
the graph log is `/tmp/chio-release-sequencer-graph.log`.

The original live release owner now receives the exact post-guard output through
`DurableSecurityReleaseContext`. Its private constructor validates the payload
against the durable signing preimage, outcome, evaluation and dispatch identity.
Stream classifiers receive actual redacted chunks as well as their signing
preimage; classifying concatenated chunk digests would not inspect the payload.
The context is borrowed, non-cloneable and non-serializable, with a redacted Debug
implementation. It conveys neither current native state nor mutation authority.
Existing output-independent release owners retain their compatible default.

The full SQLite release target passes 25 tests, including actual ordinary/nested
blocking and async output-aware release, value/stream redaction, current refusal,
panic containment, one effect/capture, signed success and terminal replay. Two
private-boundary tests reject substituted preimages, values, stream order,
dispatch identity and evaluation history. Logs:
`/tmp/chio-output-release-suite.log` and
`/tmp/chio-output-release-binding-tests.log`. Initial failures were in the new
test redactor's output-envelope encoding, not qualified native execution.
That shared-path work established the output context used by the native journal
checkpoint below. It did not activate native dispatch or close M1, and did not
change schema, migration or release scope.
Four settlement/release regressions also pass, as does strict all-target Clippy
for kernel, SQLite and control plane. Source-drift validation matches 193 entries:
all 192 prior entries, their symbols and claim metadata are preserved, with one
new output-context source anchor (not a proof of native output enforcement).
Generated coverage remains 58 rows / 168 artifacts. The 59-group flow inventory
contract passes; the two affected groups match all 25 and two executed test names.
Formatting, Rust file hygiene and whitespace checks pass. Evidence uses
`/tmp/chio-output-release-*`; the AST-only graph refresh also passed
(`/tmp/chio-output-release-graph.log`). These are affected-boundary checks, not
full workspace, native-profile or launch qualification.

### Native output journal checkpoint

The native writer now persists one output taint intent for the exact captured
operation and resolved physical outcome/evaluation. It propagates all current
principal, lineage and session restrictions in the same restricted transaction,
with original-lease checks through physical commit. The separate immutable
output journal participates in the global anchor and ordered row reconstruction;
it does not rewrite input history or create a release checkpoint. Exact retries
return historical evidence, not current policy or a new live owner.

The portable kernel store interface defaults to denial. SQLite readback returns
the current operation and optional journal together in one fenced snapshot.
Schema v32 adds an empty output journal to a verified v31 predecessor without
rewriting its history. Partial future catalogs and damaged current catalogs deny
instead of being repaired. No populated deployment has been migrated.

The physical-journal fixtures use real native capture but synthetic returned
payloads and resolved evaluation. They do not execute a native connector or
qualify output classification. The shared async entry now owns its large core
future on the heap before receipt scoping and blocking bridges. Boxing only at
the outer bridge was insufficient for the larger substitution fixture. The
revised boundary passes all six journal tests without diagnostic instrumentation,
increased thread stacks or changed policy deadlines
(`/tmp/chio-native-output-final-journal.log`, 140.28 s).

The complete 54-test native-policy run is not qualified: combined ordinary and
nested egress capture expired at the final physical-commit policy check, and
the later substitution test aborted that initial run with the now-fixed stack
overflow. The isolated four-test credential rerun retained both expiry failures
(`/tmp/chio-native-output-combined-stage.log`). Final expiry enforcement remains
unchanged. A narrow same-transaction credential-selection reuse experiment did
not fix this and was removed; no speculative cache or relaxed deadline remains.
This preserves the previously observed timing issue as an open acceptance gate.

The exact native storage group passes 87 tests, including all three new output
schema cases (`/tmp/chio-native-output-storage-inventory.log`). Four global
schema migration tests pass (`/tmp/chio-native-output-global-schema.log`). All
25 shared-release tests also pass, including process crashes, expired leases,
ordinary/nested reentry, redacted value/stream output and terminal replay
(`/tmp/chio-native-output-shared-release.log`). These checks do not turn the
failed full native-policy gate into a pass.

Strict all-target Clippy and production-library checks pass for kernel, SQLite
and control plane. The formal source gate matches 198 entries, preserving all
193 prior entries, their symbols and claim metadata with no hash placeholders.
Generated coverage still matches 58 rows / 168 artifacts. Formatting, explicit
include-file checks, Rust file hygiene, whitespace and the 59-group inventory
contract pass. These remain local affected-boundary checks, not complete
workspace, designated-platform or launch qualification. The AST-only graph
refresh log is `/tmp/chio-native-output-graph.log`.

The remaining M1 work is the
original live native output owner and classifier, frozen return/execution
coupling, native use/declassification/nonce composition and current release
checks. Retained journal records must never be used to recreate those owners.

### Physical-commit expiry checkpoint

The real-clock regression reproduced a capture committing after its verified
runtime evidence expired (`/tmp/chio-native-commit-expiry-red.log`). The existing
check sampled time before additional credential and policy verification. The new
boundary samples again after that work and rechecks the original lease,
capability, runtime, approval, DPoP and policy time contracts before physical
commit. Immutable credential data remains confined to the transaction-bound
witness; no source validation, owner check or deadline is removed.

The regression pauses after actual state verification until the original signed
runtime evidence expires. It changes neither evidence nor clocks and must prove
atomic rollback of dispatch and quota capture with all three claims retained.
The fault is available only under admission test support, configured in a TEMP
table, and absent from the production path. The exact native-policy inventory
now contains 55 tests. Its complete local run finished with 53 passed, two failed
and none ignored (`/tmp/chio-native-commit-expiry-policy.log`, 1231.86 s). Both
failures are the previously observed ordinary/nested combined-egress policy
expiry at physical commit. All six output-journal tests passed without a stack
overflow. This is not a passing native-policy gate.

The expiry regression was then strengthened to require an observation marker
from the actual after-verification pause. An earlier expiry cannot satisfy the
test, and the marker never manufactures a rejection or changes success. The
final exact rerun passed (`/tmp/chio-native-commit-expiry-final.log`, 64.54 s).
The complete 55-test run precedes this test-only observation refinement; no
second complete run is claimed.

Follow-up qualification passed: all-target strict Clippy for kernel, SQLite,
control-plane and xtask; production-library checks for kernel, SQLite and
control-plane; formatting and Rust file hygiene without new allowances; the
59-group flow inventory and security CI contracts, including the latter's
mutation tests. Source-drift validation matches all 198 entries, preserving every
prior anchor and claim metadata; generated coverage matches 58 rows / 168
artifacts. All 22 formal-mirror tests passed. No new proof claim is made. The
required AST-only graph refresh
completed (165,358 nodes / 431,042 edges); its unchanged visualization cap skipped
HTML generation. Logs use the `/tmp/chio-native-commit-expiry-` prefix and
`clippy`, `production`, `formal-check`, `formal-tests`, `coverage`, `fmt`,
`hygiene` and `graph` suffixes with `.log`.

An earlier isolated ordinary combined-capture diagnostic passed, with and without
egress (`/tmp/chio-capture-timing-profile.log`), but that does not close the
previously observed load-sensitive expiry failures. Temporary timing probes were
removed. Native invocation and the rest of M1 remain incomplete.

### Native output preparation checkpoint

The shared durable release path now verifies the original live release handle's
dispatch binding before native output preparation. The kernel gives the selected
native hook a non-serializable writer borrowed from the original finalization and
its existing lease. The hook supplies only a classified label, not a replacement
operation, identity, clock, lease, output or evaluation. Legacy hooks default to
unsupported native output preparation, with no fallback to legacy flow stores.

`NativeFlowResolver` classifies the verified post-guard value or all ordered stream
chunk payloads, not the stream signing hashes or the pre-redaction raw value.
Classifier identity and payload binding use the existing category verifier;
operator and authenticated manifest output floors remain mandatory. Current
inherited taint is joined atomically by the native writer. Classification and
workload-identity callbacks run outside the mutation sequencer. Neither
preparation nor final release renews the original lease after its callback.

A callback must complete exactly one acknowledged and independently read-back
output join. Missing, repeated, failed or suppressed writes and callback panics
deny completion. Already committed monotone taint is retained on subsequent
failure. A taint acknowledgement still does not grant output release: the original
live lifecycle permit and durable release checkpoint remain required afterward.

Tests use real native capture and SQLite outcome
records with synthetic resolved values/streams. Feature-only helpers exercise the
same preparation and payload validators, but create no live release owner,
acknowledgement, signed terminal receipt or connector permission. The native-policy
declaration now has 58 tests; the focused output preparation/journal group has
nine. No new full native-policy or native connector qualification is claimed.

The initial nine-test run finished with eight passed and one failed
(`/tmp/chio-native-output-preparation-inventory.log`, 237.04 s). All six existing
journal cases passed. The new positive fixture incorrectly reused an input-only
classifier field path (`/safe`) for its resolved output; classification correctly
denied it. The fixture now reports an exact output byte range. The expiry case
also requires observation of the actual lease-expiry rejection, so a classifier
error cannot satisfy it. Final review moved workload-identity validation outside
the mutation lock and added a second callback reentry probe. The final exact
three-test preparation run passed with none ignored
(`/tmp/chio-native-output-preparation-callback-final.log`, 112.04 s), including
classification and workload-authority reentry, value/stream payload binding,
real-clock lease expiry and missing/double/suppressed/panicking join callbacks.
These are separate runs, not a claimed second complete nine-test run.

The eight dispatch-credential, two release-output-binding and 25 shared-release
recovery tests passed (`/tmp/chio-native-output-shared-regressions.log`). These
shared cases do not select native output preparation; its final callback change
is covered by the separate three-test rerun above. Strict all-target Clippy passes
for kernel, SQLite, control plane and xtask; production-library checks pass for
kernel, SQLite and control plane. Final logs use `/tmp/chio-native-output-` with
`clippy-final`, `production-final`, `formal-check-final`, `coverage-check-final`
and `fmt-final` suffixes and `.log`.

All 22 formal-mirror checker tests pass. Source-drift validation matches 200
entries, retaining all 198 prior entries, their symbols and claim metadata with
no hash placeholders. Coverage remains 58 rows / 168 artifacts. Formatting,
Rust file hygiene, the 59-group flow inventory and security CI contract/mutation
checks pass. The AST-only graph refresh passes
(`/tmp/chio-native-output-preparation-graph.log`); HTML visualization remains
skipped at the unchanged repository size limit. These are affected local checks,
not full workspace or exact-head hosted qualification.

Still missing: capture-to-original-live-owner issuance, complete frozen
participant/signing context, native flow-use/declassification/nonce composition,
current final-release policy and actual ordinary/nested native execution. The
previous two combined-egress deadline failures remain open. This checkpoint does
not remove any native dispatch denial, change a schema, or add a proof claim.

## Retained evidence and external prerequisites

Automatic PR checks for checkpoint `7e54c14a60` exposed additional M10 work.
These are results for that checkpoint, not qualification of the follow-up:

- [cargo-vet](https://github.com/bb-connor/arc/actions/runs/34607186532) still
  reports 22 dependencies missing `safe-to-deploy` audits.
- [FIPS](https://github.com/bb-connor/arc/actions/runs/34607185882) passed all
  19 nonce-lifecycle tests but rejected its stale 18-test declaration. The
  declaration now includes the existing delayed-capture expiry regression;
  no test, assertion, workflow pin or gate is removed.
- [CVE Monitor](https://github.com/bb-connor/arc/actions/runs/34607186352) passed
  cargo-audit but reports npm advisories for sharp, Vitest/mocker, js-yaml and
  Next.js. Its retained OSV artifact names `GHSA-rgj7-g3m4-5g8c`,
  `GHSA-82fw-gwwq-j7x9`, `GHSA-2883-xcg3-v3hh`, `GHSA-2xp9-vwfh-vxw4` and
  `GHSA-p293-qw3h-jr36`; dependency remediation and affected-consumer checks
  remain required. No advisory exception was added.
- [Live treaty buyer closure](https://github.com/bb-connor/arc/actions/runs/34607185973)
  rejects the static proof-package and verifier-report hashes. This is not a
  successful runtime qualification or permission to bypass semantic parity.
- [Enterprise controller](https://github.com/bb-connor/arc/actions/runs/34607182704)
  failed exact-source/controller authorization. Workflow pins and repository
  authorization variables remain unchanged.

The capture checkpoint's eight exact groups, kernel 103, SQLite budget six,
all-target strict Clippy and 182-entry source-drift check passed. Counts overlap.
Logs remain under `/tmp/chio-native-capture-ack-*`; the 44-test native-policy log
is `exact-native-post-join-policy.log`. The full adapter log is interrupted, not
passed. Its pending rerun and the complete production-feature matrix remain open.
The preceding handoff batch closed the affected default production-library,
formal-mirror checker, formatting and AST checks, not those broader campaigns. Changed input
closures must be requalified; unchanged completed campaigns are retained.

External decisions to obtain before their gated steps, without activation now:

- Designated Linux x86_64 runner with the complete cage prerequisite profile.
- Registry/package owners and release signing, manifest publisher and independent
  witness roles; select versions against registries at release time.
- Dependency auditors for the previously observed 22 safe-to-deploy gaps; refresh
  the audit inventory, do not substitute blanket exemptions.
- Pilot operator, service identities, durable-state provisioning and approved
  migration/backup plan. No populated-store upgrade is implied by local tests.
- Commits, pushes and PR maintenance were authorized on 2026-09-11. Manual hosted
  qualification, merge, publication and deployment still require separate
  authority, as do the observed pilot and each signed promotion stage.

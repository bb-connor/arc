# Security launch: current execution status

Updated 2026-09-12. This is the short working index for the accepted
[execution plan](launch-execution-plan.md), not another qualification campaign.
Candidate: `/tmp/arc-security-launch`, `security/launch-integration`, base HEAD
`8b9f9243905dfa61acac82d83438684940777fe3`. The accumulated 722-path checkpoint
was committed and pushed as `7e54c14a60` to
[draft PR #1117](https://github.com/bb-connor/arc/pull/1117) under the user's
2026-09-11 authorization. M1's local closeout is `252b259d44da44e5f323ac9653f2ee32f05bee8a`.
M2's native failure/restart safety acceptance is committed as
`13fa4585d2a87eebf45d643638c4c6e145ac3cea` under the existing fail-closed release
contract. Earlier hashes below identify historical checkpoints, not the current
candidate. M3 implementation is in progress on the same branch. This is not
merge or release approval.

## Milestone control

| Milestone | State / missing acceptance | Next action / blocker | Evidence |
| --- | --- | --- | --- |
| M0 | Consolidated for implementation | Keep this index current; no independent cleanup campaign | Requirement and review maps below |
| M1 | Complete: implementation and local acceptance | Keep closed absent a demonstrated regression; confinement remains explicitly deferred | [Acceptance closeout](#m1-local-acceptance-closeout), [qualification deferral](#m1-confined-process-qualification-deferral) |
| M2 | Complete: local native failure/restart safety acceptance | Proceed to M3; missing release custody still blocks output and readiness | [Acceptance closeout](#m2-local-acceptance-closeout), [cutpoints and downstream contract](native-restart-safety.md) |
| M3 | Partial: physical caller snapshot and authenticated executor ledger; kernel start and historical delivery integration missing | Commit before publishing start; reconcile late reports without reopening admission; preserve counterexample until that handshake passes | [Current implementation and remaining work](../superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md#m3-caller-custody-and-executor-ledger-checkpoint-2026-09-12) |
| M4 | Consumer qualification incomplete | Inventory positive supported paths and required startup denials after M1-M3 | [Original requirement ledger](launch-plan.md#requirement-ledger) |
| M5 | Swarm is a Disabled-profile integration smoke | Bind issued capability identities, shared budget and enforced cage | [Swarm limitations](../../examples/reference-swarm/README.md) |
| M6 | Components present, integrated topology unqualified | Compose keyring, broker, cage and receipts; designated runner needed | Enterprise ledger and original plan |
| M7 | Active-defense components present, composed paths unqualified | Complete flow, response and rollback acceptance in controlled profiles | Active-defense ledger and original plan |
| M8 | Retention, scale and operational recovery unqualified | Real campaigns after lifecycle integration | Retention #1045 and million-receipt gates remain required |
| M9 | Entry packages unpublished and external consumer unqualified | Package dependency closure and clean install after M4-M8 | Three intended entrypoints remain `publish = false` |
| M10 | Not release qualified | Local gates, audits, authorized exact-candidate hosted and publication steps | Candidate lacks passing exact-head hosted qualification |
| M11 | Not started | Authorized observed pilot and signed promotion stages | [Numeric operator contract](active-defense-rollout.md) |

## M3 implementation checkpoint

Caller snapshot v4 now checks physical original claim episodes rather than
trusting their digests alone. The real sealed/activated runtime path retains the
original reservation and revalidates it without reacquiring a claim. The
authenticated message codecs and private executor SQLite ledger are implemented
as components, with explicit separation between live execution permission and
late historical evidence.

These components do not close the milestone. The kernel does not yet issue a
start authorization, authenticate an executor report into historical finalization,
or enable the new contract in sidecar/SDK clients. Credential/native caller
profiles still fail closed. The existing lost-report/expiry counterexample is
unchanged: explicitly running it with `--ignored` reproduces the original refund
and second-execution failure both before and after this checkpoint
(`/tmp/chio-m3-original-counterexample.log`, `/tmp/chio-m3-current-counterexample.log`). No
executor-only fixture is substituted for this acceptance test. The remaining
implementation sequence is recorded in the [caller design checkpoint](../superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md#m3-caller-custody-and-executor-ledger-checkpoint-2026-09-12).

| Local gate | Result | Log |
| --- | --- | --- |
| Full kernel library | 1,428 passed, zero failed or ignored | `/tmp/chio-m3-kernel-full.log` |
| Full runtime-admission integration | 86 passed, zero failed or ignored, including the real caller custody and duplicate-reservation regression | `/tmp/chio-m3-runtime-full.log` |
| Executor SQLite ledger | Nine passed, zero failed or ignored; real child death before/after effect and after report persistence | `/tmp/chio-m3-executor-final.log` |
| Existing caller SQLite integration | 21 passed, zero failed, one known ignored missing-handshake counterexample | `/tmp/chio-m3-caller-store.log` |
| Kernel durable SQLite integration | 15 passed, zero failed or ignored | `/tmp/chio-m3-durable-sqlite.log` |
| Formal source-review bindings | 21 checker tests passed; 225 matching entries; generated coverage remains 58 rows / 168 artifacts | `/tmp/chio-m3-formal-tests.log`, `/tmp/chio-m3-formal-check.log`, `/tmp/chio-m3-proof-coverage.log` |

The executor tests use explicitly signed authorizer fixtures, not a kernel start
producer. Matching source hashes are review anchors, not new formal proofs.
These are local component/regression results, not the full M3 acceptance gate,
full-workspace testing or exact-head hosted qualification.

Strict all-target Clippy passes for kernel, runtime core, SQLite, control plane
and xtask (`/tmp/chio-m3-clippy.log`). Workspace formatting and file hygiene pass.
The required AST-only graph refresh completed; HTML rendering remains skipped
at the unchanged graph-size limit. No activation or verification limit was
weakened to obtain these results.

No populated authority migration, SDK activation, workflow authorization change,
merge or release is included. M1's confinement qualification remains deferred.

## M2 local acceptance closeout

The named M2 safety matrix passes against real SQLite authorities on
Linux/aarch64: 31 child-death scenarios and three live races, covering baseline,
combined runtime/approval/DPoP, nonce, declassification and cumulative accounting.
Child termination bypasses Rust destructors. Tests check the exact abort marker,
physical accounting and custody, original operation/receipt identity, independent
effect counts and new-owner fencing. The complete cutpoint map and downstream
idempotency/status requirements are in [native restart safety](native-restart-safety.md).

The campaign found and fixed a real duplicate-start bug: an overlapping retry
could attach to a live operation and compensate its owner's hold. The existing
serving-fence sequencer now holds a process-local, non-cloneable live-operation
guard. Duplicate evaluation and background recovery cannot take that operation
while its owner is live. No mutation mutex is held across a callback or await;
SQL fences and original credential custody remain authoritative.

| Current-source local gate | Result | Log |
| --- | --- | --- |
| `scripts/check-native-restart-safety.sh` | 34 exact process/race tests and five exact ownership tests | `/tmp/chio-m2-exact-restart-gate.log` |
| Native control-plane integration | 114 exact tests, including all 80 prior M1 cases and the 34 M2 cases | `/tmp/chio-m2-native-composed.log` |
| Kernel library | 1,421 tests | `/tmp/chio-m2-kernel-library-qualified.log` |
| Native SQLite custody | 93 exact tests | `/tmp/chio-m2-native-custody.log` |
| Kernel `durable_admission_sqlite` | 15 tests, unfiltered | `/tmp/chio-m2-durable-sqlite.log` |
| SQLite `security_release_recovery` | 25 exact tests, unfiltered | `/tmp/chio-m2-release-recovery.log` |

Every row passed with zero failed or ignored tests. Counts overlap where stated.
Five older kernel fixtures held a live admission while simulating its owner's
death or beginning a subsequent attempt. They now explicitly drop that owner;
their original identity, accounting, payment and recovery assertions remain.

Final strict all-target Clippy passes for kernel, SQLite, control plane and xtask
(`/tmp/chio-m2-final-clippy.log`). The production library build passes with normal
features; its dependency graph excludes admission/cognition test-support features
(`/tmp/chio-m2-production-build.log`, `/tmp/chio-m2-normal-features.log`). All 21
formal-source checker tests pass and all 223 source-review entries match.
Generated coverage remains 58 rows and 168 artifacts. These are source-review
anchors, not new formal proofs. Workspace/include-reachable formatting, file
hygiene, the 69-inventory flow-script contract, exact-inventory self-tests and
security CI contract/mutation tests pass. The AST-only graph refresh completed;
HTML stayed skipped at the unchanged size limit. Changed Rust source hashes are
retained in `/tmp/chio-m2-final-rust.sha256` and remained unchanged through gates.

Release recovery preserves the existing contract, not unconditional availability:
an exact release checkpoint recovers the original guarded result and receipt;
without the original live owner or its checkpoint, `Finalizing`, captured quota
and the original outcome remain retained, and startup withholds readiness. The
tests do not fabricate successful terminal recovery in that case. No generic
exactly-once network effect or guaranteed client delivery is claimed.

No persistent schema, dependency, production deadline, activation default,
populated operator store or workflow authorization changed. The complete broader
flow/workspace/hosted release campaigns did not run as part of this milestone.
M1 confinement remains deferred; M6, M10 and M11 are not qualified. M3's
authenticated caller start and durable delivery are the next implementation work.

## M1 confined-process qualification deferral

On 2026-09-12 the user approved using GitHub Actions for M1's Linux x86_64
confined-process tests, or recording a deferral if that is not currently possible.
This workspace runs Linux/aarch64. The repository has Ubuntu x86_64 execution
lanes, but its existing [isolated-capture controller](https://github.com/bb-connor/arc/actions/runs/34693733714)
for candidate `d4a7c718376ee277b554717ea9db08c9d4c1715d` failed
`Authorize exact source and controller context`; its dispatch step was skipped.
The capture workflow requires a controller-issued authenticated dispatch context.
A manually invented context or weakened source authorization is not a substitute.
The later controller for M1 closeout `252b259d44da44e5f323ac9653f2ee32f05bee8a`,
[run 34707292866](https://github.com/bb-connor/arc/actions/runs/34707292866), also
completed with failure in its isolated-capture dispatch job. Neither run is
passing confined-process evidence.

Confined-process qualification is therefore explicitly deferred, not passed.
Continue the full M1 implementation and local acceptance without blocking on this
runner. Revisit qualification using an authorized exact-candidate Actions run
before claims of confined execution or production readiness. M2's local process
failure/recovery acceptance above does not qualify M6's enterprise topology. No repository
authorization variables, pinned workflow definitions or release gates were changed
to implement this decision.

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
| 4 Composite holds and mutation | Native composition locally verified | M1 |
| 5 Durable SQLite and remote authority semantics | Native SQLite crash/recovery locally verified; full original requirement not release-qualified | M2, M10 |
| 6 Admission ordering and signed terminal projection | Native profiles locally verified; caller handshake missing | M1, M3 |
| 7 Policy-owned threshold requirements | Carried; composed action acceptance pending | M7 |
| 8 Bounded approval verification | Complete native credential composition locally verified | M1 |
| 9 Durable replay and collection | Native replay/restart locally verified; response composition pending | M2, M7 |
| 10 Federation threshold compatibility | Shared authorization and frozen native return context locally verified | M1 |
| 11 Existing bounded runtime evidence | Signed validity bounds, physical capture and combined native invocation locally verified | M1 |
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
| 3 Durable security stores | Native store recovery locally verified; retention pending | M2, M8 |
| 4 Flow and one-shot declassification | Native consumption, output outcome and release locally verified | M1 |
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
| Ordinary `evaluate_tool_call*` | Installed runtime, credentials and selected security lifecycle | Coordinator/store; output guards and current security release | In-process local/egress and required credential/use profiles pass; confinement deferred |
| Nested `evaluate_tool_call_operation_with_nested_flow_client*` | Same participants, plus nested/session binding | Same original-operation owners; nested return finalization | Explicit proof-bearing sync/async profiles pass; confinement deferred |
| Nonce-required ordinary/nested | Operation-owned nonce and authenticated delivery identity | Durable nonce plus admission owner; uncertain outcomes retain accounting | Native preflight, dispatch and replay pass; caller-report transport remains unsupported |
| Governed ordinary/nested | Exact request-bound approval quorum and replay custody | Exact fenced claim disposition; expiry checked before capture | Combined runtime/approval/DPoP with nonce and declassification pass; confinement deferred |
| Native-flow security-context entrypoints | Original native binding, full-source join, policy, egress/use custody and live capture authority | Private original owner and current output policy, not historical capture | Host opt-in and prior source lifecycle selection required; default and diagnostic checkpoint stay closed; confinement deferred |
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

## Native nonce and declassification composition

The native lifecycle now supports operation-owned execution nonce and signed
declassification custody through the original ordinary/nested capture path.
The real connector, frozen return context, output evaluation and signed receipt
path remain shared with the previously supported native credential profiles.
Current-source local acceptance passes as recorded in the closeout below. The
earlier checkpoint evidence remains historical, not fresh hosted qualification.

- Nonce capture requires the original signed reservation and issuance digest,
  exact live request and original requirement, current issuer and expiry. The
  physical transaction independently checks the reservation and final deadline.
  It cannot fall back to a legacy nonce store or caller-report transport.
- A trusted, correctly bound declassification grant remains unconsumed during
  input classification and policy preparation. Its complete source includes
  inherited principal, lineage and session state. Consumption and its evidence
  commit atomically with the original egress fence before capture. Expiry or
  later failure cannot refund the one-shot use or undo committed input taint.
- Original output finalization commits the use outcome and output taint in one
  transaction. `Released` describes the request's connector use, not guarded
  output delivery or publication of the active-defense receipt outbox. Lost
  owners and uncertain effects still require original-operation recovery.
- Grant-use uniqueness is scoped to the selected authoritative security domain.
  This is not distributed one-shot enforcement across independent stores sharing
  an issuer. That deployment must designate one authoritative use store.
- Native egress and output journals use explicit v2 records for declassification;
  ordinary v1 record bytes and the schema-33 catalog remain unchanged. No new
  generic writer or schema upgrade is introduced. Imported declassification
  lifecycle selection must already permit live dispatch. Invocation never seals,
  reconciles or activates an unselected imported lifecycle.

The acceptance inventory includes real sync/async ordinary and nested execution
with nonce, with the combined runtime/approval/DPoP profile, and with both. It also
checks grant substitution, missing proof, second use with quota still available,
receipt replay, final-commit expiry, monotone state and atomic output failure.
The existing deny-only checkpoint is used to observe the exact expiry failure,
never to establish successful connector execution.

### M1 requirement-to-acceptance map

The numbers below match all eight requirements in the accepted M1 plan. Named
inventories are maintained in `scripts/check-flow-security.sh`; all named M1
inventories pass locally. Shared-path checks establish ordering and
retained-context behavior, not a qualified multi-host federation deployment.

| M1 requirement | Implementation boundary | Acceptance evidence |
| --- | --- | --- |
| 1 Original complete credentials | Original profile and live reservation; actual capability, delegation, revocation, runtime, approval and DPoP | Combined ordinary/nested profiles, missing/substituted proofs, original authority selection and participant snapshots |
| 2 Physical commit deadlines | Transaction-bound witness and independent final trusted-time check | Runtime signed freshness, runtime/nonce/declassification expiry, policy clock bounds and stale-owner rejection |
| 3 Pre-effect authorization | Shared ordinary/nested authorization and final capture helper; original composite hold | Dispatch rejection payment custody, frozen participant context, federation context and physical hold ownership |
| 4 Frozen return context | Exact original participant references, admitted evidence, grant, limits and signing identity | Frozen dispatch context, durable caller persistence and frozen receipt signing inventories |
| 5 Native one-shot use | Original nonce reservation; atomic egress consumption and output outcome | Nonce execution/replay, declassification credential matrices, signed-claim substitution, issuer time bounds and exact row semantics |
| 6 Real connector | Opt-in production captured lifecycle and shared ordinary/nested handoff | Sync/async local and egress invocation, one connector effect, expected output, verified signed receipt and exact completed replay |
| 7 Guarded output and release | Raw-output tripwire before redaction, final flow policy and original live release owner | Security kernel callbacks, actual output/chunks, output journal failures, current revocation/stop and durable release recovery |
| 8 Explicit activation | Immutable source selection, selected imported lifecycle and supported original backend | Native authority admission, runtime non-upgrade, catalog identity, migration refusal and unselected declassification lifecycle denial |

Confinement is the sole user-approved M1 qualification deferral. Process
failure/restart campaigns, the external caller handshake, complete adapter/SDK
parity, broker topology and operational active-defense outbox publication retain
their own M2-M8 acceptance gates. They are not silently included in local M1
success claims.

## M1 local acceptance closeout

M1's implementation and local acceptance are complete for the explicitly selected
SQLite-backed in-process profile. Actual ordinary and public nested sync/async
calls execute through the production captured lifecycle, return expected guarded
output and independently verifiable signed receipts, and replay the original
receipt without another effect. Required nonce, declassification and combined
runtime/approval/DPoP variants pass. Default and diagnostic activation remain
closed. Confinement is deferred by the decision above. M2 subsequently qualified
the native failure/restart safety contract; its current evidence is above.

Historical evidence for M1 closeout `252b259d44da44e5f323ac9653f2ee32f05bee8a`:

- All 37 named M1 inventories pass: 472 test executions, with overlapping filters
  counted separately. This includes all 80 native control-plane tests, all 93
  native-store custody tests, 25 durable release tests and 13 federation tests.
  The source commands live in the flow gate, which then declared 68 inventories
  across the wider roadmap. This does not claim that the entire flow gate ran.
- `/tmp/chio-m1-cohesive-acceptance-final.log` retains the first 12 passing
  inventories. Its subsequent native-authority group exposed a stale unsupported
  nonce-preflight message assertion. The corrected group and all remaining 24
  inventories pass in `/tmp/chio-m1-cohesive-acceptance-remainder.log`.
  All no-authority, no-hold and no-effect assertions remain enforced.
- `/tmp/chio-m1-federation-qualified.log` records the added 13-test exact group.
  Two older fixtures assumed the pre-signing outcome schema. Tests now retain
  legacy decoder rejection, verify missing original federation context against
  the committed outcome during recovery, and exercise both legacy and
  frozen-signing codec order with explicit security-release disposition. No
  production decoder was weakened to accommodate the fixtures.
- Additional nonce regressions pass: 18 kernel tests, 82 SQLite tests and all 17
  public lifecycle tests. Logs are `/tmp/chio-m1-nonce-kernel-regressions.log`,
  `/tmp/chio-m1-nonce-store-regressions.log` and
  `/tmp/chio-m1-nonce-public-lifecycle.log`. Counts overlap other inventories.
- Production-library checks pass for kernel, SQLite and control plane. Strict
  all-target Clippy passes for those packages and xtask. Logs are
  `/tmp/chio-m1-production-libraries.log` and `/tmp/chio-m1-clippy-final.log`.
- All 21 formal-source checker tests pass, and all 221 source entries match.
  Every prior relationship and covered symbol is preserved; proof claims are
  unchanged. Generated coverage remains 58 rows and 168 artifacts. Logs are
  `/tmp/chio-m1-formal-mirrors-tests.log`, `/tmp/chio-m1-formal-mirrors-check.log`
  and `/tmp/chio-m1-proof-coverage.log`. Source hashes are not new formal proofs.
- Workspace and explicit include-reachable formatting, the 68-inventory flow
  contract, exact-inventory runner/verifier self-tests, security CI contract and
  its mutation tests, file hygiene and patch checks pass. The final AST-only graph
  refresh is recorded in `/tmp/chio-m1-graph-final.log`; HTML remains skipped at
  the unchanged size limit. Production deadlines, activation defaults, the root
  lockfile and workflow pins are unchanged.

The production source stayed unchanged during the final acceptance run and
follow-up regression fixes; the latter changed test fixtures and gate coverage.
Changed Rust sources were fingerprinted through final verification. These are
local debug correctness checks, not a portable hosted artifact bundle,
throughput/latency qualification, a full-workspace release gate or authorization
to migrate populated operator stores, merge, publish or activate production.

## Historical M1 checkpoints

The incremental records below retain earlier implementation frontiers. They are
superseded by the M1/M2 closeouts and milestone-control table above.

The entries below retain historical checkpoint-by-checkpoint evidence. Current
composition is tracked [above](#native-nonce-and-declassification-composition).
Earlier statements about unsupported profiles describe their own source
checkpoint, not the latest working tree.

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

### Frozen receipt-signing checkpoint

Two regressions reproduced the missing M1 signing selection: unfinished retained
output could finalize with a replacement receipt authority, and completed replay
rejected the original receipt after the active signer changed. The kernel now
freezes a typed public signing identity and crypto floor before dispatch. New
private raw returns and caller-context v2 retain that selection. No private key,
backend handle or reusable authority is serialized. Legacy formats remain
explicitly unbound and keep their previous current-signer behavior; no old record
is rewritten or retroactively qualified. New schemas without identity and legacy
schemas carrying identity reject, as do incompatible floors and unknown fields.
The physical outcome digest binds the complete retained format and selection.

Unfinished finalization checks the original signer before output/settlement work
and binds the eventual body to that same key. The portable receipt primitive now
uses the embedded-key atomic signing entrypoint and independently verifies its
returned key, algorithm and signature. Callback probes exposed the previous
generic-signing handoff; an early key comparison alone did not pin that operation.
Valid Ed25519 receipt bytes and WYSIWYS preimages are preserved.

Signing callbacks run outside the mutation sequencer. After signing, the kernel
revalidates the exact physical operation and original recovery claim at freshly
sampled time, without renewing custody. Panics and expired claims retain
Finalizing with no published terminal. Completed replay verifies the retained
key under both the original and current floor, without invoking a new signer or
the tool. Participant validation after exact caller-frame readback also runs
outside the mutation sequencer.

Local behavior checks passed with no ignored tests:

- Return-context group: 22 passed, including all nine newly declared signing
  cases and five caller codec cases (`/tmp/chio-frozen-signing-expanded.log`).
  Signer replacement/recovery, ordinary/nested replay, current-floor refusal,
  callback reentry, panic and identity substitution are covered. Signer expiry
  uses the existing thread-scoped test clock, not a new real-clock campaign.
- Portable receipts: 56 default-feature tests and 59 with `fips,pq` passed
  (`/tmp/chio-frozen-signing-{portable,crypto-features}.log`). All 23 portable-kernel
  tests passed (`/tmp/chio-frozen-signing-portable-kernel.log`). Canonical Ed25519
  bytes remain unchanged; inconsistent atomic signing results reject.
- All 20 boot-selected receipt tests passed with `pq,finding-market`, including
  durable hybrid replay, signer-outage recovery, queue/fallback parity and separate
  pool authority (`/tmp/chio-frozen-signing-boot-receipts.log`). This is functional
  feature coverage, not FIPS certification or witnessed rotation qualification.
- All 32 durable-outcome tests passed (`/tmp/chio-frozen-signing-outcomes.log`).
  Physical SQLite suites passed: 15 finalization tests, three caller-context
  tests and 25 release-recovery tests
  (`/tmp/chio-frozen-signing-sqlite-{finalization,caller,release}.log`). These retain
  settlement/delivery ordering, exact restart replay, process-crash boundaries
  and no redispatch. They do not execute a native connector.

Counts overlap and are not additive. The broader return-context run covers the
new nine-test signing inventory; no separate exact-inventory execution is claimed.
The unchanged CI-controller mutation campaign was stopped as redundant, not
reported as a new pass. Structural flow-inventory and security CI checks pass.
The flow contract now contains 60 exact inventories. The AST-only graph refresh,
Rust file hygiene and explicit formatting of include-reachable tests pass.
All 200 prior source anchors, symbols and claim metadata are retained among the
203 current entries; no new proof claim is made. The root lockfile is unchanged.
Final strict all-target Clippy passed for core-types, kernel-core, kernel,
SQLite, control-plane and xtask. Portable core-types/kernel-core libraries passed
the `wasm32-unknown-unknown` no-default-features check. Native kernel, SQLite and
control-plane production-library checks passed. All 20 selected formal-mirror
tests passed, all 203 source entries match, generated coverage matches 58 rows
and 168 artifacts, and workspace formatting passes
(`/tmp/chio-frozen-signing-{clippy,portability,production,formal-tests,formal-check,coverage-check,fmt}.log`).
These are local checks, not full-workspace or exact-head hosted qualification.

This advances M1's frozen-signing subtask, not complete signing-owner custody or
witnessed rotation. Complete participant references, original live native owner,
native use/declassification/nonce composition and real ordinary/nested native
invocation remained open at this signing checkpoint. The following lifecycle
checkpoint advances that integration without adding another signing campaign.

### Native captured lifecycle checkpoint

`NativeFlowResolver::with_captured_lifecycle()` explicitly opts a trusted host
into the supported non-nonce/non-declassifying native flow. The default resolver
and capture-only test observers still deny before invocation. Ordinary and nested
evaluation share the same capture/handoff helper; a native selection cannot fall
back to legacy dispatch callbacks or the generic capture path.

Before capture, the kernel freezes the actual return context against the freshly
joined security generation, original grant, admitted evidence and signing
identity. Successful physical capture and independent readbacks privately retain
one affine, non-serializable owner. After the callback, handoff revalidates the
original authority, request, physical operation and current flow at fresh time.
Its horizon cannot exceed the original capture lease, verified credential
deadlines or exact captured policy deadline. Repeated capture, including a
suppressed error, invalidates handoff. Failure after attempted capture retains
uncertain custody and never authorizes a second invocation.

Actual registered-tool output enters the existing guard, native output-taint,
leased release-checkpoint and signed-receipt pipeline. The private owner binds
release to the original dispatch and frozen security context. It is not exposed
through the resolver's historical capture result and cannot be reconstructed
after loss. Completed replay returns the original verified receipt without
invoking the tool again.

All six new lifecycle tests passed, with no ignored tests
(`/tmp/chio-native-owner-lifecycle.log`):

- Ordinary local and egress execution, independent receipt verification, exact
  replay and one actual invocation.
- Public nested sync/async entrypoints, each with local and egress policy.
- Nonempty runtime, approval and DPoP custody together through ordinary local
  invocation and completion.
- Missing capture, failure or panic after capture, and a suppressed repeated
  capture error all withhold execution and preserve the expected quota state.
- Real expiry after capture with the original policy deadline, no extended TTL
  or substituted clock, withholds invocation.
- Refused output preparation withholds actual tool output and leaves Finalizing
  with no release checkpoint or terminal completion.

These tests use the production evaluation path with a registered in-process tool
and real initialized SQLite authority. They do not qualify a confined child
process, cage, external connector or customer deployment. Complete participant
references, native nonce/declassification variants and combined nested/egress
credential execution remain open. The previous combined-egress capture deadline
failures are not closed by this six-test run. M1 remains in progress.

The subsequent complete 64-test native-policy run passed 62 tests and failed two,
with none ignored (`/tmp/chio-native-owner-full-policy.log`). Both failures remain
the existing ordinary and nested combined-egress captures: the original native
policy expires before physical commit. All six new lifecycle tests passed in that
run. No deadline, stack size, positive test clock or verification limit changed.
This run precedes the additional post-output authority regression and is not a
passing full native-policy qualification.

Review of the newly connected path exposed a final-release gap: revocation
committed after output preparation still returned Allow, actual output and a
Completed receipt (`/tmp/chio-native-owner-release-red.log`). The kernel now
rechecks the original capability's revocation chain and emergency-stop state
after the output callback, outside the mutation sequencer and inside callback
panic containment. The existing physical validation still checks the original
finalization lease afterward. Refusal does not undo output taint, refund capture,
reacquire an owner or publish a release checkpoint. The additional regression
checks both revocation and emergency stop after the actual output join.

The final focused run passed all ten tests, with none ignored
(`/tmp/chio-native-owner-final-lifecycle.log`): seven lifecycle tests, including
the new post-output authority regression, plus all three output-preparation
regressions. These counts overlap the earlier runs and are not additive. The flow
gate now declares all 65 native-policy test names among its unchanged 60 exact
inventories. No final full 65-test pass is claimed.

All 61 selected kernel regressions passed with none ignored
(`/tmp/chio-native-owner-kernel-regressions.log`): original authority/security
binding, legacy dispatch and nonce cleanup, frozen return/signing context,
dispatch-failure accounting and exact durable output binding. These checks
preserve existing consumer boundaries; they do not qualify native process
termination or the unfinished caller-execution handshake.

Physical SQLite regressions passed all 12 native-authority tests and all 25
shared release-recovery tests, with none ignored
(`/tmp/chio-native-owner-sqlite-regressions.log`). Generic/split capture bypasses,
lease expiry, crash/restart checkpoints, current output refusal, callback reentry,
redacted values/stream chunks and exact replay remain covered. The shared crash
cases do not qualify a real native confined-process topology.

Strict all-target Clippy passed for kernel, SQLite, control-plane and xtask;
production-library checks passed for kernel, SQLite and control-plane. All 21
formal-mirror checker tests pass, including checked-in manifest coverage. The
new lifecycle requirements are scoped to the existing post-admission model;
all 11 prior requirement groups and model mappings remain unchanged. Source
validation matches 204 entries, retaining all 203 prior entries, symbols and
claim metadata. Coverage remains 58 rows / 168 artifacts, with no new proof
claim. Workspace and explicit include-file formatting, file hygiene, inventory
and security CI contracts pass. The root lockfile is unchanged. Logs use
`/tmp/chio-native-owner-` with `clippy`, `production`, `formal-tests`,
`formal-check`, `coverage-check`, `fmt`, `include-fmt`, `hygiene`,
`flow-contract` and `ci-contract` suffixes and `.log`. These are local affected
checks, not full-workspace or exact-head hosted qualification.

The final AST-only graph refresh passed
(`/tmp/chio-native-owner-graph-post-review.log`). HTML visualization remains
skipped at the unchanged repository-size limit. No merge, publication, populated
store migration, hosted qualification dispatch or operational activation occurred.

### Native compiled-catalog deadline checkpoint

Expanded production-path acceptance reproduced combined-egress refusal at the
live handoff, after physical capture. Diagnostic sampling found repeated
canonicalization and hashing of the immutable compiled native catalog during
egress history verification. This consumed the original policy window. The
kernel correctly denied the expired handoff before invoking the tool.

The store now memoizes only the two compiled catalog digests, independently for
v28 and v29. Their domain separator and canonical bytes are unchanged. Live
SQLite catalogs, rows, authority bindings, observations and verification results
are not cached. Unsupported versions and initialization errors remain
fail-closed. No policy, credential or lease deadline changed. The exploratory
claim-read refactor and all diagnostic probes were removed.

Four focused tests pass with none ignored: ordinary and public nested capture,
and ordinary plus nested sync/async execution. Every case covers local and
egress policy with nonempty runtime, governed approval and DPoP custody together.
Execution asserts actual output, independently verified receipts, retained
participant histories, committed egress where required, native output joins and
durable release checkpoints. Ordinary retry returns the exact original receipt
without a second invocation. The existing basic nested cases remain covered.

The complete declared inventories pass: 2 compiled-catalog identity tests, 87
native custody/recovery tests and 65 native-policy tests, all with zero failures
or ignored tests (`/tmp/chio-native-catalog-exact-gates.log`). This final 65-test
run includes the four focused cases and supersedes the preceding 62-pass/2-fail
result as current local policy evidence. Counts overlap and are not additive.
The catalog tests require unchanged historical digests and fresh rejection of
modified live schemas even after the compiled cache is warm.

Production-library checks pass for SQLite and control plane. Strict all-target
Clippy passes for SQLite, control plane and xtask; workspace and explicit
include-reachable formatting pass. All 23 selected formal-mirror tests pass,
with 204 matching source entries and generated coverage unchanged at 58 rows /
168 artifacts (`/tmp/chio-native-catalog-quality.log`). Every prior source entry,
symbol and claim is retained; only the existing catalog anchor adds the digest,
compiled-catalog and live-verification functions. No new proof claim is made.
The 61-inventory flow contract, security CI contract, file hygiene and whitespace
checks pass. The root lockfile is unchanged
(`/tmp/chio-native-catalog-static.log`). Final AST graph refresh passes
(`/tmp/chio-native-catalog-graph.log`); HTML visualization remains skipped at the
unchanged repository-size limit.

These remain in-process registered-tool tests, not confined-process or launch
qualification. Full frozen participant references and native
nonce/declassification/use profiles remain open; M1 is not complete. No manual
hosted qualification, populated-store migration, merge, publication or
operational activation is included.

### Frozen dispatch participant reference checkpoint

Two model regressions reproduced acceptance of a substituted nonce-issuance
reference by the live return context and caller decoder. The operation and
request still matched. These are binding counterexamples using individually
valid model operations, not evidence of bypassing the physical store's custody.

The shared kernel context now retains a bounded, typed snapshot of all 18
immutable participant references, including explicit absence. It covers
provider/budget, threshold and supplemental authorization, nonce issuance and
preflight, payment/channel/credit, runtime, governed approval and DPoP bindings.
Proposal content is hashed rather than retained. The enclosing caller-frame
digest and later tool-outcome attachment are deliberately excluded. An
exhaustive attachment match requires future additions to make a retention
decision. Native capture binds the exact prepared dispatch ledger before its
physical commit; independent capture readback and the live owner remain required.

New private caller frames use v3 and require both signing identity and participant
snapshot. Legacy v1/v2 preserve their prior canonical bytes and explicitly absent
snapshots. Unknown, missing, substituted or schema-smuggled fields reject;
legacy data cannot be reissued as complete v3 context using current references.
The shared post-capture check rejects a changed reply before tool invocation,
without refunding captured accounting. Return recording checks the same frozen
selection. No private key, reusable proof signature or protected proposal input
is added to the snapshot.

Final exact inventories pass: 27 frozen-context tests, three real SQLite caller
persistence/restart tests and all 65 native-policy tests, with zero failures or
ignored tests. The context group includes both reproduced regressions and the
capture-reply test. Native coverage retains combined runtime/approval/DPoP
ordinary and public nested sync/async execution, local and egress, as well as
accounting faults, corruption, actual output preparation and final release.
Evidence is `/tmp/chio-participant-snapshot-exact-gates.log`; the two original
model failures are retained in `/tmp/chio-participant-snapshot-red-tests.log`.
Strict all-target Clippy passes for kernel, SQLite, control plane and xtask;
production-library checks pass for the three runtime packages. All 23 selected
formal-mirror checker tests pass. All 205 source entries match, preserving every
prior entry, symbol and claim; generated coverage remains 58 rows / 168 artifacts.
These are source-drift checks, not new proofs. Workspace and explicit
include-reachable formatting, the 63-inventory flow contract, security CI
contract, file hygiene and whitespace checks pass. The root lockfile is unchanged.
Quality and static logs are `/tmp/chio-participant-snapshot-quality.log` and
`/tmp/chio-participant-snapshot-static-final.log`. The final AST-only graph
refresh passes (`/tmp/chio-participant-snapshot-graph.log`); HTML visualization
remains skipped at the unchanged repository-size limit.

Participant-ledger roots identify authority/operation history, not necessarily
one claim episode. Exact native claim references remain bound through the
native dispatch ledger; external caller claim custody and authenticated start
are still incomplete. This does not enable native nonce/declassification/use
profiles, qualify a confined process or complete M1. No merge, publication,
populated-store migration, hosted qualification dispatch or activation is included.

### Native nonce preflight custody checkpoint

The public strict-nonce preflight regression reproduced denial at the
dispatch-only preparation boundary. A nonce request is still `Prepared`, while
the existing native input journal correctly requires `BrokerAttemptRegistered`.
That dispatch contract and its historical transition digests are unchanged.

Preflight now has a distinct typed intent, callback and affine writer. It shares
the full-source label resolver and closed monotone row policy, not dispatch
authority. Its physical transaction requires the original strict-nonce request,
selected native initialization, exact current operation, recovery lease and flow
observation. One immutable preflight join is allowed per operation; independent
readback, callback error containment and the single-attempt latch remain required.
Committed taint survives subsequent denial and lost acknowledgements.

Admission schema v33 adds a separate preflight journal. Its canonical records,
digest domain and sequence are independent of input and output journals. Anchored
global ordering includes its row changes without treating them as dispatch joins.
The combined history bounds are unchanged. Migration rejects partial future
catalogs and preserves prior history; no populated operator store was migrated.

The physical issuer also independently requires the exact earlier preflight
record and its global anchor in the current fenced transaction, after verifying
the original signed nonce and cleaned budget preflight. The regression first
reproduced issuance without native taint, then passed with the writer check. This
is an operation-custody composition boundary, not a claim that an untrusted agent
possesses an issuer key or store fence. Non-native issuance and historical record
decoding retain their existing contracts.

Local behavioral verification passes:

- 93 exact native-store custody tests, including v33 migration and recovery,
  and four exact global-journal migration tests.
- 67 exact native runtime policy tests, including combined credentials, ordinary
  and nested execution, output custody and two public nonce preflight cases.
- Six exact intent contracts and 11 exact kernel preparation tests. A stale
  dispatch-probe assertion now expects the existing live-selection read; denial,
  zero legacy callbacks, zero tool calls and unchanged admission remain asserted.
- After adding the physical issuer check: its new exact regression, all 15
  existing issuance tests and the two public nonce consumers pass again. The
  full 93/67 suites preceded this final issuer-only change.

The behavioral counterexamples are
`/tmp/chio-native-nonce-preflight-red-behavior.log` and
`/tmp/chio-native-preflight-issuance-red-behavior.log`. Production library checks
for kernel, store and control plane pass, as does strict all-target Clippy for
those packages and `xtask`. All 23 formal-source tests pass; the fresh checker
matches 217 source anchors and generated coverage remains 58 rows/168 artifacts.
All 205 prior anchor relationships/symbols and non-mirror proof claims are
preserved. These are source-drift checks, not new proofs of SQLite or nonce
execution safety.

Workspace and explicit-source formatting, the 65-inventory flow wiring contract,
security CI static/mutation checks and patch hygiene pass. All 63 prior flow
inventories retain their names and commands. The root Cargo.lock is unchanged.
The repository's AST-only graph refresh follows these final source edits. These
local checks do not constitute passing exact-head hosted qualification.

This is pre-issuance taint custody, not completed native nonce execution. Binding
the issued nonce through fresh dispatch preparation, atomic capture and ordinary/
nested output release remains next. Declassification/use custody and actual
confinement remain open; M1 and launch qualification are not complete.

## Retained evidence and external prerequisites

### CI repairs on the published integration branch

Native output preparation is committed as `5c7397ad44`. The separate CI follow-up
addresses three evidenced M10 gate mismatches on prior head `46ce85b2e0`:

- [Build](https://github.com/bb-connor/arc/actions/runs/34612762295/job/103309393442)
  rejected a stale generated Docker workspace lockfile. Offline regeneration and
  check pass (`/tmp/chio-output-preparation-docker-{regenerate,check}.log`). Only
  three existing dependency edges changed; package versions, sources, checksums
  and the root lockfile are unchanged.
- [FIPS](https://github.com/bb-connor/arc/actions/runs/34612762075/job/103307089838)
  passed all 15 nonce issuance tests but declared 13. The declaration now matches
  every listed and passed name from that exact hosted log. CI contract and
  mutation checks pass. This is not a new FIPS execution or a workflow repin.
- [Runtime policy](https://github.com/bb-connor/arc/actions/runs/34612761815/job/103307102068)
  and [runtime spine](https://github.com/bb-connor/arc/actions/runs/34612761815/job/103307101928)
  each failed two import-serialization cases at an outdated error assertion.
  Require the shared migration owner's exact busy error. All five focused tests
  pass (9.14 s), as does strict Clippy for the target
  (`/tmp/chio-output-preparation-runtime-import-{tests,clippy}.log`). Concurrency,
  reentry, source callback counts, destination reads, lost acknowledgements,
  panics and restart assertions remain intact. Full runtime lanes were not rerun.

These repairs do not qualify the remaining hosted gates or native invocation.

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

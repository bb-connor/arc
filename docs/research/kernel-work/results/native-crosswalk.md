# Task 5: measured native correspondence and its boundary

The available native profile preserves one logical call and original nonce
across the tested process deaths. **Full KW1-to-native correspondence is not
established.** The new experiment also reproduces the external-effect failure
of an unqualified connector. These results narrow the claim; they do not pass
the plan's complete cross-owner composition gate.

## Source and qualification

Baseline `188031256600903676eb69bda3144b9e8a1660da`; the only native code changes
are owning integration tests. The production kernel and process implementations
are unchanged. [Verification](followthrough/verification.json) binds actual
source bytes, toolchain, feature profile, commands and terminal outputs. The
conceptual baseline continues to assume all PR #1172 requirements shipped at
`de84fc306efbb4c8dd6de748d0ad2a8d695fd30e`; its
[live PR observation](native/recovery-pr-observation.json) is not production
implementation evidence. The native test profile uses SQLite, strict nonces,
`worker-server`, distinct local owner signing keys and one loopback endpoint
process under the same administrator.

## G2 command correspondence

Paths below are relative to the repository. A source anchor alone is not a
passing correspondence test.

| KW1 command(s) | Actual owning entry point / commit boundary | Evidence and remaining difference |
| --- | --- | --- |
| `Finalize`, `Readback` | `ProcessRuntime::tool_request`, `invoke_with_recovery`, `Store::admit`, `Store::retain_nonce` in `chio-process/src/{lib.rs,store/}` | Original request, native request binding and nonce survive reopening. Process SHA and native admission hash are separately retained in receipt metadata. This is not the PR's new `FinalizedRequestEnvelopeV1` bridge. |
| `Capture`, `Send` | `ChioKernel::evaluate_tool_call_with_metadata`; durable admission coordinator; `AdmissionOperation` dispatch state in `chio-kernel/src/admission_operation.part1.inc`; SQLite admission store | Real death at tool entry, before the endpoint send, leaves a spent unknown operation. Physical send cardinality still requires a qualified connector. |
| `Crash`, `Rollback` | `ProcessRuntime::open`; `ChioKernel::reconcile_durable_admission_startup`; `SqliteAuthorityStore::open_serving_with_clock` | Real process exits and serving-owner reopen, with preserved custody. Existing crash tests cover retained state; this new experiment does not roll back a live store or prove the full PR serving-epoch protocol. |
| `Approve`, `Change` | Whole-request digest in `ProcessRuntime::invoke_with_recovery`; existing governed intent/approval verification | Rebinding source parameter, version, recipient, request ID or capability rejects before another send. Full all-owner materialized-artifact approvals and semantic requirements digests are supplied PR semantics, not established by these tests. |
| `Lookup`, `Evidence` | Existing funded example `execution_evidence::{validate,retained,verify_claim}`; PR recovery/provider participants | Source-only comparison. No native E1 authoritative lookup/absence-closure experiment here; the real endpoint is E2. |
| `Permission`, `ReadResult`, `Release` | Native output-digest delivery contract in `durable_admission_sqlite.rs`; current process request admission; PR artifact/release owners | Signed mismatch denial with no output/charge and positive matched delivery are tested. Generic channel-complete release and read-revocation correspondence to KW1 remain unproved. Application file release in the new harness is explicitly not that mediator. |
| `ClearKnowledge`, `Translate` | PR flow/artifact/confinement and authority-scope translation owners; `subcontract::permit::{verify,verify_parent}` is an existing remote permit anchor | No complete native monotone-knowledge or domain-qualified translation test in this profile. The family adapter only preserves its declared symbolic identity mapping. |
| `Dependency`, `AdvanceDependency` | PR scoped observation, typed dependency and held-reservation owners | No native cross-owner lifetime experiment. KW1 checks remain finite model evidence. |
| `Fund`, `Accept`, `Pay`, `RefundParent` | Existing funded example allocation/settlement and receiver permit paths; native SQLite budget/payment journals | Native aggregate-family and held-payment tests are fresh. Full distributed obligation/backing composition and independent earned-child settlement were not exercised here. No monetary-gate pass is claimed. |
| `Settle` | `SqliteAdmissionOperationStore` capture-waiver and payment-journal recovery; admission startup reconciliation | Tests establish retained capture/release and original-term waiver behavior. They do not implement every modeled provider closure or cross-owner settlement port. |
| `Project`, `Gc` | Native durable terminal projection; PR artifact provenance/quarantine/retention owners | Current admission persistence is tested; the PR artifact lifetime/GC refinement is unmeasured. |
| `Plan` | PR recoverability advisor owner | No production correspondence assertion. The local model supplies deterministic bounded advice only. |

The pre-code [design](native-design.md) deliberately adds no alternative recovery
authority or production adapter. Existing abstract admission Lean proofs are
unchanged and remain model proofs, not equivalence proofs for these Rust paths.

## Physical observations

The [owning test](../../../../crates/kernel/chio-process/tests/cross_owner_recovery.rs)
runs five cuts for both two and three local owners. Every other owner completes
and replays while the first recovers twice. Each call retains one process charge
and a strict original execution nonce. A separate endpoint OS process appends
and fsyncs the observable effects; its log is never an input to recovery.

| First-owner death cut | First-owner effects after recovery | Recovery behavior |
| --- | ---: | --- |
| Before `invoke` / admission | 1 | First actual admission completes |
| Tool entry, after native capture, before wire send | 0 | Unknown, no redispatch, no output |
| After endpoint effect, before tool return | 1 | Unknown, no redispatch, no output |
| After durable returned outcome, before application release | 1 | Original completed receipt replays |
| After application release | 1 | Original completed receipt replays |

All other owners have exactly one effect. These are 10 trajectory schedules,
plus the hidden-retry counterexample, not 11 independent deployments. The new
test does not cover every internal admission-intent/capture cut, native release
checkpoint, authenticated remote edge or monetary obligation. Existing SQLite
tests cover additional logical finalization and payment cuts without claiming
that those tests themselves kill an OS process.

The counterexample connector sends twice inside one `invoke`. The kernel counts
one logical call; the endpoint records two effects. This falsifies an
unconditional external-effect cardinality claim. KW1's qualified one-send port
remains an explicit premise. Connector qualification must include the transport's
actual retry behavior and dispatch boundary; kernel receipts alone are insufficient.

## Corrections and acceptance

An initial assertion wrongly required byte-identical refusal receipts for an
unknown operation. The retained observations show fresh trusted time and signing
identity on subsequent refusals. The corrected assertion preserves operation ID,
native binding, dispatch commit, operation version, unknown outcome and nonce;
completed outcomes still require the exact original signed receipt. This is a
model/native reconciliation, not a change to production behavior.

The inherited contractual-resolution test used a removed clock API. Migrating
it to explicitly injected fixture clocks revealed a second fixture error:
returning a trusted owner from an expired future time to the past correctly
triggers wall-clock-regression refusal. The expiration check now has a separate
fixture; the race/replay test never rewinds the owner. Both rejection and positive
waiver/restart paths remain tested. The durable-admission suite has 25 tests.

Initial compile failures, the receipt-boundary failure and the clock-regression
diagnostic are retained under `native/`. The initial no-feature aggregate-family
binary had zero tests and is not counted; qualification explicitly enables
`worker-server`. Final assertions and artifact checks are in the source-bound
verification record. Task 5's local fault experiment is complete when that record
passes. Its **full native composition acceptance remains open**, with the missing
seams enumerated above rather than declared satisfied by prose.

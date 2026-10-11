# Execution review: response path, evidence tokens, structured rejection and response simulation, October 1, 2026

Scope: the execution-boundaries part of commits `f4bd52c981`, `d1ac03a40b`, `754c798655`,
`ea6c0a27cc`, `23f5f875e7`, `cef19eff5f`, `eb3dcdc641`, `0cec93924a`, `eadddecbe5`,
`ef0f074d37`, `69c7d416b6`, `0d1b7e4941`, `8153ab54c7`, `fc8eb0c9be`, `3f279844e4`,
`f25cd61f49`, `d29c3d8188`, `c7a20fe626` and `93277b4209`, judged against mechanisms A, C
and D and the Acceptance section of
`docs/superpowers/specs/2026-09-26-unrepresentable-defects-design.md`, corrections 1A to 1E
of `docs/superpowers/plans/2026-09-26-security-engineering-excellence.md`, and the records
`docs/reviews/2026-09-26-resumed-execution.md`, `docs/reviews/2026-09-26-execution-boundaries.md`
and `docs/reviews/2026-09-27-production-response-simulation.md`. Base `07e963e8f5`, tip
`a2630c20a1`; all paths are at the tip unless a hash prefixes them. Method: diff reading
followed by a trace of the resulting code at the tip, with scripted census counts (method
stated inline); no Cargo run was needed because no finding is High or Critical.

**Judgment: The property that matters holds. I traced every route into live dispatch and
effect execution and found none by which a simulation report, a dry-run plan or a plan
without a bound live mode can reach an effect or mint live authority: the binding is
mandatory at decode and covered by the hashed authorization body that governed intent,
submission proof and threshold approvals all bind, fresh entry points take
`FreshLiveAdmission` by type, recovery authorities are constructible only inside the
recovery module, and the scheduler re-checks live mode on every iteration. What is weaker
than recorded is the enforcement around that property: the live-mode guards outside the
type system have no negative test (RP1), the structured `DispatchRejection` is flattened to
a string on the kernel path that production dispatch actually takes (RP2), and the newest
code, the simulator, reintroduces 24 cause-discarding conversions the dispatch plan
forbade (RP3). Mechanism D was never planned or built, and the T1 acceptance counts are not
met workspace-wide. The binding and the isolated simulator were worth their cost; the
parallel public dispatch-preparation API and the compile-fail tests that guard it were
not.**

## Plan conformance

| Plan item | Recorded status | Verified status | Evidence |
| --- | --- | --- | --- |
| 1A private binding fields, wire type with `deny_unknown_fields`, `try_from` | Done | Done | `crates/security/chio-security-types/src/response_execution.rs:35-47,67-80` |
| 1A delete detached `validate()` | Done | Done | No `validate` on `ResponseExecutionBinding`; construction is `new` or `try_from` |
| 1A expected and observed versions in the rejection | Done | Done | `response_execution.rs:86-88`; test `execution_binding_rejection_carries_the_compared_versions` |
| 1A compile-fail literal and specific deserialization error | Done | Done | `response_execution.rs:27-34`; `crates/security/chio-security-types/tests/response.rs:188-245` |
| 1B three authority types | Done | Done, different shape | `FreshLiveAdmission` at `response_execution.rs:114-128`; `CommittedDispatchAuthority` and `CommittedAdmissionAuthority` wrap `ActiveResponseExecutionRequestParts` (`active_response_committed_recovery/authority.rs:11-58`) instead of the spec's field list; constructors are `pub(super)` to the recovery module |
| 1B fresh dispatch and both admission entry points take `FreshLiveAdmission` only | Done | Done | `state_machine.rs:110-113`, `active_response_coordinator/admission_request.rs:25-37`, `active_response_dispatch.rs:124-161`, `active_response_executor.rs:273-286` |
| 1B "grep for remaining mode checks and expect only the constructor" | Done | Overstated | Six production call sites besides `FreshLiveAdmission::new`: `active_response_committed_recovery.rs:374,835`, control-plane `active_response/executor.rs:177`, quarantine `executor.rs:192`, `state_machine.rs:360`, SQLite `response_outbox.rs:222`. The two recovery sites are the recovery rule itself; the rest are defense in depth |
| 1B negative tests per `DispatchRejection` variant at every entry point | Open | Open, and the gap matters | RP1 |
| 1B module doc that signature coverage of `execution` blocks stripping | Done | Done | `response.rs:170-176`; key-set pin `754c798655` |
| 1C mandatory binding, legacy removed, distinct recovery authorities | Done | Done | `response.rs:133,180`; no response-path `legacy` hits; recovery split at `active_response_committed_recovery.rs:324-561,828-870` |
| 1D one discriminant per rule | Partial | Partial | `DispatchRejection` (11 variants), `PlanDefect`, `RecordDefect`, `CanonicalFailure` exist; `StateMachineError::InvalidTiming` still covers six rules (`state_machine.rs:548,808,819,822,877,887`) |
| 1D replace `map_err(\|_\| ...)` with source chaining | Partial | Partial | Quarantine production discards 93 at base to 29 at tip (scripted count excluding `cfg(test)` modules and test files); correlation's 16 untouched; seven new in `simulation.rs` (RP3) |
| 1D reason reaches receipt and operator log | Partial | Scheduler path only | Codes flow through `rejection_codes.rs`; the kernel-owned dispatch path flattens to strings (RP2) |
| 1E one declaration and one name per response domain; tests use literals | Done | Done | `response_domains.rs:4-7`; scripted scan finds every `chio.response-*`/`chio.active-response-*` byte domain declared once in production code; `tests/state_machine/domain_compatibility.rs` uses literal known answers and no test names the constants |
| Spec A: `compile_fail` per token type | Not tracked | Partial | Present for `ResponseExecutionBinding`, `FreshLiveAdmission`, `ResponseStateMachine::create`, `ResponseDispatchPreparationRequest`; absent for `ActiveResponseExecutionRequest` and `VerifiedResponseSimulationAuthorization` (RP6) |
| Spec A: all-`pub` `Verified*`/`Authorized*` in TCB 18 to 0; with `Deserialize` 4 to 0 | Not tracked | Not met | RP8 |
| Spec C: every variant maps to a registered code; one registry | Not tracked | First half met, second not | All 84 `urn:chio:error:*` literals in quarantine and security-types exist in `spec/errors/registry.yaml`, but nothing enforces it; `PortError` still carries ad-hoc `store.*` codes (`ports/error.rs:59-133`) and the simulator uses `simulation.*` codes |
| Spec D: escape-hatch gate with allowlist and violating fixture | Never planned | Absent | No such gate in `scripts/`; `check-trust-boundaries.py` checks 14 sealed proof types and `UntrustedJsonText` constructor sites only (RP6) |
| Addendum: 1A/1B/1C/1E land inside Packet 1's reviewable commit | Not stated | Not met | Spread over seven commits ending in `f25cd61f49` (236 files, +4,291/-1,488) (RP9) |
| Deployment config binds execution mode | Done | Done | `crates/security/chio-active-response-authority/src/config.rs:26-46,163-185`; tests reject missing, unknown and substituted modes and v1 schemas |
| Production simulation isolated from live authority | Done | Done | See Verified clean |

## RP1. Medium: the live-mode guards that the type system does not cover have no negative test

The types make a dry-run plan unusable at the fresh entry points. Everywhere else the live
rule is a runtime check, and none of these checks is exercised by a test that supplies a
dry-run plan:

- kernel committed-admission resume, `active_response_committed_recovery.rs:372-375`;
- kernel committed-dispatch recovery, `active_response_committed_recovery.rs:834-839`;
- control-plane executor validation, `crates/platform/chio-control-plane/src/security/active_response/executor.rs:175-178`;
- scheduler effect loop, `crates/security/chio-quarantine/src/executor.rs:189-193`;
- planning-outbox recovery when the stored plan's mode differs from the host's,
  `event_consumer/recovery.rs:518-520`;
- outbox invariants (Simulated requires dry-run; a prepared binding requires live),
  `crates/platform/chio-store-sqlite/src/security_state/response_outbox.rs:212-225,855-871`;
- the authority daemon's selection and artifact checks,
  `crates/security/chio-active-response-authority/src/store.rs:813-815,824-826`.

Evidence: `DryRun` appears in no test under `chio-kernel`, in no test of
`chio-control-plane/src/security/active_response/`, in no `chio-store-sqlite` test, and in
`chio-active-response-authority` only in the config tests. Every real-adapter fixture that
uses dry-run pairs a dry-run plan with a dry-run host, so the mode-switch branch at
`recovery.rs:518` is never taken. The two quarantine tests that do use dry-run cover
`FreshLiveAdmission::new` and a direct transition into `Applying`
(`tests/response_dispatch.rs:253-306`), both of which the types or `state_machine.rs:360`
already enforce.

Failure scenario: a refactor of `resume_dispatch_committed_active_response` drops the check
at `:373` (the authority is minted 170 lines later at `:544`, and nothing at the
constructor repeats the rule). CI stays green. A dry-run plan whose outbox row reached
`Prepared` (after a host profile switch, or through a future bug in the outbox validator,
also untested) would then resume into a committed dispatch. The scheduler check would still
refuse to apply effects, but that check is untested too, so the same refactor discipline
that removed one can remove the other without a red test.

This is the 1B negative-corpus item, which the plan honestly leaves open. It is listed here
because the execution record states "Fresh admission, committed admission recovery and
dispatch recovery all require Live" as delivered behavior, and only the first is
regression-protected. Fix: one negative test per guard above, each driving a dry-run plan
through the production entry point, asserting the specific rejection, and mutation-checked
by deleting the guard (standard rules 10.1 and 10.2). Also give the daemon's mode mismatch
its own code; today it is reported as `active_response.not_pre_admitted`
(`store.rs:783-797,813-815`), which names a different rule (standard 3.1).

**Confidence:** Confirmed. Source trace: no test constructs the input that reaches any of
these branches.

## RP2. Medium: `DispatchRejection` is flattened to a string on the kernel path that production dispatch uses

`DispatchRejection` names each rule and carries a registered code
(`crates/security/chio-security-types/src/response_dispatch.rs:11-164`). The quarantine
scheduler path keeps it. The path every production dispatch now takes does not:

1. `prepare_kernel_dispatch` formats the `StateMachineError` into
   `ActiveResponseExecutorError::RejectedBeforeCommit(String)`
   (`crates/kernel/chio-kernel/src/kernel/active_response_dispatch.rs:100-104`).
2. The coordinator formats that string again into `active_response_denied(...)`, which is
   `KernelError::GovernedTransactionDenied(String)`
   (`active_response_coordinator.rs:786-794`, `execution_validation.inc:813-818`).
3. `KernelError::report` gives every such denial the code
   `CHIO-KERNEL-GOVERNED-TRANSACTION-DENIED` (`kernel/error.rs:536-540`), and the control
   plane copies that code into the outbox (`event_consumer/coordinator.rs:984-1009`).

The same happens at admission: `FreshLiveAdmission::new`'s `DispatchRejection` becomes a
formatted string at `event_consumer/admission_request.rs:27-33`.

Failure scenario: preparation refuses a dispatch because the capability digest differs, or
because the first lease falls outside the plan window. The outbox and the operator log
record the generic governed-denial code; the rule survives only as English inside a
`reason` string. A caller cannot match on it, a receipt cannot carry the registered
`response-dispatch-*` URN, and a Packet 4 fuzz oracle cannot tell which boundary refused.
The tests at this seam already show the cost: they compare exact English sentences
(`active_response/authority_tests.rs:51-53,64-67`).

The correction 1D checkpoint in the umbrella plan says dispatch discriminants "retain
registered codes through executor errors, scheduler retries, operator logs and signed
receipt construction." That is true of the quarantine scheduler path and false of this
one. The flattening predates the slice (`07e963e8f5:crates/platform/chio-control-plane/src/security/active_response/executor.inc:323-326`),
but `3f279844e4` rebuilt this exact seam and kept it. Fix: give `ActiveResponseExecutorError`
a typed `Rejected(DispatchRejection)` variant (standard 3.4: typed errors at every component
seam) and an active-response denial variant on `KernelError` that reports the inner code.

**Confidence:** Confirmed. Source trace through the three conversions listed.

## RP3. Medium: the simulator, the newest response code, reintroduces cause-discarding conversions and an unregistered code namespace

The dispatch plan's commit rule 4 forbids any new `map_err(|_| ...)`
(`docs/superpowers/plans/2026-09-26-security-execution-dispatch.md:69-74`), and standard
rule 3.2 forbids discarding a cause. `f25cd61f49` added 24 such conversions in the four new
simulation files; at the tip they are `response_simulation_report.rs:81,122,138,158,180,189,190,199`,
control-plane `security/response_simulation.rs:50,95,98,115,165` plus the `Err(_) =>` at
`:177`, SQLite `security_state/response_simulation.rs:22,108,110`, and quarantine
`simulation.rs:25,105,138,139,304,437,438` plus `:447`. The count comes from the commit's
added lines, separating these from code moved between files in the same commit.

Two of them undo work done a day earlier. `simulation.rs:25` maps a `PlanDefect` (which has
its own registered code) to the string code `simulation.plan`. `verify_response_simulation_receipt`
and `ResponseSimulationReport::validate` collapse wrong signer, invalid signature, wrong
configuration digest, identifier mismatch, mode, window, approval-shape and model-result
mismatches into `PortError::integrity_failure()` or `invalid_data()`
(`response_simulation_report.rs:54-94,149-195`). The simulator's own codes
(`simulation.execution_mode`, `simulation.stale_scope`, ...) are ad-hoc `ErrorCode` strings,
the second registry that mechanism C set out to remove.

Failure scenario: an operator sees a dry-run report rejected on restart with
`store.integrity_failure`; whether the signer rotated, the deployment digest changed or the
stored report was tampered with is not recoverable from the error. In `run()`, a failed
append is discarded and replaced by a readback (`response_simulation.rs:172-178`), so a disk
or integrity fault during append surfaces as `unavailable` with no cause. The addendum's
acceptance line "Packet 1's negative tests assert specific variants" is therefore not met:
the simulation tests assert error kinds or substrings
(`crates/platform/chio-control-plane/tests/response_dry_run.rs:90-112`,
`event_consumer/tests/real_adapter/response_dry_run.rs:224-233,254`). Fix: a
`SimulationRejection` enum with one variant per rule, sources chained, codes registered in
`spec/errors/registry.yaml`; tests assert variants.

**Confidence:** Confirmed. Diff count of added lines in `f25cd61f49` and source reading at the tip.

## RP4. Low: after legacy removal the live rule was not restored to the dispatch builder, the SQLite dispatch store or the recovery authority constructors

`3f279844e4` removed the mode check from shared dispatch preparation so that verified legacy
recovery could project a historical plan (execution-boundaries record, "The legacy recovery
regression exposed a real defect"). `f25cd61f49` then deleted legacy plans without restoring
the check. At the tip, `prepare_dispatch` (`active_response_dispatch.rs:177-313`) and the
public projections it uses (`state_machine/projection.rs:16-101`) accept a dry-run plan, and
the SQLite store's `validate_response_dispatch_request`
(`crates/platform/chio-store-sqlite/src/security_state/dispatch.rs:697-780`) commits one,
because `ResponseDispatchCommitRequest` has public fields (`ports/dispatch.rs:91-96`). The
outbox store checks mode (`response_outbox.rs:212-225`); the dispatch store does not.

There is no production route today: the only producers of a sealed request either hold a
`FreshLiveAdmission` or were minted after a live check. But `CommittedAdmissionAuthority::new`
and `CommittedDispatchAuthority::new` carry no rule themselves
(`active_response_committed_recovery/authority.rs:17-25,44-49`), so the guarantee for
committed admission rests on statement order inside one 190-line function, which is the
"convention enforced by memory" the spec was written to remove ("each type carries its own
rule exactly once"). Fix: `plan.require_live_execution()?` at the top of `prepare_dispatch`
and in the SQLite validator (standard 4.4), and move the live check into the two recovery
constructors.

**Confidence:** Confirmed. Source trace; the defect is the rule's location, not a reachable path.

## RP5. Low: the control plane's execution mode is caller-asserted, with a live default

The function that ties the host profile to the verified deployment mode, digest and receipt
signer, `ActiveDefenseDeploymentConfig::response_execution_profile`
(`chio-active-response-authority/src/config.rs:141-161`), has no production caller.
`KernelAttestedFindingResponseCoordinator::new_unbound` accepts any
`ActiveResponseExecutionProfile`, whose variants are public
(`security/response_simulation.rs:193-197`), and `ProductionResponseSimulator::new` accepts
any non-zero configuration digest (`:73-90`). The coordinator trait also defaults
`execution_mode()` to `Live` (`event_consumer/coordinator.rs:183-186`), although the
simulation module states "there is no inferred default" (`response_simulation.rs:192`).

Impact is bounded: `ProductionActiveDefenseHostConfig::new` takes the concrete coordinator,
which overrides the default (`security/orchestration.rs:93-104`, `coordinator.rs:527-537`),
and a host whose mode disagrees with the authority daemon fails closed at the daemon and at
`recovery.rs:518`. The residual defect is evidence binding: a dry-run host can sign reports
under a digest that is not the deployment's. Fix: make `execution_mode` a required method,
and make the profile constructible only from a verified deployment value.

**Confidence:** Confirmed. Source trace; no production caller of the binding function.

## RP6. Low: the response tokens production relies on are not under any gate, and mechanism D was dropped between spec and plan

The sealed-proof check in `scripts/check-trust-boundaries.py:220-233` covers the 14 types
listed in `docs/security/trust-boundary-inventory.json`. None of the response path's tokens
is listed: `FreshLiveAdmission`, `ActiveResponseExecutionRequest`,
`VerifiedResponseSimulationAuthorization`, `ResponseExecutionBinding`. A future `pub` field
on `ActiveResponseExecutionRequest` (`active_response_executor.rs:228-241`), the token every
live dispatch actually carries, would pass every gate and every test: it has no
`compile_fail` regression. Two of the three compile-fail regressions the execution record
cites guard `ResponseDispatchPreparationRequest` and `prepare_response_dispatch`
(`active_response_dispatch.rs:107-161`), a public API that no production code calls (all
eleven users are tests) and that sits outside the `admission-test-support` feature.

The spec's mechanism D (an escape-hatch gate that lists `for_test`/`from_raw`-style
constructors and fails on a new one) never became a plan item: the umbrella plan has no
checkbox for it and the remaining-work queue does not mention it. No such gate exists.
Fix: register the four tokens in the proof inventory; add a `compile_fail` for
`ActiveResponseExecutionRequest`; move `prepare_response_dispatch` behind the test-support
feature; either build the escape-hatch gate or record its withdrawal.

**Confidence:** Confirmed. Inventory and script read directly; caller list from `git grep`.

## RP7. Low: unreachable discriminants and legacy vestiges remain

`DispatchRejection::ExecutionBinding` (`response_dispatch.rs:16`) and
`ResponseShapeError::InvalidExecutionBinding` (`response.rs:1388`) can no longer be
constructed by production code: a binding is valid by construction, and its only error
arises inside serde. Both survive with a registered URN
(`spec/errors/registry.yaml:1472`) and a test that builds the variant by hand
(`tests/response.rs:216`). Legacy-era vestiges remain in test code: single-element tuple
destructuring left from removed legacy loops (`chio-quarantine/tests/response_dispatch.rs:257-260,271-276`)
and a fixture documented as seeding "the durable boundary left by an older binary"
(`active_response_executor/test_support.rs:48`) when the scenario is now a crash between
admission commit and dispatch. Fix: delete the two variants and their registry entry, and
reword or flatten the vestiges.

**Confidence:** Confirmed. `git grep` finds no production constructor of either variant.

## RP8. Note: the spec's T1 acceptance counts are not met at the tip

Census method: named-field structs whose names start with `Verified`, `Authorized`,
`Admitted` or `Validated`, in production files (test directories, `*_tests.rs`,
`test_support` and `#[cfg(test)] mod` bodies excluded), classified by field visibility,
with "TCB" meaning `crates/kernel/*`, `crates/security/*`, `chio-core-types`,
`chio-store-sqlite` and `chio-control-plane`. This method does not reproduce the spec's 18
exactly (it gives 29 at the spec's own candidate `3cd73631a1`), so I report base and tip
under one method: 29 all-`pub` TCB types with 11 deriving `Deserialize` at `07e963e8f5`,
and 18 with 7 at the tip. The spec's named cases (`VerifiedCapability`,
`VerifiedPassport`, `VerifiedActiveResponseOperatorCapability`, the four `Deserialize`
types) are all resolved, by `21c831d396` outside this slice. Remaining `Deserialize` cases
include `VerifiedOutcomeRequestV1` (`chio-core-types/src/capability/governance.rs:118`),
`VerifiedFindingPurchase` (`chio-kernel/src/finding_purchase.rs:75`),
`VerifiedFindingStatusProof`, `VerifiedFindingRecovery`, `VerifiedFixPayload`,
`VerifiedFixCommandResult` and `AdmittedChildBudgetJson`. The acceptance target of zero is
not met, and the remaining-work queue correctly describes the 14 sealed types as bounded
work rather than a workspace audit.

## RP9. Note: the corrections did not land as one reviewable change

The addendum required 1A, 1B, 1C and 1E inside Packet 1's reviewable commit. They landed
across seven commits, the last being `f25cd61f49`: 236 files, +4,291/-1,488, combining the
simulator, legacy removal, the `legacy_json` to `signed_json` rename, a wire-schema change
and 158 regenerated Python SDK files. The dependency budget was raised from 478 to 479
packages for the new kernel-to-quarantine edge (`scripts/check-dependency-budget.py:151-157`),
with a justification that cites a review document from inside the gate script. The raise is
measured and recorded; the commit size is what makes RP3 easy to miss in review.

## Execution-record claims checked

| Claim (record:line) | Verdict | Evidence |
| --- | --- | --- |
| Fresh creation and preparation require `FreshLiveAdmission`; three compile-fail regressions (`2026-09-26-execution-boundaries.md:15-20`) | True | `state_machine.rs:103-113`; `active_response_dispatch.rs:107-123`. Two of the three guard a test-only API (RP6) |
| A committed dispatch must use exact readback and cannot prepare a replacement (`execution-boundaries.md:22-27`) | True | `active_response_dispatch.rs:37-42`; control-plane `executor.rs:156-161`; `authority_tests.rs:37-80` |
| No untrusted production route through `ResponseDispatchCommitRequest` (`execution-boundaries.md:29-35`) | True | All producers are sealed; the SQLite store itself does not check mode (RP4) |
| Test-only construction helpers are behind `admission-test-support` (`execution-boundaries.md:35-36`) | Partly | `test_support.rs` is gated and enabled only in dev-dependencies; `prepare_response_dispatch` is not (RP6) |
| Dependency graph adds exactly `chio-quarantine`, ceiling 479 (`execution-boundaries.md:83-95`) | True as to the gate change | `check-dependency-budget.py:151-157`, self-test updated |
| 312 passing owning tests; quarantine 116 (`execution-boundaries.md:122-127`) | Consistent | Table sums to 312; `3f279844e4` quarantine has 115 `#[test]` plus one compile-fail doctest |
| Missing, null, unknown bindings reject; no legacy variant, default or alias (`2026-09-27-production-response-simulation.md:3-7`) | True | `response.rs:133,180`; `response_execution.rs:35-47`; six mutation vectors in `mutations-v1.json` asserted by `security_generated_vectors.rs` (`checked == 6`) |
| Fresh admission, committed-admission recovery and dispatch recovery all require Live (`production-response-simulation.md:6-7`) | True in source, untested for recovery | RP1 |
| Simulation result cannot become a live permit; no reservation or hold (`production-response-simulation.md:15-19`) | True | `active_response_simulation.rs:109-172` performs verification only; `VerifiedResponseSimulationAuthorization` has private fields and no `Serialize` |
| Dry-run installs no live effect backend and rejects live coordinator entry points (`production-response-simulation.md:36-39`) | True | `response_simulation.rs:199-231`; guards at `event_consumer/coordinator.rs:606,624,652,728,751,812,855` |
| The authority daemon checks selections and artifacts against the configured mode (`production-response-simulation.md:39-41`) | True, untested, misnamed code | `store.rs:813-826` (RP1) |
| Deployment profile assembly validates mode, digest and signer together (`production-response-simulation.md:41-42`) | Implemented, not wired | `config.rs:141-161` has no production caller (RP5) |
| 175 passing tests, per-target counts (`production-response-simulation.md:71-80`) | Consistent | `#[test]` counts at `f25cd61f49`: 11, 4, 16, 4, 5, 2, 3 match the table |
| No source-size cap or assertion baseline widened (`production-response-simulation.md:94`) | True | `f25cd61f49` touches no file under `scripts/` |
| Deployment configuration authenticates execution mode (`2026-09-26-resumed-execution.md:31`) | True as integrity binding | Mode is inside the SHA-256 deployment digest (`config.rs:163-185`), the file is owner-and-mode checked (`:292-300`), and the control-plane client pins the same digest (`active_response_authority/client.rs:226,289`). It is not a signature |
| Commit `eadddecbe5`: "the decoder reports a position, so nothing attacker-supplied is echoed" | False | serde_json error text includes offending field names, variant names and string values. The site it changed was later replaced by a typed decoder (`active_response_committed_recovery.rs:1209-1215`); other formatted serde errors remain (`execution_validation.inc:429-434`) |
| Correction 1D checkpoint: codes retained "through executor errors, scheduler retries, operator logs and signed receipt construction" (umbrella plan, 1D checkpoint) | True for the scheduler path only | RP2 |

## Verified clean

- **No route from simulation to live effect.** Every path that applies an effect goes
  through `ResponseExecutor::execute`, which re-checks live mode each iteration
  (`chio-quarantine/src/executor.rs:181-193`); `drive_apply` and `drive_rollback` are private
  to it. A dry-run host installs `SimulationOnlyEffects`, which refuses `execute` and
  `load_result` (`response_simulation.rs:201-212`).
- **Binding is part of what is approved.** `plan_body_hash` is computed over the compact
  body including `execution` (`active_response_admission.rs:522-559`); the governed intent,
  submission proof and threshold approvals bind that hash or the governed-intent hash
  (`:560-579`, `active_response_coordinator.rs:902-950`), so approvals collected for a
  dry-run plan cannot authorize its live twin. The full plan hash is recomputed from the
  body for both admission and simulation (`execution_validation.inc:672-708`,
  `active_response_simulation.rs:67-72`).
- **Kernel admission envelope.** `ActiveResponseAdmissionRequest::new` requires a
  `FreshLiveAdmission` and exact equality between the full plan and the compact body
  (`admission_request.rs:25-37`).
- **Recovery sealing.** Both recovery authorities are `pub(in crate::kernel)` with
  `pub(super)` constructors reachable only from the recovery module; their only
  construction sites (`active_response_committed_recovery.rs:544,839`) follow a live check.
  The sealed execution request has private fields and `pub(super)` constructors; its
  test constructor is feature-gated and enabled only through dev-dependencies under
  resolver 2.
- **Simulation evidence cannot pass as live evidence.** The report receipt is
  `AdvisoryEvaluation`/`AdvisoryOnly` with simulation metadata; live completion
  verification requires an `active_defense_body` of a terminal response kind
  (`execution_validation.inc:410-442`). Report verification takes the trust anchor and
  configuration digest from the verifier and recomputes the model
  (`response_simulation_report.rs:54-94,149-167`).
- **Outbox states.** `Simulated` requires a dry-run publication and no dispatch identity; a
  prepared binding requires a live plan (`response_outbox.rs:212-225,855-871`).
- **Deployment mode.** Required field, digest-covered, substitution under the original
  digest rejected, unknown modes and v1 schemas rejected (`config/tests.rs`).
- **Domains.** One declaration per response domain at the tip; known-answer test unchanged
  since `0d1b7e4941`.
- **Quarantine error types.** `StateMachineError`, `PlanDefect`, `RecordDefect`,
  `CanonicalFailure` and `ExecutorError` chain causes with `#[source]`/`#[from]`, and every
  variant has a code present in the registry; dispatch negative tests match exact variants
  through a helper that panics on any other (`tests/response_dispatch.rs:154-163`).
- **House rules on the response path.** No production `unwrap`/`expect`, no em dashes and no
  process vocabulary in the 37 production files of this slice.
- **`d29c3d8188`** removes ten copies of a test helper that built `chio-cli` into
  `target/debug`; the harness already discovers the executable through `ensure_chio_executable`.

## Recommendations for the remaining plan

1. Close 1B's negative corpus at the real seams listed in RP1, with a recorded mutation per
   guard. This is the cheapest way to make the delivered property durable.
2. Type the kernel-to-executor seam (RP2) before Packet 4's fuzz oracles are written; they
   need the discriminant, not the sentence.
3. Give the simulator a structured rejection enum with registered codes (RP3), and register
   or retire the ad-hoc `store.*`/`simulation.*` codes so mechanism C's "one registry" can
   close.
4. Restore the live check in `prepare_dispatch`, the SQLite dispatch validator and the two
   recovery constructors (RP4); remove the dead variants (RP7).
5. Register the response tokens with the sealed-proof check, add a compile-fail for
   `ActiveResponseExecutionRequest`, feature-gate `prepare_response_dispatch`, and decide
   mechanism D explicitly (RP6).
6. Derive the host's execution profile from the verified deployment and remove the
   `Live` trait default (RP5).
7. Report T1 progress with a stated census method, so the 18-to-0 target can be tracked
   (RP8).

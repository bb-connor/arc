# Kernel terminal receipts implementation plan

> **For agentic workers:** Use superpowers:executing-plans. Root implements and pushes; Claude reviews and merges. Work through the tasks below in dependency order.

**Goal:** Preserve one terminal owner for every dispatched call, including failed finalization, and sign truthful request-identity dispositions.

**Architecture:** A move-only post-effect obligation owns dispatch evidence through receipt commitment or durable saga handoff. Receipt publication distinguishes a refused append, an unknown append outcome, and an acknowledged commit with subsequent delivery failure. Non-durable evidence failures retain a reserved buffer slot and close new dispatch until supervised recovery resolves them.

**Tech stack:** Existing Rust kernel, receipt-store trait, signing backend, trusted clock, SQLite fixtures, Tokio tests and concurrency harnesses. No new dependency or store migration.

**Spec:** `docs/superpowers/specs/2026-10-04-typed-reservations-design.md`, phase 1; `2026-10-04-pure-admission-machine-design.md`, M20; `2026-10-04-durable-stop-epoch-design.md`, S15.

## Global constraints

- Original base: `b1d0ee30dfcf10bdd363023522fe678f2f45febb`. Integration includes main through `85b74cf023`. Preserve already-landed admission custody, payment journaling and bounded receipt writer repairs.
- Non-durable acceptance is one committed terminal receipt OR one buffered evidence obligation with dispatch latched. Persistence eventually requires a healthy clock, signer and store. The in-memory buffer is not crash-durable.
- A durable call leaves terminal truth to its saga. Never append a competing cancellation or deny after handing off that operation.
- Unknown append outcomes retain the original receipt identity. Absence on an early read cannot establish that an in-flight write will never commit.
- No compensation, refund or release follows merely from an unknown result. Keep positive authorizations after capture error.
- Reserve 1024 evidence slots per kernel and 4096 per multi-kernel host by default, configurable with minimum 1. A buffered record retains both permits.
- Only new-dispatch admission checks the evidence latch. Compensation, recovery, receipt outboxes and session reports remain available.
- Root owns this implementation and the M20 helper. Claude owns KERN-1 stop and KERN-4 session entry; agree shared-file hunks before integration.
- One source unit for KERN-2. Do not publish partial phase-1 behavior as completion. No broad proof campaign or schema-slot change.

## Reconciled source

`evaluation/return_recording.rs` disarms the non-durable guard before ordinary finalization. Both evaluators use it. Security outcome release occurs before return recording. Durable return failure currently terminalizes unknown and writes a separate Deny; Drop similarly writes a cancellation before terminalizing. The capture-error and non-settled payment branches discard release outcomes.

`chio_runtime` is already reserved against caller metadata. Add `receipt_context`, which is not reserved. The non-settled payment path already denies delivery; preserve that behavior despite the older spec description of Allow.

## Review focus

- A timed-out append later commits: preserve its receipt id and never append a competing terminal. Task 2.
- Clock, signer and store fail together: retain the bounded obligation and refuse further dispatch, without blocking cleanup. Task 3.
- Two authenticated namespaces reuse one request id: bindings, latches and terminal counting remain isolated. Tasks 1 and 4.
- Cancellation races durable return recording: saga custody remains authoritative; neither Drop nor recovery duplicates a terminal. Task 4.
- A payment rail reports an ambiguous capture: retain its authorization and record the actual state; never imply a successful release. Task 5.

### Task 1: Original controls and identity contract

**Files:** `kernel/tests/post_effect_receipts.rs`, `kernel/tests.rs`, new `kernel/receipt_identity.rs`, the reserved metadata list in `kernel/mod.rs`, and explicit receipt-producing call sites.

**Interfaces:** Produce `IdentityDisposition::{Reusable, Retained, Terminal}` and `with_identity_disposition(Option<Value>, IdentityDisposition) -> Option<Value>`. The producing transition chooses the enum. The helper writes the snake-case signed field while preserving other kernel metadata. KERN-1 derives `retryable_after_resume` from `disposition == Reusable`; it never chooses Retained for a definite stop.

- [x] Run the new evaluator controls on Original: malformed redaction leaves zero receipts after one actual invocation; caller `receipt_context` is accepted. Keep a successful one-receipt control.
- [ ] Add producing-row controls: early reusable denial, persisted compensated terminal, unknown submitted-commit retained denial, post-effect terminal, Allow and pending-approval exceptions. Include duplicate request ids in distinct authenticated namespaces.
- [x] Implement the typed helper, reserve `receipt_context`, and derive namespace metadata from the existing authenticated replay binding. Do not classify by error text or infer Terminal from the verdict alone.
- [ ] Run focused identity tests. Expected: correct disposition and unchanged existing metadata; caller forgery denied before invocation. Commit the task without publishing the incomplete unit.

### Task 2: Make append acknowledgement explicit

**Files:** `kernel/responses/receipt_persistence.rs`, `kernel/responses/allow_responses.rs`, new `kernel/effect_obligation/publication.rs`, receipt-store fixtures in kernel tests.

**Interfaces:** Produce an internal publication result distinguishing `Refused`, `OutcomeUnknown { receipt_id }`, and `Committed { receipt_id }`. Only the post-effect obligation can consume the committed result into `Discharged`. Post-commit errors carry the original receipt id as `DeliveryFailedAfterReceipt`.

- [x] Add a store fixture that commits then returns a timeout, plus a fixture whose queued append commits after timeout. Assert no replacement terminal is appended while original completion is unresolved.
- [x] Separate the append acknowledgement from trace allocation, settlement observation, federation co-signing, provenance and nonce creation. Keep all existing ordering and authority checks before the append.
- [x] Return post-commit delivery failures without re-entering fault-receipt construction. Unknown writes require completion/readback; unsupported authoritative readback keeps the obligation latched.
- [ ] Run publication, federation, settlement and nonce-focused controls. Expected: one persisted terminal id for every acknowledged/late commit. Commit.

### Task 3: Reserve and recover non-durable evidence

**Files:** New `kernel/effect_obligation/evidence.rs` and `recovery.rs`, kernel construction/struct fields, kernel dispatch admission checks, and hosted multi-kernel construction.

**Interfaces:** Produce move-only `EvidenceSlot`, `acquire_evidence_slot()`, `ensure_post_effect_evidence_latch_clear()`, bounded pending-record storage, and a supervised single-flight recovery owner. Recovery owns only the shared clock, signing and receipt-persistence resources it needs, never a borrowed kernel or a raw pointer.

- [x] Add slot-exhaustion and shared-host two-slot/three-session controls. Assert refusal before invocation and permit retention while buffering.
- [x] Add failing-clock/signer/store controls plus recovery while no new requests arrive. Assert cleanup and session reports remain usable while dispatch is latched.
- [x] Implement fixed capacity, reserved-slot ownership, bounded fault templates, single-flight flushing with backoff and controlled shutdown. Preserve the original append identity until its outcome is settled.
- [ ] Add latch/dispatch and worker-exit races to existing concurrency tests. Run focused tests, including no-progress and recovery cases. Commit.

### Task 4: Own both evaluators through discharge

**Files:** New `kernel/effect_obligation.rs`, `evaluation/async_evaluation_core.rs`, `evaluation/nested_flow_evaluation.rs`, `evaluation/return_recording.rs`, `kernel_drop_guard.rs`, `security_dispatch.rs`.

**Interfaces:** `post_effect(obligation, returned) -> Discharged`; private discharge construction; `Discharged::deliver(self) -> Result<ToolCallResponse, KernelError>`. Ownership includes charge, admission, child receipts, security handles and the reserved evidence slot. Bind discharge to authenticated namespace, request id, operation id when present, and matched grant.

- [ ] Extend Originals across transport failures, child flush, credential commitment and durable return-recording failure. Retain the existing pre-dispatch compensation controls.
- [ ] Move the post-dispatch half of each evaluator under the obligation. Keep pre-dispatch Drop compensation unchanged. Durable Drop retains the original saga for the existing recovery driver and never writes a competing receipt. A generic kernel-independent idle driver remains open under the ruling below.
- [x] Move `record_released` and final lifecycle release after discharge; signed terminal truth survives either callback failing. Contain callback and destructor panics.
- [x] Add receipt-binding mismatch controls and compiler-checked negative Clone/Default assertions for both owners, plus the exact post-effect return signature. These passed in the full library run. Field/module privacy is source-reviewed; no separate UI compile-fail suite is claimed. Final review repairs still require the composed evaluator and durable/drop/security suites.

### Task 5: Preserve payment outcomes and qualify the whole unit

**Files:** `kernel/validation.rs`, `payment/types.rs`, owning payment tests, protocol receipt documentation and evidence inventories touched by source.

**Interfaces:** Settlement metadata records actual `release_outcome`; capture error records `not_released`, authorization identity and a stable error code, with an audit fault.

- [x] Add a real evaluator control with a failing capture adapter: invocation happened, capture attempted, release was never attempted, positive authorization retained and terminal metadata truthful. Add rejected/non-settled release success/failure controls.
- [x] Remove release on capture error; preserve the current denial of non-settled output. Resolve the spec's Pending/Captured open decision with Claude before changing that policy.
- [ ] Run the final post-effect matrix, durable admission, security dispatch, payment and receipt-focused suites, then strict owning Clippy. Reconcile touched formal-source anchors without claiming proof execution.
- [ ] Send exact source SHA, commands, outcomes and remaining acceptance to Claude. Rebase once on actual main, verify composition, then publish one KERN-2 PR.

## Progress

- Plan approved by Claude at 2026-10-12T17:15Z; the shared identity helper was requested as an early standalone prerequisite.
- `8202e93624`: initial evaluator Original, one safe control passed and four expected failures. `/tmp/kern2-original.log`.
- Early helper #1242 `dfe5a6a621`: four Original failures at `86938625ea`; 49 focused tests and strict all-target kernel Clippy passed at Rust-identical `98d8131906`. Remaining M20 transitions and namespace binding stay in this plan.
- `0f9fedf5a2`: publication and security-release Original, one safe control passed and four expected failures. `/tmp/receipt-publication-original2.log`, SHA256 `5e43427a99c10f1b4c0729f8b1d58d31c12a1d3c6d830caa767d71bbc458472c`. The preceding fixture registration error is not runtime evidence.
- `6593042a01`: publication outcome repair, 140 focused tests and strict all-target kernel Clippy passed. The trace sequence remains allocated under the transition lock. Public error variants describe the outcome but cannot be accepted as unforgeable discharge evidence.
- `be7b7b31f1`: latch Original failed as expected: two invocations instead of one after an unresolved append. `/tmp/receipt-latch-original.log`.
- Five formal abstraction entries (seven symbol hashes) reviewed against the four named models. No proof execution. Task 3 latch/recovery, Task 4 owned finalization and Task 5 monetary outcomes remain open. Phase 2 escape-hatch tooling and full reservation-ledger conversion remain separate roadmap work.

- Task 2 split per the approved proportionality ruling: #1244 `87c77a84ef`, based on main `e10d6bc66b`, has 35 focused publication/settlement tests plus 10 protocol-refusal controls and strict Clippy passing. Independent review found one stale error oracle, reproduced and repaired. Full ownership is not implied by this slice.
- Payment outcome source `6fc0786695`: seven outcome tests, 27 simulated-payment tests and strict Clippy pass. Review found accepted non-object caller metadata suppresses authoritative financial fields; public-entrypoint Originals are in `bebfd0fb9b`, repair pending. Prepayment custody is a separate repair: Original `d404f2db1e` has two safe controls and three expected failures, plus the existing release oracle fails. Repair `a344b142f1` awaits Root gates.
- Task 3 remains unqualified draft. Review repairs cover outstanding-producer shutdown, immutable trace sequence epochs, callback panic containment inside the lock guards, child readback projection, mandatory initial byte charge, and the frozen signing floor. Root owns the resource and recovery modules; Task 4 owns finalization and nested-child production.
- Ruling: a pending durable known return remains owned by the persistent admission saga, with `DurableOutcomePending`. There is no generic kernel-independent idle finalization driver. Do not claim that acceptance or add a no-op scheduler. A durable nested call separately reserves child-evidence capacity before the first child; `ChildrenOnly` recovery never mints a competing parent terminal.
- Ruling: unknown child append resolution requires a complete retained-history API with an unsupported default. Legacy `load_child_receipt` defaults to an ambiguous miss and SQLite's implementation is live-only. The additive readback is prepared in `fix/retained-child-receipts`; no mutable-row-only absence proof is permitted.
- Evidence capacity measures retained canonical payload bytes with bounded envelope headroom. Fault templates retain complete valid action parameters; oversized templates are refused before dispatch. Child admission reserves count and byte capacity before beginning a child. Fault-only oversized financial references must carry explicit omission plus their original digest, never silent truncation or invented settlement truth.

## Integration checkpoint (2026-10-12)

- Identity #1242 merged as `0ab30ba50e`; publication #1244 merged as `74570d7ff7`; payment outcomes #1248 merged as `cfee00fa7d`. The payment entrypoint rejects non-object caller metadata before effects. Its final x86 evidence is nine outcome tests, 27 simulated-payment tests and strict owning Clippy.
- Four callback/clock/publication Originals failed at `2af82c3e31`. Repair `2f87578f49` passed those controls and the same binary passed 39 ownership, recovery, publication and payment tests. This is bounded evidence, not qualification of later changes.
- Shutdown and child-client Originals at `52b86d4cfb` both failed at runtime. Repairs `b1762428e5` and `92361a9403` retain the waiter synchronization and the unsigned child before entering the client. Their composed GREEN is pending.
- Terminal binding now includes evaluation identity, authenticated namespace, request, capability, matched grant, server, tool, policy and input. DischargeBinding::validate_receipt rejects mismatched terminal identity before append. The later Discharged comparison duplicated the same cloned binding and was removed after review. Preparation and two-tenant controls passed in the 1753-test library run.
- The composed strict run found unchecked internal Option invariants and oversized delivery/error variants. They are being repaired without lint waivers. The stage-label control is checking that a post-commit execution-nonce failure is not relabeled as provenance.
- Retained-child readback uses complete authenticated live/archive history with an unsupported default. Original `b0b6ce674c` and repair `f8696157fc` are awaiting the corrected SQLite qualification. The two earlier wrong-import attempts are compile refusals, not runtime evidence.
- The prepayment retry repair remains separate. Its first GREEN run exposed cleanup of a replayed hold (four passing controls, one failing); the next repair derives Fresh/Replayed/Unknown cleanup custody atomically from the authorizing store. Unknown or replayed custody cannot authorize compensation.
- The historical PostAdmissionDropGuard abstraction does not prove the new retained-child recovery transitions. Source-anchor reconciliation preserves that distinction. Generic durable idle finalization also remains open; the original admission saga remains the durable owner.

## Current acceptance checkpoint

- Source candidate `69894cc084` includes main `61bb9eb715`. The full kernel library suite and strict all-target Clippy are running on this immutable source; the prior broad run (`b8a17e218a`) had 1687 passing and 61 failing tests. Those failures exposed masked original errors, original-saga incident recovery and old synchronous Drop expectations. They are not a passing qualification result.
- `b7fff5109d` retains original post-effect errors and records unknown durable outcomes through the original saga only. `69894cc084` requires the same operation, dispatch binding and incident identity across replay. Cancelled futures retain DispatchCommitted until the real recovery driver runs; no second frontdoor receipt is allowed.
- `d446f43d2e` reproduced contradictory economic metadata: a later short payment reference retained the earlier omitted reference's digest. `a7e8cde180` replaces companion fields with the observed value and preserves unrelated authority fields. Controls also cover null references and large-to-safe integer replacements. Focused GREEN is part of the active composed run.
- Retained-child #1256 merged as `df30bfd62c`. Original `b0b6ce674c`: kernel unsupported-default control passed, SQLite live control passed and five retained-history cases failed. Repair `f8696157fc`: kernel control and all six SQLite cases passed, as did strict Clippy for both owners.
- Prepayment cleanup is a separate candidate. Original `8146595f2a` has two passing controls and five runtime failures. Complete repair `9cad87bd0d`, followed by the original-saga cancellation control `0fdaefa7e8`, is under x86 qualification. The earlier `032c689803` attempt did not compile and is not GREEN evidence.
- Formal review adds mandatory source anchors for the actual fault observation and saga incident helpers. Historical model transitions and evidence remain unchanged. Source-drift acceptance does not prove retained recovery liveness, strict production timestamp order or a generic durable idle finalizer.

## Review repair checkpoint

- `69894cc084`: full kernel library 1753 passed, zero failed or ignored.
  Strict Clippy found two oversized post-effect error returns; `8f7321b9ac`
  boxes the source error without changing its classification. Later source
  changes are not covered by that earlier full run.
- P2-1 and P2-3: `f70c35efcb` removes the unreachable discharge comparison and
  the unused legacy post-dispatch Drop branch. `abd57871c0` moves the eight-cell
  disposition control and direct reservation test onto the actual post-effect
  owner. Missing reserved fault/child custody now emits an audit fault.
- P2-2 and P3-6: Original `67a84bb0e2` is under qualification. Controls require
  320 real simultaneously pending ordinary calls, coherent host byte capacity,
  checked overflow, independent explicit byte bounds, and continuation of an
  already-dispatched durable parent while another call latches new dispatch.
- P3-7: both latch checks remain. The early check avoids acquiring budget,
  payment and credentials under a known latch. The dispatch-time check closes
  the race while admission waits. Claude accepted this distinction.
- Prepayment custody #1261 merged as `0accc90c72` and is composed here. Its
  exact source has focused kernel/store/control-plane tests and strict Clippy
  passing on x86; replayed or unknown holds cannot authorize generic cleanup.
- The new escape-hatch gate explicitly inventories the cfg(test)
  `EvidenceQueue::empty_for_test` constructor. It creates an empty queue for
  capacity/shutdown controls; it cannot be called by a production build.
- `3577c7c62c` adds the real SQLite incident/return version-fence control. Both
  write orderings must preserve the winning operation and refuse mutation by
  the loser. This test-only addition still awaits its focused run.
- Remaining qualification: capacity/continuation repair, final owning suites
  and strict Clippy, refreshed reviewed source anchors and their checker tests,
  file hygiene, and Claude's exact-source review. Generic durable idle
  finalization and crash durability of the memory buffer remain outside this
  source unit; neither is claimed complete.

## Identity disposition at receipt producers

The response builders require a typed disposition supplied by the producing row. They insert the kernel-reserved metadata before signing. Callers cannot supply this namespace. No builder infers identity from the absence of metadata or from an error message.

| Producer | Disposition |
| --- | --- |
| Validation, negotiation, overload and persistence refusal before admission | Reusable |
| Resource read refused without a persisted operation or effect | Reusable |
| Typed unknown outcome from submitted durable Begin or participant mutation | Retained |
| Confirmed live operation or conflicting replay | No new receipt; return the admission error and preserve the original owner |
| Confirmed compensation or durable terminal projection | Terminal |
| Explicit unconfirmed dispatch commit | Retained |
| Effect already executed, including cancellation or output refusal | Terminal |
| Successful cleanup without a durable operation or remaining custody | Reusable |
| Cleanup that leaves custody bound to the request | Terminal |

Durable admission returns a typed failure with an optional receipt disposition selected at its storage boundary. Before admission it may sign Reusable. A typed storage OutcomeUnknown permits Retained. A confirmed live operation permits no new receipt; confirmed compensation permits Terminal. The original typed error remains available to the caller.

Original controls use the actual ordinary and nested entrypoints: expired signed capabilities must produce Reusable with no invocation; a missing session root after durable admission must produce Terminal after compensation. Keep healthy Allow and approval-required controls, and the existing CommitUnconfirmed Retained control. Approval-required is a distinct response state even when its signed wire decision is Deny.

No caller gains retry authority from a Terminal or Retained response. The remaining recovery-driver and historical model limitations remain open.

## Producer validation checkpoint

- Original `8bedb91905`: early-refusal controls pass twice and fail twice (ordinary missing Reusable; nested loses the benign metadata field before reaching its disposition assertion). The persisted-compensation control fails on missing Terminal. The approval-required control passes without a disposition.
- Original `8f3aa7d058`: both durable Begin controls fail on the intended signed metadata assertions. An acknowledgement lost after storing the row lacks Retained. The conflicting-request oracle expected Terminal, but source review rejected that expectation: the original operation was still live, so the M20 contract permits no new terminal receipt. That assertion is superseded by the genuine failure at `4eace87424`. The conflict preserves its live original owner, unchanged operation and zero dispatch count. Earlier conflict-fixture attempts allowed startup recovery to compensate the owner and do not establish the disposition defect.
- `11aa111f7b` composes the typed refusal producers and explicit Begin phase errors. Library compilation passed; focused runtime tests and the actual SQLite mutual-refusal test are pending. The direct durable terminal builder and its replay metadata validation are under separate review before final qualification.

## Durable producer and replay checks

- `aff93ea615`: 38 focused kernel tests pass, including namespace separation, compensation, cancellation and unknown dispatch. The exact SQLite mutual-refusal control passes one test covering both write orders; the earlier incorrect filter ran zero tests and is excluded.
- Original `773b6848a6`: unknown broker acknowledgement fails because it reports Terminal rather than Retained. Durable output finalization has two passing controls and three failures for missing Terminal (delivery denial, incomplete stream and recovered incomplete stream).
- Original `4eace87424`: a conflicting reentry into a live operation incorrectly returns a new signed Terminal receipt. The test requires an error while preserving the original operation and zero effects.
- `e8d9429e82`: production repairs bind durable terminal receipt metadata to the authenticated stored namespace and reproduce it during exact replay validation. Typed unknown storage outcomes sign Retained; confirmed live failures preserve their owner without a competing receipt. Focused validation is running.

## Producer validation renewal

- `4036e6e497`: 47 focused kernel tests pass. This includes all five durable output/replay controls, all three admission identity controls, all thirteen session report controls, and existing cancellation, cumulative approval and dispatch-commit controls.
- Report Original `7fe4e2506e`: all three session entrypoints fail because the conflict report carries an execution decision. `fdf41cdfd0` signs a trace observation with the exact conflict reason and preserves the original pending approval and its successful continuation.
- The previous aggregate-budget unit test never reached quota exhaustion: its single-operation fixture rejected the second request as a replay conflict. The replacement uses the public SQLite integration boundary and must prove a distinct compensated second operation, no second invocation, no second-grant usage, and an unchanged first terminal operation. Its initial payment-specific observer was unsuitable for this non-monetary test; neither that failure nor the earlier cyclic unit-test compile refusal is qualification.
- Resource refusal Original `f01093074f` requires signed Reusable metadata bound to the exact request ID and authenticated tenant namespace. This test and the corrected SQLite aggregate control remain pending.
- The standalone cancellation repair is rebased onto main as `a45d6b8e70`; its three focused cancellation tests pass. Strict Clippy remains in progress. The predecessor `bfff9e712e` passed all 1,725 kernel library tests and strict Clippy on x86_64.

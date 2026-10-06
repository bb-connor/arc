# Design: crossing primitive and fused-commit hot path

- Status: PROPOSED (revision 3, after the wave 2 cross-spec review of specs 3, 5 and 8, 2026-10-05)
- Date: 2026-10-04
- Scope:
  - One kernel primitive, `CrossingTx`, that executes every point where an effect or a byte leaves Chio custody, as one transaction shape in the serving writer.
  - Three commit classes that decide when the rollback anchor must be durable before an acknowledgement.
  - Fast paths that fuse today's ten authority commits per side-effecting call into three, and keep read-only calls receipted.
  - Group commit, later per-domain writer sharding, and asynchronous materialization of receipts that stay durable before allow.
  - It changes durability plumbing and commit grouping. It does not change authority semantics, except for the explicit contract changes listed in section 15.
- Owners:
  - `chio-store-sqlite`: writer loop, savepoint batches, commit classes and anchor policy, custody check, crossing records, receipt mover, sharding.
  - `chio-kernel`: `CrossingTx` plans, crossing inventory, effect execution for spec 9.
  - `formal/apalache`: the new crossing model.
  - The process host and benchmarks: acceptance.
- Related: `2026-07-12-admission-operation-design.md` ("Corrected invariant", participant model); M: `docs/security/engineering-standard.md` rule 5.1; M: `docs/security/native-restart-safety.md`; M: `docs/adr/ADR-0013-async-receipt-durability.md`; M: `docs/adr/ADR-0022-store-and-kernel-decomposition.md`; `spec/PROTOCOL.md` section 6.
- Citations: `M:` = `integration/process-security-m4` at `19df31ad9`; `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`; `R:` = #1172 docs; `W:` = the uncommitted recovery worktree `standalone/arc-worktrees/recoverable-agent-runtime-20261002` as of 2026-10-04; `B:` = `origin/wip/bench-results-2026-09-13` (#1163). Unprefixed kernel paths are under M: `crates/kernel/chio-kernel/src/`, unprefixed store paths under M: `crates/platform/chio-store-sqlite/src/`.
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md` bet 2. Reviewed in `review-spec10` (S10-01 to S10-29); see the review disposition section.
- Siblings: the umbrella `2026-10-04-ftl-lessons-program-design.md`; specs 1 to 8 (`closed-kernel-abi`, `authority-faults`, `typed-reservations`, `authority-space-teardown`, `unified-event-queue`, `opaque-adapter-context`, `microkernel-isolation-backend`, `durable-stop-epoch`); spec 9 `pure-admission-machine`; spec 11 `integrity-gated-admission`. All are `2026-10-04-*-design.md`.

## Revision 3 changes

The adversarial reviews of specs 3, 5 and 8 found contradictions with this spec. The wave 2 shared decisions resolve them here, and the review disposition section lists each finding under "Wave 2 (cross-spec)".

- **Stop dispositions per crossing kind (S8-11, S8-27).**
  - The Stop column of section 4.2 now carries spec 8's `StopDisposition`: `Deny`, `Withhold`, `Settle` or `AllowIfContainment`. Spec 8 section 5 is normative.
  - Containment is no longer refused by the check that spec 8 allows. Settlement of earlier effects stays available.
  - `ExternalPrepare` carries a purpose, `Authorize` or `Settle`.
  - `StopEpoch` takes `(kind, scope, disposition)` and reads durable heads together with process-local latches (S8-02).
- **A stop is a temporary refusal (S8-12, S8-17, S8-18).**
  - `KernelStopped` writes no deny tombstone, and tier-1 denials sign a receipt only (X15).
  - A caller report is a progress-only return record that is never stop-checked (section 7).
  - A two-commit read refused at its outcome commit writes a return record and returns `OutputWithheld` (X14).
- **The writer loop cannot refuse a stop (S8-03).** Stop, restrict, relax, resume, rollover and reconcile commits run in a priority lane that is exempt from `Overloaded`, `max_batch` and the tenant cap (X17, X20).
- **Sharded stops do not block on a dead shard (S8-13).** The stop chain originates in the pool shard and each shard holds a verified replica. A shard that is behind is not ready, and the operator acknowledgement reports `enforced` per shard (section 10).
- **The division with specs 3 and 9 (S3-15, S3-05).**
  - Spec 9 decides and this spec executes.
  - This spec executes the receipts append for check-only and `NonDurable` calls and reports `Committed`, `Refused` or `Unknown` (rule 28).
  - `ReceiptCommitted` is reported at the commit point.
- **Latch naming (S3-03).** X16 and X22 use spec 9's `HaltOperation`, which halts one operation and never the kernel.
- **Hints (S5-11).** A `Committed` reply is the only point after which spec 9 may post a hint. Section 18 states what that guarantees per commit class.

## Revision 2 changes

- **Anchor rule replaced (S10-01, S10-03, S10-12, S10-22).** Revision 1 deferred every anchor sync to the next crossing. That would have let a restore silently undo revocations, stops and fences. Revision 2 defines three commit classes. Crossing-authorizing and restrictive commits are acknowledged only after an anchor sync. Progress-only commits are anchored within a bounded lag. The writer's custody check moves to an in-memory expected head, so an unanchored commit does not fence the writer.
- **Read-only path narrowed (S10-02, S10-04, S10-05, S10-16).**
  - The check-only dispatch applies only outside durable read-only coverage, and only to calls that `can_redispatch_unknown_read` accepts. That predicate already excludes every pre-dispatch consumable.
  - Durable read-only calls get a two-commit variant or the three-commit path.
  - The D1 claim and the read-only baseline are corrected. The check-only path costs the same one `receipts.db` fsync as today.
- **Inventory and targets re-derived from M: (S10-06, S10-07).**
  - M: head issues 10 authority commits per side-effecting call, not 11, because the post-return pure results already commit together.
  - The targets now come from the steady process-host run's per-file fsync attribution, with setup excluded. `read` targets a median of at most 95 ms, not 60 ms, because non-fsync time is about 69 ms.
  - Throughput is measured on a new shared-writer kernel benchmark. The B: rows are context only.
- **Fast-path denials keep tombstones (S10-09).** A refused fused intent commit writes a deny tombstone with its receipt, in an anchored restrictive commit. Admission rule 4 and spec 8 S15 hold unchanged.
- **New contracts:**
  - `CommitOutcomeUnknown` (S10-10);
  - post-effect refusal handling and `Overloaded` (S10-11);
  - external-call crossing kinds (S10-12);
  - a savepoint failure protocol (S10-15);
  - an intent-from-`Prepared` variant (S10-08).
- **Receipts rebased on the existing projection and materialization path (S10-13, S10-24).** The receipt stays in the terminal tombstone and is never deleted. Asynchronous materialization satisfies ADR-0013 as written, with the authority writer as its local WAL.
- **Sharding demoted to a later phase with explicit preconditions (S10-14).**

## 1. Decision summary

Today, durable commits dominate process-mediated calls.

- **Latency.** The steady process-host run reports a `read` median of 130 ms, p95 161 ms (M: `sdks/typescript/packages/ai-sdk-process/BENCHMARK.md:108-110`), against a tool handler of about 0.6 ms (`:175-191`).
- **Durable writes on the call path.** Per mediated invocation, excluding host setup, the same run issues about 11.0 `authority.db`, 10.5 rollback-anchor, 3.8 `process.db` and 1.2 `receipts.db` fsyncs. That is about 26.5 fsyncs at about 2.3 ms each, roughly 61 ms of the median (`BENCHMARK.md:87-117`; section 2.8).
- **Where the authority commits come from.** The authority commits are the admission saga's durable states, and each is followed by an anchor sync. The direction document records that going lower "means changing those contracts, which the formal models cover" (M: `docs/architecture/AGENT_PROCESS_DIRECTION.md:166-167`).

Six decisions:

1. **One crossing primitive.** Every crossing runs as a `CrossingTx`: one savepoint inside the serving writer's transaction.
   - It covers dispatch, native capture, caller start, recovery and semantic capture, output release, P4 artifact release, P5 confined return, and every commit that precedes an external call.
   - Each crossing evaluates the ordered `CrossingCheck`s (stop epoch, closure fences, revocation, knowledge integrity, reservations), then writes a crossing record.
   - Specs 3, 4, 8 and 11 gain one enforcement point.
2. **Three commit classes.** Every commit on the serving connection is one of:
   - crossing-authorizing;
   - restrictive: revocations, stops, fences, tombstones, knowledge joins;
   - progress-only.

   The first two are acknowledged only after the anchor covering them is durable. Progress-only commits are anchored within a bounded lag. **Rule:** losing an unanchored commit to a restore can never enable a crossing that its presence would have refused.
3. **Fused fast path.** A side-effecting call becomes three commits: an anchored **intent commit** (six pre-effect commits fused), a progress-only **return record** (two fused), and an anchored **outcome commit** (two fused). Anchor syncs drop from about 10 to 2.
4. **Read-only calls by durable mode.**
   - Outside durable read-only coverage, eligible calls take a **check-only dispatch**: an authoritative, linearized crossing that writes nothing and costs no fsync. The receipt append stays as today.
   - Under `DurableAdmissionMode::All`, which the process host requires, eligible reads take a **two-commit read** (intent, outcome).
   - Every other read takes the three-commit path.
5. **Group commit.** A writer loop batches concurrent members into one transaction with a savepoint each. Each batch costs one WAL fsync and at most one anchor sync. Sharding by authority domain follows once its preconditions hold (section 10).
6. **Receipts off the synchronous path, still durable before allow.**
   - The terminal projection already commits the signed receipt into `authority.db` before allow.
   - This design makes its materialization into `receipts.db` asynchronous, behind a gate. ADR-0013's conditions are met as written: the authority writer is the local WAL, the sequence is assigned before allow, and saturation fails closed.

Targets (section 14):

| Measure | Baseline | Target |
|---|---|---|
| Authority commits per side-effecting call | 10 | 3 |
| Synchronous anchor syncs per side-effecting call | about 10.5 | 2, plus at most 1 lag anchor on a delayed return (X7a) |
| On-path authority, anchor and receipt fsyncs | about 22.7 | 5 or fewer on the ideal path; 6 on an isolated delayed return |
| Process-mediated `read` median | 130 ms | 95 ms or less (p95 125 ms or less) |
| Throughput at 16 callers on a new shared-writer kernel benchmark | phase 0 baseline | at least 4x, with no regression at concurrency 1 |

## 2. Verified current state

### 2.1 Commit inventory on M: head (side-effecting `ToolDispatch`, no nonce, no approval)

| # | Commit | Code |
|---|---|---|
| 1 | Begin: `Prepared`, operation row, replay key | `begin_durable_tool_admission` (`kernel/admission_coordinator.rs:465`) calling `store.begin` (`:760`) |
| 2 | `Prepared -> BrokerAttemptRegistered` (provider attempt attached) | `apply_admission_command` (`:898`) |
| 3 | Budget hold, `-> BudgetAuthorized` (already one joint transaction) | `authorize_durable_budget_hold` (`:1337`) calling `claim_and_authorize_budget_and_commit_admission` (`:1364`; store `admission_operation_store.rs:673`) |
| 4 | `BudgetAuthorized -> ReadyToDispatch` | `mark_durable_capture_pending` (`:1536`) |
| 5 | `ReadyToDispatch -> CapturePending` | `mark_durable_capture_pending` (`:1544`) |
| 6 | Capture plus `-> DispatchCommitted` (joint) | `capture_and_commit_durable_dispatch` (`:1814`) calling `claim_and_capture_invocation_and_commit_dispatch` (`:1869`). Without capture, `commit_durable_dispatch` (`:1560`) |
| 7 | Tool return: blob, outcome, `DispatchCommitted -> Finalizing` | `record_durable_tool_return` (`admission_coordinator/terminal.rs:142`) calling `claim_and_record_tool_returned` (`:312`; store `tool_outcome_store.rs:417`) |
| 8 | Begin post-return evaluation, which freezes the evaluation record | `claim_and_begin_post_return_evaluation` (`terminal.rs:1183`; store `tool_outcome_store.rs:441`) |
| 9 | All pure post-return results plus outcome resolution (one transaction) | `finalize_post_return_with_pure_results` (`terminal.rs:1343`; store `tool_outcome_store.rs:567`). `record_next_pure_result` (`:1301`) is in-memory |
| 10 | Terminal projection: receipt, payment evidence and capture, observer work | `commit_admission_projection` (`terminal.rs:1817`, `:1865`) |

After commit 10, `materialize_durable_admission_receipt` (`terminal.rs:1890`; `kernel/responses/receipt_persistence.rs:530`) appends the receipt to `receipts.db` before the call returns. It also seeds the settlement attempt.

The benchmark's "eleven" (`BENCHMARK.md:110-115`) predates the batching of pure results into commit 9.

Conditional commits on the same path:
- DPoP and governed-approval claims (`kernel/admission_coordinator/dpop_acquisition.rs:83`, `governed_acquisition.rs:86`).
- Operation-owned runtime-hook acquisition, which "requires a live durable admission" (`kernel/dispatch/runtime_admission.rs:87`).
- Nonce preflight, after which the execution request continues an existing `Prepared` operation (`:843`).
- Approval reservation (`reserve_durable_approval_set`, `:1421`).

### 2.2 Anchor and custody

| Mechanism | Detail | Code |
|---|---|---|
| Write sequence | Every write runs `begin_write` (IMMEDIATE, `verify_active_owner`, `verify_authority_anchor`), then `commit_write` (poisons the owner on an unknown outcome), then `sync_after_write` | M: `admission_operation_store.rs:350-383` |
| Custody check | `verify_authority_anchor` requires the connection's `data_version` to equal the owner's expected value, then calls `RollbackAnchor::verify_current`, which requires the database to **equal** the anchor record | `serving_owner.rs:180-198`; `serving_owner/rollback_anchor.rs:170-189` |
| Anchor sync | `sync_authority_anchor` runs `prove_extension` and writes the next record. A failure poisons the owner | `serving_owner.rs:269-292`; `rollback_anchor.rs:257-276` |
| Anchor record | Admission and global commit chain heads and digests, `trusted_time_high_water_unix_ms`, owner epoch and lease | `rollback_anchor.rs:33-46` |
| Startup | `reconcile_startup` accepts a database that extends the anchor | `rollback_anchor.rs:106-130` |
| Connection recovery | A recovered connection serves "only once the anchor equals the database head" | `serving_owner.rs:833-848` |
| Shared connection | The budget, revocation, admission-operation and tool-outcome stores share one serving connection | `serving_owner.rs:884-900` |
| Revocation commits | They sync the anchor | `revocation_store.rs:500-504` |
| Read companions | They prove extension instead of equality | `serving_owner.rs:200-217` |
| Owner replacement | It relies on the OS lock, the owner epoch and the lease row, not on per-commit anchor syncs | `serving_owner.rs:612-616`, `:701-805` |

### 2.3 Writers and stores

| Store | Writer | On the call path |
|---|---|---|
| `authority.db` | The serving writer. It holds admission operations, tool outcomes, budgets, the payment journal, approval and nonce ledgers, canonical admission receipts in terminal projections, revocations, and the finding market, purchases, challenges and status, channel lifecycle and release publisher, FROST, fiscal and the economic-state cache (`serving_owner.rs:628-690`) | Every commit in 2.1 |
| `receipts.db` | A separate writer (`chio_tool_receipts` with `raw_json`, `receipt_store/bootstrap/open.rs:621-655`) | One synchronous append per call |
| `process.db` | A separate writer (M: `crates/products/chio-cli/src/cli/process_host/provision.rs:211`) | The call slot commits before the kernel call (M: `crates/kernel/chio-process/ARCHITECTURE.md:40-45`), plus model-journal checkpoints and blobs |
| `mailboxes.db`, `runner.db` | Separate writers, checkpointed separately (M: `process_host/relocation.rs:26`) | Not per kernel call |
| Remote budget stores, payment rails, external stateful evaluators, governed mutation services | External | Saga participants |

### 2.4 Durable modes and the read-only retry contract

- **Default mode.** `DurableAdmissionMode::SideEffecting` is the default and does not cover read-only tools.
- **Process host.** The process host refuses any mode other than `All` (M: `crates/kernel/chio-process/src/registry.rs:55-59`).
- **Bounded fresh dispatch.** An unknown outcome earns a bounded fresh dispatch only when all of these hold:
  - the operation was durably `DispatchCommitted`;
  - recovery signed an `OutcomeUnknownAfterDispatch` receipt with `retained_dispatch_commit`;
  - `can_redispatch_unknown_read` holds;
  - the caller used `invoke`, not `invoke_known_only`. The latter "never redispatch[es] an unknown outcome, even for a read-only tool".

  It allows at most `MAX_DISPATCH_ATTEMPTS = 3` (M: `crates/kernel/chio-process/src/lib.rs:67-71`, `:341-375`, `:533-549`).
- **What the predicate excludes** (`kernel/validation.rs:256-305`): DPoP, execution nonces, declassification grants, governed intents, approvals, threshold proposals, supplemental authorization, aggregate budgets, finding delivery, security bindings, operation-owned authority, runtime hooks, swarm admission, and any matching grant with `max_invocations`, a cost cap, required DPoP, or any constraint.

### 2.5 Crossing check sites today

- **Stop:** an in-memory flag at about eleven sites (`2026-10-04-durable-stop-epoch-design.md` section 2).
- **Closure fences:** proposed inside the `DispatchCommitted` CAS (spec 4 section 4.1), with its crossing table in section 4.3.
- **Recovery:** a same-writer tombstone (W: `crates/platform/chio-store-sqlite/src/admission_operation_store/recovery/native.rs:286-293`).
- **P4:** the knowledge join and `ReleaseIntent` commit before sink I/O (W: `docs/architecture/recoverable-agent-runtime/implementation/p4/OPERATIONS.md:98-106`).
- **P5:** a serialized process-activity read after the return-admission commit, just before `sink.deliver` (W: `crates/platform/chio-control-plane/src/confinement.rs:211-239`).
- **Guard revalidation:** check-then-act (`kernel/dispatch.rs:806`).

### 2.6 Receipts and logs

- **Path.** The terminal projection signs (`terminal.rs:1668`) and commits the receipt into `authority.db`. `materialize_durable_admission_receipt` then appends it to `receipts.db` and seeds the settlement attempt exactly once on first append (`receipt_persistence.rs:530-545`).
- **Restart mover.** `reconcile_durable_admission_receipt_projections` (`kernel/admission_coordinator.rs:423`) is the restart mover. The restart matrix covers the cutpoint "Terminal projection before receipt append ... Original receipt projection repaired and replayed" (M: `docs/security/native-restart-safety.md:49`).
- **Replay.** Replay loads the canonical receipt from the authority store's projection (`terminal.rs:452-506`).
- **Cost and size.** Signing costs 0.23 ms, and the `receipts.db` append p50 is 4.7 ms (B:). The store grew about 11.9 KB per call (B: `bilateral-admission-sustained-load.json`: 41,039 KiB over 3,543 calls).
- **Existing Merkle machinery.** An RFC 6962 Merkle tree (M: `crates/core/chio-core-types/src/merkle.rs:1-9`) and checkpoint statements (`checkpoint.rs:1-7`, `:38-51`).
- **Reports read `raw_json`.** The billing, behavioral, settlement, compliance and authorization reports use `json_extract` over `raw_json` (`receipt_store/reports/*.rs`).
- **ADR-0013** keeps durable-before-allow as the default. It allows async durability only behind a feature gate and a durable local WAL, with these conditions:
  - the sequence is assigned before `Allow`;
  - saturation fails closed;
  - gaps are recorded as audit faults.

### 2.7 Formal coverage

No TLA or Apalache model of the admission saga's commit sequence exists on M:, V: or W:. M: `formal/apalache/` holds `ReceiptBeforeAllow`, `PostAdmissionDropGuard`, `KernelTransitionCancelSafe`, `MonotoneLogApalache`, `RevocationCutCompleteness` and `ResponseLifecycle`. `formal/tla/` covers revocation, delegation depth and information flow.

### 2.8 Baselines

From the steady process-host run after the claim-folding changes, 33 mediated invocations (M: `BENCHMARK.md:87-117`):

| File | fsyncs | Per call |
|---|---:|---:|
| `authority.db` | 363 | 11.0 |
| Serving lock and rollback anchor | 348 | 10.5 |
| `process.db` (call slots, model-journal checkpoints and blobs) | 126 | 3.8 |
| `receipts.db` | 39 | 1.2 |
| On-path subtotal (excluding host setup) | 876 | 26.5 |
| Host process setup and status (excluded) | 426 | 12.9 |
| Unattributed (excluded) | 11 | 0.3 |

- **Where the `read` time goes.** At about 2.3 ms per fsync, the on-path subtotal is about 61 ms of the 130 ms `read` median. Non-fsync time is therefore about 69 ms, assuming `read`'s profile is near the average.
- **Context only.** The B: kernel-only allow, p50 13.9 ms, uses an in-memory admission store and no `authority.db` (B: `crates/kernel/chio-runtime-core/benches/fixtures/treaty_admission_allow_fixture.rs:12-13`). The B: sustained load, 59 calls per second, runs one private kernel and store per worker (B: `crates/kernel/chio-runtime-core/examples/treaty_sustained_load.rs:8-23`), on a host with a load average of 13.85.
- **Not targets.** Neither B: harness exercises a shared serving writer, so neither is a target here.

## 3. Goals and non-goals

Goals:
- One transaction shape for every crossing, carrying every crossing check.
- Fewer durable commits and anchor syncs per call. No restore can widen authority.
- Throughput that scales with concurrent callers on one writer.
- Receipts durable before allow, verifiable as today, and smaller at rest.

Non-goals:
- Changing verdicts or the receipt wire format.
- Cross-database atomicity. Cross-store participants stay saga participants.
- Removing per-receipt signatures.
- Moving process-journal ownership of call slots (open decision 2).
- Reducing non-fsync CPU time. Phase 0 attributes it, and a separate effort owns it.

## 4. The crossing primitive

### 4.1 Shape

```rust
pub enum CrossingKind {
    DispatchIntent,            // side-effecting or durable read dispatch: the intent commit
    CheckOnlyDispatch,         // eligible read-only dispatch outside durable coverage: no writes
    CallerStart,               // authenticated caller-execution start
    NativeCapture,
    RecoveryCapture,           // W: recovery continuation capture
    SemanticCapture,           // W: P3 semantic remedy capture
    OutputRelease,             // the outcome commit; also records the output influence join (spec 11, rule I4)
    ArtifactRelease,           // W: P4 knowledge join + ReleaseIntent
    ConfinedReturn,            // W: P5 return admission (P5's final activity read is kept, X5a)
    ExternalPrepare { purpose: PreparePurpose }, // cross-store prepare before a payment-rail or remote-budget call
    MutationSubmit,            // MutationReady -> MutationSubmitted before the mutation service call
    ExternalEvaluation,        // begin-evaluation record before sending output to an ExternalStateful step
    ActiveResponseExecute,     // governed active response execution
    FederationCosign,          // co-sign request for an admitted request (terminal.rs:1910)
    ChannelReleasePublish,     // channel release publication
}

pub enum PreparePurpose {
    Authorize,                 // a new authorization before dispatch
    Settle,                    // capture or release that settles an effect committed before the call
}

pub enum CrossingCheck {
    StopEpoch,           // spec 8 tier 2: (kind, scope, disposition) over durable heads and process latches
    ClosureFence,        // spec 4 section 4.1
    Revocation,          // chain walk; capability lineage where installed
    KnowledgeIntegrity,  // spec 11, authoritative check
    Reservations,        // spec 3: writes Compensable holds; observes Commitment entries
    Record,              // the crossing record
}

pub enum CrossingResult {
    Committed(CrossingCommitted),          // acknowledged after COMMIT and, if required, the anchor sync
    Refused(CrossingRefused),              // typed reason, no state change
    OutcomeUnknown,                        // COMMIT or the post-COMMIT anchor sync failed; owner poisoned
    Retry,                                 // the batch transaction was lost before COMMIT (X21); re-queue
    StoreUnavailable,                      // known not committed; the store cannot run this member now (X21 retry exhaustion, poisoned owner, failed recovery fence)
}
```

`CrossingRefused` reasons:

| Kind of reason | Reasons |
|---|---|
| Policy refusals | `KernelStopped`, `AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity`, `ReservationConflict` |
| Non-policy | `VersionConflict` (the planned CAS saw another version, X5), `Unavailable` (fast-path preconditions do not hold, so the driver re-plans the slow path; never a storage failure), `Overloaded` (the writer queue is full, so the refusal comes before any write) |

Spec 9 receives refusals as `CommitFailed { reason }`, `OutcomeUnknown` as the distinct event `CommitOutcomeUnknown`, `StoreUnavailable` as the distinct event `StoreUnavailable` (spec 9 M19: the same member is retained and re-fed, never compensated), and `Retry` as nothing: the driver re-submits.

### 4.2 Checks per kind

The Stop column carries spec 8's `StopDisposition`. Spec 8 section 5 is normative, and this table repeats its values:
- `Deny`: refused while stopped.
- `Withhold`: the operation is retained (`Finalizing` or `Parked`) with output held, and proceeds after resume.
- `Settle`: allowed only to complete or settle an effect committed before the stop head. A new authorization is `Deny`.
- `AllowIfContainment`: allowed only when the head has `allow_containment = true`. A host latch implies `false` (spec 8 S20).

| Kind | Stop | Fence | Revocation | Integrity | Reservations | Commit class |
|---|---|---|---|---|---|---|
| `DispatchIntent` | `Deny` | yes | yes | yes | holds, capture | crossing-authorizing |
| `CheckOnlyDispatch` | `Deny` | yes | yes | yes (see X13) | none | no write |
| `CallerStart` | `Deny` | yes | yes | yes | capture before effect | crossing-authorizing |
| `NativeCapture` | `Deny` | yes | yes | yes | capture | crossing-authorizing |
| `RecoveryCapture`, `SemanticCapture` | `Deny` | yes | yes | yes | recovery consumption | crossing-authorizing |
| `OutputRelease` | `Withhold` | yes | yes: the release revalidates the capability before bytes leave (as M: does today, `allow_responses.rs:53`); a refusal follows X16 | yes, for release | capture, release authority | crossing-authorizing |
| `ArtifactRelease` | `Withhold` | yes | yes: the releasing context's capability; a refusal withholds and keeps P4 pins (spec 4 section 7 item 8) | P4 join is the check | pin, release intent | crossing-authorizing |
| `ConfinedReturn` | `Withhold` | yes | yes: the actor's capability, as P5 re-authenticates it today (W: `confinement.rs:104`); a refusal withholds and keeps confined consumption | P5 return contract | confined consumption | crossing-authorizing |
| `ExternalEvaluation` | `Withhold` | yes | yes: output never leaves for the external step under a revoked capability; a refusal follows X16 | yes | none | crossing-authorizing |
| `ExternalPrepare { Authorize }` | `Deny` | yes | yes | where applicable | the participant's intent row | crossing-authorizing |
| `ExternalPrepare { Settle }` | `Settle` | subject before cut | subject before cut | where applicable | the participant's intent row | crossing-authorizing |
| `MutationSubmit` | `Deny` | yes | yes | where applicable | the participant's intent row | crossing-authorizing |
| `FederationCosign`, `ChannelReleasePublish` | `Settle` | subject before cut | subject before cut | where applicable | the participant's intent row | crossing-authorizing |
| `ActiveResponseExecute` | `AllowIfContainment` | yes | yes | where applicable | the participant's intent row | crossing-authorizing |

**The `StopEpoch` check.**
- It evaluates `(kind, scope, disposition)`.
- Its effective state is the durable stop heads read in the transaction, together with the process-local latches: spec 8's host latch, and a stop whose write has not yet become durable (spec 8 S20, S8-02). The writer loop runs in-process, so it reads the latches from an `ArcSwap`.
- A process latch can only tighten the result. It never relaxes a durable head.
- `Settle` requires the operation to have committed its effect, or its authorization, at an epoch before the current `Stopped` head. The crossing record carries that epoch.
- Tier 1, spec 8's early check, reads the per-store shared `StopHeads` (spec 8 S8-08). It never reads a per-kernel field, and it is never authoritative.

**Settlement and permanent fences.** A settlement kind (`ExternalPrepare { Settle }`, `FederationCosign`, `ChannelReleasePublish`) completes or settles an effect that already committed. It does not authorize new work.
- The closure-fence and revocation checks therefore apply the same subject-before-cut test as `Settle` does for stop. The check passes when every subject the crossing settles committed at an admission chain position before the closure fence row or the revocation entry that would refuse it. That covers the captured or released hold, the co-signed admitted request, and the published release of earned funds.
- A subject committed after the cut is refused. So is any crossing that would start a new authorization; that is `ExternalPrepare { Authorize }`, which keeps the plain checks.
- The crossing record carries each subject's chain position, so an auditor can replay the test.
- Closure and revocation therefore never strand earned work. This is spec 4 section 7 rule 1 ("payable work remains payable") and spec 4's escrow invariants. The stop half is spec 8 section 5.

Capability issuance is not a crossing here. It runs in the capability authority store, so under X3 it is `early_only`: spec 8 S8 applies, with no anchor in this writer.

Rules:

1. **X1. One shape.** Every crossing in section 4.2 is a `CrossingTx`. **Section 4.2 is the registry of crossing kinds.** A new kind needs:
   - a row here, with its checks and commit class;
   - a spec 8 section 5 stop disposition;
   - an ordering point. By default it is the kind's own `CrossingTx` commit, ordered by `CrossingOrder` (X4). A spec 4 section 4.3 entry is needed only for a kind whose bytes or effects leave Chio custody at a different point, or that needs closure semantics beyond the fence check. Today that is dispatch, output release, recovery continuation, P5 confined return and P4 artifact release;
   - the L0 op in spec 1 that drives it. Spec 1 registers ops, not crossing kinds, and each crossing is reached only through an op it already classifies.
2. **X2. Order.** Checks run in `CrossingCheck` order, before any mutation, and the first refusal ends the crossing.
3. **X3. Same writer.** A check is authoritative only when its state lives in the crossing's writer. Otherwise it is an early read, reported `early_only` (spec 8 section 13).
4. **X4. Record and crossing order.** `crossing_records(crossing_id, kind, operation_id, scope_digest, checks_digest, store_uuid, commit_sequence, member_ordinal)` is written last in the same savepoint. It is operational, not signed evidence.
   - **One total order.** `CrossingOrder = (store_uuid, commit_sequence, member_ordinal)`. It orders every written crossing, stop and fence record and influence observation in one store. Every consumer uses it: spec 8 S7's subject-before-stop test and DST property, and spec 11 I22a's selector-slot order.
     - `commit_sequence` reuses the existing durable authority chain. It is the greatest `authority_global_commits.commit_sequence` written by the member's savepoint (M: `serving_owner/global_commit_chain.rs:43-77`). Every written crossing mutates at least one authority projection, so the value is defined. Stop and fence records are covered by the same chain (spec 8 S2), so they have a `commit_sequence` too.
     - `member_ordinal` is the member's 0-based position in its batch, assigned in dequeue order (X19).
     - Members run serially and the chain sequence is strictly increasing within a store, so `commit_sequence` alone already orders written crossings, including two members of one batch. `member_ordinal` is a tiebreak that a written crossing never needs.
     - The tuple is chosen over `(batch_index, writer_epoch)`, which revision 2 used and this revision withdraws. A per-batch ordinal collides across consecutive batches, a batch number leaves members of one batch unordered, and `writer_epoch` is the serving owner's fence, not a commit counter.
   - **Check-only crossings** write nothing. A `CheckOnlyDispatch` or X13a release records `(store_uuid, observed_commit_sequence, check_ordinal)` in the call's receipt metadata as `chio_runtime.crossing`, where `observed_commit_sequence` is the chain head that the check read in the writer.
     - **Comparison.** Written and check-only positions are compared through a discriminated key, not as raw tuples:

       ```text
       key(written(s, c, m))       = (s, c, 0, m)
       key(check_only(s, c, k))    = (s, c, 1, k)    where k = (store_owner_epoch, owner_check_counter)
       ```

     - Every check that observed head `c` therefore sorts after every crossing written at `c`, whatever its `member_ordinal`, and before anything written at `c + 1`. The two ordinal domains never collide, because the discriminator separates them.
     - `check_ordinal` orders only checks that observed the same head, and it is restart-stable. It is the pair `(store_owner_epoch, owner_check_counter)`:
       - `store_owner_epoch` is the serving owner's persisted fence epoch, the one already written with every global commit (M: `global_commit_chain.rs:43-77`). It strictly increases on each owner acquisition.
       - `owner_check_counter` is a per-owner in-memory counter that starts at 0.
       - A restarted owner that observes the same head `c` therefore has a higher epoch, and no two check-only receipts share a key.
   - **Comparison.**
     - Orders compare only within one `store_uuid`.
     - `commit_sequence` continues across owner changes, because it is the store's own table key, not an owner counter.
     - A sharded tenant compares stop records through its verified replica, which has its own sequence in the shard's store (section 10).
     - After a restore only the anchored prefix exists, and X6 already covers it.
   - Spec 8's property "no `Deny` or `Withhold` crossing ordered after a `Stopped` head" is evaluated over written records and check-only receipt metadata together.
5. **X5. Spec 9 boundary.** `CrossingTx` executes spec 9's planned commit effects and never decides an admission transition. Each plan carries the expected operation version.
   - **X5a. P5.** `ConfinedReturn` covers stop and fence at the return-admission commit (W: `store.admit_confined_return`, `chio-control-plane/src/confinement.rs:214-226`). P5's final serialized activity read before `sink.deliver` (`:234-236`, a process-journal read outside this writer) stays as written, so a late cancellation still withholds bytes.
     - That final read is not a stop check (spec 8 S8-10).
     - A durable stop committed after the return-admission commit and before `sink.deliver` does not withhold the bytes.
     - The final read also consults the process latches, so a host latch set in that window does withhold them.
   - **X5b. Participant preconditions are preserved.** Moving a participant into a `CrossingTx` keeps every transaction-local precondition that participant checks today. Those preconditions stay with the participant and run inside the crossing's savepoint, before the crossing record. They are not new `CrossingKind`s or global `CrossingCheck`s. The recovery P6 setup gate is the case that exists today (W:):
     - **`NativeCapture`** keeps `setup::require_capture` (W: `chio-store-sqlite/src/admission_operation_store/setup/gate.rs:80-124`), called in the capture transaction at `security_participant_state/dispatch_ledger/capture.rs:45-51`. When a protected setup selection exists for the tenant's `native-capture` scope, it checks:
       - the selection is current;
       - the native authority binding and the security context (tenant, session, principal, lineage root, isolation epoch, context generation) equal the selected deployment's;
       - the scope is qualified (`ready`), or else the capture is the one selected benign self-test (workflow, creation digest, not yet captured).
     - **`RecoveryCapture` and `SemanticCapture`** keep `setup::require_command` and `setup::require_ready` (W: `gate.rs:4-79`; `admission_operation_store/semantic.rs:274`).
     - **`ArtifactRelease`** and the knowledge paths keep `setup::require_ready` (W: `admission_operation_store/knowledge.rs:228`).
     - **Refusal.** A precondition refusal rolls back the savepoint and surfaces as that participant's refusal (`ParticipantRefused`, spec 9), so it compensates before dispatch and nothing crosses. Removing or weakening a participant precondition is a regression that X5b forbids, and the differential suite (section 17) compares the legacy and fused paths on the setup gate's refusal cases.
     - **Integrity deployment.** Configuration that spec 11 adds goes through the existing P6 policy owner (`apply_reviewed_semantic_deployment`, spec 1 section 6), with explicit fields and validation. `CrossingTx` reads the installed generation; it never activates policy itself.

## 5. Commit classes and the anchor

The rollback anchor detects a database restored behind its last anchored state, and it carries the trusted-time high-water mark. Today it is synced after every authority commit.

| Class | Commits | Anchor |
|---|---|---|
| Crossing-authorizing | Every `CrossingTx` with a write, including every commit that precedes an external call | Synced before acknowledgement |
| Restrictive | Revocations; stop and resume epochs (spec 8 S1); closure fences (spec 4); recovery cancellation tombstones; deny tombstones (X15); `DeniedAfterDelivery` terminals and `DeliveryRefused` records reached by refusal (X16); origin-claim chain mutations, including uncreated-reservation retirement (spec 2 section 6.10 O5); knowledge and taint joins; isolation-epoch changes; export seals | Synced before acknowledgement |
| Progress-only | Begin and attachments on slow paths; pre-dispatch budget holds of operations that have not crossed; parked states; the return record; finalize records of pure post-return results that are not fused; external-step journal entries after the external call | Synced within bounded lag (X7) |

Rules:

6. **X6. Restore safety.** Losing an unanchored commit to a restore can never enable a crossing that its presence would have refused. Progress-only commits satisfy this for three reasons:
   - each describes state no effect depends on yet (a pre-dispatch hold of an operation that never crossed is equivalent to that operation never having begun);
   - every crossing-authorizing commit anchors the whole chain prefix, because the anchor records the chain head;
   - a lost return record leaves `DispatchCommitted`, which recovery terminalizes as outcome-unknown with holds frozen. That is the conservative branch.
7. **X7. Bounded lag.** Progress-only commits are anchored when a crossing-authorizing or restrictive commit follows, or after `anchor_lag_commits` (default 32) or `anchor_lag_ms` (default 100), whichever comes first. A batch boundary alone does not force a sync.
   - **X7a. Synchronous and lag anchors.** A **synchronous anchor** is the sync that a crossing-authorizing or restrictive commit's acknowledgement waits on. A **lag anchor** is a sync the writer loop runs because `anchor_lag_commits` or `anchor_lag_ms` fired. No member's acknowledgement waits on it, but it is a real fsync and is counted.
   - A side-effecting fast-path call always costs 2 synchronous anchors, for the intent and the outcome. It costs 1 more lag anchor when its return record ages past `anchor_lag_ms`, or past `anchor_lag_commits` intervening commits, before the outcome commit anchors it. That is the isolated delayed-return case.
   - Restore safety does not depend on which kind of sync covers a commit. Section 14 counts the two kinds separately and never trades a lag anchor away to meet a number.
8. **X8. Trusted time.** A restore can regress the trusted-time high-water mark by at most the anchor lag, because every crossing re-anchors the floor. The fallible authority clock and its fences (M: `docs/security/trusted-time.md`) are unchanged.
9. **X9. Custody check.** The writer no longer compares the database to the anchor on every transaction.
   - The owner keeps an in-memory expected head: admission and global commit sequence, chain digests, and `data_version`, updated after each commit it writes.
   - `begin_write` and `begin_read` verify `data_version` and the expected head, which is a cheap read of the head row.
   - `prove_extension(anchor, database)` runs at anchor sync and at startup only.
   - The connection-recovery fence accepts a recovered connection only when the database extends the published anchor **and** equals the expected head. If the expected head was lost, `open_serving` reconciles it as today.
   - Companions keep proving extension.
   - All of this lands in phase 1, with Loom models of commit, sync and verify races.

## 6. Fast paths

### 6.1 Side-effecting call: intent, return record, outcome

```text
evaluate (pure core + guards + revalidation reads; no writes)
  -> intent commit   [DispatchIntent; crossing-authorizing; WAL fsync + anchor sync]
       commits 1-6: begin, attempt, BudgetAuthorized(hold), ReadyToDispatch, CapturePending,
       capture + DispatchCommitted
  -> handoff to the tool
  -> return record   [progress-only; WAL fsync; anchor within lag (X7)]
       commits 7-8: blob + outcome + DispatchCommitted -> Finalizing, and the frozen
       PostReturnEvaluationRecordV1 (evaluation time, frozen steps, normalized context)
  -> pure post-return evaluation in memory (OutputGuard, Pricing), from the frozen inputs
  -> outcome commit  [OutputRelease; crossing-authorizing; WAL fsync + anchor sync]
       commits 9-10: pure results + resolution, terminal projection (receipt, payment
       evidence and capture), receipt sequence assigned (section 11)
  -> allow returned; receipt materialized to receipts.db asynchronously (section 11)
```

Preconditions for the fused intent commit:
- every participant in spec 9's plan has an in-transaction plan and apply form in the admission writer, including DPoP and governed-approval claims;
- no participant needs a persisted operation first (operation-owned runtime hooks do);
- no approval is pending;
- no participant needs an external authorization before dispatch;
- the call is not caller-executed.

Rules:

The operation-insertion step, whether a standalone Begin or part of fused IntentCommit, applies spec 4 section 4.1's closure-ref check in the same writer transaction before creating any new operation. If the fence committed first, no nonterminal row or approval can be inserted; if Begin committed first, its atomic refs make it visible to the closure drain. Existing exact replay remains observational. Dispatch/release fencing still applies independently.

10. **X10. Intent from `Prepared`.** When a nonce preflight already committed `Prepared` (`kernel/admission_coordinator.rs:843`), the intent commit starts from that persisted operation. The plan flag is `from_prepared`, with the expected version, and fuses commits 2 to 6. An operation-owned runtime hook acquires against the persisted `Prepared` first, and the remaining steps fuse.
    - **Refusal from `Prepared`.** The savepoint cannot roll back what was acquired against `Prepared` before the fused steps: the nonce preflight and the hook's reservation. A refused fused intent from `Prepared`, for any policy reason including `KernelStopped`, therefore writes no deny tombstone. Spec 9 M10 emits `Compensate { PreDispatchRefusal, PreDispatchNoEffect, receipt }` against the persisted operation. That releases the hook and the nonce through their participants, as the slow path does; a hook held outside this writer is released in a first group. Repeated refusals cannot strand runtime capacity.
    - `Overloaded` from `Prepared` re-submits with bounded backoff (spec 9 M10).
11. **X11. Return record binds evaluation inputs.** The return record freezes the evaluation time (its `recorded_at`), the post-return steps and the normalized context. The outcome commit verifies them. Recovery at cutpoint C4 re-runs from those inputs, never against current time or state, as the admission design requires.
12. **X12. Fast-path eligibility census.** Phase 0 reports which profiles qualify. The steady process-host profile qualifies for the full fused path: no runtime hook, no swarm admission, and no nonces, as its read tools' bounded redispatch implies. Profiles with nonces or operation-owned hooks use X10. Everything else takes a slow path (section 7).

### 6.2 Read-only calls by durable mode

| Mode and eligibility | Path | Durable commits on the path |
|---|---|---|
| `!mode.covers(ReadOnly)`, `can_redispatch_unknown_read`, and integrity tracking off for the calling context | Check-only dispatch, then a check-only release crossing and the receipt append (as today) | 0 authority; 1 `receipts.db` |
| `!mode.covers(ReadOnly)`, not eligible (the call carries a consumable, or integrity tracking is on) | Durable three-commit path | 3 authority |
| `mode.covers(ReadOnly)` (the process host), eligible, driver permits redispatch on unknown | Two-commit read: intent, outcome | 2 authority |
| `mode.covers(ReadOnly)`, otherwise (including `invoke_known_only`) | Three-commit path | 3 authority |

Rules:

13. **X13. Check-only dispatch.**
    - It is an IMMEDIATE transaction that evaluates stop, fence, revocation and integrity, writes nothing, and commits without a WAL write. It linearizes with every committed stop, fence, revocation and applicable integrity-policy change, because it holds the write lock in the batch's serial order.
    - Eligibility requires `can_redispatch_unknown_read`, which excludes every pre-dispatch consumable, so no quota, nonce, DPoP proof or runtime reservation is skipped.
    - That predicate also requires matching grants without constraints, so spec 11's grant-declared `RequiredIntegrity` makes a call ineligible. The integrity check here covers only requirements from non-grant floors (spec 11's open decisions).
    - Fence refs are derived from the request inside the check, because no operation row exists.
    - **Integrity tracking excludes the path.** When spec 11's integrity tracking (I4, rollout flag `integrity-tracking`) is enabled for the calling context, the call is not check-only eligible (spec 9 section 4.4). I4 commits the output-influence join in the same writer transaction as the outcome commit or release. The X13a release writes no authority row, so it would deliver bytes with no join, and a later consequential call could pass against stale trusted state. Such reads take the durable three-commit path, whose `OutcomeCommit` writes the join before the bytes leave.
    - **X13a. Release.** Before output is released, a second check-only crossing re-checks stop, fence, revocation and `CrossingCheck::KnowledgeIntegrity { key, requirement }`, matching the durable `OutputRelease` row (section 4.2). Derive the applicable release requirement from the currently installed integrity policy and floors, and evaluate it against committed state in this release crossing's writer transaction. Do not reuse the dispatch-time requirement, policy generation or successful check as permission to release. A policy change and release serialize in that writer: a change committed first is checked before any bytes leave.
      - **Eligibility is not an integrity exemption.** For an eligible read, the check covers the non-grant requirements described in X13. For `NonDurable`, it also covers grant requirements as X13c specifies. Recheck I4b's tracking prerequisite: if the current requirement cannot be satisfied on this no-write path, including when tracking now requires an output join, return typed `InsufficientIntegrity` from this release crossing even if `satisfies(current_state, requirement)` is true. This is the existing integrity refusal, not a new reason or `Unavailable` replanning signal. Withhold rather than omit the join prerequisite, fabricate a join or re-dispatch the call. Initially tracked contexts still take the durable path under X13/X13c.
      - A `Revoked` or `InsufficientIntegrity` refusal takes spec 9 M11/M20 and X16's post-effect handling: withhold all result bytes and append a signed `Withheld` receipt naming the actual reason, with `retry: Never` guidance for this refusal. A check-only read remains `IdentityDisposition::Reusable` under M20 because no durable identity owner or executed effect exists; retry advice does not burn its id. Stop and store-unavailability refusals retain X16's distinct retry advice. There is no new custody or operation row on this path. Success and refusal both append the receipt to `receipts.db` through the existing `finalize_ordinary_recovery_response` path, with the same fsync budget; X13b still governs append failure.
    - **X13b. D1.** D1 is closed on the success and refusal paths only if the receipt append is made infallible-or-latched. That is spec 3 phase 1 (`PostEffectObligation`, kernel-evidence latch). This path changes nothing about D1 otherwise. A crash between handoff and the receipt append still leaves no record, by design for undurable calls. Durable coverage (`All`) is the remedy.
    - **X13c. `NonDurable` calls.** Spec 9's `NonDurable` class covers calls under `Monetary` or development `Off` that no durable path covers.
      - These calls also dispatch through a `CheckOnlyDispatch` crossing, which writes nothing and linearizes stop, fence, revocation and applicable integrity-policy changes.
      - The integrity check covers grant-declared requirements too, because the class does not exclude grant constraints.
      - The release re-check is X13a, and the receipt append is rule 28.
      - The class exists so that spec 3 phase 1's obligation has a machine counterpart. It is not a fast path.
      - Under integrity tracking, a would-be `NonDurable` call takes the durable three-commit path instead, for the same reason as X13: its release has no authority write to carry the I4 join.
14. **X14. Two-commit read.** This is a contract change, behind the flag `crossing-read-two-commit`.
    - For an eligible read whose driver declares that redispatch on unknown is permitted (spec 9 `EvaluationContext`; the process runtime's `invoke`, not `invoke_known_only`), the return record fuses into the outcome commit.
    - A crash after handoff and before the outcome commit leaves `DispatchCommitted`. Recovery signs `OutcomeUnknownAfterDispatch` with `retained_dispatch_commit`, and the process runtime's bounded fresh dispatch applies unchanged.
    - This amends the admission design's "persist returned bytes before post-return work" for this class only (section 15).
    - **X14a. Stop at the outcome commit.** When the fused outcome commit is refused with `KernelStopped`, the savepoint rolls back. The driver then commits a progress-only return record with the returned bytes, which is never stop-checked (spec 9 M11).
      - The operation is `Finalizing` with output withheld, so it is never re-dispatched (spec 8 S8-18).
      - The client receives spec 8's `OutputWithheld { operation_id, reason: KernelStopped }`.
      - The same fallback applies to an infrastructure failure after the return and before the outcome commit (spec 9 M16).

### 6.3 Denials on the fast path

15. **X15. Deny tombstones.** A policy refusal of a fused intent commit from `Unbegun` for `AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity` or `ReservationConflict`, or a deny decided during evaluation of a durable-coverage call before any row exists, writes a deny tombstone in one **restrictive** commit. A refusal from `Prepared` compensates instead (X10). The tombstone holds:
    - an operation row in `CompensatedBeforeDispatch`, with the same replay key semantics as today;
    - the signed deny receipt, as its terminal evidence.

    Admission rule 4 ("terminal tombstones retained") and `unique(request_namespace_digest, request_id) -> one operation_id` hold unchanged for these reasons. `Unavailable` re-plans with no tombstone, `VersionConflict` re-projects, and `Overloaded` denies with a receipt before admission.
    - **Identity disposition (spec 9 M20).** The tombstone's receipt, and the compensation receipt of a refusal from `Prepared` (X10), carry `chio_runtime.identity_disposition = Terminal`. The `Overloaded` deny carries `Reusable`. So does a `StoreUnavailable` deny before any row, because no tombstone could commit.

    - **X15a. Stop denials are temporary (spec 8 S15, S8-17).** `KernelStopped` writes no tombstone on either tier.
      - A tier-1 early denial, and a fused intent commit refused with `KernelStopped`, sign a deny receipt carrying `observed` and persist no operation row. The request id stays usable after resume.
      - This keeps today's behavior: M:'s early stop check runs before any begin commit. It also avoids an anchored write per denied request in the middle of an incident.
      - A slow-path operation that already has a begin row still compensates, as today, and its id is terminal (spec 9 M10, M15). The same holds for a fused intent from `Prepared` (X10).
      - **Identity disposition (spec 9 M20).** The tier-1 and fused-from-`Unbegun` stop denials carry `identity_disposition = Reusable`, and spec 8's `retryable_after_resume = true`. The `Prepared` and slow-path stop compensations carry `Terminal` and `retryable_after_resume = false`. The two fields always agree.

### 6.4 Refusals after the effect

16. **X16. Post-effect refusals.** When an `OutputRelease` (or a return record) is refused:

    | Reason | Effect |
    |---|---|
    | `KernelStopped` | The savepoint rolls back. The operation stays `Finalizing` with output withheld in release custody (the return record holds the bytes) and resumes after the stop is lifted (spec 8 S14). A return record is never stop-checked, so this refusal reaches only the outcome commit and the release crossings. For the two-commit read see X14a |
    | `AuthoritySpaceClosed`, `Revoked` or `InsufficientIntegrity` | Spec 9 emits `HaltOperation` for that operation and applies M11a: the output is withheld for good, and the refusal decides delivery, never money. With no outstanding obligation, including a payment journal already `Final`, the operation terminalizes as the existing `DeniedAfterDelivery` with the refusing reason and retained markers, recognizing any recorded charge or release (spec 9 M11; spec 3 rule 13 is the legacy phase 1 form). With a settlement intent in flight, `RefuseDelivery` records `Finalizing(DeliveryRefused)`, the intent completes under its original identity, and the operation then terminalizes. With an `Open` positive reversible hold, `RefuseDelivery` records the refusal, and the hold and payment journal stay untouched until the payment owner's own successor settles them. A refusal never makes `ContractualZeroCharge` eligible. The terminal and the refusal record are restrictive, non-crossing commits, so the fence that refused the release cannot refuse either, and spec 4's drain terminates. The `OutputRelease` closure-fence check is spec 4 section 4.1 rule 3a, which includes spec 4 rule 1a's legacy predicate for `legacy_unindexed` operations. The same row applies when spec 9's reconciler re-emits a retained finalization |
    | `ReservationConflict` | `HaltOperation` plus an incident. It should be unreachable, because capture amounts were reserved before dispatch |
    | `VersionConflict` | Re-project |
    | `Overloaded` | Not produced for post-effect members (X17b). If received, the driver re-submits; never compensates |
    | `Unavailable` | The fused outcome commit's preconditions no longer hold (for example, an external rail capture). Spec 9 re-plans the settlement as slow-path steps, with an `ExternalPrepare { Settle }` crossing, then the rest of the outcome commit (spec 9 M11). Before recording a new settlement intent, the slow path runs the `OutputRelease` checks (stop, fence, revocation, integrity) in X13's no-write transaction form. X13's read eligibility does not apply, because the fence refs come from the operation's row. A permanent refusal there records no intent and goes to spec 9 M11a with the journal still `Open` |

    For a check-only read or a `NonDurable` call, refusal yields the signed `withheld` receipt (X13a), `KernelStopped` included. No custody holds the output. A check-only read's retry advice follows the refusal reason, exactly as spec 9 M11 and M20 classify it: `KernelStopped` gives `retry: AfterResume` and `StoreUnavailable` gives `retry: AfterStoreRecovery` (both `Reusable`), while `Revoked`, `AuthoritySpaceClosed` or `InsufficientIntegrity` gives `retry: Never` guidance but remains `Reusable`: no row, tombstone, custody or executed effect binds that read's id. A `NonDurable` effect has already executed, so its result is terminal: `OutputWithheld { retry: Never, effect_executed: true }`, with `retryable_after_resume: false` (spec 9 M11, spec 8 S15). `HaltOperation` halts one operation; it never closes the kernel to new dispatch (spec 3's `LatchScope::Operation`).

## 7. Slow paths keep their semantics

| Path | Commits | What changes |
|---|---|---|
| Approval parking | Park commit (`Prepared -> ApprovalRequired` with the hold), progress-only. Then one resume intent commit (`ApprovalReserved -> ReadyToDispatch -> CapturePending -> DispatchCommitted`) | Fewer commits after resume. A resume intent commit refused with `KernelStopped` leaves the operation parked (spec 9 M10) |
| Cross-store participant (remote budget, payment rail) | `ExternalPrepare` crossing (operation row plus payment journal intent, anchored before the external call), the external authorization, then the intent commit | The prepare is anchored, so a restore cannot orphan a rail hold |
| Caller execution (M3) | Reserve (no permission), `CallerStart` crossing (capture before the effect), the authenticated report as a progress-only return record that is never stop-checked, then the outcome commit with its `OutputRelease` crossing (`Withhold` while stopped) | Start and release become `CrossingTx` instances. A report that arrives during a stop is recorded, not lost; only the release waits for resume (spec 8 S8-12; spec 9 M11) |
| Recovery continuation | `reserve_recovery_call` in `process.db` (W:), then the continuation's fast path with `RecoveryCapture` checks | The tombstone check moves into the check list |
| External stateful post-return step | Return record, `ExternalEvaluation` crossing (anchored before output leaves), the external step under its journal, then the outcome commit | The pre-call commit is anchored |
| Economic mutation | `MutationSubmit` crossing before the mutation service call, then the applied or not-applied result | The pre-call commit is anchored |

## 8. Invariants preserved

| Admission rule | Status under this design |
|---|---|
| 1. `Prepared` before the first participant mutation | Strengthened on the fused path (atomic). Unchanged on slow paths |
| 2. Participants keyed by `operation_id` | Unchanged |
| 3. `DispatchCommitted` before any handoff | Unchanged: the anchored intent commit precedes handoff |
| 4. Terminal tombstones retained | Unchanged, including fast-path denials (X15). `KernelStopped` denials create no tombstone, as today's early stop check creates no row (X15a) |
| 5. Receipt-side projections in one typed transaction | Unchanged: the outcome commit is that transaction |
| 6. Holds released only by named release authority | Unchanged |
| Durable outcome before post-return work | Unchanged, except for the opt-in two-commit read (X14) |

Engineering standard rule 5.1 holds by X6, X9 and X15.

```text
handoff(op)                -> durable(intent_commit(op)) and anchored(intent_commit(op))
release(op)                -> durable(outcome_commit(op)) and anchored(outcome_commit(op))
publish_allow(op)          -> receipt(op) in outcome_commit(op) and sequence_assigned(op)   (refines ReceiptBeforeAllow)
committed(fence or stop for s) before cas(op) and s in scopes(op) -> not crossed(op)
restore(db to prefix >= anchor) -> forall crossing c refused before restore: c still refused
refused(c)                 -> state_after(batch) | c = state_before(batch) | c
deny(op) on fused path and reason(op) != KernelStopped -> tombstone(op) and anchored(tombstone(op))
deny(op) and reason(op) = KernelStopped -> no_row(op) or parked(op) or compensated_slow_path(op)
```

## 9. Group commit

17. **X17. Writer loop.** One writer task owns the serving connection, and every write on it goes through the loop. That covers admission, revocation, stop, budget administration, the finding market, channels, FROST and fiscal, each with its commit class.
    - Members enqueue with a reply handle. Enqueue is the submission point (spec 9 M17). Once enqueued, the writer runs and commits the member whether or not anyone still holds its reply handle. A dropped handle never cancels a member, and spec 9's `DropReconcileJob` may take the handle over.
    - **Explicit withdrawal.** The writer supports `withdraw(member)` for a member that is queued but not yet executing, including one re-queued after `Retry` (X21). It answers `Withdrawn`, meaning known not committed and removed from the queue, or `TooLate`, meaning the member has started executing and its final reply follows. Only an explicit `withdraw` removes a member; a dropped handle never does. Spec 9's `DropReconcileJob` (M17) and spec 8's timed-out widening transitions (S36) use it.
    - The loop takes the queue head and every member already queued (`max_batch`, default 64; at most `max_intent_members`, default 16, `DispatchIntent` members per batch).
    - It opens one IMMEDIATE transaction and runs each member as a closure inside its own `SAVEPOINT`.
    - Today's `lock_mutations` critical sections (claim, revalidate, commit) become one member closure.
    - The batch commits once (one WAL fsync), syncs the anchor once if any member is crossing-authorizing or restrictive or the lag bound is reached, then replies to every member.
    - **X17a. Priority lane.** Spec 8's `Stop`, `Restrict`, `Relax`, `Resume`, `Rollover` and `Reconcile` commits enter a priority lane (spec 8 S8-03, S36). `Relax` is included because an operator must be able to widen containment while the ordinary queue is full, and, unlike a stop, a refused relax has no intent latch to preserve it. `Reconcile` is included because resume stays refused until it is anchored (spec 8 S25a).
      - They are dequeued ahead of the FIFO queue.
      - They are never refused with `Overloaded`, and never counted against `max_batch`, `max_intent_members` or the per-tenant cap (X20).
      - A full queue therefore cannot keep an operator from stopping the kernel.
      - Under X21, a lost transaction answers `Retry`, and the lane re-runs first. A stop that cannot become durable (for example on `SQLITE_FULL`) is covered by spec 8's fsynced stop-intent latch, written before the transaction. Boot honors that latch until a durable head supersedes it.
    - **X17b. Post-effect members bypass the queue bound.** `Overloaded` applies only to members that would start new work: intent commits, check-only dispatches, slow-path pre-dispatch steps, and non-admission writes such as budget administration.
      - Post-effect members are never refused with `Overloaded`: return records, outcome commits, release crossings, `Terminalize`, `Compensate`, `RefuseDelivery`, `ReleaseHold` and `ResolveCaptureWaiver`. A rail-held `ResolveCaptureWaiver` uses the same key and capability rules (spec 9 M7b). A rail adapter used for an unknown-outcome `ReleaseHold` must declare one of two capabilities over the hold's `hold_release_key` (spec 9 M7a). `IdempotentPerKey` means at most one release executes per key, whatever request body carries it. The key includes the hold's `attempt_generation`, which rotates only after a durable `release_abandoned` proves the previous key's request can never execute (spec 9 M7a). `FenceByKey` means a terminal fence whose success excludes later acceptance of any request with that key. A status query alone does not qualify, so the `ExternalPrepare { Settle }` crossing refuses a release on an adapter without either capability, before any rail call. Refusing one would turn a known outcome into an unknown one, or strand a hold.
      - Their number is bounded by operations already admitted. Each dispatched operation has at most one post-effect member queued, so admitting them past the bound cannot grow the queue without limit.
18. **X18. No added latency at low load.** The loop never waits to fill a batch. At concurrency 1, latency is unchanged.
19. **X19. Linearization.** Members execute serially in dequeue order, each seeing earlier members' effects. Every CAS keeps its meaning. Dequeue order assigns `member_ordinal`, and each member's authority-chain appends give it a strictly greater `commit_sequence` than every earlier member. So X4's `CrossingOrder` equals execution order.
20. **X20. Fairness.** Members dequeue FIFO, after the X17a priority lane, with a per-tenant cap of a quarter of a contended batch. The cap reorders across tenants only, and X19's order is the dequeue order after the cap. In the single-tenant process host (`LOCAL_SYSTEM_TENANT_ID`) the cap is inert.
21. **X21. Savepoint failure protocol.**
    - After any non-refusal SQLite error, the loop checks `sqlite3_get_autocommit()` and acts on what it reports. On `SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_BUSY` and `SQLITE_NOMEM`, SQLite may roll back the whole transaction automatically, or may leave it active with only the failing statement rolled back (SQLite, "Response To Errors Within A Transaction"). The loop never assumes either outcome.
    - If the transaction is gone, every member gets `Retry` (known not committed) and re-queues. No member ever runs outside the batch transaction. Whole-transaction losses are bounded too. After `batch_loss_retries` (default 2) consecutive losses, the writer answers every queued member `StoreUnavailable` and raises a store incident, and spec 9 M19 retains them. Priority-lane stop and resume members stay covered by spec 8's stop-intent journal.
    - **If the transaction is still active,** SQLite kept it open, whatever the error code. Before anything else, the loop runs `ROLLBACK TO` and then `RELEASE` for that member's savepoint, discarding every write the member made. Then:
      - a uniqueness or CAS-guard constraint answers `Refused(VersionConflict)`, which spec 9 re-projects;
      - any other error answers that member `Retry`, known not committed. After `member_fault_retries` (default 2) consecutive failures of the same planned member, it is answered `StoreUnavailable` instead and a store incident is raised. `StoreUnavailable` is distinct from `Refused(Unavailable)`, which means only that a fused form is ineligible. Spec 9 retains the same member for every effect and never compensates or terminalizes because of it (spec 9 M19);
      - the next member runs only after the savepoint rollback succeeds, so no member executes against a partially applied predecessor.
    - **If `ROLLBACK TO` or `RELEASE` fails,** the loop issues `ROLLBACK` for the whole transaction. No `COMMIT` was issued, so every member is known not committed and gets `Retry`. The writer discards the connection and reopens it through the X9 connection-recovery fence before the next batch. This forced whole-transaction rollback counts toward `batch_loss_retries`, like an automatic rollback. After that many consecutive losses of either kind, every queued member is answered `StoreUnavailable` and a store incident is raised, so the batch can never loop forever and `DropReconcileJob` always gets a final reply.
      - If the fence fails, the owner is poisoned. Queued members are answered `StoreUnavailable` (spec 9 M19). Pre-dispatch drivers with no row deny with a `Reusable` receipt; every other member is retained with its holds until `StartupReconciler` re-drives it after restart.
      - A stop or resume in the priority lane is still covered by spec 8's stop-intent journal (S25).
    - In-memory side effects of a member (the trusted-time fence, caches) are buffered and applied only after `COMMIT`.
    - **`store_healthy`.** After a batch commits following a store incident, the writer emits `store_healthy` once. Spec 9's `StoreRecoveryDriver` re-feeds every retained member on it, and with bounded backoff otherwise.
22. **X22. Unknown outcomes.**
    - If `COMMIT` fails with an unknown outcome, the owner is poisoned and every member gets `OutcomeUnknown`. The same happens when the anchor sync fails after a successful `COMMIT` (`serving_owner.rs:284-289`).
    - Spec 9 emits `HaltOperation` for each member's operation: no dispatch, no compensation, holds and credentials retained (spec 3's `BoundaryFailure::CommitUnconfirmed`). A pre-dispatch member answered `OutcomeUnknown` signs the ambiguous deny with `identity_disposition = Retained` (spec 9 M12, M20). Its request's terminal record comes from reconciliation. Restart reconciles each one. The halt is per operation; the poisoned owner, not a kernel latch, is what stops further writes until restart. Members queued after the poisoning are answered `StoreUnavailable` (X21, spec 9 M19).
    - A `DispatchIntent` member reconciled as `DispatchCommitted` is terminalized as outcome-unknown with holds frozen, even though the driver never handed off. This is the batch's blast radius, bounded by `max_intent_members`. Release then needs the existing counterparty authorities (section 19).

## 10. Writer sharding (later phase, with preconditions)

ADR-0022 names the single-writer ceiling (M: `docs/adr/ADR-0022-store-and-kernel-decomposition.md:9-13`). Sharding by authority domain ships only when every precondition holds:

| # | Precondition |
|---|---|
| S1 | Every cross-tenant aggregate on the serving connection is listed and kept in an unsharded pool shard (slow path), or is forbidden under sharding. That covers the finding market, purchases, challenges and status, channels and release publisher, fiscal, FROST and the economic-state cache (`serving_owner.rs:628-690`) |
| S2 | **Stops (spec 8 S8-13).** The kernel-scope stop chain originates in the pool shard. Each tenant shard holds a verified replica: the same record bytes and digests, appended in that shard as a restrictive commit, so its `StopEpoch` check is authoritative over the replica (X3). The operator acknowledgement returns after the origin commit, with a per-shard status of `enforced` (the replica holds the head) or `fenced_by_lease` (the shard has not confirmed, and will latch `Stopped` when its origin-freshness lease expires, S3). It does not block on a dead shard. The lease bounds how long any shard can keep serving after a kernel stop. **Revocations** use a durable fan-out outbox, with readback per the AP8 discipline (M: `docs/superpowers/specs/2026-10-03-transport-revocation-design.md`) |
| S3 | **Readiness.** A shard is ready only when its replica's stop head equals the origin's exactly, by `(chain_generation, epoch)` and record digest (spec 8 S2, S37), read from the origin at boot. A replica behind catches up first. A replica ahead means the origin regressed, so the shard latches `Stopped` and does not serve. A replica holding an old chain generation's high epoch is behind any newer generation. If the origin is unreachable, the shard is not ready. A new shard is seeded with the origin head before it serves. Revocation heads load the same way before readiness. **While serving**, a shard holds an origin-freshness lease on the monotonic clock: renewed every 250 ms, valid for 1 s. A shard whose replica head id falls behind the origin's, or that loses the origin past the lease, latches the kernel scope `Stopped` and goes `not_ready` with `stop_origin_stale` (spec 8 S37) Lease renewal is challenge-bound: only a signed origin attestation answering the shard's outstanding single-use nonce renews it, and only up to the nonce's send time plus the lease. Replayed or delayed heartbeats never renew (spec 8 S37). |
| S4 | Capabilities are bound to one shard at issuance, or every revocation fans out |
| S5 | Pool-scoped fences without a shard replica are reported `early_only` when checked from a tenant shard. Kernel-scope stops are checked against the replica (S2), and the replication window is what the `enforced` status reports |
| S6 | The process registry's single `durable_admission_store_uuid` (M: `crates/kernel/chio-process/src/registry.rs:58-66`), receipt mover ordering, checkpoint ordering and relocation are defined per shard |

Under sharding:
- a shard is a tenant within a serving authority, with its own database, owner, anchor, chains, crossing records and staged receipts;
- one operation's saga, replay key, budget family and process tree stay in one shard;
- ATTACH across WAL databases is not used.

## 11. Receipt durability

The existing path is kept and made asynchronous behind the gate `async-receipt-materialization`.

| # | Rule |
|---|---|
| 23 | **Durable before allow.** The outcome commit holds the signed receipt in the terminal projection, as today, and allow is returned only after that anchored commit. The receipt is never deleted from the terminal tombstone, so replay keeps loading it from the authority store |
| 24 | **Sequence before allow.** The outcome commit assigns the receipt's log sequence from a per-namespace counter in the authority writer. The namespace is the authority store's identity in the receipt store. `materialize_durable_admission_receipt` becomes the mover: it appends in sequence order, seeds the settlement attempt exactly once on first append as today, and folds receipts into checkpoint batches. **Moves are idempotent.** The receipt log has a unique key on `(namespace, log_sequence)` and on `receipt_id`, and an append is `INSERT ... ON CONFLICT DO NOTHING` followed by a digest comparison with the existing row. A crash after the `receipts.db` commit and before the mover advances therefore re-runs as a no-op: no second log entry and no second Merkle leaf. A conflicting digest is an audit fault that stops the mover and fails closed through rule 25. The mover's cursor is the highest `log_sequence` present in `receipts.db` for the namespace, so no separate moved marker can disagree with the log. Settlement seeding runs only when the insert actually inserted. Gaps and duplicates are audit faults surfaced to SIEM. These are ADR-0013's conditions, with the authority writer as its durable local WAL, so no ADR rule changes |
| 25 | **Saturation fails closed.** A mover backlog above `receipt_backlog_max` (default 4,096) denies new mediated allows before admission. This succeeds today's `receipt_store_serving_closed` gate. Status reports a receipt `signed_but_not_durable` (ADR-0013 wording) until its `receipts.db` commit |
| 26 | **Slim at rest.** Only substructures that no report queries are deduplicated into a content table by digest, for example capability snapshots and delegation chains, with references counted for retention and erasure. Phase 0 attributes the 11.9 KB per call and lists the `json_extract` paths before choosing. Fields the reports query stay in `raw_json`, or move to generated columns. `raw_json` is reconstituted byte-exactly on read |
| 27 | **Signatures stay.** Checkpoint batches align with group-commit batches and emit C2SP-compatible checkpoint notes (north-star bet 6) |
| 28 | **Receipt append for classes with no row.** Check-only reads and `NonDurable` calls (spec 9) have no terminal projection, so their `receipts.db` append is the discharge (spec 9 M16). This spec executes it and reports one of three results. `Committed` is reported at the commit point, right after the append returns `Ok`, and before federation co-sign, trace sequence allocation and the settlement claim; failures of those steps are post-receipt (spec 3, S3-05). `Refused` means known not committed. `Unknown` means the append timed out or was lost; the receipt writer actor may still commit it (chio-store-sqlite `receipt_store.rs:918-924`). Spec 9 maps `Unknown` to `KernelEvidenceLatch` and appends no fault receipt until a read-back of the original id |

## 12. Formal model

A new `formal/apalache/AdmissionCrossing.tla` models one or two operations, the store, the anchor with commit classes, batches with savepoints, crashes at every cutpoint, `Restore(k)` for any k at or above the anchored head, and recovery.

| Kind | Content |
|---|---|
| Invariants | Handoff only after an anchored intent commit; release only after an anchored outcome commit. Allow only after the receipt is in the outcome commit with a sequence (refining `ReceiptBeforeAllow`). No crossing of a `Deny` or `Withhold` kind after a committed fence or stop in its scope, **including after any `Restore`** (X6); `Settle` and `AllowIfContainment` kinds pass only under their spec 8 conditions. No hold release outside named release authorities. Savepoint isolation for refused members, and no member effect after a lost transaction (X21). Fast-path denials other than `KernelStopped` leave anchored tombstones (X15); `KernelStopped` denials leave none (X15a). A stop-refused outcome commit leaves a return record and is never re-dispatched (X14a). The priority lane is never refused with `Overloaded` (X17a) |
| Recovery set | Absent, `Prepared` or `BrokerAttemptRegistered` (slow paths), `ApprovalRequired`, `CapturePending`, `DispatchCommitted`, `AwaitingCallerReport`, `Finalizing`, `Completed`, `CompensatedBeforeDispatch`, `DeniedAfterDelivery`, `OutcomeUnknownAfterDispatch` |
| Refinement | Each crossing commit step refines a sequence of spec 9's `AdmissionMachine.tla` transitions; the model also maps to `PostAdmissionDropGuard` and `KernelTransitionCancelSafe` |
| Negative mutants | Acknowledge before the anchor sync; classify a revocation, stop or fence as progress-only; publish allow before the outcome commit; reply before `COMMIT`; continue a batch after the transaction was lost; skip the fence check in a fused intent commit; drop the deny tombstone; tombstone a `KernelStopped` denial; refuse a stop member with `Overloaded`; stop-check a return record; ignore the process latch in `StopEpoch` |

The model lands in phase 0, before any rule changes behavior.

## 13. Failure modes and crash cutpoints

These extend M: `native-restart-safety.md`'s matrix:

| Cutpoint | Durable state | Recovery |
|---|---|---|
| C1. Before the intent commit | Nothing | None; the caller retries |
| C2. Intent committed, anchor sync failed or outcome unknown | `DispatchCommitted`; owner poisoned; no handoff | Outcome unknown, holds frozen (X22) |
| C3. After handoff, before the return record | `DispatchCommitted` | Unknown, as today |
| C4. Return record committed | `Finalizing` with frozen evaluation inputs | Re-run pure evaluation from the frozen inputs (X11) |
| C5. Outcome committed, anchor sync failed | `Completed`; owner poisoned; output not released | Restart re-anchors forward; replay returns the recorded outcome |
| C6. After release | `Completed` | Replay |
| C7. Restore to a prefix at or above the anchor | Progress-only suffix lost | X6: no refused crossing becomes allowed. A lost return record becomes unknown |
| B1. Batch `COMMIT` outcome unknown | Unknown for every member | Owner poisoned; restart reconciles each member |
| B2. Batch transaction lost before `COMMIT` | Nothing from the batch | Members get `Retry` (X21) |
| B2a. Statement error with the transaction still active | That member's savepoint is rolled back; other members are unaffected | That member gets `VersionConflict`, `Retry`, or `StoreUnavailable` after `member_fault_retries` (X21). Spec 9 M19 retains it; `store_healthy` re-feeds it |
| B2b. Savepoint rollback fails | The whole transaction is rolled back | Members get `Retry`; the connection is reopened through X9. If the fence fails, the owner is poisoned and queued members get `StoreUnavailable` (X21) |
| R1. Receipt not yet materialized | Receipt in the terminal projection | The mover resumes; status `signed_but_not_durable` |
| R1a. Crash after the `receipts.db` append, before the mover advances | Receipt in the log and in the terminal projection | The re-run append conflicts on `(namespace, log_sequence)` and `receipt_id`, the digests match, and nothing is appended (rule 24) |
| R2. Check-only or `NonDurable` receipt append outcome unknown | The append may or may not commit | Spec 9 M16: `KernelEvidenceLatch` with a buffered fault record; read back the original id before appending any fault receipt (rule 28) |
| P1. Stop committed while a two-commit read is in flight | `DispatchCommitted`, then the return record after the refused outcome commit | `Finalizing`, output withheld; released after resume (X14a) |

Other failures:
- A refused crossing returns its typed reason with no state change.
- A full writer queue gives `Overloaded` before any write, except to the X17a priority lane.
- A full mover backlog denies new allows (rule 25).

## 14. Acceptance targets

Measured on the steady process-host run (M: `BENCHMARK.md`) on its machine class, plus a new shared-writer kernel benchmark. The new benchmark runs N concurrent callers on one kernel with a SQLite `DurableAdmissionRuntime`, modes `All` and `SideEffecting`, and stub tools.

| Measure | Baseline | Target | Gate |
|---|---|---|---|
| Authority commits per fast-path side-effecting call | 10 (M: head, section 2.1) | 3 | Deterministic (store hook) |
| Synchronous anchor syncs per fast-path side-effecting call (X7a) | about 10.5 (348/33) | 2 | Deterministic, under a fixture with no lag trigger: return-to-outcome under `anchor_lag_ms` and fewer than `anchor_lag_commits` intervening commits |
| Total anchor syncs per fast-path side-effecting call, including lag anchors | about 10.5 | 2 on the ideal path; 3 on an isolated delayed return | Reported, with synchronous and lag anchors listed separately |
| Synchronous `receipts.db` fsyncs per durable call (with the gate on) | about 1.2 | 0 | Deterministic |
| On-path authority, anchor and receipt fsyncs per side-effecting call | about 22.7 | 5 or fewer on the ideal path (3 WAL + 2 synchronous anchors); 6 on an isolated delayed return (plus one lag anchor) | Deterministic under the no-lag-trigger fixture; reported otherwise |
| On-path fsyncs per call including `process.db`, excluding setup | about 26.5 | 9 or fewer | Reported |
| Authority commits per two-commit read (`All`, eligible) | 10 | 2 | Deterministic |
| fsyncs per check-only read (non-durable, eligible) | 1 `receipts.db` (plus a budget commit only for quota grants, which are ineligible) | 1 `receipts.db`, 0 authority | Deterministic |
| Process-mediated `read` median / p95 | 130 / 161 ms | 95 / 125 ms or less | Reported |
| Shared-writer throughput at 16 callers (new benchmark) | Phase 0 measurement | At least 4x the phase 0 baseline | Reported |
| Shared-writer latency at concurrency 1 | Phase 0 measurement | No regression above 5 percent | Reported |
| Receipt bytes at rest per call | about 11.9 KB | At most half, set after phase 0 attribution | Reported |

**Derivation of the `read` target.**
- Non-fsync time is about 69 ms (section 2.8).
- A two-commit read issues 2 authority commits, 2 anchor syncs and about 3.8 `process.db` fsyncs. That is about 7.8 fsyncs, or about 18 ms, for a predicted median of about 87 ms.
- The three-commit path predicts about 89 ms on the ideal path. A delayed return adds one lag anchor, about 2.3 ms (X7a).
- The target leaves margin for variance.
- Going further requires reducing non-fsync CPU time, which is out of scope (section 3).

The B: kernel-only and sustained-load figures stay as context (section 2.8).

## 15. Protocol, schema and wire impact

- **Native wire, verdicts and receipt format:** none, except spec 8's `OutputWithheld` result for a stop-withheld two-commit read (X14a), which spec 8 defines.
- **Receipt metadata:** `chio_runtime.crossing { kind, store_uuid, observed_commit_sequence, check_ordinal }` on check-only reads and `NonDurable` calls (X4), a `withheld` decision reason on refused releases, the stop head's `observed` on `KernelStopped` denials (X15a), and `chio_runtime.identity_disposition` on every non-allow receipt (spec 9 M20). `chio_runtime` and `receipt_context` are kernel-reserved keys that caller metadata cannot set (spec 9 M20).
- **`spec/PROTOCOL.md` section 6:** durable-before-allow is satisfied by the receipt in the anchored terminal projection. A receipt is audit-complete when the receipt store and a checkpoint cover it.
- **Admission design amendments:** X14 and X14a (the opt-in two-commit read and its stop fallback), X15 and X15a (deny tombstones on the fused path except for `KernelStopped`; rule 4 unchanged), the caller report as a progress-only return record (section 7), and the commit classes of section 5.
- **ADR-0013:** no rule change. The authority writer is the local WAL under rules 23 to 25.
- **Store schema:** new tables `crossing_records` and the receipt content table, and a receipt sequence counter per namespace. Fence and stop tables belong to specs 4 and 8.
- **Formal:** the new model and its manifest entries.

## 16. Rollout

Every phase ships behind its own flag: `crossing-anchor-classes`, `crossing-primitive`, `crossing-fusion`, `crossing-read-two-commit`, `async-receipt-materialization`, `group-commit` and `sharded-writer`. The deterministic gates of section 14 must pass before a flag defaults on.

0. **Measure.** Re-trace fsyncs per call and retain the artifact; attribute receipt bytes and `json_extract` paths; build the shared-writer benchmark and record its baselines; land the Apalache model with the `Restore` adversary and mutants; run the eligibility census (X12).
1. **Commit classes and the custody check (section 5).** Classify every commit site, move to the in-memory expected head, and apply the bounded lag. Anchor syncs drop from about 10.5 to about 2 per call before any fusion.
2. **`CrossingTx` for existing crossings.** Wrap dispatch commit, output release and the external-call crossings, moving the stop, fence, revocation and applicable `KnowledgeIntegrity` checks inside, with crossing records.
3. **Fusion,** in order: the intent commit with deny tombstones; the return record fused with begin-evaluation; the outcome commit; the check-only read; the two-commit read behind its flag.
4. **Async receipt materialization**, behind its gate (section 11).
5. **Group commit**, with the savepoint protocol.
6. **Sharding**, after the section 10 preconditions.

## 17. Tests and conformance evidence

- **Apalache:** the model and mutants of section 12.
- **Loom:** batch leader and followers; savepoint isolation; `StoreUnavailable` after member retry exhaustion leaves no partial member and later members unaffected; acknowledgement strictly after `COMMIT` and the required anchor sync; a stop commit racing a fused intent commit; a stop member, and separately a relax member, in the priority lane against a full queue (X17a); a host latch set while a `StopEpoch` check reads the `ArcSwap`; commit, anchor sync and expected-head verification races (X9); a lost-transaction batch (X21).
- **DST:** crash injection at C1-C7, B1, B2, R2 and P1, plus restore-from-snapshot at random anchored prefixes, under random workloads. Stops are issued under `Overloaded` and under `SQLITE_FULL` injection. Under sharding, one shard is offline during a stop fan-out and then restarts; it must not serve until its replica catches up (S3). A serving shard partitioned from the origin during a stop latches `Stopped` within its 1 s lease. A crash between the `receipts.db` append and the mover's advance re-runs as a no-op (rule 24). The properties are section 8's predicates.
- **Differential:** generated workloads run through the legacy and fused paths must reach identical terminal states, receipts and release decisions. The two-commit read is compared under its own flag.
- **Check-only release integrity (X13a):** dispatch an eligible read, then commit a stricter non-grant release floor or a new installed policy generation before release. The second crossing evaluates the new requirement and, when it fails, emits no result bytes and appends `Withheld { reason: InsufficientIntegrity }` with `retry: Never`. Repeat for a `NonDurable` side effect and assert one execution, no redispatch and `effect_executed: true`. Cover unchanged policy (release succeeds), a changed policy still satisfied (release succeeds), a tracking requirement enabled after dispatch while the current state still satisfies the floor (typed `InsufficientIntegrity`, no unjoined delivery, `Reusable` for the check-only read), and both writer orders of a policy update racing release. Instrument the release checker to show it reads the current policy and committed integrity state, rather than a cached dispatch verdict. The no-write path retains zero authority commits and one receipt append; a refused release's append failure still takes X13b's evidence latch.
- **Participant preconditions (X5b):** under the fused path, these must refuse exactly as on the legacy path:
  - native capture with a protected setup selection and an unqualified scope;
  - native capture whose security context differs from the selected deployment in any field;
  - a second selected self-test capture;
  - a semantic capture and an artifact release on an unqualified scope.

  Native capture on a qualified scope and the one selected self-test must pass. Each case is repeated after a stale deployment generation, a stop and a restart.
- **Commit-budget gates:** these are deterministic, from store hooks, and scoped to fast-path-eligible plans:

  | Path | Commits | Anchor syncs |
  |---|---:|---:|
  | Side-effecting | 3 | 2 |
  | Two-commit read | 2 | 2 |
  | Check-only read | 0 | 0 |

  Each slow path has its own budget table: approval adds the park commit, cross-store adds the prepare, caller execution adds start and report, external evaluation adds its crossing.
- **Benchmarks:** the process-host and shared-writer harnesses report the section 14 rows per run.
- **chio-conformance:**
  - a stop or revocation committed and then restored-around still denies;
  - a fast-path policy deny other than `KernelStopped` burns the request id;
  - a `KernelStopped` deny leaves the id usable after resume;
  - containment (`ActiveResponseExecute`) passes a stop with `allow_containment = true` and is refused under a host latch;
  - settlement of an earlier call (`ExternalPrepare { Settle }`, `ChannelReleasePublish`) passes a stop, and `ExternalPrepare { Authorize }` is refused;
  - a caller report during a stop is recorded and released after resume;
  - a two-commit read refused at its outcome commit returns `OutputWithheld` and is never re-dispatched;
  - a read-only or `NonDurable` call always yields a receipt or a buffered fault behind `KernelEvidenceLatch`;
  - a receipt append that times out and later commits yields exactly one terminal receipt;
  - a crash after handoff yields outcome-unknown, never redispatch for side-effecting tools;
  - a fused intent from `Prepared` refused by a fence or revocation compensates and releases its runtime hook (X10);
  - settlement of an effect committed before a revocation or closure passes those checks, and a new authorization after the cut is refused;
  - an outcome commit under a full writer queue is never refused `Overloaded` (X17b);
  - a re-run receipt move appends nothing (rule 24);
  - a read under integrity tracking takes the durable path, and its influence join is committed before the output is delivered (X13);
  - a member whose reply handle is dropped after enqueue still commits, and the handle's new owner receives the reply (X17);
  - a `Terminalize` and a `Compensate` member that exhaust `member_fault_retries` are answered `StoreUnavailable`, never `Refused(Unavailable)`; after `store_healthy` the same member commits exactly once. After owner poisoning, queued members get `StoreUnavailable` and restart re-drives them (X21, X22);
  - an `ExternalPrepare { Settle }` for an unknown-outcome release on a rail adapter with neither `IdempotentPerKey` nor `FenceByKey` is refused before any rail call (X17b);
  - every non-allow receipt carries `identity_disposition`, and for stop denials it agrees with spec 8's `retryable_after_resume` (X15, X15a);
  - a pre-dispatch member answered `OutcomeUnknown` signs a `Retained` deny, and the outcome-unknown terminal that reconciliation later writes is the request's one `Terminal` receipt (X22);
  - crossing order (X4):
    - two members in one batch get strictly increasing `commit_sequence`;
    - members with the same `member_ordinal` in consecutive batches are ordered by `commit_sequence`;
    - a stop committed between two batches orders the first batch before it and the second after it;
    - across an owner restart, `commit_sequence` continues and no order repeats;
    - a check-only receipt's `observed_commit_sequence` places it between the commits it observed.

## 18. Alignment with sibling specs

| Spec | What it must carry |
|---|---|
| Spec 9 | **Division:** spec 9 decides every transition and receipt; this spec executes the commits and reports `Committed`, `Refused`, `OutcomeUnknown` or `Retry` per crossing, and `Committed`, `Refused` or `Unknown` per receipt append (rule 28). **Effects:** `IntentCommit` (with the `from_prepared` flag), `ReturnRecord` (fused with begin-evaluation; also the caller report and the X14a fallback, never stop-checked), `OutcomeCommit`, `CheckOnlyCrossing` acknowledged by `CheckOnlyAcknowledged` (read-only and `NonDurable` classes), `DenyTombstone` (not for `KernelStopped`) and `ParticipantCommit`. **Events:** `CommitFailed` reasons including `Overloaded`; `CommitOutcomeUnknown` (`HaltOperation`, no compensation, reconcile at restart); `StoreUnavailable` (M19: retain the same member, re-feed on `store_healthy`); `ReceiptAppendFailed`. **Receipts:** every non-allow receipt carries spec 9 M20's `identity_disposition`. **Inputs:** `EvaluationContext` must carry whether the driver permits redispatch on unknown (X14). **Section 6.4:** post-effect refusal handling, spec 9 M11 and M16 |
| Spec 11 | Owns `KnowledgeIntegrity` semantics. It runs inside the intent commit and every dispatch-commit step, fast or slow. In check-only read dispatch and release it applies to current non-grant requirements, because grant constraints make a read ineligible (X13, X13a); the NonDurable class includes grant requirements (X13c). Release always rechecks the installed policy and I4b prerequisites in its own crossing, even if dispatch passed. The outcome commit records the output influence join. A call under integrity tracking never takes the check-only or `NonDurable` path, so every delivery it makes has an outcome commit to carry the join (X13, X13c) |
| Spec 3 | Spec 3 owns the affine driver contract, `LatchScope` and the ledger. Its obligation is discharged by the acknowledgement of a spec 9 M14 discharge effect that this spec executes: the outcome commit, the return record, a terminal projection, or the rule 28 receipt append. The `Reservations` check writes only `Compensable` holds and records `Commitment` entries by reference. Spec 3 phase 1's obligation and kernel-evidence latch close D1 on the check-only and `NonDurable` paths (X13b, X13c). `HaltOperation` is spec 3's `LatchScope::Operation` |
| Spec 4 | The dispatch-commit fence is the `ClosureFence` check. Section 4.1's new crossing kinds join its section 4.3 table. Refused releases end in a restrictive, non-crossing `DeniedAfterDelivery` terminal or `DeliveryRefused` record (spec 9 M11a), so its drain terminates |
| Spec 8 | Stop and resume epochs are restrictive commits, anchored before acknowledgement, consistent with its S1, and run in the X17a priority lane. Its tier-2 check is `StopEpoch` over `(kind, scope, disposition)`, durable heads and process latches. Section 4.2's Stop column repeats its section 5 dispositions. Its tier 1 reads the per-store shared `StopHeads`. `KernelStopped` denials are temporary (X15a); the caller report and the X14a fallback are never stop-checked. Sharded stops follow section 10 S2 and S3. Check-only reads carry `chio_runtime.crossing` for its DST property, which excludes `Settle` and `AllowIfContainment` kinds |
| Spec 5 | A crossing's `Committed` reply is the only point after which spec 9 posts a hint (spec 9 M18). For crossing-authorizing and restrictive commits, `Committed` implies anchored, so a re-read observes the hinted change. For progress-only commits, a `Restore` within the anchor lag (X7) can undo it, and spec 5 consumers treat absence as a resync |

## 19. Residual risks and open decisions

Residual risks:
- **Settlement during a stop.** `Settle` kinds (section 4.2) move funds and evidence while the kernel is stopped. They are limited to effects committed before the stop head. No disposition in this revision freezes settlement as well. Spec 8 owns that choice, and this spec enforces whatever disposition spec 8 assigns to a kind.
- **Withheld output in classes with no row.** A stop or fence that refuses the release of a check-only or `NonDurable` call drops the output, with a `withheld` receipt, because there is no custody to hold it (X16). Durable coverage (`All`) is the remedy.
- **Batch blast radius.** One unknown `COMMIT` freezes the holds of up to `max_intent_members` intent members whose drivers never handed off. A hold that ends outcome-unknown is released only by `MutuallyAgreedUnknown`, a counterparty authority (spec 9 M7a), plus an operator incident path. `ContractualCaptureWaiver` applies only to a known return (spec 9 M7b).
- **Progress-only loss on restore.** A restore can turn completed calls into outcome-unknown. That is bounded by the anchor lag, and it is always the conservative branch.
- **Non-fsync time.** It dominates after this design (about 69 ms for `read`). The latency targets are honest about it.
- **Write-lock queueing.** Check-only crossings queue behind write batches under load. They ride batches without writes.
- **Deduplication correctness.** Content-addressed receipt bodies make byte-exact reconstitution and reference counting correctness requirements. Differential tests guard them.
- **Platform variance.** fsync cost varies by platform, so targets are re-baselined per platform.

Open decisions:
1. **Return record for side-effecting calls.** Keep it (this draft), or fuse it for a two-commit path generally and accept a wider unknown window.
2. **Process call slot.** Co-locate it with the authority writer, saving about one fsync per call, at the cost of moving journal ownership.
3. **Receipt sequence namespace.** A per-authority namespace (this draft), or a shared namespace with the mover assigning sequence under an ADR-0013 revision.
4. **Shard key and pool shard** (section 10).
5. **Batch defaults.** `max_batch`, `max_intent_members`, `anchor_lag_commits`, `anchor_lag_ms`, and the per-tenant cap.
6. **Signature elision.** Whether receipts could later rely on checkpoint inclusion proofs. Not proposed.
7. **Drop the check-only path entirely,** in favor of `All` everywhere, if the shared-writer benchmark shows the two-commit read costs little.

## Review disposition

| Finding | Disposition |
|---|---|
| S10-01 | Applied: three commit classes; restrictive commits anchored before acknowledgement; X6 restated; bounded lag (X7); `Restore` adversary in the model |
| S10-02 | Applied: check-only requires `!mode.covers(ReadOnly)` and `can_redispatch_unknown_read`; durable modes take the two- or three-commit path; the "existing contract" claim deleted; mode matrix in section 6.2 |
| S10-03 | Applied: in-memory expected-head custody check; `prove_extension` at anchor and startup only; connection-recovery fence redefined; phase 1 and Loom (X9) |
| S10-04 | Applied: eligibility via `can_redispatch_unknown_read`, which excludes every pre-dispatch consumable; fence refs derived from the request (X13) |
| S10-05 | Applied differently: the check-only release keeps today's `receipts.db` append, so there is no extra fsync. The D1 claim is limited to what spec 3 closes. The baseline is corrected. A refused release writes a signed `withheld` receipt (X13a, X13b) |
| S10-06 | Applied: baselines re-derived from per-file attribution excluding setup; the `read` target is now 95 ms from a stated derivation; throughput on a new shared-writer benchmark; B: rows are context only |
| S10-07 | Applied: the inventory re-derived from M: code (10 commits, post-effect 4); citations corrected; conditional commits listed (section 2.1) |
| S10-08 | Applied: preconditions restated; intent from persisted `Prepared` (X10); eligibility census (X12) |
| S10-09 | Applied: deny tombstones in an anchored restrictive commit (X15); rule 4 unchanged |
| S10-10 | Applied: `OutcomeUnknown` result and spec 9 event; anchor-sync failure replies; `max_intent_members` cap; frozen-hold risk documented (X22) |
| S10-11 | Applied: `CheckOnlyAcknowledged` (spec 9); `Overloaded`; post-effect refusal table (X16) |
| S10-12 | Applied: external-call crossing kinds (`ExternalPrepare`, `MutationSubmit`, `ExternalEvaluation`, `ActiveResponseExecute`, `FederationCosign`, `ChannelReleasePublish`), crossing-authorizing |
| S10-13 | Applied: rebased on the existing projection, `materialize_durable_admission_receipt` and the restart mover; the receipt never leaves the terminal tombstone; backlog bound; sequence before allow, so no ADR-0013 rule change (section 11) |
| S10-14 | Applied: sharding demoted to phase 6 with preconditions S1-S6 |
| S10-15 | Applied: savepoint failure protocol with an autocommit check, `Retry`, no member outside the transaction, and buffered side effects (X21) |
| S10-16 | Applied: check-only exempt from X4; its linearization index travels in receipt metadata |
| S10-17 | Applied: issuance is `early_only`, not a crossing here; P5's final read is kept (X5a) |
| S10-18 | Applied: `Reservations` writes only `Compensable` holds and observes `Commitment` entries |
| S10-19 | Applied: every write goes through the loop, with its class; `lock_mutations` sections become member closures (X17) |
| S10-20 | Applied: the return record freezes the evaluation time, steps and context; the outcome commit verifies them (X11) |
| S10-21 | Applied: `Restore(k)`, a widened recovery set, and refinement to spec 9's model |
| S10-22 | Applied: anchor triggers defined by class or lag; a batch boundary alone does not force a sync (X7) |
| S10-23 | Applied: commit-budget gates scoped to fast-path plans, with per-slow-path budgets |
| S10-24 | Applied: deduplicate only non-queried substructures, with generated columns and reference counting (rule 26) |
| S10-25 | Applied: the quote is attributed to `AGENT_PROCESS_DIRECTION.md:166-167` |
| S10-26 | Applied: the projection is cited at `terminal.rs:1817`, `:1865` |
| S10-27 | Applied: `mailboxes.db`, `runner.db` and canonical receipts in `authority.db` added (section 2.3) |
| S10-28 | Applied: X20 states that the cap reorders across tenants only and is inert in the single-tenant host |
| S10-29 | Applied: "staged projection" removed; the classes are defined in section 5 |

### Wave 2 (cross-spec)

Findings from the reviews of specs 3, 5 and 8 that this spec had to absorb, per the wave 2 shared decisions:

| Finding | Disposition |
|---|---|
| S3-03 | Applied: X16 and X22 use spec 9's `HaltOperation` (spec 3 `LatchScope::Operation`); no kernel-wide latch on post-effect refusals or unknown outcomes |
| S3-05 | Applied: rule 28 reports `ReceiptCommitted` at the commit point, and `Unknown` for an append that may still commit; R2 cutpoint |
| S3-15 | Applied: section 18 states the division (spec 9 decides, this spec executes, spec 3 owns the affine contract); rule 28 executes the receipts append for classes with no row |
| S3-16 | Applied: X13c routes spec 9's `NonDurable` class through a check-only crossing |
| S3-25 | Applied: X16 cites spec 9 M11 and spec 3 rule 13. The umbrella row and spec 3's commit count are outside this file |
| S5-11 | Applied: section 18 spec 5 row states what `Committed` guarantees per commit class |
| S8-02 | Applied: `StopEpoch` reads durable heads and process latches (section 4.2); P5's final read consults the latches (X5a) |
| S8-03 | Applied: X17a priority lane, exempt from `Overloaded`, `max_batch`, `max_intent_members` and the tenant cap; X20 amended |
| S8-08 | Applied: tier 1 reads the per-store shared `StopHeads` (section 4.2) |
| S8-10 | Applied: X5a cites `admit_confined_return` and states that the final journal read is not a stop check |
| S8-11 | Applied: the Stop column carries `StopDisposition` per kind, citing spec 8 section 5; `ExternalPrepare` split by purpose; X1 requires a disposition for new kinds; model invariant excludes `Settle` and `AllowIfContainment` |
| S8-12 | Applied: the caller report is a progress-only return record, never stop-checked (section 7) |
| S8-13 | Applied: section 10 S2, S3 and S5 replaced (pool-shard origin, verified replicas, readiness by epoch, non-blocking acknowledgement) |
| S8-17 | Applied: X15a, no tombstone for `KernelStopped` on either tier |
| S8-18 | Applied: X14a, return record on a stop-refused outcome commit, `OutputWithheld` |
| S8-19 | Applied: section 7 approval row; spec 9 M10 retains `Parked` |
| S8-27 | Applied: `AllowIfContainment`; a host latch implies `allow_containment = false` |
| S8-28 | Applied: `commit_durable_dispatch` cited at `:1560`. Also fixed three stale sub-rule labels from revision 2: the `Retry` comment and the restrictive-class row cited X15b, X12a and X13c for what are X21, X15 and X16. The label X13c now names the new `NonDurable` rule |

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180435355 | Make receipt-log moves idempotent | Fixed now. Revision 2 already assigned the log sequence in the outcome commit. This round adds unique keys on `(namespace, log_sequence)` and `receipt_id`, `ON CONFLICT DO NOTHING` with a digest comparison, and a cursor taken from the log itself, so a crash after the append re-runs as a no-op | rule 24; cutpoint R1a; section 17 |
| 4180731780 | Compensate hooks acquired before the fused intent | Fixed now. A fused intent from `Prepared` refused for any policy reason compensates the persisted operation, releasing the hook and nonce through their participants, and writes no tombstone. X15's tombstone is scoped to refusals from `Unbegun` | X10, X15; spec 9 M10 |
| 4180731789 | Exempt prior-effect settlement from permanent authority fences | Fixed now. The settlement kinds apply the subject-before-cut test to the closure-fence and revocation checks, as they do for stop. A new authorization after the cut is still refused | section 4.2; section 17 |
| 4180731782 (spec 8) | Continuously fence shards that lose the stop origin | Fixed here for the sharding side. A serving shard holds a 250 ms / 1 s origin-freshness lease on the monotonic clock and latches `Stopped` with `stop_origin_stale` when it falls behind or loses the origin. The acknowledgement reports `enforced` or `fenced_by_lease` (spec 8 S37) | section 10 S2, S3; section 17 |
| (related) | Post-effect `Overloaded` | Added with spec 9's 4180435341 fix: post-effect members bypass the queue bound | X17b, X16 |

### Codex review (PR #1174, round 2)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180839013 | Persist influence joins before check-only output release | Fixed now. A call whose context has integrity tracking enabled is not check-only eligible and takes the durable three-commit path, so its `OutcomeCommit` writes the I4 join before bytes leave. Would-be `NonDurable` calls under integrity tracking do the same | section 6.2 table; X13; X13c; section 18; spec 9 section 4.4 |
| 4180839034 (spec 9) | Do not compensate while the intent commit is still in flight | Supporting change here. Enqueue is the submission point, and a dropped reply handle never cancels a member, so spec 9 M17 treats a dropped-after-submission driver as `CommitUnconfirmed` and reconciles from the writer's reply | X17; spec 9 M17 |

## Appendix A. Precedent

- **FTL.** One trap entry decides every system call path (FTL `kernel/src/arch/x64/syscall.rs:65`). `ReserveSlot` reserves before an infallible commit (FTL `libs/ftl_utils/src/reserve_slot.rs`). `CrossingTx` is the single entry for every custody crossing.
- **Group commit** batches the log flushes of many transactions into one. It is standard in PostgreSQL and MySQL. SQLite supports it through one transaction with nested savepoints, but rolls back the whole transaction on some errors, hence X21 ([SAVEPOINT](https://www.sqlite.org/lang_savepoint.html), [WAL](https://www.sqlite.org/wal.html)).
- **Certificate Transparency** batches entries under signed tree heads with inclusion proofs ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)).

Where the analogy breaks:
- FTL commits nothing durably and has no restore adversary.
- Chio must survive a crash at any cutpoint and a restore to any anchored prefix without widening authority. That is why commit classes, the custody check, the return record and the cutpoint matrix exist.

### Codex review (PR #1174, round 4)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180933166 | Handle errors that leave the batch transaction open | Fixed now. X21 defines the active-transaction branch: the member's savepoint is rolled back and released before anything else, the member gets `VersionConflict`, `Retry`, or `Unavailable` after bounded retries, and no later member runs against an unrecovered savepoint. If the savepoint rollback fails, the whole transaction rolls back (`Retry` for all, connection reopened through X9, owner poisoned if the fence fails). New crash rows B2a and B2b | X21; section 13 |

### Codex review (PR #1174, round 3)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180886727 | Recheck revocation before releasing tool output | Fixed now. Every release crossing (`OutputRelease`, `ArtifactRelease`, `ConfinedReturn`, `ExternalEvaluation`) rechecks revocation before bytes leave Chio custody. The effect has happened, so a refusal withholds the output and never compensates: X16's `Revoked` row (shared with closure and integrity) terminalizes as `DeniedAfterDelivery` through spec 9 M11, and P4 and P5 keep their pins and consumption | section 4.2; X16 |
| 4180886724 (spec 9) | Treat a committed capture as post-dispatch at a cut | Fixed in spec 9 section 6.1 and M10 | spec 9 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-10-02 | The deterministic two-anchor target conflicts with bounded-lag anchoring | Fixed. X7a separates synchronous anchors, which acknowledgements wait on, from lag anchors fired by `anchor_lag_commits` or `anchor_lag_ms`. The deterministic gate is 2 synchronous anchors under a fixture with no lag trigger. Total anchors are reported separately. The fsync target states the 5-fsync ideal path and the 6-fsync isolated delayed-return case. Restore safety is unchanged | X7a; section 1 table; section 14 |
| Reconciliation note on 4180933166 | The X21 opening sentence overstates automatic rollback | Fixed. Per SQLite, `SQLITE_FULL`, `SQLITE_IOERR`, `SQLITE_BUSY` and `SQLITE_NOMEM` may roll back the whole transaction or leave it active. The loop never assumes either outcome and branches on `sqlite3_get_autocommit()` | X21 |

### Codex review (PR #1174, round 5)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180993960 (spec 9) | Make stopped non-durable effects terminal to retries | Fixed with spec 9 M11. X16 now separates the redispatch-safe check-only read (`retry: AfterResume`) from the terminal `NonDurable` effect (`retry: Never`, `effect_executed: true`) | X16 |
| 4180993966 (spec 9) | Reconcile an external hold release before retrying it | Fixed with spec 9 M7a. X17b requires rail adapters used for unknown-outcome releases to support idempotent submission or status query by key | X17b |

### Codex review (PR #1174, round 6)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4181461517 | Recheck revocation on check-only release | Fixed now. The X13a release crossing rechecks stop, fence and revocation; round 32 also makes the current integrity check explicit, matching the durable `OutputRelease` row. A revocation after dispatch withholds the output under spec 9 M11's post-effect handling, for both check-only reads and `NonDurable` calls | X13a |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-02 | Writer escalation produces Unavailable for effects whose machine declares that result impossible | Fixed. X21 retry exhaustion, a failed recovery fence and members queued after poisoning now answer the distinct `CrossingResult::StoreUnavailable`, known not committed. `Refused(Unavailable)` keeps its one meaning, a fused form is ineligible. Spec 9 M19 retains the same member for every effect, and the writer emits `store_healthy` to re-feed it | section 4.1; X21; X22; B2a, B2b; section 17 |
| R-9-01 | A negative rail status query is not proof that an in-flight release can never arrive | Fixed with spec 9 M7a. X17b requires a declared `IdempotentPerKey` or `FenceByKey` capability over the per-hold key. The prepare crossing refuses an adapter without one, before any rail call | X17b; section 17 |
| R-8-02 / R-6-06 | Identity disposition for retryable versus terminal denials | Fixed through spec 9 M20. Tombstones and `Prepared` or slow-path compensations are `Terminal`; tier-1, fused-from-`Unbegun` stop, `Overloaded` and no-row `StoreUnavailable` denials are `Reusable`. Spec 8's `retryable_after_resume` agrees. `chio_runtime` and `receipt_context` are kernel-reserved (R-6-05 cross-reference) | X15; X15a; section 15; section 18 |

### Codex review (PR #1174, round 7)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185260847 | Include Relax commits in the priority lane | Fixed now. X17a lists `Stop`, `Restrict`, `Relax`, `Resume` and `Rollover`, matching spec 8 S36, and the Loom plan runs a relax member against a full queue | X17a; section 1; section 17 |
| 4185260860 (spec 8) | Carry the chain generation through rollover | Fixed in spec 8. Section 10 S3 compares replica and origin stop heads as `(chain_generation, epoch)`, so a replica holding an old generation's high epoch is behind | section 10 S3 |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364947 (spec 8) | Require exact origin equality before shard readiness | Mirrored in section 10 S3: readiness requires an exact match; a replica ahead latches | section 10 S3 |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-10-03 | The crossing index lacks the ordering contract required by its consumers | Fixed. X4 defines `CrossingOrder = (store_uuid, commit_sequence, member_ordinal)` over the existing durable authority chain, with check-only crossings placed by `observed_commit_sequence`, plus comparison rules for owner change, sharding and restore. `(batch_index, writer_epoch)` is withdrawn everywhere. X19 ties the order to execution order, and tests cover same-batch, consecutive-batch, stop-between and owner-restart cases. Answers the owner's open question 3: reuse the global commit sequence with a member ordinal, and add no new sequence | X4; X19; section 15 receipt metadata; section 17 |
| R-6-07 (emitter side) | An ambiguous commit denial binds the adapter before recovery produces the terminal receipt | Fixed. X22 states that pre-dispatch members answered `OutcomeUnknown` sign `Retained` denials, and that the reconciled outcome-unknown terminal is the one `Terminal` receipt | X22; section 17 |

### Codex review (PR #1174, round 13)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186619818 | Give check-only crossings a true after-commit order | Fixed now. Written and check-only positions compare through a discriminated key: `(s, c, 0, member_ordinal)` for written crossings and `(s, c, 1, check_ordinal)` for checks. A check that observed head `c` sorts after everything written at `c` and before `c + 1`, and the two ordinal domains cannot collide | X4 check-only crossings |

### Codex review (PR #1174, round 14)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186767763 | Make check ordinals restart-stable | Fixed now. `check_ordinal` is `(store_owner_epoch, owner_check_counter)`. The persisted owner fence epoch strictly increases on each acquisition, so a restarted owner observing the same head can never reuse a key | X4 check-only crossings |

### Independent review pass 4 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-1-03 (spec 10 part) | The recovery inventory stops before implemented P6 setup and signed maintenance | Fixed. New rule X5b keeps every participant's transaction-local preconditions inside its `CrossingTx`: native capture keeps `setup::require_capture`, recovery and semantic capture keep `require_command` and `require_ready`, and artifact release keeps `require_ready`. They stay named participant preconditions, not new crossing kinds. Integrity deployment configuration goes through the existing P6 policy owner. Differential tests cover the setup gate | X5b; section 17 |

### Codex review (PR #1174, round 18)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187315424 | Bound lost-transaction retries before requeueing | Fixed now. Consecutive whole-transaction losses count toward `batch_loss_retries` (default 2). After that the writer answers members `StoreUnavailable` and raises a store incident, so M19's fail-closed retention applies. Stop requests stay protected by the intent journal | X21 |

### Codex review (PR #1174, round 19)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187433143 | Complete the cross-spec crossing registry | Fixed by narrowing X1 to the owning registry. Section 4.2 is the registry of crossing kinds. The default ordering point is the kind's own `CrossingTx` commit under `CrossingOrder`. Spec 4 section 4.3 lists only kinds whose custody-exit point differs. Spec 1 registers the driving L0 ops, not crossings | X1 |

### Codex review (PR #1174, round 24)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187829615 (spec 9) | Do not compensate while a Retry member is requeued | Supporting change. The writer gains an explicit `withdraw(member)` for queued, not-yet-executing members, including ones re-queued after `Retry`. It answers `Withdrawn` (known not committed) or `TooLate`. Spec 9 M17 and spec 8 S36 use it | X17 |

### Codex review (PR #1174, round 25)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187931934 | Bound retries after savepoint cleanup failures | Fixed now. A forced whole-transaction rollback after a failed `ROLLBACK TO` or `RELEASE` counts toward `batch_loss_retries`, like an automatic rollback. After that bound, members get `StoreUnavailable` and a store incident is raised, so the batch cannot loop and reconcilers get a final reply | X21 |

### Codex review (PR #1174, round 27)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4188089194 | Align check-only retry advice with the refusal reason | Fixed now. X16 uses spec 9 M11 and M20's reason-specific mapping: `AfterResume` for a stop, `AfterStoreRecovery` for store unavailability, and `retry: Never` guidance for revocation, closure or integrity refusals (round 33 corrects their check-only identity disposition to `Reusable`) | X16 |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-03 (spec 10 side) | A withheld result is incorrectly sufficient authority for zero-charge settlement | Fixed with spec 9 M11a. X16's fence row decides delivery only. It terminalizes as `DeniedAfterDelivery` when no positive reversible-hold obligation remains, and otherwise records `DeliveryRefused` with the hold and journal untouched. Both are restrictive commits, so the drain still terminates | X16; X17b; section 5 restrictive class; section 18 spec 4 row |
| R-9-04 (spec 10 side) | The machine puts contractual capture waivers in the wrong execution phase | Fixed. Only `MutuallyAgreedUnknown` releases an outcome-unknown hold. `ContractualCaptureWaiver` applies only to a known return (spec 9 M7b) | section 19 batch blast radius |
| R-8-03 (spec 10 side) | Unread-journal bypass drops a stopper from the two-person resume predicate | Applied here. Spec 8's new `Reconcile` record joins the priority lane, because resume stays refused until it is anchored | X17a; revision summary |
| R-9-05 (spec 10 side) | Delivery refusal strands a payment whose ordinary capture already completed | Fixed with spec 9 M11a. X16's fence row recognizes a payment journal already `Final` at the `DeniedAfterDelivery` terminal, lets an in-flight intent complete under its original identity before terminalizing, and retains only an `Open` hold. The `Unavailable` row's slow path checks the release before it records a new settlement intent | X16 |

### PR #1174 review round 32

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4197876499 | Recheck integrity before check-only result release | Fixed. X13a runs KnowledgeIntegrity against current release policy, floors and committed state in the writer. Failed integrity withholds bytes with the actual signed reason and terminal retry advice. A new tracking requirement cannot release without its join, and NonDurable effects are never redispatched. The existing checker, receipt owner and no-write budget remain | X13, X13a, X13c; sections 16-18; release-policy race cases |

### PR #1174 review round 33

| Review | Issue | Disposition | Contract |
|---|---|---|---|
| 4198091675 | Type the newly required join refusal | Fixed. A no-write release that cannot record a now-required output join returns InsufficientIntegrity even if the current level satisfies the floor. It withholds output without re-dispatch or Unavailable replanning | X13a; conformance |
| 4198110084 (spec 10 side) | Keep check-only identity truthful | Fixed. Every refused check-only read remains Reusable, including reason-specific retry Never. No row, custody, tombstone or adapter terminal binding is invented | X13a; X16; spec 9 M20 |
| 4198091703 (spec 10 side) | Fence fused operation creation | Fixed. Standalone Begin and fused intent creation check complete derived authority refs against closure fences in the same insertion transaction | X10; spec 4 section 4.1 |

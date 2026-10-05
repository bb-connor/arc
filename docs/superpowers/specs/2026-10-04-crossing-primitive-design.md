# Design: crossing primitive and minimal-commit hot path

- Status: PROPOSED (revision 1, baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
- Date: 2026-10-04
- Scope: one kernel primitive, `CrossingTx`, that executes every point where an effect or a byte leaves Chio custody as one transaction shape in the serving writer; an anchor-before-crossing rule; a fast path that brackets each mediated effect with two crossing commits; group commit; per-domain writer sharding; a receipt log that keeps durable-before-allow while leaving the synchronous path. It changes durability plumbing and commit grouping, not authority semantics.
- Owners: `chio-store-sqlite` (writer loop, savepoint batches, anchor policy, crossing records, receipt staging and mover, sharding), `chio-kernel` (`CrossingTx` plans, crossing inventory, effect execution for spec A), `formal/apalache` (new crossing model), the process host and benchmarks (acceptance)
- Related: `2026-07-12-admission-operation-design.md` ("Corrected invariant", participant model); M: `docs/security/engineering-standard.md` rule 5.1; M: `docs/security/native-restart-safety.md`; `docs/adr/ADR-0013-async-receipt-durability.md`; M: `docs/adr/ADR-0022-store-and-kernel-decomposition.md`; `spec/PROTOCOL.md` section 6
- Citation convention: `M:` = `integration/process-security-m4` at `19df31ad9` (the remote has moved; citations are pinned). `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`. `R:` = #1172 docs. `W:` = the uncommitted recovery worktree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`, line references as of 2026-10-04. `P:` = `feat/process-command-experience-20260924`. `B:` = `origin/wip/bench-results-2026-09-13` (#1163).
- Origin: `docs/research/2026-10-04-chio-kernel-north-star.md` bet 2 (the performance keystone)
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella); `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`, `2026-10-04-durable-stop-epoch-design.md`; `2026-10-04-pure-admission-machine-design.md` (spec A), `2026-10-04-integrity-gated-admission-design.md` (spec C)

## 1. Decision summary

A process-mediated call costs a median of 130 to 357 ms for a tool whose handler runs in about 0.6 ms (M: `sdks/typescript/packages/ai-sdk-process/BENCHMARK.md:175-191`, `:100-117`). The kernel-only allow path costs a p50 of 13.9 ms, of which receipt signing is 0.23 ms (B: `bilateral-admission-components.csv`). The cost is durable commits: eleven authority commits per mediated call, each followed by a rollback-anchor sync, about 40 fsyncs per call at about 2.3 ms each (M: `docs/architecture/AGENT_PROCESS_DIRECTION.md:150-167`). The benchmark notes that going lower "means changing those contracts, which the formal models cover". This design changes them, deliberately and with a model.

Five decisions:

1. **One crossing primitive.** Every crossing (dispatch, native capture, caller start, recovery and semantic capture, output release, P4 artifact release, P5 confined return, issuance) runs as a `CrossingTx`: one transaction in the serving writer that evaluates ordered `CrossingCheck`s (stop epoch, closure fences, revocation and lineage, knowledge integrity, reservations) and writes a crossing record. Specs 3, 4, 8 and C gain one enforcement point instead of one per crossing site.
2. **Anchor before crossing.** The rollback anchor is synced only before a commit that authorizes a crossing, never after every commit. Commits that record internal facts defer their anchor sync to the next crossing or batch boundary. This alone removes most anchor syncs, which are half of today's authority fsyncs.
3. **Two crossing commits per effect.** The pre-effect states (begin, the admission transitions, the budget hold, `DispatchCommitted`) fuse into one **intent commit**. The post-effect states (post-return evaluation, capture, terminal projection, receipt staging) fuse into one **outcome commit**. A side-effecting call keeps one anchor-free **return record** between them, so the admission design's rule that returned bytes are durable before post-return work survives. A read-only call has no intent commit: its dispatch is a check-only crossing that writes nothing and syncs nothing, and its single durable commit is the release, which carries the receipt. That retires defect D1.
4. **Group commit and sharding.** A writer loop batches concurrent crossings into one SQLite transaction with a savepoint per crossing, one WAL fsync and at most one anchor sync per batch. Writers shard per authority domain once cross-shard fences fan out.
5. **Receipts off the synchronous path, not out of durability.** The outcome commit stages the signed receipt in the authority writer, which satisfies durable-before-allow. A mover appends it to the receipt log and its Merkle checkpoints. Receipts are deduplicated at rest by content address, unchanged on the wire.

Targets (section 14): authority commits per side-effecting mediated call from 11 to at most 3, anchor syncs from 11 to at most 2, a process-mediated `read` median from 130 ms to at most 60 ms, and at least 5x the B: sustained-load throughput with concurrent callers.

## 2. Verified current state

### 2.1 Commit inventory (process-mediated, side-effecting, common path)

The benchmark attributes eleven commits: "the operation's begin, three modeled admission transitions, the budget hold and capture, the tool-return record with its three post-return stages, and the terminal projection" (M: `BENCHMARK.md:110-115`). The original per-file trace artifact was not retained (`BENCHMARK.md:76-77`), so phase 0 re-traces before changing anything. The code sites on M::

| Stage | Code | Notes |
|---|---|---|
| Begin (`Prepared`) | `begin_durable_tool_admission` (M: `kernel/admission_coordinator.rs:465`) calling `store.begin` (`:760`) | Operation row and replay key |
| Budget hold, `BudgetAuthorized` | `authorize_durable_budget_hold` (`:1337`) calling `claim_and_authorize_budget_and_commit_admission` (`:1363`; store `admission_operation_store.rs:673`) | Already a joint transaction |
| `ReadyToDispatch`, `DispatchCommitted` | `commit_durable_dispatch` (`:1560`) via `apply_admission_command`; capture variant `capture_and_commit_durable_dispatch` (`:1814`) calling `claim_and_capture_invocation_and_commit_dispatch` (`:1868`; store `:500`) | `DispatchCommitted` precedes handoff |
| Tool-return record (`Finalizing`) | `record_durable_tool_return` (M: `admission_coordinator/terminal.rs:142`) calling `claim_and_record_tool_returned` (`:312`) | Contract: blob, outcome and `DispatchCommitted -> Finalizing` in one fenced commit (M: `tool_outcome.rs:1842-1845`) |
| Post-return stages | `claim_and_begin_post_return_evaluation` (`terminal.rs:1183`), `record_next_pure_result` (`:1301`) over frozen steps `OutputGuard` and `Pricing` (M: `tool_outcome/post_return.rs:7-10`), with mode `Pure` or `ExternalStateful` (`:14-17`) | Three commits on the common path |
| Capture | budget capture of the reported cost | Post-effect |
| Terminal projection | `commit_admission_projection` (`admission_coordinator.rs:1801`; store `admission_operation_store/projection.rs:1593`) | One typed receipt-side transaction (admission rule 5) |

Every write runs `begin_write` (IMMEDIATE transaction, `verify_active_owner`, `verify_authority_anchor`; M: `crates/platform/chio-store-sqlite/src/admission_operation_store.rs:350-363`), then `commit_write` (`:374-383`, which poisons the owner on an unknown commit outcome), then `sync_after_write` (`:365-372`), which calls `sync_authority_anchor` (M: `serving_owner.rs:269-292`) and `RollbackAnchor::sync_after_commit` (M: `serving_owner/rollback_anchor.rs:257-276`). The store runs WAL with `synchronous = FULL` (M: `admission_operation_store/part_01.inc:99-100`), so each commit is one WAL fsync and each anchor sync is one more.

### 2.2 Writers and stores

| Store | Writer | On the call path |
|---|---|---|
| `authority.db`: admission operations, tool outcomes, budgets, payment journal, approvals and nonces as operation-owned ledgers | The admission serving writer | Every commit above |
| `receipts.db`: the receipt log (`chio_tool_receipts` with `raw_json`, M: `receipt_store/bootstrap/open.rs:621-655`) | Separate SQLite writer | One append per call (39 fsyncs per 33 calls in the trace, `BENCHMARK.md:91-92`) |
| `process.db`: process journal, call slots, checkpoints, blobs | Separate writer (M: `chio-cli/src/cli/process_host/provision.rs:211`) | The call slot commits before the kernel call (M: `chio-process/ARCHITECTURE.md:40-45`) |
| Remote budget stores, payment rails, external stateful evaluators | External | Saga participants, never in one transaction |

The process host checkpoints these files separately (M: `process_host/relocation.rs:26`).

### 2.3 Crossing check sites today

- Stop: an in-memory flag at about eleven sites, outside any writer transaction (`2026-10-04-durable-stop-epoch-design.md` section 2).
- Closure fences: proposed inside the `DispatchCommitted` CAS (`2026-10-04-authority-space-teardown-design.md` section 4.1), with named release crossings in its section 4.3.
- Recovery: a same-writer tombstone checked at begin and capture (W: `admission_operation_store/recovery/native.rs:286-293`).
- P4: the knowledge join and `ReleaseIntent` commit before sink I/O (W: `docs/architecture/recoverable-agent-runtime/implementation/p4/OPERATIONS.md:98-106`).
- P5: the final serialized activity read before sink I/O (W: `crates/platform/chio-control-plane/src/confinement.rs:234-236`).
- Pre-dispatch guard revalidation: check-then-act at M: `kernel/dispatch.rs:806`.

Each site encodes its own ordering. None shares a transaction shape.

### 2.4 Receipts and logs

- Receipts are signed per call with Ed25519 (0.23 ms) and appended to `receipts.db` (append p50 4.7 ms, B:). The store grew 41 MB over 3,543 calls, about 11.9 KB per call (B: `bilateral-admission-sustained-load.json`).
- Chio already has an RFC 6962 Merkle tree (M: `crates/core/chio-core-types/src/merkle.rs:1-9`) and Merkle-batch checkpoint statements with inclusion proofs, witnesses and equivocation records (M: `crates/kernel/chio-kernel/src/checkpoint.rs:1-7`, `:38-51`).
- ADR-0013 keeps durable-before-allow as the default and allows async receipt durability only behind a durable local WAL (`docs/adr/ADR-0013-async-receipt-durability.md`, "Decision").

### 2.5 Formal coverage

There is no Apalache model of the admission saga's commit sequence. The relevant models are `ReceiptBeforeAllow.tla` (receipt persistence and allow publication as separate actions), `PostAdmissionDropGuard.tla`, `KernelTransitionCancelSafe.tla`, `MonotoneLogApalache.tla` and `RevocationCutCompleteness.tla` (M: `formal/apalache/`). The admission design's recovery truth table is prose.

### 2.6 Baselines

| Measure | Value | Source |
|---|---|---|
| Authority commits per mediated call | 11 | M: `BENCHMARK.md:110-115` |
| fsyncs per mediated call | about 40 (from about 85) | M: `AGENT_PROCESS_DIRECTION.md:150-167` |
| fsync cost | about 2.3 ms | M: `BENCHMARK.md:96-98` |
| Process-mediated `read` median / p95 | 130 ms / 161 ms (latest in the series) | M: `BENCHMARK.md:108-110` |
| Kernel-only allow p50 / p99 | 13.9 ms / 26.2 ms | B: `bilateral-admission-components.csv` |
| Sustained load | 59.0 calls/s over 60 s | B: `bilateral-admission-sustained-load.json` |

## 3. Goals and non-goals

Goals:
- One transaction shape for every crossing, carrying every crossing check.
- Fewer durable commits and anchor syncs per call without weakening any admission invariant.
- Throughput that scales with concurrent callers.
- Receipts stay durable before allow, verifiable as today, and smaller at rest.

Non-goals:
- Changing authority semantics, verdicts or receipt wire format.
- Cross-database atomicity. Cross-store participants stay saga participants.
- Removing per-receipt signatures (section 11.4).
- Changing the process journal's ownership of call slots in v1 (open decision 2).

## 4. The crossing primitive

### 4.1 Shape

```rust
pub enum CrossingKind {
    DispatchIntent,      // side-effecting dispatch: the intent commit
    CheckOnlyDispatch,   // read-only dispatch: no writes, no fsync
    CallerStart,         // M: authenticated caller-execution start
    NativeCapture,
    RecoveryCapture,     // W: recovery continuation capture
    SemanticCapture,     // W: P3 semantic remedy capture
    OutputRelease,       // the outcome commit; also records the output influence join (spec C, rule I4)
    ArtifactRelease,     // W: P4 knowledge join + ReleaseIntent
    ConfinedReturn,      // W: P5 return admission
    Issuance,            // capability issuance (defense in depth, spec 8 S8)
}

pub enum CrossingCheck {
    StopEpoch,           // spec 8 tier 2
    ClosureFence,        // spec 4 section 4.1
    Revocation,          // chain walk; capability lineage where installed
    KnowledgeIntegrity,  // spec C, authoritative check
    Reservations,        // spec 3: Compensable and Commitment entries
    Record,              // the crossing record
}

pub struct CrossingTx<'b> {
    batch: &'b mut WriterBatch,       // savepoint-scoped slot in the writer's batch
    kind: CrossingKind,
    scopes: CrossingScopes,           // tenant, lineage, session, process, recovery scope
    mutations: CrossingMutations,     // from spec A's IntentCommitPlan / OutcomeCommitPlan
}

impl CrossingTx<'_> {
    /// Runs every applicable check in order, then the mutations, then the record.
    /// A refusal rolls back this crossing's savepoint only.
    pub fn execute(self) -> Result<CrossingCommitted, CrossingRefused>;
}
```

`CrossingCommitted` is acknowledged to its caller only after the batch commits and, for anchor-requiring kinds, after the anchor sync (section 5). `CrossingRefused` carries a typed reason and leaves no state. The reasons are `KernelStopped`, `AuthoritySpaceClosed`, `Revoked`, `InsufficientIntegrity` and `ReservationConflict`, plus two reasons that are not policy refusals:
- `VersionConflict`: the planned CAS saw a different operation version (X5).
- `Unavailable`: the fast-path preconditions do not hold, for example a participant outside the admission writer. The driver then falls back to the slow path (section 7), and spec A's machine emits `ParticipantCommit` steps.

Spec A receives all seven as `CommitFailed { reason }`.

### 4.2 Checks per kind

| Kind | Stop | Fence | Revocation | Integrity | Reservations | Anchor before ack |
|---|---|---|---|---|---|---|
| `DispatchIntent` | yes | yes | yes | yes | hold, slot attach | yes |
| `CheckOnlyDispatch` | yes | yes | yes | yes | none | no (nothing written) |
| `CallerStart` | yes | yes | yes | yes | capture before effect | yes |
| `NativeCapture` | yes | yes | yes | yes | capture | yes |
| `RecoveryCapture`, `SemanticCapture` | yes | yes | yes | yes | recovery consumption | yes |
| `OutputRelease` | yes | yes | no (effect happened) | yes, for release | capture, release authority | yes |
| `ArtifactRelease` | yes | yes | no | P4 join is the check | pin, release intent | yes |
| `ConfinedReturn` | yes | yes | no | P5 return contract | confined consumption | yes |
| `Issuance` | yes | no | parent chain | no | issuance reservation | yes |

Rules:

1. **X1. One shape.** Every crossing in section 4.2 is a `CrossingTx`. A new crossing kind needs a row, a spec 4 section 4.3 entry, and a spec 1 registry entry before it ships.
2. **X2. Order.** Checks run in the order of `CrossingCheck`, before any mutation. The first refusal ends the crossing. The order puts the cheapest, broadest denial first and keeps mutations out of refused crossings.
3. **X3. Same writer.** A check is authoritative only when its state lives in the writer that runs the crossing. A check whose state lives elsewhere (a remote revocation backend, issuance in the capability authority store) runs as an early read and is reported as `early_only` (spec 8 section 13).
4. **X4. Record.** `crossing_records(crossing_id, kind, operation_id, scope_digest, checks_digest, batch_index)` is written last in the same savepoint. It is the join key for audit, DST properties and hints. It is operational, not signed evidence.
5. **X5. Spec A boundary.** `CrossingTx` executes what spec A's `Effect::IntentCommit` and `Effect::OutcomeCommit` plan. It never decides an admission transition. It applies the planned CAS and refuses on a version mismatch.

## 5. Anchor before crossing

The rollback anchor detects a database restored behind its last anchored state. Today it is synced after every authority commit.

6. **X6. Anchor before crossing.** A commit that authorizes a crossing is acknowledged only after the anchor record covering it is durable. A commit that only records internal facts (the return record, a parked state, a staged projection) does not sync the anchor; its coverage arrives with the next anchored commit.
7. **X7. Why it is safe.** A database rolled back past an unanchored internal commit loses only facts that authorized nothing outside Chio. Recovery then sees an earlier state and takes the conservative branch (for a lost return record, `DispatchCommitted` becomes `OutcomeUnknownAfterDispatch`, holds frozen). A rollback past an anchored crossing commit is detected exactly as today.
8. **X8. Companions.** Read companions already accept a database state that extends the anchor (M: `serving_owner.rs:200-217`), so a lagging anchor needs no reader change.

## 6. Fast paths

### 6.1 Side-effecting call: intent, return, outcome

```text
evaluate (pure core + guards + revalidation reads; no writes)
  -> intent commit   [DispatchIntent CrossingTx; WAL fsync + anchor sync]
       begin + BudgetAuthorized(hold) + ReadyToDispatch + DispatchCommitted
  -> handoff to the tool
  -> return record   [WAL fsync only; X6]
       blob + outcome + DispatchCommitted -> Finalizing   (contract M: tool_outcome.rs:1842-1845)
  -> pure post-return evaluation in memory (OutputGuard, Pricing)
  -> outcome commit  [OutputRelease CrossingTx; WAL fsync + anchor sync]
       evaluation results + capture + terminal projection + receipt staging
  -> allow returned
```

Preconditions for the fused intent commit, all evaluated during planning:
- every pre-effect participant lives in the admission writer (budget hold, payment journal entry, approval and nonce ledgers);
- no approval is pending (`ApprovalRequired` takes the slow path);
- no participant needs an external authorization before dispatch;
- the call is not caller-executed.

Preconditions for the fused outcome commit: every frozen post-return step has mode `Pure` (M: `post_return.rs:14-17`), and capture needs no external rail.

Rules:

9. **X9. No intermediate pre-effect state.** On the fast path the operation row, the replay key, the hold and `DispatchCommitted` become durable together. A crash before the intent commit leaves nothing to compensate. A deny decided during evaluation writes only its deny receipt.
10. **X10. Return record kept.** The return record stays a separate commit for side-effecting calls, so returned bytes are durable before post-return work, as the admission design requires. It costs one WAL fsync and no anchor sync (X6).

### 6.2 Read-only call: check-only dispatch, one release commit

Read-only calls skip durable admission under the default `SideEffecting` mode today, and can execute with no receipt (defect D1). They get their own path:

11. **X11. Check-only dispatch.** Before handoff, the kernel runs a `CheckOnlyDispatch` crossing: an IMMEDIATE transaction that evaluates stop, fence, revocation and integrity, writes nothing and commits without a WAL write or fsync. It linearizes with every committed stop, fence and revocation, because it takes the write lock. Arguments that leave custody at dispatch are therefore covered.
12. **X12. One durable commit.** After the tool returns, one `OutputRelease` crossing commits the receipt, the release decision and any capture. Output is released only after that commit and its anchor sync. If the commit fails, output is withheld and spec 3's obligation and latch apply.
13. **X13. Retry.** A crash between handoff and the release commit leaves no durable trace. Read-only tools already earn a bounded fresh dispatch on unknown outcomes (M: `AGENT_PROCESS_DIRECTION.md:155-160`), so this is the existing contract.

## 7. Slow paths keep their semantics

| Path | Commits | What changes |
|---|---|---|
| Approval parking | park commit (`Prepared -> ApprovalRequired` with hold, no anchor), then one resume intent commit (`ApprovalReserved -> ReadyToDispatch -> DispatchCommitted`) | Fewer commits after resume; parking semantics unchanged |
| Cross-store participant (remote budget, payment rail authorization) | prepare commit (operation row + payment journal intent; persisted before the external call, as the participant model requires), external authorization, then the intent commit | The intent commit still carries every crossing check |
| Caller execution (M3) | reserve (no permission), authenticated start (`CallerStart` crossing, capture before the effect), authenticated report (outcome commit) | Start and report become `CrossingTx` instances; the protocol is unchanged |
| Recovery continuation | `reserve_recovery_call` in `process.db` (W:), then the continuation's own fast path with `RecoveryCapture` checks | The tombstone check moves into the crossing's check list |
| External stateful post-return step | return record, the external step under its existing journal, then the outcome commit | Unchanged ordering |
| Economic mutation | unchanged | Not a tool crossing |

## 8. Invariants preserved

The admission design's rules (`2026-07-12-admission-operation-design.md`, "Corrected invariant"):

| Rule | Status under this design |
|---|---|
| 1. `Prepared` commits before the first participant mutation | Strengthened: on the fast path they commit atomically; on slow paths `Prepared` commits first as today |
| 2. Participants keyed by `operation_id` | Unchanged |
| 3. `DispatchCommitted` before any handoff | Unchanged: the intent commit, anchored, precedes handoff |
| 4. Terminal tombstones retained | Unchanged |
| 5. Receipt-side projections in one typed transaction | Unchanged: the outcome commit is that transaction |
| 6. Holds released only by named release authority | Unchanged |

Engineering standard rule 5.1, "durable intent precedes the effect; unknown stays unknown", holds by X6 and X9.

```text
handoff(op) -> durable(intent_commit(op)) and anchored(intent_commit(op))
release(op) -> durable(outcome_commit(op)) and anchored(outcome_commit(op))
publish_allow(op) -> staged_receipt(op) in outcome_commit(op)          (refines ReceiptBeforeAllow)
committed(fence or stop for scope s) before cas(op) and s in scopes(op) -> not crossed(op)
refused(c) -> state_after(batch) restricted to c = state_before(batch) restricted to c
crash at any cutpoint -> recover(op) in {absent, DispatchCommitted, Finalizing, Completed, parked}
```

## 9. Group commit

14. **X14. Writer loop.** One writer task owns the admission connection. Crossings enqueue with a reply handle. The loop takes the queue head and every request already queued (up to `max_batch`, default 64), opens one IMMEDIATE transaction, and runs each crossing inside its own `SAVEPOINT` (SQLite savepoints nest inside a transaction). A refused crossing rolls back to its savepoint. Then one `COMMIT` (one WAL fsync), one anchor sync if any member needs it (X6), and replies to every member.
15. **X15. No added latency at low load.** The loop never waits to fill a batch. With an empty queue a single crossing commits immediately, so concurrency-1 latency is unchanged by batching. Batches form only under contention.
16. **X16. Linearization.** Crossings within a batch execute serially in queue order, each seeing the effects of the ones before it. The batch is equivalent to that serial order, so every CAS keeps its meaning.
17. **X17. Fairness.** Queue order is FIFO, with a per-tenant cap of a quarter of a contended batch, so one tenant's burst cannot fill every batch.
18. **X18. Blast radius.** A `COMMIT` whose outcome is unknown poisons the serving owner, as `commit_write` does today, and every member of the batch is reported outcome-unknown and reconciled at restart. Check-only crossings ride batches without writes.

## 10. Writer sharding

ADR-0022 names the single-writer ceiling (M: `ADR-0022-store-and-kernel-decomposition.md:9-13`).

19. **X19. Shard key.** A shard is an authority domain: a tenant within a serving authority. Each shard has its own database, serving owner, rollback anchor, global commit chain, crossing records and receipt staging.
20. **X20. What must stay in one writer.** One operation's saga, its replay key, its budget family, and its process tree. A budget family or shared pool never spans shards. Cross-tenant pools stay unsharded in a pool shard and take the slow path.
21. **X21. Global state fans out.** Kernel-scope stop heads and revocations of capabilities used across shards are written as fence rows into every shard (one commit per shard). The operator acknowledgement completes only after every shard reads them back, the AP8 discipline (M: `docs/superpowers/specs/2026-10-03-transport-revocation-design.md`). Until then the status reports the unfenced shards.
22. **X22. No cross-shard transaction.** Crossings read only their own shard (X3). ATTACH across WAL databases is not used, as the admission design already requires.

## 11. Receipt log

### 11.1 Staging in the outcome commit

The outcome commit writes the signed receipt into `crossing_receipts` in the authority writer. Allow is returned after that commit, so durable-before-allow holds: the receipt is signed and committed to a configured durable store before allow. This amends ADR-0013's wording, not its rule.

### 11.2 Mover

A mover appends staged receipts to the receipt log in staging order, assigns the log sequence, folds them into Merkle checkpoint batches (M: `checkpoint.rs`), and deletes the staging row only after the log commit. A receipt is audit-complete when it is in the log and covered by a checkpoint. Until then status reports it `staged`, ADR-0013's `signed_but_not_durable` made stronger, because the staging row is itself durable.

### 11.3 Slim at rest, identical on the wire

The receipt store deduplicates large repeated substructures, such as capability snapshots, delegation chains, policy and manifest bodies, into a content table keyed by digest. It reconstitutes `raw_json` byte-exactly on read, so signatures verify unchanged. Phase 0 attributes the 11.9 KB per call before choosing what to deduplicate. The receipt wire format and verifier are unchanged.

### 11.4 Signatures and checkpoints

Per-receipt Ed25519 signatures stay. They cost 0.23 ms and existing verifiers depend on them. Merkle batching already exists at the checkpoint layer. The mover aligns checkpoint batches with group-commit batches and emits C2SP-compatible checkpoint notes (north-star bet 6), so public witnesses can cosign.

## 12. Formal model

A new `formal/apalache/AdmissionCrossing.tla` models one or two operations, the durable store, the anchor, batches with savepoints, crashes at every cutpoint, and recovery.

Invariants:
- handoff only after an anchored intent commit;
- release only after an anchored outcome commit;
- allow only after receipt staging, refining `ReceiptBeforeAllow`;
- no crossing after a committed fence or stop in its scope;
- no hold release outside named release authorities;
- savepoint isolation for refused crossings;
- recovery reaches only `{absent, DispatchCommitted, Finalizing, Completed, parked}`.

Refinement mappings to `PostAdmissionDropGuard.tla` and `KernelTransitionCancelSafe.tla`: pre-dispatch cancellation now leaves no durable state on the fast path.

Negative mutants:
- acknowledge before the anchor sync;
- publish allow before the outcome commit;
- reply to batch members before `COMMIT`;
- skip the fence check in a fused intent commit.

The model lands before phase 3 (section 16).

## 13. Failure modes and crash cutpoints

These extend M: `native-restart-safety.md`'s matrix:

| Cutpoint | Durable state | Recovery |
|---|---|---|
| C1. Before the intent commit | nothing | none; the caller retries |
| C2. Intent committed, anchor not synced | `DispatchCommitted`, unanchored; no handoff (X6) | as today: possibly dispatched, outcome unknown, holds frozen |
| C3. After handoff, before the return record | `DispatchCommitted` | unknown, as today |
| C4. Return record committed | `Finalizing` | re-run pure post-return evaluation from frozen steps |
| C5. Outcome committed, anchor not synced | `Completed`, unanchored; output not released | replay returns the recorded outcome |
| C6. After release | `Completed` | replay |
| B1. Batch `COMMIT` outcome unknown | unknown for every member | owner poisoned; restart reconciles each member |
| R1. Staged receipt not yet moved | staging row | mover resumes; status `staged` |

Other failures:
- A refused crossing returns its typed reason with no state change.
- A writer queue at capacity refuses new crossings with `Overloaded` before any write.
- A shard whose fence fan-out is incomplete reports `unfenced` and keeps the operator stop or closure pending (X21).

## 14. Acceptance targets

Measured with the existing benchmarks on the same machine class as their baselines. The commit and anchor counts are deterministic gates; latency and throughput are reported.

| Measure | Baseline | Target |
|---|---|---|
| Authority commits per side-effecting mediated call | 11 | at most 3 (intent, return, outcome) |
| Anchor syncs per side-effecting call | 11 | at most 2 |
| Durable commits per read-only call | 0 (no receipt, D1) | exactly 1, with receipt |
| Host-observed fsyncs per mediated call (steady scenario, excluding setup) | about 40 | at most 12 |
| Process-mediated `read` median / p95 | 130 / 161 ms | at most 60 / 90 ms |
| Kernel-only allow p50 | 13.9 ms | at most 7 ms |
| Sustained throughput (B: harness, at least 8 concurrent callers) | 59 calls/s | at least 300 calls/s |
| Receipt bytes at rest per call | about 11.9 KB | at most 3 KB |

The latency targets are estimates (fsync count times about 2.3 ms, plus measured non-fsync time) and are confirmed in phase 0.

## 15. Protocol, schema and wire impact

- **Native wire, verdicts, receipt format.** None.
- **`spec/PROTOCOL.md` section 6.** Durable-before-allow is satisfied by receipt staging in the authority writer. A receipt's audit-complete state is reached when the log and a checkpoint cover it.
- **ADR-0013.** Amended wording (section 11.1).
- **Store schema.** New `crossing_records`, `crossing_receipts` and the receipt content table. Fence and stop tables belong to specs 4 and 8.
- **Formal.** The new model and its manifest entries.

## 16. Rollout

Every phase ships behind its own flag (`crossing-anchor-policy`, `crossing-primitive`, `crossing-fusion`, `group-commit`, `sharded-writer`). The commit-count gates must pass before a flag defaults on.

0. **Measure.** Re-trace fsyncs per call and retain the artifact. Attribute receipt bytes. Land the Apalache model and its mutants.
1. **Anchor before crossing (X6).** The largest single saving with the smallest change: anchor syncs drop from 11 to about 2 per call.
2. **`CrossingTx` for existing crossings.** Wrap `DispatchCommitted` and output release, moving the stop, fence and revocation checks inside, with crossing records. No fusion yet.
3. **Fusion.** The intent commit, then the read-only check-only dispatch and one-commit release (retires D1), then the outcome commit with receipt staging and the mover.
4. **Group commit.**
5. **Sharding**, after the fan-out fences exist.

## 17. Tests and conformance evidence

- **Apalache:** the model and mutants of section 12.
- **Loom:** batch leader and followers; savepoint isolation of a refused crossing; acknowledgement strictly after `COMMIT` and anchor sync; a stop commit racing a fused intent commit.
- **DST:** crash injection at C1-C6 and B1 under random workloads. Properties are section 8's predicates.
- **Differential:** generated workloads run through the legacy and fused paths must reach identical terminal states, receipts and release decisions.
- **Commit-budget gates (deterministic):** a store hook counts commits and anchor syncs per call. CI fails above 3 commits and 2 anchor syncs for side-effecting calls, or above 1 commit for read-only calls.
- **Benchmarks:** the process-mediated and kernel-only harnesses report the latency and throughput rows of section 14 per run.
- **chio-conformance:** a read-only call always yields a receipt; a stop committed before a dispatch denies it; a crash after handoff yields outcome-unknown, never redispatch for side-effecting tools.

## 18. Alignment with specs A and C, and with specs 3, 4 and 8

- **Spec A** must include, in its effect vocabulary: `IntentCommit(IntentCommitPlan)`, `ReturnRecord(ReturnRecordPlan)` (anchor-free), `OutcomeCommit(OutcomeCommitPlan)`, `CheckOnlyCrossing` for read-only dispatch, and slow-path effects for park, prepare (cross-store) and caller start and report. A plan carries the expected operation version for the CAS (X5).
- **Spec C** owns the semantics of `CrossingCheck::KnowledgeIntegrity`. This spec only guarantees that it runs inside the intent commit and the check-only dispatch, after revocation and before reservations.
- **Spec 3**'s `PostEffectDischarge` is produced by the outcome commit; its `Commitment` entries are written by the `Reservations` check.
- **Spec 4**'s dispatch-commit fence is the `ClosureFence` check; its crossing table is this spec's inventory.
- **Spec 8**'s tier-2 check is the `StopEpoch` check.

## 19. Residual risks and open decisions

Residual risks:
- Group commit widens the blast radius of one unknown commit outcome to a batch (X18).
- fsync cost varies by platform; the latency targets need re-baselining per platform.
- Check-only dispatch takes the write lock and can queue behind long batches under heavy write load. Batching check-only crossings with writers bounds it.
- Content-addressed receipt bodies make byte-exact reconstitution a correctness requirement. A differential verifier test guards it.

Open decisions:
1. **Return record for side-effecting calls.** Keep it (this draft, three commits), or fuse it into the outcome commit for a two-commit path and accept a wider unknown window during pure post-return evaluation.
2. **Process call slot.** Co-locate the `process.db` call-slot commit with the authority writer, saving one fsync per call, at the cost of moving journal ownership.
3. **Receipt staging location.** The authority writer (this draft), or ADR-0013's separate local WAL.
4. **Shard key.** Tenant or authority domain, and how cross-tenant pools are served.
5. **Batch policy defaults.** `max_batch` and the per-tenant cap.
6. **Signature elision.** Whether receipts could later rely on checkpoint inclusion proofs instead of per-receipt signatures. This would be a receipt contract change, and is not proposed.

## Appendix A. Precedent

- **FTL.** One trap entry decides every system call path (FTL `kernel/src/arch/x64/syscall.rs:65`), and `ReserveSlot` reserves before an infallible commit (FTL `libs/ftl_utils/src/reserve_slot.rs`). `CrossingTx` is the single entry for every custody crossing, with reservations committed in its last step.
- **Group commit** batches the log flushes of many transactions into one, a technique from main-memory database work in the 1980s and standard in PostgreSQL and MySQL. SQLite supports it through one transaction with nested savepoints ([SAVEPOINT](https://www.sqlite.org/lang_savepoint.html), [WAL](https://www.sqlite.org/wal.html)).
- **Certificate Transparency** batches log entries under signed tree heads with inclusion proofs ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962)). Chio's checkpoint layer already does this; section 11.4 aligns its batches with group commit.

Where the analogy breaks: FTL commits nothing durably and has no restart contract. Every Chio crossing must survive a crash at any cutpoint with an outcome the recovery table names, which is why the anchor rule, the return record and the cutpoint matrix exist.

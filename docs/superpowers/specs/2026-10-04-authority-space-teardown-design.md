# Design: closing authority spaces (the closure rule for capabilities, sessions, processes, swarms, and delegated work)

- Status: PROPOSED (revision 4, 2026-10-05, after PR #1174 review round 1; revision 3 re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:))
- Date: 2026-10-04
- Scope: the non-additive closure operation that Chio's additive composition rules leave undefined. It covers:
  - one shared drain for admitted work;
  - fences at linearization points;
  - a terminal, manual, durable closure record per space kind (capability subtree, hosted session, process tree, swarm graph, D1 delegation root);
  - funded-work invariants;
  - stranded-capacity accounting.

  It adds no reversible containment, no reclamation and no new revocation semantics.
- Owners:
  - `chio-kernel`: drain, dispatch-commit fence, process-liveness guard.
  - `chio-store-sqlite`: closure records, fence rows, authority refs.
  - `chio-workflow`: D1 root fence.
  - `chio-runtime-core`: swarm tombstone.
  - `chio-security-kernel`: overlay revalidation.
  - `chio-process`: process trigger.
  - `chio-control-plane` and `chio-mcp-remote`: close routes.
  - `chio-core-types`: closure artifact.
- Related:
  - Security and admission: `2026-07-12-admission-operation-design.md`; M: `2026-09-07-caller-dispatch-commitment-design.md`; M: `2026-10-03-transport-revocation-design.md` (AP8); M: `docs/security/engineering-standard.md` rules 5.5 and 5.6; M: `docs/security/active-defense-rollout.md`.
  - Verifiable work: V: `2026-10-02-dynamic-delegation-design.md` (D1); V: `2026-10-02-sovereign-swarm-evolution-design.md` (S1); V: `docs/papers/verifiable-work/PROTOCOL.md` (F1); V: `2026-10-03-work-runtime-design.md` (W1).
  - Recovery: R: `docs/architecture/recoverable-agent-runtime/08-protocol-operations.md`.
  - Protocol: `spec/PROTOCOL.md` section 5.3 rule 5 and section 8.3.
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`
- Citation convention:
  - M: = `origin/integration/process-security-m4` at `19df31ad9`.
  - V: = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - R: = `origin/research/openappa-recovery-20261001` at `de84fc306` (PR #1172).
  - W: = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002` (branch `feat/recoverable-agent-runtime-20261002`; recovery P0-P5 implemented locally; built on #1160 checkpoint `f25cd61f4`). Line references reflect the working tree on 2026-10-04 and may drift.
  - All four are treated as shipped.
  - V: W1-W4 APIs have no code and are cited as "assumed shipped (contract anchor)". Recovery documents that describe something absent from W: are marked "doc-only, not implemented in W:". Integration must pin the landed signatures.

## Revision 4 changes

From round 1 of the PR #1174 review (dispositions at the end of this spec):
- **Output release is fenced.** The caller-executed and native output-release checks, and the finalization commit of ordinary durable returns, now consult the closure fence (rule 3a and the section 4.3 table). A closure that commits after `DispatchCommitted` but before release now withholds the output. The operation then terminalizes as `DeniedAfterDelivery`, as in spec 9 M11 and spec 10 X16. (Independent review pass 5 adds spec 9 M11a: a positive-cost refused return instead keeps its hold in `Finalizing(DeliveryRefused)`, because closure is not pricing authority.)
- **Pre-migration operations are fenced.** A migration backfills and verifies authority refs. Any operation it cannot index stays `legacy_unindexed`, and a legacy predicate in the dispatch and release CAS refuses it once any closure fence exists (rule 1a).
- **Stranded capacity has two snapshots.** One is taken at `Fenced` and one after the drain. The signed `Closed` artifact carries the final one (section 8).

## Revision 3 changes

- **Recovery withdrawal uses `CancelWorkflow`.** "Emergency revocation invalidates pending approvals" (R: `08-protocol-operations.md:57`) is doc-only and not implemented in W:. Section 6.5 now has an operator-assigned closure actor issue `CancelWorkflow` for each recovery workflow bound to the space. It relies on the fresh revocation of the seed capability at capture.
- **The section 4.1 fence already ships in W:.** Recovery's same-writer cancellation tombstone is consulted by both begin and capture (W: `crates/platform/chio-store-sqlite/src/admission_operation_store/recovery/native.rs:286-293`). Section 4.1 cites it, and the R: cancellation rule is no longer only a contract anchor.
- **The drain classifier unifies three sites:** startup reconciliation, recovery's `reconcile_recovery_original` (W: `crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery_runtime.rs:184-240`), and this drain. Section 5 rule 1 records where they differ.
- **New closure members.**
  - Recovery workflows, including `Quarantined` ones.
  - P5 confined children. The drain calls `NativeConfinedRuntime::cancel`, which commits the native disposition and then the process cancel (W: `crates/platform/chio-control-plane/src/confinement.rs:258-274`).
  - P5's return-admission commit (`store.admit_confined_return`, `:214-226`; spec 10 `ConfinedReturn`) is the stop and fence linearization point beside `DispatchCommitted`. The final journal activity read (`:234-236`) stays the cancellation ordering point only, because it is a process-journal read outside the admission writer (section 4.3).
- **Knowledge invariants.** Closure clears no knowledge, removes no pin, and leaves uncertain releases pinned (section 7). Confined-child reservations join stranded accounting (section 8).
- **Durable stop precedent.** The scoped semantic emergency stop is persisted and checked inside capture transactions (W: `crates/platform/chio-store-sqlite/src/admission_operation_store/semantic.rs:355-372`; `semantic/capture.rs:47`, `:294`, `:336`). Open decision 5 cites it.

## Revision 2 changes

- **Rescoped as the closure rule.** The rule is the one the verifiable-work paper leaves open: "removing tasks, reclaiming their budgets, migrating receivers or changing the graph's policy limits would require closure or fencing rules beyond this operation" (V: `docs/papers/verifiable-work/sections/08-limits.tex:5-6`).
- **New kinds.**
  - Added `DelegationRoot` (D1). It fences unsealed slots and retains sealed capacity.
  - Added a `SwarmGraph` extension fence in `extend_swarm_authority_bundle`, in addition to the consumption check.
- **Funded and delegated work.**
  - Added section 7, which states the funded and delegated work invariants verbatim from their sources.
  - Added section 8, stranded-capacity accounting.
- **Linearization.**
  - Added a fence checked inside the durable `DispatchCommitted` transaction. This follows the recovery lane's cancellation linearization.
  - Added a deny-only, dispatch-revalidating process-liveness guard.
- **Reuse instead of new protocol.**
  - Hosted MCP session closure now reuses AP8 session-wide revocation (write plus readback) instead of a new `pending` protocol. On that surface, session closure does revoke.
  - The drain classifier is the startup recovery classifier, parameterized by cause (engineering-standard rule 5.6).
  - The closure record is the durable cancellation outcome (rule 5.5).
  - Pending recovery approvals are withdrawn through R:'s emergency-revocation transition.
- **New triggers.** Added triggers for R: `CancelWorkflow`, W1 `Cancel`, and worker self-cancel.
- **Added a proposed composition lemma** for the paper (section 11).
- **Dropped.**
  - The `GovernedResponseEffect::CloseAuthoritySpace` option. "Permanent revocation remains manual" (M: `docs/security/active-defense-rollout.md:23`).
  - All "after B: merges" sequencing.
- **Citations.** Re-pinned to M:/V:/R:.

## 1. Decision summary

Chio has many cuts, and none of them reaches admitted work:
- A capability revocation cuts every descendant at check time. It walks the leaf and each ancestor link (M: `crates/kernel/chio-kernel/src/kernel/validation.rs:609`, `kernel/delegation.rs:76-84`), and is model-checked in M: `formal/apalache/RevocationCutCompleteness.tla`.
- Process cancel is terminal and subtree-wide, but it "does not fence a call already admitted by the process journal" (M: `crates/kernel/chio-process/ARCHITECTURE.md:86-87`).
- Active-defense overlays deny new evaluations. Their guards do not opt into dispatch revalidation (M: `kernel/mod.rs:882-884` default `false`; no override in M: `crates/security/chio-security-kernel/src/containment.rs:72`, `capability_set_suspension.rs:41`).

The verifiable-work layer is additive by design:
- **D1** has "deliberately no reset, timeout refund, untrusted absence report or release of sealed allocations" (V: `dynamic-delegation-design.md:86-87`).
- **S1** extension "does not retire old permissions or reclaim their budgets" (V: `sovereign-swarm-evolution-design.md:92-93`).
- **W1** `Cancel` "does not reclaim D1 budget, erase history, refund earned work or establish absence of an effect" (V: `work-runtime-design.md:83`).
- The beta places "budget reclamation" out of scope (V: `2026-10-03-agentic-work-kernel-design.md:131`).

So there is no defined way to stop a space and account for what remains.

Decision:

1. **Fences at linearization points.**
   - A closure fence is checked inside the same transaction that commits `DispatchCommitted` for a durable operation. A deny-only, dispatch-revalidating guard covers process liveness and the two overlay guards. A fence that commits before the dispatch commit forbids dispatch, and a dispatch that commits first is post-dispatch.
   - The ordering rule is R:'s cancellation rule: "If capture wins the race, cancellation retains the operation for reconciliation; if cancellation wins, no later capture is authorized" (R: `08-protocol-operations.md:21`). W: implements it for recovery workflows with a tombstone in the same writer that both begin and capture consult (W: `admission_operation_store/recovery/native.rs:286-293`).
2. **One drain.** `AdmittedWorkDrain` classifies each affected durable operation with the startup recovery classifier, parameterized by cause `authority-cut`. It uses only transitions that already exist. It never releases a hold outside a named release authority and never recalls a dispatched effect.
3. **Terminal closure record.** The record composes existing fences per kind, the drain, withdrawals, exit hints and a signed artifact that includes stranded-capacity accounting. Closure is manual: an operator or a delegator/holder within their own subtree, never an automatic response effect.
4. **Funded-work invariants.** These are stated verbatim (section 7). Closure never touches an earned claim, never accelerates a refund, and never releases a sealed allocation.

Revocation, the existing fences and the existing saga remain the only safety mechanisms. Enumeration of affected work is evidence, never authority.

## 2. Verified current state

| Surface | Current behavior | Evidence |
|---|---|---|
| Subtree cut | Leaf plus every chain link checked | M: `kernel/validation.rs:609`; `kernel/delegation.rs:76-84`; `formal/apalache/RevocationCutCompleteness.tla` |
| Pre-dispatch re-check | Emergency flag, live authority, then guards with opt-in revalidation; check-then-act | M: `kernel/dispatch.rs:692-712`, `:806`, `:826-843` |
| Durable dispatch commit | CAS to `DispatchCommitted`, with a combined capture variant | M: `kernel/admission_coordinator.rs:1560`, `:1814` |
| Compensation | Pre-dispatch only | M: `kernel/admission_coordinator.rs:1607` |
| Startup recovery | Fenced reconciliation of non-terminal operations | M: `kernel/admission_coordinator/recovery.rs:108` |
| Admission states | Include `CapturePending` and `AwaitingCallerReport`; separate security operation model | M: `admission_operation.rs:228-240`; `security_admission_operation.rs` |
| Qualified capture authority | Trait plus test adapter only | M: `admission_operation/capture.rs:383`, `:772` (same on V:) |
| Process cancel | Recursive CTE marks the subtree `cancelled`; `ProcessState` is `Running` or `Cancelled`; worker op `cancel` closes own subtree | M: `chio-process/src/store.rs:254-267`; `src/types.rs:126-129`; `src/lib.rs:570`; `WORKER_PROTOCOL.md:57` |
| Process runner | Terminates active direct workers of cancelled processes; revokes credentials after completion | M: `crates/products/chio-cli/PROCESS_RUNNER.md:288-289`, `:312-313` |
| Process security identity | Session = runtime, lineage = process lineage | M: `chio-process/src/security.rs:24-33` |
| Hosted session revocation (AP8) | Success only after every capability's write and readback; partial progress non-2xx; idempotent | M: `transport-revocation-design.md:36-41`; `chio-mcp-remote/src/remote_mcp/admin/revocation_batch.rs:1`, `:137`; route `admin.rs:24-27` |
| Kernel session lifecycle | Draining, per-request cancellation, anchor change fails dispatch start, close requires drain | M: `chio-kernel/src/session.rs:1261-1274`, `:1492`, `:330` |
| Capability revoke route | Service bearer token | M: `chio-control-plane/src/trust_control/authority_handlers.rs:527` |
| Emergency stop | Process-local `AtomicBool`; restart resumes (ledger EV11/AC6) | M: `kernel/construction.rs:369` |
| D1 allocator | `create_root`, `subdivide`, `select`, `claim_dispatch`, `seal_dispatch`; no freeze operation; receivers verify sealed permits offline against allocator keys | V: `crates/platform/chio-workflow/src/delegation/store.rs:85-271`; `dynamic-delegation-design.md:77-78` |
| S1 extension | Additive CAS install; terminal graphs and changed epochs reject | V: `chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs:88`; `chio-swarm-authority/src/evolution.rs:37`, `:80` |
| S1 terminal receipt | Carries budget rollups | V: `chio-swarm-authority/src/types.rs:320` |
| Swarm consumption hook | Verifies the swarm reference from the store | V: `chio-runtime-core/src/admission_hook/swarm_authority.rs:12` |
| Release authorities | `PreDispatchNoEffect`, `TransportNotAccepted`, `ContractualZeroCharge`, `MutuallyAgreedUnknown`, `ContractualCaptureWaiver` | V: `crates/kernel/chio-kernel/src/payment/journal.rs:88-96` |
| Blast radius | `BlastRadiusPort` and `CausalLineageStore` ports; no production lineage store (fakes only) | M: `chio-security-types/src/ports/lineage.rs:277`, `:294` |
| Approvals | Approval-set reservation cancel; threshold proposal cancel; journaled cleanup actions | M: `approval.rs:647`; `threshold_approval.rs:509`; `kernel/admission_cleanup.rs`, `kernel/approval_cleanup.rs` |
| Recovery approvals | "Emergency revocation invalidates pending approvals" is doc-only and not implemented in W:. What exists is fresh revocation at capture and on every return, plus `CancelWorkflow` | R: `08-protocol-operations.md:57`; W: `crates/kernel/chio-kernel/src/recovery/records.rs:52-68` (`Cancel` permission) |
| Recovery cancel | `CancelWorkflow` moves `Active` to `CancelRequested`, or straight to `Cancelled` with `admission_closed` when nothing was admitted. A same-writer tombstone fences delayed original submissions at begin and capture | W: `admission_operation_store/recovery/native.rs:286-293` |
| Recovery original closure | `reconcile_recovery_original` acts only when it can own the operation. It compensates `Prepared` through `CapturePending` with cause `scoped-recovery`, compensates `ApprovalRequired` when cancelled or past deadline, and terminalizes `DispatchCommitted` | W: `kernel/admission_coordinator/recovery_runtime.rs:184-240` |
| Recovery control tokens | Direct operator-assigned tokens only: no delegation chain, caveats or attenuation | W: `crates/kernel/chio-kernel/src/recovery/ports.rs:202-251` |
| Semantic emergency stop | Scoped, persisted as a recovery `command` record, checked at plan acceptance and inside capture and submission transactions | W: `admission_operation_store/semantic.rs:355-372`; `semantic/capture.rs:47`, `:294`, `:336` |
| Confined children (P5) | Root-only attach, host-allocated `confined_{id}`, at most 16 per scope, never refunded. `cancel` commits the native disposition, then `ProcessRuntime::cancel`. The final journal activity read is the release's cancellation ordering point | W: `crates/platform/chio-control-plane/src/confinement.rs:117-150`, `:234-236`, `:258-274`; `chio-security-types/src/confinement.rs:7` |
| Federation | Revocation epoch roots over iroh lane b | V: `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs:1-6` |

## 3. Goals and non-goals

Goals:

- One drain that every authority cut uses.
- Closure fences that linearize with the durable dispatch commit, plus revalidating guards for check-then-act paths.
- One idempotent, manual, terminal close per space kind, with a durable record and a signed artifact.
- The funded and delegated work invariants of section 7, unchanged.
- An explicit account of capacity that closure strands.

Non-goals:

- Reclaiming D1, S1, process-share or pool capacity. Closure records it; it does not return it.
- Refunding earned work, accelerating escrow refunds, or synthesizing a release authority.
- Automatic closure. Permanent revocation remains manual.
- Reversible containment, suspension or lift. These stay in active defense.
- Remote drain or recall, task migration, or retargeting sealed work.
- An isolation-epoch transition. Taint survives closure (M: `active-defense-rollout.md:19`).

## 4. Fences at linearization points

### 4.1 Dispatch-commit fence (durable operations)

1. **Authority refs.** `AdmissionOperationStore::begin` writes `admission_operation_authority_refs(operation_id, ref_kind, ref_id)` in the operation's insertion transaction. The rows are:
   - every id in the admission's `CanonicalRevocationSet` (M: `supplemental_quota.rs:732-752`);
   - one `session` row;
   - `process_lineage` and `principal` rows from the trusted `SecurityInvocationContextV1` (process calls supply runtime and lineage, M: `chio-process/src/security.rs:24-33`). On M: the lineage id is the tree root's capability id (`chio-process/src/lib.rs:419-431`), so it matches a closure of the whole tree but not of a subtree;
   - one `process_tree` row for every process on the calling process's path, root first, including the caller itself. chio-process already loads that path at admission (`store.lineage(process_id)`, `lib.rs:419`), and its length is bounded by the process depth limit. A `ProcessTree(p)` closure fences `process_tree = p`, so it matches every operation of every descendant of `p` by an exact join, with no ancestor lookup inside the CAS;
   - one `swarm_graph` row when a continuation was consumed;
   - for D1, the ref depends on whether the permit was already sealed (V: `crates/kernel/chio-kernel/src/delegated_work.rs`):
     - a call admitted by the D1 guard under a permit sealed before admission records `delegation_root_sealed`, with the permit digest. No `DelegationRoot` fence ever matches it, because section 6.2 keeps sealed permits executable, so closing the root never strands receiver work it is required to honor;
     - issuance-side operations on unsealed slots (allocation, subdivide, select, seal) record `delegation_root`, and only these are matched by the `DelegationRoot` fence.
   1a. **Operations from before the index.** The migration that creates `admission_operation_authority_refs` and `closure_fences` also adds `admission_operations.authority_refs_state` (`indexed` or `legacy_unindexed`).
   - **Backfill.** For every non-terminal operation whose persisted record holds its revocation set, session and security context, the migration writes the refs, re-derives them, compares the two, and marks the operation `indexed`.
   - **What stays legacy.** Every other non-terminal operation stays `legacy_unindexed`. New operations are `indexed` in their insertion transaction.
   - **Legacy predicate.** The dispatch CAS (rule 3) and the release check (rule 3a) refuse a `legacy_unindexed` operation when any row exists in `closure_fences`. Every fence row postdates every legacy operation, because the same migration creates the fence table. So this refuses dispatch only for closures that could have covered the operation, and it over-fences rather than under-fences. The coordinator compensates on its own path with `AuthoritySpaceClosed { closure_id }`, naming the earliest fence.
   - **Why not the drain alone.** The drain cannot close this gap: it never steals a live lease (section 5 rule 3), and a coordinator holding the lease sees no refs.
   - **Removal.** A later migration removes the legacy predicate only once `count(non-terminal and legacy_unindexed) = 0`.
2. **Fence rows.** A closure writes `closure_fences(ref_kind, ref_id, closure_id, fence_commit)` into the same SQLite writer.
3. **Fence check.** `commit_durable_dispatch` and `capture_and_commit_durable_dispatch` (M: `admission_coordinator.rs:1560`, `:1814`) add `NOT EXISTS` over the join of the operation's refs and `closure_fences` to their CAS.
   - A fenced operation fails the CAS with `AuthoritySpaceClosed { closure_id }`.
   - The coordinator then compensates on its own path.

   3a. **Release fence check.** Output can still leave Chio custody after `DispatchCommitted`. Every release that does so runs the same `NOT EXISTS` predicate over the operation's refs and `closure_fences`, plus rule 1a's legacy predicate, in the admission writer, in the same transaction as the finalization commit that releases the output. Three releases are affected:
   - the caller-executed release check (M: `admission_coordinator/terminal.rs:118-131`, the stop and revocation checks at `:126` and `:131`);
   - the native output release check (M: `admission_coordinator/native_output.rs:388-401`);
   - the finalization commit of ordinary durable returns.

   On M: these releases check stop and revocation, but not closure. Under spec 10 they become `OutputRelease` crossings, where Fence = yes, and this rule is that check.
   - **Refusal.** A refused release is `AuthoritySpaceClosed { closure_id }`. Following spec 9 M11 and M11a and spec 10 X16, the operation halts and its output is withheld for good. Closure decides delivery only, never money:
     - with no outstanding obligation (no payment participant, a zero amount, a prepaid settlement, or a payment journal already `Final`), it terminalizes as `DeniedAfterDelivery` with retained markers. A recorded capture, authorized release or resolved waiver stands as recorded: nothing is captured, released or refunded again;
     - with a settlement intent already in flight, `RefuseDelivery` records `Finalizing(DeliveryRefused)`, the intent completes under its original identity (it passes the fence, section 7 item 9), and the operation then terminalizes;
     - with an `Open` positive reversible hold, `RefuseDelivery` records `Finalizing(DeliveryRefused)`. The known return, the hold and the payment journal stay as they were until the payment owner's own successor settles them. Closure never releases, waives or captures that obligation, and no new settlement intent starts after the refusal, so payable work stays payable (section 7).
   - **Why the drain terminates.** The terminal and the refusal record are both restrictive, non-crossing commits, so the fence that refused the release cannot refuse either. A `DeliveryRefused` operation is drained: its output can never leave custody and it can start no effect.
   - **Startup.** Startup reconciliation treats this refusal as that commit, not as a reconciliation failure, and continues with unrelated operations.
4. **Ordering.** Fence before dispatch commit means no dispatch. Dispatch commit before fence means the operation is post-dispatch and the drain retains it. Its output release still meets the fence (rule 3a), so a closure that commits before release withholds the output.

```text
committed(fence(c)) before cas(op -> DispatchCommitted) and refs(op) intersects space(c)
  -> not DispatchCommitted(op)
DispatchCommitted(op) before committed(fence(c)) -> drain(op) = retain_post_dispatch
committed(fence(c)) before release(op) and refs(op) intersects space(c)
  -> not released(op) and (terminal(op) = DeniedAfterDelivery or delivery_refused(op))
delivery_refused(op) -> hold(op) and journal(op) unchanged by closure
legacy_unindexed(op) and exists closure_fences -> not DispatchCommitted_after(op) and not released_after(op)
```

When the fence store and the admission store are different writers (a configuration with a remote revocation backend), rule 3 degrades to the guard check of section 4.2. The artifact then flags `dispatched_after_fence_unlinearized` when commit indices overlap.

**Shipped precedent.** W: already applies this pattern to recovery workflows. A cancellation tombstone and the authoritative operation lookup share one writer, and "both begin and capture consult it, fencing delayed original submissions" (W: `admission_operation_store/recovery/native.rs:286-293`). Closure fences generalize that tombstone from one workflow to an authority space.

### 4.2 Dispatch-revalidating guards (check-then-act paths)

5. **`ProcessLivenessGuard`** is a deny-only guard. It denies when the invoking process or any ancestor is `Cancelled`, or when any process on its path (its section 4.1 rule 1 `process_tree` refs) carries a `ProcessTree` closure fence. It never consults the root-wide security lineage for this.
   - It sets `requires_dispatch_revalidation() = true`, so it is re-checked at M: `dispatch.rs:806`.
   - Its source is the process registry's read-only state, which it reads only.
   - A lookup failure denies.
   - This closes the gap where process cancel does not fence an admitted call, for every dispatch that has not committed.
6. **Overlay guards.** `ContainmentGuard` and `CapabilitySetSuspensionGuard` override `requires_dispatch_revalidation` to `true`. Their `revalidate_before_dispatch` repeats the read-only lookup and fails closed. This is defect D6.
7. **Non-durable lanes** (MCP edge read-only calls without durable admission) have only these guards. Their residual race is reported, not prevented (section 15).

### 4.3 Named release crossings

Every crossing where bytes or effects leave Chio custody has one named ordering point. A closure that commits before the point withholds the crossing; one that commits after it cannot retract the crossing.

| Crossing | Ordering point | Source |
|---|---|---|
| Tool dispatch (durable) | `DispatchCommitted` CAS, with the section 4.1 fence | M: `admission_coordinator.rs:1560`, `:1814` |
| Output release, caller-executed (M3) | The release check during finalization of an authenticated caller report, with the rule 3a fence in the finalization commit (spec 10 `OutputRelease`) | M: `admission_coordinator/terminal.rs:118-131` |
| Output release, native | The native output release authority check during finalization, with the rule 3a fence in the finalization commit (spec 10 `OutputRelease`) | M: `admission_coordinator/native_output.rs:388-401` |
| Output release, ordinary durable return | The finalization commit that releases the recorded return, with the rule 3a fence (spec 10 `OutputRelease`) | M: `admission_coordinator/terminal.rs` (`finalize_durable_tool_return`) |
| Recovery continuation | Same-writer tombstone at begin and capture | W: `admission_operation_store/recovery/native.rs:286-293` |
| Confined return (P5) | The return-admission commit (`store.admit_confined_return`, spec 10 `ConfinedReturn`) is the stop and fence point. The final serialized journal activity read before sink I/O stays the cancellation ordering point: an earlier completed cancellation withholds bytes and retains the native join and consumption | W: `crates/platform/chio-control-plane/src/confinement.rs:214-226`, `:234-236` |
| Artifact release (P4) | Commit of the knowledge join and `ReleaseIntent` before sink delivery | W: `docs/architecture/recoverable-agent-runtime/implementation/p4/OPERATIONS.md:98-106` |

Every new crossing must name its point before it ships. This adopts P5's rule and closes FTL's admitted SMP gap for Chio. The full crossing registry is spec 10 section 4.2 plus this table (spec 10 X1). What each crossing does while the kernel is stopped is spec 8 section 5, which is normative for stop dispositions.

## 5. Admitted-work drain

```rust
pub enum DrainTrigger {
    RevocationCommitted { capability_id: CapabilityId, commit: Option<RevocationCommitMetadata> },
    OverlayApplied { effect_id: RecordId, target: TenantScopedId },
    ProcessTreeCancelled { root_process_id: String },
    SessionClosed { session_id: SessionId, closure_id: AdmissionDigest },
    SwarmGraphClosed { graph_id: String, closure_id: AdmissionDigest },
    DelegationRootClosed { root_slot_id: String, closure_id: AdmissionDigest },
    WorkflowCancelled { workflow_id: String },   // W: CancelWorkflow (implemented)
    WorkCancelled { handle: String },            // V: W1 Cancel (assumed shipped, contract anchor)
}

pub trait AdmittedWorkDrain {
    fn drain(&self, trigger: &DrainTrigger, now: AuthorityTime) -> Result<DrainLedger, KernelError>;
}
```

Rules:

1. **Shared decision code (engineering-standard 5.6).** Three sites classify non-terminal operations today, and they must become one function parameterized by cause:
   - startup reconciliation (M: `admission_coordinator/recovery.rs:108`);
   - recovery's `reconcile_recovery_original` (W: `kernel/admission_coordinator/recovery_runtime.rs:184-240`);
   - this drain, with `cause = AuthorityCut { trigger_digest }`.

   The unified function takes W:'s shape. It acts only after `try_own_operation` succeeds, so it never steals a live lease, and then dispatches on state. Two differences must be resolved in the merge:
   - **`CapturePending`.** W: compensates it directly, relying on the compensation CAS to lose against a committed capture. The unified function keeps that form when the capture authority shares the admission writer, and adds the lookup-by-operation step when it does not.
   - **`DispatchCommitted`.** W: terminalizes it immediately (`terminalize_dispatch_committed_admission`). The drain does the same once it owns the operation, which yields the conservative outcome-unknown terminal with holds frozen. Without ownership it halts the operation (spec 9 `HaltOperation`, spec 3 `LatchScope::Operation`) and defers to the coordinator.

   **Normative source.** The single normative cut and drain table is the cut function of `2026-10-04-pure-admission-machine-design.md` (spec 9), evaluated with `CutCause::AuthorityCut`. The table below is an informative summary of this spec's intent. Where the two differ, spec 9 governs, and a change to the drain behavior is made there, not here. Spec 9 revision 2 records the review of the differences (S9-06), including:
   - `Parked` compensates under `AuthorityCut`;
   - the `Effect::CancelTransport` and `Effect::QueryParticipant` effects;
   - the governed economic mutation rows.

   | Observed state | Action |
   |---|---|
   | `Prepared` through `ReadyToDispatch`, or `ApprovalRequired` | Compensate (M: `admission_coordinator.rs:1607`) with cause `authority-cut`; latch the session request if one exists (spec 9 `LatchRequest`) |
   | `CapturePending` | Look up by operation. No capture: compensate. Capture committed: post-dispatch |
   | `DispatchCommitted`, owned by the drain | Halt the operation (spec 9 `HaltOperation`) and cancel the transport cooperatively where supported (M: `chio-mcp-adapter/src/transport/utils.rs:239`). Then follow spec 9 section 6.1's `X` row: with a `NotAccepted` proof, `NotAcceptedAfterDispatchCommit`; with a recoverable durable return, `Finalizing`, whose release then meets the fence (below); otherwise `OutcomeUnknownAfterDispatch` with holds frozen. Exactly one terminal; never redispatch, release or compensate |
   | `DispatchCommitted`, still owned by a live coordinator | Halt and defer: the drain never steals the lease. The coordinator either terminalizes it under the same `X` row or reaches `Finalizing`, and then follows the next row |
   | `Finalizing` | The release meets the fence (section 4.1 rule 3a), and the output is withheld for good (spec 9 M11, M11a). The operation terminalizes as `DeniedAfterDelivery` when no obligation is outstanding, including a payment already `Final`. Otherwise it is recorded as `DeliveryRefused`: an in-flight settlement intent completes and then terminalizes, and an `Open` hold is retained for the payment owner. It is never terminalized as outcome-unknown, because its return is recorded |
   | `Finalizing(DeliveryRefused)` | Drained. An in-flight settlement intent keeps completing under its original identity, and the operation then terminalizes (spec 9 M11a). `stranded_final.delivery_obligations` lists it as `InFlight` until a readback confirms `Final`, and an untouched hold as `Open` (section 8) |
   | `AwaitingCallerReport` | `HaltOperation { UnsettledCallerCustody }` plus the fault (spec 9 section 6.1). A later authenticated report records the return and moves the operation to `Finalizing`, so its release meets the fence and follows the `Finalizing` row |
   | Recovery workflow bound to the space | `CancelWorkflow` by the closure actor (section 6.5); the same-writer tombstone fences begin and capture |
   | Confined child in the space | `NativeConfinedRuntime::cancel`: native disposition first, then process cancel and pidfd termination (W: `crates/platform/chio-control-plane/src/confinement.rs:258-274`). A plain `ProcessRuntime::cancel` alone would leave the native confined record unterminated |
   | Security operation model, dispatch `NotStarted` | That model's own compensation path |
   | Security operation model, `CallerReserved` or `Committed` | Post-dispatch |
   | `GovernedEconomicMutation` | Request the authoritative not-applied result; never assume it |
   | Terminal | Record only |

2. **Release.** The drain never releases a hold itself.
   - Holds move only through the compensation projection, under `PreDispatchNoEffect`, or by the transport's `TransportNotAccepted`.
   - The drain never produces `MutuallyAgreedUnknown`, `ContractualCaptureWaiver` or `ContractualZeroCharge`. Each requires its own counterparty or contract evidence (V: `payment/journal.rs:88-96`).
   - A closure refusal is never contract evidence. It does not make `ContractualZeroCharge` eligible, and a positive-cost refused return keeps its hold (spec 9 M11a).
3. **Concurrency.** The drain uses the version-bound recovery claim and never steals a live lease. A coordinator holding the lease meets the dispatch-commit fence (section 4.1) and compensates on its own path.
4. **Idempotency.** The drain is idempotent per `operation_id`. Process call slots and sibling shares are consumption and are never compensated (M: `chio-process/ARCHITECTURE.md:22-24`, `:43-44`).

```text
drain_action(op) = compensate -> dispatch_not_committed(op) at CAS version and not capture_committed(op)
drain never performs release_hold(op) outside {PreDispatchNoEffect, TransportNotAccepted}
cut_commit(trigger) precedes every drain action for trigger
```

**Enumeration.** The authority refs index (section 4.1) finds operations. Descendant sets for withdrawal and hint fan-out use `BlastRadiusPort` (M: `chio-security-types/src/ports/lineage.rs:277`). No production `CausalLineageStore` exists (defect D12). Until one exists over the `chio-store-sqlite` capability lineage, enumeration reports `Incomplete` and safety is unchanged. Operations that the migration could not index (section 4.1 rule 1a) are found by scanning recoverable rows and counted as `legacy_unindexed`. Their dispatch and release are fenced by rule 1a's legacy predicate, not by the drain.

## 6. Closure record and kinds

### 6.1 Types

```rust
pub enum AuthoritySpaceRef {
    CapabilitySubtree { root_capability_id: CapabilityId },
    Session { session_id: SessionId },            // hosted MCP or in-process kernel session
    ProcessTree { root_process_id: String },
    SwarmGraph { graph_id: String },
    DelegationRoot { root_slot_id: String },      // D1 slot subtree
}

pub struct AuthoritySpaceClosureV1 {
    pub closure_id: AdmissionDigest,   // SHA256("chio.authority-space-closure.v1\0" || canonical({coordinator_authority_id, request_namespace_digest, space}))
    pub space: AuthoritySpaceRef,
    pub authorizer: ClosureAuthorizer,
    pub reason_hash: AdmissionDigest,
    pub state: AuthoritySpaceClosureState, // Fencing, Fenced, Draining, Closed
    pub fence_commits: Vec<ClosureFenceCommit>,
    pub drain: DrainLedger,
    pub stranded_at_fence: StrandedCapacity,         // section 8: snapshot at Fenced
    pub stranded_final: Option<StrandedCapacity>,    // section 8: recomputed after the drain; Some only in Closed
    pub enumeration: EnumerationCompleteness,
    pub batch_id: Option<AdmissionDigest>,
    pub version: u64,
}
```

### 6.2 Fence per kind

| Kind | Fence (existing surface first) | Revokes |
|---|---|---|
| `CapabilitySubtree` | Revoke root with write plus readback (AP8 backend, M: `admin/revocation_batch.rs:48`); fence row on the root id | Root only; descendants die by chain walk |
| `Session`, hosted MCP | AP8 `POST /admin/sessions/{id}/trust` (session-wide revocation with readback, M: `admin.rs:24-27`); then kernel session forced close (latch, rotate anchor, drain, `close_persisted`); fence row on the session | Every capability issued to that session |
| `Session`, in-process kernel | Forced close only; fence row on the session | Nothing |
| `ProcessTree` | `ProcessRuntime::cancel(root)` (M: `chio-process/src/lib.rs:570`); fence row `(process_tree, root_process_id)`, keyed on the requested process id (section 4.1 rule 1), never on the security lineage. On M: that lineage is the tree root's capability id (`chio-process/src/lib.rs:419-431`), so a lineage fence would also stop the requested process's siblings and ancestors. `ProcessLivenessGuard` | Nothing; the runner revokes worker credentials |
| `SwarmGraph` | Tombstone in W1's qualified graph issuer, checked at continuation consumption (V: `admission_hook/swarm_authority.rs:12`) and inside the canonical graph-extension transaction of the serving store, so a closed graph cannot grow; deny code `chio_swarm_graph_closed`. The legacy `extend_swarm_authority_bundle` (V: `chio-runtime-core/src/store/sqlite/swarm_authority_bundles.rs:88-132`) calls the same shared rule and is not a production writer (rule 6) | Nothing |
| `DelegationRoot` | Fence row in W1's qualified D1 store (the delegation module in `chio-store-sqlite` under the serving connection, V: `2026-10-03-work-runtime-design.md:123-131`). `subdivide`, `select` and `seal_dispatch` reject under a fenced ancestor in the same canonical transaction that commits the allocation, selection or permit. The legacy `chio-workflow` delegation store (V: `delegation/store.rs:10-47`, `:112`, `:176`, `:271`) calls the same shared rule and is not a production writer (rule 6) | Nothing |

Rules:

1. **Revocation is surface-specific.** Closing a hosted MCP session revokes its issued capabilities, because AP8's truthful batch already does and those capabilities are minted for that session. In-process sessions, process trees, swarm graphs and D1 roots do not revoke capabilities, which may serve other spaces. An operator who wants both submits a batch linked by `batch_id`.
2. **Sealed D1 permits stay dispatchable.**
   - Receivers verify sealed permits offline against allocator keys, "without accessing the allocator database" (V: `dynamic-delegation-design.md:77-78`).
   - A `DelegationRoot` fence therefore stops unsealed work only.
   - Sealed permits remain executable until the receiver revokes its receiver-issued capability (`max_invocations=1`).
   - The artifact lists them as `sealed_outstanding`. It never claims they were stopped.
3. **Closure is not completion.** A closed graph is not terminal in S1's sense: S1 terminal receipts are completion evidence with budget rollups (V: `types.rs:320`). The extension verifier treats a tombstone as it treats a terminal graph, and rejects the extension. The closure artifact copies existing rollups when a terminal receipt exists.
4. **Manual only.** No automatic response effect may close a space (M: `active-defense-rollout.md:23`). Reversible pause is the emergency stop or an overlay.
5. **Taint survives.** A closed session or process does not reset principal or lineage taint. Closure is not an isolation-epoch transition (M: `active-defense-rollout.md:19`).
6. **D1 and S1 closure composes with W1's qualified issuer (R-4-03).** W1 moves production D1 allocation and S1 graph issuance into the qualified serving store and retires the legacy writers (V: `2026-10-03-work-runtime-design.md:123-131`). Closure joins that plan rather than targeting the legacy surfaces.
   - **One canonical transaction.**
     - The live closure predicate (fence row or tombstone, plus closure generation) is a row of the qualified serving store.
     - It is checked in the same transaction as the operation it gates: allocation (`subdivide`), selection, permit sealing (`seal_dispatch`) and graph extension.
     - A refusal commits nothing. There is no second closure database acting as issuance authority, and no transaction spans two stores.
   - **One rule, two callers.**
     - The predicate is a shared domain function in `chio-workflow`, next to the D1 and S1 transition rules W1 already shares.
     - The legacy `chio-workflow` delegation store and the runtime-core swarm-authority bundles call it as example adapters. Neither stays a writable production owner.
     - Runtime graph copies remain lookup and evidence sources (W1). A copy cannot issue after a closure or after its owner lease is lost.
   - **One authorized migration.** W1's owner-authorized, quiesced migration already preserves allocator namespace, roots, allocation digests, revisions, selections and exact permit bytes. It is extended to also retain, with their original references:
     - fence rows and tombstones;
     - each closure's generation;
     - the closure record and its drain and progress state (section 6.3);
     - the stranded-capacity snapshots (section 8).

     These records are registered in the qualified store's projection and global-commit inventory, integrity verification, and snapshot and relocation paths, exactly as W1 requires for its own mutations. The migration then disables the legacy writer. A source that is missing or untrusted is rejected, never replaced with empty closure state.
   - **Supported landing order (answers open decision 8).** The recommended order is W1's qualified issuer first, then phase 3 against it, so no closure state ever exists in a legacy writer. If phase 3 must land first, its fences and tombstones live in the legacy stores only until W1's migration, which then imports them under the rule above. The legacy writer is retired in the same step. The two plans never advertise two production issuance heads at once.
   - **Unchanged.** Closure never refunds, reclaims or invalidates sealed capacity, and offline sealed permits keep their documented semantics (rule 2, section 7). Historical reads of migrated state keep their access rules.

### 6.3 Ordering

1. Insert the record in `Fencing`, idempotent on `closure_id`.
2. Apply the kind fence plus fence rows. Readback is required, following AP8: a fence that cannot be read back keeps the record in `Fencing` and returns non-2xx with per-ref status.
3. CAS the record to `Fenced`.
4. CAS to `Draining` and run the drain.
5. Withdraw (section 6.5).
6. When every ledger entry is terminal, delivery-refused (spec 9 M11a) or incident-bound, recompute `stranded_final` (section 8), sign the artifact, CAS to `Closed`, and emit exit hints. A delivery-refused entry needs no financial settlement before `Closed`: its output can never be released, and its payment, whether `Open` or `InFlight`, is recorded in `stranded_final.delivery_obligations` with its stage (section 8). Closure never waits for a payment rail.

```text
fenced(c) and binds(op, space(c)) and durable(op) and fence_in_admission_store(c)
  -> not dispatched_after(op, fence(c))
state(c) = Closed -> forall op in ledger(c): terminal(op) or delivery_refused(op) or incident_bound(op)
```

### 6.4 Authorization

| Space | Who may close |
|---|---|
| `CapabilitySubtree(root)` | Operator (service auth, as revoke today); the root's issuer; any delegator in the root's verified chain; the root's subject (relinquish) |
| `Session(id)` | Operator; the session's authenticated principal |
| `ProcessTree(id)` | Operator; the process itself or an ancestor, through the existing worker `cancel` op (own subtree only, M: `WORKER_PROTOCOL.md:57`) |
| `SwarmGraph(id)` | Operator; the graph issuer or planner subject |
| `DelegationRoot(slot)` | The allocator owner for any slot; the authenticated holder for a slot it holds (fences that slot's unsealed descendants) |

Non-operator closers sign `chio.authority-space-close-request.v1 { space, reason_hash, nonce, issued_at, expires_at }` with a lifetime of 60 seconds or less. `(signer_key, nonce)` is reserved once. Closure only revokes, fences, latches, compensates and withdraws, so no authorization path widens authority.

### 6.5 Withdrawal

- **Recovery workflows and approvals.** "Emergency revocation invalidates pending approvals" (R: `08-protocol-operations.md:57`) is doc-only and not implemented in W:. Instead:
  - An operator-assigned closure actor holding the `Cancel` permission on `chio.recovery` issues `CancelWorkflow` for every workflow whose scope or seed capability is bound to the space, including `Quarantined` ones (W: `crates/kernel/chio-kernel/src/recovery/records.rs:52-68`).
  - The same-writer tombstone fences late begin and capture (W: `admission_operation_store/recovery/native.rs:286-293`). Fresh revocation of the seed capability at capture covers any approval granted before the cancel.
  - Recovery control accepts only direct, operator-assigned tokens with no delegation chain (W: `crates/kernel/chio-kernel/src/recovery/ports.rs:202-251`). A delegator or holder authorized to close a space (section 6.4) therefore never issues `CancelWorkflow` itself; the closure coordinator does, under the operator closure actor.

  This spec adds no `withdraw_pending`.
- **Approval-set reservations and proposals.**
  - Approval-set reservations of compensated operations are cancelled through M: `approval.rs:647`, under the journaled cleanup pattern (M: `kernel/approval_cleanup.rs`).
  - Open threshold proposals are cancelled through M: `threshold_approval.rs:509`.
- **Authority-fault remedies.** The kernel holds no pending fault state. Remedy admission denies when the faulted capability, or an ancestor in its own chain, is revoked (`2026-10-04-authority-faults-design.md`).

Safety never depends on withdrawal. A late approval meets the fence.

## 7. Funded and delegated work invariants

These are quoted from their sources and are normative for every closure kind:

1. **Earned claims are untouched.** "An earned claim has no timeout or refund transition" (V: `docs/papers/verifiable-work/sections/04-execution.tex:111`). "Payable work remains payable after parent failure/refund" (V: `2026-10-03-work-owner-services-design.md:63`). Closure of a parent space never changes a `Payable` or `Paid` claim.
2. **Escrow follows its agreed deadlines.** The F1 transitions are Fund, Submit, Record accept/reject, Expire (strictly after the refund deadline), Withdraw and Refund (V: `docs/papers/verifiable-work/PROTOCOL.md:48-57`).
   - Closure invokes no chain escrow transition.
   - Funded but unsubmitted children expire or are decided on schedule.
   - A kernel hold left as outcome-unknown by the drain is released only by `MutuallyAgreedUnknown` under its own preconditions (spec 9 M7a).
   - A hold retained with a delivery-refused known return is settled only by the payment owner's own successor, for example a `ContractualCaptureWaiver` once a positive capture is pending (spec 9 M7b, M11a).
   - Closure never synthesizes any of these.
3. **Allowance is not money.** "A child has its own actual funding; unused parent allowance is not money" (V: `work-owner-services-design.md:63`).
4. **Sealed allocations are retained.** "There is deliberately no reset, timeout refund, untrusted absence report or release of sealed allocations" (V: `dynamic-delegation-design.md:86-87`).
5. **No retargeting.** Provider substitution "does not retarget sealed work" (V: `agentic-work-kernel-design.md:133`). Closure does not either.
6. **Local attestation only.** Execution evidence attests local execution, so the artifact never claims remote completion or delivery.
7. **Process shares.** Process call slots and sibling shares remain allocated after cancellation (M: `chio-process/ARCHITECTURE.md:22-24`).
8. **Knowledge and confined children (W: P4, P5).** Closure clears no knowledge, removes no pin, and refunds no confined-child reservation.
   - Uncertain artifact releases stay pinned (W: `implementation/p4/OPERATIONS.md:143-153`).
   - A confined child's cancellation "does not remove pins, refund, or clear knowledge" (W: `implementation/p5/OPERATIONS.md:114-118`).
   - A parent's joined knowledge is never reset by closing the child or the parent's space.
9. **Settlement passes the fence.** The settlement crossings `ExternalPrepare { Settle }`, `FederationCosign` and `ChannelReleasePublish` pass the closure fence and the revocation check when the subject they settle committed before the cut (spec 10 section 4.2). New authorizations in a closed space are refused. This keeps items 1 and 2 true after closure.

## 8. Stranded-capacity accounting

D1, S1 and processes all strand capacity on purpose. Closure makes that cost auditable without reclaiming it:

```rust
pub struct StrandedCapacity {
    pub d1_unsealed_remainder: Vec<SlotRemainder>,   // fenced, now unusable, by currency
    pub d1_sealed_outstanding: Vec<SealedPermitRef>, // still dispatchable at receivers (6.2 rule 2)
    pub s1_unissued_allocations: Vec<PoolAllocationRef>,
    pub process_retained_shares: Vec<ProcessShareRef>,
    pub frozen_holds: Vec<OperationHoldRef>,          // outcome-unknown; released only per 7.2
    pub delivery_obligations: Vec<DeliveryObligationRef>, // delivery-refused known returns whose payment is not confirmed Final (spec 9 M11a)
    pub confined_reservations: Vec<ConfinedChildRef>, // P5: at most 16 per scope, never refunded
    pub pinned_artifacts: u64,                        // P4 pins retained by the space (count only)
    pub completeness: EnumerationCompleteness,
}

pub struct DeliveryObligationRef {                   // read back from the native payment journal at stranded_final
    pub operation_id: OperationId,
    pub hold_id: HoldId,
    pub journal_state: JournalState,                 // as read back: HoldPlaced, Authorized, Settling, ReconcileFailed or Resolving
    pub stage: DeliveryObligationStage,              // Open | InFlight
    pub intent: Option<SettlementIntentRef>,         // InFlight only: the original settle action, amount and journal digest
}
```

- **Delivery obligations.** Closure never waits for a payment rail. `stranded_final` lists every `DeliveryRefused` operation whose payment is not confirmed `Final`, so the `Closed` artifact states at its cut exactly which payments were outstanding:
  - `Open`: an untouched positive hold, waiting for the payment owner (spec 9 M11a and open decision 8);
  - `InFlight`: a recorded capture, release or waiver intent that has not completed. This includes `ReconcileFailed` and rail unavailability, and it records the original intent so later evidence can show that the same intent completed;
  - an operation is omitted only when the store read back its journal as `Final` in the transaction that computes `stranded_final`. A lost acknowledgement, or a completion not yet read back, is never presumed final, and that operation is listed as `InFlight`.

  Closure executes no settlement. The payment owner keeps driving an in-flight intent under its original identity after `Closed`, and records its completion in the native payment evidence. That evidence, not an amended artifact, shows the later outcome (spec 9 M11a).

The accounting has two snapshots. Both are evidence only.
- **`stranded_at_fence`** is computed from the owning stores at `Fenced`. It records what the fence cut off, and it is carried in the `Fenced` artifact.
- **`stranded_final`** is recomputed after every ledger entry is terminal, delivery-refused or incident-bound (section 6.3 step 6), immediately before the CAS to `Closed`, and it is carried in the `Closed` artifact. Recomputing matters because the drain changes the picture:
  - an operation observed as `DispatchCommitted` at the fence can complete and settle under its live lease, or become outcome-unknown and freeze its hold;
  - an in-flight knowledge operation can add a pin after the fence.

  The snapshot at the fence cannot report these, so only `stranded_final` lists the final `frozen_holds`, `delivery_obligations` and `pinned_artifacts`.
- **After closure.** Changes after `Closed`, such as a frozen hold later released under section 7.2, are recorded by their own evidence, not by amending the artifact.
- **Reclamation.** A future reclamation design may take a `Closed` artifact's `stranded_final` as a precondition. This spec defines no reclamation.

## 9. Exit hints and evidence

- **Kernel sessions.** Hints project onto the closed `HintSubject` vocabulary of `2026-10-04-unified-event-queue-design.md` (spec 5 Part B):
  - `Changed` on `Capability(id)` for every capability id in the closed lineage that a session holds. Lineage fan-out happens at post time, so a session subscribed to a descendant's own id is reached (spec 5 Part B, S5-14);
  - `Terminal` on `Lifecycle` for closed sessions;
  - `Changed` on `Operation` for drained operations the session owns.
- **Processes.** A `ProcessTree` closure changes `ProcessState`, which advances the process `hint_revision` in the same transaction (spec 5 Part B, rule P1; `Lifecycle` is one of the two subjects the process projection keeps). A waiting `inspect` returns, and a worker whose credential was revoked sees `unauthenticated`. Child exit observations still come from runner outcomes and `wait_children`.
- **Workflows and work.** Workflows use the recovery event chain (W: `admission_operation_recovery.sql`, whose global monotonic `sequence` column is the cursor). Work uses W1 queries.
- **No authority.** Hints carry no authority. Consumers re-read the closure record.
- **Artifact.** The kernel signs `chio.authority-space-closure.v1` at `Fenced` and at `Closed`, listing:
  - fence commits;
  - compensated operations with receipt ids;
  - post-dispatch operations with terminal or incident ids, and flags `admitted_before_cut` or `dispatched_after_fence_unlinearized`;
  - withdrawals;
  - stranded capacity: `stranded_at_fence` in the `Fenced` artifact, and `stranded_final` in the `Closed` artifact (section 8);
  - enumeration completeness.
- **Trace.** Add `RuntimeTraceEvent::AuthoritySpaceClosureTransition` beside `RevocationCommitted` (M: `kernel/validation/revocation_trace.rs:15`).

## 10. Federation

- A subtree closure of a locally issued root publishes through revocation checkpoints over iroh lane b (V: `lanes/revocation.rs:1-6`). Remote kernels deny within their view freshness window.
- A kernel that commits or installs a revocation from any source runs the drain for ids in its authority refs (reactive drain). Each kernel drains only its own work.
- Closures of remote capabilities, sessions, process trees, swarm graphs and D1 roots are local. The artifact marks them `scope: local`.

## 11. Proposed composition lemma (paper, proposal only)

This proposes a closure extension to the Proposition (V: `docs/papers/verifiable-work/sections/05-composition.tex:62-76`), to answer the scope gap at `08-limits.tex:5-6`.

> **Proposition (preservation under closure).** Assume the premises of the Proposition. In addition, assume that every closure fence is either committed in the same protected store (the same writer) as durable dispatch commits, or, for `early_only` backends, revalidated before dispatch (section 4.2). Every finite interleaving of the Proposition's transitions together with closure operations (fence, drain, withdraw, close) preserves:
> 1. delegation and graph allocations remain within their original bounds, and paid plus refunded funds do not exceed deposited backing;
> 2. a sealed invocation retains its receiver, capability, input, tool operation and request;
> 3. an earned child claim retains its terms and remains payable or paid.
>
> It also adds:
> 4. after a closure fence that is checked in the dispatch transaction's writer commits, no durable operation bound to the space commits dispatch;
> 4'. (weaker, `early_only` fences in a different writer) after such a fence commits, no durable operation bound to the space commits dispatch unless its pre-dispatch revalidation read the fence store before the fence committed. Such an operation is reported as `dispatched_after_fence_unlinearized` (section 4.1);
> 5. closure releases no reserve and no sealed allocation.
>
> Sealed D1 permits are outside properties 4 and 4'. They stay dispatchable and are listed as `sealed_outstanding` (section 6.2 rule 2).

**Proof sketch:**
- Closure adds fence rows and terminal records only. It never mutates an allocation, seal, graph allocation or claim, so properties 1-3 follow from the Proposition.
- The drain performs only pre-dispatch compensation, which is an existing recovery transition, plus operation halts and session-request latches (spec 3 `LatchScope::Operation` and `LatchScope::SessionRequest`). It never sets the kernel-wide evidence latch.
- Property 4 is section 4.1's CAS ordering. It holds only because the fence and the dispatch CAS share one writer, which serializes them.
- Property 4' follows from section 4.2's revalidation. A check that reads before a remote fence commits, followed by a local dispatch CAS, satisfies the weaker premise but not property 4. That interleaving is the reason the premise is split.
- Property 5 is section 5 rule 2 plus section 7.

This is a proposal. No Lean coverage is claimed.

## 12. Recovery

- Closure records use the fenced CAS and version discipline of the admission store. Startup resumes non-`Closed` records:
  - `Fencing` re-applies fences, which are idempotent (AP8 retries are idempotent; process cancel updates only `running` rows; tombstone and fence inserts are idempotent).
  - `Fenced` and `Draining` re-run the drain.
- A crash between fence commit and record CAS leaves the fence in force, and recovery records it.
- Overlapping closures may list one operation twice. Consumers trust the operation terminal.

## 13. Failure modes

| Failure | Behavior |
|---|---|
| Fence write or readback fails | Record stays `Fencing`; non-2xx with per-ref status; recovery retries |
| Fence store not co-located with the admission store | Guard-only fence; artifact flags any unlinearized dispatch |
| Process registry or overlay lookup fails at revalidation | Deny |
| Operation store unavailable during drain | Fence holds; `Closed` not reached |
| Compensation rejected (operation changed) | Re-read and reclassify |
| Unqueryable transport after dispatch | `OutcomeUnknownAfterDispatch`, holds frozen, incident; listed in `frozen_holds` |
| D1 allocator unavailable | `DelegationRoot` fence not applied; record stays `Fencing` |
| Blast radius `Incomplete` or port missing | Recorded; safety unchanged |
| Signing unavailable | `Closed` not reached; fences and drain stand |

## 14. Protocol, schema and wire impact

- `spec/PROTOCOL.md` section 8:
  - add `POST /admin/authority-spaces/close` and `GET /admin/authority-spaces/{closure_id}` beside `/admin/revocations` (section 8.3);
  - document that hosted session closure composes AP8.
- Signed-artifact registry: add `chio.authority-space-closure.v1` and `chio.authority-space-close-request.v1`.
- Deny codes: `chio_swarm_graph_closed`, `chio_delegation_root_closed` and `AuthoritySpaceClosed`.
- Paper: section 11 is offered for the scope section.
- Section 5.3 rule 5 and `P2` are unchanged. There is no peer negotiation; federated peers see revocation checkpoints only.

## 15. Rollout

1. **Phase 1.**
   - Authority refs index with backfill and the legacy predicate (section 4.1 rule 1a); dispatch-commit and release fences (rules 3 and 3a); drain on the revocation trigger; `CapabilitySubtree` closure; artifact; operator authorization.
   - `ProcessLivenessGuard` and overlay revalidation (D6).
2. **Phase 2.**
   - Hosted session closure over AP8; in-process forced close; `ProcessTree` closure; process, workflow and work triggers; delegator and holder authorization.
3. **Phase 3.**
   - `SwarmGraph` tombstone (consumption plus extension); `DelegationRoot` fence; stranded-capacity accounting.
   - Lands against W1's qualified D1 store and graph issuer, in the same canonical transactions, with closure state added to W1's migration inventory (section 6.2 rule 6). If phase 3 lands before W1, W1's migration imports its fences and tombstones and retires the legacy writers in the same step.
4. **Phase 4.**
   - Production `CausalLineageStore`; reactive drain on lane b; event-queue hints.

Every phase ships behind the `authority-space-closure` configuration flag until its conformance scenarios pass. GT1 applies: new gates must run in hosted CI before any claim.

## 16. Tests and conformance evidence

- **Apalache.** `formal/apalache/AuthoritySpaceClosure.tla` composes `RevocationCutCompleteness.tla` with `PostAdmissionDropGuard.tla` and a fence variable.
  - Invariants: no dispatch commit after a co-located fence; no output release after a co-located fence (rule 3a); no dispatch or release of a `legacy_unindexed` operation once a fence exists (rule 1a); no compensation after dispatch commit or committed capture; no hold release outside {`PreDispatchNoEffect`, `TransportNotAccepted`}; `Closed` implies a terminal ledger.
  - Mutants: drop the `NOT EXISTS` clause; drop it from the release check; drop the legacy predicate; compensate a `DispatchCommitted` operation.
  - Negative example for property 4 under an `early_only` fence: guard check reads the remote fence store, the remote fence commits, then the local dispatch CAS commits. The model must report property 4 violated and property 4' satisfied, with the operation flagged `dispatched_after_fence_unlinearized`.
- **Loom.** Race fence commit against the `DispatchCommitted` CAS, and against the release-bearing finalization commit; exactly one order wins and the loser reclassifies.
- **Kani.** The shared classifier is total and never maps a post-dispatch or capture-committed state to compensation.
- **Proptest.** Random trees, process cancels, D1 subdivisions and seals, and S1 extensions under closure. Sealed permits and earned claims are unchanged, and the stranded ledger matches the store.
- **Unit.**
  - Overlay revalidation denies after a late suspension.
  - `ProcessLivenessGuard` denies a cancelled subtree.
  - Subtree closure noninterference: root R has children A and B, and A has a child A1. A `ProcessTree(A)` closure fences operations of A and A1, which carry `process_tree = A` refs. Operations of R and B still dispatch, because the fence is keyed on `process_tree = A` and not on the root-wide lineage.
  - A `ProcessTree` closure containing a confined child terminates the native confined record through `NativeConfinedRuntime::cancel`. A return staged before the activity read is withheld, and pins remain.
  - A space closure issues `CancelWorkflow` for a bound recovery workflow, and a delayed original submission is fenced by the tombstone.
  - `extend_swarm_authority_bundle` rejects a tombstoned graph.
  - D1 `seal_dispatch` rejects under a fenced root, while a previously sealed permit still verifies.
  - W1 composition (section 6.2 rule 6):
    - close a graph and a D1 root;
    - migrate through W1's authorized migration;
    - restart;
    - attempt subdivide, select, seal and extend through the public W1 facade and through the legacy entry points.

    Every new prohibited authority stays refused. Historical reads and already sealed permits keep their documented semantics. Further cases cover interruption mid-migration (the migration resumes or rejects, and never yields empty closure state), a stale legacy owner that writes after retirement (refused by the continuity checks), and both landing orders.
  - AP8 partial progress keeps the record in `Fencing`.
  - A closure committed after `DispatchCommitted` and before release withholds the output, for caller-executed, native and ordinary durable returns. With no payment, a zero amount or a prepaid settlement, the operation terminalizes as `DeniedAfterDelivery`. A restart between the refusal and the terminal completes the terminal.
  - **Closure recognizes a settled payment (R-9-05).** A positive-cost call whose ordinary capture is already `Settled`, then refused at release by a closure, terminalizes once as `DeniedAfterDelivery` with the charge as recorded and no refund. One whose capture is `Settling` at the refusal completes that capture under its original identity, then terminalizes. The settled one never appears in `delivery_obligations`; the settling one appears as `InFlight` if the record closes before a readback confirms `Final`.
  - **Closure is not pricing authority (R-9-03).** A positive-cost return on a reversible hold that is still `Open`, refused at release by a closure, is recorded as `DeliveryRefused` once. Across restart and closure completion, its hold and journal are unchanged, it is never re-dispatched, and it appears in `stranded_final.delivery_obligations` as `Open`. The record still reaches `Closed`. A later settlement by the payment owner's own successor terminalizes it once, and that is recorded by the payment evidence, not by amending the artifact.
  - **Closure records unresolved in-flight payments (R-4-04).** Close a space while a refused operation's capture is `ReconcileFailed` and the rail keeps failing; separately while the rail is unavailable; after a lost capture acknowledgement; and across a restart before `stranded_final`. Each time the record reaches `Closed` without waiting, and the artifact lists the operation as `InFlight` with its original intent. A capture confirmed `Final` by readback is omitted, and a lost acknowledgement is not presumed final. A later retry completes the same intent, charges once, and is recorded by the payment evidence, not by amending the artifact.
  - Migration backfill: indexed operations re-derive equal refs. A `legacy_unindexed` operation whose coordinator holds the lease fails its dispatch CAS once any closure fence exists.
  - Stranded accounting: an operation that settles, or becomes outcome-unknown, during the drain, and a pin added after the fence, appear in `stranded_final` and not in `stranded_at_fence`.
- **Conformance.**
  - Extend `chio-conformance` active-defense tests with "suspend after admission" and "process cancel during dispatch".
  - Add "close parent with earned child", in which the child claim stays `Payable` and the parent escrow follows its deadline.

## 17. Residual risks and open decisions

Residual risks:

- **Dispatched effects.** Effects already handed to a tool complete after any cut. This is reported.
- **Non-durable lanes.** These rely on revalidating guards, so one dispatch can race a fence.
- **Sealed D1 permits.** These remain executable at receivers until receiver-side revocation. There is no cross-owner closure notice channel.
- **Offline descendants.** Offline-delegated descendants are cut but not notified until presented.
- **Two operation models.** Two durable operation models exist (tool dispatch and security operation), and the classifier tracks both.
- **Recovery merge risk.** The recovery closure classifier and the confined runtime are uncommitted W: code built on an older #1160 checkpoint. New W: control-plane code samples `SystemTime::now()` (for example W: `crates/platform/chio-control-plane/src/confinement.rs:52-53`) instead of the fallible authority clock. Closure timestamps and deadlines must use the authority clock after the merge.

Open decisions and pushback:

1. **Pushback on "capture-time linearization removes the residual".** It removes it only for durable operations whose fence rows share the admission store's writer. The qualified `AdmissionCaptureAuthority` is still test-only on M: and V: (`capture.rs:772`), and remote revocation backends are separate writers. The residual stays for those, and for non-durable lanes.
2. **Should process completion close its space?** `ProcessState` has no exited state (M: `chio-process/src/types.rs:126-129`). The runner revokes the worker credential after completion (M: `PROCESS_RUNNER.md:288-289`), so the worker protocol can no longer drive the process. The process identity, however, stays admissible to host-side `ProcessRuntime` callers until cancel or expiry, and exit leaves no authority fact to key a closure on. Candidate 3 in `docs/research/2026-10-04-ftl-lessons-brainstorm.md` proposes a terminal `Exited` state, which would become a closure trigger.
3. **Overlay drain timing.** Should overlay apply invoke the drain synchronously in the effect transition, or asynchronously from the scheduler?
4. **D1 closure notice.** Should the D1 allocator publish a signed closure notice that receivers may consult before dispatching a sealed permit? This would add a cross-owner channel. Today receivers deliberately do not contact the allocator.
5. **Emergency stop persistence.** Resolved by `2026-10-04-durable-stop-epoch-design.md`. It defines a hash-chained `StopEpochV1` in the admission writer, checked inside every crossing transaction from section 4.3, and loaded before readiness. A stop never closes, revokes or drains. Closure stays this spec's manual operation, and closure ops remain allowed while stopped (stop spec S17). Background follows (EV11/AC6). A shipped precedent exists in W:: `set_semantic_emergency_stop(scope, bool)` persists a scoped stop as a recovery `command` record, and capture and submission transactions check it (W: `admission_operation_store/semantic.rs:355-372`; `semantic/capture.rs:47`, `:294`, `:336`). A kernel-wide stop should reuse that shape: persisted in the serving writer, and checked inside each capture or dispatch-commit transaction.
6. **Reclamation.** Should a future design permit reclamation of `d1_unsealed_remainder` after a `Closed` artifact proves no outstanding seals? Section 7 rule 4 forbids it today.
7. **Federated drain defaults.** What should be the default for reactive drain on federated revocation, and how long should closure records be retained?
8. **Closure landing order versus W1 (resolved).** W1's qualified issuer lands first, and phase 3 targets it. If phase 3 must land first, W1's migration imports the existing closure state and retires the legacy writer in the same step. Section 6.2 rule 6 holds the contract and section 16 the tests.

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180274509 | Project workflow exit hints from the implemented event chain | Already addressed in revision 3 (wave 2 parent edit): workflows use the recovery event chain, whose global `sequence` column is the cursor. The R: outbox is not relied on | Section 9 |
| 4180389987 | Fence ordinary output release during closure | Fixed now. Caller-executed, native and ordinary durable releases run the closure-fence predicate in the finalization commit. A refused release terminalizes as `DeniedAfterDelivery` with output withheld | Section 4.1 rules 3a and 4; section 4.3 table; section 5 drain row; section 16 |
| 4180389999 | Recompute stranded capacity after the drain | Fixed now. `stranded_at_fence` goes in the `Fenced` artifact, and `stranded_final`, recomputed after the ledger is terminal, goes in the `Closed` artifact and is the reclamation precondition | Sections 6.1, 6.3 step 6, 8 and 9; section 16 |
| 4180435346 | Backfill authority refs before enabling closure fences | Fixed now. The migration backfills and verifies refs. Operations it cannot index are `legacy_unindexed`, and a legacy predicate in the dispatch CAS and release check refuses them once any fence exists. The predicate is removed only when none remain | Section 4.1 rule 1a; section 5 enumeration; section 16 |

## Appendix A. FTL reference

What FTL does (paths under `/Users/connor/Medica/backbay/ftl`):

- `HandleSpace::close` (`kernel/src/hspace.rs:165-185`) sets `destroyed` under the lock, takes the thread and handle sets, then closes each outside the lock. Later inserts fail with `Destroyed`. Section 6.3 follows the same order: fence, then act on members.
- `Thread::close` (`kernel/src/thread.rs:257-286`) cancels waits and timers, removes the thread from the scheduler and its space, and emits `ThreadExited`. Subscribing to an exited thread emits immediately (`thread.rs:112-117`).
- Closing a `Poll` wakes all waiters with `Destroyed` (`kernel/src/poll.rs:125-135`), the analog of withdrawal.

Where the analogy breaks:

- **Durability.** FTL close is synchronous and in memory on one kernel. Chio spans durable stores, owners and external tools, so it needs fences, records and a ledger.
- **Running work.** FTL terminates threads, with an admitted SMP gap for a thread running elsewhere (`thread.rs:279-280`). Chio cannot stop a dispatched effect or a sealed permit held by another owner. The fence and the drain stop new effects and account for the rest.
- **Economic state.** FTL has none. Chio's earned claims and sealed allocations must survive closure untouched, which FTL never has to express.

### Codex review (PR #1174, round 4)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180933163 | Index process-tree ancestors for closure fences | Fixed now. Each operation records one `process_tree` ref for every process on its path, root first, from the path chio-process already loads at admission. A `ProcessTree(p)` fence on `p` therefore matches every descendant's operations by an exact join, and the dispatch CAS cannot commit a descendant after the closure. The rule 1a backfill derives the same rows | section 4.1 rule 1 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-4-01 | The process-tree fence table still names the superseded lineage key | Fixed. The `ProcessTree` row fences `(process_tree, root_process_id)` on the requested process id and explains why the root-wide security lineage would over-fence. `ProcessLivenessGuard` checks the `process_tree` refs on its path. A subtree noninterference test is added (siblings and ancestors still dispatch) | section 6.2 table; section 4.2 rule 5; section 16 |
| R-4-02 | The closure lemma claims atomic ordering for the explicitly weaker backend | Fixed. Property 4 is restricted to fences checked in the dispatch transaction's writer. A weaker property 4' covers `early_only` fences, with `dispatched_after_fence_unlinearized` reporting. Sealed D1 permits are excluded from both. The check, remote fence, local commit interleaving is a negative Apalache example | section 11; section 16 |

### Codex review (PR #1174, round 14)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186767792 | Remove the impossible second terminalization | Fixed now. The drain table is split by phase and matches spec 9's cut table. An owned `DispatchCommitted` gets exactly one terminal under the `X` row. Only `Finalizing`, including a caller report that reached it, terminalizes as `DeniedAfterDelivery` when its release meets the fence. No operation is terminalized twice | section 5 drain table |

### Independent review pass 4 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-4-03 | Closure targets legacy D1/S1 writers without joining their planned authority migration | Fixed. The `DelegationRoot` fence and `SwarmGraph` tombstone live in W1's qualified serving store and are checked in the same canonical transaction as allocation, selection, sealing and extension. Legacy adapters call the shared domain rule and are not production writers. W1's single authorized migration retains fences, tombstones, closure generation, drain and progress state, and original references, registers them in the qualified inventories, and disables the old writer. The supported landing order is W1 first. Acceptance tests cover migration, restart, legacy entry points, interruption and a stale owner. Sealed permits are never refunded or invalidated | section 6.2 table and rule 6; section 15 phase 3; section 16; open decision 8 |

### Codex review (PR #1174, round 23)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187740955 | Exclude sealed D1 permits from delegation-root fences | Fixed now. A call backed by a permit sealed before admission records `delegation_root_sealed`, which no `DelegationRoot` fence matches. Only issuance-side operations on unsealed slots record `delegation_root`, so closure stops unsealed work only, as section 6.2 requires | section 4.1 rule 1 |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-03 (spec 4 side) | A withheld result is incorrectly sufficient authority for zero-charge settlement | Fixed with spec 9 M11a. A closure refusal at release decides delivery only. With no positive reversible-hold obligation, the operation terminalizes as `DeniedAfterDelivery`. Otherwise `RefuseDelivery` records `Finalizing(DeliveryRefused)`, and the hold and journal stay with the payment owner. The drain treats that operation as drained, `Closed` admits it, and `stranded_final` lists it as a retained delivery obligation. Closure never releases, waives or captures it, and an outcome-unknown hold is released only by `MutuallyAgreedUnknown` | section 4.1 rule 3a and lemma; section 5 drain table and release rule 2; section 6.3 step 6 and predicate; section 7 item 2; section 8; section 16 test |
| R-9-05 (spec 4 side) | Delivery refusal strands a payment whose ordinary capture already completed | Fixed with spec 9 M11a. A closure refusal over a payment journal already `Final` terminalizes at once with the recorded charge or release. An in-flight intent completes under its original identity and passes the fence, then the operation terminalizes. Only an `Open` positive reversible hold is retained and listed in `stranded_final` | section 4.1 rule 3a; section 5 drain table; section 6.3 step 6; section 8; section 16 test |

### PR #1174 review round 28 (Codex)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4190476130 | Account for in-flight settlements before closing | Fixed now. Closure still does not wait for a payment rail, but `stranded_final.delivery_obligations` now lists every `DeliveryRefused` payment that a readback in the same transaction has not confirmed `Final`. Each entry carries its stage (`Open`, or `InFlight` including `ReconcileFailed`) and, for `InFlight`, the original settlement intent. A lost acknowledgement is never presumed final. Later completion is recorded by the payment evidence, not by amending the artifact | section 5 drain table; section 6.3 step 6; section 8; section 16 tests |

### Independent review pass 6 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-4-04 | Closed evidence omits an unresolved in-flight delivery payment | Fixed with round 28's comment 4190476130 (above). Acceptance cases cover persistent `ReconcileFailed`, rail unavailability, a lost capture acknowledgement and a restart before `stranded_final` | section 8; section 16 tests |

# Design: durable stop epoch

- Status: PROPOSED (revision 1, baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5)
- Date: 2026-10-04
- Scope: replace the process-local kernel emergency flag with a durable, scoped, hash-chained stop record that lives in the admission store's serving writer.
  - It is checked twice: early, from an in-memory head, and authoritatively, inside every crossing transaction.
  - It is loaded before readiness, so a restarted kernel comes up stopped.
  - It is reachable by authenticated operators.
  - It generalizes the recovery worktree's scoped semantic stop and closes ledger items EV11 and AC6.
  - It adds no revocation, no closure, and no automatic stop policy.
- Owners:
  - `chio-kernel`: stop head, dispositions, readiness, in-transaction checks.
  - `chio-store-sqlite`: stop chain table and crossing-transaction checks.
  - `chio-control-plane` and `chio-api-protect`: authenticated stop, resume, and status routes.
  - `chio-http-core`: DTOs and handlers.
  - `chio-core-types`: `StopEpochV1` and the signed artifact.
  - `chio-process`: early check before committing a call slot.
- Related:
  - M: `docs/security/native-restart-safety.md`, `docs/security/trusted-time.md`, `docs/security/kernel-signing-authority.md`, `docs/security/sidecar-control-authority.md`, `docs/security/active-defense-rollout.md`, and `docs/security/landing-ledger.json` (EV11, AC6).
  - W: `docs/architecture/recoverable-agent-runtime/` (P3 semantic remedies, the control-token profile).
  - `spec/PROTOCOL.md` section 8.
- Citation convention:
  - `M:` = `integration/process-security-m4` pinned at `19df31ad9`. The remote branch has since moved to `60ec98d6f`, and no M: line cited here differs between the two for the stop surfaces.
  - `V:` = `origin/work/verifiable-work-session-20261003` at `14477aaac`.
  - `R:` = `origin/research/openappa-recovery-20261001` at `de84fc306`.
  - `W:` = the uncommitted recovery working tree at `standalone/arc-worktrees/recoverable-agent-runtime-20261002`. Its line references reflect 2026-10-04 and may drift.
  - `P:` = `feat/process-command-experience-20260924`.
  - W1-W4 and the doc-only R: names are contract anchors.
- Origin: the FTL (nuta/ftl) review, brainstorm candidate 2 (`docs/research/2026-10-04-ftl-lessons-brainstorm.md`), and umbrella defect D2.
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`.

## 1. Decision summary

Today's kernel stop is a fail-closed latch with good ordering, but it is not an operational kill switch:

- It is three process-local atomics, initialized to "running" at construction. A restart silently resumes.
- Its HTTP handlers exist but no substrate mounts them, and their token comparison is not constant-time.
- Two admission paths never consult it.

The ledger records this as EV11 ("There is no operator-reachable emergency stop") and AC6 ("the emergency stop is process-local"). Both carry the claim limit "no restart-durable or operator-reachable stop claim".

The recovery worktree already has the right durable shape for one narrow scope. `set_semantic_emergency_stop(scope, bool)` writes a versioned, hash-chained record through the serving writer, and four store transactions read it before they act. It lacks authorization, a reason, an authorizer, time, and evidence, and it covers only semantic remedies.

This design generalizes that template:

1. **One chain.** `StopEpochV1` records live in an append-only, hash-chained table in the admission store's serving writer. They are covered by the global commit chain. There is one head per `StopScope`: kernel, tenant, or recovery scope. The semantic stop becomes the recovery scope of this chain, and its check points are kept.
2. **Two tiers.**
   - Tier 1: an in-memory head gives the cheap early deny at every existing check site.
   - Tier 2: an authoritative check inside every crossing transaction (dispatch commit, native capture, recovery and semantic capture, P4 release, P5 return admission). Tier 2 decides.
3. **Boot.** Startup reconciliation loads and verifies the heads before readiness. An unreadable or broken chain means not ready.
4. **Dispositions.** Every L0 op, every recovery command variant, and every work action has a recorded stop disposition. Revocation, verification, receipt signing, reconcile, settlement, cancel, inspect, shutdown, and stop control stay available. Governed active response stays available because every effect it can admit narrows authority.
5. **Asymmetric authorization.** Stopping needs one authorized operator, by scope. Resuming needs a different authorized principal, or a configured threshold. A trusted host's component-failure latch stays process-local.
6. **Evidence.** Each transition is a signed `chio.stop-epoch.v1` artifact, a trace event, and a SIEM export.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| The stop is three atomics initialized at construction: `emergency_stopped: AtomicBool::new(false)`, `emergency_stopped_since`, and `emergency_stop_reason` | M: `crates/kernel/chio-kernel/src/kernel/construction.rs:369-371` |
| `emergency_stop` publishes the flag before reading fallible authority time (the AC6 ordering repair). `emergency_resume` clears it. The doc anticipates a future `revoke_all` | M: `construction.rs:1656-1706`, `:1670` |
| `shutdown` does not stop admission. "Operators that want a hard stop should call `emergency_stop` in addition" | M: `construction.rs:745-757` |
| In-memory check sites: evaluation entry, async and nested evaluation, dispatch, native capture, native egress lifecycle, caller output release, native output release, approval collection, finding pool | M: `kernel/evaluation/evaluation_entry.rs:54`, `:343`; `async_evaluation_core.rs:39`; `nested_flow_evaluation.rs:121`; `kernel/dispatch.rs:712`; `credential_reservation/native_dispatch.rs:103`; `admission_coordinator/native_egress/lifecycle.rs:80`; `admission_coordinator/terminal.rs:126`; `admission_coordinator/native_output.rs:396`; `admission_coordinator/collection_context.rs:64`; `finding_pool.rs:720` |
| No check in issuance or governed active response | M: zero `emergency` references in `kernel/validation/issuance.rs` (`issue_capability` at `:10`), `governed_active_response.rs` (`admit_governed_active_response` at `:135`) and `kernel/active_response_executor.rs` |
| Every check is a flag read outside the writer transaction, so the authoritative mutation can race a stop | the sites above; contrast M: `crates/platform/chio-store-sqlite/src/admission_operation_store.rs:350-363` (`begin_write`: IMMEDIATE, `verify_active_owner`, `verify_authority_anchor`) |
| The HTTP handlers authenticate an `X-Admin-Token` with `token == expected` (not constant time). No crate outside `chio-http-core` and its tests mounts them | M: `crates/platform/chio-http-core/src/emergency.rs:188-196`, `:210`, `:229`, `:240`; route constants at `routes.rs:33` |
| The control credential precedent requires a constant-time comparator and a validated bearer token | M: `docs/security/sidecar-control-authority.md:8-24` |
| A trusted host latches the stop programmatically on component failure | M: `crates/products/chio-cli/src/cli/process_host/native_broker/authority.rs:114` |
| EV11 and AC6 are `open-acceptance`. EV11 requires "authenticated durable operator stop and restart behavior" before an operational kill-switch claim | M: `docs/security/landing-ledger.json:5066`, `:5118` |
| A new serving epoch fences the old owner and reconciles before declaring readiness. Unresolved release custody blocks readiness | M: `docs/security/native-restart-safety.md:26-30`, `:107-111` |
| Startup reconciliation is the readiness latch | M: `kernel/admission_coordinator/recovery.rs:108-117`; `admission_coordinator.rs:137` |
| Template: `set_semantic_emergency_stop(scope, stop: bool)` saves key `semantic-stop:{scope_key}`, kind `command`, through the serving writer | W: `crates/platform/chio-store-sqlite/src/admission_operation_store/semantic.rs:369-386` |
| Template persistence: version plus 1, immutable identity, and a hash-chained event per record version under recovery quotas | W: `.../admission_operation_store/recovery/storage.rs:157-200` |
| Template check points: `stopped(tx, scope)` (`semantic.rs:144-146`) runs inside plan acceptance (`:270`), `verify_capture_tx` (`semantic/capture.rs:47`), `captured_semantic_output_disposition` for `ReturnValue` (`:294`), and `semantic_dispatch_capture` (`:336`) | W: as cited |
| Template gaps: the payload is a bare `bool`, the store method takes no actor, and the only caller is a test | W: `semantic.rs:369-386`; `crates/platform/chio-control-plane/src/recovery/tests/semantic.rs:443` |
| Recovery control tokens must be direct, with no delegation chain, caveats, or attenuation | W: `crates/kernel/chio-kernel/src/recovery/ports.rs:200-215` |
| Every `GovernedResponseEffect` narrows authority: `ThrottleSession`, `RestrictEgress`, `SuspendSession`, `SuspendCapabilitySet`, `FreezeIssuance` | M: `crates/core/chio-core-types/src/capability/governance.rs:769-775` |
| "Permanent revocation remains manual" | M: `docs/security/active-defense-rollout.md:23` |
| A process commits its call slot before calling the kernel, and retains it after a later failure | M: `crates/kernel/chio-process/ARCHITECTURE.md:40-45` |

## 3. Goals and non-goals

Goals:

- A stop survives restart, crash, and serving-owner replacement. A restarted kernel comes up stopped.
- Operators can reach it through authenticated, mounted routes and a CLI.
- No effect crosses custody after the stop commits in the writer that orders that crossing.
- Every op and command has a recorded disposition, so no path is unchecked by accident.
- Stopping is easy, resuming is deliberate, and both are signed evidence.

Non-goals:

- Revoking capabilities, closing spaces, or draining work. That is `2026-10-04-authority-space-teardown-design.md`, and permanent revocation remains manual.
- Recalling effects that already crossed.
- Automatic stops from detection. Active defense keeps its own overlays.
- Stopping a remote kernel. Federation publication is informational only (section 12).

## 4. Stop record and chain

```rust
// chio-core-types::stop (closed; wire schema chio.stop-epoch.v1)
pub enum StopScope {
    Kernel,                                  // this serving authority
    Tenant { tenant_id: TenantId },
    Recovery { scope: RecoveryScopeV1 },     // replaces W:'s semantic-stop record
}

pub enum StopState { Stopped, Running }

pub struct StopEpochV1 {
    pub schema: String,                      // "chio.stop-epoch.v1"
    pub authority_id: DurableAuthorityId,    // serving authority, from the anchor
    pub scope: StopScope,
    pub epoch: u64,                          // per scope, +1 per transition, starts at 1
    pub state: StopState,
    pub reason_hash: Sha256Digest,           // operator text is retained separately, redacted
    pub authorizer: StopAuthorizer,          // operator principal(s) and approval reference
    pub decided_at: AuthorityTime,           // fallible authority clock; see rule S4
    pub previous: Sha256Digest,              // digest of this scope's prior record, or zero
    pub allow_containment: bool,             // section 7.2
}

pub enum StopAuthorizer {
    Operator { principal: PrincipalId },
    OperatorPair { stopper_epoch: u64, resumer: PrincipalId },
    Threshold { proposal_id: String, approval_set_hash: Sha256Digest },
}
```

Normative rules:

1. **S1. Writer.** Records are appended in a new table, `admission_operation_stop_epochs(scope_key, epoch, record_digest, previous_digest, payload)`. The append happens through the admission store's `begin_write` (IMMEDIATE, active-owner and anchor checks; M: `admission_operation_store.rs:350-363`), with `commit_write` and `sync_after_write`. The table is append-only: no update or delete trigger.
2. **S2. Chain.** For each scope, `epoch` increases by exactly 1, `previous` equals the digest of the prior record, and the state alternates. A stop over a stopped head, or a resume over a running head, is an idempotent no-op that returns the current head. The table joins the global commit chain projection coverage, as recovery events do.
3. **S3. Head.** The head for a scope is the highest epoch. A scope with no record is `Running`. The effective state for a crossing is `Stopped` if any applicable scope head is `Stopped` (section 5).
4. **S4. Time.** `decided_at` comes from `observe_authority_time` inside the write transaction. If time is unavailable, a *stop* still commits with `decided_at = Unavailable`, preserving the AC6 rule that stopping never depends on the clock. A *resume* without authority time refuses.
5. **S5. Migration of the template.** At startup, any existing W: `semantic-stop:{scope}` record whose value is `true` becomes a `Recovery` scope head, written as epoch 1 with authorizer `Operator { legacy }`. The four W: check points call the unified `stop_state(tx, &[Recovery(scope), Tenant(t), Kernel])` in place of `stopped(tx, scope)`. `set_semantic_emergency_stop` becomes a thin wrapper that requires an authenticated actor (section 9).
6. **S6. Bounds.** A record is at most 4 KiB, and a scope keeps at most 65,536 records. Exhaustion refuses resume, never stop: a stop past the bound overwrites nothing and latches in memory, and readiness then reports the exhausted chain.

## 5. Two-tier enforcement

**Tier 1 (early deny).** `StopHead` is an `ArcSwap<StopHeads>` loaded at boot and swapped after each committed transition.
- Every existing M: check site reads it in place of `emergency_stopped`, and each site asks for its applicable scopes.
- The process runtime reads it through a kernel accessor before committing a call slot, so a stop does not burn process call budget.

Tier 1 may lag tier 2 by one transition. It never decides an effect.

**Tier 2 (authoritative).** Each crossing transaction evaluates `stop_state(tx, scopes)` inside its own writer transaction, before the state change that lets the effect cross. The crossing table is `2026-10-04-authority-space-teardown-design.md` section 4.3:

| Crossing | Transaction that checks | Scopes |
|---|---|---|
| Durable tool dispatch | the `DispatchCommitted` CAS from `commit_durable_dispatch` and `capture_and_commit_durable_dispatch` (M: `admission_coordinator.rs:1560`, `:1814`) | Kernel, Tenant |
| Native capture | the capture transaction behind `native_dispatch.rs:103` | Kernel, Tenant |
| Recovery continuation | the same-writer tombstone transactions at begin and capture (W: `recovery/native.rs:286-293`) | Kernel, Tenant, Recovery |
| Semantic remedy | W: `semantic.rs:270`; `semantic/capture.rs:47`, `:294`, `:336` | Kernel, Tenant, Recovery |
| Caller and native output release | the release checkpoint transactions behind M: `terminal.rs:126` and `native_output.rs:396` | Kernel, Tenant |
| P4 artifact release | the commit of the knowledge join and `ReleaseIntent` | Kernel, Tenant |
| P5 confined return | the final serialized activity read before sink I/O (W: `chio-control-plane/src/confinement.rs:234-236`) | Kernel, Tenant |

Rules:

7. **S7. Tier 2 decides.** A crossing transaction that observes `Stopped` fails with `KernelStopped { scope, epoch }` and makes no state change. The caller follows its existing pre-crossing failure path (section 8).
8. **S8. Issuance is defense in depth.** Capability issuance runs in the capability authority store, which is not the admission writer. It checks tier 1, plus a tier 2 read of the stop head in a separate read transaction. A capability minted in that race still cannot cross, because every crossing is fenced by S7.

```text
committed(stop(s, e)) before cas(op -> DispatchCommitted) and scope(op) includes s
  -> not DispatchCommitted(op)
DispatchCommitted(op) before committed(stop(s, e)) -> effect may proceed; release is
  re-checked at its own crossing (S7)
stopped(head) and crossing(x) in applicable(head) -> not crossed_after(x, stop_commit)
```

## 6. Boot and readiness

9. **S9. Load before serving.** `reconcile_durable_admission_startup` (M: `recovery.rs:108`) loads every scope head inside the startup transaction. It verifies S2 for each chain, installs `StopHeads`, and only then sets `startup_reconciled`. A missing table, a digest mismatch, or an epoch gap leaves the kernel not ready, with reason `stop_chain_unverified`.
10. **S10. Come up stopped.** A stopped head at boot keeps every `deny` disposition denied from the first request. The status route reports `stopped` with epoch, scope, authorizer, and `decided_at`.
11. **S11. No durable store, no durable claim.** A kernel without a durable admission runtime (ephemeral development profiles) keeps today's process-local behavior. Its status reports `durability: process_local`. A profile that requires durable admission, such as the work profiles and process runtimes, also gets the durable stop.

## 7. Dispositions

### 7.1 L0 ops (spec 1 rule R5)

| Disposition | Ops | Rationale |
|---|---|---|
| `deny` | `EvaluateToolCall`, `EvaluatePlan`, `EvaluateSessionOperation`, `EvaluateNestedRequest`, `ConsumeExecutionNonce`, `DebitFindingPoolPurchase`, `IssueCapability`, `UpdateLiveTrust`, `ManageDelegationParent`, `RecoveryDisclosureIssuance` | admit an effect, or widen live trust |
| `allow` | `VerifyCapability`, `VerifyPassport`, `VerifyReceipt`, `VerifyDpopPreview` | pure |
| `allow` | `SignReceipt`, `SignReceiptRelayingTrustedBody`, `ExportExecutionEvidence` | deny and terminal receipts must still be signable; export is historical |
| `allow` | `SessionOpen`, `SessionRequest`, `SessionEventRelay`, `SessionClose` | no effect of their own; every effect-bearing request reaches a denied Admit op; clients must still connect, cancel, and receive the stop hint |
| `allow` | `RevokeCapability`, `EmergencyControl`, `Reconcile`, `ObserveSettlement`, `Shutdown` | narrow authority, control the stop, or settle the past |
| `allow` (S12) | `AdmitGovernedActiveResponse` | every `GovernedResponseEffect` narrows authority |
| per entry point (S13) | `CallerExecution` | reserve and start deny; report and reconcile allow |
| per variant (R5a) | `RecoveryControl` | `InspectWorkflow` and `CancelWorkflow` allow; every other variant denies |

12. **S12. Containment during a stop.** `AdmitGovernedActiveResponse` is `allow` only while the closed `GovernedResponseEffect` enum (M: `governance.rs:769-775`) contains only authority-narrowing effects.
    - The disposition function matches that enum exhaustively, so adding a variant forces a new disposition decision.
    - Admission still requires its threshold approval.
    - When a stop record sets `allow_containment = false`, containment is denied too, for incidents where the active-defense authorities themselves are suspect.
13. **S13. Per-entry-point dispositions.** This proposes rule R5b for spec 1. An op whose entry points differ in direction (begin versus observe) declares dispositions per entry point. The only use today is `CallerExecution`: `reserve_` and `start_` deny, while `reconcile_caller_execution*` and authenticated reports allow, because the effect already happened.

### 7.2 Higher layers (rule R12 inheritance)

- **L1 process ABI.**
  - `invoke` denies through `EvaluateToolCall`, and tier 1 denies before the slot commits.
  - `inspect`, `checkpoint`, `blob_put`, `blob_read`, and `cancel` allow. They are local, credential-scoped state and cross no custody boundary.
  - Native tools behind `invoke`, including mailbox send, spawn, and `wait_children`, deny with `invoke`.
- **L2 work (contract anchors).** `Delegate`, `Select`, `Seal`, `Extend`, and `Submit` deny. `Reconcile`, `Cancel`, and every `WorkQueryV1` allow.
- **L3 recovery.**
  - `CreateWorkflow`, `SelectOffer`, `SubmitApproval`, `ResumeWorkflow`, `ReportDecision`, and `/v1/recovery/review` deny.
  - `InspectWorkflow`, `CancelWorkflow`, `/v1/recovery/settle`, and `/v1/recovery/explain` allow.
  - Explain is pure advisory, and settle records provider finality for effects that already happened.

```text
forall op in KernelOp: disposition(op) defined           (kani: total, exhaustive)
forall v in RecoveryCommandBodyV1: disposition(v) defined
disposition(op) = deny and stopped(scope(op)) -> refused(op) at tier 1 and tier 2
```

## 8. In-flight work and approvals

14. **S14. No recall.** An operation whose crossing committed before the stop is not recalled. Its later crossings (output release, P4 release, P5 return) are separate crossings, and are withheld while stopped.
    - Withheld output keeps its release custody. It is released after resume through the existing replay path.
    - It is never re-dispatched. This matches M: `terminal.rs:126` ("does not exempt a later delivery from the current stop state").
15. **S15. Pre-crossing failure.** An operation that fails S7 before `DispatchCommitted` takes its existing pre-dispatch failure path. It compensates under `PreDispatchNoEffect` and signs a deny receipt with reason `kernel_stopped`.
    - Its request id is then terminal, so a client retries after resume under a new request id.
    - This design adds no parking state and no drain.
16. **S16. Approvals.** Approval collection denies while stopped (M: `collection_context.rs:64`). Pending approvals stay pending and expire by their own deadlines, and a resolution after resume still meets the live checks.
    - Recovery approvals cannot proceed, because `SubmitApproval` and `ResumeWorkflow` deny.
17. **S17. Closure is separate.** A stop never revokes, fences spaces, or drains. An operator who wants permanent effect submits a closure (spec 4) while stopped. Closure ops are allowed because they only revoke, fence, compensate, and withdraw.

## 9. Authorization

18. **S18. Stop.**
    - Any principal on the operator roster with stop permission for the scope may stop it: kernel scope needs kernel-operator permission, and tenant scope needs that tenant's operator.
    - Stop tokens follow the recovery control-token profile: direct tokens, with no delegation chain, caveats, or attenuation (W: `recovery/ports.rs:200-215`).
    - The routes are mounted on the control plane and the API-protect sidecar, behind the sidecar control authority's validated bearer credential and constant-time comparison (M: `sidecar-control-authority.md:8-24`). The `X-Admin-Token` string comparison (M: `emergency.rs:193`) is replaced.
19. **S19. Resume.**
    - Resume requires a principal on the roster different from every authorizer of the stop being resumed (`OperatorPair`).
    - Alternatively, when the deployment configures it, a threshold proposal collected through `ThresholdApprovalCollector`, recorded as `Threshold`.
    - A single-operator deployment may configure `SamePrincipalAfter { cooldown >= 300 s }` explicitly in signed deployment configuration. The record then names that policy.
    - An unavailable roster or collector leaves the scope stopped.
20. **S20. Host latch.**
    - Programmatic `emergency_stop(reason)` from trusted host code, such as the broker authority failure at M: `native_broker/authority.rs:114`, remains a process-local latch, ORed with the durable heads.
    - It needs no operator to resume. A fresh process either re-establishes the failed component or fails readiness.
    - The status route reports it separately as `host_latch`.
21. **S21. Order.** A resume of a tenant scope never clears a kernel-scope stop, and a kernel resume never clears tenant stops. Scopes are independent heads.

## 10. Evidence

- **Artifact.** Each committed transition produces a signed `chio.stop-epoch.v1` artifact: the `StopEpochV1` body, signed by the boot-installed receipt signer (M: `kernel-signing-authority.md:3`, `:29`).
- **Trace.** `RuntimeTraceEvent::StopEpochTransition { scope, epoch, state }` joins the existing trace events. The SIEM exporter emits the artifact.
- **Status route.** It returns `{ stopped, scope_heads: [...], host_latch, durability }`. The existing `stopped`, `since`, and `reason` fields stay as a projection of the kernel-scope head, with `reason` redacted to the operator-visible text.
- **Deny receipts.** Every deny receipt produced by a stop carries `chio_runtime.stop = { scope, epoch }`, so an auditor can join any refused request to the transition that refused it.

## 11. Hints (cross-spec edit to spec 5)

A stop is reversible, so it is never `Terminal`. This design proposes one subject for `2026-10-04-unified-event-queue-design.md`: `HintSubject::Stop { scope_ref }` with `HintKind::Changed`, meaning "re-read the stop status".

- **Kernel sessions.** Each session in an affected scope receives it, after the transition commits (H2).
- **Processes.** The process `hint_revision` advances for processes in an affected tenant or the kernel scope, after the commit. A waiting `inspect` returns, and the worker reads the status, or simply observes that `invoke` denies.
- **H9 audience.** Tenant-scope stops are visible only to that tenant's sessions and processes. The kernel scope is visible to all.

## 12. Federation

22. **S22. Informational publication.** A serving authority may publish its kernel-scope `chio.stop-epoch.v1` artifacts to treaty peers over iroh lane b, beside revocation epoch roots (V: `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs:1-8`).
    - A peer may use it as an input to its own local policy, for example refusing to start new cross-owner work with a stopped owner.
    - It confers no authority, cannot stop the peer, and is never required for safety.

## 13. Multi-instance and degraded backends

- **One owner per store.** The serving-owner model gives one active writer per admission store. Instances that share a store share the chain, and a replacement owner reloads it at S9.
- **Separate stores.** Kernels with separate stores have separate chains. A fleet stop is a control-plane fan-out, reported per authority, and is never claimed atomic.
- **Degraded backends.** When a crossing's ordering writer is not the admission writer (for example a remote revocation backend, or capability issuance per S8), that crossing gets tier 1 plus a separate read. The status route then lists it as `stop_enforcement: early_only`.

## 14. Failure modes

| Failure | Behavior |
|---|---|
| Stop write fails to commit | Tier 1 latches anyway (AC6 ordering); the route returns non-2xx `stop_not_durable`; readiness reports it; retry is idempotent |
| Commit outcome unknown | Serving owner marks outcome unknown (M: `admission_operation_store.rs` `commit_write`); the kernel stays latched until restart reloads the chain |
| Chain unreadable or invalid at boot | Not ready (S9) |
| Authority clock unavailable | Stop commits with `Unavailable` time; resume refuses (S4) |
| Roster or collector unavailable | Resume refuses; stop is unaffected |
| Tier 1 stale | Tier 2 decides every crossing (S7) |
| Crash after commit, before head swap | Restart loads the committed head; the kernel comes up stopped |
| Chain bound reached | Resume refuses; stop latches; readiness reports exhaustion (S6) |

## 15. Protocol, schema, and wire impact

- **Schemas.** New `chio.stop-epoch.v1` record and artifact under `spec/schemas/`, with codegen and vectors.
- **`spec/PROTOCOL.md` section 8.**
  - Mounted stop, resume, and status routes on the control plane and the sidecar, with their credential.
  - The status response shape (additive fields).
  - The deny reason `kernel_stopped` and the `chio_runtime.stop` receipt metadata.
- **Ledger.** EV11 and AC6 acceptance evidence is listed in section 17. AC6's ordering repair is preserved by S4.
- **Native wire.** No change. Verdicts and receipt kinds are unchanged.

## 16. Rollout

1. **Chain and boot.** Stop table, chain verification, S9 boot load and readiness, kernel scope only. Tier 1 replaces the atomics behind `is_emergency_stopped()`. Routes mounted behind the control credential. Status `durability`.
2. **Tier 2.** In-transaction checks at dispatch commit and native capture, then the release crossings. Issuance defense in depth (S8). Process early check.
3. **Scopes.** Tenant scope. Recovery scope with migration of the W: semantic stop (S5).
4. **Authorization and evidence.** Resume policy (S19), signed artifacts, trace and SIEM, deny receipt metadata, hints (section 11).
5. **Federation.** Lane b publication (S22).

Every phase ships behind `durable-stop` until its conformance scenarios pass. Hardening gate GT1 applies: no EV11 claim until the scenarios run in hosted CI.

## 17. Tests and conformance evidence

- **Loom:** a stop commit racing a `DispatchCommitted` CAS gives exactly one order; with a stale tier 1, tier 2 still refuses the post-stop crossing.
- **Crash injection** (store test hooks):
  - commit stop, kill before the head swap, restart: the kernel comes up stopped;
  - kill mid-resume before commit, restart: still stopped;
  - kill after resume commit: running.
- **DST:** random stop, resume, dispatch, release, and recovery capture sequences. Property: no crossing commits with an index after a `Stopped` head commit in an applicable scope.
- **Kani:** disposition totality over `KernelOp`, `RecoveryCommandBodyV1`, and `GovernedResponseEffect`.
- **Unit:**
  - chain rules S2 (gap, mismatch, idempotent repeat);
  - S4 clock behavior;
  - S5 migration of a legacy `semantic-stop` record;
  - constant-time credential comparison;
  - distinct-principal resume;
  - host latch independence (S20).
- **Conformance** (`chio-conformance`, EV11 evidence):
  - operator stop through the mounted route;
  - process restart comes up stopped;
  - a tool call, a recovery resume, and a P5 return all deny while stopped;
  - revocation, closure, cancel, and inspect still work;
  - resume by the same principal is refused;
  - resume by a second principal succeeds.

## 18. Residual risks and open decisions

Residual risks:

- **Pre-stop crossings.** Effects whose crossing committed before the stop complete. Only their later releases are withheld.
- **Early-only crossings.** Crossings whose ordering writer is not the admission writer get tier 1 only.
- **Cross-owner work.** A stop does not reach a remote owner's kernel, so cross-owner work already sealed elsewhere continues there.
- **Burned request ids.** Pre-dispatch failures burn request ids (S15). Clients need new ids after resume.

Open decisions:

1. **Single-operator resume.** Is the default `OperatorPair`, with `SamePrincipalAfter` opt-in, right? Recommendation: yes.
2. **Containment.** Should containment during a stop default to allowed (S12), with `allow_containment = false` as the stricter option? Recommendation: allowed by default, because every current effect narrows authority.
3. **R5b.** Should spec 1 adopt R5b (per-entry-point dispositions), or should `CallerExecution` split into two ops?
4. **Recovery scope merge.** Should the recovery scope keep its own table during migration, or merge immediately (S5)? Recommendation: merge, because the template has no production caller.
5. **Federation consumption.** Should treaty peers be allowed to make a published stop a mandatory local deny for new cross-owner work, or only advisory?
6. **Pre-dispatch parking.** Should pre-dispatch operations park instead of compensating (S15), to preserve request ids across a short stop? This needs a new admission state, and this design declines it.

## Appendix A. FTL reference

What FTL does (`/Users/connor/Medica/backbay/ftl`):

- **Boot ordering.** `boot` initializes memory, CPU state, and drivers, and loads the first thread before the scheduler runs any user code (`kernel/src/boot.rs:39-45`). Nothing user-visible runs until boot completes. Section 6's "load before serving" is the same ordering.
- **Destroyed flag.** A handle space's `destroyed` flag is checked under the space lock by every insert (`kernel/src/hspace.rs:46`, `:90`), and set under the same lock at close (`:169`). Tier 2 is that pattern: the stop is checked inside the same writer transaction as the state change it guards.

Where the analogy breaks:

- **Durability.** FTL has no persistent state, and a reboot always starts fresh. A Chio restart must come up stopped, so the flag must be durable and verified before readiness.
- **Reversibility.** FTL's `destroyed` flag is terminal. A Chio stop is reversible, so it needs epochs, a chain, and an authorization asymmetry between stop and resume.
- **Ordering writers.** FTL has one lock per object. Chio has several writers, and a crossing in a different writer than the stop gets only the early check (section 13).

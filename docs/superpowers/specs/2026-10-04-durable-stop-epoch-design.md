# Design: durable stop epoch

- Status: PROPOSED (revision 2, baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5; revised 2026-10-05 after adversarial review)
- Date: 2026-10-04
- Scope: replace the process-local kernel emergency flag with a durable, scoped, hash-chained stop record that lives in the admission store's serving writer.
  - It is checked twice: early, from in-memory heads shared by every kernel attached to the store, and authoritatively, inside every crossing transaction, with a disposition per crossing kind.
  - It is loaded before the startup reconciliation sweep, so a restarted kernel comes up `ready_stopped`, serving its status, stop and resume routes.
  - It is reachable by authenticated operators through mounted routes, a process-host control socket, and a CLI that also works while the host is down.
  - It generalizes the recovery worktree's scoped semantic stop. It closes ledger item EV11 at phase 1 and preserves the AC6 ordering repair. AC6 itself closes before this design lands, with a document and a test (section 16).
  - It adds no revocation, no closure, and no automatic stop policy.
- Owners:
  - `chio-kernel`: stop heads, dispositions, readiness, typed `KernelStopped`, the stop-aware reconciliation sweep.
  - `chio-store-sqlite`: stop chain table, stop-intent journal file, signing obligations, in-transaction checks.
  - `chio-control-plane`, `chio-api-protect` and `chio-mcp-remote`: mounted stop, restrict, resume and status routes; one shared `StopHeads` per store.
  - `chio-cli`: process-host control socket, operator CLI, offline stop.
  - `chio-http-core`: DTOs and handlers.
  - `chio-core-types`: `StopEpochV1`, the stop-control quorum artifact, and the signed artifact.
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
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md` (spec 1), `2026-10-04-authority-faults-design.md` (spec 2), `2026-10-04-typed-reservations-design.md` (spec 3), `2026-10-04-authority-space-teardown-design.md` (spec 4), `2026-10-04-unified-event-queue-design.md` (spec 5), `2026-10-04-opaque-adapter-context-design.md` (spec 6), `2026-10-04-microkernel-isolation-backend-design.md` (spec 7), `2026-10-04-pure-admission-machine-design.md` (spec 9), `2026-10-04-crossing-primitive-design.md` (spec 10), `2026-10-04-integrity-gated-admission-design.md` (spec 11).

## Revision 2 changes

The adversarial review (1 Blocker, 15 Major, 11 Minor, 3 Nit) found that revision 1 could not start a host restarted mid-stop, could lose an operator's stop, assumed identity infrastructure that does not exist, and disagreed with specs 9 and 10 in several places. Revision 2:

- **Boot (S8-01).** Heads load before the reconciliation sweep. The sweep treats `KernelStopped` as Retain, never as a failure. A new readiness state `ready_stopped` serves status, stop and resume. Withheld output keeps durable custody across restart (S9, S10, S26).
- **Stop durability (S8-03).** A fsynced stop-intent latch is written before the stop transaction (S25). Resumes refuse at `bound - 1`, so a stop can always append (S6). Stop transitions use a priority lane in spec 10's writer loop (S36). The route reports `stop_durable`, `stop_not_durable` or `stop_outcome_unknown`.
- **Shared heads (S8-02, S8-08).** `StopHeads` belongs to the store or runtime handle, so every kernel in the process shares it, including api-protect's per-request authority kernel. Every crossing evaluates durable heads together with process latches (S23, S24). "Lags by one transition" is replaced by the real bound.
- **Authorization (S8-04 to S8-07).**
  - Phases before identity record `StopAuthorizer::SharedCredential`.
  - Two-person resume depends on a named prerequisite: signed operator capability tokens, with a roster in signed deployment configuration (S28).
  - Quorum resume uses an offline-verified `chio.stop-control-quorum.v1` artifact, not `ThresholdApprovalCollector` (S29).
  - Stop authentication never needs authority time.
  - The cooldown starts at the first successful authority-time observation after the stop.
  - Break-glass resume carries a signed time attestation.
  - `decided_at` is a closed `DecisionTime` enum.
- **Operator reach (S8-09).** The process host gets a control socket. The CLI drives it, and it can stop offline when the host is down (S30).
- **Dispositions (S8-10, S8-11, S8-27).** Section 5 is now the normative stop disposition for each `CrossingKind` (`Deny`, `Withhold`, `Settle`, `AllowIfContainment`), matching spec 10 section 4.2. The P5 point is the `admit_confined_return` commit. A host latch implies `allow_containment = false`.
- **Refusals per path (S8-12, S8-17, S8-18, S8-19).**
  - `KernelStopped` is a temporary refusal: no deny tombstone, and request ids are not burned except on the slow path with a begin row, as on M: today.
  - The caller report is a progress-only return record that is never stop-checked (S27).
  - A two-commit read refused at the outcome commit writes a return record and is never re-dispatched.
  - Parked operations are retained.
  - A new wire result, `OutputWithheld`, tells the client.
- **Sharding (S8-13).** Shards hold verified replicas, and shard readiness requires the origin head epoch. The acknowledgement does not block on dead shards (S37).
- **Restore, upgrade and downgrade (S8-14).** A new section, 13a, covers the schema version bump, distinguishes a table absent before migration from one missing after migration, and adds tests (S34).
- **Issuance (S8-15, S8-16).** Every mint path is enumerated (S8). HTTP authority's internal capability counts as `EvaluateToolCall`. Control-profile issuance is carved out after S28.
- **Chain and scope gaps (S8-20 to S8-23).**
  - New `Restrict` and `Relax` transitions; every transition carries `expected_epoch` (S31).
  - Per-entry-point rows for `RecoveryControl`; `ManageDelegationParent` stays `deny`, as spec 1 already says.
  - A typed `KernelStopped` from the recovery store, so recovery workflows pause and are never terminated (S35).
  - Recovery-scope stop authority (S32).
  - Tenant attribution (S33).
- **Evidence, tests and proof tools (S8-25, S8-26, S8-28 to S8-30).**
  - The serving-authority store signs. Deny receipts carry `observed_epoch`.
  - The lane b extension is named.
  - The reason is a salted commitment.
  - Test cases are added for every gap the review found.
  - The Kani totality claim is withdrawn in favor of compiler exhaustiveness plus spec 1's census. Loom models only the writer loop and the heads.
- **Rollout (S8-24).** Phase 1 is the minimal honest phase that closes EV11 (section 16). Phase 2 is spec 10's `StopEpoch` `CrossingCheck`. The spec 9 dependency is named.

**Codex review (PR #1174, round 1).** S6 lets a stop or restrict fill the last slot, so exhaustion always ends `Stopped`. S19 binds the resume to the stored cooldown origin. S25 keys the intent journal by scope. S37 adds an origin-freshness lease for serving shards. New S38 defines the signing obligation.

**Codex review (PR #1174, round 8).** S2 gains per-transition field rules. An automatic `Rollover` is representable without a fake request: `requested_via: SystemRollover`, `authorizer: ChainRollover { serving_owner, writer_epoch }`, no contributors, and a fixed reason commitment over the restated head. The contributor invariant applies only to `Stop`, `Restrict`, `Relax` and `Resume`. S37's origin-freshness lease renews only from a signed, challenge-bound response, extends only to `sent_at + lease`, and ignores heartbeats for renewal, so replay can never extend it.

**Codex review (PR #1174, round 7).** Records carry a signed `chain_generation`, and positions compare as `StopEpochId = (chain_generation, epoch)` everywhere: heads, `expected_epoch`, replicas, floors and observed epochs. A `Rollover` record starts each new generation and restates the head, so a rollover never changes `Stopped` or `Running` (S2, S6, S37).

**Independent review pass 5 (R-8-03).** A stopper whose pending intent is retired by an offline bypass now stays in the incident's stopper set.
- A `SubsumedIntent` snapshot carries the entry's contributors, bound to the entry by a recomputable `entry_digest`.
- An entry that an unreadable-journal bypass covered is retired only after a new state-preserving `Reconcile` record carries its snapshot on the same chain. A progress-only note no longer does it.
- S19's stopper set includes every snapshot's contributors. New S19a takes exclusions only from chain records, and resume waits for the reconciliation (S19, S19a, S25, S25a).

## 1. Decision summary

Today's kernel stop is a fail-closed latch with good ordering, but it is not an operational kill switch:

- It is three process-local atomics, initialized to "running" at construction. A restart silently resumes.
- Its HTTP handlers exist but no substrate mounts them, and their token comparison is not constant-time.
- Issuance and governed active response never consult it.
- Each hosted session builds its own kernel, so a programmatic stop in one kernel does not reach the others.

The ledger records this as EV11 ("There is no operator-reachable emergency stop") and AC6 ("the emergency stop is process-local"). Both carry the claim limit "no restart-durable or operator-reachable stop claim".

The recovery worktree already has the right durable shape for one narrow scope. `set_semantic_emergency_stop(scope, bool)` writes a versioned, hash-chained record through the serving writer, and four store transactions read it before they act. It lacks authorization, a reason, an authorizer, time, and evidence, and it covers only semantic remedies.

This design generalizes that template:

1. **One chain.**
   - `StopEpochV1` records live in an append-only, hash-chained table in the admission store's serving writer, covered by the global commit chain.
   - There is one head per `StopScope`: kernel, tenant, or recovery scope.
   - A fsynced stop-intent latch, written before the transaction, keeps a stop alive across restart even when its commit fails.
2. **Two tiers.**
   - Tier 1: in-memory heads, shared per store across every kernel in the process, give the cheap early deny at every existing check site.
   - Tier 2: an authoritative check inside every crossing transaction, with the disposition of that crossing kind (section 5). Tier 2 decides.
3. **Boot.**
   - Heads load and verify before the reconciliation sweep.
   - The sweep retains stop-withheld operations rather than failing.
   - The host serves `ready_stopped`.
   - An unreadable or broken chain means not ready, but the stop and status routes still answer.
4. **Dispositions.** Every crossing kind, every L0 op and entry point, every recovery command variant, and every work action has a recorded stop disposition.
   - Revocation, verification, receipt signing, reconcile, settlement of past effects, cancel, inspect, shutdown and stop control stay available.
   - Governed active response stays available unless the stop forbids containment.
5. **Asymmetric authorization.** Stopping needs one authenticated operator and never needs the clock. Resuming needs a different principal, an offline-verified quorum, or an explicit single-operator cooldown.
   - Before operator identity exists, records name the shared credential truthfully.
   - A trusted host's component-failure latch stays process-local, and it forbids containment.
6. **Evidence.** Each transition is a signed `chio.stop-epoch.v1` artifact, a trace event, and a SIEM export. Each stop deny receipt names the epoch it observed.

## 2. Verified current state

| Fact | Evidence |
|---|---|
| The stop is three atomics initialized at construction: `emergency_stopped: AtomicBool::new(false)`, `emergency_stopped_since`, and `emergency_stop_reason` | M: `crates/kernel/chio-kernel/src/kernel/construction.rs:369-371` |
| `emergency_stop` publishes the flag before reading fallible authority time (the AC6 ordering repair). `emergency_resume` clears it. The doc anticipates a future `revoke_all`, and says the kernel "remains running so orchestrators and health probes see a live process; it is inert" | M: `construction.rs:1656-1706`, `:1661-1662`, `:1667-1672`, `:1674-1681` |
| `shutdown` does not stop admission. "Operators that want a hard stop should call `emergency_stop` in addition" | M: `construction.rs:745-757` |
| Eleven in-memory check sites: evaluation entry (also the non-tool capability path), async and nested evaluation, dispatch, native capture, native egress lifecycle, caller output release, native output release, approval collection, finding pool | M: `kernel/evaluation/evaluation_entry.rs:54`, `:343`; `async_evaluation_core.rs:39`; `nested_flow_evaluation.rs:121`; `kernel/dispatch.rs:712`; `credential_reservation/native_dispatch.rs:103`; `admission_coordinator/native_egress/lifecycle.rs:80`; `admission_coordinator/terminal.rs:126`; `admission_coordinator/native_output.rs:396`; `admission_coordinator/collection_context.rs:64`; `finding_pool.rs:720` |
| No check in issuance (`issue_capability` at `:10`, `issue_capability_with_security_context` at `:51`) or governed active response | M: `kernel/validation/issuance.rs`; `governed_active_response.rs:135`; `kernel/active_response_executor.rs` |
| Mint paths outside `ChioKernel`: the api-protect sidecar mint routes sign directly; trust-control passport issuance calls the capability authority directly; the HTTP authority mints a kernel capability for every HTTP authorization | M: `crates/products/chio-api-protect/src/proxy/sidecar.rs:266`, `:586` (route `router.rs:60`); `crates/platform/chio-control-plane/src/trust_control/passport_handlers.rs:1384`; `crates/platform/chio-http-core/src/authority.rs:982` |
| Every check is a flag read outside the writer transaction, so the authoritative mutation can race a stop | the sites above; contrast M: `crates/platform/chio-store-sqlite/src/admission_operation_store.rs:350-363` (`begin_write`: IMMEDIATE, `verify_active_owner`, `verify_authority_anchor`) |
| Startup reconciliation finalizes every `Finalizing` operation. Any finalization error becomes `deferred_failure`, which is returned as `Err` before `*reconciled = true` | M: `kernel/admission_coordinator/recovery.rs:108-131`, `:295-341`, `:358` |
| Caller-executed release checks the stop after the report is persisted: "A persisted checkpoint authenticates the original output. It does not exempt a later delivery from the current stop state" | M: `admission_coordinator/terminal.rs:118-131` |
| Hosts propagate a reconciliation error as a startup or attach failure | M: `crates/platform/chio-control-plane/src/durable_admission.rs:263`; `crates/products/chio-api-protect/src/proxy/state.rs:672-674`; `async_evaluation_core.rs:355` |
| One store serves many kernels: hosted MCP builds one `ChioKernel` per session over a shared `DurableAdmissionRuntime`; edge kernels share a control-plane store over HTTP; api-protect evaluates the HTTP proxy on an ephemeral `HttpAuthority` kernel separate from its `mediation_kernel` | M: `chio-mcp-remote/src/remote_mcp/session_core/factory.rs:153-158`, `:181-195`, `:381-400`; `chio-control-plane/src/durable_admission.rs:170-205`; `chio-api-protect/src/evaluator.rs:151`, `chio-http-core/src/authority.rs:546`, `proxy/state.rs:189` |
| The HTTP handlers authenticate an `X-Admin-Token` with `token == expected` (not constant time). No crate outside `chio-http-core` and its tests mounts them | M: `crates/platform/chio-http-core/src/emergency.rs:188-196`, `:210`, `:229`, `:240`; route constants at `routes.rs:33` |
| The control credentials are single shared bearer tokens: `ProtectConfig::sidecar_control_token`, and trust control's `service_token`. Neither yields a principal | M: `docs/security/sidecar-control-authority.md:8-24`; `trust_control/authority_handlers.rs:35` |
| No operator roster with stop permission exists. M:'s only `RosterPolicy` is for liability adjudication. W:'s `RecoveryDeployment.actors` covers recovery scopes only | M: `trust_control/capital_and_liability/liability.rs:11`; W: `crates/kernel/chio-kernel/src/recovery/ports.rs:223-234` |
| `ThresholdApprovalCollector` collects approvals for an original tool-call admission, and refuses while stopped | M: `admission_coordinator/collection_context.rs:13-53`, `:64-66` |
| The recovery control-token profile verifies with `current_unix_timestamp_ms()`, which is `SystemTime ... unwrap_or(0)` | W: `recovery/ports.rs:199-201`; W: `kernel/mod.rs:1798-1805` |
| `observe_authority_time` refuses when the wall clock is below the persisted floor | M: `crates/platform/chio-store-sqlite/src/admission_operation_store/schema/clock.rs:35-50` |
| A trusted host latches the stop programmatically on component failure | M: `crates/products/chio-cli/src/cli/process_host/native_broker/authority.rs:114` |
| The process host requires `DurableAdmissionMode::All` and serves only worker and broker sockets, with no HTTP control surface. The serving owner holds the OS lock | M: `crates/kernel/chio-process/src/registry.rs:55-59`; `chio-cli/src/cli/process_host/serving.rs`; `serving_owner.rs:612-616` |
| The rollback anchor is a two-slot, 1024-byte-per-slot local file in the lock root. `reconcile_startup` refuses a database that does not extend it | M: `crates/platform/chio-store-sqlite/src/serving_owner/rollback_anchor.rs:22-30`, `:106-130` |
| The admission schema version is 34 and is gated at open | M: `admission_operation_store.rs:219`; `schema.rs:63-72` |
| Global commit rows are immutable through `BEFORE UPDATE` and `BEFORE DELETE` triggers that `RAISE(ABORT)` | M: `serving_owner/global_commit_chain.rs:86-96` |
| EV11 and AC6 are `open-acceptance`. EV11 requires "authenticated durable operator stop and restart behavior" in hosted CI. AC6's remaining acceptance is "Document in-process stop scope and verify the existing stop precedes fallible time reads; durable operational stop remains EV11" | M: `docs/security/landing-ledger.json:5066`, `:5118` |
| A Loom harness for the stop flag exists | M: `.loom/harnesses.toml:60` (`loom_emergency_stop_arcswap`) |
| A new serving epoch fences the old owner and reconciles before declaring readiness. Unresolved release custody blocks readiness | M: `docs/security/native-restart-safety.md:26-30`, `:107-111` |
| Template: `set_semantic_emergency_stop(scope, stop: bool)` requires an installed semantic registry, saves key `semantic-stop:{scope_key}`, kind `command`, through the serving writer, with no fence argument | W: `crates/platform/chio-store-sqlite/src/admission_operation_store/semantic.rs:369-386` (`installation` at `:375-376`) |
| Template persistence: version plus 1, immutable identity, and a hash-chained event per record version under recovery quotas | W: `.../admission_operation_store/recovery/storage.rs:157-200` |
| Template check points: `stopped(tx, scope)` (`semantic.rs:144-146`) runs inside plan acceptance (`:270`), `verify_capture_tx` (`semantic/capture.rs:47`), `captured_semantic_output_disposition` for `ReturnValue` (`:294`), and `semantic_dispatch_capture` (`:336`). Refusals use generic reasons such as `refused("plan authority")` | W: as cited |
| Template gaps: the payload is a bare `bool`, the store method takes no actor, and the only caller is a test | W: `semantic.rs:369-386`; `crates/platform/chio-control-plane/src/recovery/tests/semantic.rs:513` |
| Every `GovernedResponseEffect` narrows authority: `ThrottleSession`, `RestrictEgress`, `SuspendSession`, `SuspendCapabilitySet`, `FreezeIssuance` | M: `crates/core/chio-core-types/src/capability/governance.rs:769-775` |
| "Permanent revocation remains manual" | M: `docs/security/active-defense-rollout.md:23` |
| A process commits its call slot before calling the kernel, retries with the same request id, and retains the slot after a later failure | M: `crates/kernel/chio-process/ARCHITECTURE.md:40-45` |
| `register_delegation_parent` calls `validate_non_tool_capability`, whose first check is the stop | M: `kernel/validation/lineage.rs:123-135`; `evaluation_entry.rs:46-58`; used by `chio-process/src/lib.rs:436` |

## 3. Goals and non-goals

Goals:

- A stop survives restart, crash, serving-owner replacement, and a failed or unknown commit. A restarted kernel comes up `ready_stopped`.
- Operators can reach it through mounted routes, a process-host control socket, and a CLI, including while the host is down.
- No effect of a `Deny` or `Withhold` kind crosses custody after the stop commits in the writer that orders that crossing.
- Every crossing kind, op, entry point and command variant has a recorded disposition, so no path is unchecked by accident.
- Stopping is easy and never waits on the clock, a quorum or a dead shard. Resuming is deliberate. Both are signed evidence.

Non-goals:

- Revoking capabilities, closing spaces, or draining work. That is spec 4, and permanent revocation remains manual.
- Recalling effects that already crossed.
- Automatic stops from detection. Active defense keeps its own overlays.
- Stopping a remote kernel. Federation publication is informational only (section 12).
- Surviving a whole-volume restore that rolls back both the database and the anchor (section 13a, residual risk).

## 4. Stop record and chain

```rust
// chio-core-types::stop (closed; wire schema chio.stop-epoch.v1)
pub enum StopScope {
    Kernel,                                  // this serving authority
    Tenant { tenant_id: TenantId },          // never LOCAL_SYSTEM_TENANT_ID (S33)
    Recovery { scope: RecoveryScopeV1 },     // replaces W:'s semantic-stop record
}

pub enum StopTransition {
    Stop,      // Running -> Stopped
    Restrict,  // Stopped -> Stopped, narrowing only (S31)
    Relax,     // Stopped -> Stopped, widening allow_containment; authorized like Resume
    Resume,    // Stopped -> Running
    Rollover,  // first record of a new chain generation; restates the head's state and allow_containment, changes nothing (S6)
    Migration, // S5 only: (generation 1, epoch 1) of a Recovery scope with a legacy stopped value; yields Stopped
    Reconcile, // Stopped -> Stopped; restates the head and changes nothing; records the contributors of an entry an unread-journal bypass covered (S25a)
}

pub enum StopState { Stopped, Running }      // derived from the transition

pub struct StopEpochV1 {
    pub schema: String,                      // "chio.stop-epoch.v1"
    pub authority_id: DurableAuthorityId,    // serving authority, from the anchor
    pub scope: StopScope,
    pub chain_generation: u32,               // per scope, starts at 1, +1 per Rollover (S6); signed and part of the record identity
    pub epoch: u64,                          // per scope and chain generation, +1 per transition, starts at 1
    pub transition: StopTransition,
    pub state: StopState,
    pub expected_epoch: StopEpochId,         // head id the transition was decided against; (1, 0) for a scope's first record
    pub reason_commitment: Sha256Digest,     // SHA-256(salt || text), salt and text in the note table (S1); Rollover: the fixed commitment of S2
    pub authorizer: StopAuthorizer,
    pub decided_at: DecisionTime,
    pub trusted_floor_at_commit: u64,        // persisted trusted-time floor read in the appending transaction; always available, even when decided_at is Unavailable
    pub previous: Sha256Digest,              // digest of this scope's prior record, or zero
    pub allow_containment: bool,             // section 7.1, S12
    pub requested_via: StopRequestPath,
    pub satisfies_intent: Option<StopIntentRef>, // Stop and Restrict: the journal entry this record applies (S25); None for Resume, Relax, Rollover, Migration and Reconcile
    pub offline_bypass: bool,                    // true only for an offline-CLI Stop or Restrict appended without a journal entry (S2, S25); then satisfies_intent is None
    pub subsumes_intents: Vec<SubsumedIntent>,   // offline_bypass only: a signed snapshot of the pending journal entry the CLI read and folded in, at most one (S25); empty otherwise
    pub subsumes_unread: bool,                   // offline_bypass only: the journal was unreadable; this record retires no entry, and S25a reconciles the unread ones
    pub reconciles: Option<ReconciledIntent>,    // Reconcile only: the unread entry and the subsumes_unread record it is reconciled against (S25a); None otherwise
    pub contributors: Vec<StopRequestRecord>,    // Stop, Restrict, Relax, Resume: every applied request, 1..=2 (S25), and authorizer and reason_commitment above are contributors[0]; Rollover, Migration and Reconcile: empty (S2 field rules)
}

pub enum StopRequestPath {
    Route { host_id: HostId },
    ControlSocket,
    OfflineCli,
    Migration,                               // S5 only
    SystemRollover,                          // S6: the writer's automatic Rollover; no request exists
    SystemReconcile,                         // S25a: the writer's Reconcile of an unread entry; no new request exists
}

/// A position in a scope's chain. Ordered lexicographically: chain_generation first, then epoch.
pub struct StopEpochId { pub chain_generation: u32, pub epoch: u64 }

pub struct StopIntentRef { pub intent_id: [u8; 16], pub generation: u64 }
pub struct StopRequestRecord {
    pub request_id: [u8; 16],
    pub authorizer: StopAuthorizer,
    pub reason_commitment: Sha256Digest,
    pub decided_at: DecisionTime,
}

pub struct SubsumedIntent {                  // a signed snapshot of one stop-intent journal entry (S2, S25)
    pub intent_ref: StopIntentRef,
    pub allow_containment: bool,
    pub contributors: Vec<StopRequestRecord>, // 1..=2: the entry's contributors, copied unchanged; they join S19's stopper set
    pub entry_digest: Sha256Digest,           // SHA-256 of the entry's canonical encoding; recomputed from these fields plus the record's authority_id and scope
}

pub struct ReconciledIntent {                // Reconcile only (S25a)
    pub bypass: StopEpochId,                  // the subsumes_unread bypass record of the current incident
    pub intent: SubsumedIntent,               // the entry as read once the journal became readable
}

pub enum DecisionTime {
    Observed(UnixMillis),                    // observe_authority_time inside the write transaction
    Unavailable,                             // Stop, Restrict, Rollover and Migration only (S4, S5, S6)
    Attested(TimeAttestationRef),            // break-glass Resume (S19)
}

pub enum StopAuthorizer {
    SharedCredential { credential_id_hash: Sha256Digest }, // phases before S28; truthful about who is known
    Operator { principal: PrincipalId },                   // a roster principal (S28)
    OperatorPair { stopper_epoch: StopEpochId, resumer: PrincipalId },
    SamePrincipalAfter { principal: PrincipalId, cooldown_ms: u64, cooldown_started: UnixMillis },
    Quorum { artifact_digest: Sha256Digest, principals: Vec<PrincipalId> },        // S29
    BreakGlass { artifact_digest: Sha256Digest, attestation: TimeAttestationRef }, // S19
    RecoveryActor { subject: PublicKeyHex },                                       // S32, Stop and Restrict only
    LegacySemanticStop,                                                            // S5 migration only
    ChainRollover { serving_owner: ServingOwnerId, writer_epoch: u64 },            // S6: Rollover records only; the owner and serving epoch that appended it; changes no state
    ChainReconcile { serving_owner: ServingOwnerId, writer_epoch: u64 },           // S25a: Reconcile records only; the owner and serving epoch that appended it; changes no state
}
```

Normative rules:

- **S1. Writer.**
   - Records are appended to a new table, `admission_operation_stop_epochs(scope_key, chain_generation, epoch, record_digest, previous_digest, payload)`, keyed by `(scope_key, chain_generation, epoch)`, through the admission store's `begin_write` (IMMEDIATE, active-owner and anchor checks; M: `admission_operation_store.rs:350-363`), `commit_write` and `sync_after_write`.
   - The table is append-only: `BEFORE UPDATE` and `BEFORE DELETE` triggers `RAISE(ABORT)`, as `authority_global_commits_immutable` does (M: `serving_owner/global_commit_chain.rs:86-96`).
   - Every transition is a restrictive commit under spec 10 section 5, anchored before acknowledgement.
   - The salted reason text lives in `admission_operation_stop_notes(scope_key, chain_generation, epoch, salt, redacted_text)`. That table is operator-readable, outside the chain, and deletable for retention. The chain keeps only the commitment, so short text cannot be brute-forced from the record.
- **S2. Chain.**
   - **Identity.** A record's identity is `(authority_id, scope, chain_generation, epoch)`, and every field of it is in the signed body. Every comparison of positions in a scope's chain (heads, `expected_epoch`, replicas, floors, observed epochs) compares `StopEpochId` lexicographically, never `epoch` alone.
   - Within a chain generation, `epoch` increases by exactly 1, and `previous` equals the digest of the prior record.
   - A `Rollover` record is epoch 1 of generation `g + 1`. Its `previous` is the digest of generation `g`'s final record, its `expected_epoch` is that record's id, and its `state` and `allow_containment` equal that record's. The chain of digests is therefore unbroken across generations.
   - `state` follows the transition. `Restrict`, `Relax` and `Reconcile` require a `Stopped` head, and `Resume` requires a `Stopped` head.
   - A `Stop` over a stopped head is an idempotent no-op that returns the current head, unless it asks for narrower containment, in which case it is recorded as `Restrict`.
   - A `Resume` over a running head is a no-op that returns the current head.
   - **Field rules per transition.** The writer constructs, and every verifier checks, the rule for the record's transition. A record that breaks its rule is invalid. A verifier refuses it, and the writer never appends it:
     - **`Stop`, `Restrict`, `Relax`, `Resume`.** `contributors` holds 1 or 2 requests. `authorizer` and `reason_commitment` equal `contributors[0]`'s. `requested_via` is `Route`, `ControlSocket` or `OfflineCli`. `satisfies_intent` is set for every `Stop` and `Restrict` (S25), with one exception: an offline `Stop` or `Restrict` appended by the journal-bypass path (S25 "Offline CLI") has `requested_via: OfflineCli`, `satisfies_intent: None` and `offline_bypass: true`. Verifiers accept that form only with `requested_via = OfflineCli`. It never retires a journal entry through `satisfies_intent`. It retires entries only through its `subsumes_intents` snapshots, which S25's satisfaction rule validates:
       - each `SubsumedIntent { intent_ref, allow_containment, contributors, entry_digest }` in `subsumes_intents` is a signed snapshot of an entry the CLI read. There is at most one, because the journal holds one entry per scope.
         - `allow_containment` is that entry's value, and `contributors` copies the entry's contributors unchanged (1 or 2).
         - `entry_digest` is the SHA-256 of the entry's canonical encoding. A verifier recomputes it from the snapshot's fields plus the record's `authority_id` and `scope`, and refuses a snapshot whose digest does not recompute. The contributors are therefore bound to the entry the CLI read, and they are signed into the chain to the same standard as S25's normal application, which copies the same requests into `contributors`.
         - The record's own `allow_containment` must be no wider than any snapshot's.
         - Verification uses the snapshot in the signed record, never the journal, because S25 removes the entries afterward. A later boot or replica can therefore re-verify the proof after journal cleanup.
         - At the time of removal, boot also checks each live entry's bytes against its `entry_digest`; a mismatch is refused;
       - with `subsumes_unread: true`, the record retires no entry by itself. Once the journal is readable, each entry it covered is applied by a `Reconcile` record or a narrowing `Restrict` (S25a).
       - A non-bypass record must have an empty `subsumes_intents` and `subsumes_unread: false`. A note row exists for each contributor (S1). `authorizer` is never `ChainRollover`, `ChainReconcile` or `LegacySemanticStop`.
       - `reconciles` is `None` for every transition except `Reconcile`.
     - **`Rollover`.** No request exists, so `contributors` is empty and `satisfies_intent` is `None`. `authorizer` is `ChainRollover { serving_owner, writer_epoch }`, naming the serving owner and serving epoch that appended it. `requested_via` is `SystemRollover`, or `OfflineCli` when the offline CLI appends it under the serving-owner lock (S30).
       - `state`, `allow_containment` and `expected_epoch` restate the previous generation's final record (its state, its containment flag, and its id).
       - `reason_commitment = SHA-256("chio.stop-epoch.rollover.v1\0" || canonical(expected_epoch) || previous)`. That is a fixed domain string plus the restated head id and digest, with no salt and no note row, because there is no operator text to protect. A verifier recomputes it.
       - `decided_at` is `Observed` when authority time is available, else `Unavailable`. A rollover never waits on the clock.
     - **`Reconcile`** (S25a). No new request exists, so `contributors` is empty and `satisfies_intent` is `None`. The recovered entry's requests travel in `reconciles.intent.contributors` (1 or 2), so they are signed into the chain without being presented as a new decision. `authorizer` is `ChainReconcile { serving_owner, writer_epoch }`. `requested_via` is `SystemReconcile`, or `OfflineCli` when the offline CLI appends it under the serving-owner lock (S30).
       - It requires a `Stopped` head. `state` is `Stopped`, and `allow_containment` equals the head's, so it neither narrows nor widens anything.
       - `reconciles.bypass` names an `offline_bypass` record with `subsumes_unread: true` in the head's ancestry within the current incident, and no `Relax` or `Resume` follows that record.
       - `reconciles.intent.allow_containment` is no narrower than the head's. A narrower entry is applied as a narrowing `Restrict` instead (S25a).
       - `reconciles.intent.entry_digest` recomputes from the snapshot, as for `subsumes_intents`.
       - `reason_commitment = SHA-256("chio.stop-epoch.reconcile.v1\0" || canonical(expected_epoch) || canonical(reconciles))`. It has no salt and no note row, because no operator text is new, and a verifier recomputes it.
       - `decided_at` is `Observed` when authority time is available, else `Unavailable`. A reconciliation never waits on the clock.
       - No other transition may carry `ChainReconcile`, `SystemReconcile` or `reconciles`.
     - **`Migration`** (S5). The transition is `Migration`, never `Stop`, because no request exists. It is valid only as `(chain_generation 1, epoch 1)` of a `Recovery` scope with no earlier record, written by the S5 startup migration. A verifier refuses a `Migration` record at any other position, in any other scope kind, or after any other record.
       - `state = Stopped`. `allow_containment` is the deployment's default for new stops (S12), recorded explicitly.
       - `contributors` is empty, `satisfies_intent` is `None`, `authorizer` is `LegacySemanticStop`, and `requested_via` is `Migration`.
       - `expected_epoch = (1, 0)`, and `previous` is zero.
       - `reason_commitment = SHA-256("chio.stop-epoch.migration.v1\0" || legacy_key)`, where `legacy_key` is the UTF-8 bytes of the W: key `semantic-stop:{scope}`. It has no salt and no note row, and a verifier recomputes it.
       - `decided_at` is `Observed` when authority time is available, else `Unavailable`. Migration never waits on the clock.
       - No other transition may carry `LegacySemanticStop` or `requested_via: Migration`.
   - The table joins the global commit chain projection coverage, as W:'s recovery projection kind does.
- **S3. Head.**
   - The head for a scope is its highest `StopEpochId`, which is always in its current chain generation. A scope with no record is `Running`.
   - The effective state for a crossing is `Stopped` if any applicable scope head is `Stopped`, or if any process latch applies (S23).
- **S4. Time.**
   - `decided_at` comes from `observe_authority_time` inside the write transaction.
   - If time is unavailable, including when the wall clock is below the persisted floor (M: `schema/clock.rs:35-50`), a `Stop` or `Restrict` still commits with `DecisionTime::Unavailable`. This preserves the AC6 rule that stopping never depends on the clock.
   - A `Resume` or `Relax` without authority time refuses, unless it is the break-glass path (S19).
- **S5. Migration of the template.**
   - At startup, any existing W: `semantic-stop:{scope}` record whose value is `true` becomes a `Recovery` scope head. It is written as a `Migration` record at `(1, 1)` under S2's `Migration` field rules, so the scope comes up `Stopped`.
   - The migration runs in S9 step 2, before the heads are installed in step 3, in the same transaction that creates the stop chain table. A legacy stopped scope is therefore never observed `Running`, even for one request.
   - Like a stop, the `Migration` record takes the commit-first signing obligation (S38). A resume of the migrated scope refuses with `StopEvidencePending` until it is signed.
   - A legacy value of `false`, or no legacy value, writes no record, and the scope is `Running` (S3).
   - The four W: check points call the unified `stop_state(tx, kind, &[Recovery(scope), Tenant(t), Kernel])` in place of `stopped(tx, scope)`.
   - `set_semantic_emergency_stop` becomes a thin wrapper that requires an authenticated actor (section 9) and takes the serving fence.
   - Stopping a recovery scope never depends on whether a semantic registry is installed. The `installation(&tx, scope)` precondition (W: `semantic.rs:375-376`) applies only to the legacy write path, which migration retires.
- **S6. Bounds and headroom.**
   - A record is at most 4 KiB, and a chain generation holds at most 65,536 records (`bound`).
   - `Resume` and `Relax` refuse once the current generation holds `bound - 1` records. `Stop`, `Restrict` and `Reconcile` may append up to `bound`, because each leaves the head `Stopped`.
   - Only `Resume` produces a `Running` head, and it never takes the last slot, so a running head always has room for one durable `Stop`. Exhaustion therefore always ends `Stopped`. It can never leave a `Running` durable head with a stop that only tier 1 holds.
   - **Rollover.** When a commit leaves the current generation holding `bound - rollover_margin` records or more (`rollover_margin` default 8, at least 4), the writer appends a `Rollover` record as the scope's next commit, in the priority lane (S36).
     - It is a restrictive commit, anchored before acknowledgement, built under S2's `Rollover` field rules: authorizer `ChainRollover { serving_owner, writer_epoch }`, `requested_via: SystemRollover`, no contributors, the fixed reason commitment. It restates the head's `state` and `allow_containment` and satisfies no intent (`satisfies_intent: None`), so a rollover never changes `Stopped` or `Running` and never relaxes anything. It therefore needs no resume authority and invents no request.
     - The headroom rules above apply within each generation, so they hold before and after the rollover. Between the trigger and the rollover's commit, at least `rollover_margin - 1` slots remain, and resume and relax still refuse at `bound - 1`.
     - If the rollover cannot commit (for example on `SQLITE_FULL`), the writer retries it with backoff. A generation that reaches `bound` meanwhile ends `Stopped` as above and stays stopped until the rollover commits. Readiness reports `stop_chain_exhausted`. The offline CLI can append the same `Rollover` record under the serving-owner lock (S30), with `requested_via: OfflineCli` and the CLI's own `ChainRollover { serving_owner, writer_epoch }`. The CLI requires stop authority to run, and it logs that credential in its operator audit, not in the record, because the record cannot relax anything.
     - A pending intent (S25) applies after the rollover, at the new generation's next epoch.
     - Earlier generations stay in the append-only table. Heads, checks and replicas read only the current generation's head, so a generation reset of `epoch` never makes two records indistinguishable: they differ in `chain_generation`, which is signed.

## 5. Two-tier enforcement

**Tier 1 (early deny).**
- `StopHeads` is an `ArcSwap<StopHeadsSnapshot>` owned by the store or runtime handle, not by `ChioKernel` (S24). Every kernel attached to that store in the process reads the same instance.
- Every existing M: check site reads it in place of `emergency_stopped`, asking for its applicable scopes.
- The process runtime reads it through a kernel accessor before committing a call slot, so a stop does not burn process call budget.
- Tier 1 never decides an effect.

**Tier 2 (authoritative).**
- `CrossingCheck::StopEpoch` (spec 10 section 4.1) takes `(kind, scopes, disposition)` and evaluates `stop_state` inside the crossing's own writer transaction, before the state change that lets the effect cross.
- It reads `durable_heads ∪ process_latches` (S23).
- The table below is the normative stop disposition for each spec 10 `CrossingKind`. Spec 10 section 4.2's Stop column shows the same values and cites this table.

```rust
pub enum StopDisposition {
    Deny,               // refused while stopped
    Withhold,           // operation retained (Finalizing or Parked), bytes held in durable custody; proceeds after resume
    Settle,             // allowed only to complete or settle an effect committed before the stop head; a new authorization is Deny
    AllowIfContainment, // allowed only when the head has allow_containment = true and no host latch applies
}
```

| `CrossingKind` (spec 10) | Disposition | Transaction that checks | Scopes |
|---|---|---|---|
| `DispatchIntent` | `Deny` | the fused intent commit. Legacy: the `DispatchCommitted` CAS from `commit_durable_dispatch` and `capture_and_commit_durable_dispatch` (M: `admission_coordinator.rs:1560`, `:1814`) | Kernel, Tenant |
| `CheckOnlyDispatch` | `Deny` | the check-only crossing in the writer loop (spec 10 X4: no write; its index travels in receipt metadata) | Kernel, Tenant |
| `CallerStart` | `Deny` | the `CallerStart` crossing (capture before the effect) | Kernel, Tenant |
| `NativeCapture` | `Deny` | the capture transaction behind M: `native_dispatch.rs:103` | Kernel, Tenant |
| `RecoveryCapture` | `Deny` | the same-writer tombstone transactions at begin and capture (W: `recovery/native.rs:286-293`) | Kernel, Tenant, Recovery |
| `SemanticCapture` | `Deny` | W: `verify_capture_tx` (`semantic/capture.rs:47`) and `semantic_dispatch_capture` (`:336`) | Kernel, Tenant, Recovery |
| `MutationSubmit` | `Deny` | `MutationReady -> MutationSubmitted` before the mutation service call | Kernel, Tenant |
| `OutputRelease` | `Withhold` | the outcome commit. Legacy: the release checkpoint transactions behind M: `terminal.rs:126` and `native_output.rs:396` | Kernel, Tenant |
| `ArtifactRelease` | `Withhold` | the commit of the P4 knowledge join and `ReleaseIntent` | Kernel, Tenant |
| `ConfinedReturn` | `Withhold` | the `admit_confined_return` commit (W: `chio-control-plane/src/confinement.rs:214-226`; spec 10 X5a) | Kernel, Tenant |
| `ExternalEvaluation` | `Withhold` | the begin-evaluation record before output goes to an `ExternalStateful` step | Kernel, Tenant |
| `ExternalPrepare` | `Settle` | the prepare commit. Purpose `Settle` (capture or release of an existing hold) is allowed; purpose `Authorize` (a new rail authorization) is denied | Kernel, Tenant |
| `FederationCosign` | `Settle` | the co-sign request for an admitted request (M: `terminal.rs:1910`), allowed only when that request's dispatch committed before the stop head | Kernel, Tenant |
| `ChannelReleasePublish` | `Settle` | publication of a release of funds earned by effects committed before the stop head | Kernel, Tenant |
| `ActiveResponseExecute` | `AllowIfContainment` | governed active response execution | Kernel, Tenant |

Writer checks that are not crossings keep their W: positions:

| Check | Disposition | Scopes |
|---|---|---|
| W: semantic plan acceptance (`semantic.rs:270`) | `Deny` | Kernel, Tenant, Recovery |
| W: `captured_semantic_output_disposition` for `ReturnValue` (`semantic/capture.rs:294`) | `Withhold` | Kernel, Tenant, Recovery |

Rules:

- **S7. Tier 2 decides.** A crossing transaction that observes an effective `Stopped` state for a `Deny` or `Withhold` kind fails with the typed `KernelStopped { scope, epoch, observed_via }`, and makes no state change.
   - The caller follows the path for its disposition and phase (section 8, S15). Every store-level refusal is typed `KernelStopped`, never a generic reason string (S35).
   - A `Settle` crossing passes only when every effect it completes or settles has a `CrossingOrder` (spec 10 X4) earlier than the stop record's own `commit_sequence` in the same store. For a sharded tenant, that is the replica record's sequence in the shard's store. A `Settle` crossing with no prior committed subject is a new authorization and is refused. The same subject-before-cut test applies to the closure-fence and revocation checks of `Settle` kinds (spec 10 section 4.2), so a revocation or closure that lands after the effect committed never blocks its settlement.
   - An `AllowIfContainment` crossing passes only when every applicable `Stopped` head has `allow_containment = true` and no host latch applies (S20).
   - P5: a stop committed after the `admit_confined_return` commit and before `sink.deliver` is caught best-effort. The final serialized activity read (spec 10 X5a, kept for cancellation) also consults tier 1 (`durable_heads ∪ process_latches`). The claim limit names this window as tier 1 only.
- **S8. Issuance is defense in depth.** Capability issuance does not run in the admission writer, so under spec 10 X3 it is `early_only`. A capability minted in the race window still cannot cross, because every crossing is fenced by S7. Every mint path is listed:

   | Mint path | Check |
   |---|---|
   | `ChioKernel::issue_capability` (M: `issuance.rs:10`) | tier 1 from the shared heads, plus a separate read of the durable head |
   | `ChioKernel::issue_capability_with_security_context` (M: `issuance.rs:51`) | same |
   | api-protect sidecar mint routes (M: `proxy/sidecar.rs:266`, `:586`) | tier 1 from the api-protect process's shared heads (S24) |
   | trust-control passport issuance (M: `passport_handlers.rs:1384`) | tier 1 from the trust-control host's heads when that host attaches the admission store; otherwise listed `unchecked` in the status route and the claim limit |
   | HTTP authority's per-request internal capability (M: `chio-http-core/src/authority.rs:982`) | not issuance. It is part of `EvaluateToolCall`: the HTTP authorization denies with a signed `kernel_stopped` receipt before minting |

   Control-profile issuance has a carve-out after S28 (section 7.1, S13).

```text
committed(stop(s, e)) before crossing(x) and kind(x) in {Deny, Withhold} and s in scopes(x)
  -> not crossed(x)
crossed(x) before committed(stop(s, e)) -> effect may proceed; its later crossings are
  checked at their own commits (S7)
settle(x) crossed after committed(stop(s, e)) -> forall y in subject(x): order(y) < order(stop(s, e))   (CrossingOrder, spec 10 X4)
allow_if_containment(x) crossed while stopped -> head.allow_containment and no host latch
```

## 6. Boot and readiness

- **S9. Heads first, then the sweep.** Startup runs in this order:
   1. Open the store as serving owner. The anchor is reconciled (M: `rollback_anchor.rs:106-130`).
   2. Check the stop chain table under the schema gate (section 13a). A table that is absent before migration is created by the migration in the same step, which also writes S5's `Migration` records for legacy stopped scopes. A table that is missing when the schema version claims it means not ready, with reason `stop_chain_missing`.
   3. Read the stop-intent journal (S25). Verify S2 for every scope chain. Install `StopHeads` as the verified heads, overlaid with every intent entry that its scope's anchored head does not satisfy (S25), one per scope.
   4. Run reconciliation. `reconcile_durable_admission_startup` (M: `recovery.rs:108`) is many transactions, not one. Each finalization or release step consults the installed heads:
      - a `KernelStopped` refusal is **Retain**: the operation stays `Finalizing` with output withheld, and the sweep does not record a `deferred_failure` for it;
      - any other error keeps today's behavior.

      This is spec 9 M11's retain rule, adopted by the legacy reconciler in phase 1.
   5. Set readiness (S10).

   A digest mismatch or epoch gap leaves the kernel `not_ready` with reason `stop_chain_unverified`. Tier 1 is then installed as `Stopped` for the kernel scope (fail closed), and the stop and status routes still answer.
- **S10. Readiness states.** Readiness has three states:

    | State | Meaning | Routes served |
    |---|---|---|
    | `not_ready { reason }` | chain unverified, reconciliation failed for a reason other than a stop, or a missing table | status; stop (records the intent latch, and appends when the chain is writable); resume refuses |
    | `ready_stopped { scope_heads }` | verified, and some applicable head (or latch) is `Stopped` | status, stop, restrict, relax, resume, and every `allow` disposition |
    | `ready` | verified and running | everything |

    - Health probes treat `ready_stopped` as live and serving, matching M:'s promise that the stopped kernel "remains running ... it is inert" (`construction.rs:1661-1662`).
    - A stopped head at boot keeps every `Deny` and `Withhold` disposition in force from the first request.
    - The status route reports, per scope: state, epoch, authorizer, `decided_at`, `allow_containment`, `durability`, and `withheld_operations`.
- **S11. No durable store, no durable claim.**
    - A kernel without a durable admission runtime (ephemeral development profiles) keeps process-local behavior. Its status reports `durability: process_local`.
    - A profile that requires durable admission, such as the work profiles and process runtimes, gets the durable stop.
    - In every case, all kernels a host process constructs bind to one `StopHeads` instance. That includes api-protect's ephemeral `HttpAuthority` kernel, which binds to the heads of its `mediation_kernel`'s store. The proxy path is therefore never outside the stop.
- **S26. Withheld output keeps durable custody.** Every `Withhold` refusal leaves the bytes in a durable custody record, so they survive restart and are released after resume:

    | Kind | Custody record |
    |---|---|
    | durable `OutputRelease` | the return record (M: `load_durable_tool_return`) |
    | native output release | the release checkpoint (M: `native-restart-safety.md:107-111`) |
    | caller output | the persisted caller report (S27) |
    | `ArtifactRelease` | the pinned artifact and its release intent |
    | two-commit read | a return record written on refusal (S14) |

    - `ConfinedReturn` is durable only if the confined child's output is journaled before the admission commit. Until W: confirms that, withheld P5 returns are counted as `withheld_volatile` in the status route, and the claim limit names them.

## 7. Dispositions

### 7.1 L0 ops (spec 1 rule R5)

| Disposition | Ops or entry points | Rationale |
|---|---|---|
| `deny` | `EvaluateToolCall` (including HTTP authority's internal capability, S8), `EvaluatePlan`, `EvaluateSessionOperation`, `EvaluateNestedRequest`, `ConsumeExecutionNonce`, `DebitFindingPoolPurchase`, `UpdateLiveTrust`, `RecoveryDisclosureIssuance` | admit an effect, or widen live trust |
| `deny` | `ManageDelegationParent` | `register_delegation_parent` calls `validate_non_tool_capability`, which checks the stop first (M: `validation/lineage.rs:123-135`, `evaluation_entry.rs:46-58`). Spec 1 records the same disposition. A host restarted while stopped defers process-tree restoration until resume |
| per entry point (S13) | `IssueCapability` | ordinary issuance `deny`. After S28, control-profile issuance is `allow`: direct tokens whose subject is a roster principal, never an agent scope (S8-16) |
| `allow` | `VerifyCapability`, `VerifyPassport`, `VerifyReceipt`, `VerifyDpopPreview` | pure |
| `allow` | `SignReceipt`, `SignReceiptRelayingTrustedBody`, `ExportExecutionEvidence` | deny and terminal receipts must still be signable; export is historical |
| `allow` | `SessionOpen`, `SessionRequest`, `SessionEventRelay`, `SessionClose` | no effect of their own; every effect-bearing request reaches a denied Admit op; clients must still connect, cancel, and learn of the stop |
| `allow` | `RevokeCapability`, `EmergencyControl`, `Reconcile`, `ObserveSettlement`, `Shutdown` | narrow authority, control the stop, or settle the past |
| `allow` unless `allow_containment = false` (S12) | `AdmitGovernedActiveResponse` | every `GovernedResponseEffect` narrows authority |
| per entry point (S13) | `CallerExecution` | `reserve_` and `start_` deny; the authenticated report is a progress-only return record and is allowed (S27); release is `OutputRelease` (`Withhold`); `reconcile_caller_execution*` allow. `reconcile_caller_execution*` is an entry point of `CallerExecution` only, never of `Reconcile` (spec 1 R1, R5b) |
| per entry point (S13, R5a) | `RecoveryControl` | see the next table |

`RecoveryControl` entry points (spec 1 section 5 lists seven in W:, and spec 2 section 6.10 adds an eighth):

| Entry point | Disposition | Rationale |
|---|---|---|
| `authenticate_recovery_actor` (W: `recovery/ports.rs:193`) | `allow` | `CancelWorkflow` and recovery-scope stop must authenticate |
| `execute_recovery_command` | per variant (R5a): `InspectWorkflow`, `CancelWorkflow` and proposed `RetireSuccessorReservation` allow; every other variant denies | as spec 1 R5a. Spec 2 O5 retirement requires predecessor-scope Cancel authority and an exact Reserved link; it never creates or retargets a successor |
| `read_recovery_workflow` | `allow` | observation |
| `load_recovery_request_custody` (W: `recovery/ports.rs:272`) | `allow` | an actor-authenticated read; it crosses no effect custody |
| `observe_recovery_capability_liveness` | `allow` | observation |
| `reserve_recovery_review` (W: `recovery_runtime.rs:267`) | `deny` | it advances a workflow toward an effect |
| `acknowledge_recovery_reservation` (W: `recovery_runtime.rs:91`) | `deny` | it binds a process reservation to a workflow |
| `reserve_successor_ordinal` (spec 2 section 6.10 O4, proposed) | `deny` | it mutates the original's origin claim toward a linked continuation. Checked for the verified predecessor scope and the authenticated successor scope persisted in the link, in the claim's writer transaction before any mutation. An authenticated replay matching the stored successor scope is a readback and is allowed; a scope change conflicts. `CreateWorkflow` must use that stored scope. Root supersession happens only in the stop-gated `CreateWorkflow` (spec 2 O3) |

P6 component operations (control plane and store, not `KernelOp`). Spec 1 section 6 holds the full classification:

| Operation | Disposition | Rationale |
|---|---|---|
| Setup and qualification mutations (`pin_setup_creation`, `configure_protected_setup`, `commit_setup_probe`, `accept_setup_report`) | `deny` | they change the selected deployment or its qualification |
| Setup preparation reads (`setup_preparation`, `prepare_setup_report`) | `allow` | observation |
| Setup gate (`require_ready`, `require_command`, `require_capture`) | inherits its caller's disposition | a transaction-local participant precondition, not an entry point (spec 10 X5b) |
| Decision report submit (`submit_decision_report`) | `deny` | a durable mutation |
| Decision report read (`read_decision_report`) | `allow` | observation |
| Maintenance proposal (`propose_policy_maintenance`) | `deny` | a mutation, even though it is inert until applied |
| Policy basis read | `allow` | observation |
| Signed policy application (`apply_reviewed_semantic_deployment`) | `deny` | it installs a new deployment generation; it waits for resume |

- **S12. Containment during a stop.** `AdmitGovernedActiveResponse` and the `ActiveResponseExecute` crossing are allowed only while all three conditions hold:
    - the closed `GovernedResponseEffect` enum (M: `governance.rs:769-775`) contains only authority-narrowing effects;
    - every applicable `Stopped` head has `allow_containment = true`;
    - no host latch applies (S20).

    The disposition function matches that enum exhaustively, so adding a variant forces a new decision. Admission still requires its threshold approval.

    Containment mutates state (suspensions, egress restrictions). For a forensic freeze, operators stop with `allow_containment = false`. The status route surfaces the flag per scope. An existing stop can be tightened to `false` in place with `Restrict` (S31).
- **S13. Per-entry-point dispositions.** This is spec 1 rule R5b. An op whose entry points differ in direction (begin versus observe), or in authority profile (agent versus control), declares a disposition per entry point. It is used today by `CallerExecution`, `IssueCapability` (after S28) and `RecoveryControl`.

### 7.2 Higher layers (rule R12 inheritance)

- **L1 process ABI.**
  - `invoke` denies through `EvaluateToolCall`. Tier 1 denies before the slot commits.
  - `inspect`, `checkpoint`, `blob_put`, `blob_read` and `cancel` allow. They are local, credential-scoped state and cross no custody boundary.
  - Native tools behind `invoke` deny with `invoke`. These include mailbox send, spawn, `wait_children` and `settle_children` (W: `crates/products/chio-cli/PROCESS_RUNNER.md:211-218`). Workers observe child state through `inspect`.
- **L2 work (contract anchors).** `Delegate`, `Select`, `Seal`, `Extend` and `Submit` deny. `Reconcile`, `Cancel` and every `WorkQueryV1` allow.
- **L3 recovery.**
  - `CreateWorkflow`, `SelectOffer`, `SubmitApproval`, `ResumeWorkflow`, `ReportDecision` and `/v1/recovery/review` deny.
  - `InspectWorkflow`, `CancelWorkflow`, proposed `RetireSuccessorReservation` (spec 2 O5), `/v1/recovery/settle` (`attach_provider_finality`) and `/v1/recovery/explain` allow. Explain is pure advisory, and settle records provider finality for effects that already happened.

```text
forall kind in CrossingKind: stop_disposition(kind) defined     (exhaustive match, spec 1 R2)
forall op in KernelOp, entry in entries(op): disposition(op, entry) defined (spec 1 census)
forall v in RecoveryCommandBodyV1: disposition(v) defined       (exhaustive match)
disposition = deny and stopped(scope) -> refused at tier 1 and tier 2
```

## 8. In-flight work and approvals

- **S14. No recall, no re-dispatch.** An operation whose crossing committed before the stop is not recalled. Its later crossings (output release, P4 release, P5 return, external evaluation) are separate crossings, and they are `Withhold` while stopped.
    - Withheld output keeps durable custody (S26). It is released after resume through the existing replay path, and it is never re-dispatched. This matches M: `terminal.rs:126` ("does not exempt a later delivery from the current stop state").
    - **Two-commit read** (spec 10 X14, no return record):
      - a `KernelStopped` refusal of the outcome commit rolls back the savepoint, then writes a progress-only return record that holds the bytes;
      - the operation is then `Finalizing` with output withheld, so recovery never signs `OutcomeUnknownAfterDispatch` for it and the process runtime never re-dispatches the read.
    - **Client-visible result.** A request whose output is withheld completes with `OutputWithheld { operation_id, reason: KernelStopped { scope, observed } | StoreUnavailable | AuthoritySpaceClosed | Revoked | InsufficientIntegrity, retry: AfterResume | AfterStoreRecovery | Never, effect_executed: bool }`. `AfterStoreRecovery` is the transient condition for a reusable check-only read whose release met `StoreUnavailable` (spec 9 M19). The client retries after a backoff once the store is healthy, with no stop involved:
      - on JSON-RPC surfaces, an error with code `output_withheld` and data `{ operation_id, scope, observed, retry, effect_executed }`;
      - on the process ABI, `invoke` returns status `withheld` with the same fields.
      - **`retry: AfterResume`** applies to durable operations (the output stays in release custody) and to check-only reads (no effect, so a retry is safe). After resume, a replay with the same request id (or the same process operation key) returns the released output through the bound durable result. A surface without that replay path delivers the outcome only through the terminal receipt and is named in the claim limit.
      - **`retry: Never`, with `effect_executed: true`,** applies to a `NonDurable` side-effecting call whose release a stop refused (spec 9's `NonDurable` class, spec 10 X13c). Its effect has already run, and no custody holds the output or a replay key, so a retry after resume would dispatch the effect again (spec 5 confirms that a non-durable retry redispatches). The client must treat the call as executed with its output lost.
- **S15. Stop refusals per path.** `KernelStopped` is a temporary refusal. It never writes a deny tombstone, and it burns a request id only where M: does today.

    | Path | Where refused | Result | Request id |
    |---|---|---|---|
    | Tier 1 early, before any durable row | any existing check site | `SignReceipt(Deny { kernel_stopped })` with `observed`; no tombstone | not burned; the same id proceeds after resume |
    | Fused intent commit (spec 9 M10, spec 10 X15) | tier 2 in `IntentCommit` | savepoint rolls back; deny receipt only; no `DenyTombstone` | not burned |
    | Check-only read | tier 1 or the check-only crossing | deny receipt only | not burned |
    | Fused intent commit from `Prepared` (spec 10 X10, spec 9 M10) | tier 2 in `IntentCommit` | compensate the persisted operation under `PreDispatchNoEffect`; deny receipt | terminal, as on M: today |
    | Slow path with a begin row, not parked | the dispatch-commit CAS | compensate under `PreDispatchNoEffect`; deny receipt | terminal, as on M: today |
    | `Parked` (approval) | the resume intent commit | **Retain** in `Parked`; no compensation (S16) | unchanged; resumes after resume |
    | Post-dispatch (`Finalizing`, a release) | the release crossing | `Withhold` (S14) | unchanged |
    | Caller report | never stop-checked (S27) | return record persisted | unchanged |
    | `NonDurable` side-effecting call, release refused | the release crossing, after the effect ran | signed withheld receipt with `retryable_after_resume: false`; `OutputWithheld { retry: Never, effect_executed: true }`. **Terminal, not temporary**: there is no custody to resume from | terminal for that call; a retry is a new, deliberate dispatch |

    - A stop receipt carries `chio_runtime.stop = { scope, observed, retryable_after_resume }`, with `observed: StopObservation` (section 10), beside `chio_runtime.identity_disposition` (spec 9 M20). `retryable_after_resume` MUST equal `identity_disposition == Reusable`:
      - `true` (`Reusable`) only on the tier-1, fused-from-`Unbegun` and check-only rows, and on a check-only read's `Withheld { retry: AfterResume }`. No row, tombstone or custody binds the request id there;
      - `false` (`Terminal`) on the `Prepared`-intent and slow-path rows, whose compensated row now holds the request id, and on the `NonDurable` effect row, whose effect already ran;
      - the `Parked`, post-dispatch and caller-report rows sign no stop receipt at the refusal. The operation stays live, and its later terminal receipt carries `Terminal`.
      - never `Retained`. Spec 9 M20's third value marks the ambiguous deny of an unknown commit, and `retryable_after_resume` would be `false` for it, but a stop refusal is definite, so no stop receipt carries it.

      A receipt with `true` is evidence of a refused attempt, not a terminal admission record. One with `false` tells the client that retrying the same request id returns the bound terminal result, never a fresh admission. `chio_runtime` is a kernel-reserved metadata key, so caller metadata can never set either field (spec 9 M20).
    - Under process retries, a process retries with the same request id (M: `chio-process/ARCHITECTURE.md:40-45`).
      - On the tier-1, fused and check-only paths, the retry after resume proceeds.
      - On the slow path with a begin row, and on a fused intent from `Prepared`, the id is terminal. The retained call slot then belongs to a dead logical operation, so the worker must use a new operation key. The process tier-1 check before slot commit makes this path rare.
- **S16. Approvals.** Approval collection denies while stopped (M: `collection_context.rs:64`).
    - Approval resolutions for parked operations that arrive while stopped are refused at the edge, before any operation step and without consuming the approval. The parked operation is retained, never compensated (spec 9 M10). After resume, the resolution may be resubmitted and meets the live checks, and pending approvals expire by their own deadlines.
    - Recovery approvals cannot proceed, because `SubmitApproval` and `ResumeWorkflow` deny.
- **S17. Closure is separate.** A stop never revokes, fences spaces, or drains. An operator who wants a permanent effect submits a closure (spec 4) while stopped. Closure ops are allowed because they only revoke, fence, compensate and withdraw.
- **S27. The caller report is progress-only.**
    - An authenticated caller report is persisted as a progress-only return record, the caller output's custody, and it is never stop-checked. Only the later `OutputRelease` crossing is (`Withhold`).
    - This keeps M:'s split between recording and release (`claim_and_record_tool_returned`, then the stop check at `terminal.rs:118-131`).
    - It prevents a stop from turning a known outcome into an unknown one with holds frozen.
    - Spec 10 section 7 and spec 9 M11 state the same rule.
- **S35. Recovery workflows pause.**
    - The recovery and semantic stores return a typed `KernelStopped { scope, epoch }`. They no longer return `refused("plan authority")`, `refused("dispatch basis stale")` or `refused("output emergency stop")` (W: `semantic.rs:270`, `semantic/capture.rs:294-296`, `:336-340`).
    - Every W: caller treats `KernelStopped` as retain or pause, never as terminal failure.
    - A recovery workflow interrupted by a stop resumes after the stop is lifted.

## 9. Authorization

- **S18. Stop.** Stopping is easy and never depends on the clock.
    - **Phase 1 to the identity prerequisite.** Stop routes authenticate with the existing control credential:
      - the sidecar control token on api-protect;
      - the trust-control service token;
      - the hosted MCP admin credential;
      - peer credentials plus the control token on the process-host socket.
      Comparison is constant-time (M: `sidecar-control-authority.md:8-24`), replacing `token == expected` (M: `emergency.rs:193`). Records carry `StopAuthorizer::SharedCredential { credential_id_hash }`, which says truthfully that only the credential, not a principal, is known.
    - **After S28.** A stop is authorized by a signed operator capability token whose subject is a roster principal with stop permission for the scope. Kernel scope needs kernel-operator permission, and tenant scope needs that tenant's operator. Tokens follow the direct-token profile: no delegation chain, caveats or attenuation (W: `recovery/ports.rs:200-215`).
    - **No authority time.**
      - A shared credential involves no time.
      - A token stop checks its signature, subject, roster membership and scope. It checks expiry against the live authority time when available, and otherwise against the persisted trusted-time floor (a monotone lower bound). A token expired relative to the floor is refused.
      - Stop never calls `current_unix_timestamp_ms()` or its `unwrap_or(0)` fallback (W: `kernel/mod.rs:1798-1805`). Accepting a token that expired between the floor and true time is an accepted risk, because a stop only restricts.
- **S19. Resume.** Resume is deliberate. It always carries `expected_epoch` (S31), and it depends explicitly on S28. Before S28, resume uses the shared credential and is recorded as `SharedCredential`. The phase 1 claim limit states "no two-person resume".
    - **Default, `OperatorPair`.** A roster principal different from every principal in the incident's stopper set.
      - **The incident.** It begins at the first `Stop` after the scope's last `Resume`, or at a `Migration` record, which opens the incident of a migrated legacy stop. It covers every later `Restrict`, `Reconcile` and `Rollover` until the resume.
      - **Migrated incidents.** A `Migration` opener records no principal, because the legacy toggle had none (S5). Its stopper set starts empty, and later `Restrict` contributors join it as usual.
        - `OperatorPair.stopper_epoch` names the `Migration` record, so any roster principal outside the set may resume.
        - `SamePrincipalAfter` measures from the `Migration` record's first authority-time observation, which the supervised task writes as for a stop.
        - That is stricter than the legacy toggle, which required no actor at all. Once S28 retires the shared credential, a migrated scope still has a defined resume basis.
      - **The stopper set** is the union, across chain generations, of:
        - the authorizers and contributors of every `Stop` and `Restrict` in that incident;
        - the contributors of every `SubsumedIntent` that a record of the incident carries, in an offline bypass record's `subsumes_intents` or in a `Reconcile` record's `reconciles` (S25, S25a).

        A request that a bypass folded in, or that S25a recovered from a journal the bypass could not read, therefore excludes its principal exactly as if its own record had committed. `Rollover`, `Migration` and `Reconcile` records add no authorizer of their own, and they never hide a principal, because the set is collected through them.
      - `OperatorPair.stopper_epoch` names the incident's opening `Stop`, not the head. The resumer must differ from every principal in the set.
      - `SamePrincipalAfter` measures its cooldown from the opening `Stop`'s observation.
    - **Quorum.** When configured, a `chio.stop-control-quorum.v1` artifact (S29), recorded as `Quorum`.
    - **Single operator.** A deployment may configure `SamePrincipalAfter { cooldown >= 300 s }` explicitly in signed deployment configuration.
      - The cooldown starts at the first successful authority-time observation at or after the stop commit.
      - A supervised task retries `observe_authority_time` while a stopped head lacks that observation. On success it writes `admission_operation_stop_observations(scope_key, chain_generation, epoch, first_observed_at)` as a progress-only commit, keyed by the full `StopEpochId`. Every insert, lookup and comparison uses `(scope_key, chain_generation, epoch)`, so an observation from an older generation's stop with the same numeric epoch can never satisfy a new stop's cooldown.
      - A stop committed with `DecisionTime::Unavailable` therefore gains a start point as soon as the clock recovers. The row survives restart, and the next boot's supervised task re-drives a missing one.
      - The resume record copies the row into `SamePrincipalAfter.cooldown_started` together with its `StopEpochId`. The resume binds the incident's opening `Stop` id, not the head id. A resume whose `cooldown_started` does not equal the stored observation for that opening `Stop`'s exact `(chain_generation, epoch)` refuses. Later `Restrict` and `Rollover` records therefore neither reject the valid observation nor restart the cooldown.
      - The row is a progress-only commit. A restore that loses it only restarts the cooldown at the next observation, so it can delay a resume but never shorten the cooldown.
    - **Break-glass.** When authority time is unavailable or below the persisted floor, so that an ordinary resume refuses (S4), a quorum artifact that also carries a signed time attestation may resume.
      - The time source is pinned in signed deployment configuration.
      - The resume is recorded with `DecisionTime::Attested` and `StopAuthorizer::BreakGlass`.
      - Break-glass never moves the trusted-time floor.
      - It prevents an attacker who can perturb time from keeping the kernel stopped indefinitely.
    - **Unavailable roster.** If the roster or configuration is unavailable, the scope stays stopped.
- **S19a. Exclusions come only from the chain.** The stopper set is computed only from anchored `StopEpochV1` records of the scope's chain (S19).
    - Progress-only rows (notes, observation rows, signing obligations), trace events, SIEM exports and journal entries never add a principal to the set or remove one. Losing any of them therefore never makes a stopper eligible to resume.
    - A request recorded only in the journal is not yet in the set. Its unsatisfied entry instead refuses `Resume` and `Relax` with `StopIntentPending` (S25, S31) until a chain record carrying its contributors is anchored: the applying `Stop` or `Restrict`, a bypass snapshot, or a `Reconcile` record (S25a).
    - Every record that satisfies an entry names that entry's contributors, and S25 removes an entry only after such a record is anchored. Retiring an entry therefore never precedes recording its contributors.
    - The set lives in the one stop chain, under the one serving writer. There is no separate roster of historical stoppers to drift from it.
- **S20. Host latch.**
    - Programmatic `emergency_stop(reason)` from trusted host code, such as the broker authority failure at M: `native_broker/authority.rs:114`, remains a process-local latch in `StopHeads`. It applies to every kernel of the process and to every tier-2 check (S23).
    - It needs no operator to resume. A fresh process either re-establishes the failed component or fails readiness.
    - A host latch implies `allow_containment = false`, because it fires when the authority service itself has failed.
    - The status route reports it separately as `host_latch`.
    - Rewiring `emergency_stop()` to the durable chain is forbidden, so broker failure never requires a two-person resume.
- **S21. Order.** A tenant resume never clears a kernel-scope stop, and a kernel resume never clears tenant or recovery stops. Scopes are independent heads.
- **S28. Identity and roster prerequisite.** S19's `OperatorPair`, `Quorum` and `BreakGlass`, and the control-profile issuance carve-out, require:
    - signed operator capability tokens whose subject is the principal (a `PrincipalId` derived from the subject key);
    - a kernel and tenant roster of principals with `stop` and `resume` permission per scope, published in signed deployment configuration and verified at boot;
    - a quorum threshold `k` and a pinned time-attestation key in the same configuration.

    Until these land, every record is `SharedCredential`, and no two-person claim is made.
- **S29. Stop-control quorum artifact.**

    ```rust
    pub struct StopControlQuorumV1 {
        pub schema: String,                 // "chio.stop-control-quorum.v1"
        pub authority_id: DurableAuthorityId,
        pub scope: StopScope,
        pub expected_epoch: StopEpochId,    // (chain_generation, epoch)
        pub transition: StopTransition,     // Resume or Relax
        pub roster_digest: Sha256Digest,    // the signed roster the approvals are checked against
        pub approvals: Vec<SignedApproval>, // each over H(authority_id, scope, expected_epoch, transition, roster_digest)
        pub time_attestation: Option<SignedTimeAttestation>, // required for break-glass only
    }

    pub struct SignedTimeAttestation {      // signed by the pinned time source (S19 break-glass)
        pub authority_id: DurableAuthorityId,
        pub scope: StopScope,
        pub expected_epoch: StopEpochId,    // equals the artifact's expected_epoch
        pub incident_opening: StopEpochId,  // the incident's opening Stop or Migration (S19)
        pub attested_unix_ms: u64,
        pub nonce: [u8; 16],                // fresh per attestation
        pub signature: Signature,
    }
    ```

    - **Break-glass binding.** When `time_attestation` is present, each approval covers `H(authority_id, scope, expected_epoch, transition, roster_digest, H(time_attestation))`. The approvals therefore sign the exact attestation, and an old attestation cannot be grafted onto a new quorum. Inside the resume transaction the writer checks five things:
      - the attestation verifies against the time source pinned in signed deployment configuration;
      - its `authority_id`, `scope` and `expected_epoch` equal the artifact's and the current head's;
      - its `incident_opening` equals the incident's opening record;
      - `attested_unix_ms` is at or above the opening record's `trusted_floor_at_commit`, a signed value that is present even when that record's `decided_at` is `Unavailable`, and at or above the current persisted trusted-time floor. No local database timestamp is consulted;
      - its `nonce` has not been used before, because nonces are recorded with the resume.

      Any failure refuses the break-glass resume.

    - Verification is offline and signature-only: at least `k` distinct roster principals, no store reads, and no live clock except the attestation.
    - **Bound to the active roster.** The artifact's `roster_digest` must equal the digest of the operator roster active for the scope at the current deployment generation. The verifier takes that from the signed deployment configuration it already holds, not from the artifact. An artifact naming an older roster, even a validly signed one, is refused. After a roster rotation, principals removed from it can never form a quorum.
    - It is not the tool-call `ThresholdApprovalCollector`, which binds approvals to an original agent request and refuses while stopped (M: `collection_context.rs:13-66`).
- **S30. Operator reach.**
    - **Mounted routes** for stop, restrict, relax, resume and status on:
      - trust control (`chio-control-plane`);
      - the api-protect sidecar;
      - the hosted MCP admin surface (`chio-mcp-remote`).
    - **Process-host control socket.** A Unix socket in the host's runtime directory. It requires peer-credential checks (owning uid) plus the control credential, and it carries the same DTOs as the routes. The process host has no HTTP control surface today (M: `process_host/serving.rs`).
    - **CLI.** `chio stop|restrict|relax|resume|status --scope ...` drives the routes or the control socket.
    - **Offline stop.** When the host is down or crash-looping, the CLI acquires the serving-owner lock itself, appends the stop under the same rules (S1, S25), and exits. The next boot loads it (S9). Offline resume uses the same path and requires S19 authorization.
    - **Route results.**

      | Result | Meaning |
      |---|---|
      | `stop_durable` | committed and anchored |
      | `stop_not_durable` | the commit was refused or timed out in the writer. The intent latch holds (`durability: latch_only`), or, if that write also failed, only the process latch (`durability: process_only`) |
      | `stop_outcome_unknown` | the commit outcome is unknown and the owner is poisoned. The intent latch holds, so the next boot honors the stop |
- **S31. Restrict, relax and expected epoch.**
    - `Restrict` (Stopped to Stopped, new epoch) only narrows: it may set `allow_containment` from `true` to `false`. It is authorized like a stop.
    - `Relax` widens `allow_containment` from `false` to `true`. It is authorized like a resume (S19).
    - Every record carries `expected_epoch`. `Resume` and `Relax` refuse with `StopHeadMoved { head: StopEpochId }` when the head has moved, so a delayed resume can never clear a newer stop issued for a different incident. A `Rollover` also moves the head id. A resume decided before a rollover therefore refuses and is re-decided against the new head. That is safe, because the rollover changed no state.
    - `Stop` and `Restrict` never refuse on a moved head. They apply to the current head.
    - `Resume` and `Relax` also refuse with `StopIntentPending` while the scope has an unsatisfied stop-intent entry (S25). `expected_epoch` protects against a moved head; this protects against an intent that is recorded but not yet committed.
- **S32. Recovery-scope stop authority.**
    - A recovery scope may be stopped or restricted by kernel operators, by the owning tenant's operators, or by a recovery actor authenticated through `authenticate_recovery_actor` with a new `RecoveryPermission::Stop` in the deployment's actor assignment (W: `recovery/ports.rs:223-234`; W: `recovery/records.rs:52-69`).
    - A recovery actor can never resume or relax. Resuming a recovery scope follows S19 with the tenant's roster.
- **S33. Tenant attribution.**
    - **Admission operations.** The tenant is `authenticated_tenant_id` from the request namespace (M: `admission_operation/identity.rs:125-156`), read in-transaction from the operation row.
    - **Local-system calls.** Calls attributed to `LOCAL_SYSTEM_TENANT_ID` are subject to the kernel scope only. A tenant stop naming `LOCAL_SYSTEM_TENANT_ID` is refused at the route.
    - **Recovery and semantic crossings.** They take the tenant from the recovery scope's `RecoveryTenantId` (W: `chio-security-types/src/recovery/observation.rs:10-14`), mapped to `TenantId` by signed deployment configuration.
      - When tenant scope is enabled, a recovery installation whose tenant is unmapped is not ready (fail closed).
    - **Processes.** The process tier-1 check uses the tenant bound to the process registration's authenticated principal.

## 10. Evidence

- **Artifact.** Each committed transition produces a signed `chio.stop-epoch.v1` artifact: the `StopEpochV1` body, signed by the serving authority's boot-installed receipt signer (M: `kernel-signing-authority.md:3`, `:29`). The artifact's identity is `(authority_id, scope, chain_generation, epoch)`, all signed, so it is unique across chain generations.
  - In the remote durable profile, the control-plane serving authority that owns the store signs. The edge kernel that relayed the request is named in `requested_via`.
- **S38. Signing obligation.** `SigningBackend::sign_bytes` is fallible (M: `crates/core/chio-core-types/src/crypto.rs:869`). A stop therefore never waits on the signer, and a resume never commits without its evidence.
    - `record_digest` and `previous` cover the canonical `StopEpochV1` body without the signature. Attaching the signature later changes no chain digest.
    - **Running rollovers sign inside the transaction.** A `Rollover` that restates `Running` signs its body inside the appending transaction, like `Resume`. If signing fails, the transaction rolls back and the writer retries with backoff. The previous generation's `rollover_margin` keeps appends possible meanwhile, and a stop can always take the last slot (S6). A running head is therefore never left with an unsigned record in its chain, and S38's claim that a running head's whole chain is signed holds.
    - **Stop, Restrict, Reconcile, Migration and stopped rollovers commit first.** A `Rollover` that restates `Stopped` follows this path, because the scope stays stopped while its evidence is pending. So does a `Reconcile`, which always restates `Stopped`.
      - The restrictive commit that appends the record also inserts `admission_operation_stop_signing(scope_key, chain_generation, epoch, state = pending)`. A `Rollover`, `Reconcile` or `Migration` record, appended by the writer with no new request, gets the same obligation as an operator's stop.
      - After the commit and anchor sync, the writer signs the body. It stores the artifact, and marks the obligation `signed`, in a progress-only commit.
      - A signing failure leaves the record committed and enforced. For a stop or restrict, the route still returns `stop_durable`, with `evidence: pending`. A rollover, reconcile or migration has no route caller, so the status route reports `evidence_pending` for the scope.
    - **Reconciliation.**
      - A supervised task retries pending obligations with backoff, and boot re-drives them after S9 step 3.
      - The trace event and the SIEM export fire only for signed artifacts.
      - The status route reports `evidence_pending` per scope.
    - **Resume and Relax sign inside the transaction.**
      - The writer builds the record and signs it while holding the write transaction, with a bounded timeout (`stop_sign_timeout`, default 2 s). It then commits the record and the signed artifact together.
      - A signing failure or timeout rolls the transaction back. The head stays `Stopped`, and the route returns `ResumeRefused { reason: EvidenceUnavailable }`.
      - Holding the writer for at most `stop_sign_timeout` is acceptable for a rare, operator-driven transition that runs in the priority lane (S36).
    - **No resume over missing evidence.**
      - `Resume` and `Relax` refuse with `StopEvidencePending` while any record of the scope's chain, in any chain generation and of any transition (`Stop`, `Restrict`, `Rollover`, `Reconcile`, `Migration`), has a pending obligation. They refuse with `StopIntentPending` while the scope has an unsatisfied stop-intent entry (S25).
      - A scope whose stop evidence is unsigned therefore stays `Stopped`, and the kernel never returns to `ready` for that scope until reconciliation signs the stop.
      - Only a signed resume can make a head `Running`, and it can commit only when every earlier record is signed. A running head's whole chain, across every generation, is therefore backed by signed artifacts.
- **Trace.** `RuntimeTraceEvent::StopEpochTransition { scope, id: StopEpochId, transition, state }` joins the existing trace events. The SIEM exporter emits the artifact.
- **Status route.** It returns `{ readiness, stopped, scope_heads: [...], host_latch, durability, stop_enforcement, withheld_operations, withheld_volatile }`. The existing `stopped`, `since` and `reason` fields stay as a projection of the kernel-scope head, with `reason` taken from the redacted note.
- **Deny receipts.** Every stop deny receipt carries `chio_runtime.stop = { scope, observed, decided_by: tier1 | tier2, retryable_after_resume }`. `observed` is a discriminated `StopObservation`:
  - `Epoch(StopEpochId)`, the durable head that refused;
  - `HostLatch { latch_id }`, for S20's host latch, which has no epoch;
  - `PendingIntent(StopIntentRef)`, for a `process_only` or `latch_only` stop whose record has not committed.

  A latch-only denial therefore never names an unrelated or running head. Each receipt also carries `chio_runtime.identity_disposition`, and the two always agree (S15, spec 9 M20). The `chio_runtime` block is kernel-reserved: caller-supplied metadata carrying it is rejected before evaluation. M: does not reserve it today (`kernel/mod.rs:151-159`), so this is a kernel change. For `Epoch`, the value is a `StopEpochId`. Tier 1's view can be stale, which is why the field is named `observed`. An auditor joins a refused request to the transition that refused it, or to a later one when tier 1 lagged.

## 11. Hints (spec 5)

A stop is reversible, so it is never `Terminal`. Spec 5 adopts `HintSubject::Stop { scope_ref }` with `HintKind::Changed`, meaning "re-read the stop status". It lands with spec 5 Part B.

- **Source.** The `watch` change notification on the shared `StopHeads` (S24) is the only source of Stop hints for sessions. It fires after each acknowledged transition and on host-latch changes. No hint source reads a per-kernel field.
- **Kernel sessions.** Each session in an affected scope receives it after the transition's `Committed` acknowledgement (spec 5 H2; stop transitions are restrictive commits, so they are anchored).
- **Processes.** There is no process `Stop` hint: spec 5 Part B limits the process projection to `Lifecycle` and `Budget`. Processes learn of a stop from `kernel_stopped` (with `observed`) on `invoke`; operators read the control socket's status.
- **H9 audience.** Tenant-scope stop hints reach only that tenant's sessions. Kernel-scope hints reach all sessions.

## 12. Federation

- **S22. Informational publication.** A serving authority may publish its kernel-scope `chio.stop-epoch.v1` artifacts to treaty peers over iroh lane b.
    - Lane b carries only `RevocationGossipBatch` and catch-up today, verified against pinned revocation-oracle signer keys (V: `crates/trust/chio-federation-transport-iroh/src/lanes/revocation.rs:1-30`). Publication therefore needs:
      - a new message kind, `StopEpochPublication`;
      - a signer-directory entry for the serving authority's receipt signer.
    - A peer may use a publication as an input to its own local policy, for example refusing to start new cross-owner work with a stopped owner.
    - A publication confers no authority, cannot stop the peer, and is never required for safety.

## 13. Multi-instance, sharding and degraded backends

- **One owner per store.** The serving-owner model gives one active writer per admission store. Kernels that share a store in one process share one `StopHeads` (S24). A replacement owner reloads the chain at S9.
- **Remote durable admission.** Edge kernels that share a control-plane store over HTTP (M: `chio-control-plane/src/durable_admission.rs:170-205`) poll or long-poll the head.
  - Each edge holds a staleness bound, `stop_head_max_staleness` (default 1 s).
  - When no fresh head arrives within the bound, the edge treats every scope as `Stopped` for `Deny` and `Withhold` kinds, and reports `stop_head_stale`.
  - Tier 2 still decides, because the crossings commit in the control-plane store.
- **Separate stores.** Kernels with separate stores have separate chains. A fleet stop is a control-plane fan-out, reported per authority, and is never claimed atomic.
- **Degraded backends.** When a crossing's ordering writer is not the admission writer (for example a remote revocation backend, or issuance per S8), that crossing gets tier 1 plus a separate read. The status route then lists it as `stop_enforcement: early_only`.

- **S24. Shared heads and the real staleness bound.**
    - `StopHeads` is owned by the store or runtime handle.
    - The writer swaps it after `COMMIT` and the anchor sync, and before the transition's acknowledgement returns. Every in-process kernel therefore reflects every acknowledged transition.
    - A transition that is committed but not yet acknowledged may be invisible to tier 1. Tier 2 decides those crossings.
    - Remote edges lag by at most `stop_head_max_staleness`, and fail closed beyond it.
- **S23. Durable heads and process latches together.**
    - The effective state inside every crossing closure is `durable_heads ∪ process_latches`.
    - The writer loop runs in-process and reads the latches from the same `ArcSwap` in `StopHeads`.
    - So a host latch, or a stop whose write failed (`process_only` or `latch_only`), refuses store-only crossings with no tier-1 site, such as P4 artifact release, P5 `admit_confined_return`, and the recovery and semantic store checks.
- **S36. Priority lane.**
    - `Stop`, `Restrict`, `Relax`, `Resume`, `Rollover` and `Reconcile` commits run in a priority lane of spec 10's writer loop, exempt from `Overloaded`, `max_batch` and per-tenant caps (spec 10 X17, X20). Overload and full disks are incident conditions.
    - **Narrowing transitions.** Under `SQLITE_FULL` or `IOERR` retry (spec 10 X21), a `Stop` or `Restrict` waits at most `stop_commit_wait` (default 2 s). It then returns `stop_not_durable` with the intent latch in force, and keeps the write queued. A late commit can only narrow.
    - **Widening transitions are never left queued.** A `Resume` or `Relax` that reaches `stop_commit_wait` is withdrawn from the queue if it has not started executing, and the route returns `resume_not_committed`. If it is already inside a batch transaction, the route returns `resume_outcome_unknown`, and the operator reads the scope's status before retrying. Its `expected_epoch` makes a retry safe: a commit that did land moved the head, so the retry refuses. A widening write never commits after the operator was told it failed.
- **S37. Sharding** (only together with spec 10 section 10).
    - The kernel-scope chain originates in the pool shard.
    - Each tenant shard holds a verified replica: the same record bytes and digests, appended as a restrictive commit in the shard. That replica is what spec 10 X3 needs for a tier-2 check in the shard's own writer.
    - Shard readiness requires the replica's head to equal the origin's head exactly, by `(chain_generation, epoch)` and by record digest, read from the origin at boot.
      - **Replica behind.** It catches up first.
      - **Replica ahead.** A shard never legitimately outruns its origin, so this is an origin regression, for example a whole-volume rollback. The shard latches `stop_origin_regressed`, latches the kernel scope `Stopped`, and does not serve.
      - **Unreachable origin.** The shard is not ready.
    - A shard that holds an old generation's high epoch is behind a newer generation's low epoch, because generation compares first. It replicates the `Rollover` record and the new generation's records before it is ready, and its freshness check (below) treats it as behind until then.
    - New shards are seeded with the head before readiness.
    - The operator acknowledgement returns after the origin commit, with per-shard `enforced` status. It never blocks on a dead shard, so stopping stays easy. A shard that misses the fan-out cannot become ready until it catches up.
    - **Origin-freshness lease.**
      - A serving tenant shard holds a lease on the origin head.
      - It polls the origin at least every `shard_origin_refresh` (default 250 ms). **Only a challenge-bound response renews the lease.**
        - **Poll.** Each poll carries a fresh 128-bit `nonce` from the shard's CSPRNG. The shard keeps at most `shard_origin_outstanding` (default 4) outstanding nonces, each with the monotonic time at which it was sent.
        - **Response.** The origin answers with `OriginHeadAttestationV1 { shard_id, nonce, origin_head: StopEpochId, origin_head_digest, origin_committed_mono_ms }`, signed by the serving authority's receipt key. `origin_committed_mono_ms` is the origin's monotonic time of that head's commit, for diagnostics only.
        - **Acceptance.** The shard accepts a response only when all of these hold:
          - the signature verifies against the pinned origin key;
          - `shard_id` is its own;
          - `nonce` is outstanding, and the shard consumes it on first use;
          - `origin_head` is not behind the last head the shard accepted;
          - `origin_head` equals the shard's replica head, **and** `origin_head_digest` equals the digest of the shard's local record at that position. Comparing positions alone is never enough.
        - **Fork.** A response at the shard's position whose `origin_head_digest` differs from the local record's digest is a fork, for example after a whole-volume restore of the origin (S34) produced a different signed record at the same `(chain_generation, epoch)`. The shard latches as in "Lost origin" with `reason: stop_origin_forked` and never renews. Only operator reconciliation clears a fork. The same holds when catching up: a replicated record whose `previous` does not equal the digest of the shard's record before it is a fork.
        - **Ahead.** A response whose `origin_head` is ahead of the replica head renews nothing. The shard takes the "Behind" path, and its lease renews only on a later response that matches its caught-up replica by position and digest.
        - **Lease extent.** An accepted response extends the lease to `sent_at(nonce) + shard_origin_lease`, measured from when the poll was sent, not when the response arrived. A delayed response can therefore never stretch the lease past its own challenge.
        - **Rejection.** A replayed, stale, foreign or unknown-nonce response is discarded and renews nothing. A response whose head is behind the last accepted head is a regression: the shard latches as in "Lost origin" with `reason: stop_origin_regressed`.
        - **Hints only.** Fan-out heartbeats and replicated records never renew the lease. A heartbeat that shows an origin head above the replica's triggers the "Behind" path and an immediate poll; nothing else.
      - The lease lasts `shard_origin_lease` (default 1 s), measured on the shard's monotonic clock, never on authority time.
      - **Bound under replay.** Replaying or delaying origin messages can only withhold renewals, so it can make the shard fail closed sooner. It can never extend the lease.
    - **Behind.** When a response or heartbeat shows an origin head id above the replica's head id, the shard at once installs the kernel scope as `Stopped` in its process latches (S23), then appends the missing records. Tier 2 refuses `Deny` and `Withhold` kinds until the replica catches up.
    - **Lost origin.** When the lease expires, the shard installs the same latch and drops to `not_ready { reason: stop_origin_stale }`. It refuses `Deny` and `Withhold` kinds. It returns to service only after a newly accepted challenge response, bound to a fresh nonce under the acceptance rule above, shows the origin head equal to the replica head by `(chain_generation, epoch)` and by record digest. A replica behind catches up first. A replica ahead of the origin is an origin regression: it latches `stop_origin_regressed` and stays out of service.
    - **Acknowledgement bound.**
      - The origin reports a shard as `enforced` when its replica reaches the stop record's id. Otherwise it reports `fenced_by_lease`, with the time at which that shard's lease expires.
      - Every shard therefore enforces a kernel stop within `shard_origin_lease` plus one renewal interval, whether or not it can reach the origin. A response to a poll sent before the stop committed extends the lease to at most `sent_at + shard_origin_lease`. Every response to a later poll carries the stop record's id or a later one, so it puts the shard on the "Behind" path.
    - A resume committed at the origin takes effect in a shard only after that shard replicates it, so a lagging shard errs toward stopped.

## 13a. Restore, upgrade and downgrade

- **S34. Restore and version rules.**
    - **Anchored transitions.** Stop and resume are restrictive commits, anchored before acknowledgement (spec 10 section 5). A database-only restore to before a stop does not extend the anchor, so `reconcile_startup` refuses (M: `rollback_anchor.rs:106-130`) and the host fails closed.
    - **Stop-intent journal.** It lives in the lock root beside the anchor (S25). A database-only restore therefore keeps every scope's intent entry, and the boot honors them.
    - **Whole-volume restore.** A volume or VM snapshot that restores the database together with the anchor and the latch silently resurrects a running kernel. Later transitions then reuse epoch numbers, so two different signed artifacts can exist for the same `(authority_id, scope, chain_generation, epoch)`. This is a residual risk. Deployments may enable `stop_epoch_floor_check`: at boot, the last record exported to SIEM or published to federation peers is read from a configured external witness as an exact `(StopEpochId, record_digest)` per scope. That exact pair must occur in the local chain's ancestry: the record at that id must exist locally with that digest, and the local head must be at or after it. A local chain that reached the same or a higher position through a different sequence fails this check. Otherwise the host is not ready.
    - **Schema version.** Phase 1 bumps the admission schema version from 34 (M: `admission_operation_store.rs:219`), so the open gate refuses older binaries (M: `schema.rs:63-72`). An older binary never runs against a store that has a stop table.
    - **Upgrade.** The migration that bumps the version creates the stop tables in the same transaction. "Absent before migration" is a normal upgrade. "Missing after migration" means not ready (S9).
- **S25. Stop-intent journal.**
    - Before a stop or restrict transaction begins, the stopping process records its intent in `stop-intent`, a two-slot file in the lock root. The file uses the anchor's slot discipline: write the whole journal to the inactive slot with a sequence number and checksum, fsync it, then make it current.
    - **One entry per scope: the scope's single pending transition.** The journal is a keyed set: `scope_key -> { intent_id, generation, authority_id, scope, allow_containment, contributors: [PendingStopRequest; 1..=2] }`. Each entry is that scope's intent latch, and it represents exactly one future transition: the next one.
      - The entry stores no transition kind and no epoch. The writer computes both when it applies the entry, from the durable head at that moment: over a `Running` head it appends a `Stop` at the head's successor `(head.chain_generation, head.epoch + 1)`; over a `Stopped` head it appends a narrowing `Restrict` at that successor. The intended epoch is therefore always the next one, and an entry can never name an epoch the chain cannot reach.
      - `intent_id` is 128 random bits chosen when the entry is created. `generation` is the number of contributing requests.
      - Each `PendingStopRequest` carries the fields of a `StopRequestRecord` (request id, authorizer, reason commitment and decision time), recorded after S18 authenticates the request. The applying record, a bypass snapshot and a `Reconcile` record copy them unchanged, so a contributor's identity reaches the chain on every path that retires its entry (S19a).
      - **Contributors.** A request that would change the scope's state relative to its durable head plus the pending entry becomes a contributor. Only two states are reachable through stops (`Stopped` with containment allowed, then `Stopped` with containment refused), so an entry has at most two contributors: the request that created it, and at most one later request that narrows `allow_containment` to `false`, which raises `generation` to 2.
      - A request that would change nothing is an idempotent no-op, as in S2. It returns the pending entry's status (`stop_not_durable` with `latch_only` until the entry applies), and its authorizer and reason go to the trace and to `admission_operation_stop_notes`, not to the journal.
      - **Applying.** The appended record carries the entry's final, most restrictive state: the entry's `allow_containment`, `satisfies_intent = { intent_id, generation }` for the generation it was built from, and `contributors` listing every request of that generation, with each request's authorizer and reason commitment.
      - **Why the application is always a valid S2 transition.** Every `Stop` and `Restrict` record of a scope applies that scope's entry, except an offline bypass record, which proves the entry it read through `subsumes_intents` and leaves an unread one to S25a. `Resume` and `Relax` are refused while an entry is pending (below). So the head reaches an unsatisfied entry's state without applying it only under a `subsumes_unread` bypass, where S25a applies the entry as a state-preserving `Reconcile` record. Otherwise the application is either a `Stop` over `Running` or a narrowing `Restrict` over `Stopped`.
      - An intent for one scope never overwrites another scope's entry. With tenant A's stop pending as `latch_only` under `SQLITE_FULL`, a stop for tenant B adds a second entry, and a crash restores both.
    - **Satisfaction.** An entry is satisfied only by proof, never by an epoch number. `satisfied(entry, head)` holds when the scope's anchored head is `Stopped`, and some record `r` in the head's ancestry within the current incident:
      - carries `satisfies_intent = { intent_id: entry.intent_id, generation: g }` with `g >= entry.generation`, so its `contributors` cover the entry's merged set; or is an `offline_bypass` record whose `subsumes_intents` lists `{ entry.intent_id, g }` with `g >= entry.generation`; or is a `Reconcile` record whose `reconciles.intent.intent_ref` is `{ entry.intent_id, g }` with `g >= entry.generation`. A snapshot's `contributors` cover the entry's set, and the live entry's bytes must match its `entry_digest` at removal. A `subsumes_unread` bypass record alone satisfies no entry;
      - has `allow_containment` no wider than the entry's (`false` when the entry says `false`);
      - is followed only by records that preserve a state at least as narrow: `Restrict`, or a `Rollover` or `Reconcile` that restates the head. No `Relax` or `Resume` follows `r`.

      A rollover after the applying record therefore never hides the proof, and a fulfilled entry is removed at boot rather than re-applied or left blocking resume.

      A record built from an older generation does not satisfy the entry. The writer then applies the entry again, which over the now-`Stopped` head is a narrowing `Restrict` built from the current generation.
    - **Removal.** An entry is removed only after an anchored head satisfies it. A crash between that anchor and the removal leaves a satisfied entry, which boot verifies against the head and then removes. An unrelated same-scope record never retires an entry.
    - **Boot.** Every entry that the anchored head does not satisfy is honored, whatever the head's epoch: the scope is `Stopped` with the narrower of the head's and the entry's `allow_containment`, and `durability: latch_only`. The first write after verification applies each such entry as above, or as a `Reconcile` record when S25a applies.
    - **Resume and relax wait for pending intents.** `Resume` and `Relax` refuse with `StopIntentPending { scope }` while the scope has any unsatisfied entry. Under the same journal mutex, and before the widening transition commits, the writer also removes every satisfied entry for the scope and fsyncs the journal slot. If that removal fails, the widening transition is refused (`StopIntentPending { scope, reason: removal_failed }`). An unreadable journal also refuses it (`StopIntentPending { scope, reason: journal_unreadable }`), because the writer cannot then prove that no unsatisfied entry exists. The journal therefore never holds an entry that a later `Resume` or `Relax` would turn from satisfied into unsatisfied, and boot can never reapply a stale intent over a validly resumed scope. The check runs under the journal mutex, which the writer holds from the check through the commit and anchor sync of the resume or relax. A stop or restrict intent that arrives meanwhile waits for the mutex, then records its entry and applies over the resulting head. A resume can therefore never commit between an intent's fsync and that intent's own record.
    - **Bound.** The journal holds at most `stop_intent_max_entries` entries (default 4096). Each entry is at most 512 bytes, so a slot stays under 2 MiB.
      - When the journal is full, a new scope's intent is not recorded. The route returns `stop_not_durable` with `durability: process_only` and reason `stop_intent_journal_full`, and readiness reports it.
      - Existing entries are never evicted to make room.
    - **Writer.** The serving owner, which holds the lock root, serializes journal writes. The offline CLI takes the same owner lock (S30).
    - A failed intent write leaves only the process latch (`process_only`), and the route reports it. This applies only to a serving host, whose process keeps the latch.
    - **Offline CLI.** The offline CLI never reports `process_only`, because its process exits and no latch survives. With the host down and the owner lock held (S30), it appends the durable stop record itself:
      - when the journal is full or the intent write fails, it skips the journal and appends the transition directly: a `Stop` over a running head, or a narrowing `Restrict` over a stopped head. A down host has no queue to overload.
      - **Pending entries are folded in first.** Before a bypass append, the CLI reads the scope's existing journal entries. Reading still works when a write does not. The bypass record folds them in:
        - its `allow_containment` is the narrowest of the request and every pending entry;
        - `subsumes_intents` holds a signed snapshot of the entry: `{ intent_ref: { intent_id, generation }, allow_containment, contributors, entry_digest }` (S2). Its contributors join S19's stopper set once the bypass record is anchored.

        Satisfaction (below) treats a listed entry as satisfied, so a stale entry can neither be re-applied over an already narrow head nor block `Resume` or `Relax`. If the journal cannot even be read, the CLI still appends the bypass record, with an empty list and the signed flag `subsumes_unread: true`, and reports `stop_durable` with `journal_unreadable`. Boot then refuses readiness until the journal is readable (S9).
        - **Recoverable proof.** Once the journal is readable, each entry for that scope is reconciled through S25a. No unread entry leaves the journal before its contributors are in an anchored chain record. An unread entry blocks `Resume` and `Relax` only until its `Reconcile` or `Restrict` is anchored, which happens on the first write while the store is writable.
        - **Record form.** The bypass record uses S2's verifiable no-intent offline form: `requested_via: OfflineCli`, `satisfies_intent: None`, `offline_bypass: true`, with its contributor and note as usual. No `StopIntentRef` is fabricated;
      - success requires the record committed and anchored, and the CLI reports `stop_durable`;
      - if that append also fails, the CLI exits non-zero and reports `stop_not_in_force`. It states that no stop is recorded and that the operator must keep the host down or retry. It never claims a stop is in force.
    - This extends AC6's "publish first" rule from memory to durability.
- **S25a. Reconciling entries an unreadable-journal bypass covered.** Once the journal is readable (at boot, or when a host not ready for `journal_unreadable` reads it again), the writer reconciles every entry of a scope whose current incident holds an `offline_bypass` record with `subsumes_unread: true` (the bypass record). This completes before any `Resume` or `Relax` of that scope can commit.
    - **Membership.** Any such entry was recorded in the current incident, because a `Resume` or `Relax` cannot commit while an unsatisfied entry exists and removes every satisfied one first (S25).
    - **Entry no narrower than the head.** The writer appends a `Reconcile` record (S2) in the priority lane (S36), with `reconciles = { bypass, intent }`, where `intent` is the entry's `SubsumedIntent` snapshot: its ref, containment, contributors and `entry_digest`.
      - The record restates the head, so the incident does not pretend to narrow again.
      - It is a restrictive commit, anchored before acknowledgement (S1). Only after that anchor does S25 remove the entry, after checking the live bytes against `entry_digest`.
    - **Entry narrower than the head.** It is applied as a narrowing `Restrict`, as usual, whose `contributors` carry the entry's requests. No `Reconcile` is appended for it.
    - **Stopper set.** Either way, the entry's contributors are in an anchored chain record before the entry leaves the journal, so S19 excludes them. A progress-only note may still keep the redacted reason for audit (S1), but it carries no exclusion (S19a).
    - **Resume waits.** Until that record is anchored the entry is unsatisfied. The scope stays `Stopped` with the narrower of the head's and the entry's `allow_containment`, and `Resume` and `Relax` refuse with `StopIntentPending` (S25, S31). The status route reports `stop_reconcile_pending` for the scope.
    - **Failure.** If the `Reconcile` cannot commit (for example on `SQLITE_FULL`), the writer retries it with backoff in the priority lane, and the entry stays. With the host down, the offline CLI can append the same record under the serving-owner lock (S30). Resume stays refused until the record is anchored.
      - An unknown commit outcome poisons the owner, as for any transition. The next boot re-reads the chain: an anchored `Reconcile` satisfies the entry and boot removes it; otherwise boot reconciles again.
      - A crash between the anchor and the removal leaves a satisfied entry, which boot removes without appending a second record.
    - **Restore and rollover.** A database-only restore behind the `Reconcile` fails the anchor check (S34), so the host fails closed rather than losing the exclusion. A whole-volume restore that predates the `Reconcile` also restores the journal entry, so boot reconciles it again. A later `Rollover` never hides the record, because S19 collects the set across generations.
    - **Headroom.** A `Reconcile` leaves the head `Stopped`, so it may take slots up to `bound` (S6). In a full generation it waits for the pending `Rollover`, and resume stays refused meanwhile.

## 14. Failure modes

| Failure | Behavior |
|---|---|
| Restart with operations in `Finalizing` while stopped | Heads load first; the sweep retains them; the host serves `ready_stopped`; resume releases them (S9, S26) |
| Stop write refused, or timed out in the writer | Intent latch holds, and tier 1 latches; the route returns `stop_not_durable` with `latch_only`; retry is idempotent (S25, S30) |
| Stop intent write fails too | Process latch only; the route returns `stop_not_durable` with `process_only`; readiness reports it |
| Commit outcome unknown | Owner poisoned (M: `admission_operation_store.rs` `commit_write`); the route returns `stop_outcome_unknown`; the intent latch makes the next boot stopped |
| Writer overloaded or tenant capped | The priority lane bypasses both (S36) |
| Disk full | The bounded wait then `stop_not_durable` with the intent latch, if the latch write succeeded (S36) |
| Chain unreadable or invalid at boot | `not_ready`; kernel scope latched `Stopped`; the stop and status routes answer (S9, S10) |
| Authority clock unavailable | Stop and restrict commit with `Unavailable`; resume refuses unless break-glass; the cooldown waits for the first observation (S4, S19) |
| Clock below the persisted floor | Same as unavailable; break-glass resume available (S19) |
| Roster, configuration or quorum unavailable | Resume refuses; stop is unaffected |
| Tier 1 stale (in-process) | Only between `COMMIT` and acknowledgement; tier 2 decides (S24) |
| Remote edge cannot refresh the head | Fail closed after `stop_head_max_staleness` (section 13) |
| Crash after commit, before head swap | Restart loads the committed head; the kernel comes up stopped |
| Chain at `bound - 1` | Resume and relax refuse; a stop or restrict can still append, and the head ends `Stopped` (S6) |
| Generation reaches `bound - rollover_margin` | The writer appends a `Rollover` record in the priority lane. State is unchanged, and the new generation starts with full headroom (S6) |
| Rollover cannot commit (disk full) | Retried with backoff. Resume and relax still refuse at `bound - 1`. A generation that reaches `bound` ends `Stopped` until the rollover commits, or until the offline CLI appends it (S6) |
| Replayed or delayed origin response, or a replayed fan-out heartbeat | Discarded unless it answers an outstanding nonce, which is consumed on first use. A late answer extends the lease only to `sent_at + shard_origin_lease`. Heartbeats never renew. The shard loses its lease on schedule and reports `stop_origin_stale` (S37) |
| Origin response whose head is behind the shard's last accepted head | Regression: the shard latches the kernel scope `Stopped` and goes `not_ready { stop_origin_regressed }` (S37) |
| Crash around a rollover | The rollover is anchored before acknowledgement, so restart finds either generation `g`'s final record or the anchored `Rollover` record as head. Both carry the same state (S6) |
| Delayed resume after a newer stop | Refused with `StopHeadMoved` (S31) |
| Host latch set | Every crossing refuses `Deny` and `Withhold` kinds; containment refused (S20, S23) |
| Shard misses the fan-out | That shard latches the kernel scope `Stopped` at its next renewal, and is not ready until its replica reaches the origin epoch (S37) |
| Serving shard loses the origin | Its lease expires within `shard_origin_lease`. It latches the kernel scope `Stopped` and reports `not_ready` with `stop_origin_stale` (S37) |
| Stops for several scopes pending at once | Each scope keeps its own intent entry, and a crash restores every one (S25) |
| Intent journal full | `stop_not_durable` with `process_only` and `stop_intent_journal_full`; no entry is evicted (S25) |
| Resume or relax while a same-scope stop or restrict intent is pending | Refused with `StopIntentPending`; the intent applies first (S25, S31) |
| A committed stop record is wider than, or older than, the merged intent | The entry is not retired; the writer applies it again as a `Restrict` built from the current generation. A crash in between restores the narrower policy at boot (S25) |
| A latch-only stop, then a narrowing request for the same scope, then a crash | The entry holds both contributors at generation 2. Boot honors it as `Stopped` with containment refused; the first write appends one `Stop` at `head.epoch + 1` that carries both contributors (S25) |
| Offline bypass while the journal is unreadable, then the journal becomes readable | Each covered entry is applied as an anchored `Reconcile` record carrying its contributors, or as a narrowing `Restrict`, before it is removed. Its contributors join the stopper set. Until then, and while the journal is unreadable, resume and relax refuse with `StopIntentPending` (S19, S25, S25a) |
| `Reconcile` cannot commit | Retried with backoff in the priority lane; the entry stays; resume and relax refuse with `StopIntentPending`; the status route reports `stop_reconcile_pending` (S25a) |
| A progress-only stop note or observation row is lost | The stopper set is unchanged, because it reads only chain records (S19a). A lost observation only restarts a cooldown (S19) |
| Origin response at the shard's position with a different head digest | Fork (for example, a whole-volume restore at the origin): the shard latches the kernel scope `Stopped`, goes `not_ready { stop_origin_forked }`, and never renews. Operator reconciliation clears it (S37) |
| Artifact signing fails for a rollover or migration record | The record stays committed and enforced. The obligation is retried and re-driven at boot. The status route reports `evidence_pending`, and resume and relax refuse with `StopEvidencePending` until it is signed (S38) |
| Artifact signing fails for a stop or restrict | The stop stays committed and enforced, and the route returns `stop_durable` with `evidence: pending`. The obligation is retried, and re-driven at boot. Resume and relax refuse with `StopEvidencePending` (S38) |
| Artifact signing fails or times out for a resume or relax | The transaction rolls back, and the head stays `Stopped`. The route returns `ResumeRefused { EvidenceUnavailable }` (S38) |
| Database-only restore behind the stop | Anchor refuses; not ready (S34) |
| Whole-volume restore | Residual risk; optional external epoch floor (S34) |
| Older binary | Refused by the schema gate (S34) |

## 15. Protocol, schema, and wire impact

- **Schemas.** New `chio.stop-epoch.v1` and `chio.stop-control-quorum.v1` under `spec/schemas/`, with codegen and vectors. New store tables: `admission_operation_stop_epochs`, `admission_operation_stop_notes`, `admission_operation_stop_observations` and `admission_operation_stop_signing` (S38). A schema version bump (S34). The lock-root `stop-intent` journal format, keyed by scope (S25).
- **`spec/PROTOCOL.md` section 8.**
  - Mounted stop, restrict, relax, resume and status routes, with their credential and route results (S30).
  - The status response shape and readiness states (additive fields).
  - The deny reason `kernel_stopped`, the `chio_runtime.stop` receipt metadata, and the `output_withheld` result (S14).
- **Process ABI.** The `withheld` status on `invoke` (S14) and the control socket DTOs (S30). Both are additive.
- **Federation.** Lane b `StopEpochPublication` and the signer-directory entry (S22).
- **Ledger.** EV11 acceptance evidence is listed in section 17. AC6 closes before this design (section 16), and S4 and S25 preserve its ordering rule.
- **Native wire.** Verdicts and receipt kinds are unchanged.

## 16. Rollout

0. **AC6 now.** AC6's remaining acceptance needs no durable chain: "Document in-process stop scope and verify the existing stop precedes fallible time reads" (M: `landing-ledger.json:5118`).
   - Land a security document describing the in-process stop scope.
   - Add a test that asserts the flag is published before `read_authority_time` (M: `construction.rs:1674-1681`), extending the Loom harness `loom_emergency_stop_arcswap` (M: `.loom/harnesses.toml:60`).
   - This spec preserves AC6. It does not close it.
1. **Phase 1, the minimal honest phase for EV11** (bug-fix lane; legacy evaluator and reconciler; no dependency on specs 9 or 10).
   - **Durable record.** The kernel-scope chain in the admission serving writer as a restrictive commit (S1, S2); the schema version bump (S34); resume headroom (S6); the per-scope stop-intent journal (S25); the signing obligation (S38).
   - **Boot.** Heads before the sweep, with stop-withheld operations retained (S9); `ready_stopped`, with routes served when not ready (S10); durable custody for withheld output (S26).
   - **Enforcement.**
     - Tier 1 at all eleven M: sites, read from `StopHeads` shared per store across every kernel in the host, including api-protect's proxy authority kernel (S11, S24).
     - A typed `KernelStopped` (S35).
     - The host latch kept separate (S20) and consulted by store-only crossings (S23).
     - Tier 2 lands as CAS predicates in the existing dispatch-commit and release transactions, in the same form as spec 4 section 4.1. Phase 2 absorbs them.
   - **Operator reach.**
     - Mounted routes on api-protect, trust control and hosted MCP.
     - The process-host control socket and CLI, including offline stop (S30).
     - Constant-time comparison (N23).
     - `StopAuthorizer::SharedCredential` (S18).
     - Stop authentication without a clock (S18).
   - **Evidence in hosted CI (GT1).**
     - A stop through the route.
     - A restart with in-flight `Finalizing` work comes up `ready_stopped` and serves status.
     - Tool calls deny.
     - Revocation and cancel work.
     - Resume works, and the withheld output is released.
   - **Claim limit.** "Durable, operator-reachable, restart-safe, early-enforced, with tier-2 predicates at dispatch commit and release only. No two-person resume. Issuance paths outside the kernel are tier 1 only, or unchecked where listed (S8). P5 window between admission and delivery is tier 1 only (S7). Withheld P5 returns are volatile until W: journals confined output (S26)."
2. **Phase 2, tier 2 as spec 10's `StopEpoch` `CrossingCheck`.** This is the per-kind dispositions of section 5 in every `CrossingTx`, plus the priority lane (S36). It lands with spec 10 phase 2.
   - **Spec 9 dependency.** Spec 9 phase 3 builds the stop path on the machine. Its M10 parked-retain row, M11 retain row, and the progress-only caller report (S27) carry these rules onto the machine. Phase 1 implements the same rules on the legacy evaluator, so phase 2 changes where they execute, not what they decide.
3. **Phase 3, identity and roster (S28), then S19 and S29.** Two-person, quorum, cooldown and break-glass resume. Control-profile issuance carve-out.
4. **Phase 4, tenant scope** (S33).
5. **Phase 5, recovery scope** (S5, S32). This is a trivial merge, because the template has no production caller.
6. **Phase 6, evidence and hints.** Signed artifacts, trace, SIEM, deny receipt metadata, `withheld` results everywhere, and spec 5 Part B hints (section 11).
7. **Phase 7, federation** (S22).
8. **Sharding** only together with spec 10 section 10 (S37).

Every phase ships behind `durable-stop` until its conformance scenarios pass. Hardening gate GT1 applies: no EV11 claim until the phase 1 scenarios run in hosted CI.

## 17. Tests and conformance evidence

- **Loom.**
  - The writer loop's swap of `StopHeads` against concurrent tier-1 readers.
  - Host-latch publication against crossing closures.
  - The ordering "publish the latch, then read time".
  - Loom does not model SQLite IMMEDIATE ordering.
- **Store hooks and DST for races.**
  - A stop commit racing a `DispatchCommitted` CAS gives exactly one order.
  - With a stale tier 1, tier 2 still refuses the post-stop crossing.
  - Random stop, restrict, resume, dispatch, release, settle and recovery capture sequences. Properties:
    - no `Deny` or `Withhold` crossing has a `CrossingOrder` after a `Stopped` head's commit in an applicable scope, counting written records and check-only receipts placed by `observed_commit_sequence` (spec 10 X4);
    - every `Settle` crossing after a stop references only subjects whose `CrossingOrder` precedes the stop record's;
    - every `AllowIfContainment` crossing during a stop has `allow_containment` and no host latch.
  - A shard offline during the fan-out, then restarted: it is not ready until caught up (S37).
  - A serving shard partitioned from the origin, then a kernel stop at the origin: within `shard_origin_lease` the shard refuses `Deny` crossings and reports `stop_origin_stale`. After it reconnects, it serves again only once its replica holds the stop (S37).
  - **Replayed freshness evidence (Codex round 8).** Capture a pre-stop origin response and a pre-stop fan-out heartbeat. Commit a kernel stop at the origin, cut the shard's polls, and replay both repeatedly. Neither renews the lease. The lease expires no later than `shard_origin_lease` after the shard's last fresh poll was sent, and the shard reports `stop_origin_stale`. Responses with a consumed nonce, an unknown nonce, another shard's id, a bad signature, or a head behind the last accepted head never renew. The last of these latches with `stop_origin_regressed`. A response delayed past its poll extends the lease only to `sent_at + shard_origin_lease` (S37).
  - **Legacy migration (Codex round 9).** Seed a W: store with `semantic-stop:{scope} = true`, then upgrade and start. The scope's first record is a `Migration` at `(1, 1)`, `Stopped`, with empty `contributors`, `authorizer: LegacySemanticStop` and the fixed reason commitment. Recovery crossings for the scope deny from the first request. A verifier refuses a `Migration` record at `(1, 2)`, in a kernel scope, or after a `Stop`. A legacy `false` writes nothing.
  - **Unsigned rollover or migration blocks resume (Codex round 9).** Make the signer fail during an automatic rollover, and separately during a migration. Each record commits with a pending obligation. A resume refuses with `StopEvidencePending` until reconciliation signs it, across the generation boundary.
  - **Equal-position origin fork (Codex round 9).** A shard replica holds a `Running` record at `(1, 7)`. Restore the origin's whole volume from a snapshot and append a different `Stopped` record at `(1, 7)`. The shard's next challenge response carries a matching position, a fresh nonce and a valid signature, but a different `origin_head_digest`. The shard latches with `stop_origin_forked`, refuses `Deny` and `Withhold` crossings, and never renews.
  - **Rollover representability (Codex round 8).** An automatic rollover produces a record with empty `contributors`, `satisfies_intent: None`, `authorizer: ChainRollover { serving_owner, writer_epoch }`, `requested_via: SystemRollover`, and the fixed reason commitment, which verifies. A verifier rejects four records: a `Rollover` with a contributor; a `Rollover` whose reason commitment, state or `expected_epoch` does not restate the previous generation's final record; a `Stop` with authorizer `ChainRollover`; and a `Stop` whose authorizer differs from `contributors[0]` (S2 field rules).
- **Crash injection** (store test hooks).
  - Commit a stop, kill before the head swap, restart: the kernel comes up stopped.
  - Kill mid-resume before commit, restart: still stopped.
  - Kill after the resume commit: running.
  - Write the intent latch, kill before the stop commit, restart: `ready_stopped` with `latch_only`, then the record is appended (S25).
  - Two pending stop intents (tenant A `latch_only` under `SQLITE_FULL`, then tenant B), kill, restart: both scopes come up stopped, and each entry is removed only after its own scope's record is anchored (S25).
  - Commit a stop, kill before its artifact is signed, restart: the stop is enforced, the obligation is re-driven, and a resume refuses with `StopEvidencePending` until it is signed (S38).
  - **Queued resume versus a restrict intent (R-8-01).** Signed stopped head E with containment allowed; a resume expecting E is queued; a restrict intent (containment off) is fsynced. The resume refuses with `StopIntentPending`. In the variant where the resume held the journal mutex first, it commits and anchors E+1, the restrict entry is then recorded and applied as a `Stop` with containment off; kill between that anchor and the next transaction, restart: the scope is `Stopped` with containment off, never `Running` (S25, S31).
  - **Two pending stops for one scope (R-8-01).** Two stop requests for the same scope merge, the second narrowing containment (generation 2). The first, wider record commits carrying generation 1 and is anchored; kill before the follow-up `Restrict`, restart: the entry is unsatisfied, so the scope comes up `Stopped` with containment off and `latch_only`, and the first write appends a `Restrict` carrying generation 2 (S25).
  - **Latch-only stop, then a narrowing request, then a crash (Codex round 5).** The head is `Running` at epoch 4. A stop under `SQLITE_FULL` is recorded as `latch_only` (generation 1); a narrowing request (containment off) joins the entry (generation 2) before any record commits. Kill, restart: the scope is `Stopped` with containment off; the first write appends exactly one `Stop` at epoch 5 with containment off, `satisfies_intent` generation 2 and both contributors; the entry is then removed. No `Restrict` is ever appended over the running head (S2, S25).
  - **S8-01:** stop with caller-executed, native and ordinary operations in `Finalizing`; kill; restart. The host serves `ready_stopped`, status answers, resume succeeds, and the outputs are released exactly once.
  - **Unreadable-journal bypass keeps every stopper (R-8-03).** Roster principals A, B and C; the default `OperatorPair` resume.
    - A requests a stop with containment disabled. Its journal entry is fsynced, and the host dies before the chain record commits.
    - With the journal made unreadable, B runs the offline CLI. The bypass appends a stopped head with containment disabled and `subsumes_unread: true`.
    - Make the journal readable and boot. Boot appends a `Reconcile` record carrying A's snapshot and only then removes the entry. The stopper set is `{A, B}`.
    - A's `OperatorPair` resume refuses at every point: while the journal is unreadable (`StopIntentPending`, `journal_unreadable`); after it is readable but before the `Reconcile` is anchored (`StopIntentPending`); and afterward, because A is in the stopper set.
    - It still refuses after a restart, after the entry is removed, after a rollover into a new generation, after a database-only restore behind the `Reconcile` (the anchor refuses startup), and after a whole-volume restore to before it (boot reconciles again).
    - C's resume succeeds. Deleting the scope's progress-only notes changes nothing.
  - **Stopper variants (R-8-03).**
    - An unread entry with two contributors: both join the stopper set, and neither may resume.
    - A readable bypass: the `subsumes_intents` snapshot carries A's contributor and recomputes its `entry_digest`. A's resume refuses. A verifier rejects a snapshot whose contributors do not recompute the digest.
    - An unread entry with containment disabled over a bypass head with containment allowed: it is applied as a narrowing `Restrict` whose contributors include A, no `Reconcile` is appended, and A's resume refuses.
    - A `Reconcile` that cannot commit (`SQLITE_FULL`): the entry stays, the status route reports `stop_reconcile_pending`, and resume refuses until the record is anchored.
- **Identity disposition per path (R-8-02).** Each case separate. Each asserts `retryable_after_resume == (identity_disposition == Reusable)` and the behavior of a retry with the same request id after resume:
  - tier-1 early stop denial: `Reusable`; the retry is admitted;
  - fused intent from `Unbegun` refused by a stop: `Reusable`; the retry is admitted;
  - fused intent from `Prepared` refused by a stop: compensated, `Terminal`; the retry returns the bound compensated result;
  - slow path with a begin row refused by a stop: compensated, `Terminal`; the retry returns the bound compensated result;
  - parked operation during a stop: no stop receipt; after resume it proceeds, and its terminal receipt is `Terminal`;
  - durable post-effect release during a stop: output withheld with no stop receipt; released after resume, terminal receipt `Terminal`;
  - check-only read withheld: `Reusable`, `retry: AfterResume`;
  - `NonDurable` effect withheld: `Terminal`, `retry: Never`;
  - caller metadata carrying `chio_runtime` is rejected before evaluation.
- **Failure injection.**
  - Stop under `Overloaded` and per-tenant caps: committed through the priority lane.
  - Stop under `SQLITE_FULL`: `stop_not_durable` with `latch_only`; a restart is stopped.
  - Stop with an unknown commit outcome: `stop_outcome_unknown`; a restart is stopped.
  - Stop with the signer failing: `stop_durable` with `evidence: pending`, and the stop is enforced. Resume with the signer failing or timing out: rolled back, still stopped (S38).
  - A full intent journal: the next new-scope stop reports `process_only` and `stop_intent_journal_full`, and no existing entry is evicted (S25).
- **Multi-kernel.**
  - A stop through one hosted MCP session's route denies tool calls in every other session's kernel.
  - A resume clears them all.
  - The api-protect proxy path denies while stopped (S24, S11).
  - A remote edge past `stop_head_max_staleness` fails closed.
- **Paths.**
  - A two-commit read refused at the outcome commit writes a return record, is never re-dispatched, and returns `output_withheld` (S14).
  - A caller report during a stop is persisted; its release is withheld; after resume it is released (S27).
  - A parked operation receives an approval during a stop: the approval is refused unconsumed, and the operation stays `Parked` (S16).
  - Tier-1 and fused-path stop denials write no tombstone. The same request id succeeds after resume (S15).
  - A host latch refuses a P4 release and a P5 `admit_confined_return`, and refuses containment (S23, S20).
  - A recovery workflow paused by a stop resumes after resume (S35).
- **Restore and versions.**
  - A database-only restore behind a stop fails startup (S34).
  - A restore with the intent latch present comes up stopped.
  - An older binary refuses the bumped schema.
  - "Missing after migration" is not ready.
- **Unit.**
  - Chain rules S2 (gap, mismatch, idempotent repeat, `Restrict` narrowing only).
  - `expected_epoch` refusal (S31).
  - S4 clock behavior.
  - Clock-unavailable stop authentication commits (S18).
  - Cooldown start on the first observation (S19).
  - Quorum artifact verification with fewer than `k`, duplicate principals, or a wrong roster digest (S29).
  - S5 migration of a legacy `semantic-stop` record without an installed registry.
  - Resume headroom at `bound - 1`, and a stop or restrict filling the last slot ends `Stopped` (S6).
  - **Rollover while stopped (Codex round 7).** Drive a stopped scope to `bound - rollover_margin`. The `Rollover` record is generation 2, epoch 1, still `Stopped` with the same `allow_containment`. Crossings stay refused throughout, a pending resume decided against the old head refuses with `StopHeadMoved`, and a pending intent applies at `(2, 2)`. Repeat while running: the head stays `Running`, and a stop after the rollover appends at `(2, 2)`.
  - **Shard with an old high epoch (Codex round 7).** A shard replica at `(1, 65,530)` and an origin head at `(2, 3)`. The shard is behind, latches the kernel scope `Stopped`, and is not ready until it replicates the `Rollover` record and generation 2. A comparison of `epoch` alone would wrongly call the shard ahead; the test asserts it is not used.
  - **Artifact identity across generations (Codex round 7).** Artifacts for `(1, 7)` and `(2, 7)` of one scope have distinct signed bodies and identities. A verifier given one cannot accept it as the other, and the SIEM floor check compares `(chain_generation, epoch)`.
  - Cooldown: a resume with a mismatched `cooldown_started` refuses, and a lost observation row restarts the cooldown (S19).
  - **`Reconcile` field rules (R-8-03).** A verifier rejects a `Reconcile` that narrows or widens `allow_containment`, follows a `Running` head, names a bypass record without `subsumes_unread`, names one from an earlier incident or one followed by a `Relax` or `Resume`, carries an entry narrower than the head, has a non-empty `contributors`, or carries a snapshot whose `entry_digest` does not recompute (S2).
  - Constant-time credential comparison.
  - Host latch independence and its containment implication (S20).
  - Tenant attribution, including the `LOCAL_SYSTEM_TENANT_ID` refusal (S33).
- **Disposition coverage.** Totality over `CrossingKind`, `KernelOp`, `RecoveryCommandBodyV1` and `GovernedResponseEffect` is enforced by exhaustive matches under spec 1 R2 (no wildcards), so it needs no proof tool. The real gap is the mapping from entry point to op, which is spec 1's generated census test.
- **Conformance** (`chio-conformance`, EV11 evidence).
  - An operator stop through the mounted route and through the process-host socket.
  - A process restart with in-flight work comes up `ready_stopped`.
  - A tool call, a recovery resume and a P5 return all deny or withhold while stopped.
  - Revocation, closure, cancel and inspect still work.
  - After S28: a resume by the same principal is refused, and a resume by a second principal succeeds.
  - Before S28: a resume records `SharedCredential`.

## 18. Residual risks and open decisions

Residual risks:

- **Pre-stop crossings.** Effects whose crossing committed before the stop complete. Only their later releases are withheld.
- **Early-only crossings.** Crossings whose ordering writer is not the admission writer, including issuance, get tier 1 only.
- **P5 delivery window.** A stop between the admission commit and `sink.deliver` is caught by tier 1 only (S7).
- **Volatile P5 withholds.** These last until W: journals confined output (S26).
- **Whole-volume restore.** It can resurrect a running kernel, unless the external epoch floor is configured (S34).
- **Cross-owner work.** A stop does not reach a remote owner's kernel, so cross-owner work already sealed elsewhere continues there.
- **Slow-path request ids.** A stop refusal on the slow path with a begin row burns the request id, as on M: today (S15).
- **Shared credential.** Until S28, anyone holding the control credential can resume.
- **Operator token expiry.** Before the control-profile carve-out, operator tokens for cancel, closure and containment must be provisioned with a validity longer than the longest expected stop (S8-16).

Open decisions:

1. **Single-operator resume.** Is the default `OperatorPair`, with `SamePrincipalAfter` opt-in, right? Recommendation: yes.
2. **Containment.** Should containment during a stop default to allowed (S12), with `allow_containment = false` as the stricter option? Recommendation: allowed by default, because every current effect narrows authority. Host latches always forbid it.
3. **R5b.** Should spec 1 keep R5b (per-entry-point dispositions), or split `CallerExecution`, `IssueCapability` and `RecoveryControl` into separate ops? Recommendation: keep R5b.
4. **Federation consumption.** Should treaty peers be allowed to make a published stop a mandatory local deny for new cross-owner work, or only advisory?
5. **Pre-dispatch parking on the slow path.** Should slow-path operations with a begin row park instead of compensating (S15), to preserve request ids across a short stop? This needs a new admission state, and this design declines it. Under the machine (spec 9), fused calls already preserve ids.
6. **External epoch witness.** Which witness should `stop_epoch_floor_check` read (S34): SIEM, a federation peer, or a transparency log?

## Review disposition

| Finding | Disposition |
|---|---|
| S8-01 Blocker | Applied. S9 ordering, Retain during the sweep, `ready_stopped` (S10), durable custody (S26), crash case in section 17 |
| S8-02 | Applied. S23; test in section 17 |
| S8-03 | Applied. Headroom (S6), intent latch (S25), priority lane (S36), route results (S30) |
| S8-04 | Applied. `SharedCredential` (S18); identity prerequisite named (S28); S19 depends on it |
| S8-05 | Applied. Offline quorum artifact (S29) |
| S8-06 | Applied. Stop authentication without authority time (S18) |
| S8-07 | Applied. Cooldown from the first observation (S19); break-glass; `DecisionTime` enum |
| S8-08 | Applied. Shared heads (S24); remote staleness bound (section 13); api-protect binding (S11) |
| S8-09 | Applied. Control socket, CLI, offline stop (S30) |
| S8-10 | Applied. P5 point is `admit_confined_return` (section 5); delivery window stated (S7) |
| S8-11 | Applied. Per-kind dispositions (section 5); `StopEpoch` takes `(kind, scopes, disposition)`; DST property adjusted |
| S8-12 | Applied. S27 |
| S8-13 | Applied. S37 |
| S8-14 | Applied. Section 13a (S34) |
| S8-15 | Applied. S8 mint path table |
| S8-16 | Applied. Control-profile carve-out after S28 (section 7.1); operational requirement before it (section 18) |
| S8-17 | Applied differently. `KernelStopped` writes no tombstone on any path except the slow path with a begin row, which keeps M:'s behavior (S15). The review recommended "no tombstone" for tier 1 only. The fused path also drops the tombstone, because a stop is temporary and process retries reuse ids |
| S8-18 | Applied. A return record on refusal; `OutputWithheld` (S14) |
| S8-19 | Applied. Edge refusal without consumption; parked Retain (S16, S15) |
| S8-20 | Applied. `Restrict`, `Relax`, `expected_epoch` (S31) |
| S8-21 | Applied. `RecoveryControl` entry-point table; `settle_children` row; recovery-scope authority (S32). `ManageDelegationParent` stays `deny`; spec 1 revision 3 already records `deny` with the same M: citation, so no spec 1 change is needed |
| S8-22 | Applied. S35 |
| S8-23 | Applied. S33 |
| S8-24 | Applied. Section 16 phases 0-8; spec 9 dependency named |
| S8-25 | Applied. Signer, lane b extension, `observed_epoch` (sections 10 and 12) |
| S8-26 | Applied. Section 17 |
| S8-27 | Applied. Host latch implies `allow_containment = false` (S20, S12); forensic guidance; flag in status |
| S8-28 | Applied. Citations corrected (`tests/semantic.rs:513`; reconciliation is many transactions; `issue_capability_with_security_context`; installation independence in S5). The spec 10 `:1598` citation is spec 10's to fix |
| S8-29 | Applied. Trigger wording (S1); salted reason commitment with a separate note table |
| S8-30 | Applied. Kani totality withdrawn in favor of compiler exhaustiveness and spec 1's census; Loom limited to the writer loop and heads; races through store hooks and DST |

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180274497 | Reserve durable capacity for a final stop | Already addressed in revision 2; tightened now | S6: resumes refuse at `bound - 1`, so a running head always has a slot for a durable stop. `Stop` and `Restrict` may fill the last slot, so exhaustion always ends `Stopped` |
| 4180274500 | Allow containment to be disabled during an existing stop | Already addressed in revision 2 | S2 records a narrowing stop-over-stopped as `Restrict`; S31 defines `Restrict` (Stopped to Stopped, `allow_containment` true to false, authorized like a stop) |
| 4180389997 | Define stop behavior when artifact signing fails | Fixed now | S38: a stop commits first with a durable signing obligation; a resume or relax signs inside its transaction or rolls back; resume refuses while any stop evidence is pending; failure-table rows and tests |
| 4180390001 | Define a cooldown origin for clockless stops | Already addressed in revision 2; tightened now | S19: the cooldown starts at the first authority-time observation after the stop, stored durably in `admission_operation_stop_observations` and re-driven at boot; break-glass covers a clock that never recovers. Now also: resume must match the stored origin, and a lost row only restarts the cooldown |
| 4180731762 | Persist outstanding stop intents per scope | Fixed now | S25: the intent file is a keyed journal, one entry per scope; entries merge within a scope, never across scopes, and are removed only after that scope's matching transition is anchored; bounded, with no eviction |
| 4180731782 | Continuously fence shards that lose the stop origin | Fixed now | S37: a renewable origin-freshness lease on the shard's monotonic clock; a shard that is behind or loses the origin latches the kernel scope `Stopped` and goes not ready; the acknowledgement reports `enforced` or `fenced_by_lease` |

### Codex review (PR #1174, round 5)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180993960 (spec 9) | Make stopped non-durable effects terminal to retries | Fixed here for spec 8's wire and receipt surface. `OutputWithheld` gains `retry: AfterResume \| Never` and `effect_executed`. A `NonDurable` side-effecting call whose release a stop refused returns `retry: Never` with `effect_executed: true`, and its stop receipt has `retryable_after_resume: false`. S15's per-path table lists that path as terminal, not temporary | S14 client-visible result; S15 |
| 4180993957 | Preserve every pending transition for a scope | Fixed now. Each scope's pending requests collapse into one next transition. The journal entry stores no transition kind or epoch. At apply time the writer appends a `Stop` at `head.epoch + 1` over a running head, or a narrowing `Restrict` at `head.epoch + 1` over a stopped head, always with the entry's final state (narrowest containment, every contributor). An entry has at most two contributors, because only two states are reachable through stops, and a non-narrowing request is an idempotent no-op. `satisfies_intent` plus `contributors` cover the merged set, matching the R-8-01 retirement rule. A crash test covers a latch-only `Stop` followed by a narrowing request | `StopEpochV1.contributors`; S25; section 14; section 17 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-8-01 | An unrelated same-scope epoch can erase a pending stop or restriction | Fixed. Each journal entry has a durable `intent_id` and a `generation` that counts its contributing requests. Stop and Restrict records carry `satisfies_intent`. An entry retires only when an anchored head proves it was applied (matching id, current generation, containment no wider), never by epoch number. Boot honors every unsatisfied entry. Resume and relax refuse with `StopIntentPending` under the journal mutex, so a resume cannot commit between an intent's fsync and its record. A `Restrict` that finds a running head applies as a `Stop`. Both counterexamples are crash tests | `StopEpochV1.satisfies_intent`; S25; S31; S38; S9 step 3; section 14 failure rows; section 17 |
| R-1-01 (spec 1) | Caller reconciliation belongs to two different ABI operations | Fixed in spec 1. The S13 `CallerExecution` row here now states that `reconcile_caller_execution*` belongs to `CallerExecution` only | section 7 S13 row |

### Codex review (PR #1174, round 7)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185260860 | Carry the chain generation through rollover | Fixed now. `StopEpochV1` carries a signed `chain_generation`, and the record identity, table key, notes, signing obligation, artifact and trace use `(chain_generation, epoch)`. `expected_epoch`, quorum approvals, `StopHeadMoved`, the SIEM floor, the `Epoch` arm of `observed` and shard readiness and freshness compare `StopEpochId` lexicographically. A `Rollover` record starts each generation at `bound - rollover_margin`, restates the head and satisfies no intent, so it never changes state and needs no resume authority; headroom applies per generation. Tests cover rollover while stopped and running, a shard with an old high epoch, and artifact identity across generations | section 4 types; S1, S2, S3, S6, S25, S29, S31, S34, S37, S38; section 10; section 14; section 17; spec 10 section 10 |
| 4185260847 (spec 10) | Include Relax commits in the priority lane | Fixed in spec 10 X17a, which now lists `Stop`, `Restrict`, `Relax`, `Resume` and `Rollover`, matching S36 | S36 (now also lists `Rollover`) |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-8-02 | Slow-path terminal stop denials are marked retryable after resume | Fixed. `retryable_after_resume` must equal spec 9 M20's `identity_disposition == Reusable`. It is `false` for compensated slow-path and `Prepared`-intent stop denials and for the `NonDurable` effect, and `true` only for tier-1, fused-from-`Unbegun` and check-only refusals. S15 gains the missing `Prepared` row. Per-path tests are separate for early, fused, prepared, slow, parked, post-effect, check-only and `NonDurable` | S15; section 10 deny receipts; section 17 |
| R-6-05 / R-6-06 (cross-reference) | Kernel-reserved receipt metadata | Fixed. The `chio_runtime.stop` block, with `chio_runtime.identity_disposition`, is kernel-reserved, so caller metadata can never set or override it. This is a kernel change: M: reserves seven other keys (`kernel/mod.rs:151-159`) | section 10 deny receipts; S15 |

### Codex review (PR #1174, round 9)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185756902 | Define an encodable legacy migration transition | Fixed now. `StopTransition::Migration` is a new variant with its own S2 field rules: valid only at `(1, 1)` of a `Recovery` scope with no earlier record; `Stopped`; empty `contributors`; `authorizer: LegacySemanticStop`; `requested_via: Migration`; `satisfies_intent: None`; a reason commitment over a fixed domain string and the legacy key. S5 writes it in S9 step 2, before the heads are installed, so a legacy stopped scope comes up `Stopped` | `StopTransition`; S2; S5; S9; section 17 |
| 4185756924 | Create signing obligations for rollover records | Fixed now. `Rollover` and `Migration` take the commit-first signing obligation and reconciliation path, like `Stop` and `Restrict`. Resume and relax refuse with `StopEvidencePending` while any record of the scope's chain, in any generation, is unsigned | S38; section 14; section 17 |
| 4185756940 | Reject equal-position origin forks before renewing the lease | Fixed now. Acceptance requires the origin head to equal the replica head by position **and** digest. An equal position with a different digest is a fork that latches `stop_origin_forked` and never renews. An origin head that is ahead renews nothing and takes the Behind path, and catch-up checks `previous` digests | S37; section 14; section 17 |

### Codex review (PR #1174, round 8)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185510083 | Make automatic rollover records representable | Fixed now. S2 defines field rules per transition. A `Rollover` has `requested_via: SystemRollover` (or `OfflineCli` for the offline append), `authorizer: ChainRollover { serving_owner, writer_epoch }`, empty `contributors`, `satisfies_intent: None`, and `reason_commitment = SHA-256("chio.stop-epoch.rollover.v1\0" \|\| expected_epoch \|\| previous)`. It restates the previous generation's final state, containment and id. The `authorizer`/`reason_commitment == contributors[0]` invariant applies only to `Stop`, `Restrict`, `Relax` and `Resume`, and verifiers reject a record that breaks its transition's rule | section 4 types (`StopRequestPath`, `StopAuthorizer::ChainRollover`, `DecisionTime`); S2; S6; section 17 |
| 4185510099 | Reject replayed origin-freshness heartbeats | Fixed now. Only a signed `OriginHeadAttestationV1` that answers an outstanding, single-use shard nonce renews the lease, and only to `sent_at(nonce) + shard_origin_lease`. A replayed, stale, foreign or unknown-nonce response renews nothing. A head behind the last accepted head latches with `stop_origin_regressed`. Fan-out heartbeats are hints that trigger the "Behind" path and never renew. Replay can only shorten the lease. New failure rows and a replay test | S37; section 14; section 17 |

### Codex review (PR #1174, round 10)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185993956 | Block running rollover heads until their artifact is signed | Fixed now. A `Rollover` that restates `Running` signs inside its transaction, like `Resume`, and rolls back and retries if signing fails; the rollover margin and the reserved stop slot keep the chain appendable. Only a rollover that restates `Stopped` commits first with a pending obligation. A running head's chain is therefore always signed | S38 |

### Codex review (PR #1174, round 11)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186194363 | Key cooldown observations by the full stop epoch | Fixed now. `admission_operation_stop_observations` is keyed by `(scope_key, chain_generation, epoch)`, and every insert, lookup and comparison uses the full `StopEpochId`. The resume record carries it, so an older generation's observation can never satisfy a new stop's cooldown | S19 |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364947 | Require exact origin equality before shard readiness | Fixed now. Boot readiness requires an exact position and digest match with the origin head. A replica behind catches up. A replica ahead is an origin regression: the shard latches `stop_origin_regressed` and the kernel scope `Stopped`, and does not serve. Spec 10 S3 mirrors this | section 13 sharding; S37 |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-6-07 (alignment) | An ambiguous commit denial binds the adapter before recovery produces the terminal receipt | Fixed. `retryable_after_resume` stays equal to `identity_disposition == Reusable`, so it is `false` for the new `Retained` value. A stop refusal is definite, so stop receipts are never `Retained` | S15 |
| R-10-03 (consumer side) | The crossing index lacks the ordering contract required by its consumers | Fixed. S7's `Settle` test, its predicate and the DST property use spec 10 X4's `CrossingOrder`. A subject's order is compared with the stop record's own `commit_sequence` in the same store, or the shard's replica. `ChainRollover`'s `writer_epoch` remains the serving owner's fence and is not used for ordering | S7; section 8 predicate; section 17 DST |

### Codex review (PR #1174, round 13)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186619802 | Require exact origin equality when recovering the lease | Fixed now. Recovery from `stop_origin_stale` requires a newly accepted challenge response showing the origin head equal to the replica head by position and digest. A replica behind catches up first, and a replica ahead latches `stop_origin_regressed` | S37 lost origin |
| 4186619834 | Verify the witnessed stop-chain digest | Fixed now. `stop_epoch_floor_check` reads the witnessed `(StopEpochId, record_digest)` and requires that exact pair in the local chain ancestry. A forked chain that reaches the same position through a different sequence is not ready | section 13a whole-volume restore |

### Codex review (PR #1174, round 14)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186767809 | Do not rely on a process latch for offline stops | Fixed now. The offline CLI never falls back to a process latch. On a full journal or a failed intent write it appends the durable stop record directly. If that also fails it exits non-zero with `stop_not_in_force`, stating that no stop is recorded | S25 writer; S30 |

### Codex review (PR #1174, round 17)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187142791 | Define a valid record for journal-bypass offline stops | Fixed now. S2 defines a verifiable no-intent offline form: `requested_via: OfflineCli`, `satisfies_intent: None`, `offline_bypass: true`. Verifiers accept it only from the offline CLI, it retires no journal entry, and the bypass append uses it. No intent reference is fabricated | S2; S25 offline CLI |

### Independent review pass 4 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-1-03 (cross-reference) | The recovery inventory stops before implemented P6 setup and signed maintenance | Applied here. Section 7 gains P6 stop-disposition rows matching spec 1 section 6: mutations `deny`, reads `allow`, and the setup gate inherits its caller's disposition | section 7 |

### Codex review (PR #1174, round 18)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187315432 | Preserve stopper identities across stopped rollovers | Fixed now. S19 defines the incident (from the first `Stop` after the last `Resume`) and its stopper set: the authorizers and contributors of every `Stop` and `Restrict` in it, collected across generations and through `Rollover` records. `OperatorPair.stopper_epoch` names the opening stop, and the resumer must differ from every principal in the set | S19 |

### Codex review (PR #1174, round 19)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187433114 | Check the opening-stop observation for cooldown resumes | Fixed now. A `SamePrincipalAfter` resume binds the incident's opening `Stop` id and is checked against that stop's observation, not the head's. Restrictions and rollovers neither reject the valid observation nor restart the cooldown | S19 |
| 4187433127 | Add a journal-bypass form for offline Restrict | Fixed now. The no-intent offline form (`requested_via: OfflineCli`, `satisfies_intent: None`, `offline_bypass: true`) covers both `Stop` and `Restrict`. The bypass path appends a `Stop` over a running head or a narrowing `Restrict` over a stopped head | S2; S25 |

### Codex review (PR #1174, round 20)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187512211 | Define an opening incident for migrated stopped scopes | Fixed now. A `Migration` record opens an incident with an empty stopper set. `OperatorPair.stopper_epoch` names it, so any roster principal outside the set may resume, and `SamePrincipalAfter` measures from its first observation. A migrated scope keeps a resume basis after S28 | S19 |
| 4187512221 | Bind quorum resumes to the active roster | Fixed now. The quorum artifact's `roster_digest` must equal the roster active for the scope at the current deployment generation, taken from the verifier's signed deployment configuration. Older rosters are refused, so removed principals cannot form a quorum | S29 |
| 4187512225 | Preserve satisfied intents across rollover | Fixed now. Satisfaction is checked over the head's ancestry within the incident: a matching `satisfies_intent` record followed only by state-preserving records (`Restrict`, or a restating `Rollover`) satisfies the entry. A rollover never hides the proof, and the entry is removed at boot | S25 satisfaction |

### Codex review (PR #1174, round 21)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187599062 | Remove satisfied intents before allowing resume | Fixed now. Under the journal mutex, and before a `Resume` or `Relax` commits, the writer removes every satisfied entry for the scope and fsyncs the slot. A failed removal refuses the widening transition, so no stale intent can be reapplied at boot over a resumed scope | S25 |
| 4187599073 | Bind break-glass time attestations to the incident | Fixed now. `SignedTimeAttestation` names the authority, scope, `expected_epoch`, incident opening, time and a nonce. The quorum approvals cover its hash, so it cannot be grafted onto a new quorum. The resume transaction checks the pinned source, the incident binding, freshness against the opening commit and the trusted-time floor, and nonce reuse | S29; S19 break-glass |

### Codex review (PR #1174, round 22)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187663042 | Define a timestamp for clockless incident openings | Fixed now. Every `StopEpochV1` carries a signed `trusted_floor_at_commit`, the persisted floor read in its own transaction, so it is present even when `decided_at` is `Unavailable`. Break-glass checks the attestation against the opening record's floor and the current floor, never a local timestamp | record fields; S29 break-glass |
| 4187663066 | Reconcile pending intents before an offline bypass | Fixed now. Before a bypass append, the CLI reads the scope's pending entries and folds them in: narrowest containment, and a new `subsumes_intents` list. Satisfaction treats listed entries as satisfied, so a stale entry cannot block resume or be re-applied. An unreadable journal still gets the stop, and boot refuses readiness | record fields; S25 offline CLI and satisfaction |
| 4187663074 | Cancel timed-out resume and relax writes | Fixed now. Only narrowing transitions stay queued after `stop_commit_wait`. A timed-out `Resume` or `Relax` is withdrawn before execution (`resume_not_committed`), or reported `resume_outcome_unknown` if already in a batch. `expected_epoch` makes the retry safe, so a widening write never commits after a failure report | S36 |
| 4187663058 (spec 9) | Use a store-recovery retry condition for unavailable checks | `OutputWithheld` gains `reason: StoreUnavailable` and `retry: AfterStoreRecovery`, used by spec 9 M19 for reusable check-only reads | S14 client-visible result |

### Codex review (PR #1174, round 24)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187829605 | Make unreadable-journal bypasses retire pending intents | Fixed now. An unreadable-journal bypass record carries a signed `subsumes_unread: true`. Once readable, boot treats each entry no narrower than the head as satisfied by that record, records its contributors in a note and removes it, and applies a narrower entry as a `Restrict`. This is sound because entries present while stopped belong to the current incident. Unread entries can no longer block readiness or resume | record fields; S25 offline CLI |

### Codex review (PR #1174, round 25)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187931947 | Align bypass field rules with intent retirement | Fixed now. S2's field rule says a bypass record never retires entries through `satisfies_intent`, only through its proof fields. Each `subsumes_intents` ref must name a read entry at its generation, with no wider containment, and `subsumes_unread` triggers S25's boot reconciliation. Non-bypass records must leave both fields empty | S2 |

### Codex review (PR #1174, round 26)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4187992998 | Persist evidence needed to verify bypass intent references | Fixed now. `subsumes_intents` holds signed `SubsumedIntent { intent_ref, allow_containment, entry_digest }` snapshots. Verification uses the snapshot in the signed record, so later boots and replicas can re-verify after S25 removes the entries, and boot checks live entry bytes against the digest before removal | record fields; S2; S25 |
| 4187993012 | Represent latch-only denials without a stop epoch | Fixed now. Stop deny receipts carry `observed: StopObservation`: `Epoch(StopEpochId)`, `HostLatch { latch_id }` or `PendingIntent(StopIntentRef)`. A host-latch or latch-only denial is truthfully represented and never names an unrelated head | section 10 deny receipts; S15; S14 |
| 4187993006 (spec 9) | Match retry advice to the actual release refusal | `OutputWithheld.reason` also admits `AuthoritySpaceClosed`, `Revoked` and `InsufficientIntegrity` for spec 9's reason-specific check-only release refusals | S14 |

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-8-03 | Unread-journal bypass drops a stopper from the two-person resume predicate | Fixed. Confirmed against the round 24-26 text: the `subsumes_unread` retirement wrote the entry's contributors only to a progress-only note, and `SubsumedIntent` held only a digest, so S19's set lost the stopper on both bypass paths. Now `SubsumedIntent` carries the entry's contributors, bound by an `entry_digest` that verifiers recompute, and they join S19's set. A `subsumes_unread` record satisfies no entry by itself: S25a retires each covered entry only after a new state-preserving `Reconcile` record, a restrictive anchored commit on the same chain, carries its snapshot. A narrower entry is still a `Restrict`. S19a takes exclusions only from chain records, never from notes. Resume refuses with `StopIntentPending` until reconciliation is anchored, and while the journal is unreadable. One chain and one writer; no separate stopper roster | record fields; S2; S6; S19; S19a; S25; S25a; S36; S38; section 14; section 17 |

### Independent review pass 6 and PR round 28

| Comment or finding | Title | Disposition | Where |
|---|---|---|---|
| R-2-03 / 4190476138 (spec 8 side) | Reserving a successor can permanently supersede the root while recovery creation is stopped | Applied here. The `RecoveryControl` table gains spec 2's `reserve_successor_ordinal` with disposition `deny`, checked for the predecessor's and successor's scopes in the claim's writer transaction before any mutation. An identical replay is a readback and is allowed. Root supersession happens only in the stop-gated `CreateWorkflow` | section 7 `RecoveryControl` table |

## Appendix A. FTL reference

What FTL does (`/Users/connor/Medica/backbay/ftl`):

- **Boot ordering.** `boot` initializes memory, CPU state and drivers, and loads the first thread before the scheduler runs any user code (`kernel/src/boot.rs:39-45`). Nothing user-visible runs until boot completes. Section 6's "heads first, then the sweep" is the same ordering.
- **Destroyed flag.** A handle space's `destroyed` flag is checked under the space lock by every insert (`kernel/src/hspace.rs:46`, `:90`), and set under the same lock at close (`:169`). Tier 2 is that pattern: the stop is checked inside the same writer transaction as the state change it guards.

Where the analogy breaks:

- **Durability.** FTL has no persistent state, and a reboot always starts fresh. A Chio restart must come up stopped, so the flag must be durable and verified before the reconciliation sweep.
- **Reversibility.** FTL's `destroyed` flag is terminal. A Chio stop is reversible, so it needs epochs, a chain, and an authorization asymmetry between stop and resume.
- **Ordering writers.** FTL has one lock per object. Chio has several writers, and a crossing in a different writer than the stop gets only the early check (section 13).

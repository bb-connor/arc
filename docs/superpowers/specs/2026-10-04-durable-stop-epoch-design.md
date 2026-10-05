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
  - `chio-store-sqlite`: stop chain table, stop-intent latch file, in-transaction checks.
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
}

pub enum StopState { Stopped, Running }      // derived from the transition

pub struct StopEpochV1 {
    pub schema: String,                      // "chio.stop-epoch.v1"
    pub authority_id: DurableAuthorityId,    // serving authority, from the anchor
    pub scope: StopScope,
    pub epoch: u64,                          // per scope, +1 per transition, starts at 1
    pub transition: StopTransition,
    pub state: StopState,
    pub expected_epoch: u64,                 // head epoch the transition was decided against; 0 for the first record
    pub reason_commitment: Sha256Digest,     // SHA-256(salt || text); salt and text in the note table (S1)
    pub authorizer: StopAuthorizer,
    pub decided_at: DecisionTime,
    pub previous: Sha256Digest,              // digest of this scope's prior record, or zero
    pub allow_containment: bool,             // section 7.1, S12
    pub requested_via: StopRequestPath,      // Route { host_id } | ControlSocket | OfflineCli | Migration
}

pub enum DecisionTime {
    Observed(UnixMillis),                    // observe_authority_time inside the write transaction
    Unavailable,                             // Stop and Restrict only (S4)
    Attested(TimeAttestationRef),            // break-glass Resume (S19)
}

pub enum StopAuthorizer {
    SharedCredential { credential_id_hash: Sha256Digest }, // phases before S28; truthful about who is known
    Operator { principal: PrincipalId },                   // a roster principal (S28)
    OperatorPair { stopper_epoch: u64, resumer: PrincipalId },
    SamePrincipalAfter { principal: PrincipalId, cooldown_ms: u64, cooldown_started: UnixMillis },
    Quorum { artifact_digest: Sha256Digest, principals: Vec<PrincipalId> },        // S29
    BreakGlass { artifact_digest: Sha256Digest, attestation: TimeAttestationRef }, // S19
    RecoveryActor { subject: PublicKeyHex },                                       // S32, Stop and Restrict only
    LegacySemanticStop,                                                            // S5 migration only
}
```

Normative rules:

- **S1. Writer.**
   - Records are appended to a new table, `admission_operation_stop_epochs(scope_key, epoch, record_digest, previous_digest, payload)`, through the admission store's `begin_write` (IMMEDIATE, active-owner and anchor checks; M: `admission_operation_store.rs:350-363`), `commit_write` and `sync_after_write`.
   - The table is append-only: `BEFORE UPDATE` and `BEFORE DELETE` triggers `RAISE(ABORT)`, as `authority_global_commits_immutable` does (M: `serving_owner/global_commit_chain.rs:86-96`).
   - Every transition is a restrictive commit under spec 10 section 5, anchored before acknowledgement.
   - The salted reason text lives in `admission_operation_stop_notes(scope_key, epoch, salt, redacted_text)`. That table is operator-readable, outside the chain, and deletable for retention. The chain keeps only the commitment, so short text cannot be brute-forced from the record.
- **S2. Chain.**
   - For each scope, `epoch` increases by exactly 1, and `previous` equals the digest of the prior record.
   - `state` follows the transition. `Restrict` and `Relax` require a `Stopped` head, and `Resume` requires a `Stopped` head.
   - A `Stop` over a stopped head is an idempotent no-op that returns the current head, unless it asks for narrower containment, in which case it is recorded as `Restrict`.
   - A `Resume` over a running head is a no-op that returns the current head.
   - The table joins the global commit chain projection coverage, as W:'s recovery projection kind does.
- **S3. Head.**
   - The head for a scope is its highest epoch. A scope with no record is `Running`.
   - The effective state for a crossing is `Stopped` if any applicable scope head is `Stopped`, or if any process latch applies (S23).
- **S4. Time.**
   - `decided_at` comes from `observe_authority_time` inside the write transaction.
   - If time is unavailable, including when the wall clock is below the persisted floor (M: `schema/clock.rs:35-50`), a `Stop` or `Restrict` still commits with `DecisionTime::Unavailable`. This preserves the AC6 rule that stopping never depends on the clock.
   - A `Resume` or `Relax` without authority time refuses, unless it is the break-glass path (S19).
- **S5. Migration of the template.**
   - At startup, any existing W: `semantic-stop:{scope}` record whose value is `true` becomes a `Recovery` scope head. It is written as epoch 1 with authorizer `LegacySemanticStop` and `requested_via: Migration`.
   - The four W: check points call the unified `stop_state(tx, kind, &[Recovery(scope), Tenant(t), Kernel])` in place of `stopped(tx, scope)`.
   - `set_semantic_emergency_stop` becomes a thin wrapper that requires an authenticated actor (section 9) and takes the serving fence.
   - Stopping a recovery scope never depends on whether a semantic registry is installed. The `installation(&tx, scope)` precondition (W: `semantic.rs:375-376`) applies only to the legacy write path, which migration retires.
- **S6. Bounds and headroom.**
   - A record is at most 4 KiB, and a scope keeps at most 65,536 records (`bound`).
   - Every transition other than `Stop` refuses once the scope holds `bound - 1` records. A running head therefore always has room for one `Stop`.
   - A scope that reaches `bound` is stopped, and stays stopped, until a chain rollover. Readiness reports `stop_chain_exhausted`.
   - A chain rollover is an offline CLI operation authorized like a resume (S19). It archives the chain and seeds a new chain generation whose genesis record's `previous` is the archived chain's final digest.

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
   - A `Settle` crossing passes only when every effect it completes or settles has a crossing index (`batch_index`, `writer_epoch`) earlier than the stop head's commit. A `Settle` crossing with no prior committed subject is a new authorization and is refused.
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
settle(x) crossed after committed(stop(s, e)) -> every subject(x) indexed before stop(s, e)
allow_if_containment(x) crossed while stopped -> head.allow_containment and no host latch
```

## 6. Boot and readiness

- **S9. Heads first, then the sweep.** Startup runs in this order:
   1. Open the store as serving owner. The anchor is reconciled (M: `rollback_anchor.rs:106-130`).
   2. Check the stop chain table under the schema gate (section 13a). A table that is absent before migration is created by the migration in the same step. A table that is missing when the schema version claims it means not ready, with reason `stop_chain_missing`.
   3. Read the stop-intent latch (S25). Verify S2 for every scope chain. Install `StopHeads` as the verified heads, overlaid with any unsuperseded intent.
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
| per entry point (S13) | `CallerExecution` | `reserve_` and `start_` deny; the authenticated report is a progress-only return record and is allowed (S27); release is `OutputRelease` (`Withhold`); `reconcile_caller_execution*` allow |
| per entry point (S13, R5a) | `RecoveryControl` | see the next table |

`RecoveryControl` entry points (spec 1 section 5 lists seven):

| Entry point | Disposition | Rationale |
|---|---|---|
| `authenticate_recovery_actor` (W: `recovery/ports.rs:193`) | `allow` | `CancelWorkflow` and recovery-scope stop must authenticate |
| `execute_recovery_command` | per variant (R5a): `InspectWorkflow` and `CancelWorkflow` allow; every other variant denies | as spec 1 R5a |
| `read_recovery_workflow` | `allow` | observation |
| `load_recovery_request_custody` (W: `recovery/ports.rs:272`) | `allow` | an actor-authenticated read; it crosses no effect custody |
| `observe_recovery_capability_liveness` | `allow` | observation |
| `reserve_recovery_review` (W: `recovery_runtime.rs:267`) | `deny` | it advances a workflow toward an effect |
| `acknowledge_recovery_reservation` (W: `recovery_runtime.rs:91`) | `deny` | it binds a process reservation to a workflow |

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
  - `InspectWorkflow`, `CancelWorkflow`, `/v1/recovery/settle` (`attach_provider_finality`) and `/v1/recovery/explain` allow. Explain is pure advisory, and settle records provider finality for effects that already happened.

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
    - **Client-visible result.** A request whose output is withheld completes with `OutputWithheld { operation_id, reason: KernelStopped { scope, observed_epoch } }`:
      - on JSON-RPC surfaces, an error with code `output_withheld` and data `{ operation_id, scope, observed_epoch, retry: "after_resume" }`;
      - on the process ABI, `invoke` returns status `withheld` with the same fields.

      After resume, a replay with the same request id (or the same process operation key) returns the released output through the bound durable result. A surface without that replay path delivers the outcome only through the terminal receipt and is named in the claim limit.
- **S15. Stop refusals per path.** `KernelStopped` is a temporary refusal. It never writes a deny tombstone, and it burns a request id only where M: does today.

    | Path | Where refused | Result | Request id |
    |---|---|---|---|
    | Tier 1 early, before any durable row | any existing check site | `SignReceipt(Deny { kernel_stopped })` with `observed_epoch`; no tombstone | not burned; the same id proceeds after resume |
    | Fused intent commit (spec 9 M10, spec 10 X15) | tier 2 in `IntentCommit` | savepoint rolls back; deny receipt only; no `DenyTombstone` | not burned |
    | Check-only read | tier 1 or the check-only crossing | deny receipt only | not burned |
    | Slow path with a begin row, not parked | the dispatch-commit CAS | compensate under `PreDispatchNoEffect`; deny receipt | terminal, as on M: today |
    | `Parked` (approval) | the resume intent commit | **Retain** in `Parked`; no compensation (S16) | unchanged; resumes after resume |
    | Post-dispatch (`Finalizing`, a release) | the release crossing | `Withhold` (S14) | unchanged |
    | Caller report | never stop-checked (S27) | return record persisted | unchanged |

    - A stop deny receipt carries `chio_runtime.stop = { scope, observed_epoch, retryable_after_resume: true }`. It is evidence of a refused attempt, not a terminal admission record.
    - Under process retries, a process retries with the same request id (M: `chio-process/ARCHITECTURE.md:40-45`).
      - On the tier-1, fused and check-only paths, the retry after resume proceeds.
      - On the slow path with a begin row, the id is terminal. The retained call slot then belongs to a dead logical operation, so the worker must use a new operation key. The process tier-1 check before slot commit makes this path rare.
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
    - **Default, `OperatorPair`.** A roster principal different from every authorizer of the stop being resumed.
    - **Quorum.** When configured, a `chio.stop-control-quorum.v1` artifact (S29), recorded as `Quorum`.
    - **Single operator.** A deployment may configure `SamePrincipalAfter { cooldown >= 300 s }` explicitly in signed deployment configuration.
      - The cooldown starts at the first successful authority-time observation at or after the stop commit.
      - A supervised task retries `observe_authority_time` while a stopped head lacks that observation. On success it writes `admission_operation_stop_observations(scope_key, epoch, first_observed_at)` as a progress-only commit.
      - A stop committed with `DecisionTime::Unavailable` therefore gains a start point as soon as the clock recovers.
    - **Break-glass.** When authority time is unavailable or below the persisted floor, so that an ordinary resume refuses (S4), a quorum artifact that also carries a signed time attestation may resume.
      - The time source is pinned in signed deployment configuration.
      - The resume is recorded with `DecisionTime::Attested` and `StopAuthorizer::BreakGlass`.
      - Break-glass never moves the trusted-time floor.
      - It prevents an attacker who can perturb time from keeping the kernel stopped indefinitely.
    - **Unavailable roster.** If the roster or configuration is unavailable, the scope stays stopped.
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
        pub expected_epoch: u64,
        pub transition: StopTransition,     // Resume or Relax
        pub roster_digest: Sha256Digest,    // the signed roster the approvals are checked against
        pub approvals: Vec<SignedApproval>, // each over H(authority_id, scope, expected_epoch, transition, roster_digest)
        pub time_attestation: Option<SignedTimeAttestation>, // required for break-glass only
    }
    ```

    - Verification is offline and signature-only: at least `k` distinct roster principals, no store reads, and no live clock except the attestation.
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
    - Every record carries `expected_epoch`. `Resume` and `Relax` refuse with `StopHeadMoved { head_epoch }` when the head has moved, so a delayed resume can never clear a newer stop issued for a different incident.
    - `Stop` and `Restrict` never refuse on a moved head. They apply to the current head.
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

- **Artifact.** Each committed transition produces a signed `chio.stop-epoch.v1` artifact: the `StopEpochV1` body, signed by the serving authority's boot-installed receipt signer (M: `kernel-signing-authority.md:3`, `:29`).
  - In the remote durable profile, the control-plane serving authority that owns the store signs. The edge kernel that relayed the request is named in `requested_via`.
- **Trace.** `RuntimeTraceEvent::StopEpochTransition { scope, epoch, transition, state }` joins the existing trace events. The SIEM exporter emits the artifact.
- **Status route.** It returns `{ readiness, stopped, scope_heads: [...], host_latch, durability, stop_enforcement, withheld_operations, withheld_volatile }`. The existing `stopped`, `since` and `reason` fields stay as a projection of the kernel-scope head, with `reason` taken from the redacted note.
- **Deny receipts.** Every stop deny receipt carries `chio_runtime.stop = { scope, observed_epoch, decided_by: tier1 | tier2, retryable_after_resume }`. Tier 1's epoch can be stale, which is why the field is named `observed_epoch`. An auditor joins a refused request to the transition that refused it, or to a later one when tier 1 lagged.

## 11. Hints (spec 5)

A stop is reversible, so it is never `Terminal`. Spec 5 adopts `HintSubject::Stop { scope_ref }` with `HintKind::Changed`, meaning "re-read the stop status". It lands with spec 5 Part B.

- **Source.** The `watch` change notification on the shared `StopHeads` (S24) is the only source of Stop hints for sessions. It fires after each acknowledged transition and on host-latch changes. No hint source reads a per-kernel field.
- **Kernel sessions.** Each session in an affected scope receives it after the transition's `Committed` acknowledgement (spec 5 H2; stop transitions are restrictive commits, so they are anchored).
- **Processes.** There is no process `Stop` hint: spec 5 Part B limits the process projection to `Lifecycle` and `Budget`. Processes learn of a stop from `kernel_stopped` (with `observed_epoch`) on `invoke`; operators read the control socket's status.
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
    - `Stop`, `Restrict`, `Relax` and `Resume` commits run in a priority lane of spec 10's writer loop, exempt from `Overloaded`, `max_batch` and per-tenant caps (spec 10 X17, X20). Overload and full disks are incident conditions.
    - Under `SQLITE_FULL` or `IOERR` retry (spec 10 X21), the route waits at most `stop_commit_wait` (default 2 s). It then returns `stop_not_durable` with the intent latch in force, and keeps the write queued.
- **S37. Sharding** (only together with spec 10 section 10).
    - The kernel-scope chain originates in the pool shard.
    - Each tenant shard holds a verified replica: the same record bytes and digests, appended as a restrictive commit in the shard. That replica is what spec 10 X3 needs for a tier-2 check in the shard's own writer.
    - Shard readiness requires a replica epoch at or above the origin head epoch, read from the origin at boot. An unreachable origin means the shard is not ready.
    - New shards are seeded with the head before readiness.
    - The operator acknowledgement returns after the origin commit, with per-shard `enforced` status. It never blocks on a dead shard, so stopping stays easy. A shard that misses the fan-out cannot become ready until it catches up.

## 13a. Restore, upgrade and downgrade

- **S34. Restore and version rules.**
    - **Anchored transitions.** Stop and resume are restrictive commits, anchored before acknowledgement (spec 10 section 5). A database-only restore to before a stop does not extend the anchor, so `reconcile_startup` refuses (M: `rollback_anchor.rs:106-130`) and the host fails closed.
    - **Stop-intent latch.** It lives in the lock root beside the anchor (S25). A database-only restore therefore keeps the latch, and the boot honors it.
    - **Whole-volume restore.** A volume or VM snapshot that restores the database together with the anchor and the latch silently resurrects a running kernel. Later transitions then reuse epoch numbers, so two different signed artifacts can exist for the same `(authority_id, scope, epoch)`. This is a residual risk. Deployments may enable `stop_epoch_floor_check`: at boot, the head epoch per scope must be at or above the last epoch exported to SIEM or published to federation peers, read from a configured external witness. Otherwise the host is not ready.
    - **Schema version.** Phase 1 bumps the admission schema version from 34 (M: `admission_operation_store.rs:219`), so the open gate refuses older binaries (M: `schema.rs:63-72`). An older binary never runs against a store that has a stop table.
    - **Upgrade.** The migration that bumps the version creates the stop tables in the same transaction. "Absent before migration" is a normal upgrade. "Missing after migration" means not ready (S9).
- **S25. Stop-intent latch.**
    - Before the stop transaction begins, the stopping process writes and fsyncs a stop-intent record to a two-slot file, `stop-intent`, in the lock root, using the anchor's slot discipline.
    - The record holds `{ authority_id, scope, intended_epoch, transition: Stop | Restrict, allow_containment, credential_id_hash or principal }`.
    - At boot, an intent whose `intended_epoch` exceeds the durable head epoch for its scope makes that scope `Stopped` with `durability: latch_only`. The first write after verification appends the matching record.
    - The intent is superseded, and its slot rewritten, only after a durable head with epoch at or above `intended_epoch` is anchored.
    - A failed intent write leaves only the process latch (`process_only`). The route reports it.
    - This extends AC6's "publish first" rule from memory to durability.

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
| Chain at `bound - 1` | Resume refuses; a stop can still append (S6) |
| Chain at `bound` | Scope stays stopped until offline rollover (S6) |
| Delayed resume after a newer stop | Refused with `StopHeadMoved` (S31) |
| Host latch set | Every crossing refuses `Deny` and `Withhold` kinds; containment refused (S20, S23) |
| Shard misses the fan-out | That shard is not ready until its replica reaches the origin epoch (S37) |
| Database-only restore behind the stop | Anchor refuses; not ready (S34) |
| Whole-volume restore | Residual risk; optional external epoch floor (S34) |
| Older binary | Refused by the schema gate (S34) |

## 15. Protocol, schema, and wire impact

- **Schemas.** New `chio.stop-epoch.v1` and `chio.stop-control-quorum.v1` under `spec/schemas/`, with codegen and vectors. New store tables: `admission_operation_stop_epochs`, `admission_operation_stop_notes` and `admission_operation_stop_observations`. A schema version bump (S34). The lock-root `stop-intent` file format.
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
   - **Durable record.** The kernel-scope chain in the admission serving writer as a restrictive commit (S1, S2); the schema version bump (S34); resume headroom (S6); the stop-intent latch (S25).
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
    - no `Deny` or `Withhold` crossing commits with an index after a `Stopped` head commit in an applicable scope;
    - every `Settle` crossing after a stop references only subjects indexed before it;
    - every `AllowIfContainment` crossing during a stop has `allow_containment` and no host latch.
  - A shard offline during the fan-out, then restarted: it is not ready until caught up (S37).
- **Crash injection** (store test hooks).
  - Commit a stop, kill before the head swap, restart: the kernel comes up stopped.
  - Kill mid-resume before commit, restart: still stopped.
  - Kill after the resume commit: running.
  - Write the intent latch, kill before the stop commit, restart: `ready_stopped` with `latch_only`, then the record is appended (S25).
  - **S8-01:** stop with caller-executed, native and ordinary operations in `Finalizing`; kill; restart. The host serves `ready_stopped`, status answers, resume succeeds, and the outputs are released exactly once.
- **Failure injection.**
  - Stop under `Overloaded` and per-tenant caps: committed through the priority lane.
  - Stop under `SQLITE_FULL`: `stop_not_durable` with `latch_only`; a restart is stopped.
  - Stop with an unknown commit outcome: `stop_outcome_unknown`; a restart is stopped.
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
  - Resume headroom at `bound - 1` (S6).
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

## Appendix A. FTL reference

What FTL does (`/Users/connor/Medica/backbay/ftl`):

- **Boot ordering.** `boot` initializes memory, CPU state and drivers, and loads the first thread before the scheduler runs any user code (`kernel/src/boot.rs:39-45`). Nothing user-visible runs until boot completes. Section 6's "heads first, then the sweep" is the same ordering.
- **Destroyed flag.** A handle space's `destroyed` flag is checked under the space lock by every insert (`kernel/src/hspace.rs:46`, `:90`), and set under the same lock at close (`:169`). Tier 2 is that pattern: the stop is checked inside the same writer transaction as the state change it guards.

Where the analogy breaks:

- **Durability.** FTL has no persistent state, and a reboot always starts fresh. A Chio restart must come up stopped, so the flag must be durable and verified before the reconciliation sweep.
- **Reversibility.** FTL's `destroyed` flag is terminal. A Chio stop is reversible, so it needs epochs, a chain, and an authorization asymmetry between stop and resume.
- **Ordering writers.** FTL has one lock per object. Chio has several writers, and a crossing in a different writer than the stop gets only the early check (section 13).

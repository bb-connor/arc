# Design: confinement evidence for tool servers and workers (microkernel backend exploratory)

- Status: EXPLORATORY (revision 5, 2026-10-05, after the second independent review on PR #1174; revision 4 after Codex review; revision 3 re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P5 (W:)).
  - Sections 5, 6, and 7 are PROPOSED and can be reviewed for implementation.
  - Sections 8 and 9 (the microkernel backend and its spike) stay EXPLORATORY. No implementation is authorized there, and the spike is throwaway.
- Date: 2026-10-04
- Scope:
  - (a) truthful per-receipt disclosure of tool-server confinement on the shipped `native_launch` binding;
  - (b) a verifier-facing confinement record over cage, Firecracker, and process-container evidence;
  - (c) worker (caller) confinement: a qualified split-domain worker profile, the shipped P5 confined-reader profile, and caller-confinement attribution with an exporter for P5 evidence;
  - (d) confinement as checkable verifiable-work evidence through the existing `RuntimeAssuranceBacking` facet;
  - (e) qualification requirements and a bounded spike for an FTL-like microkernel backend.
- Owners:
  - `chio-kernel`: the delivery binding;
  - `chio-mcp-adapter`: the adapted-server binding;
  - `chio-process` and the `chio-cli` process runner: worker attribution and the container launch record;
  - `chio-control-plane` (`NativeConfinedRuntime`) and `chio-store-sqlite`: the confined-reader evidence exporter;
  - `chio-cage-plan`: the state vocabulary;
  - `chio-finding-worker`: the Firecracker projection;
  - `chio-finding` and `chio-finding-verifier`: facet evaluation;
  - `chio-core-types`: schemas.
- Related: `2026-07-09-enterprise-hardening-design.md` sections 9 and 11; `docs/adr/ADR-0011-boundary-taxonomy-product-wording.md`; `spec/SECURITY.md` section 2.3; `spec/PROTOCOL.md` sections 3 and 6; V: `2026-10-02-dynamic-delegation-design.md`; V: `2026-09-15-pre-settlement-execution-design.md`.
- Origin: lessons from the FTL (`nuta/ftl`) review, FTL v0.1.0 at commit `b73801a`.
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-closed-kernel-abi-design.md`, `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`

Citation convention:

| Prefix | Ref | Notes |
|---|---|---|
| `M:` | `origin/integration/process-security-m4` at `19df31ad9` | PR #1160 |
| `V:` | `origin/work/verifiable-work-session-20261003` at `14477aaac` | PR #1173 |
| `R:` | `origin/research/openappa-recovery-20261001` at `de84fc306` | PR #1172 |
| `P:` | `feat/process-command-experience-20260924` | |
| `W:` | uncommitted working tree of `arc-worktrees/recoverable-agent-runtime-20261002` (branch `feat/recoverable-agent-runtime-20261002`, committed HEAD `de84fc306`) | Recovery P0-P5, built on #1160 checkpoint `f25cd61f4`. Line refs reflect the working tree on 2026-10-04 and may drift |
| FTL | FTL checkout | |

All five count as shipped for this revision. W1-W4 and R: APIs whose code does not exist are labeled "assumed shipped (contract anchor)".

## Revision 5 changes

From the second independent review on PR #1174:
- **Launch qualification is not input trust (R-11-05, with spec 11).** Revision 4's `container` predicate treated a run plan that pins every input as grounds for a trusted start. Qualification now attests only the boundary, meaning the worker has no channel outside mediation. A context's initial input influence is spec 11's I7a: every bootstrap contribution is joined before readiness, and pinned contributions are `External` unless an operator-signed `BootstrapTrustAssertionV1` covers them (rule 6.3.5; S1-S5 note).
- **Required lanes come from the agreement and run plan (R-7-02).** Revision 4 derived the worker lane from a receipt carrying `worker_profile`, so a missing profile could remove the lane instead of failing it. Section 7 rule 3 now derives the required lanes and the expected worker identity from the agreement scope and run plan before reading any receipt evidence. A missing profile or reference on a required lane fails the facet.

## Revision 4 changes

- **The confinement attestation needs appraisal registration.** On the baseline, `derive_runtime_attestation_appraisal` accepts four schemas and returns `UnsupportedSchema` before local trust policy runs (`main`/V: `crates/economy/chio-appraisal/src/appraisal.rs:711-750`). A trust-policy rule alone could never accept confinement evidence. Section 7 rule 6 adds the verifier family, the inventory entries and an appraisal adapter that re-projects native records.
- **Every in-scope production receipt binds to exactly one record, whatever the backend.** Revision 3 checked record identity only for receipts carrying `native_launch` and accepted any other receipt under a permitted `tool_origin`. A host could then attest an unrelated Firecracker or container launch. A backend-neutral `confinement_launch` reference covers non-cage tool lanes (rule 5.1.6), and worker-lane receipts bind through `worker_profile.launch_ref`. Section 7 rule 3 now requires exactly one match for every receipt in scope.
- **The container launch record is signed only after the start succeeds.** A failed start yields a distinct signed `BootstrapFailed` record, and no worker call is admitted before the success record exists (section 5.3).
- **`worker_profile` is a verified fact, not unqualified evidence.** Integrity admission (spec 11 rule I7) derives a context's initial influence from it, so rule 6.3.5 now defines qualification, the single place it is checked, and fail-closed behavior: any failure starts the context at `unknown`.

## Revision 3 changes

- **The worker lane is already cage-confined in one profile.** Recovery P5 launches a "confined reader" child agent process under the cage, with measured `FullyEnforced` evidence retained and bound into an `IsolationBoundaryV1` (W:`crates/security/chio-security-types/src/confinement.rs:132-155`; W:`crates/platform/chio-store-sqlite/src/admission_operation_store/knowledge/confinement/launch.rs:98-133`). Revision 2 said the worker lane "is not reported". That is corrected in sections 1, 2, and 4.
- **Added a fourth worker profile, `confined_reader` (section 6.2).** Its execution domain holds no credential, socket, tool, or model access at all. P5 is the existing qualified instance of requirements S1-S3. `split_domain` stays the profile for agents that need tools.
- **Found an attribution gap on both sides (section 6.4).** P5 emits no `ChioReceipt` and no `native_launch`, and its full return evidence "stays in trusted review custody" (W:`docs/architecture/recoverable-agent-runtime/implementation/p5/OPERATIONS.md:44-46`). `worker_profile.launch_ref` for `confined_reader` points at the P5 launch digest and boundary `EvidenceRef` through a new exporter.
- **Added an output-channel dimension.** P5's closed `ConfinedChannelV1` (nine channels, all withheld except the bounded `Value` return) is the evidence model for "what can leave". `ConfinementSurfaces` gains `output_channels` (section 5.2).
- **Section 7** cites the P5 boundary plus its enforcement as a ready worker-lane `ConfinementRecord` source.
- **Merge note (section 14).** W: predates M:'s cage crate split. P5 edits `chio-cage` internals that M: moved, and adds cage APIs that must be ported.
- **FTL appendix.** P5 is the anti-`lx`: a zero-authority observer with a single framed channel in and out.

## Revision 2 changes

- **Re-baselined on M:.** The cage, its plan and init crates, and the broker are shipped. Native stdio launch is cage-only (M:`crates/protocol/chio-mcp-adapter/src/transport/stdio_parts/transport.inc:287`, `:517-522`).
- **Dropped the `confinement` key.** The shipped `native_launch` binding is reused, which leaves an absence-disclosure rule, the adapted-server gap, and the Firecracker projection.
- **Added content.**
  - The `ProcessContainer` backend, which cannot reach `FullyEnforced` until section 5.3 lands.
  - Worker confinement (section 6).
  - Verifiable-work evidence through `RuntimeAssuranceBacking` (section 7).
- **Settled questions.** The state enum stays in `chio-cage-plan`. Unconfined reasons align with `ToolOrigin`. FTL stays NO-GO.

## 1. Decision summary

The question this spec started from was whether an FTL-style microkernel plus library OS could isolate Chio tool servers. The answer stays no (section 8): FTL v0.1.0 fails the requirements that matter structurally. The review did surface three real, FTL-independent gaps in how Chio reports confinement:

1. **Tool-server confinement is referenced only on the broker path, and absence is not interpreted.** The kernel binds `native_launch` only when the connection supplies a prepared launch receipt. Only the broker's per-invocation connections do this. The long-lived `AdaptedMcpServer` is caged at spawn but supplies nothing. No rule says what a receipt without `native_launch` means.
2. **Worker confinement is reported nowhere a verifier can read, and ordinary workers share a domain with their credential.**
   - The ordinary worker credential sits in the same domain as workload code. This is the same flaw class as FTL's `lx`, which shares an address space and handle space with the application it serves (FTL `lx/src/thread.rs:58`, `lx/src/process.rs:81`). Any code that can read a Chio worker's bearer credential and reach its socket can issue every worker operation. The framework adapter's discipline is advisory against that code.
   - Recovery P5 already confines one worker-lane shape correctly: a confined reader child with zero authority. It retains measured cage evidence, but only in review custody, with no receipt and no attribution.
3. **Verifiable work treats confinement as an unverified host premise.** Neither execution evidence nor findings can require it, even though the `RuntimeAssuranceBacking` facet already exists for runtime assurance claims.

Decisions:

- Section 5 makes `native_launch` the only tool-confinement binding. It defines the disclosure for its absence, closes the adapted-server gap, and defines a verifier-side projection record over the cage, Firecracker, and process-container backends. It adds no receipt metadata key, no launch pipeline, and no best-effort state.
- Section 6 defines worker profiles (`direct`, `container`, `split_domain`, `confined_reader`) with qualification rules, a host-sourced `worker_profile` field inside the existing `chio_process` attribution, and an exporter that makes P5's retained evidence verifiable.
- Section 7 lets a finding or agreement require confinement through `RuntimeAssuranceBacking`. It wraps the projection record in the existing runtime-attestation envelope rather than adding a 14th facet.
- Sections 8 and 9 keep the microkernel bar and a three-day spike.

## 2. Verified current state

**Tool-server binding (shipped).**

| Fact | Evidence |
|---|---|
| The kernel binds `native_launch = {receipt_id, receipt_sha256}` from the connection's prepared launch receipt into delivery metadata, and denies when host attribution carries a different reference | M:`crates/kernel/chio-kernel/src/kernel/evaluation/delivery_preparation.rs:27-58` (mismatch at `:47-54`) |
| The trait default returns `None`. The doc says it is "trusted transport evidence, never caller-provided metadata" | M:`crates/kernel/chio-kernel/src/runtime/connection.rs:183-187` |
| Producers: only the broker's per-invocation `NativeBrokerMcpTool` and its `BrokerMcpConnection` wrapper. The broker refuses preparation without an enforcement receipt | M:`crates/security/chio-secret-broker/src/native_mcp.rs:226`, `:246-265`; M:`kernel_admission/capture/connection/mcp.rs:59-71` |
| `AdaptedMcpServer` implements `ToolServerConnection` without overriding `prepared_native_launch_receipt`, although the adapter retains the spawn-time `native_enforcement_receipt` | M:`crates/protocol/chio-mcp-adapter/src/server.rs:141`, `:168-235` |
| Process attribution carries `chio_process {runtime_id, process_id, operation_key, request_sha256, attempt}`, optional `recovery_policy` and `route`, and `native_launch` from host-configured launch receipts | M:`crates/kernel/chio-process/src/lib.rs:458-479` |
| `ProcessLaunchReceipt` "grants no authority. Offline verification must load the referenced envelope and verify its digest, signer and confinement claims" | M:`crates/kernel/chio-process/src/routes.rs:44-51` |
| Offline verification and export of native launch evidence exist in the CLI | M:`crates/products/chio-cli/src/cli/mcp/cage_policy/evidence.rs:204`, `:280`, `:305` |

**Cage vocabulary (shipped).**

| Fact | Evidence |
|---|---|
| `CageEnforcementState { Unsupported, Rejected, BootstrapFailed, FullyEnforced, Exited }` | M:`crates/security/chio-cage-plan/src/enforcement.rs:14-20` |
| `FullyEnforcedEvidence` | M:`enforcement.rs:182` |
| Pinned nono and seccompiler versions | M:`enforcement.rs:8-10` |
| `SandboxArchitecture::current()` accepts only x86_64 | M:`crates/security/chio-cage-plan/src/model.rs:122-137` |
| `NetworkMode` has only `Blocked` | M:`model.rs:153-154` |
| Brokered descriptors use `BrokerIpc` | M:`model.rs:170` |
| Cage receipts: `FullyEnforced` maps to `MediatedDecision`, `Prevent`, `Mediated`; failure states map to deny; `Exited` maps to `TraceObservation`, `DetectOnly`, `Verified` | M:`crates/security/chio-cage/src/receipt.rs:505-531` |

**Firecracker (shipped).**
- The jailer-only launch has a vsock channel, no guest NIC, and an in-guest cgroup (M:`crates/platform/chio-finding-worker/src/lib.rs:1-8`).
- `FindingWorkerGuestEnforcement` is "kernel-authored enforcement evidence from the trusted guest supervisor" (M:`src/protocol.rs:514-521`).
- A test asserts there is no `network-interfaces` entry (M:`src/executor.rs:1751`).

**Workers (shipped).**

| Fact | Evidence |
|---|---|
| The worker credential is a 256-bit bearer secret. "The host must isolate worker OS processes ... This service does not implement OS isolation" | M:`crates/kernel/chio-process/WORKER_PROTOCOL.md:16-28` |
| Every operation derives identity from authentication. There are no administrative operations | M:`WORKER_PROTOCOL.md:59-61` |
| Container profile: only the worker socket inode is mounted; all capabilities dropped; `no-new-privileges`; default seccomp; no external network; read-only root; fixed limits | M:`crates/products/chio-cli/PROCESS_CONTAINERS.md:44-57` |
| Docker and the shared kernel are trusted | M:`PROCESS_CONTAINERS.md:8` |
| Cgroup usage is reported as `unavailable_container_cgroup` | M:`PROCESS_CONTAINERS.md:68-72` |
| The runner commits container intent and ID before start | M:`PROCESS_CONTAINERS.md:76-80` |
| mini-SWE routes model commands "through a host-selected Chio tool" | M:`sdks/python/chio-mini-swe/README.md:3-6` |
| "The Python adapter itself does not sandbox agent code. A worker must not also receive a local shell callback, sandbox administration credentials or Docker socket access" | M:`sdks/python/chio-mini-swe/README.md:55-59` |
| `ProcessSecurityProfile { tenant_id, isolation_epoch_id, generation }` | M:`crates/kernel/chio-process/src/security.rs:4-7` |

**Confined readers (W:, recovery P5, Linux x86_64 profile, `phase_accomplished: true`).**

| Fact | Evidence |
|---|---|
| Only a root process may attach a confined child. The child gets a CA-signed capability with no tool, resource, or prompt grants and a fixed 625 bps parent share. Callers cannot choose child ids, lineage, or epoch | W:`crates/platform/chio-control-plane/src/confinement.rs:121`; W:`.../implementation/p5/OPERATIONS.md:19-24` |
| `IsolationBoundaryV1` binds the parent and child capability digests, ancestry (at most 8), a host-allocated lineage and epoch, seed and observation artifacts, `ConfinedExecutionProfileV1`, the return contract, limits, and the deadline | W:`crates/security/chio-security-types/src/confinement.rs:132-155` |
| Lifecycle: `Reserved`, `LaunchPrepared`, `EnforcedRunning`, `ReturnStaged`, `ReturnAdmitted`, `Closed`, `Failed`, `Cancelled`, `Quarantined` | W:`chio-security-types/src/confinement.rs:35-45` |
| The pinned cage plan requires network `Blocked`, `NativeMinimalV1`, default filesystem deny, exactly `LANG=C LC_ALL=C TZ=UTC`, no broker IPC, no read or write grants, and one argument. `ConfinedProviderV1::Disabled` | W:`crates/platform/chio-control-plane/src/confinement/execution.rs:46-77` |
| Limits: one launch, zero tool calls, zero model calls | W:`chio-security-types/src/confinement.rs:85-115` |
| The store retains the cage `FullyEnforcedEvidence` after checking plan, profile, image, and helper digests, and records `launch = H("chio.confined.launch.v1" \|\| evidence)` | W:`chio-store-sqlite/src/admission_operation_store/knowledge/confinement/launch.rs:98-133` |
| Input is one framed `CHIOCF1` packet (observation plus up to 8 seeds, at most 64 KiB). Output is an 8-byte candidate whose canonical boolean projection the host recomputes | W:`crates/core/chio-core-types/src/recovery/confinement.rs:59-106` |
| `ConfinedChannelV1 { Value, Error, Stdout, Stderr, Log, Progress, File, Callback, Stream }`. Every channel except the bounded `Value` return is withheld | W:`chio-security-types/src/confinement.rs:14-25`; W:`.../p5/OPERATIONS.md:40-46` |
| No `ChioReceipt` or `native_launch` is produced on the confined path. "Full return evidence stays in trusted review custody" | W:`.../p5/OPERATIONS.md:44-46`; no `native_launch` or `ChioReceipt` reference in W:`chio-control-plane/src/confinement*` |
| `NativeConfinedRuntime::cancel` commits the native disposition, then cancels the process journal child | W:`chio-control-plane/src/confinement.rs:258-274` |

**Verifiable work (shipped).**

| Fact | Evidence |
|---|---|
| "Qualified tool confinement and complete observer declarations remain host assumptions" | V:`crates/kernel/chio-kernel/src/delegated_work.rs:4-5` |
| The closed 13-facet vocabulary includes `RuntimeAssuranceBacking` | V:`crates/economy/chio-finding/src/report.rs:38-55` |
| `RuntimeAssuranceBacking` is required whenever `finding.runtime_assurance_tier` is set | V:`report.rs:101-103` |
| The verifier requires a signed runtime-attestation envelope, a signed appraisal, pinned attestation and appraisal authorities, and a non-empty local trust policy. It receives the production receipts | V:`crates/trust/chio-finding-verifier/src/verify.rs:1467-1520` |
| `RuntimeAttestationEvidence { schema, verifier, tier, issued_at, expires_at, evidence_sha256, runtime_identity, workload_identity, claims }` | V:`crates/core/chio-core-types/src/capability/runtime_attestation.rs:25-47` |
| `RuntimeAssuranceTier { None, Basic, Attested, Verified }` | V:`runtime_attestation.rs:17-23` |

**Receipt vocabulary.**
- `ToolOrigin { CallerExecuted, ChioInternal, HostExecutedProviderReported, HostExecutedUnmediated }` (M:`crates/core/chio-core-types/src/receipt/kinds.rs:107`).
- `TrustLevel` (M:`kinds.rs:11`) and `BoundaryClass` (M:`kinds.rs:64`).
- `spec/SECURITY.md` still records host sandboxing as residual (M:`spec/SECURITY.md:162`, `:732`). `native_launch` is not documented in `spec/PROTOCOL.md`.

## 3. Goals and non-goals

### Goals

- Every mediated tool-call receipt is interpretable for tool confinement. Either it references a cage enforcement receipt through `native_launch`, or it renders as "not confined by Chio" with a reason derived from `tool_origin`.
- Long-lived caged adapted servers bind the same reference as the broker path.
- One verifier-facing projection over the cage, Firecracker, and process-container backends, with no change to their native schemas.
- Worker confinement becomes a reported, qualifiable dimension. The split-domain profile removes the credential from the domain where model-generated code runs.
- A finding or agreement can require confinement evidence, and the verifier denies it when the evidence is absent.
- A written bar for any microkernel backend, plus a three-day spike.

### Non-goals

- A new receipt metadata key for tool confinement, a generic launch trait, a third native launch mode, or any `BestEffort`/`Partial`/`Advisory` success state (hardening design 9.4).
- A 14th finding facet. The closed vocabulary stays closed.
- Hostname egress control inside any sandbox. That stays with the broker and egress proxy.
- Defending against model steering. Split-domain confinement bounds code execution, not what an authorized controller chooses to call.
- A production microkernel backend.

## 4. Two lanes

```text
 agent workload (LLM-driven code)
        |
 worker lane:  [ worker process or container ] --chio.process.v1 (bearer credential)--> process host + kernel (TCB)
               [ confined reader child (P5)  ] <--CHIOCF1 frame in / 8-byte value out--  host (no credential)
                                                                                            |
 tool lane:                                                    broker or adapter --> [ caged tool server ]
                                                                                       (cage receipt, native_launch)
```

Chio confines the tool lane with the cage and Firecracker and reports it through `native_launch`.

The worker lane splits two ways:
- Ordinary workers are confined by the host (container profile or nothing) and reported nowhere.
- P5 confined readers are cage-confined with retained `FullyEnforced` evidence, but that evidence stays in review custody.

FTL's single container mixes both lanes in one domain. Its kernel accepts privileged calls from any instruction address (FTL `kernel/src/arch/x64/syscall.rs:65`), which is why the worker lane needs its own rules (section 6).

## 5. Tool-server confinement (PROPOSED)

### 5.1 `native_launch` is the binding

1. A mediated tool-call receipt claims tool-server confinement only through a kernel-bound launch reference: `native_launch` for the Linux cage, or `confinement_launch` for any other backend (rule 6). The kernel binds either one from the connection's prepared receipt (M:`delivery_preparation.rs:27-58`). No other metadata field may claim it. Host attribution may repeat it, and any difference denies (existing behavior, extended to `confinement_launch`).
2. **Absence disclosure.** A receipt with neither `native_launch` nor a verified `confinement_launch` renders as "not confined by Chio" (ADR-0011 wording), never as unknown-but-safe. A receipt carrying a verified `confinement_launch` is confined under rule 6. The reason comes from the receipt's existing `tool_origin`, so no new field is needed:

| `native_launch` | `tool_origin` | Rendered disclosure |
|---|---|---|
| present, referenced cage receipt `FullyEnforced` | any | confined by Chio (Linux cage) |
| absent, `confinement_launch` present and its record `FullyEnforced` | any | confined by Chio (named backend) |
| absent | `ChioInternal` | in-process tool; not sandboxed by Chio |
| absent | `CallerExecuted` | caller-executed; not sandboxed by Chio |
| absent | `HostExecutedProviderReported`, `HostExecutedUnmediated` | host-executed; not sandboxed by Chio |

3. **Liveness at dispatch.** `native_launch` may be bound only when the referenced cage receipt is `FullyEnforced`, and the transport has not observed `Exited` at dispatch readiness. Otherwise dispatch fails closed. The broker path already refuses without a receipt (M:`native_mcp.rs:226`). The adapted path follows rule 4.
4. **Adapted servers.** `AdaptedMcpServer` overrides `prepared_native_launch_receipt` to return its retained spawn-time enforcement receipt (M:`server.rs:141`) while its child is alive. Once the transport records the cage `Exited` receipt, `prepare_delivery` returns an error, so dispatch denies rather than proceeding unreferenced. Every receipt for a long-lived server references the same spawn receipt, which is correct, because the confinement was established once.
5. **Offline verification.** A verifier loads the referenced envelope, recomputes its canonical digest, verifies its signer against its own pinned kernel keys, and requires `FullyEnforced`. This is the existing CLI path (M:`cage_policy/evidence.rs:204`). `spec/PROTOCOL.md` section 6 documents the key and this procedure.

```text
receipt.native_launch = ref ->
  sha256(canonical(envelope(ref.receipt_id))) = ref.receipt_sha256
  and signer(envelope) in verifier_pinned_kernel_keys
  and envelope.enforcement_record.state = FullyEnforced
  and not exited_before(dispatch_committed(operation_id))

receipt.confinement_launch = ref ->
  sha256(canonical(record(ref))) = ref.record_sha256
  and record(ref).schema = ref.record_schema
  and signer(record) in verifier_pinned_kernel_keys
  and record(ref).enforcement = FullyEnforced
  and record(ref).attempt_id = ref.attempt_id
  and not exited_before(dispatch_committed(operation_id))

absent(receipt.native_launch) and absent(receipt.confinement_launch)
  -> disclosure(receipt) = not_confined(tool_origin)
```

6. **Backend-neutral reference.** A tool-lane backend other than the Linux cage (`FirecrackerGuest` today) claims confinement only through `confinement_launch { record_schema, record_sha256, attempt_id }`. The kernel binds it from the connection's prepared delivery under rules 1, 3 and 5, exactly as it binds `native_launch`: only when the referenced record verifies, is `FullyEnforced`, and has not exited at dispatch readiness. Until a backend's dispatch path binds this reference, its records cannot cover production receipts (section 7 rule 3).

### 5.2 Confinement record (verifier-side projection)

The projection is computed by exporters and verifiers from native records. It is never stored in tool-call receipts.

```rust
pub const CONFINEMENT_RECORD_SCHEMA: &str = "chio.confinement.record.v1";

#[serde(rename_all = "snake_case")]
pub enum ConfinementBackendKind { LinuxCage, FirecrackerGuest, ProcessContainer } // closed

#[serde(rename_all = "snake_case")]
pub enum EvidenceObserver { HostParent, HostVmm, GuestSupervisor, SameDomain }

#[serde(rename_all = "snake_case")]
pub enum SurfaceStatus { Enforced, Absent, NotEnforced }

#[serde(deny_unknown_fields)]
pub struct ConfinementRecord {
    pub schema: String,
    pub attempt_id: String,
    pub backend: ConfinementBackendKind,
    pub lane: ConfinementLane,                // Tool | Worker
    pub state: chio_cage_plan::CageEnforcementState,
    pub admission_digest: String,
    pub profile_digest: String,
    pub authority_inventory_digest: String,   // fd table | device set | mounts plus socket inode
    pub surfaces: ConfinementSurfaces,        // filesystem, network, host_interface,
                                              // inherited_authority, environment, resources,
                                              // output_channels
    pub native_record_schema: String,
    pub native_record_digest: String,
    pub recorded_at_unix_ms: u64,
}
```

Rules, carried from revision 1:

1. The projection is deterministic. A verifier re-projects from the native record and requires canonical byte equality.
2. `FullyEnforced` requires every isolation surface (all except `output_channels`) to be `Enforced` or `Absent`, and no surface may have a `SameDomain` observer. `output_channels` is reported, not gating, unless a return contract claims it (rule 7).
3. `SameDomain` is any observer the confined code can write to.
4. A `GuestSupervisor` fact counts only alongside a `HostVmm` fact for the same attempt.
5. The enums are closed, with `deny_unknown_fields`.
6. Projection never upgrades a native state.
7. `output_channels` records which result channels can leave the confined domain. When a return contract claims channel discipline (P5's `ReturnContractV1`), every channel the contract does not enable must be `Enforced`, or the record cannot be `FullyEnforced`. It uses P5's closed `ConfinedChannelV1` vocabulary (W:`chio-security-types/src/confinement.rs:14-25`), each channel `Enforced` (withheld or bounded by a contract) or `NotEnforced` (raw). A tool-lane cage leaves its result channels to the kernel's ordinary output guards. Its projection records them as `NotEnforced` with observer `HostParent`, because the cage itself does not withhold them. This is honest, and it is the axis on which a confined reader differs from a caged tool.

8. **`attempt_id` is the lane's launch identity** (section 7 rule 3). For a `LinuxCage` tool-lane record it is the id of the cage enforcement receipt, which names one spawn. For any other tool-lane backend it is the `attempt_id` carried by `confinement_launch` (rule 5.1.6). For a worker-lane record it is the runner's launch attempt, `worker_profile.launch_attempt` (6.3). It is never `chio_process.attempt`, which numbers retries of one operation (M:`chio-process/src/lib.rs:455-461`), not launches.

Mapping per backend:

| Field | `LinuxCage` (tool lane) | `LinuxCage` (worker lane, `confined_reader`) | `FirecrackerGuest` | `ProcessContainer` |
|---|---|---|---|---|
| native record | cage enforcement receipt | retained `FullyEnforcedEvidence` plus `IsolationBoundaryV1` digest and `launch` digest (W:`.../knowledge/confinement/launch.rs:125-128`) | jailer config, `FirecrackerIdentity`, `FindingWorkerGuestEnforcement` | signed container launch record (5.3) |
| network | Landlock net plus seccomp socket denial, `HostParent` | `Blocked` plan (W:`confinement/execution.rs:50`), `HostParent` | `Absent` (no NIC), `HostVmm` | no external network, `HostParent` |
| host_interface | seccomp allowlist, `HostParent` | `NativeMinimalV1`, `HostParent` | jailer seccomp plus device set, `HostVmm` | engine default seccomp, capabilities dropped, `no-new-privileges`, `HostParent` |
| inherited_authority | fd table | `Absent`: no broker IPC, no read or write grants, no credential | device set | mounts plus socket inode |
| resources | plan rlimits, `HostParent` | limits plus pidfd deadline (W:`confinement/execution.rs:121-132`), `HostParent` | in-guest cgroup, `GuestSupervisor` (with `HostVmm`) | fixed container limits, `HostParent` |
| output_channels | `NotEnforced` (kernel output guards apply) | `Value` bounded by `ReturnContractV1`; all other channels withheld, `HostParent` | `NotEnforced` | `NotEnforced` |

### 5.3 Process container launch record

The process-container profile (M:`PROCESS_CONTAINERS.md:44-57`) is enforced by Docker under a trusted engine and kernel, but nothing signed attests it. Its evidence lives in the private `runner.db`. So it cannot reach `FullyEnforced` today. Proposal:

1. **Inspect before start.** After the container is created and before the start request, the runner inspects the exact owned container ID it already commits (M:`PROCESS_CONTAINERS.md:76-80`). It compares the effective host configuration against the fixed profile:
   - capabilities dropped and `no-new-privileges`;
   - seccomp profile and network mode;
   - read-only root and the mount set (exactly the socket inode plus the tmpfs mounts);
   - limits, user, and the rejected image volumes.

   Any mismatch signs a `Rejected` record (step 4), removes the container, and never issues the start.
2. **Start, then confirm.** The runner issues the start for that exact container ID. It then inspects again and requires the same container ID, `State.Running`, an engine-reported `StartedAt`, and an `inspected_config_digest` equal to the pre-start one.
3. **Sign success only after the start.** Only after step 2 confirms does the runner sign `chio.process.container-launch.v1 { process_id, attempt, image_id, container_id, engine_identity, profile_digest, inspected_config_digest, state: FullyEnforced, started_at }`. Here `started_at` is the engine-reported start time.
4. **Distinct failure records.** A failed inspection, a failed start request, or a post-start inspection that does not confirm signs `chio.process.container-launch.v1 { process_id, attempt, image_id, container_id, engine_identity, profile_digest, state, failed_at, failure_class }` with no `started_at`. The state is `Rejected` for a pre-start mismatch and `BootstrapFailed` otherwise, using `CageEnforcementState`. The runner stops and removes a container that started but did not confirm. At most one signed record exists per `(process_id, attempt)`.
5. **No admission before evidence.** The runner does not mark the attempt ready, and the process host refuses worker-protocol calls on the attempt's credential, until the success record is committed. If signing fails after the start, the container is stopped and the attempt is recorded `BootstrapFailed`. There is no unsigned fallback.

The signer is open decision 2.

## 6. Worker (caller) confinement (PROPOSED)

### 6.1 The FTL lesson applied to Chio workers

In FTL, the Linux personality library and the application share one address space and one handle space. Application threads run in the container's handle space (FTL `lx/src/thread.rs:58`). Process address spaces clone the root space, so `lx` memory is writable from the application (FTL `lx/src/process.rs:81`, `kernel/src/vmspace.rs:104`). Policy that `lx` enforces is therefore advisory against the application.

A Chio worker has the same shape:
- The bearer credential and socket are delivered into the worker's domain (M:`WORKER_PROTOCOL.md:13-14`, `PROCESS_CONTAINERS.md:38-40`).
- The worker application is the agent workload, often including model-generated code.
- Any code in that domain can read the credential and invoke any in-scope tool, write checkpoints, put blobs, or cancel the subtree.

The kernel still bounds every call to the process capability, so this is not authority escalation. What the workload can defeat is the personality's discipline (stable operation keys, checkpoint-before-release, `known_outcome_only`) and the separation between deciding and executing.

### 6.2 Worker profiles

| Profile | Meaning | Claim |
|---|---|---|
| `direct` | ordinary OS process with rlimits | none; resource limits only |
| `container` | the shipped container profile (5.3) | the worker is confined from the host; workload and credential share a domain |
| `split_domain` | S1-S5 below | model-generated code runs outside the credential's domain |
| `confined_reader` | shipped recovery P5 confined child (section 2) | a child agent process observes sensitive data under the cage with zero authority, and only a bounded, contract-checked value leaves |

A `confined_reader` qualifies only when its native record holds:
- `IsolationBoundaryV1` is in state `EnforcedRunning` or later;
- the retained `FullyEnforcedEvidence` matches the boundary's pinned plan, profile, image, and helper digests;
- the limits are one launch, zero tool calls, and zero model calls.

It is the strongest worker-lane profile in one respect: the execution domain holds no credential, socket, tool, or model access at all. It is also the narrowest. It cannot invoke tools, so it does not replace `split_domain` for agents that act.

A `split_domain` profile qualifies only when every requirement holds:

- **S1.** The credential and socket exist only in the controller domain. The execution domain receives no socket mount, no credential, no shell or callback channel to the controller, no sandbox administration credentials, and no Docker socket. This generalizes M:`chio-mini-swe/README.md:55-59`.
- **S2.** Model-generated commands and code execute only through mediated tool calls. Those tool servers must carry `native_launch` (5.1) or run as a Firecracker guest, and each execution has a receipt.
- **S3.** The controller runs only operator-pinned code: an image digest or executable digest in the run plan. It never evaluates model output as code.
- **S4.** The controller itself runs under the `container` profile or stronger, with its own launch record (5.3).
- **S5.** The run plan binds the controller digest and the execution tool server IDs. The runner records the profile per attempt.

S1-S5 qualify the controller's boundary. They say nothing about the controller's inputs. Pinning the controller code (S3) and binding the servers (S5) make a run reproducible, but they do not assert that the task, seeds or other bootstrap input are free of external influence. Those inputs are joined under spec 11 rule I7a.

P5 is the existing qualified reference for S1-S3, in a narrower shape:
- **S1.** The pinned plan has no broker IPC fd and no read or write grants, and the child holds no worker credential (W:`confinement/execution.rs:46-77`).
- **S2.** P5 mediates through a host-framed `CHIOCF1` stdin packet and a host-recomputed return, rather than through tool calls.
- **S3.** The image and helper digests are pinned in `ConfinedExecutionProfileV1` (W:`chio-security-types/src/confinement.rs:119-126`).

A `split_domain` implementation should reuse P5's launch custody and enforcement-record path for its execution domain where it can.

### 6.3 Caller-confinement attribution

The existing `chio_process` attribution object (M:`lib.rs:458-479`) gains one host-sourced field:

```json
"worker_profile": { "kind": "direct | container | split_domain | confined_reader",
                    "launch_ref": { "record_id": "...", "record_sha256": "..." },
                    "launch_attempt": "..." }
```

Rules:

1. The value comes from host configuration bound to the attempt, the way `native_launch` comes from host launch receipts. The worker cannot supply or change it.
2. `launch_ref` and `launch_attempt` are required for `container`, `split_domain`, and `confined_reader`. `launch_attempt` is the runner's launch attempt for the worker, the `attempt` of the container launch record (5.3) or the boundary's launch for `confined_reader`. It is distinct from `chio_process.attempt`, which numbers retries of one operation. A host attribution that differs from the runner's per-attempt record denies, mirroring the `native_launch` mismatch rule.
   - For `confined_reader`, `record_id` is the boundary's `EvidenceRef`, and `record_sha256` is the retained `launch` digest (W:`.../knowledge/confinement/launch.rs:125-127`).
   - It is attached to receipts the parent produces after the return is admitted, and to the exported evidence of section 6.4.
3. An absent `worker_profile` renders as `direct` (no claim). That rendering is only for display and influence; it never satisfies a confinement requirement. Where an agreement's run plan requires the worker lane, an absent profile fails the facet (section 7 rule 3).
4. `split_domain` may be recorded only when S5's plan binding exists and every execution tool server ID in the plan is served with a verified backend-appropriate launch reference: rule 5.1.3 (`native_launch`) for the Linux cage, or rule 5.1.6 (`confinement_launch`) for another tool-lane backend such as a Firecracker guest.
5. **A verified fact, never a grant.** `worker_profile` grants no authority, and no guard or policy branches on it, with one consumer: integrity admission (`2026-10-04-integrity-gated-admission-design.md` rule I7) uses it to choose a context's initial influence. That makes it an allow-affecting fact for that one purpose, so integrity admission consumes it only in verified form:
   - **Qualification.** The fact is `Verified(kind)` only when every condition holds:
     - the host attribution equals the runner's per-attempt record (rule 2);
     - the referenced launch record verifies: pinned signer, canonical digest equal to `launch_ref.record_sha256`, and state `FullyEnforced` (for `confined_reader`, `EnforcedRunning` or later);
     - the record's attempt equals `launch_attempt` (rule 2), which the runner binds per launch;
     - the kind's own boundary predicate holds: for `container`, the launch record's image digest equals the run plan's; for `split_domain`, S1-S5.
   - **What qualification means.** A `Verified` profile attests only that the worker has no channel outside mediation. It never makes the worker's inputs trusted. The context's initial input influence is spec 11 rule I7a: every bootstrap contribution is joined before readiness, and a pinned contribution is `External` unless an operator-signed `BootstrapTrustAssertionV1` covers it. A content digest proves which bytes were supplied, not their provenance.
   - **Where it is checked.** The host verifies the fact once, when the process's knowledge scope is created. It commits the resulting initial influence in the serving writer in the same transaction (spec 11 rule I7). Crossings read the committed state and never re-derive it from attribution.
   - **Failure behavior.** Any of these yields `Unverified`, which is treated exactly as `direct`: an absent field, an unverifiable or mismatched record, a record lookup that fails, or a kind predicate that does not hold. The context then starts at `unknown = true`, which no integrity requirement satisfies. A failure can only make the starting state less trusted, never more.
   - **Never upgraded later.** A later attribution can only add influence (spec 11 rule I2).

```text
attribution.worker_profile.kind in {container, split_domain} ->
  verified(launch_record(launch_ref))
  and launch_record.attempt = attribution.worker_profile.launch_attempt

attribution.worker_profile.kind = split_domain ->
  plan_binds(controller_digest, execution_server_ids)
  and forall call c by execution_server_ids: launch_ref(c) verified
      -- launch_ref is native_launch for the Linux cage, or confinement_launch for
      -- another tool-lane backend (rule 5.1.6), each checked by its 5.1 predicate

attribution.worker_profile.kind = confined_reader ->
  exported(boundary(launch_ref.record_id)).state >= EnforcedRunning
  and launch_digest(retained_evidence) = launch_ref.record_sha256
  and boundary.limits = { launches: 1, tool_calls: 0, model_calls: 0 }

initial_influence(ctx) is trusted ->
  worker_profile_fact(ctx) = Verified(k) and k in {container, split_domain}
  and forall b in bootstrap(ctx): inherited_trusted(b) or asserted_trusted(b)     (spec 11 I7a)
worker_profile_fact(ctx) = Unverified -> initial_influence(ctx).unknown
```

### 6.4 Confined-reader evidence exporter (new requirement)

P5's evidence is complete, but it is review-custody only. The selected sink receives "the admitted intent and exact boolean" (W:`.../p5/OPERATIONS.md:44-46`), and the confined path emits no `ChioReceipt` or `native_launch`. A verifier therefore cannot check a `confined_reader` claim today. Proposal:

1. **The export.** An authorized operator export, using a new `RecoveryPermission`-gated read or an existing review read (open decision 6), emits `chio.confined-reader.evidence.v1`. Its fields are:
   - `boundary`: the canonical `IsolationBoundaryV1`;
   - `enforcement`: the retained cage `FullyEnforcedEvidence`;
   - `launch`: the digest;
   - `state`: the terminal `IsolationStateV1`;
   - for an admitted return, the `ConfinedReturnEvidenceV1` disclosure and endorsement signatures (W:`chio-security-types/src/confinement.rs:184`).
2. **Withheld channels.** The export never contains withheld channel bytes (`Stdout` beyond the 8-byte candidate, `Stderr`, `Log`, `Progress`, `File`, `Callback`, `Stream`). It carries only the evidence P5 already retains.
3. **Signer.** The export is signed by the same serving authority that retained the record. Verifiers check the cage evidence against their own pinned kernel keys, exactly as for `native_launch` (rule 5.1.5).
4. **Projection.** The export projects deterministically into a worker-lane `ConfinementRecord` (section 5.2), so section 7 can attest it.
5. **No authority.** The export grants nothing and changes no P5 state. A missing or failed export leaves the claim unverifiable, which renders as `direct` (rule 6.3.3).

## 7. Confinement in verifiable-work evidence (PROPOSED)

Verifiable work names confinement as a host assumption (V:`delegated_work.rs:4-5`). The finding verifier already has the right shape for a checkable claim: `RuntimeAssuranceBacking` is required whenever `runtime_assurance_tier` is set, and it demands a signed attestation, a signed appraisal, pinned authorities, and a local trust policy (V:`report.rs:101-103`, `verify.rs:1467-1520`).

1. **Confinement attestation profile.**
   - An exporter emits a `RuntimeAttestationEvidence` (V:`runtime_attestation.rs:25-47`) with `schema = "chio.runtime-attestation.chio-confinement.json.v1"`, registered by rule 6. The records inside its claims keep their own schema, `chio.confinement.record.v1`.
   - `evidence_sha256` covers the canonical `ConfinementRecord` set for the work: tool-lane records for every execution tool server, plus the worker-lane record. For a `confined_reader`, the worker-lane record is the projection of the P5 export (section 6.4), which is the one worker-lane source shipped with measured cage evidence today.
   - `claims` carries those records and their native-record digests.
   - The envelope is signed by the operator's runtime-attestation authority and appraised by the appraisal authority the verifier pins.
2. **Tier ceiling.** Confinement-only evidence resolves to at most `RuntimeAssuranceTier::Basic`. `Attested` and `Verified` stay reserved for hardware-rooted attestation, which local trust policy decides. See open decision 1.
3. **Binding to the work (backend-neutral, per lane).** Inside `RuntimeAssuranceBacking`, every production receipt in the agreement's confinement scope must map to exactly one attested record **for each lane that applies to it**. The evaluator already receives the production receipts (V:`verify.rs:1467-1473`).
   - **Required lanes come first, from the agreement and run plan.** Before reading any receipt evidence, the verifier derives from the agreement's confinement scope and the signed run plan:
     - which lanes are required;
     - the execution tool server ids, for the tool lane;
     - the expected worker identity, for the worker lane: the worker attempt, the profile kind and the launch reference the runner bound to it.

     Optional receipt fields never decide whether a lane applies.
     - The **tool lane** is required for every in-scope receipt whose tool server is an execution tool server named in the run plan.
     - The **worker lane** is required for every in-scope receipt produced under the run plan's worker attempt, identified by the agreement's process or request scope, whenever the agreement requires worker confinement. It is required whether or not the receipt carries `worker_profile`.
     - Both can apply to one receipt. A `container` worker that invokes a caged execution tool produces a receipt naming two distinct launches, and both must verify. Choosing either one alone would let an agreement that requires both boundaries pass with one.
   - **A missing reference fails a required lane.** A required lane with no reference fails the facet. That includes a receipt with no `worker_profile` at all, a profile with no `launch_ref` or `launch_attempt`, and a profile whose kind or launch reference differs from the run plan's expected worker identity.
   - **References and attempt binding, per lane.** The map uses only kernel-bound or runner-bound references in the signed receipt, whatever the backend. Each reference has its own attempt binding (rule 5.2.8):
     - tool lane, `LinuxCage`: `native_launch { receipt_id, receipt_sha256 }` (5.1). It carries no separate attempt field. Its attempt identity is `receipt_id`, the cage enforcement receipt that names one spawn, so the matched record has `native_record_digest = receipt_sha256` and `attempt_id = receipt_id`. A long-lived adapted server references one spawn from many receipts, which all map to that one record;
     - tool lane, any other backend: `confinement_launch { record_schema, record_sha256, attempt_id }` (rule 5.1.6), matched on `record_sha256` and its own `attempt_id`;
     - worker lane (`ProcessContainer`, `confined_reader`, or a `split_domain` controller): `chio_process.worker_profile.launch_ref.record_sha256` and `worker_profile.launch_attempt` (6.3), never `chio_process.attempt`.
   - **Match, keyed by (receipt, lane).** For each applicable lane, exactly one attested record must have `lane` equal to that lane, `native_record_digest` equal to that lane's reference digest, and `attempt_id` equal to that lane's attempt binding. The facet fails when an applicable lane has no reference, zero matching records, or more than one matching record in that lane, or when a reference matches only a record of the other lane.
   - **No substitution.** A disclosed `tool_origin` never substitutes for a reference in scope. Only receipts outside the scope, such as in-process `ChioInternal` tools the agreement permits, fall back to the disclosure table. A record attested for an attempt that no in-scope receipt references vouches for nothing, and it never satisfies a required lane on its own.
4. **Requiring it.** An agreement or finding requires confinement by setting `runtime_assurance_tier = Basic` and adding a trust-policy rule that accepts the schema. Verifiers deny unless the evidence is present (`Unavailable` and `Asserted` never pass a required facet; V:`report.rs:107-110`). The paper's host premise becomes a negotiated, checkable term. No facet is added.
5. **Scope.** Execution evidence attests local execution only (V:`execution_evidence.rs:1`). A confinement record attests the exporter's own launches, never a remote owner's.
6. **Appraisal registration (required before rule 4 can pass).** On the baseline, `derive_runtime_attestation_appraisal` accepts four schemas and returns `UnsupportedSchema` for any other before local trust policy runs (`main`/V: `crates/economy/chio-appraisal/src/appraisal.rs:711-750`). The shared trust boundary repeats the closed list (V: `crates/core/chio-core-types/src/runtime_attestation.rs:65-110`), and so does the signed-artifact schema table (V: `signed_artifact.rs:1247-1250`). A trust-policy rule alone therefore cannot accept confinement evidence. One change adds:
   - the schema constant `chio.runtime-attestation.chio-confinement.json.v1`, `AttestationVerifierFamily::ChioConfinement`, and the adapter id `chio_confinement` (`runtime_attestation.rs`);
   - arms for them in `verifier_family_for_attestation_schema` and `derive_runtime_attestation_trust_material`;
   - an arm in `derive_runtime_attestation_appraisal`. Its adapter re-projects every claimed `ConfinementRecord` from its native record (rule 5.2.1), verifies native-record signers against pinned kernel keys, and rejects on any mismatch. Its normalized assertions carry the record digests and cap the effective tier at `Basic` (rule 2) before local policy runs;
   - the signed-artifact schema table entry, and the entry in the appraisal artifact inventory (`chio-appraisal/src/artifact_inventory.rs:7`).

   The family enum stays closed, and the change is additive. An older verifier returns `UnsupportedSchema`, which fails the facet (fail closed). Carrying the claims under the existing `enterprise_verifier` schema was rejected, because that adapter does not re-project native records and so cannot enforce rule 5.2.1.

## 8. Microkernel or library-OS backend qualification (EXPLORATORY)

Before a microkernel backend may emit a `FullyEnforced` record, it must meet all of the following.

| # | Requirement | FTL v0.1.0 |
|---|---|---|
| Q1 | No ambient creation of external-effect or unbounded objects | Fails: `NetCreate` and `ConsoleOpen` take no handle (FTL `kernel/src/net.rs:68`, `kernel/src/console.rs:110`). `VmoCreate` has no quota (`kernel/src/vmobject.rs:241`) |
| Q2 | The enforcement point is outside the workload's write reach (separate address space for the library OS, or kernel-only policy) | Fails: shared handle space and address space (FTL `lx/src/thread.rs:58`, `lx/src/process.rs:81`). FTL calls are accepted from any instruction address (`kernel/src/arch/x64/syscall.rs:65`) |
| Q3 | A supervisor-set network ceiling the holder cannot widen | Partial: the holder binds rules with WRITE (`kernel/src/net.rs:94`) |
| Q4 | A brokered channel equivalent to `BrokerIpc` (M:`model.rs:170`) | Missing: no IPC object in `libs/ftl_types/src/syscall.rs` |
| Q5 | Attenuated handle transfer | Missing: READ/WRITE only, no transfer call |
| Q6 | Filesystem grants by object identity | Missing: embedded cpio only (`lx/src/main.rs:45`) |
| Q7 | Memory, thread, and CPU quotas with observable hits | Partial: a 1024-handle cap only (`kernel/src/hspace.rs:18`) |
| Q8 | Architecture parity behind the same gate | Parity: both are x86_64-only (M:`model.rs:128-137`) |
| Q9 | SMP correctness under teardown | Open FIXME (`kernel/src/thread.rs:279`) |
| Q10 | A kernel-authored, workload-unreachable authority inventory | Missing: the console is the only output, and it is ambient |
| Q11 | Runs under a qualified VMM from digest-pinned assets with no NIC | Unverified: QEMU microvm only (`run.sh:15`) |
| Q12 | Release posture: tags, a security policy, pinned provenance (like `PINNED_NONO_VERSION`, M:`enforcement.rs:8`) | Partial: v0.1.0, one maintainer |
| Q13 | The worker lane meets S1 inside the guest: the library OS must not share a domain with model-generated code | Fails: same as Q2 |

Q1, Q2, and Q13 decide whether rule 5.2.2 can ever yield `FullyEnforced`. Until they hold, every fact observed in `lx` is `SameDomain`.

## 9. Spike (EXPLORATORY, three engineer-days, throwaway)

1. Boot FTL under the Firecracker jailer with no NIC and one vsock device. Record the blockers.
2. Run a static musl stdio MCP server through `initialize`, `tools/list`, and one `tools/call`. Count `ENOSYS` hits at the `lx` dispatcher fallback (FTL `lx/src/syscall/mod.rs:347`).
3. Run an adversarial binary that issues raw FTL calls (`NetCreate`; `VmSpaceMap` on handle 2; `HandleClose` on handle 1) and writes into `lx` heap pages. On stock v0.1.0 all must succeed, which confirms the Q1, Q2, and Q13 classifications. Estimate the patch size for capability-gated creation. Do not build it.

Output: `docs/research/2026-10-ftl-isolation-spike.md`.

- **GO** permits only a PROPOSED design, and only if steps 1 and 2 pass and upstream signals acceptance of capability-gated creation.
- **NO-GO** otherwise. Re-review at FTL's next tagged release.

## 10. Failure modes and fail-closed behavior

| Condition | Result |
|---|---|
| Referenced cage receipt missing, digest mismatch, untrusted signer, or not `FullyEnforced` | Receipt renders not-confined. Verifier facet fails. Broker and adapted dispatch deny at preparation |
| Adapted child `Exited` before dispatch | `prepare_delivery` errors. Dispatch denied |
| Host attribution `native_launch` or `worker_profile` differs from the transport or runner record | Deny (existing rule for `native_launch`, extended) |
| Container inspection differs from the fixed profile | Signed `Rejected` record. The start is never issued. No unsigned record |
| Container start fails, or the post-start inspection does not confirm | Container stopped and removed. Signed `BootstrapFailed` record. Attempt never ready, and no worker call is admitted |
| Signing the container success record fails after the start | Container stopped. Attempt recorded `BootstrapFailed`. No call is admitted |
| An in-scope production receipt lacks a reference for an applicable lane, or matches zero or several attested records in that lane, or matches only a record of the other lane | Facet fails, whatever its `tool_origin` |
| A receipt to which both lanes apply verifies in only one lane | Facet fails |
| A receipt in a scope that requires the worker lane has no `worker_profile`, or its profile has no launch reference, or the profile differs from the run plan's expected worker | Facet fails. The lane is required by the agreement and run plan, not by the receipt (rule 7.3) |
| A `container` or `split_domain` context with pinned bootstrap input and no trust assertion | Profile still `Verified`. Pinned contributions join `External` (spec 11 I7a), so a `Trusted` requirement denies |
| The verifier's appraisal layer does not know the confinement attestation schema | `UnsupportedSchema`. Facet fails |
| The `worker_profile` fact is unverified (absent, mismatched, unverifiable, lookup failed) | The context starts at `unknown` (spec 11 rule I7). Integrity-gated calls deny |
| Projection error (unknown schema, missing surface) | No record. A facet requiring it is `Unavailable`, which denies |
| A future backend reports a `SameDomain` surface | Cannot be `FullyEnforced`. Admission denies |
| `split_domain` claimed without a plan binding | Attribution rejected. Attempt does not start |
| `confined_reader` claimed without an exportable boundary, or the export's evidence does not match the pinned profile | Attribution rejected. The claim renders as `direct` |
| Confined export requested for a boundary in `Failed`, `Cancelled`, or `Quarantined` | Export carries the terminal state. It never claims an admitted return |

## 11. Protocol, schema, and wire impact

- **`spec/PROTOCOL.md` section 6:** document `native_launch`, the verification procedure (5.1.5), the absence disclosure table (5.1.2), and the `chio_process.worker_profile` attribution field.
- **New schemas under `spec/schemas/chio-wire/v1/security/`:** `confinement-record-v1`, `process-container-launch-v1` (success and failure forms), and `confined-reader-evidence-v1` (section 6.4). Register `chio.runtime-attestation.chio-confinement.json.v1` as a runtime-attestation schema, with its verifier family and appraisal adapter (rule 7.6). `chio.confinement.record.v1` stays the schema of the records inside its claims. Positive and negative vectors, plus codegen, follow hardening design 10.1.
- **One new metadata key, `confinement_launch`, beside `native_launch` and bound the same way (rule 5.1.6). No receipt kind and no finding facet.** All additions are additive. Older verifiers ignore the key, and they fail a required facet because they do not know the attestation schema.
- **`spec/SECURITY.md` section 2.3:** list the disclosure and the worker profiles as controls. The residual-risk sentence stays for `direct` workers and unconfined origins.

## 12. Rollout

1. Adapted-server binding (5.1.4) plus PROTOCOL documentation. Small, and independent of the rest.
2. Container launch record (5.3) and the `worker_profile` attribution (6.3) with `direct` and `container`.
3. The `confined_reader` export (6.4) and attribution. This lands after W: merges, and needs the cage port noted in section 14.
4. The `split_domain` qualification (S1-S5) and its mini-SWE reference profile.
5. Confinement record projections, the attestation profile and its appraisal registration (5.2, 7). The Firecracker projection lands with the finding-worker exporter and its `confinement_launch` binding.
6. Microkernel: only on a spike GO, as a separate PROPOSED design.

Rollback of steps 1-5 stops emitting the new evidence. It never relaxes cage-only stdio launch.

## 13. Tests and conformance evidence

- **Unit:**
  - the adapted server returns its spawn receipt while alive, and preparation errors after `Exited`;
  - the disclosure table is rendered for every `ToolOrigin`;
  - `worker_profile` mismatch denies;
  - each `worker_profile` qualification failure (absent, mismatched, unverifiable record, failed lookup, image digest differing from the run plan) yields `Unverified` and an `unknown` initial influence;
  - a `Verified` `container` profile with a pinned external task input and no `BootstrapTrustAssertionV1` starts with that contribution as `External`, not trusted (spec 11 I7a).
- **Proptest:** projection determinism; `FullyEnforced` is rejected with any `NotEnforced` or `SameDomain` isolation surface, and with any withheld-by-contract channel that is not `Enforced`; native digest mismatch is rejected.
- **Container:** the inspection comparator rejects each single-field deviation from the fixed profile (capabilities, seccomp, network, mounts, read-only root, limits). A start failure yields a signed `BootstrapFailed` record and no success record. A worker call before the success record is committed is refused.
- **chio-conformance:** extend `tool_server_escape` (M:`crates/tooling/chio-conformance/tests/threats/tool_server_escape.rs`):
  - a receipt referencing an `Exited` or `BootstrapFailed` cage receipt fails verification;
  - an adapted-server call carries `native_launch`;
  - a `split_domain` attempt whose execution server lacks a verified launch reference (`native_launch`, or `confinement_launch` for a Firecracker guest) is rejected, and one whose Firecracker execution server carries a verified `confinement_launch` is accepted.
- **Verifier:** a finding with `runtime_assurance_tier = Basic` is denied without the confinement attestation, passes with it, and fails when:
  - a production receipt references an unattested launch;
  - an in-scope receipt carries no reference, even under a permitted `tool_origin`;
  - two attested records match one receipt in the same lane;
  - a receipt to which both lanes apply (a `container` worker calling a caged execution tool) passes with one record per lane, and fails when either lane's record is omitted;
  - on a receipt whose run plan requires both lanes, each single-lane omission fails: the tool lane's `native_launch` or `confinement_launch` removed, and the worker lane's `launch_ref` removed;
  - the same receipt with the whole `worker_profile` object absent fails, while the bundle contains a valid worker-lane record that no receipt references;
  - a record whose `attempt_id` differs from the lane's attempt binding (wrong spawn, wrong `confinement_launch.attempt_id`, or `chio_process.attempt` used in place of `launch_attempt`) is rejected;
  - the verifier predates the appraisal registration (`UnsupportedSchema`).
- **Confined reader:** an export of an admitted P5 return projects to a worker-lane record with `inherited_authority = Absent` and `output_channels` showing only `Value`. An export whose retained evidence differs from the pinned helper or image digest is rejected. An export of a `Cancelled` boundary carries no return evidence.
- **Adversarial (worker lane):** in a `container` worker, a workload subprocess reads the credential and invokes a tool. The call succeeds and is recorded under `container`, which demonstrates why `split_domain` exists. In a `split_domain` attempt, the execution domain has no socket or credential to read.

## 14. Residual risks and open decisions

### Residual risks

- Surface flags are coarse. Verifiers must not rank backends by flags. The native record stays authoritative.
- The VMM remains the real boundary for any guest kernel.
- `split_domain` bounds code execution, not prompt-injected steering of the controller, which remains bounded by the process capability.
- The trusted Docker engine and shared kernel stay in the `ProcessContainer` trust base.
- Execution evidence and confinement records attest local launches only.

### Open decisions

1. **Tier mapping.** Is confinement-only evidence capped at `Basic`, or does it warrant a distinct tier? The tier enum is undocumented beyond "derived from attestation" (V:`runtime_attestation.rs:14-23`).
2. **Container launch record signer:** the process host's own key, the kernel receipt signer, or a dedicated runner identity registered as a `[[component]]` in `2026-10-04-closed-kernel-abi-design.md`?
3. **Requirement level for work.** Should funded or delegated work profiles require `split_domain` workers by default, or leave it to each agreement through section 7?
4. **Adapted-server liveness.** Is a repeated spawn-time reference enough, or should the transport mint a per-call liveness observation?
5. **Microkernel scope.** Pin a future backend to FTL, or open it to any capability guest that meets Q1-Q13?
6. **Confined export authority.** Should the P5 export be a new `RecoveryPermission` (for example `confined.export`), or ride the existing review read? The review read already carries review-custody semantics. A separate permission keeps exporting distinct from approving.
7. **Merge of the cage changes.** W:'s P5 adds cage APIs: `ObservedCageExit`, `enforce_deadline`, `try_wait_verified`, `base_plan_digest`, and `base_profile_digest`, in W:`crates/security/chio-cage/src/launch.rs`. It also edits `chio-cage` internals (`lib_parts/part_01.rs`, `launch/linux_parts/part_01_sections/bootstrap.inc`, `launch/linux_parts/part_02.rs`). W:'s base `f25cd61f4` predates M:'s split into `chio-cage`, `chio-cage-plan`, and `chio-cage-init`. Who ports these APIs into the split crates, and in which order relative to the M:/V: union?

Refinements to the review directives, recorded with evidence:
- The directive "map `ConfinementRecord` into `RuntimeAssuranceBacking`" is kept, but the record cannot be mapped directly. The facet only accepts a signed runtime-attestation envelope plus a signed appraisal from pinned authorities (V:`verify.rs:1481-1515`). Section 7 therefore wraps the record set in that envelope.
- `ProcessContainer` is added as directed, but its evidence is currently unsigned and private (`runner.db`). It cannot be `FullyEnforced` until section 5.3 lands.
- Revision 3 refines the directive "`confined_reader` is stronger than `split_domain`". It is stronger only on the authority axis: its execution domain holds nothing. It is not a substitute profile, because it cannot invoke tools. Section 6.2 keeps both.
- Revision 3 refines the output-channel directive. The new `output_channels` surface does not let a tool-lane cage claim channel discipline it does not enforce. Tool-lane cages record `NotEnforced` there, so rule 5.2.2 still allows `FullyEnforced` for them only if `output_channels` is excluded from that rule. Rule 5.2.2 therefore applies to the six isolation surfaces. `output_channels` is reported, not gating, unless a return contract (as in P5) claims it.

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180389982 | Register the confinement schema with the appraisal layer | Fixed now. Adds a verifier family, trust-material and appraisal arms, inventory entries, and an adapter that re-projects records and caps the tier at `Basic`. The `enterprise_verifier` alternative is rejected | Section 7 rule 6; section 11 |
| 4180389993 | Bind non-cage confinement records to production receipts | Fixed now. Every in-scope receipt must map to exactly one record through `native_launch`, `confinement_launch` or `worker_profile.launch_ref`; `tool_origin` never substitutes | Rule 5.1.6; section 7 rule 3; section 10 |
| 4180435350 | Sign container launch evidence after start succeeds | Fixed now. Inspect, start, confirm, then sign. A failed start signs a distinct `BootstrapFailed` record, and no call is admitted before the success record | Section 5.3 |
| 4180731791 | Treat worker profile as an authorization fact | Fixed now. A verified fact with explicit qualification, checked once at scope creation, and fail-closed to `unknown`. Spec 11 rule I7 now cites it | Rule 6.3.5; spec 11 rule I7 |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-7-01 | Exactly one confinement record per receipt rejects calls covered by both lanes | Fixed. The match is now exactly one record per applicable lane, keyed by (receipt, lane), and both are required when both lanes apply. Each reference has its own attempt binding: `native_launch` uses its cage enforcement `receipt_id` as the attempt identity, `confinement_launch` carries `attempt_id`, and the worker lane uses a new runner-bound `worker_profile.launch_attempt`, because `chio_process.attempt` numbers operation retries, not launches (M:`chio-process/src/lib.rs:455-461`) | Section 7 rule 3; rule 5.2.8; section 6.3 rules 2 and 5; section 10; section 13 |

### Independent review pass 2 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-7-02 | Worker-lane applicability is defined using the evidence whose absence should fail verification | Fixed. The verifier derives the required lanes and the expected worker identity from the agreement scope and signed run plan before reading receipt evidence. The worker lane is required for every in-scope receipt under the worker attempt, whether or not it carries `worker_profile`. A missing profile, a missing launch reference, or a profile that differs from the run plan fails the facet, and an unreferenced record never satisfies a required lane. Tests cover each single-lane omission and a fully absent profile | rule 6.3.3; section 7 rule 3; section 10; section 13 |
| R-11-05 (spec 7 side) | Pinning bootstrap bytes is treated as proof that those bytes have no external influence | Fixed with spec 11 I7a. The `container` qualification predicate is now a boundary check (image digest equals the run plan), not input pinning. `Verified` attests only "no channel outside mediation". Bootstrap contributions are joined under I7a, and pinned ones are `External` without an operator-signed assertion. S1-S5 note that boundary qualification is not input trust | S1-S5 note; rule 6.3.5; section 6.3 formal block; section 10; section 13 |

### Codex review (PR #1174, round 9)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185756917 | Exempt backend-neutral references from the absence predicate | Fixed now. A receipt is classified `not_confined` only when both `native_launch` and `confinement_launch` are absent. `confinement_launch` has its own verification predicate (record digest, schema, pinned signer, `FullyEnforced`, attempt id, not exited before dispatch), so valid Firecracker or other backend-neutral evidence is accepted | section 5.1 predicate; rule 6 |

### Codex review (PR #1174, round 10)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4185993967 | Accept backend-neutral launch references for split-domain servers | Fixed now. The `split_domain` predicate requires a verified backend-appropriate launch reference for every execution-server call: `native_launch` for the Linux cage, or `confinement_launch` for another backend (rule 5.1.6). A Firecracker execution server can therefore yield `Verified(split_domain)`. Tests cover both | rule 6.3 predicate; section 10 tests |

### Codex review (PR #1174, round 11)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186194327 | Permit backend-neutral launches for split-domain profiles | Fixed now. Rule 6.3.4 now records `split_domain` when every planned execution server has a verified backend-appropriate reference, either rule 5.1.3 `native_launch` or rule 5.1.6 `confinement_launch`, matching the round 10 predicate | rule 6.3.4 |

### Codex review (PR #1174, round 12)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4186364937 | Qualify absence on both launch reference forms | Fixed now. Rule 2 classifies a receipt as unconfined only when it has neither `native_launch` nor a verified `confinement_launch`, matching the table and the formal predicate | section 5.1 rule 2 |

## Appendix A. FTL reference

What FTL does (paths in the FTL checkout):

- **System calls.** The kernel ABI is a closed 31-entry enum (`libs/ftl_types/src/syscall.rs`). Numbers below `SYSCALL_BASE` are passed back to the thread's `syscall_pc` (`kernel/src/arch/x64/syscall.rs:65`), and faults go to `fault_pc` (`kernel/src/arch/x64/idt.rs:444`).
- **Library OS.** `lx` implements 47 Linux system calls and returns `ENOSYS` otherwise (`lx/src/syscall/mod.rs:347`). One initrd is loaded per boot, so there is one container per boot.
- **Handles.** Handles carry READ/WRITE rights in per-space tables capped at 1024 (`kernel/src/hspace.rs:18`). Closing a space tears down its threads and handles (`kernel/src/hspace.rs:165`).

Where the analogy maps and breaks:

- FTL's `lx` corresponds to a Chio worker personality (framework adapter). Both are tenant code with policy that the co-resident workload can bypass. That makes FTL a cautionary example for the worker lane (section 6), not a model for the tool lane.
- FTL's container boundary separates tenants on one kernel. In a VM-per-tool-server deployment, the VMM provides tenant separation and that boundary is unused.
- FTL's handle table is the workload's complete authority only once ambient creation (Q1) is removed.
- Recovery P5 is the anti-`lx`. The observing code holds zero authority: no credential, socket, broker, tool, or model. It has one framed channel in (`CHIOCF1`) and one bounded, host-recomputed value out. It is FTL's "container with no Net or Console handle" done right, with a mediated return added. FTL's flaw is ambient `NetCreate`/`ConsoleOpen` (Q1). P5's pinned plan forbids every ambient route before launch (W:`confinement/execution.rs:46-77`).

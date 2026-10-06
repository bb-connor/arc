# Design: layered kernel ABI registry and TCB budget

- Status: PROPOSED (revision 3, re-baselined 2026-10-04 on #1160 + #1173 + #1172 + uncommitted recovery P0-P6 (W:))
- Date: 2026-10-04
- Scope: declare every closed trusted operation set as one layered registry:
  - L0, the in-process kernel;
  - L1, the agent-process ABI;
  - L2, the work ABI;
  - L3, the recovery ABI;
  - separate trusted components.

  Classify every live entry point and seam against it, and gate the registry and the TCB dependency closure in CI with the hardening tooling that already exists.
- Owners: `chio-kernel-core` (`KernelOp`), `chio-kernel` (L0 classification), `chio-process` (L1 rows), work and recovery owners (L2, L3 rows), `scripts/` gates (with the hardening-toolchain owners), bindings (`chio-kernel-browser`, `chio-kernel-mobile`, `chio-cpp-kernel-ffi`)
- Related:
  - `docs/protocols/PORTABLE-KERNEL-ARCHITECTURE.md`;
  - ADR-0011, ADR-0019 item 6, ADR-0022 item 4;
  - M: `2026-09-26-hardening-toolchain-spec.md` (H8, H11, GT1);
  - M: `2026-09-26-unrepresentable-defects-design.md` (Mechanism D);
  - M: `docs/security/trust-boundary-inventory.json`;
  - V: `2026-10-03-work-runtime-design.md`, `2026-10-03-work-developer-surface-design.md`, `2026-10-03-work-owner-services-design.md`;
  - R:/W: `docs/architecture/recoverable-agent-runtime/02-rust-design.md`, `08-protocol-operations.md`, `11-contract-catalog.md`, and W: `implementation/p1`-`p5` `OPERATIONS.md`;
  - `spec/PROTOCOL.md` sections 3 and 8.
- Origin: lessons from the FTL (nuta/ftl) review
- Siblings: `2026-10-04-ftl-lessons-program-design.md` (umbrella), `2026-10-04-authority-faults-design.md`, `2026-10-04-typed-reservations-design.md`, `2026-10-04-authority-space-teardown-design.md`, `2026-10-04-unified-event-queue-design.md`, `2026-10-04-opaque-adapter-context-design.md`, `2026-10-04-microkernel-isolation-backend-design.md`

Citations:
- `M:` = `origin/integration/process-security-m4` @ `19df31ad9` (#1160).
- `V:` = `origin/work/verifiable-work-session-20261003` @ `14477aaac` (#1173).
- `R:` = `origin/research/openappa-recovery-20261001` @ `de84fc306` (#1172), recovery design documents.
- `W:` = the uncommitted working tree of `standalone/arc-worktrees/recoverable-agent-runtime-20261002` (branch `feat/recoverable-agent-runtime-20261002`, committed HEAD `de84fc306`, built on the #1160 checkpoint `f25cd61f4`). Recovery P0-P5 and the P6 product surface (protected setup and qualification, decision reports, maintenance proposals and separately signed policy application) are implemented there. Line references reflect that tree on 2026-10-04 and may drift. W: is treated as shipped.
- `P:` = `feat/process-command-experience-20260924` @ `e24596543`.
- Bare paths are `main` @ `f5a9d2ab2` and are used only for closure measurements.
- W1-W4 APIs have no code on these refs and are cited as **assumed shipped (contract anchor)**. Recovery names documented in R: but absent from W: code are marked **doc-only (not implemented in W:)**.

## Revision 3 changes

- **L3 is implemented and pinned.** It is the seven `RecoveryCommandBodyV1` variants, three endpoints (`review`, `settle`, `explain`), and the 15-variant `RecoveryPermission`. `ExplainIntent` is not a command: it is `POST /v1/recovery/explain` under `Inspect` (section 2, section 4).
- **L0 grows from 27 to 29 ops.** W: adds 24 live public `ChioKernel` methods (all `&self`) and one test-gated method, so the union surface grows from 230 to 254. New `RecoveryControl` (28) and `RecoveryDisclosureIssuance` (29) ops; `Reconcile` and `query` absorb the rest (section 5). New rule R5a gives per-variant stop dispositions for an entry point that multiplexes an L3 enum.
- **L1 version collision.** M: commit `2a4c2fbe4` bumped `PROCESS_ABI` v2 to v3 for broker routes, and W: independently bumped v2 to v3 for durable knowledge and recovery. The registry records the union as `chio.process.abi.v4`.
- **New seams classified by polarity** (section 6): the recovery authority port and process reservation port, the grant v2 signer, and the knowledge, semantic and confinement seams. Two new pure components, `chio-recovery` (advisory, outside the TCB) and `chio-semantic-contracts` (activation gate). P3 connector coverage becomes a component census row.
- **R13 precedent.** The semantic HTTP gateway client lives in `chio-control-plane`, not the kernel.
- **Pushback, recorded in open decisions 8-10:** knowledge enforcement is not an `UpdateLiveTrust` toggle (the kernel methods are queries, and the one-way switch is on `ProcessRuntime`); W: adds 24 methods, not about 23; settlement and provider finality map to `Reconcile`, not a new op.

## Revision 2 changes

- **Layered registry.** Revision 1 covered only `ChioKernel`. Section 4 now registers L0-L3 and component op enums under one rule set, plus R11 (semantics default to native tools) and R12 (higher layers declare the L0 ops they drive).
- **L0 re-based on the M ∪ V surface** (230 names). Two new ops: `CallerExecution` and `ExportExecutionEvidence`. Classified: boot signing seams, delegated-work install, test-only hooks, payment release-authority stores.
- **chio-process trust inputs** (`ProcessRegistry::caller`, subject seeds) are in the TCB. Verifiers and W2 owner services are components.
- **R13:** no network I/O implementations in the kernel crate (the kernel compiles `ureq` x402, ACP and webhook clients).
- **Gates reuse M: tooling.** The closure gate extends H11 `check-dependency-budget.py`. The census follows `check-trust-boundaries.py`. Allowlists live in the Mechanism D gate. H8 is the signature layer. GT1 is a named blocker.
- **Corrected:** alloy already reaches the kernel through `chio-settle` default `web3` and through `chio-core` to `chio-web3`.
- **Dropped:** new `[[component]]` ceilings, `ci-gates/tcb.toml`, and the claim that no public-API snapshot tooling exists.

## 1. Decision summary

FTL's kernel answers a closed, numbered set of system calls and bounces everything else to a per-tenant library. Chio's shipped baseline has this shape at several layers:
- **L0, in-process kernel.** It handles no dialects. No MCP, A2A, ACP, OpenAPI or provider adapter crate is in `chio-kernel`'s normal closure.
- **L1, agent process.** A six-op worker protocol with no administrative operations. New semantics arrive as native tools behind `invoke`.
- **L2, work (assumed shipped).** One closed multiplexed envelope over the worker credential, with "no second worker listener".
- **L3, recovery (implemented in W:).** Seven closed host commands, three endpoints and a closed permission vocabulary, all host-held. Workers cannot drive them.
- **Components.** The keyring, the broker and active-response authority each expose a closed operation enum. W: adds `chio-recovery` (pure advisory planner) and `chio-semantic-contracts` (pure activation gate).

What is missing is one declaration across these layers, plus gates that keep each layer from growing silently. Today:
- `ChioKernel` has 254 unclassified public methods across M, V and W.
- `PROCESS_ABI` carries two incompatible "v3" definitions.
- Its dependency closure contains `reqwest`, `hyper`, `sigstore`, `oci-client`, `prost`, alloy and `ureq`.

Decision:
- **(a) A layered registry.** One inventory, `docs/security/kernel-abi-inventory.json`, with layers L0-L3 plus components. Every live entry point at every layer maps to exactly one op or a non-op class (section 6).
- **(b) `KernelOp` at L0.** A closed, `no_std`, numbered enum of 29 trusted live operations in six classes. It is an inventory, not a dispatcher.
- **(c) Gates on existing tooling.**
  - A census checker modeled on `check-trust-boundaries.py`.
  - Closure budgets as new entries in H11's `check-dependency-budget.py`, with a small extension.
  - Escape-hatch classes in the Mechanism D gate.
- **(d) Frozen normalized request vocabulary at L0.** Dialects lower onto existing ops, and adapters advertise only the W3 support dimensions they qualify for.
- **(e) No line-count gate.** Op count, entry points per op, seam polarity, layer descent and closure membership measure attack surface; lines do not.

This does not replace:
- the `chio-kernel-core` / `chio-kernel` split;
- ADR-0022's lane decomposition;
- ADR-0019's exhaustive-match rule (R2 extends it);
- the process ABI's own compatibility contract (L1 keeps it).

## 2. Verified current state

| Fact | Evidence |
|---|---|
| Public `ChioKernel` methods, excluding test-gated ones. Counted by a heuristic script over `impl ChioKernel` blocks; it reproduces revision 1's `main` count | `main` 149 (97 `&self`, 47 `&mut self`, 3 `self`, 2 constructors). M 227 (149, 71, 3, 4) plus 4 test-gated. V 229 (150, 72, 3, 4). M ∪ V: 230 names. V adds `export_durable_execution_evidence` and `require_durable_request_retention` |
| Live trust mutators taking `&self` | M: `kernel/construction.rs:1292` (`set_capability_trust_root`), `:1399` (`set_federation_local_kernel_id`), `:1673` (`emergency_stop`); M: `kernel/validation/issuance.rs:10` (`issue_capability`); M: `kernel/validation/revocation_trace.rs:10` (`revoke_capability`) |
| Signing seams are boot-only by type | M: `kernel/signing_authority.rs:108` (`with_hybrid_signing_backend`, `&mut self`); M: `kernel/validation.rs:315` (`set_capability_crypto_floor`, `&mut self`) |
| Handle exports (live accessors to mutable kernel state) | M: `construction.rs:692` (`revocation_view`), `:1182` (`settlement_observer`), `:1237` (`memory_provenance_store`), `:1810` (`dpop_replay_source`) |
| Caller-executed tools | M: `kernel/evaluation/caller_execution.rs:170-419` (`reserve_`, `start_`, `reconcile_caller_execution*`) |
| Execution evidence export | V: `kernel/admission_coordinator/execution_evidence.rs:18`. Signs one receipt for a retained native execution, "creates neither dispatch nor settlement authority", and attests local execution only (`:14-17`) |
| Delegated-work install | V: `delegated_work.rs:21`, `:39`. A free function over `&mut ChioKernel`. It requires a durable admission store, calls `require_durable_request_retention` (V: `construction.rs:794`), installs a `Guard`, and pins accepted allocator keys. "Qualified tool confinement ... remain[s] host assumptions" (`:4-5`) |
| Harness hooks are test-only | V: `admission_coordinator.rs:19-21` (module gated on `admission-test-support`), `finalization_cutpoint.rs:67`, `native_egress.rs:79`, `native_egress/capture.rs:278` |
| Payment release authorities | V: `payment/journal.rs:88-96` (five `PaymentReleaseAuthorityKind`s); `QualifiedUnknownPaymentReleaseStore` (`payment/unknown_release.rs:401`); `QualifiedContractualCaptureWaiverStore` (`payment/contractual_resolution_record.rs:147`) |
| Network clients compiled into `chio-kernel` | V: `payment.rs:119`, `:132` (`X402PaymentAdapter`, `AcpPaymentAdapter` holding `ureq::Agent`, `:123`, `:140`); `approval_channels.rs:81` (webhook `ureq` agent); unconditional `ureq` dependency (V: `chio-kernel/Cargo.toml:110`) |
| New kernel dependencies | M: `chio-security-types`, `chio-response-model` (M: `chio-kernel/Cargo.toml:78-79`). V: `chio-workflow` (V: `Cargo.toml:74`), for `chio_workflow::delegation` |
| L1 process ABI | `PROCESS_ABI = "chio.process.abi.v3"` (M: `chio-process/src/lib.rs:65`). It is versioned with no implicit migration (M: `chio-cli/PROCESS_HOST.md:203-212`). Six worker ops (M: `chio-process/WORKER_PROTOCOL.md:50-57`). It has no process selector, mint, revocation or administrative op, and spawn and wait arrive as native tools through `invoke` (`:59-66`) |
| L1 version collision | M: `2a4c2fbe4` (2026-09-30, broker routes) changed v2 to v3. W: independently declares `chio.process.abi.v3` for durable knowledge and recovery (W: `chio-process/src/lib.rs:54`; its base `f25cd61f4` had v2). The two v3s cover different surfaces |
| L1 under durable knowledge | `ProcessRuntime::enable_durable_knowledge` is a one-way switch (W: `chio-process/src/knowledge.rs:22`). Afterwards the raw blob and storage routes and `checkpoint` refuse through `require_raw_knowledge` (W: `chio-process/src/lib.rs:259-260`, `:275-276`, `:284-285`, `:583-584`). Host-only `reserve_recovery_call` and `finalize_recovery_call` (W: `chio-process/src/recovery.rs:83`, `:110`) are not worker ops |
| L0 recovery surface (W:) | 24 live public `ChioKernel` methods, all `&self`: 20 in W: `kernel/admission_coordinator/recovery_runtime.rs:53-599`; `authenticate_recovery_actor` and `load_recovery_request_custody` (W: `recovery/ports.rs:193`, `:272`); `observe_recovery_capability_liveness` (W: `recovery/observation.rs:7`); `durable_authority_id` (W: `kernel/admission_coordinator.rs:226`). Plus test-gated `install_native_capture_observer_for_test` (W: `native_egress/capture.rs:293`) |
| Recovery authority seams (W:) | `AdmissionOperationStore::recovery_authority() -> Option<&dyn RecoveryAuthorityPort>`, default `None` (W: `admission_operation/store.rs:164`). `RecoveryAuthorityPort` has 15 methods, including `reserve_issuance`, `attach_signature`, `finalize_envelope`, `historical_release` and `settle` (W: `recovery/ports.rs:53-171`). `RecoveryProcessReservationPort::verify_reservation` (`:46-52`). The deployment is installed by host setup through `configure_recovery_deployment` (W: `chio-store-sqlite/src/admission_operation_store/recovery.rs:28`) |
| Recovery signers (W:) | The grant v2 disclosure signer is an `Arc<Ed25519Backend>` held by the control-plane runtime and checked against the deployment's aggregate issuer (W: `chio-control-plane/src/recovery/runtime.rs:60`, `:83`). The advisory explanation signer is separate (W: `implementation/p2/OPERATIONS.md:13-19`) |
| Knowledge, semantic and confinement seams (W:) | `ArtifactBlobPort` (W: `chio-kernel/src/knowledge.rs:62`) and `ArtifactReleaseSink` (`:98`). `PinnedSemanticConnector` implements `ToolServerConnection` (W: `chio-control-plane/src/semantic/connector.rs:183`) over `SemanticTransport` (`semantic/transport.rs:27`). `NativeConfinedRuntime` (W: `chio-control-plane/src/confinement.rs:23`). Durable scoped semantic stop `set_semantic_emergency_stop` (W: `chio-store-sqlite/src/admission_operation_store/semantic.rs:355`) |
| W: components | `chio-recovery`: "A directive cannot execute, close, settle, sign or release", with a `compile_fail` doctest refusing report-to-grant conversion (W: `crates/security/chio-recovery/src/lib.rs:1-10`). `chio-semantic-contracts`: "No provider, plugin, filesystem, store or clock" (W: `crates/security/chio-semantic-contracts/src/lib.rs:1`). The semantic HTTP client is a `reqwest` client in `chio-control-plane` (W: `semantic/http.rs:11`, `:34-35`), not in the kernel |
| chio-process trust inputs | `ProcessRegistry::caller` (M: `chio-process/src/registry.rs:114`) selects caller identity for mailbox sender attestation and spawn. `provision_signers` (`:85`) holds native-delegation subject signing keys |
| L2 work ABI (assumed shipped, contract anchor) | V: `2026-10-03-work-runtime-design.md:32` (`WorkRequestV1 { Prepare, Submit, Query }`), `:56` (`WorkPreparationV1`), `:73` (`WorkActionV1`), `:87` (`WorkQueryV1`), `:155` (negotiated alongside `chio.process.v1`, no second listener). No `WorkRequestV1` exists in V: `crates/` or `sdks/` |
| L3 recovery ABI (implemented in W:) | `RecoveryCommandBodyV1` has seven variants, `CreateWorkflow`, `InspectWorkflow`, `SelectOffer`, `SubmitApproval`, `ResumeWorkflow`, `CancelWorkflow`, `ReportDecision`, with wire names `create` through `report` (W: `chio-security-types/src/recovery/commands.rs:26-58`, `:69-75`). Endpoints: `/v1/recovery/commands`, `/review`, `/settle` (W: `chio-control-plane/src/recovery/transport.rs:50-52`) and `/v1/recovery/explain` (W: `recovery/explanation/transport.rs:37`). `RecoveryPermission` has 16 variants, `Create`, `Inspect`, `Select`, `Approve`, `Resume`, `Cancel`, `Report`, `Settle`, `KnowledgeRead`/`Write`/`Adopt`/`Admin`, `ConfinedLaunch`/`Return`/`Cancel` and P6's `Maintain`, whose wire names are grant tool names on server `chio.recovery` (W: `chio-kernel/src/recovery/records.rs:52-88`). R:'s `ExplainIntent` command is doc-only (not implemented in W:) |
| P6 product surface (W:) | P6 adds no `ChioKernel` method. It adds control-plane routes and store mutations. **Setup:** `RecoverySetupService` (W: `chio-control-plane/src/recovery/setup.rs:35`) mounts `/v1/recovery/setup/probe` and `/qualify` (`recovery/setup/transport.rs:30-37`) over the store's `pin_setup_creation`, `configure_protected_setup`, `commit_setup_probe`, `prepare_setup_report` and `accept_setup_report` (W: `chio-store-sqlite/src/admission_operation_store/setup/service.rs:8-283`). **Gate:** `setup/gate.rs` `require_ready`, `require_command` and `require_capture` (`:4-124`) gate commands and captures on the selected deployment and its qualification, with a narrow selected self-test allowed before readiness. Native capture calls `require_capture` at `security_participant_state/dispatch_ledger/capture.rs:45-51`; semantic and knowledge paths call `require_ready` (`semantic.rs:274`, `knowledge.rs:228`). **Maintenance:** `RecoveryMaintenanceRuntime` (`chio-control-plane/src/recovery/maintenance.rs:20`) mounts `/v1/recovery/reports/submit`, `/reports/read` and `/policy/propose` (`recovery/maintenance/transport.rs:41-47`), and none of these routes applies a policy. **Application:** the store method `apply_reviewed_semantic_deployment` (`semantic/policy.rs:99-185`) verifies an independently selected operator's signature, the exact proposal, base and generation, and the writer fence, keeps original-ID readback, and installs the reviewed deployment in the qualified writer |
| Adapter support dimensions | V: `2026-10-03-work-developer-surface-design.md:13` (admission, owned dispatch, durable observation, output-release enforcement, recovery continuation, work-command transport, funded settlement), reusing `docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json` (`:17`) |
| Owner services run outside the kernel | V: `2026-10-03-work-owner-services-design.md:9-13`, inside `chio-control-plane` |
| Component op enums | M: `chio-keyring/src/ipc.rs:323` (`WitnessServiceOperation`), `:543` (`AuditServiceOperation`); M: `chio-secret-broker/src/authority_ipc.rs:42` (`AuthorityOperation`) |
| Security seams in the kernel | M: `kernel/mod.rs:214` (`CapabilityIssuanceAdmissionAuthority`), `:334` (`SecurityInvocationContextAuthority`), `:344` (`SecurityPreDispatchPolicy`), `:403` (`SecurityPreDispatchHook`); `chio-security-kernel` is `forbid(unsafe_code)` (M: `src/lib.rs:15`) |
| TCB closure on `main` (`cargo tree -p chio-kernel -e normal`, aarch64-apple-darwin) | **Archived measurement** on `main` at `f5a9d2ab2`, not reproduced for the M:/V:/W: integrated closure: 407 distinct names (434 name/version pairs). Paths: alloy via `chio-settle` default `web3` (V: `chio-settle/Cargo.toml:15-23`, `default = ["web3"]`) **and** via `chio-core` to `chio-web3` to `alloy-primitives`; `reqwest`/`hyper` via `chio-link`, `chio-settle`, `chio-egress-contract`; sigstore via `chio-weights` to `chio-attest-verify`; `ureq` direct |
| Shrink paths (edge removal over the resolved `main` graph) | **Archived measurement** on `main` at `f5a9d2ab2` (same target and command), not reproduced for the integrated closure. Cut `chio-weights` to `chio-attest-verify`: 310 names. Also cut the `reqwest` edges of `chio-link`, `chio-settle`, `chio-egress-contract`: 281, with no `reqwest`/`hyper`/sigstore. Also cut `chio-settle`'s `web3` edges: 262, with one alloy crate left through `chio-core` to `chio-web3`. Revision 1's "285 of 407, none banned" ignored alloy |
| Existing gates on M | H11 `scripts/check-dependency-budget.py`: one musl target (`:26`), `Budget` (`:30`), `COMMON_DENY` (`:41`), `HELPER_DENY` (`:55`), `chio-cage-init` ceiling 72 (`:81-87`), broker ceiling 481 (`:89-97`), CI `ci.yml:204`. `scripts/check-trust-boundaries.py` (catalog `:16`, CI `ci.yml:193`), "a source inventory, not a Rust/SQL verifier" (`:4`). H8 deferred (M: hardening spec `:317`, `:510`). **GT1, historical:** at the M baseline none of these gates ran in hosted CI (`:514`). **Current #1160 status:** at #1160 head `89e4641f6` (2026-10-05), hosted job `111748798722` passed step 13 "Workspace structural gates" (trust-boundary, Rust hardening, compiler-probe and dependency-budget gates, M+: `ci.yml:193-205`), step 14 "Formal traceability gate" and step 15 "Temporal security gate", then failed at step 33 "Workspace tests". Structural reachability is shown; overall hosted, native and trusted qualification stays open. Mechanism D gate specified (M: unrepresentable-defects `:440`) and never built (RP6, `:516`) |
| Emergency stop | Process-local and not persisted (M: `construction.rs:369`). Ledger rows `2026-10-01-compliance-product-truth-review:EV11` and `2026-10-01-execution-review-accounting-clocks:AC6` are `open-acceptance` (M: `docs/security/landing-ledger.json`). No stop check in M: `validation/issuance.rs` |

## 3. Goals and non-goals

### Goals

- One registry of closed trusted operation sets, by layer, with numbered, versioned rows and the existing per-layer version constants.
- Every live entry point at every layer classified. An unclassified one fails the census.
- Every seam classified by polarity, so reviewers know which plug-ins can widen authority, including in-process components "above" the kernel.
- A shrink-only TCB closure budget for the kernel, an exact budget for the portable core, and dated debt with recorded paths.
- No network client implementations in the kernel crate.
- Op-set changes at any layer forced through a spec row.

### Non-goals

- Runtime dispatch through `KernelOp`, op ids on the wire, or receipts carrying op ids (open decision 4).
- Replacing `PROCESS_ABI`, `chio.work.v1` versioning or recovery command versioning. The registry records them; their owners keep their contracts.
- Proving a `query` read-only. Classification is reviewed declaration plus signature-drift detection.
- Type-vocabulary ABI. Wire schemas and codegen already govern types.

## 4. The layered registry

| Layer | Closed set | Version constant | Owner document |
|---|---|---|---|
| L0 | `KernelOp` (section 5): `ChioKernel` live methods, core free functions, binding exports, native wire messages, sidecar endpoints | `KERNEL_ABI_VERSION` (new) | `spec/PROTOCOL.md` section 8.6 (new) |
| L1 | Worker ops `inspect`, `invoke`, `checkpoint`, `blob_put`, `blob_read`, `cancel`; reserved native-tool namespaces `chio-process/*`, `chio-ipc/*`. Under durable knowledge, the raw state routes refuse | `PROCESS_ABI`, recorded as `chio.process.abi.v4` for the M ∪ W union (the two v3s are incompatible) | M: `chio-process/WORKER_PROTOCOL.md`, M: `chio-cli/PROCESS_HOST.md` |
| L2 | `WorkRequestV1` variants, `WorkPreparationV1` proposals, `WorkActionV1`, `WorkQueryV1` (assumed shipped) | `chio.work.v1` | V: `2026-10-03-work-runtime-design.md` |
| L3 | `RecoveryCommandBodyV1` (7 variants in W:; spec 2 O5 adds proposed eighth `RetireSuccessorReservation`); endpoints `review`, `settle`, `explain`; `RecoveryPermission` (16 variants, including P6's `maintain`; retirement reuses `Cancel`; grant tool names on `chio.recovery`; W: `chio-kernel/src/recovery/records.rs:52-88`) | the `V1` command schema and the recovery deployment profile | W: `chio-security-types/src/recovery/commands.rs`, W: `docs/architecture/recoverable-agent-runtime/`; spec 2 O5 |
| C | Component op enums: keyring witness/audit, broker authority, active-response authority, verifiers, W2 owner-service routes. Connector coverage census: each P3 semantic package classifies every exposed operation `covered`, `operator-authorized dynamic resolution` or `refused` (W: `05-semantic-contracts.md:15`) | per component | each component's design |

Normative rules (R1-R10 from revision 1 are retained and now apply per layer):

1. **R1. Closure.** Every live entry point at a layer maps to exactly one op of that layer, or to a non-op class (section 6). At L0, "live" means:
   - a `pub` `ChioKernel` method taking `&self` or `self: Arc<Self>`;
   - a `pub fn` reachable from the `chio-kernel-core` root;
   - a binding export;
   - a wire message;
   - a sidecar endpoint.
   At L1-L3, every protocol variant and every reserved native-tool name counts.
2. **R2. Exhaustive matches.** No wildcard arm over any layer's op enum or class enum in the owning crates (ADR-0019 item 6).
3. **R3. Numbering.** Ids are dense and never reused. Retired ids stay listed. Adding an op is a minor bump of that layer's version. Retiring an op, or changing its class or emergency-stop disposition, is a major bump. L1 keeps `PROCESS_ABI`'s stricter rule: any incompatible change is a new ABI with no implicit migration.
4. **R4. Spec coupling.** Every row carries `spec_ref`. The census requires the op's id to appear in the owning document's table with matching id, class and status.
5. **R5. Emergency-stop disposition.**
   - Each L0 op declares `emergency_stop = "deny" | "allow"` with a rationale. A generated test asserts refusal while stopped for every entry point of a `deny` op.
   - L1-L3 ops inherit the disposition of the L0 ops they drive (R12).
   - The persistence gap is tracked as ledger EV11/AC6. This rule records the dispositions; it does not make the stop durable.
   - **R5a. Multiplexed entry points.** An L0 entry point that dispatches an L3 enum (`execute_recovery_command`) declares its disposition per L3 variant, and the generated test asserts per variant. For `RecoveryControl`: `InspectWorkflow`, `CancelWorkflow` and proposed `RetireSuccessorReservation` (spec 2 O5) are `allow` (observation and closure must work during a stop), and every other variant is `deny`. Retirement uses this existing entry point and adds no L0 method. It is restricted to an exact uncreated reservation under predecessor-scope `Cancel` authority; new reservation and creation still deny while stopped.
   - **R5b. Per-entry-point dispositions.** An op whose entry points differ in direction (begin versus observe), or in authority profile (agent versus control), declares a disposition per entry point. Three ops use it:
     - `CallerExecution`: `reserve_` and `start_` are `deny`, and `reconcile_caller_execution*` plus authenticated reports are `allow`, because the effect already happened. `reconcile_caller_execution*` is an entry point of `CallerExecution` only; the `Reconcile` op does not list it (R1).
     - `IssueCapability`: ordinary issuance is `deny`; control-profile issuance (direct tokens whose subject is a roster principal, never an agent scope) is `allow` once spec 8's identity prerequisite (S28) lands.
     - `RecoveryControl`: `authenticate_recovery_actor`, `read_recovery_workflow`, `load_recovery_request_custody` and `observe_recovery_capability_liveness` are `allow`; `reserve_recovery_review` and `acknowledge_recovery_reservation` are `deny`; `execute_recovery_command` follows R5a. Spec 2's proposed `reserve_successor_ordinal` (section 6.10 O4) joins as `deny` when it lands, and the generated census then lists it. Its successor scope is authenticated at reservation and persisted in the link; its identical-replay readback still authenticates and matches that stored scope, and mutates nothing. Creation cannot change the reserved scope.
     - The complete disposition table, including L1, L2 and L3 inheritance and the durable enforcement of every `deny`, is `2026-10-04-durable-stop-epoch-design.md` section 7.
     - Splitting `CallerExecution` into two ops is the alternative. That spec's open decision 3 records the choice.
     - **Generated test under R5b.** For an op with per-entry-point dispositions, the generated test asserts per entry point: refusal while stopped for each `deny` entry point, and no stop refusal for each `allow` entry point. The census generates the inventory and these tests from one table, so an entry point has exactly one op and exactly one disposition.
6. **R6. Entry-point budget.** Each op records `max_entry_points`, and growth requires raising the row in the same PR.
7. **R11. Semantics default downward.** A capability expressible as a native tool behind an existing op must be expressed that way: L1 `invoke`, which reaches L0 `EvaluateToolCall`. A new op at any layer requires a spec argument that it cannot be lowered. This generalizes the worker protocol's existing rule (M: `WORKER_PROTOCOL.md:59-66`) and FTL's pass-through rule.
8. **R12. Layer descent.** Each L1-L3 op row lists the L0 ops it may drive. For example:
   - L1 `invoke` drives `EvaluateToolCall`, and L1 `cancel` drives no L0 op (journal only);
   - L2 `Submit(Seal)` drives `EvaluateToolCall` through the delegated-work guard;
   - L3 `ResumeWorkflow` drives L1 `invoke` through `ProcessRuntime::invoke_known_only` (W: `chio-control-plane/src/recovery/runtime.rs:191`), hence L0 `EvaluateToolCall`, plus `Reconcile`;
   - the L3 `settle` endpoint drives `Reconcile` only;
   - the host review and approval path (`materialize`, `prepare_original`, W: `chio-control-plane/src/recovery/materialize.rs:60`, `:326`) drives `RecoveryDisclosureIssuance`.
   An implementation that calls a `ChioKernel` method outside its row's descent list fails review. The census flags calls it can resolve statically.

## 5. L0: `KernelOp`

```rust
// crates/kernel/chio-kernel-core/src/abi.rs (no_std, no deps beyond core)
#[repr(u16)]
pub enum KernelOp {
    // Admit
    EvaluateToolCall = 1, EvaluatePlan = 2, EvaluateSessionOperation = 3,
    EvaluateNestedRequest = 4, AdmitGovernedActiveResponse = 5,
    ConsumeExecutionNonce = 6, DebitFindingPoolPurchase = 7,
    // Verify
    VerifyCapability = 8, VerifyPassport = 9, VerifyReceipt = 10, VerifyDpopPreview = 11,
    // Sign
    SignReceipt = 12, SignReceiptRelayingTrustedBody = 13,
    // Session
    SessionOpen = 14, SessionRequest = 15, SessionEventRelay = 16, SessionClose = 17,
    // Authority
    IssueCapability = 18, RevokeCapability = 19, UpdateLiveTrust = 20,
    ManageDelegationParent = 21, EmergencyControl = 22,
    // Lifecycle
    Reconcile = 23, ObserveSettlement = 24, Shutdown = 25,
    // Added in revision 2
    CallerExecution = 26,             // Admit
    ExportExecutionEvidence = 27,     // Sign
    // Added in revision 3 (W: recovery)
    RecoveryControl = 28,             // Lifecycle: actor authentication, command execution
    RecoveryDisclosureIssuance = 29,  // Authority: drives grant v2 issuance
}
pub const KERNEL_ABI_VERSION: KernelAbiVersion = KernelAbiVersion { major: 1, minor: 0 };
```

`KERNEL_ABI_VERSION` has not been published. Version 1.0 is defined as the first published set. If phase 0 lands after W: merges, 1.0 holds all 29 ops. If it lands before, which is the expected order, 1.0 holds ops 1-27 and the W: merge adds 28 and 29 as 1.1, a minor bump under R3. Either way, the inventory holds only symbols present in the gated tree (section 10, phase 0).

Revision 1's entry-point table still holds for the `main` surface. Changes for the union surface:

| Op | New entry points on M ∪ V | Disposition |
|---|---|---|
| `CallerExecution` | `reserve_caller_execution*`, `start_caller_execution*` (M: `caller_execution.rs:170-374`) and `reconcile_caller_execution*` (`:419`) | per entry point (R5b): `reserve_` and `start_` `deny`; `reconcile_caller_execution*` and authenticated reports `allow` |
| `Reconcile` | adds the active-response recovery methods. `reconcile_caller_execution*` belongs to `CallerExecution`, not here (R1: one op per entry point) | `allow` (recovery must run during a stop) |
| `ExportExecutionEvidence` | `export_durable_execution_evidence` (V: `execution_evidence.rs:18`) | `allow`: it signs a historical fact and creates no authority |
| `EvaluateToolCall` | the `*_with_security_context` and caller-capability variants. Process calls use `evaluate_tool_call_with_metadata[_and_security_context]` | `deny` |
| `IssueCapability` | the M issuance entry points (M: `validation/issuance.rs:10`) | per entry point (R5b): ordinary issuance `deny`; control-profile issuance `allow` after spec 8 S28. No stop check exists today (section 2) |
| `ManageDelegationParent` | `register_delegation_parent`, used by chio-process for root-first lineage restoration | `deny`, matching M: today: `register_delegation_parent` (M: `validation/lineage.rs:123-135`) calls `validate_non_tool_capability`, whose first check is the emergency stop (`evaluation_entry.rs:46-58`). A host restarted while stopped defers process-tree restoration until resume (spec 8 S8-21, `ready_stopped`) |
| `RecoveryControl` (W:) | `authenticate_recovery_actor`, `execute_recovery_command`, `read_recovery_workflow`, `load_recovery_request_custody`, `observe_recovery_capability_liveness`, `reserve_recovery_review`, `acknowledge_recovery_reservation` (7 in W:; spec 2's `reserve_successor_ordinal` makes 8 when it lands) | per entry point (R5b), with `execute_recovery_command` per L3 variant (R5a). Spec 8 section 7 holds the table |
| `RecoveryDisclosureIssuance` (W:) | `materialize_recovery_action`, `reserve_recovery_issuance`, `attach_recovery_signature`, `finalize_recovery_envelope` (4) | `deny` |
| `Reconcile` (W:) | adds `reconcile_recovery_continuation`, `observe_recovery_completion`, `replay_recovery_result`, `settle_recovery_workflow`, `reserve_recovery_provider_lookup`, `attach_recovery_provider_finality` (6) | `allow` (closure and settlement must complete during a stop) |
| query (W:) | `recovery_deployment`, `observe_recovery_source`, `recovery_native_identity`, `semantic_request_namespace`, `durable_knowledge_enforcement`, `durable_knowledge_enforced`, `durable_authority_id` (7) | n/a |
| `test_support` (W:) | `install_native_capture_observer_for_test` | n/a |
| query (proposed, spec 6) | `delegated_work_layout`: read-only, reports the installed D1 layout (`Arguments` or `GovernedContext`) so spec 6's bound builder can validate a request before sealing (spec 6 rule 11). It joins the inventory when it lands | n/a |

The phase 0 inventory classifies all 254 union names (230 on M ∪ V, plus 24 from W:). Revision 1's category counts for `main` (65 op entry points, 30 queries, 3 handle exports, 51 boot symbols) are the starting point.

Two W: queries return protected material, and the census flags them for owner review:
- `load_recovery_request_custody` (actor-authenticated) returns the protected reviewed envelope, so it sits under `RecoveryControl` rather than `query`.
- `observe_recovery_source` takes only a scope, with no actor, and returns the native security flow observation (open decision 8).

Normalized request vocabulary (frozen):
- the full kernel shapes are `ToolCallRequest`, `SessionOperation` in `OperationContext`, and the governed active-response types;
- the core shape is `PortableToolCallRequest`;
- on the wire, `AgentMessage`.

7. **R7. No dialect types in the TCB.** No L0 op input type comes from a `crates/protocol` crate other than `chio-tool-call-fabric` and `chio-egress-contract`.
8. **R8. Arguments are opaque.** Tool `arguments` are interpreted only through canonical hashing, `Constraint` matching and guards.

The protocol-side counterpart of R7 and R8 is the W3 dimension rule: an adapter advertises only the dimensions it has qualified, in `CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`. A dialect concept lowers onto existing ops, and an adapter that has not qualified a dimension fails before dispatch.

## 6. Non-op classes and seam polarity

| Class | Definition | Gate behavior |
|---|---|---|
| `query` | `&self`, documented read-only, returning owned data or shared references to immutable data | hash-tracked; reviewer attests |
| `boot` | constructor, `self` builder, `&mut self`, or a free function over `&mut ChioKernel`; unreachable once the kernel is shared | seam setters declare polarity |
| `handle_export` | `&self` returning a handle to mutable kernel state | debt only; listed in the Mechanism D allowlist with an expiry; four today |
| `binding_local` | binding plumbing that never yields Allow or signs | allowed with rationale |
| `test_support` | behind `cfg(test)` or `admission-test-support` | listed in the Mechanism D allowlist; the census verifies the cfg |

Polarities (`deny_only`, `fact_source`, `custody`, `output_transform`) are as in revision 1. New classifications:

| Symbol or component | Class / polarity |
|---|---|
| `with_hybrid_signing_backend`, `set_capability_crypto_floor` | `boot`; the signing backend is `custody` (it holds receipt-signing keys) |
| `install_delegated_work[_with_layout]`, `require_durable_request_retention` | `boot`. The installed guard is `deny_only`; the accepted allocator key list is a `fact_source` |
| The four `install_*_checkpoint_hook` / `install_durable_finalization_cutpoint` hooks | `test_support` |
| `QualifiedUnknownPaymentReleaseStore`, `QualifiedContractualCaptureWaiverStore` | `custody` (release authority: the first releases an unknown hold; the second resolves a known return's positive pending capture in `Finalizing`, spec 9 M7a and M7b) |
| `X402PaymentAdapter`, `AcpPaymentAdapter`, webhook `ApprovalChannel` | `custody` / `fact_source` implementations; R13 relocates them |
| `chio-process`: `ProcessRegistry::caller` | `fact_source` (mailbox sender attestation, spawn identity) |
| `chio-process`: `provision_signers` and its seeds | `custody` |
| `chio-finding-verifier`, peer verifier, authority verifier | components. The observer and checker are `fact_source`s |
| W2 owner services | component outside `KernelOp`; advertises only qualified W3 dimensions |
| `RecoveryAuthorityPort` (store extension via `recovery_authority()`) | `custody` and `fact_source`: it holds protected envelopes, issuance reservations and historical release, and supplies workflow records |
| `RecoveryProcessReservationPort` | `fact_source` (the process journal's committed reservation) |
| `configure_recovery_deployment` (`RecoveryDeploymentV1` with actor assignments) | `boot`, host setup only |
| Grant v2 disclosure signer (control-plane `Ed25519Backend`) | `custody` |
| Advisory explanation signer | outside the TCB: advisory only, and refused as a disclosure signer |
| `ArtifactBlobPort` | `custody` (private bytes) |
| `ArtifactReleaseSink` | `custody` (effect sink; bytes leave only after the knowledge join commits) |
| `PinnedSemanticConnector` and `SemanticTransport` | `custody` |
| Semantic ACL resolver (`SignedSemanticAudienceV1`) | `fact_source` |
| Annotators | `RestrictOnly` is `deny_only`; `AttestFacts` is `fact_source` |
| Semantic transform implementations | `output_transform` |
| Knowledge adoption classifier key | `fact_source` |
| Confined disclosure and endorsement roots | `fact_source` (independent authority roots) |
| Knowledge archive signing key | `custody` |
| `NativeConfinedRuntime` with the cage | `custody` |
| `set_semantic_emergency_stop` (store) | component control op with stop semantics, outside `KernelOp` (open decision 10) |

Rules:

9. **R9. No live trust mutation outside the op set.** A `&self` method that mutates trust configuration must be an op entry point, or move to `boot`. `UpdateLiveTrust` exists only for `set_capability_trust_root` and `set_federation_local_kernel_id` (open decision 3).
10. **R10. No new handle exports.** The four existing ones are migrated in phase 2.
11. **R13. No network client implementations in `chio-kernel`.** `custody` and `fact_source` implementations that perform network I/O live outside the kernel crate, which holds only their traits. Today the kernel compiles `ureq` clients for x402, ACP and approval webhooks (section 2). Phase 2 moves them, for example to a payment-adapter crate and the approval-channel owner, and drops `ureq` from the closure.

### P6 component operations (W:)

P6 is a control-plane and store component surface. It is classified in the C layer, keyed by route or store method, and it does not grow `KernelOp`. The census (section 7.1) generates these rows from the landed routes and store methods, and an unlisted route or mutation fails the census.

| Group | Owning entry point | Authorization | Stop disposition | Mutable generation or readiness predicates |
|---|---|---|---|---|
| Setup and qualification | `RecoverySetupService` routes `setup/probe` and `setup/qualify`; store `pin_setup_creation`, `configure_protected_setup`, `commit_setup_probe`, `accept_setup_report` (mutations); `setup_preparation`, `prepare_setup_report` (preparation reads) | Host operator key: `configure_protected_setup` refuses unless the deployment profile's root equals the selected operator (`service.rs:107-125`); probes and reports are signed with that operator key (`setup.rs:240`, `:295`) | Mutations `deny` (they advance a scope toward readiness and run the benign self-test capture). Preparation reads `allow` | The protected setup selection (scope, benign workflow, creation digest, operator root) and its qualification (`gate.rs` `ready`, `current`). These gate every command and capture in the scope until qualified |
| Setup gate (participant precondition) | `require_ready`, `require_command`, `require_capture` (`gate.rs:4-124`) | Not an entry point: a transaction-local precondition of native, recovery, semantic and knowledge participants | Inherits its caller's disposition | Selected deployment identity, security-context fields and context generation, qualification, and the one selected self-test. Spec 10 X5b keeps it inside `CrossingTx` |
| Decision reports | `reports/submit` (store `submit_decision_report`, `product/reports.rs:45`); `reports/read` (`read_decision_report`, `:121`) | Submit: `RecoveryPermission::Report` with a matching scope. Read: `Inspect` plus `KnowledgeRead` (`maintenance.rs`) | Submit `deny` (a mutation, consistent with R5a's `ReportDecision`). Read `allow` (audience-checked observation) | The report record under the scope's intake headroom |
| Maintenance proposals | `policy/propose` (store `propose_policy_maintenance`, `product/proposals.rs:5`); `policy_basis` read | `RecoveryPermission::Maintain` plus `KnowledgeRead` (`maintenance.rs`); `proposal.validate()` | Propose `deny` (inert, but a mutation). Basis read `allow` | The proposal record against the current policy basis (deployment, policy, generation) |
| Signed policy application | Store `apply_reviewed_semantic_deployment` (`semantic/policy.rs:99-185`); no route mounts it | An independently selected operator's signature over `SignedPolicyDeploymentChangeV1`. The target scope, authority domain, store UUID, tenant, deployment, policy and generation must all match, and the writer fence must be current | `deny` while stopped: it installs a new deployment generation. Applying a reviewed change waits for resume | `target_generation` must equal the installed generation. Original-ID readback is keyed `product-policy-change:{scope}:{proposal_id}`, so a lost acknowledgement replays rather than re-applies |

Rules:
- **No second owner.** New policy or deployment configuration for later specs, including spec 11's integrity deployment fields, goes through `apply_reviewed_semantic_deployment` with explicit fields and validation. It never goes through a new activation service with its own operator authority, generations or lost-acknowledgement handling.
- **Separate access rules are kept.** Historical inspection (`reports/read`, `Inspect`) and settlement keep their separate current-access rules. A stop disposition never removes them.
- **No growth of `KernelOp`.** P6 adds no `ChioKernel` method. If a later change routes a P6 decision through the kernel, it joins L0 under R1 like any other entry point.

### Placement of components (updated from revision 1 section 7)

- **Linked into the kernel.** `chio-security-types` and `chio-response-model` are tier-1 allowlist entries. `chio-workflow` is a tier-1 allowlist entry for `chio_workflow::delegation`: on `main` its own closure is 123 packages, and its non-workspace dependencies are `serde`, `thiserror`, `tracing` and `rusqlite`.
- **chio-security-kernel.** Its guards are `deny_only`. `FlowPreDispatchHook` is `custody` (it commits declassification), and `FlowPostInvocationHook` and `RawOutputTripwireHook` are `output_transform`. Composition policy (`SecurityPreDispatchPolicy`, flow-guard `MissingContextPolicy`) is recorded per binary.
- **chio-process host.** A component with the L1 rows. It is inside the TCB through the fact sources and custody listed above.
- **Separate trusted processes.** `chio-cage-init`, `chio-secret-brokerd`, the keyring witness and audit services, and `chio-active-response-authorityd` are components with their existing op enums. `chio-cage-init` and the broker keep their existing H11 budgets (ceilings 72 and 481).
- **Verifiers and W2 owner services.** Components; their routes are their op enums.
- **Recovery (W:).**
  - `chio-recovery` is a pure, `no_std`, advisory component outside the TCB. It has no ops, and a `compile_fail` doctest proves a report cannot become a grant.
  - `chio-semantic-contracts` is pure validation that gates registry activation. It behaves like `deny_only` and is in the control-plane closure.
  - The control-plane recovery, knowledge, semantic and confinement runtimes are host components with the L3 rows. They are inside the TCB through the `custody` and `fact_source` seams listed above.
  - The semantic HTTP gateway client is a `reqwest` client in `chio-control-plane` (W: `semantic/http.rs:11`). It conforms to R13 and is the template for relocating the kernel's `ureq` clients.

## 7. Gates

### 7.1 ABI census

`scripts/check-kernel-abi.py` follows the `check-trust-boundaries.py` pattern: a source inventory and review tripwire, not a verifier. It reads the catalog `docs/security/kernel-abi-inventory.json` (`chio.kernel-abi-inventory.v1`). It:

1. Enumerates L0 symbols (`impl ChioKernel` blocks, `chio-kernel-core` root functions, `#[wasm_bindgen]`, UniFFI, `extern "C"` exports), L1 worker ops and reserved tool names, and the variants of the L2, L3 and component enums. It parses their source enums.
2. Fails on:
   - an unclassified symbol, or a catalog row with no symbol;
   - signature token-hash drift (`--bless` rewrites);
   - an enum or catalog mismatch, or a missing `spec_ref` table row;
   - a reused retired id;
   - entry-point budget growth;
   - a missing seam polarity;
   - a missing emergency-stop test registration;
   - an unparseable `impl ChioKernel` block or a macro invocation inside one.
3. Cross-links the trust-boundary inventory's `proofs`. Every verified proof type consumed by an Admit op is named on that op's row.

`handle_export` and `test_support` rows are not allowlisted here. They are entries in the Mechanism D escape-hatch gate (M: unrepresentable-defects `:440`). That gate has never been built (RP6), so this spec and `2026-10-04-typed-reservations-design.md` land it together, sharing one allowlist.

### 7.2 Closure budgets (H11 extension)

`check-dependency-budget.py` gains:
- a per-budget `target` field (`x86_64-unknown-linux-musl` stays the default; `wasm32-unknown-unknown` is added);
- a per-budget `features` mode (`--no-default-features` and default);
- deny entries with `via` and `expires` fields. A denied package reached through a listed path, before its expiry, is debt. Reaching it through a new path, or after expiry, fails.

New budgets:

| Package | Target(s) | Ceiling | Deny |
|---|---|---|---|
| `chio-kernel-core` | musl and wasm32, both feature modes | exact (measured) | `tokio`, `rusqlite`, `reqwest`, `hyper`, `ureq`, `axum`, `clap`, `tonic`, `wasmtime`, `alloy*`, every `crates/protocol` member |
| `chio-kernel` | musl | measured at landing; shrink-only | `axum`, `clap`, `tonic`, `wasmtime`, and every protocol crate except `chio-tool-call-fabric` and `chio-egress-contract`. Dated debt with `via`: `alloy*` (via `chio-settle`, and via `chio-core` to `chio-web3`); `reqwest`/`hyper` (via `chio-link`, `chio-settle`, `chio-egress-contract`); `sigstore`, `oci-client`, `prost` (via `chio-weights` to `chio-attest-verify`); `ureq` (direct, until R13) |

H11 measures name/version pairs. Revision 1's numbers were distinct names; this spec records both.

### 7.3 Relationship to H8 and GT1

- **H8.** `cargo-public-api` and `cargo-semver-checks` snapshot signatures of publishable crates. The census classifies semantics. They are complementary layers. When H8 lands for `chio-kernel-core`, the census consumes its snapshot instead of its own token hash.
- **GT1.** At the M baseline no hardening gate ran in hosted CI. At #1160 head `89e4641f6`, hosted job `111748798722` reached and passed the structural, formal-traceability and temporal-security gate steps, but the job failed later at workspace tests. These gates join the same CI job (M: `ci.yml:193-205`). They are not acceptance-complete until a hosted run passes as a whole. A passing step is not a passing job, candidate or release, and local passes are evidence, not acceptance.

## 8. Failure modes and fail-closed behavior

- Missing targets, failed `cargo metadata`/`cargo tree`, or unparseable source fail the gate; nothing is skipped as success.
- A misclassified `query` is the main residual hole. Mitigations: hash drift forces re-review, `&mut` parameters and interior-mutability return types are flagged, and R9 makes trust mutation through `&self` a named op.
- The gates have no runtime behavior. Their protection is at merge time.
- Closure is measured per target and feature mode. The budget lists every feature of the root crates and fails on an unlisted feature.

## 9. Protocol, schema, and wire impact

- **`spec/PROTOCOL.md` section 8.6 "Kernel ABI" (normative)** contains:
  - the layer table;
  - the L0 op table (id, name, class, disposition, status);
  - the seam polarity table;
  - the frozen vocabulary;
  - rules R1-R13.
- L1-L3 rows link to their owners' documents rather than duplicating them.
- Section 3 gains one sentence: the kernel's trusted live operations are the closed sets in 8.6.
- No wire, schema, receipt or negotiation change.

## 10. Rollout and migration

1. **Phase 0 (registry).** The inventory is generated from the tree being gated, never from the union. The census fails on "a catalog row with no symbol" (section 7.1), so a row joins in the same change that lands its symbol.
   - **On the landing tree.** `abi.rs` declares only the ops whose entry points exist there. Landing before W: merges gives ops 1-27 as `KERNEL_ABI_VERSION` 1.0 (section 5), and the inventory classifies only the names present: the M: surface, plus V:'s if #1173 has merged. L1 rows record the process ABI that tree actually defines (M:'s `PROCESS_ABI` version 3, broker routes).
   - **With the recovery merge.** The W: merge adds ops 28 and 29, their 24 live methods and one test-gated method, the L3 rows (W:'s `RecoveryCommandBodyV1`, endpoints and `RecoveryPermission`) and the L1 union row `chio.process.abi.v4`, all in the merge that lands those symbols. That is 1.1, a minor bump under R3.
   - **The 254-name union** (section 5) is the target inventory for M ∪ V ∪ W. It is not a phase 0 precondition.
   - L2 rows stay `assumed-shipped`, carrying the contract-anchor variant names, until W1 code lands. They are catalog-only and exempt from the symbol check until then, with the exemption listed on each row.
   - Add PROTOCOL 8.6.
   - Dispositions start as observed behavior. Admit ops with no stop check get `allow`, with rationale "current behavior, decision pending owner review".
2. **Phase 1 (closure budgets).** The H11 extension and the two budgets at measured ceilings, with dated debt entries.
3. **Phase 2 (shrink).**
   - Feature-gate `chio-weights` bundle verification (removes sigstore, `oci-client`, `prost`).
   - Feature-gate the HTTP clients of `chio-link`, `chio-settle` and `chio-egress-contract`.
   - Depend on `chio-settle` with `default-features = false`.
   - Replace the kernel's `chio-core` facade imports with `chio-core-types` where the facade only re-exports, which removes the `chio-web3` path.
   - Apply R13, which removes `ureq`.
   - Remove or narrow the four handle exports.
   - Decide every `allow` disposition. A change to `deny` is batched into one `KERNEL_ABI_VERSION` 2.0.

   Measured on `main` at `f5a9d2ab2` (aarch64-apple-darwin, `cargo tree -p chio-kernel -e normal`; an archived measurement, not reproduced for the M:/V:/W: integrated closure), the first two cuts reach 281 distinct names with no `reqwest`, `hyper` or sigstore. Adding the `chio-settle` web3 cut reaches 262. The facade and R13 cuts remove the remaining alloy crate and `ureq`; they still need to be measured.
   - **Re-measurement.** Phase 0 re-measures every closure and cut count on the gated tree with a retained script and a retained resolved graph (`cargo metadata` output, target and feature set recorded). Those re-measured values, not the archived ones, become the R13 budgets.
4. **Phase 3 (L2 pinning).** When W1 code lands, replace the contract-anchor rows with exact variants and descent lists. L3 is already pinned to W:; its rows move with any change to the recovery template or command enums (today one template, `SupportTicketPublicIssue`).

The phases are order-independent with respect to merging #1160 and #1173, because the inventory is regenerated against whatever is on `main`.

## 11. Tests and conformance evidence

- Census and budget fixture tests for each failure in sections 7.1 and 7.2, in red and green, including an expired debt entry and a new `via` path.
- `chio-kernel-core` unit tests:
  - `from_id` is total over all `u16` values and injective on `ALL`;
  - `as_str` is unique;
  - `class()` agrees with the catalog.
- The ADR-0019 wildcard test is extended to every layer's op enum.
- Emergency-stop conformance: every `deny` entry point has a registered refusal case.
- **P6 census and gates (R-1-03).**
  - The census detects all 16 `RecoveryPermission` variants and every P6 route and store mutation in the section 6 table, and an unlisted one fails.
  - Native capture, semantic capture and artifact operations keep the setup gate after spec 10 refactors them (spec 10 X5b).
  - Stale deployment generation, wrong operator, a lost acknowledgement of `apply_reviewed_semantic_deployment` (it replays, never re-applies), a stop (mutations refuse, reads succeed) and a restart each exercise the existing owners.
- No new `chio-conformance` verdict scenarios, since there is no wire change.

## 12. Residual risks and open decisions

### Residual risks

- In-process plug-ins share the kernel's address space. Polarity is a reviewed declaration that types only partly back. Isolation is the subject of `2026-10-04-microkernel-isolation-backend-design.md`.
- Layer descent (R12) is checked by review plus static flagging, not proven.
- L2 rows rest on contract anchors until W1 code lands. A divergent implementation must update the rows, not the reverse.
- L3 and the W: L0 rows are pinned to uncommitted code built on an older #1160 checkpoint. They must be re-verified when W: is rebased onto M: head.
- GT1 means none of this is enforced on hosted CI today.

### Open decisions

0. **P6 integration (resolved, independent review open question 4).** The owners are the existing ones in section 6's P6 table:
   - `RecoverySetupService` and the store setup methods own setup qualification;
   - `RecoveryMaintenanceRuntime` and `propose_policy_maintenance` own policy proposal;
   - `apply_reviewed_semantic_deployment` owns signed policy application.

   The layered registry records them as C-layer component operations with the stop dispositions above. Fresh authorization, historical inspection and settlement keep their distinct access rules, and stop or crossing checks are added around these owners, never in place of them.

1. Keep `ProviderId` and `Principal` as typed L0 vocabulary, or reduce them to an opaque principal digest.
2. Census implementation language. A Python source inventory matches `check-trust-boundaries.py` and needs no new toolchain. `syn` in `xtask` (already a dependency) hashes signatures more faithfully. This draft picks Python for consistency, and switches to H8 snapshots for `chio-kernel-core` once H8 lands.
3. Whether `UpdateLiveTrust` should exist, or both methods move to `boot`.
4. Runtime reporting of `KERNEL_ABI_VERSION` (requires C FFI ABI v3).
5. Whether R12 descent should be enforced at runtime (an L1-L3 host holding a descent-scoped kernel handle) rather than by review.
6. Where R13's relocated payment adapters live (`chio-settle` or a new adapter crate). Either must stay out of the kernel closure.
7. Pushback on the directive "chio-process is in the TCB". The whole crate is not TCB. Its journal bookkeeping is outside the authority path (M: `ARCHITECTURE.md:3-6`). The TCB members are the `fact_source` and `custody` items in section 6, and the census tracks those symbols, not the whole crate.
8. **`observe_recovery_source` audience.** It is a live `&self` kernel method that takes only a `RecoveryScopeV1` and returns the native security flow observation, with no actor authentication (W: `recovery_runtime.rs:335`). This draft classifies it as `query`. The recovery owners must confirm it is reachable only from trusted host code. Otherwise it moves under `RecoveryControl` and requires an authenticated actor.
9. **Pushback on "knowledge enforcement toggles -> boot/UpdateLiveTrust".**
   - The kernel methods `durable_knowledge_enforcement` and `durable_knowledge_enforced` are read-only queries (W: `recovery_runtime.rs:590`, `:599`).
   - The toggle is `ProcessRuntime::enable_durable_knowledge` (W: `chio-process/src/knowledge.rs:22`), a one-way L1 host switch with a downgrade trigger.
   - So the kernel needs no `UpdateLiveTrust` entry. L1 records the switch as host-only and irreversible.
   - Similarly, the directive's "about 23" recovery methods is 24 live methods (it adds `durable_authority_id`) plus one test-gated method.
10. **Settlement and stop placement.**
    - Settlement and provider finality map to `Reconcile`, not a new op. They record facts about an already-dispatched continuation and must run during a stop. If owners want `Settle` independently budgeted, it becomes op 30 under a minor bump.
    - `set_semantic_emergency_stop` is a durable, scoped stop outside the kernel (W: `chio-store-sqlite/src/admission_operation_store/semantic.rs:355`). Should `EmergencyControl` adopt its persistence model (EV11/AC6), and should the census register it as a component control op?

## Review disposition

### Codex review (PR #1174, round 1)

| Comment | Title | Disposition | Where |
|---|---|---|---|
| 4180274510 | Generate the phase 0 inventory from landed code | Fixed now. Phase 0 generates the inventory from the gated tree. Ops 28-29, the W: rows, the L3 rows and the v4 L1 row join in the recovery merge that lands their symbols (1.1). The 254-name union is a target, not a precondition | Section 10 phase 0; section 5 version note |

### Independent review (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| Numbers check | Closure and edge-cut counts lack provenance for the integrated tree | Fixed. The 407/434 closure and the 310/281/262 cut counts are labelled as archived measurements on `main` at `f5a9d2ab2` (aarch64-apple-darwin, `cargo tree -p chio-kernel -e normal`), not reproduced for the M:/V:/W: integrated closure. Phase 0 re-measures them with a retained script and resolved graph, and those values become the budgets | Section 2 rows; section 10 phase 2 note |
| R-1-01 | Caller reconciliation belongs to two different ABI operations | Fixed. `reconcile_caller_execution*` is an entry point of `CallerExecution` only, with a per-entry-point `allow` under R5b. It is removed from the `Reconcile` row. R5b now states that the generated test asserts per entry point, so the inventory and the stop tests come from one table. Spec 8 S13 and its disposition row agree | R5b; union entry-point table (section 5) |

### Independent review pass 3 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-1-02 | The hosted gate rollout statement is stale against current #1160 evidence | Fixed. The M-baseline GT1 history is kept with its source. The current status is recorded as verified: hosted job `111748798722` at `89e4641f6` passed structural (13), formal traceability (14) and temporal security (15) steps, then failed at workspace tests (33). Overall qualification stays open | section 2 table; section 7.3 GT1 |

### Independent review pass 4 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-1-03 | The recovery inventory stops before implemented P6 setup and signed maintenance | Fixed, checked against W:. The baseline says P0-P6 and lists 16 `RecoveryPermission` variants (with `maintain`). A section 2 row records the P6 routes, store mutations and setup gate. A new section 6 table classifies setup, the setup gate, reports, maintenance proposals and signed policy application separately, with owner, authorization, stop disposition and mutable predicates, as C-layer component operations that do not grow `KernelOp`. Spec 11's integrity deployment configuration goes through the existing P6 policy owner. Section 11 adds the acceptance tests, and open decision 0 answers open question 4 | baseline; section 2; section 4 L3; section 6; section 11; open decision 0 |

## Appendix: FTL reference

- **A closed, numbered syscall enum with an exhaustive dispatch and an `UnknownSyscall` fallback** (FTL `libs/ftl_types/src/syscall.rs:1-36`, `kernel/src/syscall.rs:19-73`). It is the model for R1 and R2. The literal analog in Chio is L1: six worker ops, and everything else through `invoke`.
- **Pass through, don't interpret** (FTL `kernel/src/arch/x64/syscall.rs:65`). Linux semantics live in `lx`, whose fallback is `ENOSYS` (`lx/src/syscall/mod.rs:347`). It is the model for R7, R8 and R11.
- **Retired numbers stay retired.** `NetPeek` and `NetDrop` (ids 20 and 21) were removed and never refilled. It is the model for R3.
- **A two-crate dependency closure** (FTL `Cargo.toml:22-23`). It is the model for the exact `chio-kernel-core` budget.

Where the analogy breaks:
- FTL's ABI is enforced by CPU privilege. Chio's L0 boundary is a governance boundary inside one process, except where it coincides with a process boundary: the wire, the sidecar, FFI, the L1 worker socket and component IPC.
- Chio's TCB includes signing, a durable saga and budgets, so it gates growth rather than matching FTL's size.

### Independent review pass 5 (PR #1174, Codex agent)

| Finding | Title | Disposition | Where |
|---|---|---|---|
| R-9-04 (cross-reference) | The machine puts contractual capture waivers in the wrong execution phase | Applied here. The custody row now separates the two successor stores: the unknown-release store releases an unknown hold, and the capture-waiver store resolves a known return's positive pending capture (spec 9 M7a, M7b) | custody classification table |

### Independent review pass 6 and PR round 28

| Comment or finding | Title | Disposition | Where |
|---|---|---|---|
| R-2-03 / 4190476138 (spec 1 side) | Reserving a successor can permanently supersede the root while recovery creation is stopped | Applied here. R5b lists spec 2's proposed `reserve_successor_ordinal` as a `deny` `RecoveryControl` entry point, and the census row records that it makes eight when it lands. The generated test then asserts its refusal while stopped | R5b; section 5 census row |
